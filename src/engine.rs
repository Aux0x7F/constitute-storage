use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use constitute_protocol::{
    StorageKeyGrant, StorageObjectManifest, StoragePinAttestation, StoragePinIntent,
    StoragePinLease, StoragePinProjection, storage_pin_projection_from_intent,
    storage_pin_projection_from_records, validate_storage_chunk_ref, validate_storage_index_shard,
    validate_storage_manifest, validate_storage_pin_attestation, validate_storage_pin_intent,
};
use rusqlite::{Connection, OptionalExtension, params};
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::types::{
    GetObjectResponse, MaterializedIndexEntry, PruneRequest, PruneResponse, PutChunk,
    PutIndexShardRequest, PutObjectRequest, SearchResponse, StorageHealth,
    StoragePinAttestationResponse, StoragePinIntentResponse, StorageWatchEvent,
    StoredIndexShardResponse, StoredObjectResponse,
};

#[derive(Clone)]
pub struct StorageEngine {
    inner: Arc<StorageEngineInner>,
}

struct StorageEngineInner {
    root: PathBuf,
    blob_dir: PathBuf,
    db: Mutex<Connection>,
    watch_tx: broadcast::Sender<StorageWatchEvent>,
}

impl StorageEngine {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let blob_dir = root.join("objects");
        fs::create_dir_all(&blob_dir).context("create storage object dir")?;
        let db_path = root.join("storage.sqlite3");
        let conn = Connection::open(db_path).context("open storage sqlite")?;
        init_schema(&conn)?;
        let (watch_tx, _) = broadcast::channel(128);
        Ok(Self {
            inner: Arc::new(StorageEngineInner {
                root,
                blob_dir,
                db: Mutex::new(conn),
                watch_tx,
            }),
        })
    }

    pub fn root(&self) -> &Path {
        &self.inner.root
    }

    pub fn subscribe(&self) -> broadcast::Receiver<StorageWatchEvent> {
        self.inner.watch_tx.subscribe()
    }

    pub fn health(&self) -> Result<StorageHealth> {
        let db = self.lock_db()?;
        Ok(StorageHealth {
            status: "ok".to_string(),
            objects: count_table(&db, "objects")?,
            chunks: count_table(&db, "chunks")?,
            index_shards: count_table(&db, "index_shards")?,
            key_grants: count_table(&db, "key_grants")?,
            pin_leases: count_table(&db, "pin_leases")?,
            pin_intents: count_table(&db, "pin_intents")?,
            pin_attestations: count_table(&db, "pin_attestations")?,
            materialized_entries: count_table(&db, "materialized_entries")?,
        })
    }

    pub fn put_object(&self, request: PutObjectRequest) -> Result<StoredObjectResponse> {
        validate_storage_manifest(&request.manifest)?;
        if request.chunks.is_empty() {
            return Err(anyhow!("object put requires chunks"));
        }
        let mut stored = 0usize;
        let db = self.lock_db()?;
        let tx = db.unchecked_transaction()?;
        for (ordinal, chunk) in request.chunks.iter().enumerate() {
            let bytes = decode_chunk(chunk)?;
            validate_storage_chunk_ref(&chunk.chunk_ref, &bytes)?;
            self.write_chunk_file(&chunk.chunk_ref.hash, &bytes)?;
            tx.execute(
                "insert or ignore into chunks (hash, chunk_id, path, size, created_at, last_accessed_at) values (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    chunk.chunk_ref.hash,
                    chunk.chunk_ref.chunk_id,
                    self.chunk_path(&chunk.chunk_ref.hash).to_string_lossy(),
                    chunk.chunk_ref.size,
                    now_seconds(),
                    now_seconds()
                ],
            )?;
            tx.execute(
                "insert or replace into object_chunks (object_id, chunk_hash, ordinal) values (?1, ?2, ?3)",
                params![request.manifest.object_id, chunk.chunk_ref.hash, ordinal as u64],
            )?;
            stored += 1;
        }
        tx.execute(
            "insert or replace into objects (object_id, container_id, content_hash, manifest_json, logical_deleted_at, created_at, last_accessed_at) values (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                request.manifest.object_id,
                request.manifest.container_id,
                request.manifest.content_hash,
                serde_json::to_string(&request.manifest)?,
                request.manifest.logical_deleted_at,
                request.manifest.created_at,
                now_seconds()
            ],
        )?;
        tx.commit()?;
        self.emit(
            "object.stored",
            "normal",
            Some(&request.manifest.container_id),
            Some(&request.manifest.object_id),
            "encrypted object stored",
        );
        Ok(StoredObjectResponse {
            manifest: request.manifest,
            stored_chunk_count: stored,
        })
    }

    pub fn get_object(&self, object_id: &str) -> Result<GetObjectResponse> {
        let db = self.lock_db()?;
        let manifest_json: String = db
            .query_row(
                "select manifest_json from objects where object_id = ?1 and logical_deleted_at is null",
                params![object_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or_else(|| anyhow!("storage object not found"))?;
        let manifest: StorageObjectManifest = serde_json::from_str(&manifest_json)?;
        db.execute(
            "update objects set last_accessed_at = ?1 where object_id = ?2",
            params![now_seconds(), object_id],
        )?;
        let mut stmt = db.prepare(
            "select c.hash, c.chunk_id, c.path, c.size from object_chunks oc join chunks c on c.hash = oc.chunk_hash where oc.object_id = ?1 order by oc.ordinal asc",
        )?;
        let rows = stmt.query_map(params![object_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, u64>(3)?,
            ))
        })?;
        let mut chunks = Vec::new();
        for row in rows {
            let (hash, chunk_id, path, size) = row?;
            db.execute(
                "update chunks set last_accessed_at = ?1 where hash = ?2",
                params![now_seconds(), hash],
            )?;
            let bytes = fs::read(path).context("read storage chunk")?;
            chunks.push(PutChunk {
                chunk_ref: constitute_protocol::StorageChunkRef {
                    chunk_id,
                    hash,
                    hash_alg: constitute_protocol::STORAGE_CHUNK_HASH_ALG.to_string(),
                    size,
                },
                ciphertext_base64: B64.encode(bytes),
            });
        }
        Ok(GetObjectResponse { manifest, chunks })
    }

    pub fn put_index_shard(
        &self,
        request: PutIndexShardRequest,
    ) -> Result<StoredIndexShardResponse> {
        validate_storage_index_shard(&request.shard)?;
        if request.chunks.is_empty() {
            return Err(anyhow!("index shard put requires chunks"));
        }
        let mut stored = 0usize;
        let db = self.lock_db()?;
        let tx = db.unchecked_transaction()?;
        for (ordinal, chunk) in request.chunks.iter().enumerate() {
            let bytes = decode_chunk(chunk)?;
            validate_storage_chunk_ref(&chunk.chunk_ref, &bytes)?;
            self.write_chunk_file(&chunk.chunk_ref.hash, &bytes)?;
            tx.execute(
                "insert or ignore into chunks (hash, chunk_id, path, size, created_at, last_accessed_at) values (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    chunk.chunk_ref.hash,
                    chunk.chunk_ref.chunk_id,
                    self.chunk_path(&chunk.chunk_ref.hash).to_string_lossy(),
                    chunk.chunk_ref.size,
                    now_seconds(),
                    now_seconds()
                ],
            )?;
            tx.execute(
                "insert or replace into index_shard_chunks (shard_id, chunk_hash, ordinal) values (?1, ?2, ?3)",
                params![request.shard.shard_id, chunk.chunk_ref.hash, ordinal as u64],
            )?;
            stored += 1;
        }
        tx.execute(
            "insert or replace into index_shards (shard_id, container_id, shard_type, ciphertext_hash, shard_json, created_at) values (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                request.shard.shard_id,
                request.shard.container_id,
                request.shard.shard_type,
                request.shard.ciphertext_hash,
                serde_json::to_string(&request.shard)?,
                request.shard.created_at
            ],
        )?;
        tx.commit()?;
        self.emit(
            "index_shard.stored",
            "normal",
            Some(&request.shard.container_id),
            None,
            "encrypted index shard stored",
        );
        Ok(StoredIndexShardResponse {
            shard: request.shard,
            stored_chunk_count: stored,
        })
    }

    pub fn put_key_grant(&self, grant: StorageKeyGrant) -> Result<StorageKeyGrant> {
        if grant.grant_id.trim().is_empty() || grant.wrapped_key.trim().is_empty() {
            return Err(anyhow!("storage key grant missing required fields"));
        }
        let db = self.lock_db()?;
        db.execute(
            "insert or replace into key_grants (grant_id, container_id, key_ref, scope, recipient_pk, issuer_pk, grant_json, issued_at, expires_at) values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                grant.grant_id,
                grant.container_id,
                grant.key_ref,
                grant.scope,
                grant.recipient_pk,
                grant.issuer_pk,
                serde_json::to_string(&grant)?,
                grant.issued_at,
                grant.expires_at
            ],
        )?;
        self.emit(
            "key_grant.stored",
            "critical",
            Some(&grant.container_id),
            None,
            "wrapped storage key grant stored",
        );
        Ok(grant)
    }

    pub fn put_pin_intent(&self, intent: StoragePinIntent) -> Result<StoragePinIntentResponse> {
        validate_storage_pin_intent(&intent)?;
        let projection = storage_pin_projection_from_intent(&intent)?;
        let db = self.lock_db()?;
        db.execute(
            "insert or replace into pin_intents (intent_id, manifest_hash, desired_replicas, intent_json, projection_json, created_at, expires_at) values (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                intent.intent_id,
                intent.manifest_hash,
                intent.desired_replicas,
                serde_json::to_string(&intent)?,
                serde_json::to_string(&projection)?,
                now_seconds(),
                intent.expires_at
            ],
        )?;
        self.emit(
            "pin_intent.stored",
            "normal",
            None,
            None,
            "storage pin intent projection pending",
        );
        Ok(StoragePinIntentResponse { intent, projection })
    }

    pub fn put_pin_attestation(
        &self,
        attestation: StoragePinAttestation,
        now: u64,
    ) -> Result<StoragePinAttestationResponse> {
        validate_storage_pin_attestation(&attestation)?;
        let db = self.lock_db()?;
        let intent = load_pin_intent(&db, &attestation.intent_id)?
            .ok_or_else(|| anyhow!("storage pin intent not found"))?;
        db.execute(
            "insert or replace into pin_attestations (attestation_id, intent_id, storage_member_ref, status, attestation_json, issued_at, expires_at) values (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                attestation.attestation_id,
                attestation.intent_id,
                attestation.storage_member_ref,
                serde_json::to_string(&attestation.status)?,
                serde_json::to_string(&attestation)?,
                attestation.issued_at,
                attestation.expires_at
            ],
        )?;
        let projection = self.derive_and_store_pin_projection(&db, &intent, now)?;
        self.emit(
            "pin_attestation.stored",
            "normal",
            None,
            None,
            "storage pin attestation projection updated",
        );
        Ok(StoragePinAttestationResponse {
            attestation,
            projection,
        })
    }

    pub fn pin_projection(&self, intent_id: &str, now: u64) -> Result<StoragePinProjection> {
        let db = self.lock_db()?;
        let intent = load_pin_intent(&db, intent_id)?
            .ok_or_else(|| anyhow!("storage pin intent not found"))?;
        self.derive_and_store_pin_projection(&db, &intent, now)
    }

    fn derive_and_store_pin_projection(
        &self,
        db: &Connection,
        intent: &StoragePinIntent,
        now: u64,
    ) -> Result<StoragePinProjection> {
        let attestations = load_pin_attestations(db, &intent.intent_id)?;
        let projection = storage_pin_projection_from_records(intent, &attestations, now)?;
        db.execute(
            "update pin_intents set projection_json = ?1 where intent_id = ?2",
            params![serde_json::to_string(&projection)?, intent.intent_id],
        )?;
        Ok(projection)
    }

    // Legacy direct storage route bridge: retained below the protocol boundary for
    // local smoke tests and prune mechanics while swarm pin records land.
    pub fn put_pin(&self, pin: StoragePinLease) -> Result<StoragePinLease> {
        if pin.pin_id.trim().is_empty() || pin.container_id.trim().is_empty() {
            return Err(anyhow!("storage pin missing required fields"));
        }
        if pin.object_id.is_none() && pin.chunk_hash.is_none() {
            return Err(anyhow!("storage pin must target object or chunk"));
        }
        let db = self.lock_db()?;
        db.execute(
            "insert or replace into pin_leases (pin_id, container_id, object_id, chunk_hash, pinned_by, retention_class, pin_json, created_at, expires_at, last_accessed_at) values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                pin.pin_id,
                pin.container_id,
                pin.object_id,
                pin.chunk_hash,
                pin.pinned_by,
                pin.retention_class,
                serde_json::to_string(&pin)?,
                pin.created_at,
                pin.expires_at,
                pin.last_accessed_at
            ],
        )?;
        self.emit(
            "pin.stored",
            "normal",
            Some(&pin.container_id),
            pin.object_id.as_deref(),
            "storage pin lease stored",
        );
        Ok(pin)
    }

    pub fn retract_pin(&self, pin_id: &str) -> Result<()> {
        let db = self.lock_db()?;
        db.execute("delete from pin_leases where pin_id = ?1", params![pin_id])?;
        self.emit(
            "pin.retracted",
            "normal",
            None,
            None,
            "storage pin lease retracted",
        );
        Ok(())
    }

    pub fn logical_delete_object(&self, object_id: &str, at: u64) -> Result<()> {
        let db = self.lock_db()?;
        let changed = db.execute(
            "update objects set logical_deleted_at = ?1 where object_id = ?2",
            params![at, object_id],
        )?;
        if changed == 0 {
            return Err(anyhow!("storage object not found"));
        }
        self.emit(
            "object.logical_deleted",
            "normal",
            None,
            Some(object_id),
            "storage object logically deleted",
        );
        Ok(())
    }

    pub fn materialize_entries(&self, entries: &[MaterializedIndexEntry]) -> Result<usize> {
        let db = self.lock_db()?;
        let tx = db.unchecked_transaction()?;
        for entry in entries {
            tx.execute(
                "insert or replace into materialized_entries (entry_id, container_id, record_type, subject, priority, tags_json, facts_json, detail_ref_json, encrypted_detail_refs_json, created_at) values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    entry.entry_id,
                    entry.container_id,
                    entry.record_type,
                    entry.subject,
                    entry.priority,
                    serde_json::to_string(&entry.tags)?,
                    serde_json::to_string(&entry.facts)?,
                    serde_json::to_string(&entry.detail_ref)?,
                    serde_json::to_string(&entry.encrypted_detail_refs)?,
                    entry.created_at
                ],
            )?;
        }
        tx.commit()?;
        if let Some(first) = entries.first() {
            self.emit(
                "index.materialized",
                "normal",
                Some(&first.container_id),
                None,
                "local materialized index updated",
            );
        }
        Ok(entries.len())
    }

    pub fn search(
        &self,
        container_id: Option<&str>,
        record_type: Option<&str>,
        subject: Option<&str>,
        tag: Option<&str>,
    ) -> Result<SearchResponse> {
        let db = self.lock_db()?;
        let mut stmt = db.prepare(
            "select entry_id, container_id, record_type, subject, priority, tags_json, facts_json, detail_ref_json, encrypted_detail_refs_json, created_at from materialized_entries order by created_at desc limit 500",
        )?;
        let rows = stmt.query_map([], |row| {
            let tags_json: String = row.get(5)?;
            let facts_json: String = row.get(6)?;
            let detail_json: String = row.get(7)?;
            let encrypted_detail_refs_json: String = row.get(8)?;
            Ok(MaterializedIndexEntry {
                entry_id: row.get(0)?,
                container_id: row.get(1)?,
                record_type: row.get(2)?,
                subject: row.get(3)?,
                priority: row.get(4)?,
                tags: serde_json::from_str(&tags_json).unwrap_or_default(),
                facts: serde_json::from_str(&facts_json).unwrap_or(serde_json::Value::Null),
                detail_ref: serde_json::from_str(&detail_json).unwrap_or(None),
                encrypted_detail_refs: serde_json::from_str(&encrypted_detail_refs_json)
                    .unwrap_or_default(),
                created_at: row.get(9)?,
            })
        })?;
        let mut entries = Vec::new();
        for row in rows {
            let entry = row?;
            if let Some(container_id) = container_id {
                if entry.container_id != container_id {
                    continue;
                }
            }
            if let Some(record_type) = record_type {
                if entry.record_type != record_type {
                    continue;
                }
            }
            if let Some(subject) = subject {
                if entry.subject != subject {
                    continue;
                }
            }
            if let Some(tag) = tag {
                if !entry.tags.iter().any(|item| item == tag) {
                    continue;
                }
            }
            entries.push(entry);
        }
        Ok(SearchResponse { entries })
    }

    pub fn prune(&self, request: PruneRequest) -> Result<PruneResponse> {
        let now = if request.now == 0 {
            now_seconds()
        } else {
            request.now
        };
        let db = self.lock_db()?;
        if request.prune_expired && !request.dry_run {
            db.execute(
                "delete from pin_leases where expires_at is not null and expires_at <= ?1",
                params![now],
            )?;
        }

        let mut stmt =
            db.prepare("select hash, path, size from chunks order by last_accessed_at asc")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, u64>(2)?,
            ))
        })?;
        let mut candidates = Vec::new();
        for row in rows {
            let (hash, path, size) = row?;
            let pinned: i64 = db.query_row(
                "select count(*) from pin_leases where chunk_hash = ?1 or object_id in (select object_id from object_chunks where chunk_hash = ?1)",
                params![hash],
                |row| row.get(0),
            )?;
            if pinned == 0 {
                candidates.push((hash, path, size));
            }
        }

        let mut pruned_chunks = 0usize;
        let mut pruned_bytes = 0u64;
        for (hash, path, size) in candidates {
            if let Some(max) = request.max_bytes {
                if pruned_bytes >= max {
                    break;
                }
            }
            pruned_chunks += 1;
            pruned_bytes += size;
            if !request.dry_run {
                let _ = fs::remove_file(&path);
                db.execute("delete from chunks where hash = ?1", params![hash])?;
            }
        }
        if pruned_chunks > 0 {
            self.emit(
                "chunks.pruned",
                "normal",
                None,
                None,
                "unpinned storage chunks pruned",
            );
        }
        Ok(PruneResponse {
            dry_run: request.dry_run,
            pruned_chunks,
            pruned_bytes,
        })
    }

    fn lock_db(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.inner
            .db
            .lock()
            .map_err(|_| anyhow!("storage sqlite lock poisoned"))
    }

    fn write_chunk_file(&self, hash: &str, bytes: &[u8]) -> Result<()> {
        let path = self.chunk_path(hash);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        if !path.exists() {
            fs::write(path, bytes)?;
        }
        Ok(())
    }

    fn chunk_path(&self, hash: &str) -> PathBuf {
        let prefix = hash.get(0..2).unwrap_or("xx");
        self.inner.blob_dir.join(prefix).join(format!("{hash}.bin"))
    }

    fn emit(
        &self,
        kind: &str,
        priority: &str,
        container_id: Option<&str>,
        object_id: Option<&str>,
        message: &str,
    ) {
        let _ = self.inner.watch_tx.send(StorageWatchEvent {
            event_id: Uuid::new_v4().to_string(),
            priority: priority.to_string(),
            kind: kind.to_string(),
            at: now_seconds(),
            object_id: object_id.map(ToOwned::to_owned),
            container_id: container_id.map(ToOwned::to_owned),
            message: message.to_string(),
        });
    }
}

fn init_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        create table if not exists objects (
            object_id text primary key,
            container_id text not null,
            content_hash text not null,
            manifest_json text not null,
            logical_deleted_at integer,
            created_at integer not null,
            last_accessed_at integer not null
        );
        create table if not exists chunks (
            hash text primary key,
            chunk_id text not null,
            path text not null,
            size integer not null,
            created_at integer not null,
            last_accessed_at integer not null
        );
        create table if not exists object_chunks (
            object_id text not null,
            chunk_hash text not null,
            ordinal integer not null,
            primary key (object_id, chunk_hash)
        );
        create table if not exists index_shards (
            shard_id text primary key,
            container_id text not null,
            shard_type text not null,
            ciphertext_hash text not null,
            shard_json text not null,
            created_at integer not null
        );
        create table if not exists index_shard_chunks (
            shard_id text not null,
            chunk_hash text not null,
            ordinal integer not null,
            primary key (shard_id, chunk_hash)
        );
        create table if not exists key_grants (
            grant_id text primary key,
            container_id text not null,
            key_ref text not null,
            scope text not null,
            recipient_pk text not null,
            issuer_pk text not null,
            grant_json text not null,
            issued_at integer not null,
            expires_at integer
        );
        create table if not exists pin_leases (
            pin_id text primary key,
            container_id text not null,
            object_id text,
            chunk_hash text,
            pinned_by text not null,
            retention_class text not null,
            pin_json text not null,
            created_at integer not null,
            expires_at integer,
            last_accessed_at integer
        );
        create table if not exists pin_intents (
            intent_id text primary key,
            manifest_hash text not null,
            desired_replicas integer not null,
            intent_json text not null,
            projection_json text not null,
            created_at integer not null,
            expires_at integer
        );
        create table if not exists pin_attestations (
            attestation_id text primary key,
            intent_id text not null,
            storage_member_ref text not null,
            status text not null,
            attestation_json text not null,
            issued_at integer not null,
            expires_at integer
        );
        create table if not exists materialized_entries (
            entry_id text primary key,
            container_id text not null,
            record_type text not null,
            subject text not null,
            priority text not null,
            tags_json text not null,
            facts_json text not null,
            detail_ref_json text not null,
            encrypted_detail_refs_json text not null default '[]',
            created_at integer not null
        );
        "#,
    )?;
    let has_encrypted_detail_refs = conn
        .prepare("pragma table_info(materialized_entries)")?
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<std::result::Result<Vec<_>, _>>()?
        .iter()
        .any(|column| column == "encrypted_detail_refs_json");
    if !has_encrypted_detail_refs {
        conn.execute(
            "alter table materialized_entries add column encrypted_detail_refs_json text not null default '[]'",
            [],
        )?;
    }
    Ok(())
}

fn count_table(conn: &Connection, table: &str) -> Result<u64> {
    let sql = format!("select count(*) from {table}");
    let count: i64 = conn.query_row(&sql, [], |row| row.get(0))?;
    Ok(count as u64)
}

fn load_pin_intent(conn: &Connection, intent_id: &str) -> Result<Option<StoragePinIntent>> {
    let intent_json: Option<String> = conn
        .query_row(
            "select intent_json from pin_intents where intent_id = ?1",
            params![intent_id],
            |row| row.get(0),
        )
        .optional()?;
    intent_json
        .map(|json| serde_json::from_str(&json).context("decode storage pin intent"))
        .transpose()
}

fn load_pin_attestations(conn: &Connection, intent_id: &str) -> Result<Vec<StoragePinAttestation>> {
    let mut stmt = conn.prepare(
        "select attestation_json from pin_attestations where intent_id = ?1 order by issued_at asc, attestation_id asc",
    )?;
    let rows = stmt.query_map(params![intent_id], |row| row.get::<_, String>(0))?;
    let mut attestations = Vec::new();
    for row in rows {
        attestations.push(serde_json::from_str(&row?)?);
    }
    Ok(attestations)
}

fn decode_chunk(chunk: &PutChunk) -> Result<Vec<u8>> {
    B64.decode(chunk.ciphertext_base64.trim())
        .map_err(|_| anyhow!("storage chunk ciphertext is not base64"))
}

pub fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use constitute_protocol::{
        STORAGE_CHUNK_HASH_ALG, STORAGE_ENCRYPTION_ALG_XCHACHA20POLY1305, STORAGE_OBJECT_HASH_ALG,
        StorageChunkRef, StorageObjectManifest, StoragePinAttestation, StoragePinIntent,
        StoragePinProjectionStatus, StoragePinStatus, SwarmStorageAvailabilityRef,
        storage_chunk_id, storage_ciphertext_hash, storage_object_id,
    };
    use tempfile::tempdir;

    use super::*;

    fn chunk(bytes: &[u8]) -> PutChunk {
        let hash = storage_ciphertext_hash(bytes);
        PutChunk {
            chunk_ref: StorageChunkRef {
                chunk_id: storage_chunk_id(&hash),
                hash,
                hash_alg: STORAGE_CHUNK_HASH_ALG.to_string(),
                size: bytes.len() as u64,
            },
            ciphertext_base64: B64.encode(bytes),
        }
    }

    fn manifest(container_id: &str, key_ref: &str, chunk: &PutChunk) -> StorageObjectManifest {
        let content_hash = storage_ciphertext_hash(chunk.chunk_ref.hash.as_bytes());
        StorageObjectManifest {
            object_id: storage_object_id(container_id, &content_hash),
            container_id: container_id.to_string(),
            content_hash,
            hash_alg: STORAGE_OBJECT_HASH_ALG.to_string(),
            encryption_alg: STORAGE_ENCRYPTION_ALG_XCHACHA20POLY1305.to_string(),
            key_ref: key_ref.to_string(),
            chunks: vec![chunk.chunk_ref.clone()],
            created_at: 1,
            media_type: "application/octet-stream".to_string(),
            logical_deleted_at: None,
            tags: vec!["test".to_string()],
        }
    }

    #[test]
    fn put_get_and_logical_delete_object() {
        let dir = tempdir().expect("tempdir");
        let engine = StorageEngine::open(dir.path()).expect("engine");
        let chunk = chunk(b"ciphertext");
        let manifest = manifest("container-a", "container-a:key", &chunk);
        let response = engine
            .put_object(PutObjectRequest {
                manifest: manifest.clone(),
                chunks: vec![chunk.clone()],
            })
            .expect("put object");
        assert_eq!(response.stored_chunk_count, 1);
        let fetched = engine.get_object(&manifest.object_id).expect("get object");
        assert_eq!(fetched.manifest.object_id, manifest.object_id);
        assert_eq!(fetched.chunks[0].ciphertext_base64, chunk.ciphertext_base64);
        engine
            .logical_delete_object(&manifest.object_id, 2)
            .expect("logical delete");
        assert!(engine.get_object(&manifest.object_id).is_err());
    }

    #[test]
    fn materialized_index_searches_safe_facts() {
        let dir = tempdir().expect("tempdir");
        let engine = StorageEngine::open(dir.path()).expect("engine");
        let entry = MaterializedIndexEntry {
            entry_id: "entry-1".to_string(),
            container_id: "container-a".to_string(),
            record_type: "gateway.event".to_string(),
            subject: "gateway-1".to_string(),
            priority: "normal".to_string(),
            tags: vec!["gateway".to_string(), "health".to_string()],
            facts: serde_json::json!({"status": "ok"}),
            detail_ref: None,
            encrypted_detail_refs: Vec::new(),
            created_at: 1,
        };
        assert_eq!(
            engine.materialize_entries(&[entry]).expect("materialize"),
            1
        );
        let found = engine
            .search(
                Some("container-a"),
                Some("gateway.event"),
                None,
                Some("health"),
            )
            .expect("search");
        assert_eq!(found.entries.len(), 1);
    }

    #[test]
    fn materialized_index_accepts_logging_safe_facts() {
        let dir = tempdir().expect("tempdir");
        let engine = StorageEngine::open(dir.path()).expect("engine");
        let entry = MaterializedIndexEntry {
            entry_id: "log-event-1".to_string(),
            container_id: "gateway-local-logs".to_string(),
            record_type: "logEvent".to_string(),
            subject: "nvr".to_string(),
            priority: "warning".to_string(),
            tags: vec!["nvr".to_string(), "worker".to_string()],
            facts: serde_json::json!({
                "service": "nvr",
                "component": "projection",
                "category": "worker",
                "outcome": "recovered"
            }),
            detail_ref: Some(constitute_protocol::EncryptedDetailRef {
                object_id: "object-log-detail-1".to_string(),
                container_id: "gateway-local-logs".to_string(),
                key_ref: "gateway-local-logs:key".to_string(),
                manifest_hash: "sha256:log-detail-manifest".to_string(),
                summary_tags: vec!["nvr".to_string(), "detail".to_string()],
            }),
            encrypted_detail_refs: vec![constitute_protocol::EncryptedDetailRef {
                object_id: "object-log-detail-2".to_string(),
                container_id: "gateway-local-logs".to_string(),
                key_ref: "gateway-local-logs:key-secondary".to_string(),
                manifest_hash: "sha256:log-detail-manifest-2".to_string(),
                summary_tags: vec!["nvr".to_string(), "archive".to_string()],
            }],
            created_at: 1,
        };
        assert_eq!(
            engine.materialize_entries(&[entry]).expect("materialize"),
            1
        );
        let found = engine
            .search(
                Some("gateway-local-logs"),
                Some("logEvent"),
                Some("nvr"),
                Some("worker"),
            )
            .expect("search");
        assert_eq!(found.entries.len(), 1);
        assert_eq!(found.entries[0].priority, "warning");
        assert_eq!(found.entries[0].encrypted_detail_refs.len(), 1);
        assert_eq!(
            found.entries[0].encrypted_detail_refs[0].object_id,
            "object-log-detail-2"
        );
    }

    #[test]
    fn legacy_pin_lease_bridge_retract_and_prune_separate_availability_from_access() {
        let dir = tempdir().expect("tempdir");
        let engine = StorageEngine::open(dir.path()).expect("engine");
        let chunk = chunk(b"ciphertext");
        let manifest = manifest("container-a", "container-a:key", &chunk);
        engine
            .put_object(PutObjectRequest {
                manifest: manifest.clone(),
                chunks: vec![chunk],
            })
            .expect("put object");
        engine
            .put_pin(StoragePinLease {
                pin_id: "pin-1".to_string(),
                container_id: "container-a".to_string(),
                object_id: Some(manifest.object_id.clone()),
                chunk_hash: None,
                pinned_by: "owner".to_string(),
                retention_class: "proof".to_string(),
                created_at: 1,
                expires_at: None,
                last_accessed_at: None,
            })
            .expect("pin");
        let dry = engine
            .prune(PruneRequest {
                dry_run: true,
                ..Default::default()
            })
            .expect("dry prune");
        assert_eq!(dry.pruned_chunks, 0);
        engine.retract_pin("pin-1").expect("retract");
        let pruned = engine
            .prune(PruneRequest {
                dry_run: false,
                ..Default::default()
            })
            .expect("prune");
        assert_eq!(pruned.pruned_chunks, 1);
    }

    fn pin_intent() -> StoragePinIntent {
        StoragePinIntent {
            intent_id: "intent-1".to_string(),
            object_refs: vec!["object-raw-1".to_string()],
            manifest_hash: "sha256:manifest".to_string(),
            desired_replicas: 2,
            retention: "proof".to_string(),
            authority_refs: vec!["authority-raw-1".to_string()],
            expires_at: Some(1_700_000_100_000),
        }
    }

    fn pin_attestation(
        attestation_id: &str,
        member_ref: &str,
        status: StoragePinStatus,
        expires_at: Option<u64>,
    ) -> StoragePinAttestation {
        StoragePinAttestation {
            attestation_id: attestation_id.to_string(),
            intent_id: "intent-1".to_string(),
            storage_member_ref: member_ref.to_string(),
            accepted_refs: vec!["object-raw-1".to_string()],
            availability_refs: vec![SwarmStorageAvailabilityRef {
                availability_id: format!("availability-{attestation_id}"),
                object_ref: "object-raw-1".to_string(),
                storage_member_ref: member_ref.to_string(),
                expires_at,
            }],
            status,
            expires_at,
            issued_at: 1_700_000_000_000,
        }
    }

    #[test]
    fn storage_pin_intent_creates_pending_projection_state() {
        let dir = tempdir().expect("tempdir");
        let engine = StorageEngine::open(dir.path()).expect("engine");
        let response = engine.put_pin_intent(pin_intent()).expect("put pin intent");
        assert_eq!(response.projection.pinned_count, 0);
        assert_eq!(response.projection.missing_replicas, 2);
        assert_eq!(
            response.projection.status,
            StoragePinProjectionStatus::Pending
        );

        let projection = engine
            .pin_projection("intent-1", 1_700_000_000_000)
            .expect("projection");
        assert_eq!(projection.status, StoragePinProjectionStatus::Pending);
        assert_eq!(projection.missing_replicas, 2);
    }

    #[test]
    fn storage_pin_attestations_update_derived_projection() {
        let dir = tempdir().expect("tempdir");
        let engine = StorageEngine::open(dir.path()).expect("engine");
        engine.put_pin_intent(pin_intent()).expect("put pin intent");

        let first = engine
            .put_pin_attestation(
                pin_attestation(
                    "attestation-1",
                    "storage-member-raw-2",
                    StoragePinStatus::Accepted,
                    Some(1_700_000_100_000),
                ),
                1_700_000_000_000,
            )
            .expect("first attestation");
        assert_eq!(first.projection.pinned_count, 1);
        assert_eq!(first.projection.missing_replicas, 1);

        let second = engine
            .put_pin_attestation(
                pin_attestation(
                    "attestation-2",
                    "storage-member-raw-1",
                    StoragePinStatus::Pinned,
                    Some(1_700_000_100_000),
                ),
                1_700_000_000_000,
            )
            .expect("second attestation");
        assert_eq!(second.projection.pinned_count, 2);
        assert_eq!(second.projection.missing_replicas, 0);
        assert_eq!(
            second.projection.status,
            StoragePinProjectionStatus::Satisfied
        );
        assert_eq!(
            second.projection.members,
            vec![
                "storage-member-raw-1".to_string(),
                "storage-member-raw-2".to_string()
            ]
        );
    }

    #[test]
    fn expired_storage_pin_attestation_no_longer_counts() {
        let dir = tempdir().expect("tempdir");
        let engine = StorageEngine::open(dir.path()).expect("engine");
        engine.put_pin_intent(pin_intent()).expect("put pin intent");
        engine
            .put_pin_attestation(
                pin_attestation(
                    "attestation-1",
                    "storage-member-raw-1",
                    StoragePinStatus::Accepted,
                    Some(1_700_000_000_010),
                ),
                1_700_000_000_000,
            )
            .expect("attestation");

        let active = engine
            .pin_projection("intent-1", 1_700_000_000_009)
            .expect("active projection");
        assert_eq!(active.pinned_count, 1);

        let expired = engine
            .pin_projection("intent-1", 1_700_000_000_010)
            .expect("expired projection");
        assert_eq!(expired.pinned_count, 0);
        assert_eq!(expired.missing_replicas, 2);
        assert_eq!(expired.status, StoragePinProjectionStatus::Pending);
    }

    #[test]
    fn materialized_index_request_can_carry_storage_pin_intents() {
        let intent = pin_intent();
        validate_storage_pin_intent(&intent).expect("valid intent carried beside index");
        let entry = MaterializedIndexEntry {
            entry_id: "entry-with-pin".to_string(),
            container_id: "container-a".to_string(),
            record_type: "logEvent".to_string(),
            subject: "logging".to_string(),
            priority: "normal".to_string(),
            tags: vec!["logging".to_string()],
            facts: serde_json::json!({ "event": "archived" }),
            detail_ref: None,
            encrypted_detail_refs: Vec::new(),
            created_at: 1_700_000_000_000,
        };
        let request = crate::types::MaterializeIndexRequest {
            entries: vec![entry],
            pin_intents: vec![intent],
        };
        let serialized = serde_json::to_string(&request).expect("json");
        assert!(serialized.contains("pinIntents"));
        assert!(!serialized.contains("mediaBytes"));
        assert!(!serialized.contains("blobBytes"));
    }
}
