// domain-owned-vocabulary: storage.backend.not-ready storage.sqlite3 sourceSnapshot.stores
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use constitute_fabric::{HostFabricMemberContributionSpec, build_host_fabric_member_contribution};
use constitute_protocol::{
    CybersecEvidenceHoldRecord, FABRIC_MEMBER_CONTRIBUTION_DEGRADED,
    FABRIC_MEMBER_CONTRIBUTION_RUNNING, FABRIC_MEMBER_ROLE_STORAGE_JOURNAL_CACHE,
    HostFabricMemberContribution, RECORD_CYBERSEC_EVIDENCE_HOLD, RECORD_RETENTION_RELEASE,
    RECORD_STORAGE_BACKEND_POSTURE, RECORD_STORAGE_BACKEND_SNAPSHOT,
    RECORD_STORAGE_FILESYSTEM_VIEW, RECORD_STORAGE_MODULE_EXECUTABLE_INSTANTIATION_POSTURE,
    RECORD_STORAGE_MODULE_MATERIALIZATION_POSTURE, RetentionReleasePosture,
    STORAGE_BACKEND_KIND_LOCAL_FS_SQLITE, STORAGE_BACKEND_STATE_DEGRADED,
    STORAGE_BACKEND_STATE_READY, STORAGE_FILESYSTEM_VIEW_DEGRADED, STORAGE_FILESYSTEM_VIEW_READY,
    STORAGE_MODULE_EXECUTABLE_INSTANTIATED, STORAGE_MODULE_MATERIALIZATION_BLOCKED,
    STORAGE_MODULE_MATERIALIZATION_DEGRADED, STORAGE_MODULE_MATERIALIZATION_MATERIALIZED,
    StorageBackendPosture, StorageBackendSnapshot, StorageFilesystemEntry, StorageFilesystemView,
    StorageGraphEdge, StorageKeyGrant, StorageModuleExecutableInstantiationPosture,
    StorageModuleMaterializationPosture, StorageObjectManifest, StoragePinAttestation,
    StoragePinIntent, StoragePinLease, StoragePinProjection, StoragePinProjectionStatus,
    StoragePinStatus, SwarmStorageAvailabilityRef, sha256_hex, storage_pin_projection_from_intent,
    storage_pin_projection_from_records, validate_cybersec_evidence_hold,
    validate_retention_release_posture, validate_storage_backend_posture,
    validate_storage_backend_snapshot, validate_storage_chunk_ref,
    validate_storage_filesystem_view, validate_storage_graph_edge, validate_storage_index_shard,
    validate_storage_manifest, validate_storage_module_executable_instantiation_posture,
    validate_storage_module_materialization_posture, validate_storage_pin_attestation,
    validate_storage_pin_intent,
};
use rusqlite::{Connection, OptionalExtension, params};
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::types::{
    GetObjectResponse, GraphEdgeSearchResponse, MaterializedIndexEntry,
    ModuleExecutableInstantiationRequest, ModuleExecutableInstantiationResponse,
    ModuleMaterializationRequest, ModuleMaterializationResponse, PruneRequest, PruneResponse,
    PutChunk, PutIndexShardRequest, PutObjectRequest, PutSourceObjectRequest, SearchResponse,
    SourceObjectStorageResponse, StorageHealth, StoragePinAttestationResponse,
    StoragePinIntentResponse, StorageWatchEvent, StoredIndexShardResponse, StoredObjectResponse,
};

const RELATION_SOURCE_SNAPSHOT_STORES: &str = "sourceSnapshot.stores";

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
            graph_edges: count_table(&db, "graph_edges")?,
            key_grants: count_table(&db, "key_grants")?,
            pin_leases: count_table(&db, "pin_leases")?,
            pin_intents: count_table(&db, "pin_intents")?,
            pin_attestations: count_table(&db, "pin_attestations")?,
            materialized_entries: count_table(&db, "materialized_entries")?,
        })
    }

    pub fn backend_posture(
        &self,
        storage_member_ref: impl AsRef<str>,
        sampled_at: u64,
    ) -> Result<StorageBackendPosture> {
        let sampled_at = if sampled_at == 0 {
            now_seconds()
        } else {
            sampled_at
        };
        let db = self.lock_db()?;
        let missing_chunk_count = count_missing_chunk_files(&db)?;
        let state = if missing_chunk_count == 0 {
            STORAGE_BACKEND_STATE_READY
        } else {
            STORAGE_BACKEND_STATE_DEGRADED
        };
        let blocked_reasons = if missing_chunk_count == 0 {
            Vec::new()
        } else {
            vec![format!("storage.chunk.missing:{missing_chunk_count}")]
        };
        let posture = StorageBackendPosture {
            kind: Some(RECORD_STORAGE_BACKEND_POSTURE.to_string()),
            posture_id: format!("storage-backend-posture:local:{sampled_at}"),
            backend_id: "storage-backend:local".to_string(),
            storage_member_ref: storage_member_ref.as_ref().to_string(),
            backend_kind: STORAGE_BACKEND_KIND_LOCAL_FS_SQLITE.to_string(),
            state: state.to_string(),
            root_ref: "storage-root:local".to_string(),
            object_count: count_table(&db, "objects")?,
            chunk_count: count_table(&db, "chunks")?,
            stored_bytes: sum_chunk_bytes(&db)?,
            index_shard_count: count_table(&db, "index_shards")?,
            key_grant_count: count_table(&db, "key_grants")?,
            pin_lease_count: count_table(&db, "pin_leases")?,
            pin_intent_count: count_table(&db, "pin_intents")?,
            pin_attestation_count: count_table(&db, "pin_attestations")?,
            materialized_entry_count: count_table(&db, "materialized_entries")?,
            logical_deleted_object_count: count_where(
                &db,
                "objects",
                "logical_deleted_at is not null",
            )?,
            missing_chunk_count,
            evidence_refs: vec![
                "storage:sqlite:local".to_string(),
                "storage:blob-dir:local".to_string(),
            ],
            blocked_reasons,
            sampled_at,
            expires_at: Some(sampled_at + 60),
        };
        validate_storage_backend_posture(&posture)?;
        Ok(posture)
    }

    pub fn backend_snapshot(
        &self,
        storage_member_ref: impl AsRef<str>,
        limit: usize,
        captured_at: u64,
    ) -> Result<StorageBackendSnapshot> {
        let captured_at = if captured_at == 0 {
            now_seconds()
        } else {
            captured_at
        };
        let capped_at = if limit == 0 { 64 } else { limit.min(512) };
        let posture = self.backend_posture(storage_member_ref.as_ref(), captured_at)?;
        let db = self.lock_db()?;
        let snapshot = StorageBackendSnapshot {
            kind: Some(RECORD_STORAGE_BACKEND_SNAPSHOT.to_string()),
            snapshot_id: format!("storage-backend-snapshot:local:{captured_at}"),
            backend_id: posture.backend_id.clone(),
            storage_member_ref: posture.storage_member_ref.clone(),
            posture_ref: posture.posture_id,
            object_count: posture.object_count,
            chunk_count: posture.chunk_count,
            pin_lease_count: posture.pin_lease_count,
            pin_intent_count: posture.pin_intent_count,
            pin_attestation_count: posture.pin_attestation_count,
            materialized_entry_count: posture.materialized_entry_count,
            object_refs: load_prefixed_refs(
                &db,
                "select object_id from objects order by created_at desc, object_id asc limit ?1",
                "storage:object:",
                capped_at,
            )?,
            chunk_refs: load_prefixed_refs(
                &db,
                "select hash from chunks order by last_accessed_at desc, hash asc limit ?1",
                "storage:chunk:",
                capped_at,
            )?,
            pin_lease_refs: load_prefixed_refs(
                &db,
                "select pin_id from pin_leases order by created_at desc, pin_id asc limit ?1",
                "storage:pin-lease:",
                capped_at,
            )?,
            pin_intent_refs: load_prefixed_refs(
                &db,
                "select intent_id from pin_intents order by created_at desc, intent_id asc limit ?1",
                "storage:pin-intent:",
                capped_at,
            )?,
            pin_projection_refs: load_prefixed_refs(
                &db,
                "select intent_id from pin_intents order by created_at desc, intent_id asc limit ?1",
                "storage:pin-projection:",
                capped_at,
            )?,
            capped_at: capped_at as u64,
            captured_at,
            expires_at: Some(captured_at + 60),
        };
        validate_storage_backend_snapshot(&snapshot)?;
        Ok(snapshot)
    }

    pub fn cybersec_evidence_custody_posture(
        &self,
        storage_member_ref: impl AsRef<str>,
        finding_ref: impl AsRef<str>,
        processor_report_ref: impl AsRef<str>,
        subject_ref: impl AsRef<str>,
        detail_refs: Vec<String>,
        access_group_refs: Vec<String>,
        issued_at: u64,
    ) -> Result<CybersecEvidenceHoldRecord> {
        let issued_at = if issued_at == 0 {
            now_seconds()
        } else {
            issued_at
        };
        let posture = self.backend_posture(storage_member_ref.as_ref(), issued_at)?;
        let state = if posture.state == STORAGE_BACKEND_STATE_READY {
            "holding"
        } else {
            "blocked"
        };
        let mut blocked_reasons = posture.blocked_reasons.clone();
        if state == "blocked" && blocked_reasons.is_empty() {
            blocked_reasons.push("storage.backend.not-ready".to_string());
        }
        let hold = CybersecEvidenceHoldRecord {
            kind: Some(RECORD_CYBERSEC_EVIDENCE_HOLD.to_string()),
            hold_id: format!(
                "cybersec:evidence-hold:storage:{}",
                sha256_hex(format!(
                    "{}|{}|{}|{}",
                    finding_ref.as_ref(),
                    processor_report_ref.as_ref(),
                    subject_ref.as_ref(),
                    issued_at
                ))
            ),
            finding_ref: finding_ref.as_ref().to_string(),
            processor_report_ref: processor_report_ref.as_ref().to_string(),
            subject_ref: subject_ref.as_ref().to_string(),
            state: state.to_string(),
            event_refs: Vec::new(),
            detail_refs,
            storage_refs: vec![posture.backend_id.clone(), posture.posture_id.clone()],
            retention_demand_refs: vec!["retention:cybersec:evidence:storage.local".to_string()],
            access_group_refs,
            evidence_refs: posture.evidence_refs.clone(),
            safe_facts: serde_json::json!({
                "custody": "storageFulfillment",
                "accessAuthority": "notOwned",
                "threatSemantics": "notOwned",
                "objectCount": posture.object_count,
                "chunkCount": posture.chunk_count,
                "storedBytes": posture.stored_bytes,
                "missingChunkCount": posture.missing_chunk_count
            }),
            blocked_reasons,
            issued_at,
            expires_at: Some(issued_at + 60),
        };
        validate_cybersec_evidence_hold(&hold)?;
        Ok(hold)
    }

    pub fn host_fabric_storage_contribution(
        &self,
        storage_member_ref: impl AsRef<str>,
        fabric_ref: impl AsRef<str>,
        host_ref: impl AsRef<str>,
        sampled_at: u64,
    ) -> Result<HostFabricMemberContribution> {
        let posture = self.backend_posture(storage_member_ref.as_ref(), sampled_at)?;
        let snapshot =
            self.backend_snapshot(storage_member_ref.as_ref(), 64, posture.sampled_at)?;
        let running = posture.state == STORAGE_BACKEND_STATE_READY;
        let contribution =
            build_host_fabric_member_contribution(HostFabricMemberContributionSpec {
                contribution_id: format!(
                    "fabric-contribution:storage-journal-cache:{}",
                    posture.sampled_at
                ),
                fabric_ref: fabric_ref.as_ref().to_string(),
                host_ref: host_ref.as_ref().to_string(),
                member_ref: posture.storage_member_ref.clone(),
                participant_ref: posture.storage_member_ref.clone(),
                role: FABRIC_MEMBER_ROLE_STORAGE_JOURNAL_CACHE.to_string(),
                role_ref: format!("role:{FABRIC_MEMBER_ROLE_STORAGE_JOURNAL_CACHE}"),
                state: if running {
                    FABRIC_MEMBER_CONTRIBUTION_RUNNING.to_string()
                } else {
                    FABRIC_MEMBER_CONTRIBUTION_DEGRADED.to_string()
                },
                contract_ref: posture.backend_id.clone(),
                subject_ref: posture.backend_id.clone(),
                module_refs: vec![
                    "module:storage-journal".to_string(),
                    "module:storage-cache".to_string(),
                    posture.backend_kind.clone(),
                ],
                source_refs: vec![posture.root_ref.clone()],
                capability_refs: vec![
                    "capability:storage:journal".to_string(),
                    "capability:storage:cache".to_string(),
                    "capability:storage:pin".to_string(),
                ],
                grant_refs: Vec::new(),
                input_refs: vec![posture.root_ref.clone()],
                output_refs: vec![
                    posture.posture_id.clone(),
                    snapshot.snapshot_id.clone(),
                    posture.backend_id.clone(),
                ],
                evidence_refs: posture.evidence_refs.clone(),
                lifecycle_plan_refs: vec![format!(
                    "lifecycle-plan:storage-journal-cache:{}",
                    posture.backend_id.replace(':', "-")
                )],
                release_refs: Vec::new(),
                resource_posture: None,
                blocked_reasons: posture.blocked_reasons.clone(),
                safe_facts: serde_json::json!({
                    "backendKind": posture.backend_kind,
                    "objectCount": posture.object_count,
                    "chunkCount": posture.chunk_count,
                    "pinLeaseCount": posture.pin_lease_count,
                    "pinIntentCount": posture.pin_intent_count,
                    "materializedEntryCount": posture.materialized_entry_count,
                    "missingChunkCount": posture.missing_chunk_count
                }),
                observed_at: posture.sampled_at,
                expires_at: posture.expires_at,
            })?;
        constitute_protocol::validate_host_fabric_member_contribution(&contribution)?;
        Ok(contribution)
    }

    pub fn filesystem_view(
        &self,
        storage_member_ref: impl AsRef<str>,
        limit: usize,
        captured_at: u64,
    ) -> Result<StorageFilesystemView> {
        let captured_at = if captured_at == 0 {
            now_seconds()
        } else {
            captured_at
        };
        let capped_at = if limit == 0 { 64 } else { limit.min(512) };
        let posture = self.backend_posture(storage_member_ref.as_ref(), captured_at)?;
        let db = self.lock_db()?;
        let mut entries = Vec::new();
        let mut object_stmt = db.prepare(
            "select o.object_id, o.container_id, o.manifest_json, o.logical_deleted_at, coalesce(sum(c.size), 0) \
             from objects o \
             left join object_chunks oc on oc.object_id = o.object_id \
             left join chunks c on c.hash = oc.chunk_hash \
             group by o.object_id, o.container_id, o.manifest_json, o.logical_deleted_at, o.last_accessed_at \
             order by o.last_accessed_at desc, o.object_id asc \
             limit ?1",
        )?;
        let object_rows = object_stmt.query_map(params![capped_at as i64], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<u64>>(3)?,
                row.get::<_, u64>(4)?,
            ))
        })?;
        for row in object_rows {
            let (object_id, container_id, manifest_json, logical_deleted_at, size) = row?;
            let manifest: StorageObjectManifest = serde_json::from_str(&manifest_json)?;
            entries.push(StorageFilesystemEntry {
                entry_ref: format!("storage-filesystem-entry:object:{object_id}"),
                path: format!(
                    "objects/{}/{}.manifest.json",
                    storage_virtual_component(&container_id),
                    storage_virtual_component(&object_id)
                ),
                object_ref: Some(format!("storage:object:{object_id}")),
                chunk_ref: None,
                media_type: if manifest.media_type.trim().is_empty() {
                    "application/octet-stream".to_string()
                } else {
                    manifest.media_type
                },
                size,
                logical_deleted_at,
            });
        }
        let remaining = capped_at.saturating_sub(entries.len());
        if remaining > 0 {
            let mut chunk_stmt = db.prepare(
                "select hash, size from chunks order by last_accessed_at desc, hash asc limit ?1",
            )?;
            let chunk_rows = chunk_stmt.query_map(params![remaining as i64], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?))
            })?;
            for row in chunk_rows {
                let (hash, size) = row?;
                let prefix = hash.get(0..2).unwrap_or("xx");
                entries.push(StorageFilesystemEntry {
                    entry_ref: format!("storage-filesystem-entry:chunk:{hash}"),
                    path: format!(
                        "chunks/{}/{}.bin",
                        storage_virtual_component(prefix),
                        storage_virtual_component(&hash)
                    ),
                    object_ref: None,
                    chunk_ref: Some(format!("storage:chunk:{hash}")),
                    media_type: "application/octet-stream".to_string(),
                    size,
                    logical_deleted_at: None,
                });
            }
        }

        let state = if posture.state == STORAGE_BACKEND_STATE_READY {
            STORAGE_FILESYSTEM_VIEW_READY
        } else {
            STORAGE_FILESYSTEM_VIEW_DEGRADED
        };
        let view = StorageFilesystemView {
            kind: Some(RECORD_STORAGE_FILESYSTEM_VIEW.to_string()),
            view_id: format!("storage-filesystem-view:local:{captured_at}"),
            backend_id: posture.backend_id,
            storage_member_ref: posture.storage_member_ref,
            root_ref: posture.root_ref,
            state: state.to_string(),
            view_mode: "virtualReadOnly".to_string(),
            materialization_ref: "materialization:storage:filesystem-view:local".to_string(),
            object_count: posture.object_count,
            chunk_count: posture.chunk_count,
            entry_count: entries.len() as u64,
            entries,
            capped_at: capped_at as u64,
            evidence_refs: vec![
                "storage:backend:snapshot".to_string(),
                "storage:filesystem-view:virtual".to_string(),
            ],
            blocked_reasons: posture.blocked_reasons,
            captured_at,
            expires_at: Some(captured_at + 60),
        };
        validate_storage_filesystem_view(&view)?;
        Ok(view)
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

    pub fn put_source_object(
        &self,
        request: PutSourceObjectRequest,
    ) -> Result<SourceObjectStorageResponse> {
        validate_source_object_request(&request)?;
        let now = if request.issued_at == 0 {
            now_seconds()
        } else {
            request.issued_at
        };
        let object_ref = storage_object_ref(&request.manifest);
        let object = self.put_object(PutObjectRequest {
            manifest: request.manifest.clone(),
            chunks: request.chunks,
        })?;
        let graph_edge = self.put_graph_edge(StorageGraphEdge {
            edge_id: format!(
                "storage:graph-edge:{}",
                short_storage_id(&format!(
                    "{}|{}|{}",
                    request.source_snapshot_ref, object_ref, now
                ))
            ),
            container_id: request.manifest.container_id.clone(),
            from_ref: request.source_snapshot_ref.clone(),
            relation: RELATION_SOURCE_SNAPSHOT_STORES.to_string(),
            to_ref: object_ref.clone(),
            detail_ref: None,
            created_at: now,
        })?;
        let pin_intent = StoragePinIntent {
            intent_id: format!(
                "storage-pin-intent:{}",
                short_storage_id(&format!(
                    "{}|{}|{}",
                    request.source_graph_ref, object_ref, now
                ))
            ),
            object_refs: vec![object_ref.clone()],
            manifest_hash: format!("storage:manifest:{}", request.manifest.content_hash),
            desired_replicas: request.desired_replicas,
            retention: request.retention,
            authority_refs: request.authority_refs,
            expires_at: request.expires_at,
        };
        let pin_intent = self.put_pin_intent(pin_intent)?;
        let pin_attestation = StoragePinAttestation {
            attestation_id: format!(
                "storage-pin-attestation:{}",
                short_storage_id(&format!(
                    "{}|{}|{}",
                    pin_intent.intent.intent_id, request.storage_member_ref, now
                ))
            ),
            intent_id: pin_intent.intent.intent_id.clone(),
            storage_member_ref: request.storage_member_ref.clone(),
            accepted_refs: vec![object_ref.clone()],
            availability_refs: vec![SwarmStorageAvailabilityRef {
                availability_id: format!(
                    "storage-availability:{}",
                    short_storage_id(&format!(
                        "{}|{}|{}",
                        object_ref, request.storage_member_ref, now
                    ))
                ),
                object_ref,
                storage_member_ref: request.storage_member_ref,
                expires_at: request.expires_at,
            }],
            status: StoragePinStatus::Pinned,
            expires_at: request.expires_at,
            issued_at: now,
        };
        let pin_attestation = self.put_pin_attestation(pin_attestation, now)?;
        Ok(SourceObjectStorageResponse {
            object,
            graph_edge,
            pin_intent,
            pin_attestation,
        })
    }

    pub fn materialize_module(
        &self,
        request: ModuleMaterializationRequest,
    ) -> Result<ModuleMaterializationResponse> {
        validate_module_materialization_request(&request)?;
        let now = if request.issued_at == 0 {
            now_seconds()
        } else {
            request.issued_at
        };
        let module_ref = request.module_ref.clone();
        let content_index_ref = request.content_index_ref.clone();
        let artifact_ref = request.artifact_ref.clone();
        let materialized_path_ref = request.materialized_path_ref.clone();
        let storage_member_ref = request.storage_member_ref.clone();
        let object_ref = storage_object_ref(&request.manifest);
        let byte_length = request
            .chunks
            .iter()
            .map(|chunk| chunk.chunk_ref.size)
            .sum();
        let chunk_count = request.chunks.len() as u64;
        let cache_refs = if request.cache_refs.is_empty() {
            vec![format!(
                "storage:cache:module:{}",
                storage_virtual_component(&module_ref)
            )]
        } else {
            request.cache_refs.clone()
        };
        let conflict_refs = request.conflict_refs.clone();
        let adapter_residency_refs = request.adapter_residency_refs.clone();
        let legacy_transition_conflict_refs = request.legacy_transition_conflict_refs.clone();
        let source_object = self.put_source_object(PutSourceObjectRequest {
            source_graph_ref: request.source_graph_ref,
            source_snapshot_ref: request.source_snapshot_ref.clone(),
            storage_member_ref: request.storage_member_ref,
            manifest: request.manifest,
            chunks: request.chunks,
            authority_refs: request.authority_refs,
            desired_replicas: request.desired_replicas,
            retention: request.retention,
            expires_at: request.expires_at,
            issued_at: now,
        })?;
        let backend_posture = self.backend_posture(&storage_member_ref, now)?;
        let projection = &source_object.pin_attestation.projection;
        let availability_refs = projection
            .availability
            .iter()
            .map(|availability| availability.availability_id.clone())
            .collect::<Vec<_>>();
        let mut blocked_reasons = backend_posture.blocked_reasons.clone();
        if projection.status != StoragePinProjectionStatus::Satisfied {
            blocked_reasons.push(format!(
                "storage.module.pin.missing-replicas:{}",
                projection.missing_replicas
            ));
        }
        let state = if backend_posture.state == STORAGE_BACKEND_STATE_READY
            && projection.status == StoragePinProjectionStatus::Satisfied
            && blocked_reasons.is_empty()
        {
            STORAGE_MODULE_MATERIALIZATION_MATERIALIZED
        } else if backend_posture.state == STORAGE_BACKEND_STATE_DEGRADED {
            STORAGE_MODULE_MATERIALIZATION_DEGRADED
        } else {
            STORAGE_MODULE_MATERIALIZATION_BLOCKED
        };
        let posture = StorageModuleMaterializationPosture {
            kind: Some(RECORD_STORAGE_MODULE_MATERIALIZATION_POSTURE.to_string()),
            posture_id: format!(
                "storage-module-materialization-posture:{}",
                short_storage_id(&format!("{module_ref}|{artifact_ref}|{now}"))
            ),
            storage_member_ref,
            module_ref: module_ref.clone(),
            source_snapshot_ref: request.source_snapshot_ref,
            content_index_ref,
            artifact_ref,
            materialization_ref: format!(
                "storage:module-materialization:{}",
                short_storage_id(&format!("{module_ref}|{object_ref}|{now}"))
            ),
            materialized_path_ref,
            state: state.to_string(),
            object_refs: vec![object_ref.clone()],
            pin_intent_refs: vec![format!(
                "storage:pin-intent:{}",
                source_object.pin_intent.intent.intent_id
            )],
            pin_attestation_refs: vec![format!(
                "storage:pin-attestation:{}",
                source_object.pin_attestation.attestation.attestation_id
            )],
            availability_refs,
            cache_refs,
            evidence_refs: vec![
                backend_posture.backend_id,
                backend_posture.posture_id,
                source_object.graph_edge.edge_id.clone(),
            ],
            conflict_refs,
            adapter_residency_refs,
            legacy_transition_conflict_refs,
            blocked_reasons,
            byte_length,
            chunk_count,
            safe_facts: serde_json::json!({
                "storageRole": "byteCacheJournal",
                "sourceTruthOwner": "sourceRefs",
                "sourceSemanticOwner": "notStorage",
                "objectCount": 1,
                "chunkCount": chunk_count,
                "byteLength": byte_length,
                "pinProjectionStatus": format!("{:?}", projection.status),
                "missingReplicas": projection.missing_replicas
            }),
            materialized_at: now,
            expires_at: request.expires_at.or(Some(now + 60)),
        };
        validate_storage_module_materialization_posture(&posture)?;
        Ok(ModuleMaterializationResponse {
            source_object,
            posture,
        })
    }

    pub fn instantiate_module_executable(
        &self,
        request: ModuleExecutableInstantiationRequest,
    ) -> Result<ModuleExecutableInstantiationResponse> {
        validate_module_executable_instantiation_request(&request)?;
        let now = if request.issued_at == 0 {
            now_seconds()
        } else {
            request.issued_at
        };
        let object_id = storage_object_id_from_ref(&request.object_ref)?;
        let object = self.get_object(&object_id)?;
        let mut object_bytes = Vec::new();
        for chunk in &object.chunks {
            let bytes = decode_chunk(chunk)?;
            validate_storage_chunk_ref(&chunk.chunk_ref, &bytes)?;
            object_bytes.extend(bytes);
        }
        let byte_length = object
            .manifest
            .chunks
            .iter()
            .map(|chunk| chunk.size)
            .sum::<u64>();
        let chunk_count = object.manifest.chunks.len() as u64;
        let media_type = object.manifest.media_type.clone();
        let executable_hash = sha256_hex(&object_bytes);
        let executable_hash_ref = format!("sha256:{executable_hash}");
        let executable_ref = format!(
            "executable:module:{}:{}",
            storage_virtual_component(&request.module_ref),
            short_storage_id(&executable_hash)
        );
        let posture = StorageModuleExecutableInstantiationPosture {
            kind: Some(RECORD_STORAGE_MODULE_EXECUTABLE_INSTANTIATION_POSTURE.to_string()),
            posture_id: format!(
                "storage-module-executable-instantiation-posture:{}",
                short_storage_id(&format!(
                    "{}|{}|{}",
                    request.module_ref, request.object_ref, now
                ))
            ),
            storage_member_ref: request.storage_member_ref,
            module_ref: request.module_ref,
            source_snapshot_ref: request.source_snapshot_ref,
            content_index_ref: request.content_index_ref,
            artifact_ref: request.artifact_ref,
            materialization_ref: request.materialization_ref,
            materialization_posture_ref: request.materialization_posture_ref,
            object_ref: request.object_ref,
            executable_ref,
            executable_hash_ref,
            media_type: media_type.clone(),
            state: STORAGE_MODULE_EXECUTABLE_INSTANTIATED.to_string(),
            evidence_refs: vec![
                format!("storage:manifest:{}", object.manifest.content_hash),
                format!("storage:object:{}", object.manifest.object_id),
            ],
            conflict_refs: request.conflict_refs,
            adapter_residency_refs: request.adapter_residency_refs,
            legacy_transition_conflict_refs: request.legacy_transition_conflict_refs,
            blocked_reasons: vec![],
            byte_length,
            chunk_count,
            safe_facts: serde_json::json!({
                "storageRole": "byteCacheJournal",
                "sourceSemanticOwner": "notStorage",
                "loadOwner": "runner",
                "objectAddressed": true,
                "objectMediaType": media_type,
                "objectChunkCount": chunk_count
            }),
            instantiated_at: now,
            expires_at: request.expires_at.or(Some(now + 60)),
        };
        validate_storage_module_executable_instantiation_posture(&posture)?;
        Ok(ModuleExecutableInstantiationResponse { posture })
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
        for edge in &request.shard.graph_edges {
            insert_graph_edge(&tx, edge)?;
        }
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

    pub fn put_graph_edge(&self, edge: StorageGraphEdge) -> Result<StorageGraphEdge> {
        validate_storage_graph_edge(&edge)?;
        let db = self.lock_db()?;
        insert_graph_edge(&db, &edge)?;
        self.emit(
            "graph_edge.stored",
            "normal",
            Some(&edge.container_id),
            None,
            "storage graph edge stored",
        );
        Ok(edge)
    }

    pub fn graph_edges(
        &self,
        container_id: Option<&str>,
        from_ref: Option<&str>,
        relation: Option<&str>,
        to_ref: Option<&str>,
        limit: usize,
    ) -> Result<GraphEdgeSearchResponse> {
        let capped_at = if limit == 0 { 64 } else { limit.min(512) };
        let db = self.lock_db()?;
        let mut stmt = db.prepare(
            "select edge_json from graph_edges
             where (?1 is null or container_id = ?1)
               and (?2 is null or from_ref = ?2)
               and (?3 is null or relation = ?3)
               and (?4 is null or to_ref = ?4)
             order by created_at desc, edge_id asc
             limit ?5",
        )?;
        let rows = stmt.query_map(
            params![container_id, from_ref, relation, to_ref, capped_at as i64],
            |row| row.get::<_, String>(0),
        )?;
        let mut edges = Vec::new();
        for row in rows {
            let edge: StorageGraphEdge = serde_json::from_str(&row?)?;
            validate_storage_graph_edge(&edge)?;
            edges.push(edge);
        }
        Ok(GraphEdgeSearchResponse { edges })
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
        let mut release_postures = Vec::new();
        let mut blocked_chunks = 0usize;
        for row in rows {
            let (hash, path, size) = row?;
            let pinned: i64 = db.query_row(
                "select count(*) from pin_leases where (chunk_hash = ?1 or object_id in (select object_id from object_chunks where chunk_hash = ?1)) and (expires_at is null or expires_at > ?2)",
                params![hash, now],
                |row| row.get(0),
            )?;
            let live_roots: i64 = db.query_row(
                "select count(*) from object_chunks oc join objects o on o.object_id = oc.object_id where oc.chunk_hash = ?1 and o.logical_deleted_at is null",
                params![hash],
                |row| row.get(0),
            )?;
            let posture =
                storage_retention_release_posture(&request, &hash, now, pinned, live_roots)?;
            let freeable = posture.state == "freeable";
            if !freeable {
                blocked_chunks += 1;
            }
            release_postures.push(posture);
            if freeable {
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
            evaluated_chunks: release_postures.len(),
            blocked_chunks,
            pruned_chunks,
            pruned_bytes,
            release_postures,
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
        create table if not exists graph_edges (
            edge_id text primary key,
            container_id text not null,
            from_ref text not null,
            relation text not null,
            to_ref text not null,
            edge_json text not null,
            created_at integer not null
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

fn insert_graph_edge(conn: &Connection, edge: &StorageGraphEdge) -> Result<()> {
    validate_storage_graph_edge(edge)?;
    conn.execute(
        "insert or replace into graph_edges (edge_id, container_id, from_ref, relation, to_ref, edge_json, created_at) values (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            edge.edge_id,
            edge.container_id,
            edge.from_ref,
            edge.relation,
            edge.to_ref,
            serde_json::to_string(edge)?,
            edge.created_at
        ],
    )?;
    Ok(())
}

fn count_where(conn: &Connection, table: &str, predicate: &str) -> Result<u64> {
    let sql = format!("select count(*) from {table} where {predicate}");
    let count: i64 = conn.query_row(&sql, [], |row| row.get(0))?;
    Ok(count as u64)
}

fn sum_chunk_bytes(conn: &Connection) -> Result<u64> {
    let total: i64 = conn.query_row("select coalesce(sum(size), 0) from chunks", [], |row| {
        row.get(0)
    })?;
    Ok(total as u64)
}

fn count_missing_chunk_files(conn: &Connection) -> Result<u64> {
    let mut stmt = conn.prepare("select path from chunks")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    let mut missing = 0u64;
    for row in rows {
        let path = row?;
        if fs::metadata(path).is_err() {
            missing += 1;
        }
    }
    Ok(missing)
}

fn load_prefixed_refs(
    conn: &Connection,
    sql: &str,
    prefix: &str,
    limit: usize,
) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map(params![limit as i64], |row| row.get::<_, String>(0))?;
    let mut refs = Vec::new();
    for row in rows {
        refs.push(format!("{prefix}{}", row?));
    }
    Ok(refs)
}

fn storage_virtual_component(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() { "_".to_string() } else { out }
}

fn storage_object_ref(manifest: &StorageObjectManifest) -> String {
    format!("storage:object:{}", manifest.object_id)
}

fn storage_object_id_from_ref(object_ref: &str) -> Result<String> {
    let object_id = object_ref
        .trim()
        .strip_prefix("storage:object:")
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.to_string())
        .ok_or_else(|| anyhow!("storage object ref must start with storage:object:"))?;
    if object_id.len() == 64 && object_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(object_id)
    } else {
        Err(anyhow!("storage object ref must be content-addressed"))
    }
}

fn short_storage_id(value: &str) -> String {
    sha256_hex(value).chars().take(16).collect()
}

fn validate_resolved_member_ref(value: &str, context: &str) -> Result<()> {
    validate_virtual_ref(value, context)?;
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(anyhow!("{context} must be a resolved public key"))
    }
}

fn validate_source_object_request(request: &PutSourceObjectRequest) -> Result<()> {
    validate_virtual_ref(&request.source_graph_ref, "source object sourceGraphRef")?;
    validate_virtual_ref(
        &request.source_snapshot_ref,
        "source object sourceSnapshotRef",
    )?;
    validate_resolved_member_ref(
        &request.storage_member_ref,
        "source object storageMemberRef",
    )?;
    validate_storage_manifest(&request.manifest)?;
    if request.chunks.is_empty() {
        return Err(anyhow!("source object put requires chunks"));
    }
    if request.authority_refs.is_empty() {
        return Err(anyhow!("source object pin requires authorityRefs"));
    }
    if request.desired_replicas == 0 {
        return Err(anyhow!("source object desiredReplicas must be positive"));
    }
    if request.issued_at == 0 {
        return Err(anyhow!("source object missing issuedAt"));
    }
    if request
        .expires_at
        .is_some_and(|expires_at| expires_at <= request.issued_at)
    {
        return Err(anyhow!("source object expiresAt must be after issuedAt"));
    }
    validate_ref_slice(&request.authority_refs, "source object authorityRefs")
}

fn validate_module_materialization_request(request: &ModuleMaterializationRequest) -> Result<()> {
    validate_virtual_ref(&request.module_ref, "module materialization moduleRef")?;
    validate_virtual_ref(
        &request.source_graph_ref,
        "module materialization sourceGraphRef",
    )?;
    validate_virtual_ref(
        &request.source_snapshot_ref,
        "module materialization sourceSnapshotRef",
    )?;
    validate_virtual_ref(
        &request.content_index_ref,
        "module materialization contentIndexRef",
    )?;
    validate_virtual_ref(&request.artifact_ref, "module materialization artifactRef")?;
    validate_virtual_ref(
        &request.materialized_path_ref,
        "module materialization materializedPathRef",
    )?;
    validate_resolved_member_ref(
        &request.storage_member_ref,
        "module materialization storageMemberRef",
    )?;
    validate_ref_slice(
        &request.authority_refs,
        "module materialization authorityRefs",
    )?;
    validate_ref_slice(&request.cache_refs, "module materialization cacheRefs")?;
    validate_ref_slice(
        &request.conflict_refs,
        "module materialization conflictRefs",
    )?;
    validate_ref_slice(
        &request.adapter_residency_refs,
        "module materialization adapterResidencyRefs",
    )?;
    validate_ref_slice(
        &request.legacy_transition_conflict_refs,
        "module materialization legacyTransitionConflictRefs",
    )?;
    if request.authority_refs.is_empty() {
        return Err(anyhow!("module materialization requires authorityRefs"));
    }
    if request.desired_replicas == 0 {
        return Err(anyhow!(
            "module materialization desiredReplicas must be positive"
        ));
    }
    if request.issued_at == 0 {
        return Err(anyhow!("module materialization missing issuedAt"));
    }
    validate_source_object_request(&PutSourceObjectRequest {
        source_graph_ref: request.source_graph_ref.clone(),
        source_snapshot_ref: request.source_snapshot_ref.clone(),
        storage_member_ref: request.storage_member_ref.clone(),
        manifest: request.manifest.clone(),
        chunks: request.chunks.clone(),
        authority_refs: request.authority_refs.clone(),
        desired_replicas: request.desired_replicas,
        retention: request.retention.clone(),
        expires_at: request.expires_at,
        issued_at: request.issued_at,
    })
}

fn validate_module_executable_instantiation_request(
    request: &ModuleExecutableInstantiationRequest,
) -> Result<()> {
    validate_virtual_ref(&request.module_ref, "module executable moduleRef")?;
    validate_virtual_ref(
        &request.source_snapshot_ref,
        "module executable sourceSnapshotRef",
    )?;
    validate_virtual_ref(
        &request.content_index_ref,
        "module executable contentIndexRef",
    )?;
    validate_virtual_ref(&request.artifact_ref, "module executable artifactRef")?;
    validate_virtual_ref(
        &request.materialization_ref,
        "module executable materializationRef",
    )?;
    validate_virtual_ref(
        &request.materialization_posture_ref,
        "module executable materializationPostureRef",
    )?;
    validate_virtual_ref(&request.object_ref, "module executable objectRef")?;
    storage_object_id_from_ref(&request.object_ref)?;
    validate_resolved_member_ref(
        &request.storage_member_ref,
        "module executable storageMemberRef",
    )?;
    validate_ref_slice(&request.conflict_refs, "module executable conflictRefs")?;
    validate_ref_slice(
        &request.adapter_residency_refs,
        "module executable adapterResidencyRefs",
    )?;
    validate_ref_slice(
        &request.legacy_transition_conflict_refs,
        "module executable legacyTransitionConflictRefs",
    )?;
    if request.issued_at == 0 {
        return Err(anyhow!("module executable missing issuedAt"));
    }
    if request
        .expires_at
        .is_some_and(|expires_at| expires_at <= request.issued_at)
    {
        return Err(anyhow!(
            "module executable expiresAt must be after issuedAt"
        ));
    }
    Ok(())
}

fn validate_ref_slice(refs: &[String], context: &str) -> Result<()> {
    for value in refs {
        validate_virtual_ref(value, context)?;
    }
    Ok(())
}

fn validate_virtual_ref(value: &str, context: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(anyhow!("{context} missing ref"));
    }
    if value.chars().any(char::is_whitespace)
        || value.contains('\\')
        || value.starts_with('/')
        || value.starts_with("file:")
        || value.starts_with("http:")
        || value.starts_with("https:")
    {
        return Err(anyhow!("{context} must be a virtual ref"));
    }
    Ok(())
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

fn storage_retention_release_posture(
    request: &PruneRequest,
    chunk_hash: &str,
    now: u64,
    active_pins: i64,
    live_roots: i64,
) -> Result<RetentionReleasePosture> {
    let effective_retention = normalize_storage_retention_class(&request.retention_class);
    let mut blockers = Vec::new();
    if let Some(valid_until) = request.valid_until {
        if valid_until > now
            && request.supersession_refs.is_empty()
            && request.retraction_refs.is_empty()
            && request.revocation_refs.is_empty()
        {
            blockers.push(serde_json::json!({
                "code": "validity.active",
                "validUntil": valid_until,
            }));
        }
    }
    if let Some(release_after) = request.release_after {
        if release_after > now {
            blockers.push(serde_json::json!({
                "code": "releaseAfter.pending",
                "releaseAfter": release_after,
            }));
        }
    }
    if request.require_witness && request.witness_refs.is_empty() {
        blockers.push(serde_json::json!({ "code": "witness.missing" }));
    }
    if active_pins > 0 {
        blockers.push(serde_json::json!({
            "code": "activePin",
            "count": active_pins,
        }));
    }
    if live_roots > 0 {
        blockers.push(serde_json::json!({
            "code": "liveRoot",
            "count": live_roots,
        }));
    }
    if !retention_allows_unfulfilled_release(&effective_retention)
        && request.fulfillment_refs.is_empty()
    {
        blockers.push(serde_json::json!({ "code": "fulfillment.missing" }));
    }
    let default_policy_ref = format!("policy:storage.retention.{effective_retention}");
    let policy_refs = normalized_refs(&request.policy_refs, &[default_policy_ref.as_str()]);
    let posture = RetentionReleasePosture {
        kind: Some(RECORD_RETENTION_RELEASE.to_string()),
        evaluation_id: format!("storage-prune:{chunk_hash}:{now}"),
        subject_ref: format!("storage:chunk:{chunk_hash}"),
        effective_retention,
        state: if blockers.is_empty() {
            "freeable".to_string()
        } else {
            "releaseBlocked".to_string()
        },
        policy_refs,
        overlay_refs: normalized_refs(&request.overlay_refs, &["overlay:none"]),
        owner_refs: normalized_refs(&request.owner_refs, &["storage:local"]),
        holder_refs: normalized_refs(&request.holder_refs, &["storage:local"]),
        fulfillment_refs: normalized_refs(&request.fulfillment_refs, &[]),
        residency_layers: normalized_refs(&request.residency_layers, &["storageLocalBlob"]),
        witness_refs: normalized_refs(&request.witness_refs, &[]),
        supersession_refs: normalized_refs(&request.supersession_refs, &[]),
        retraction_refs: normalized_refs(&request.retraction_refs, &[]),
        revocation_refs: normalized_refs(&request.revocation_refs, &[]),
        blockers,
        valid_until: request.valid_until,
        release_after: request.release_after,
        evaluated_at: now,
    };
    validate_retention_release_posture(&posture)?;
    Ok(posture)
}

fn retention_allows_unfulfilled_release(retention_class: &str) -> bool {
    matches!(
        retention_class,
        "ephemeral" | "disposable" | "session" | "cache"
    )
}

fn normalize_storage_retention_class(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        "durable".to_string()
    } else {
        trimmed.to_string()
    }
}

fn normalized_refs(values: &[String], defaults: &[&str]) -> Vec<String> {
    let mut refs = Vec::new();
    for value in values {
        let trimmed = value.trim();
        if !trimmed.is_empty() && !refs.iter().any(|item| item == trimmed) {
            refs.push(trimmed.to_string());
        }
    }
    for value in defaults {
        if !value.is_empty() && !refs.iter().any(|item| item == value) {
            refs.push((*value).to_string());
        }
    }
    refs
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
        StorageChunkRef, StorageGraphEdge, StorageObjectManifest, StoragePinAttestation,
        StoragePinIntent, StoragePinProjectionStatus, StoragePinStatus,
        SwarmStorageAvailabilityRef, storage_chunk_id, storage_ciphertext_hash, storage_object_id,
    };
    use tempfile::tempdir;

    use super::*;

    const TEST_STORAGE_MEMBER_REF: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const TEST_STORAGE_MEMBER_REF_TWO: &str =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const TEST_OBJECT_REF: &str =
        "storage:object:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const TEST_APP_OBJECT_REF: &str =
        "storage:object:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

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
    fn source_object_put_stores_edges_and_pin_availability_without_source_semantics() {
        let dir = tempdir().expect("tempdir");
        let engine = StorageEngine::open(dir.path()).expect("engine");
        let chunk = chunk(b"source-pack-ciphertext");
        let manifest = manifest("storage:container:source-graph", "source:key:pack", &chunk);
        let object_ref = format!("storage:object:{}", manifest.object_id);

        let response = engine
            .put_source_object(PutSourceObjectRequest {
                source_graph_ref: "source:graph:constitute-git".to_string(),
                source_snapshot_ref: "source:snapshot:head".to_string(),
                storage_member_ref: TEST_STORAGE_MEMBER_REF.to_string(),
                manifest: manifest.clone(),
                chunks: vec![chunk.clone()],
                authority_refs: vec!["authority:source:graph".to_string()],
                desired_replicas: 1,
                retention: "source-object".to_string(),
                expires_at: Some(1_700_000_100),
                issued_at: 1_700_000_000,
            })
            .expect("put source object");

        assert_eq!(response.object.manifest.object_id, manifest.object_id);
        assert_eq!(response.graph_edge.from_ref, "source:snapshot:head");
        assert_eq!(
            response.graph_edge.relation,
            RELATION_SOURCE_SNAPSHOT_STORES
        );
        assert_eq!(response.graph_edge.to_ref, object_ref);
        assert_eq!(response.pin_intent.projection.missing_replicas, 1);
        assert_eq!(
            response.pin_attestation.projection.status,
            StoragePinProjectionStatus::Satisfied
        );
        assert_eq!(response.pin_attestation.projection.pinned_count, 1);
        assert_eq!(
            response.pin_attestation.projection.availability[0].object_ref,
            response.graph_edge.to_ref
        );

        let fetched = engine
            .get_object(&manifest.object_id)
            .expect("get source object");
        assert_eq!(fetched.chunks[0].ciphertext_base64, chunk.ciphertext_base64);
        let edges = engine
            .graph_edges(
                Some(&manifest.container_id),
                Some("source:snapshot:head"),
                Some(RELATION_SOURCE_SNAPSHOT_STORES),
                None,
                8,
            )
            .expect("source object graph edges");
        assert_eq!(edges.edges, vec![response.graph_edge]);
        let posture = engine
            .backend_posture(TEST_STORAGE_MEMBER_REF, 1_700_000_001)
            .expect("backend posture");
        assert_eq!(posture.pin_intent_count, 1);
        assert_eq!(posture.pin_attestation_count, 1);
    }

    #[test]
    fn module_materialization_stores_bytes_and_emits_storage_posture() {
        let dir = tempdir().expect("tempdir");
        let engine = StorageEngine::open(dir.path()).expect("engine");
        let chunk = chunk(b"module-source-pack-ciphertext");
        let manifest = manifest(
            "storage:container:module-pack",
            "source:key:module-pack",
            &chunk,
        );

        let response = engine
            .materialize_module(ModuleMaterializationRequest {
                module_ref: "module:native-dev:constitute-build".to_string(),
                source_graph_ref: "source:graph:native-dev:constitute-build".to_string(),
                source_snapshot_ref: "source:snapshot:native-dev:constitute-build:abc".to_string(),
                content_index_ref: "content-index:native-dev:constitute-build:abc".to_string(),
                artifact_ref: "artifact:native-dev:constitute-build:abc".to_string(),
                materialized_path_ref:
                    "materialized:path:storage-module:native-dev:constitute-build:abc".to_string(),
                storage_member_ref: TEST_STORAGE_MEMBER_REF.to_string(),
                manifest: manifest.clone(),
                chunks: vec![chunk],
                authority_refs: vec!["authority:source-build:operator".to_string()],
                desired_replicas: 1,
                retention: "module-materialization".to_string(),
                cache_refs: vec!["storage:cache:native-dev:constitute-build".to_string()],
                conflict_refs: vec![
                    "transition-conflict:constitute-build:cargo-git:constitute-protocol"
                        .to_string(),
                ],
                adapter_residency_refs: vec![
                    "transition-conflict:constitute-fabric:cargo-path:constitute-protocol"
                        .to_string(),
                ],
                legacy_transition_conflict_refs: vec![
                    "transition-conflict:constitute-fabric:cargo-path:constitute-protocol"
                        .to_string(),
                ],
                expires_at: Some(1_700_000_100),
                issued_at: 1_700_000_000,
            })
            .expect("materialize module");

        assert_eq!(
            response.posture.kind.as_deref(),
            Some(RECORD_STORAGE_MODULE_MATERIALIZATION_POSTURE)
        );
        assert_eq!(
            response.posture.state,
            STORAGE_MODULE_MATERIALIZATION_MATERIALIZED
        );
        assert_eq!(
            response.posture.source_snapshot_ref,
            "source:snapshot:native-dev:constitute-build:abc"
        );
        assert_eq!(
            response.posture.object_refs,
            vec![format!("storage:object:{}", manifest.object_id)]
        );
        assert_eq!(response.posture.chunk_count, 1);
        assert_eq!(
            response.posture.adapter_residency_refs,
            vec!["transition-conflict:constitute-fabric:cargo-path:constitute-protocol"]
        );
        assert_eq!(
            response.posture.legacy_transition_conflict_refs,
            response.posture.adapter_residency_refs
        );
        assert_eq!(
            response.posture.safe_facts["sourceSemanticOwner"],
            "notStorage"
        );
        assert!(
            serde_json::to_string(&response.posture)
                .expect("posture json")
                .contains("storage:pin-attestation:")
        );
        assert!(
            !serde_json::to_string(&response.posture)
                .expect("posture json")
                .contains(dir.path().to_string_lossy().as_ref())
        );

        let executable = engine
            .instantiate_module_executable(ModuleExecutableInstantiationRequest {
                module_ref: response.posture.module_ref.clone(),
                source_snapshot_ref: response.posture.source_snapshot_ref.clone(),
                content_index_ref: response.posture.content_index_ref.clone(),
                artifact_ref: response.posture.artifact_ref.clone(),
                materialization_ref: response.posture.materialization_ref.clone(),
                materialization_posture_ref: response.posture.posture_id.clone(),
                object_ref: response.posture.object_refs[0].clone(),
                storage_member_ref: TEST_STORAGE_MEMBER_REF.to_string(),
                conflict_refs: response.posture.conflict_refs.clone(),
                adapter_residency_refs: response.posture.adapter_residency_refs.clone(),
                legacy_transition_conflict_refs: response
                    .posture
                    .legacy_transition_conflict_refs
                    .clone(),
                expires_at: Some(1_700_000_100),
                issued_at: 1_700_000_001,
            })
            .expect("instantiate executable bytes");

        assert_eq!(
            executable.posture.kind.as_deref(),
            Some(RECORD_STORAGE_MODULE_EXECUTABLE_INSTANTIATION_POSTURE)
        );
        assert_eq!(
            executable.posture.state,
            STORAGE_MODULE_EXECUTABLE_INSTANTIATED
        );
        assert_eq!(
            executable.posture.object_ref,
            response.posture.object_refs[0]
        );
        assert!(
            executable
                .posture
                .executable_hash_ref
                .starts_with("sha256:")
        );
        assert_eq!(executable.posture.safe_facts["loadOwner"], "runner");
        assert_eq!(
            executable.posture.adapter_residency_refs,
            response.posture.adapter_residency_refs
        );
        assert_eq!(
            executable.posture.legacy_transition_conflict_refs,
            response.posture.legacy_transition_conflict_refs
        );
        assert_eq!(
            executable.posture.safe_facts["sourceSemanticOwner"],
            "notStorage"
        );
        assert!(
            !serde_json::to_string(&executable.posture)
                .expect("executable posture json")
                .contains(dir.path().to_string_lossy().as_ref())
        );
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
    fn host_fabric_storage_contribution_reports_backend_posture() {
        let dir = tempdir().expect("tempdir");
        let engine = StorageEngine::open(dir.path()).expect("engine");
        let chunk = chunk(b"ciphertext");
        let manifest = manifest("container-a", "container-a:key", &chunk);
        engine
            .put_object(PutObjectRequest {
                manifest,
                chunks: vec![chunk],
            })
            .expect("put object");

        let contribution = engine
            .host_fabric_storage_contribution(
                "4a29ff60c5c3837e9e20555bfeb2a046be3eb140818144628691fcf7efb1d2f1",
                "fabric:runner-lab",
                "host:runner-lab",
                1_700_000_000,
            )
            .expect("contribution");

        constitute_protocol::validate_host_fabric_member_contribution(&contribution)
            .expect("valid contribution");
        assert_eq!(
            contribution.role,
            constitute_protocol::FABRIC_MEMBER_ROLE_STORAGE_JOURNAL_CACHE
        );
        assert_eq!(
            contribution.state,
            constitute_protocol::FABRIC_MEMBER_CONTRIBUTION_RUNNING
        );
        assert_eq!(contribution.contract_ref, "storage-backend:local");
        assert_eq!(contribution.safe_facts["objectCount"].as_u64(), Some(1));
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
        assert_eq!(dry.blocked_chunks, 1);
        engine.retract_pin("pin-1").expect("retract");
        let blocked = engine
            .prune(PruneRequest {
                dry_run: false,
                ..Default::default()
            })
            .expect("blocked prune");
        assert_eq!(blocked.pruned_chunks, 0);
        assert_eq!(blocked.blocked_chunks, 1);
        assert_eq!(blocked.release_postures[0].state, "releaseBlocked");
        engine
            .logical_delete_object(&manifest.object_id, 1_700_000_000)
            .expect("logical delete");
        let pruned = engine
            .prune(PruneRequest {
                dry_run: false,
                retention_class: "disposable".to_string(),
                ..Default::default()
            })
            .expect("freeable prune");
        assert_eq!(pruned.pruned_chunks, 1);
        assert_eq!(pruned.blocked_chunks, 0);
        assert_eq!(pruned.release_postures[0].state, "freeable");
        assert_eq!(
            pruned.release_postures[0].kind.as_deref(),
            Some(RECORD_RETENTION_RELEASE)
        );
    }

    #[test]
    fn storage_prune_requires_fulfillment_for_durable_release() {
        let dir = tempdir().expect("tempdir");
        let engine = StorageEngine::open(dir.path()).expect("engine");
        let chunk = chunk(b"durable-ciphertext");
        let manifest = manifest("container-a", "container-a:key", &chunk);
        engine
            .put_object(PutObjectRequest {
                manifest: manifest.clone(),
                chunks: vec![chunk],
            })
            .expect("put object");
        engine
            .logical_delete_object(&manifest.object_id, 1_700_000_000)
            .expect("logical delete");
        let blocked = engine
            .prune(PruneRequest {
                dry_run: true,
                retention_class: "durable".to_string(),
                ..Default::default()
            })
            .expect("blocked durable prune");
        assert_eq!(blocked.pruned_chunks, 0);
        assert_eq!(blocked.blocked_chunks, 1);
        assert_eq!(blocked.release_postures[0].state, "releaseBlocked");
        assert_eq!(
            blocked.release_postures[0].blockers[0]["code"],
            "fulfillment.missing"
        );
        let witness_blocked = engine
            .prune(PruneRequest {
                now: 1_700_000_001,
                dry_run: true,
                retention_class: "durable".to_string(),
                fulfillment_refs: vec!["storage-fulfillment:replica-2".to_string()],
                require_witness: true,
                valid_until: Some(1_700_000_010),
                release_after: Some(1_700_000_010),
                ..Default::default()
            })
            .expect("witness blocked durable prune");
        assert_eq!(witness_blocked.pruned_chunks, 0);
        assert_eq!(witness_blocked.blocked_chunks, 1);
        let blocker_codes: Vec<String> = witness_blocked.release_postures[0]
            .blockers
            .iter()
            .filter_map(|blocker| blocker["code"].as_str().map(ToOwned::to_owned))
            .collect();
        assert!(blocker_codes.iter().any(|code| code == "witness.missing"));
        assert!(blocker_codes.iter().any(|code| code == "validity.active"));
        assert!(
            blocker_codes
                .iter()
                .any(|code| code == "releaseAfter.pending")
        );
        let pruned = engine
            .prune(PruneRequest {
                now: 1_700_000_011,
                dry_run: false,
                retention_class: "durable".to_string(),
                fulfillment_refs: vec!["storage-fulfillment:replica-2".to_string()],
                owner_refs: vec!["identity:operator".to_string()],
                witness_refs: vec!["witness:storage-release-observed".to_string()],
                valid_until: Some(1_700_000_010),
                release_after: Some(1_700_000_010),
                ..Default::default()
            })
            .expect("fulfilled durable prune");
        assert_eq!(pruned.pruned_chunks, 1);
        assert_eq!(pruned.blocked_chunks, 0);
        assert_eq!(pruned.release_postures[0].state, "freeable");
        assert_eq!(
            pruned.release_postures[0].fulfillment_refs,
            vec!["storage-fulfillment:replica-2".to_string()]
        );
        assert_eq!(
            pruned.release_postures[0].policy_refs,
            vec!["policy:storage.retention.durable".to_string()]
        );
        assert_eq!(
            pruned.release_postures[0].witness_refs,
            vec!["witness:storage-release-observed".to_string()]
        );
    }

    #[test]
    fn backend_posture_and_snapshot_do_not_expose_local_paths() {
        let dir = tempdir().expect("tempdir");
        let engine = StorageEngine::open(dir.path()).expect("engine");
        let chunk = chunk(b"snapshot-ciphertext");
        let manifest = manifest("container-a", "container-a:key", &chunk);
        engine
            .put_object(PutObjectRequest {
                manifest: manifest.clone(),
                chunks: vec![chunk],
            })
            .expect("put object");
        engine
            .put_pin(StoragePinLease {
                pin_id: "pin-snapshot".to_string(),
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
        engine.put_pin_intent(pin_intent()).expect("put intent");

        let posture = engine
            .backend_posture(TEST_STORAGE_MEMBER_REF, 1_700_000_001)
            .expect("backend posture");
        assert_eq!(posture.state, STORAGE_BACKEND_STATE_READY);
        assert_eq!(posture.object_count, 1);
        assert_eq!(posture.chunk_count, 1);
        assert_eq!(posture.root_ref, "storage-root:local");
        assert!(
            !serde_json::to_string(&posture)
                .expect("json")
                .contains(dir.path().to_string_lossy().as_ref())
        );

        let snapshot = engine
            .backend_snapshot(TEST_STORAGE_MEMBER_REF, 8, 1_700_000_001)
            .expect("backend snapshot");
        assert_eq!(snapshot.object_count, 1);
        assert_eq!(snapshot.pin_lease_count, 1);
        assert!(
            snapshot
                .object_refs
                .iter()
                .any(|item| item.starts_with("storage:object:"))
        );
        assert!(
            snapshot
                .pin_intent_refs
                .iter()
                .any(|item| item == "storage:pin-intent:intent-1")
        );
    }

    #[test]
    fn filesystem_view_materializes_virtual_paths_without_local_leakage() {
        let dir = tempdir().expect("tempdir");
        let engine = StorageEngine::open(dir.path()).expect("engine");
        let chunk = chunk(b"filesystem-view-ciphertext");
        let manifest = manifest("container-a", "container-a:key", &chunk);
        engine
            .put_object(PutObjectRequest {
                manifest: manifest.clone(),
                chunks: vec![chunk],
            })
            .expect("put object");

        let view = engine
            .filesystem_view(TEST_STORAGE_MEMBER_REF, 8, 1_700_000_001)
            .expect("filesystem view");

        assert_eq!(view.state, STORAGE_FILESYSTEM_VIEW_READY);
        assert_eq!(view.object_count, 1);
        assert_eq!(view.chunk_count, 1);
        let object_ref = format!("storage:object:{}", manifest.object_id);
        assert!(
            view.entries
                .iter()
                .any(|entry| entry.object_ref.as_deref() == Some(object_ref.as_str()))
        );
        assert!(view.entries.iter().any(|entry| entry.chunk_ref.is_some()));
        let serialized = serde_json::to_string(&view).expect("view json");
        assert!(!serialized.contains(dir.path().to_string_lossy().as_ref()));
        assert!(!serialized.contains("\\"));
        assert!(!serialized.contains("../"));
    }

    #[test]
    fn graph_edges_are_queryable_without_source_semantics() {
        let dir = tempdir().expect("tempdir");
        let engine = StorageEngine::open(dir.path()).expect("engine");
        let edge = StorageGraphEdge {
            edge_id: "edge-source-tree-object".to_string(),
            container_id: "container-source".to_string(),
            from_ref: "source:tree:root".to_string(),
            relation: "contains".to_string(),
            to_ref: TEST_OBJECT_REF.to_string(),
            detail_ref: None,
            created_at: 1_700_000_001,
        };

        engine.put_graph_edge(edge.clone()).expect("put graph edge");
        let by_from = engine
            .graph_edges(
                Some("container-source"),
                Some("source:tree:root"),
                Some("contains"),
                None,
                8,
            )
            .expect("query graph edges");

        assert_eq!(by_from.edges, vec![edge]);
        assert!(
            engine
                .graph_edges(
                    Some("container-source"),
                    Some("../local/path"),
                    None,
                    None,
                    8,
                )
                .expect("query invalid-looking ref")
                .edges
                .is_empty()
        );
    }

    fn pin_intent() -> StoragePinIntent {
        StoragePinIntent {
            intent_id: "intent-1".to_string(),
            object_refs: vec![TEST_OBJECT_REF.to_string()],
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
            accepted_refs: vec![TEST_OBJECT_REF.to_string()],
            availability_refs: vec![SwarmStorageAvailabilityRef {
                availability_id: format!("availability-{attestation_id}"),
                object_ref: TEST_OBJECT_REF.to_string(),
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
                    TEST_STORAGE_MEMBER_REF_TWO,
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
                    TEST_STORAGE_MEMBER_REF,
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
                TEST_STORAGE_MEMBER_REF.to_string(),
                TEST_STORAGE_MEMBER_REF_TWO.to_string()
            ]
        );
    }

    #[test]
    fn app_distribution_pin_intent_uses_storage_projection_backing() {
        let dir = tempdir().expect("tempdir");
        let engine = StorageEngine::open(dir.path()).expect("engine");
        let intent = StoragePinIntent {
            intent_id: "intent-surface-app-release".to_string(),
            object_refs: vec![TEST_APP_OBJECT_REF.to_string()],
            manifest_hash: "sha256:surface-app-manifest:nvr-ui:0.2.0".to_string(),
            desired_replicas: 1,
            retention: "app-release".to_string(),
            authority_refs: vec!["authority:app:nvr-ui".to_string()],
            expires_at: Some(1_700_000_100_000),
        };
        let pending = engine.put_pin_intent(intent).expect("put app pin intent");
        assert_eq!(
            pending.projection.status,
            StoragePinProjectionStatus::Pending
        );
        assert_eq!(pending.projection.missing_replicas, 1);

        let satisfied = engine
            .put_pin_attestation(
                StoragePinAttestation {
                    attestation_id: "attestation-surface-app-release".to_string(),
                    intent_id: "intent-surface-app-release".to_string(),
                    storage_member_ref: TEST_STORAGE_MEMBER_REF.to_string(),
                    accepted_refs: vec![TEST_APP_OBJECT_REF.to_string()],
                    availability_refs: vec![SwarmStorageAvailabilityRef {
                        availability_id: "availability-surface-app-release".to_string(),
                        object_ref: TEST_APP_OBJECT_REF.to_string(),
                        storage_member_ref: TEST_STORAGE_MEMBER_REF.to_string(),
                        expires_at: Some(1_700_000_100_000),
                    }],
                    status: StoragePinStatus::Pinned,
                    expires_at: Some(1_700_000_100_000),
                    issued_at: 1_700_000_000_000,
                },
                1_700_000_000_000,
            )
            .expect("app distribution attestation");
        assert_eq!(
            satisfied.projection.status,
            StoragePinProjectionStatus::Satisfied
        );
        assert_eq!(satisfied.projection.pinned_count, 1);
        assert_eq!(satisfied.projection.missing_replicas, 0);
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
                    TEST_STORAGE_MEMBER_REF,
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
