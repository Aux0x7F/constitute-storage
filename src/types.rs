use constitute_protocol::{
    EncryptedDetailRef, StorageChunkRef, StorageIndexShard, StorageKeyGrant, StorageObjectManifest,
    StoragePinLease,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PutChunk {
    #[serde(rename = "ref")]
    pub chunk_ref: StorageChunkRef,
    pub ciphertext_base64: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PutObjectRequest {
    pub manifest: StorageObjectManifest,
    pub chunks: Vec<PutChunk>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredObjectResponse {
    pub manifest: StorageObjectManifest,
    pub stored_chunk_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetObjectResponse {
    pub manifest: StorageObjectManifest,
    pub chunks: Vec<PutChunk>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PutIndexShardRequest {
    pub shard: StorageIndexShard,
    pub chunks: Vec<PutChunk>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredIndexShardResponse {
    pub shard: StorageIndexShard,
    pub stored_chunk_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PutKeyGrantRequest {
    pub grant: StorageKeyGrant,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PutPinRequest {
    pub pin: StoragePinLease,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PruneRequest {
    #[serde(default)]
    pub now: u64,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub prune_expired: bool,
    #[serde(default)]
    pub retention_class: String,
    #[serde(default)]
    pub max_bytes: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PruneResponse {
    pub dry_run: bool,
    pub pruned_chunks: usize,
    pub pruned_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MaterializedIndexEntry {
    pub entry_id: String,
    pub container_id: String,
    pub record_type: String,
    pub subject: String,
    #[serde(default)]
    pub priority: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub facts: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail_ref: Option<EncryptedDetailRef>,
    pub created_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MaterializeIndexRequest {
    pub entries: Vec<MaterializedIndexEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResponse {
    pub entries: Vec<MaterializedIndexEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageHealth {
    pub status: String,
    pub objects: u64,
    pub chunks: u64,
    pub index_shards: u64,
    pub key_grants: u64,
    pub pin_leases: u64,
    pub materialized_entries: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageWatchEvent {
    pub event_id: String,
    pub priority: String,
    pub kind: String,
    pub at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,
    #[serde(default)]
    pub message: String,
}
