use constitute_protocol::{
    EncryptedDetailRef, RetentionReleasePosture, StorageChunkRef, StorageGraphEdge,
    StorageIndexShard, StorageKeyGrant, StorageModuleExecutableInstantiationPosture,
    StorageModuleMaterializationPosture, StorageObjectManifest, StoragePinAttestation,
    StoragePinIntent, StoragePinLease, StoragePinProjection,
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
pub struct PutSourceObjectRequest {
    pub source_graph_ref: String,
    pub source_snapshot_ref: String,
    pub storage_member_ref: String,
    pub manifest: StorageObjectManifest,
    pub chunks: Vec<PutChunk>,
    #[serde(default)]
    pub authority_refs: Vec<String>,
    #[serde(default = "default_source_object_replicas")]
    pub desired_replicas: u32,
    #[serde(default = "default_source_object_retention")]
    pub retention: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    pub issued_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceObjectStorageResponse {
    pub object: StoredObjectResponse,
    pub graph_edge: StorageGraphEdge,
    pub pin_intent: StoragePinIntentResponse,
    pub pin_attestation: StoragePinAttestationResponse,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModuleMaterializationRequest {
    pub module_ref: String,
    pub source_graph_ref: String,
    pub source_snapshot_ref: String,
    pub content_index_ref: String,
    pub artifact_ref: String,
    pub materialized_path_ref: String,
    pub storage_member_ref: String,
    pub manifest: StorageObjectManifest,
    pub chunks: Vec<PutChunk>,
    #[serde(default)]
    pub authority_refs: Vec<String>,
    #[serde(default = "default_module_replicas")]
    pub desired_replicas: u32,
    #[serde(default = "default_module_materialization_retention")]
    pub retention: String,
    #[serde(default)]
    pub cache_refs: Vec<String>,
    #[serde(default)]
    pub conflict_refs: Vec<String>,
    #[serde(default)]
    pub adapter_residency_refs: Vec<String>,
    #[serde(default)]
    pub legacy_transition_conflict_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    pub issued_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModuleMaterializationResponse {
    pub source_object: SourceObjectStorageResponse,
    pub posture: StorageModuleMaterializationPosture,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModuleExecutableInstantiationRequest {
    pub module_ref: String,
    pub source_snapshot_ref: String,
    pub content_index_ref: String,
    pub artifact_ref: String,
    pub materialization_ref: String,
    pub materialization_posture_ref: String,
    pub object_ref: String,
    pub storage_member_ref: String,
    #[serde(default)]
    pub conflict_refs: Vec<String>,
    #[serde(default)]
    pub adapter_residency_refs: Vec<String>,
    #[serde(default)]
    pub legacy_transition_conflict_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    pub issued_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModuleExecutableInstantiationResponse {
    pub posture: StorageModuleExecutableInstantiationPosture,
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
pub struct PutGraphEdgeRequest {
    pub edge: StorageGraphEdge,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphEdgeSearchResponse {
    pub edges: Vec<StorageGraphEdge>,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PutPinIntentRequest {
    pub intent: StoragePinIntent,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PutPinAttestationRequest {
    pub attestation: StoragePinAttestation,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoragePinIntentResponse {
    pub intent: StoragePinIntent,
    pub projection: StoragePinProjection,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoragePinAttestationResponse {
    pub attestation: StoragePinAttestation,
    pub projection: StoragePinProjection,
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
    #[serde(default)]
    pub policy_refs: Vec<String>,
    #[serde(default)]
    pub overlay_refs: Vec<String>,
    #[serde(default)]
    pub owner_refs: Vec<String>,
    #[serde(default)]
    pub holder_refs: Vec<String>,
    #[serde(default)]
    pub fulfillment_refs: Vec<String>,
    #[serde(default)]
    pub residency_layers: Vec<String>,
    #[serde(default)]
    pub witness_refs: Vec<String>,
    #[serde(default)]
    pub supersession_refs: Vec<String>,
    #[serde(default)]
    pub retraction_refs: Vec<String>,
    #[serde(default)]
    pub revocation_refs: Vec<String>,
    #[serde(default)]
    pub require_witness: bool,
    #[serde(default)]
    pub valid_until: Option<u64>,
    #[serde(default)]
    pub release_after: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PruneResponse {
    pub dry_run: bool,
    pub evaluated_chunks: usize,
    pub blocked_chunks: usize,
    pub pruned_chunks: usize,
    pub pruned_bytes: u64,
    #[serde(default)]
    pub release_postures: Vec<RetentionReleasePosture>,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub encrypted_detail_refs: Vec<EncryptedDetailRef>,
    pub created_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MaterializeIndexRequest {
    pub entries: Vec<MaterializedIndexEntry>,
    #[serde(default)]
    pub pin_intents: Vec<StoragePinIntent>,
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
    pub graph_edges: u64,
    pub key_grants: u64,
    pub pin_leases: u64,
    pub pin_intents: u64,
    pub pin_attestations: u64,
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

fn default_source_object_replicas() -> u32 {
    1
}

fn default_source_object_retention() -> String {
    "source-object".to_string()
}

fn default_module_replicas() -> u32 {
    1
}

fn default_module_materialization_retention() -> String {
    "module-materialization".to_string()
}
