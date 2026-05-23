// domain-owned-vocabulary: storage.availability sourceSnapshot.stores
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Path, Query, State, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use constitute_protocol::{
    CAPABILITY_PROJECTION_DELTA_APPLY, CaacEnvelope, SWARM_FRAME_VERSION, StoragePinAttestation,
    StoragePinIntent, StoragePinStatus, SwarmFrame, SwarmFrameBody, SwarmFrameKind, SwarmRecordRef,
    SwarmStorageAvailabilityRef, ZoneScope, open_envelope, seal_envelope, sha256_hex,
    swarm_frame_id, validate_swarm_frame,
};
use serde::Deserialize;
use serde_json::{Value, json};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::engine::StorageEngine;
use crate::identity::StorageServiceIdentity;
use crate::types::{
    MaterializeIndexRequest, PruneRequest, PutGraphEdgeRequest, PutIndexShardRequest,
    PutKeyGrantRequest, PutObjectRequest, PutPinAttestationRequest, PutPinIntentRequest,
    PutPinRequest, PutSourceObjectRequest,
};

pub(crate) const STORAGE_MEMBER_REF: &str = "service:storage:local";
pub(crate) const STORAGE_CHANNELS: [&str; 4] = [
    constitute_protocol::RECORD_STORAGE_PIN_INTENT,
    constitute_protocol::RECORD_STORAGE_PIN_ATTESTATION,
    "storage.availability",
    constitute_protocol::RECORD_SURFACE_APP_DISTRIBUTION,
];
pub(crate) const STORAGE_EDGE_CAPABILITIES: [&str; 6] = [
    constitute_protocol::CAPABILITY_STORAGE_OBJECT_PUT,
    constitute_protocol::CAPABILITY_STORAGE_OBJECT_GET,
    constitute_protocol::CAPABILITY_STORAGE_PIN,
    constitute_protocol::CAPABILITY_SURFACE_APP_DISTRIBUTION_PIN,
    constitute_protocol::CAPABILITY_STORAGE_AVAILABILITY_ATTEST,
    constitute_protocol::CAPABILITY_STORAGE_LOCAL_SEARCH_QUERY,
];

#[derive(Clone)]
pub struct ApiState {
    pub engine: StorageEngine,
    pub service_identity: StorageServiceIdentity,
    pub caac_fixture_mode: bool,
}

#[derive(Debug)]
struct ApiError(anyhow::Error);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(json!({
            "error": self.0.to_string(),
        }));
        (StatusCode::BAD_REQUEST, body).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(value: anyhow::Error) -> Self {
        Self(value)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SearchQuery {
    container_id: Option<String>,
    record_type: Option<String>,
    subject: Option<String>,
    tag: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GraphQuery {
    container_id: Option<String>,
    from_ref: Option<String>,
    relation: Option<String>,
    to_ref: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProjectionQuery {
    now: Option<u64>,
}

pub fn router(engine: StorageEngine, service_identity: StorageServiceIdentity) -> Router {
    let state = ApiState {
        engine,
        service_identity,
        caac_fixture_mode: false,
    };
    Router::new()
        .route("/hosted-service.json", get(hosted_service_manifest))
        .route("/health", get(health))
        .route("/v1/objects", post(put_object))
        .route(
            "/v1/objects/{object_id}",
            get(get_object).delete(logical_delete_object),
        )
        .route("/v1/index-shards", post(put_index_shard))
        .route("/v1/key-grants", post(put_key_grant))
        .route("/v1/prune", post(prune))
        .route("/operator/storage/v1/pin-intents", post(put_pin_intent))
        .route(
            "/operator/storage/v1/pin-attestations",
            post(put_pin_attestation),
        )
        .route(
            "/operator/storage/v1/pin-projections/{intent_id}",
            get(get_pin_projection),
        )
        .route("/operator/storage/v1/pins", post(put_pin))
        .route("/operator/storage/v1/pins/{pin_id}", delete(retract_pin))
        .route(
            "/operator/storage/v1/source-objects",
            post(put_source_object),
        )
        .route(
            "/operator/storage/v1/backend-posture",
            get(get_backend_posture),
        )
        .route(
            "/operator/storage/v1/evidence-custody",
            get(get_evidence_custody),
        )
        .route("/operator/storage/v1/snapshot", get(get_backend_snapshot))
        .route(
            "/operator/storage/v1/filesystem-view",
            get(get_filesystem_view),
        )
        .route(
            "/operator/storage/v1/local-index/materialize",
            post(materialize_index),
        )
        .route("/operator/storage/v1/local-index/search", get(search))
        .route(
            "/operator/storage/v1/graph-edges",
            get(get_graph_edges).post(put_graph_edge),
        )
        .route("/operator/storage/v1/watch", get(watch))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn hosted_service_manifest(State(state): State<ApiState>) -> impl IntoResponse {
    let service_pk = state.service_identity.service_pk.as_str();
    let service_ref = format!("service:storage:{service_pk}");
    Json(json!({
        "service": "storage",
        "servicePk": service_pk,
        "deviceLabel": "Constitute Storage",
        "serviceVersion": env!("CARGO_PKG_VERSION"),
        "apiBaseUrl": "",
        "healthUrl": "/health",
        "capabilities": STORAGE_EDGE_CAPABILITIES,
        "channels": [
            {
                "channelId": constitute_protocol::RECORD_STORAGE_PIN_INTENT,
                "recordKinds": [constitute_protocol::RECORD_STORAGE_PIN_INTENT],
                "capabilities": [constitute_protocol::CAPABILITY_STORAGE_PIN]
            },
            {
                "channelId": constitute_protocol::RECORD_STORAGE_PIN_ATTESTATION,
                "recordKinds": [constitute_protocol::RECORD_STORAGE_PIN_ATTESTATION, constitute_protocol::RECORD_STORAGE_AVAILABILITY_REF],
                "capabilities": [constitute_protocol::CAPABILITY_STORAGE_AVAILABILITY_ATTEST]
            },
            {
                "channelId": "storage.availability",
                "recordKinds": [constitute_protocol::RECORD_STORAGE_PIN_PROJECTION, constitute_protocol::RECORD_STORAGE_AVAILABILITY_REF],
                "capabilities": [constitute_protocol::CAPABILITY_STORAGE_OBJECT_GET, constitute_protocol::CAPABILITY_STORAGE_LOCAL_SEARCH_QUERY]
            },
            {
                "channelId": constitute_protocol::RECORD_SURFACE_APP_DISTRIBUTION,
                "recordKinds": [constitute_protocol::RECORD_SURFACE_APP_MANIFEST, constitute_protocol::RECORD_STORAGE_PIN_INTENT, constitute_protocol::RECORD_STORAGE_PIN_PROJECTION],
                "capabilities": [constitute_protocol::CAPABILITY_SURFACE_APP_DISTRIBUTION_PIN, constitute_protocol::CAPABILITY_STORAGE_PIN, constitute_protocol::CAPABILITY_STORAGE_OBJECT_GET]
            }
        ],
        "swarmEdge": {
            "memberRef": service_pk,
            "serviceRef": service_ref.clone(),
            "servicePk": service_pk,
            "promiseRefs": [
                service_ref,
                service_pk
            ],
            "role": "edgeMember",
            "transport": "gateway.swarm.edge.websocket",
            "channels": STORAGE_CHANNELS,
            "capabilities": STORAGE_EDGE_CAPABILITIES
        },
        "operatorRoutes": {
            "pinIntents": "/operator/storage/v1/pin-intents",
            "pinAttestations": "/operator/storage/v1/pin-attestations",
            "pinProjections": "/operator/storage/v1/pin-projections/{intentId}",
            "sourceObjects": "/operator/storage/v1/source-objects",
            "backendPosture": "/operator/storage/v1/backend-posture",
            "snapshot": "/operator/storage/v1/snapshot",
            "filesystemView": "/operator/storage/v1/filesystem-view",
            "graphEdges": "/operator/storage/v1/graph-edges",
            "watch": "/operator/storage/v1/watch"
        }
    }))
}

async fn health(State(state): State<ApiState>) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(state.engine.health()?))
}

fn consume_edge_frame(state: &ApiState, frame: SwarmFrame, now: u64) -> Result<Value, ApiError> {
    validate_swarm_frame(&frame, now).map_err(anyhow::Error::from)?;
    let record_kind = frame
        .record_ref
        .as_ref()
        .map(|record| record.kind.as_str())
        .unwrap_or_default();
    match (&frame.kind, record_kind) {
        (SwarmFrameKind::StoragePinIntent, _)
        | (SwarmFrameKind::RecordPublish, constitute_protocol::RECORD_STORAGE_PIN_INTENT) => {
            consume_pin_intent_frame(state, &frame, now)
        }
        (SwarmFrameKind::StoragePinAttestation, _)
        | (SwarmFrameKind::RecordPublish, constitute_protocol::RECORD_STORAGE_PIN_ATTESTATION) => {
            consume_pin_attestation_frame(state, &frame, now)
        }
        _ => Err(anyhow::anyhow!("storage edge frame record kind is unsupported").into()),
    }
}

pub fn process_gateway_frame(
    state: &ApiState,
    frame: SwarmFrame,
    now: u64,
) -> anyhow::Result<Vec<SwarmFrame>> {
    let source_frame = frame.clone();
    let response = consume_edge_frame(state, frame, now).map_err(|err| err.0)?;
    let mut frames = Vec::new();
    let input_is_pin_intent = matches!(source_frame.kind, SwarmFrameKind::StoragePinIntent)
        || source_frame
            .record_ref
            .as_ref()
            .is_some_and(|record| record.kind == constitute_protocol::RECORD_STORAGE_PIN_INTENT);
    if input_is_pin_intent
        && let Some(attestation) = response
            .get("attestation")
            .filter(|value| value.is_object())
    {
        frames.push(attestation_response_frame(
            &state.service_identity,
            &source_frame,
            attestation.clone(),
            now,
        )?);
    }
    if let Some(projection) = response.get("projection").filter(|value| value.is_object()) {
        frames.push(projection_response_frame(
            &state.service_identity,
            &source_frame,
            projection.clone(),
            now,
        )?);
    }
    Ok(frames)
}

fn attestation_response_frame(
    service_identity: &StorageServiceIdentity,
    source_frame: &SwarmFrame,
    attestation: Value,
    now: u64,
) -> anyhow::Result<SwarmFrame> {
    let attestation_id = attestation
        .get("attestationId")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("storage-pin-attestation")
        .to_string();
    let mut frame = response_frame(
        service_identity,
        source_frame,
        SwarmFrameKind::StoragePinAttestation,
        constitute_protocol::RECORD_STORAGE_PIN_ATTESTATION,
        &attestation_id,
        constitute_protocol::RECORD_STORAGE_PIN_ATTESTATION,
        constitute_protocol::CAPABILITY_STORAGE_AVAILABILITY_ATTEST,
        attestation,
        now,
    );
    frame.frame_id = swarm_frame_id(&frame)?;
    Ok(frame)
}

fn projection_response_frame(
    service_identity: &StorageServiceIdentity,
    source_frame: &SwarmFrame,
    projection: Value,
    now: u64,
) -> anyhow::Result<SwarmFrame> {
    let projection_id = source_frame
        .record_ref
        .as_ref()
        .map(|record| format!("storage:pin:projection:{}", record.id))
        .unwrap_or_else(|| "storage:pin:projection".to_string());
    let mut frame = response_frame(
        service_identity,
        source_frame,
        SwarmFrameKind::ProjectionDelta,
        "storage.availability",
        &projection_id,
        constitute_protocol::RECORD_STORAGE_PIN_PROJECTION,
        CAPABILITY_PROJECTION_DELTA_APPLY,
        projection,
        now,
    );
    frame.frame_id = swarm_frame_id(&frame)?;
    Ok(frame)
}

fn response_frame(
    service_identity: &StorageServiceIdentity,
    source_frame: &SwarmFrame,
    kind: SwarmFrameKind,
    channel_id: &str,
    record_id: &str,
    record_kind: &str,
    capability: &str,
    record: Value,
    now: u64,
) -> SwarmFrame {
    let recipient_pk = frame_recipient_pk(source_frame, &service_identity.service_pk);
    let envelope = seal_envelope(
        record_kind,
        &json!({ "record": record }),
        &service_identity.service_sk_hex,
        &[recipient_pk],
        now,
        now + 60_000,
    )
    .ok()
    .and_then(|envelope| serde_json::to_value(envelope).ok());
    SwarmFrame {
        version: SWARM_FRAME_VERSION,
        frame_id: String::new(),
        kind,
        issuer: STORAGE_MEMBER_REF.to_string(),
        audience: json!({ "actorRef": source_frame.issuer }),
        zone_scope: source_frame.zone_scope.clone().or_else(default_zone_scope),
        issued_at: now,
        expires_at: Some(now + 60_000),
        nonce: format!(
            "storage-response-{now}-{record_kind}-{}",
            source_frame.frame_id
        ),
        correlation_id: Some(source_frame.frame_id.clone()),
        channel_id: Some(channel_id.to_string()),
        record_ref: Some(SwarmRecordRef {
            kind: record_kind.to_string(),
            id: record_id.to_string(),
            revision: Some(1),
        }),
        capability: Some(capability.to_string()),
        body: SwarmFrameBody {
            encoding: "caac".to_string(),
            envelope,
            public_bootstrap: false,
            payload: None,
            signature: None,
        },
        ack: None,
    }
}

fn default_zone_scope() -> Option<ZoneScope> {
    Some(ZoneScope {
        zone_id: "zone_lab".to_string(),
        privacy: Some("rawIds".to_string()),
        ttl: Some(30),
        max_hops: Some(2),
    })
}

fn consume_pin_intent_frame(
    state: &ApiState,
    frame: &SwarmFrame,
    now: u64,
) -> Result<Value, ApiError> {
    let intent: StoragePinIntent = serde_json::from_value(edge_record_payload(state, frame, now)?)
        .map_err(anyhow::Error::from)?;
    let intent_response = state.engine.put_pin_intent(intent.clone())?;
    let attestation = attestation_for_intent(&intent, now);
    let attestation_response = state.engine.put_pin_attestation(attestation.clone(), now)?;
    Ok(json!({
        "status": "accepted",
        "frameId": frame.frame_id,
        "channelId": frame.channel_id,
        "intent": intent_response.intent,
        "attestation": attestation_response.attestation,
        "projection": attestation_response.projection,
        "emittedRecords": [
            {
                "recordKind": constitute_protocol::RECORD_STORAGE_PIN_ATTESTATION,
                "recordId": attestation.attestation_id,
                "channelId": constitute_protocol::RECORD_STORAGE_PIN_ATTESTATION
            }
        ]
    }))
}

fn consume_pin_attestation_frame(
    state: &ApiState,
    frame: &SwarmFrame,
    now: u64,
) -> Result<Value, ApiError> {
    let attestation: StoragePinAttestation =
        serde_json::from_value(edge_record_payload(state, frame, now)?)
            .map_err(anyhow::Error::from)?;
    let response = state.engine.put_pin_attestation(attestation, now)?;
    Ok(json!({
        "status": "accepted",
        "frameId": frame.frame_id,
        "channelId": frame.channel_id,
        "attestation": response.attestation,
        "projection": response.projection
    }))
}

fn edge_record_payload(state: &ApiState, frame: &SwarmFrame, now: u64) -> Result<Value, ApiError> {
    if frame.body.encoding != "caac" {
        return Err(anyhow::anyhow!("storage edge requires sealed CAAC frame body").into());
    }
    let envelope = frame
        .body
        .envelope
        .as_ref()
        .filter(|value| value.is_object())
        .ok_or_else(|| anyhow::anyhow!("storage edge frame missing sealed envelope"))?;
    if !state.caac_fixture_mode {
        reject_placeholder_caac(frame, envelope)?;
        let caac: CaacEnvelope = serde_json::from_value(envelope.clone())
            .map_err(|_| anyhow::anyhow!("storage edge requires opened CAAC envelope"))?;
        let payload = open_envelope(&caac, &state.service_identity.service_sk_hex, now, None)
            .map_err(|err| anyhow::anyhow!("storage edge CAAC open failed: {err}"))?;
        return Ok(payload
            .get("record")
            .cloned()
            .filter(|value| value.is_object())
            .unwrap_or(payload));
    }
    let payload = ["sealedPayload", "payload", "record"]
        .iter()
        .find_map(|key| envelope.get(*key).filter(|value| value.is_object()))
        .cloned()
        .unwrap_or_else(|| envelope.clone());
    Ok(payload
        .get("record")
        .cloned()
        .filter(|value| value.is_object())
        .unwrap_or(payload))
}

fn reject_placeholder_caac(frame: &SwarmFrame, envelope: &Value) -> Result<(), ApiError> {
    if frame
        .body
        .signature
        .as_deref()
        .is_some_and(is_placeholder_token)
        || envelope
            .get("shape")
            .and_then(Value::as_str)
            .is_some_and(is_placeholder_token)
        || envelope.get("sealedPayload").is_some()
    {
        return Err(
            anyhow::anyhow!("storage edge rejects placeholder CAAC outside fixture mode").into(),
        );
    }
    if let Some(signature) = envelope.get("signature").and_then(Value::as_str)
        && is_placeholder_token(signature)
    {
        return Err(
            anyhow::anyhow!("storage edge rejects placeholder CAAC outside fixture mode").into(),
        );
    }
    Ok(())
}

fn is_placeholder_token(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    lowered.contains("placeholder") || lowered.contains("fixture")
}

fn frame_recipient_pk(frame: &SwarmFrame, fallback_pk: &str) -> String {
    if is_hex_pk(&frame.issuer) {
        frame.issuer.clone()
    } else {
        fallback_pk.to_string()
    }
}

fn is_hex_pk(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn attestation_for_intent(intent: &StoragePinIntent, now: u64) -> StoragePinAttestation {
    let attestation_id = format!(
        "storage-pin-attestation-{}",
        sha256_hex(format!(
            "{}|{}|{}",
            intent.intent_id, intent.manifest_hash, STORAGE_MEMBER_REF
        ))
    );
    StoragePinAttestation {
        attestation_id: attestation_id.clone(),
        intent_id: intent.intent_id.clone(),
        storage_member_ref: STORAGE_MEMBER_REF.to_string(),
        accepted_refs: intent.object_refs.clone(),
        availability_refs: intent
            .object_refs
            .iter()
            .map(|object_ref| SwarmStorageAvailabilityRef {
                availability_id: format!(
                    "storage-availability-{}",
                    sha256_hex(format!("{attestation_id}|{object_ref}"))
                ),
                object_ref: object_ref.clone(),
                storage_member_ref: STORAGE_MEMBER_REF.to_string(),
                expires_at: intent.expires_at,
            })
            .collect(),
        status: StoragePinStatus::Accepted,
        expires_at: intent.expires_at,
        issued_at: now,
    }
}

async fn put_object(
    State(state): State<ApiState>,
    Json(request): Json<PutObjectRequest>,
) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(state.engine.put_object(request)?))
}

async fn get_object(
    State(state): State<ApiState>,
    Path(object_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(state.engine.get_object(&object_id)?))
}

async fn put_source_object(
    State(state): State<ApiState>,
    Json(request): Json<PutSourceObjectRequest>,
) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(state.engine.put_source_object(request)?))
}

async fn logical_delete_object(
    State(state): State<ApiState>,
    Path(object_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    state
        .engine
        .logical_delete_object(&object_id, crate::engine::now_seconds())?;
    Ok(Json(json!({ "status": "deleted", "objectId": object_id })))
}

async fn put_index_shard(
    State(state): State<ApiState>,
    Json(request): Json<PutIndexShardRequest>,
) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(state.engine.put_index_shard(request)?))
}

async fn put_key_grant(
    State(state): State<ApiState>,
    Json(request): Json<PutKeyGrantRequest>,
) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(state.engine.put_key_grant(request.grant)?))
}

async fn put_pin_intent(
    State(state): State<ApiState>,
    Json(request): Json<PutPinIntentRequest>,
) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(state.engine.put_pin_intent(request.intent)?))
}

async fn put_pin_attestation(
    State(state): State<ApiState>,
    Json(request): Json<PutPinAttestationRequest>,
) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(state.engine.put_pin_attestation(
        request.attestation,
        crate::engine::now_millis(),
    )?))
}

async fn get_pin_projection(
    State(state): State<ApiState>,
    Path(intent_id): Path<String>,
    Query(query): Query<ProjectionQuery>,
) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(state.engine.pin_projection(
        &intent_id,
        query.now.unwrap_or_else(crate::engine::now_millis),
    )?))
}

// Direct storage adapters below the swarm protocol pin boundary.
async fn put_pin(
    State(state): State<ApiState>,
    Json(request): Json<PutPinRequest>,
) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(state.engine.put_pin(request.pin)?))
}

async fn retract_pin(
    State(state): State<ApiState>,
    Path(pin_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    state.engine.retract_pin(&pin_id)?;
    Ok(Json(json!({ "status": "retracted", "pinId": pin_id })))
}

async fn prune(
    State(state): State<ApiState>,
    Json(request): Json<PruneRequest>,
) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(state.engine.prune(request)?))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BackendPostureQuery {
    now: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceCustodyQuery {
    now: Option<u64>,
    finding_ref: Option<String>,
    processor_report_ref: Option<String>,
    subject_ref: Option<String>,
    detail_refs: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BackendSnapshotQuery {
    now: Option<u64>,
    limit: Option<usize>,
}

async fn get_backend_posture(
    State(state): State<ApiState>,
    Query(query): Query<BackendPostureQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let member_ref = format!("service:storage:{}", state.service_identity.service_pk);
    Ok(Json(state.engine.backend_posture(
        member_ref,
        query.now.unwrap_or_else(crate::engine::now_seconds),
    )?))
}

async fn get_evidence_custody(
    State(state): State<ApiState>,
    Query(query): Query<EvidenceCustodyQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let member_ref = format!("service:storage:{}", state.service_identity.service_pk);
    let detail_refs = query
        .detail_refs
        .as_deref()
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    Ok(Json(
        state.engine.cybersec_evidence_custody_posture(
            member_ref,
            query
                .finding_ref
                .as_deref()
                .unwrap_or("cybersec:finding:storage-unspecified"),
            query
                .processor_report_ref
                .as_deref()
                .unwrap_or("processor-report:cybersec-unspecified"),
            query
                .subject_ref
                .as_deref()
                .unwrap_or("storage:evidence:unspecified"),
            detail_refs,
            query.now.unwrap_or_else(crate::engine::now_seconds),
        )?,
    ))
}

async fn get_backend_snapshot(
    State(state): State<ApiState>,
    Query(query): Query<BackendSnapshotQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let member_ref = format!("service:storage:{}", state.service_identity.service_pk);
    Ok(Json(state.engine.backend_snapshot(
        member_ref,
        query.limit.unwrap_or(64),
        query.now.unwrap_or_else(crate::engine::now_seconds),
    )?))
}

async fn get_filesystem_view(
    State(state): State<ApiState>,
    Query(query): Query<BackendSnapshotQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let member_ref = format!("service:storage:{}", state.service_identity.service_pk);
    Ok(Json(state.engine.filesystem_view(
        member_ref,
        query.limit.unwrap_or(64),
        query.now.unwrap_or_else(crate::engine::now_seconds),
    )?))
}

async fn materialize_index(
    State(state): State<ApiState>,
    Json(request): Json<MaterializeIndexRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let count = state.engine.materialize_entries(&request.entries)?;
    let mut pin_intents = 0usize;
    for intent in request.pin_intents {
        state.engine.put_pin_intent(intent)?;
        pin_intents += 1;
    }
    Ok(Json(json!({
        "status": "materialized",
        "materializationBudgetRef": "materialization:storage:local-index:operator",
        "consumerFloorRef": "consumer-floor:storage:local-index:operator",
        "retentionPosture": {
            "state": "indexed",
            "retentionClass": "operator-local-index"
        },
        "entries": count,
        "pinIntents": pin_intents
    })))
}

async fn search(
    State(state): State<ApiState>,
    Query(query): Query<SearchQuery>,
) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(state.engine.search(
        query.container_id.as_deref(),
        query.record_type.as_deref(),
        query.subject.as_deref(),
        query.tag.as_deref(),
    )?))
}

async fn put_graph_edge(
    State(state): State<ApiState>,
    Json(request): Json<PutGraphEdgeRequest>,
) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(state.engine.put_graph_edge(request.edge)?))
}

async fn get_graph_edges(
    State(state): State<ApiState>,
    Query(query): Query<GraphQuery>,
) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(state.engine.graph_edges(
        query.container_id.as_deref(),
        query.from_ref.as_deref(),
        query.relation.as_deref(),
        query.to_ref.as_deref(),
        query.limit.unwrap_or(64),
    )?))
}

async fn watch(State(state): State<ApiState>, ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(move |socket| watch_socket(socket, state.engine))
}

async fn watch_socket(mut socket: WebSocket, engine: StorageEngine) {
    let mut rx = engine.subscribe();
    while let Ok(event) = rx.recv().await {
        match serde_json::to_string(&event) {
            Ok(text) => {
                if socket.send(Message::Text(text.into())).await.is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::StorageServiceIdentity;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;
    use constitute_protocol::{
        CybersecEvidenceHoldRecord, STORAGE_CHUNK_HASH_ALG,
        STORAGE_ENCRYPTION_ALG_XCHACHA20POLY1305, STORAGE_OBJECT_HASH_ALG, SWARM_FRAME_VERSION,
        StorageChunkRef, StorageGraphEdge, StorageObjectManifest, StoragePinAttestation,
        StoragePinIntent, StoragePinStatus, SwarmFrameBody, SwarmRecordRef, ZoneScope,
        pubkey_from_sk_hex, storage_chunk_id, storage_ciphertext_hash, storage_object_id,
        swarm_frame_id, validate_cybersec_evidence_hold,
    };
    use tempfile::tempdir;
    use tower::ServiceExt;

    const STORAGE_TEST_SK: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";
    const ISSUER_TEST_SK: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn test_identity() -> StorageServiceIdentity {
        StorageServiceIdentity {
            service_pk: pubkey_from_sk_hex(STORAGE_TEST_SK).expect("service pk"),
            service_sk_hex: STORAGE_TEST_SK.to_string(),
        }
    }

    fn fixture_state(engine: StorageEngine) -> ApiState {
        ApiState {
            engine,
            service_identity: test_identity(),
            caac_fixture_mode: true,
        }
    }

    fn product_state(engine: StorageEngine) -> ApiState {
        ApiState {
            engine,
            service_identity: test_identity(),
            caac_fixture_mode: false,
        }
    }

    fn pin_intent(desired_replicas: u32) -> StoragePinIntent {
        StoragePinIntent {
            intent_id: "intent-edge-1".to_string(),
            object_refs: vec!["object-raw-1".to_string()],
            manifest_hash: "sha256:manifest".to_string(),
            desired_replicas,
            retention: "proof".to_string(),
            authority_refs: vec!["authority-raw-1".to_string()],
            expires_at: Some(1_700_000_100_000),
        }
    }

    fn pin_attestation(attestation_id: &str) -> StoragePinAttestation {
        StoragePinAttestation {
            attestation_id: attestation_id.to_string(),
            intent_id: "intent-edge-1".to_string(),
            storage_member_ref: "storage-member-raw-edge".to_string(),
            accepted_refs: vec!["object-raw-1".to_string()],
            availability_refs: vec![SwarmStorageAvailabilityRef {
                availability_id: format!("availability-{attestation_id}"),
                object_ref: "object-raw-1".to_string(),
                storage_member_ref: "storage-member-raw-edge".to_string(),
                expires_at: Some(1_700_000_100_000),
            }],
            status: StoragePinStatus::Pinned,
            expires_at: Some(1_700_000_100_000),
            issued_at: 1_700_000_000_000,
        }
    }

    fn source_chunk(bytes: &[u8]) -> crate::types::PutChunk {
        let hash = storage_ciphertext_hash(bytes);
        crate::types::PutChunk {
            chunk_ref: StorageChunkRef {
                chunk_id: storage_chunk_id(&hash),
                hash,
                hash_alg: STORAGE_CHUNK_HASH_ALG.to_string(),
                size: bytes.len() as u64,
            },
            ciphertext_base64: B64.encode(bytes),
        }
    }

    fn source_manifest(chunk: &crate::types::PutChunk) -> StorageObjectManifest {
        let container_id = "storage:container:source-api".to_string();
        let content_hash = storage_ciphertext_hash(chunk.chunk_ref.hash.as_bytes());
        StorageObjectManifest {
            object_id: storage_object_id(&container_id, &content_hash),
            container_id,
            content_hash,
            hash_alg: STORAGE_OBJECT_HASH_ALG.to_string(),
            encryption_alg: STORAGE_ENCRYPTION_ALG_XCHACHA20POLY1305.to_string(),
            key_ref: "source:key:api".to_string(),
            chunks: vec![chunk.chunk_ref.clone()],
            created_at: 1_700_000_000,
            media_type: "application/vnd.constitution.source-pack".to_string(),
            logical_deleted_at: None,
            tags: vec!["source".to_string()],
        }
    }

    fn storage_edge_frame(
        frame_kind: SwarmFrameKind,
        record_kind: &str,
        channel_id: &str,
        record_id: &str,
        record: Value,
        nonce: &str,
    ) -> SwarmFrame {
        let now = 1_700_000_000_000;
        let mut frame = SwarmFrame {
            version: SWARM_FRAME_VERSION,
            frame_id: String::new(),
            kind: frame_kind,
            issuer: "runtime:browser-test".to_string(),
            audience: json!({ "service": "storage" }),
            zone_scope: Some(ZoneScope {
                zone_id: "zone_lab".to_string(),
                privacy: Some("rawIds".to_string()),
                ttl: Some(30),
                max_hops: Some(2),
            }),
            issued_at: now,
            expires_at: Some(now + 60_000),
            nonce: nonce.to_string(),
            correlation_id: Some(format!("corr-{nonce}")),
            channel_id: Some(channel_id.to_string()),
            record_ref: Some(SwarmRecordRef {
                kind: record_kind.to_string(),
                id: record_id.to_string(),
                revision: Some(1),
            }),
            capability: Some(constitute_protocol::CAPABILITY_STORAGE_PIN.to_string()),
            body: SwarmFrameBody {
                encoding: "caac".to_string(),
                envelope: Some(json!({
                    "envelopeId": format!("env-{nonce}"),
                    "shape": "sealed-frame-placeholder",
                    "sealed": true,
                    "sealedPayload": {
                        "record": record
                    }
                })),
                public_bootstrap: false,
                payload: None,
                signature: Some("fixture-signature-placeholder".to_string()),
            },
            ack: None,
        };
        frame.frame_id = swarm_frame_id(&frame).expect("frame id");
        frame
    }

    fn product_storage_edge_frame(
        frame_kind: SwarmFrameKind,
        record_kind: &str,
        channel_id: &str,
        record_id: &str,
        record: Value,
        nonce: &str,
    ) -> SwarmFrame {
        let now = 1_700_000_000_000;
        let envelope = seal_envelope(
            record_kind,
            &json!({ "record": record }),
            ISSUER_TEST_SK,
            &[test_identity().service_pk],
            now,
            now + 60_000,
        )
        .expect("seal");
        let mut frame = SwarmFrame {
            version: SWARM_FRAME_VERSION,
            frame_id: String::new(),
            kind: frame_kind,
            issuer: pubkey_from_sk_hex(ISSUER_TEST_SK).expect("issuer pk"),
            audience: json!({ "service": "storage" }),
            zone_scope: Some(ZoneScope {
                zone_id: "zone_lab".to_string(),
                privacy: Some("rawIds".to_string()),
                ttl: Some(30),
                max_hops: Some(2),
            }),
            issued_at: now,
            expires_at: Some(now + 60_000),
            nonce: nonce.to_string(),
            correlation_id: Some(format!("corr-{nonce}")),
            channel_id: Some(channel_id.to_string()),
            record_ref: Some(SwarmRecordRef {
                kind: record_kind.to_string(),
                id: record_id.to_string(),
                revision: Some(1),
            }),
            capability: Some(constitute_protocol::CAPABILITY_STORAGE_PIN.to_string()),
            body: SwarmFrameBody {
                encoding: "caac".to_string(),
                envelope: Some(serde_json::to_value(envelope).expect("envelope json")),
                public_bootstrap: false,
                payload: None,
                signature: None,
            },
            ack: None,
        };
        frame.frame_id = swarm_frame_id(&frame).expect("frame id");
        frame
    }

    #[test]
    fn storage_edge_pin_intent_emits_attestation_and_projection() {
        let dir = tempdir().expect("tempdir");
        let engine = StorageEngine::open(dir.path()).expect("engine");
        let state = fixture_state(engine);
        let intent = pin_intent(1);
        let frame = storage_edge_frame(
            SwarmFrameKind::StoragePinIntent,
            constitute_protocol::RECORD_STORAGE_PIN_INTENT,
            constitute_protocol::RECORD_STORAGE_PIN_INTENT,
            &intent.intent_id,
            serde_json::to_value(&intent).expect("intent json"),
            "nonce-storage-pin-intent",
        );
        let response =
            consume_edge_frame(&state, frame, 1_700_000_000_000).expect("edge pin intent");

        assert_eq!(response["status"], "accepted");
        assert_eq!(response["attestation"]["intentId"], "intent-edge-1");
        assert_eq!(response["projection"]["pinnedCount"], 1);
        assert_eq!(response["projection"]["missingReplicas"], 0);
        assert_eq!(response["projection"]["status"], "satisfied");
        assert_eq!(
            response["emittedRecords"][0]["recordKind"],
            constitute_protocol::RECORD_STORAGE_PIN_ATTESTATION
        );
    }

    #[test]
    fn storage_gateway_stream_frame_consumes_without_http_and_emits_response_frames() {
        let dir = tempdir().expect("tempdir");
        let engine = StorageEngine::open(dir.path()).expect("engine");
        let state = fixture_state(engine);
        let intent = pin_intent(1);
        let frame = storage_edge_frame(
            SwarmFrameKind::StoragePinIntent,
            constitute_protocol::RECORD_STORAGE_PIN_INTENT,
            constitute_protocol::RECORD_STORAGE_PIN_INTENT,
            &intent.intent_id,
            serde_json::to_value(&intent).expect("intent json"),
            "nonce-storage-stream-pin-intent",
        );
        let emitted =
            process_gateway_frame(&state, frame, 1_700_000_000_000).expect("stream frame");

        assert_eq!(emitted.len(), 2);
        assert!(
            emitted
                .iter()
                .any(|frame| frame.kind == SwarmFrameKind::StoragePinAttestation)
        );
        assert!(
            emitted
                .iter()
                .any(|frame| frame.kind == SwarmFrameKind::ProjectionDelta)
        );
        for frame in emitted {
            validate_swarm_frame(&frame, 1_700_000_000_001).expect("valid emitted frame");
        }
    }

    #[test]
    fn storage_edge_pin_attestation_updates_projection_from_channel_record() {
        let dir = tempdir().expect("tempdir");
        let engine = StorageEngine::open(dir.path()).expect("engine");
        engine.put_pin_intent(pin_intent(2)).expect("put intent");
        let state = fixture_state(engine);
        let attestation = pin_attestation("attestation-edge");
        let frame = storage_edge_frame(
            SwarmFrameKind::StoragePinAttestation,
            constitute_protocol::RECORD_STORAGE_PIN_ATTESTATION,
            constitute_protocol::RECORD_STORAGE_PIN_ATTESTATION,
            &attestation.attestation_id,
            serde_json::to_value(&attestation).expect("attestation json"),
            "nonce-storage-pin-attestation",
        );
        let response =
            consume_edge_frame(&state, frame, 1_700_000_000_000).expect("edge attestation");

        assert_eq!(response["status"], "accepted");
        assert_eq!(response["projection"]["pinnedCount"], 1);
        assert_eq!(response["projection"]["missingReplicas"], 1);
    }

    #[tokio::test]
    async fn legacy_storage_product_routes_are_not_mounted() {
        let dir = tempdir().expect("tempdir");
        let engine = StorageEngine::open(dir.path()).expect("engine");
        let app = router(engine, test_identity());
        let retired_local_edge_adapter = format!("/{}{}", "swarm", "/edge");
        for (method, path) in [
            ("POST", retired_local_edge_adapter.as_str()),
            ("POST", "/v1/pin-intents"),
            ("POST", "/v1/pin-attestations"),
            ("POST", "/v1/pins"),
            ("GET", "/v1/watch"),
            ("POST", "/v1/local-index/materialize"),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{method} {path}");
        }
    }

    #[tokio::test]
    async fn operator_backend_posture_and_snapshot_are_explicit_storage_views() {
        let dir = tempdir().expect("tempdir");
        let engine = StorageEngine::open(dir.path()).expect("engine");
        engine.put_pin_intent(pin_intent(1)).expect("put intent");
        let app = router(engine, test_identity());

        let posture = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operator/storage/v1/backend-posture?now=1700000000")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(posture.status(), StatusCode::OK);

        let snapshot = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operator/storage/v1/snapshot?now=1700000000&limit=4")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(snapshot.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn operator_evidence_custody_exposes_storage_fulfillment_without_access_authority() {
        let dir = tempdir().expect("tempdir");
        let engine = StorageEngine::open(dir.path()).expect("engine");
        let app = router(engine, test_identity());

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operator/storage/v1/evidence-custody?now=1700000000&findingRef=cybersec:finding:1&processorReportRef=processor-report:cybersec:1&subjectRef=logging.events.encryptedDetail&detailRefs=encrypted-detail:logging.default")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let hold: CybersecEvidenceHoldRecord = serde_json::from_slice(&body).expect("hold");
        validate_cybersec_evidence_hold(&hold).expect("valid evidence hold");
        assert_eq!(hold.state, "holding");
        assert_eq!(hold.detail_refs, vec!["encrypted-detail:logging.default"]);
        assert_eq!(
            hold.safe_facts["accessAuthority"].as_str(),
            Some("notOwned")
        );
        assert_eq!(
            hold.safe_facts["threatSemantics"].as_str(),
            Some("notOwned")
        );
    }

    #[tokio::test]
    async fn operator_filesystem_view_is_explicit_storage_materialization() {
        let dir = tempdir().expect("tempdir");
        let engine = StorageEngine::open(dir.path()).expect("engine");
        let app = router(engine, test_identity());

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operator/storage/v1/filesystem-view?now=1700000000&limit=4")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn operator_graph_edges_are_explicit_storage_view() {
        let dir = tempdir().expect("tempdir");
        let engine = StorageEngine::open(dir.path()).expect("engine");
        let app = router(engine, test_identity());
        let edge = StorageGraphEdge {
            edge_id: "edge-api-source-object".to_string(),
            container_id: "container-source".to_string(),
            from_ref: "source:snapshot:1".to_string(),
            relation: "stores".to_string(),
            to_ref: "storage:object:source-pack-1".to_string(),
            detail_ref: None,
            created_at: 1_700_000_001,
        };

        let create = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/operator/storage/v1/graph-edges")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({ "edge": edge })).expect("edge json"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(create.status(), StatusCode::OK);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operator/storage/v1/graph-edges?containerId=container-source&fromRef=source:snapshot:1&relation=stores")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn operator_source_object_route_stores_object_edge_and_availability() {
        let dir = tempdir().expect("tempdir");
        let engine = StorageEngine::open(dir.path()).expect("engine");
        let app = router(engine, test_identity());
        let chunk = source_chunk(b"source-api-ciphertext");
        let manifest = source_manifest(&chunk);

        let create = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/operator/storage/v1/source-objects")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "sourceGraphRef": "source:graph:api",
                            "sourceSnapshotRef": "source:snapshot:api-head",
                            "storageMemberRef": "service:storage:local",
                            "manifest": manifest,
                            "chunks": [chunk],
                            "authorityRefs": ["authority:source:api"],
                            "desiredReplicas": 1,
                            "retention": "source-object",
                            "expiresAt": 1_700_000_100,
                            "issuedAt": 1_700_000_000
                        }))
                        .expect("source object json"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(create.status(), StatusCode::OK);
        let body = axum::body::to_bytes(create.into_body(), usize::MAX)
            .await
            .expect("body");
        let value: Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(value["graphEdge"]["fromRef"], "source:snapshot:api-head");
        assert_eq!(value["pinAttestation"]["projection"]["status"], "satisfied");

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operator/storage/v1/graph-edges?containerId=storage:container:source-api&fromRef=source:snapshot:api-head&relation=sourceSnapshot.stores")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn storage_edge_rejects_placeholder_caac_outside_fixture_mode() {
        let dir = tempdir().expect("tempdir");
        let engine = StorageEngine::open(dir.path()).expect("engine");
        let state = product_state(engine);
        let intent = pin_intent(1);
        let frame = storage_edge_frame(
            SwarmFrameKind::StoragePinIntent,
            constitute_protocol::RECORD_STORAGE_PIN_INTENT,
            constitute_protocol::RECORD_STORAGE_PIN_INTENT,
            &intent.intent_id,
            serde_json::to_value(&intent).expect("intent json"),
            "nonce-placeholder-rejected",
        );

        let err = consume_edge_frame(&state, frame, 1_700_000_000_000)
            .expect_err("placeholder must reject");
        assert!(err.0.to_string().contains("placeholder CAAC"));
    }

    #[test]
    fn storage_edge_opens_real_caac_before_reading_pin_intent_payload() {
        let dir = tempdir().expect("tempdir");
        let engine = StorageEngine::open(dir.path()).expect("engine");
        let state = product_state(engine);
        let intent = pin_intent(1);
        let frame = product_storage_edge_frame(
            SwarmFrameKind::StoragePinIntent,
            constitute_protocol::RECORD_STORAGE_PIN_INTENT,
            constitute_protocol::RECORD_STORAGE_PIN_INTENT,
            &intent.intent_id,
            serde_json::to_value(&intent).expect("intent json"),
            "nonce-real-caac-pin-intent",
        );

        let response =
            consume_edge_frame(&state, frame, 1_700_000_000_000).expect("edge pin intent");
        assert_eq!(response["status"], "accepted");
        assert_eq!(response["intent"]["intentId"], "intent-edge-1");
    }
}
