use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Path, Query, State, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::engine::StorageEngine;
use crate::types::{
    MaterializeIndexRequest, PruneRequest, PutIndexShardRequest, PutKeyGrantRequest,
    PutObjectRequest, PutPinRequest,
};

#[derive(Clone)]
pub struct ApiState {
    pub engine: StorageEngine,
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

pub fn router(engine: StorageEngine) -> Router {
    let state = ApiState { engine };
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
        .route("/v1/pins", post(put_pin))
        .route("/v1/pins/{pin_id}", delete(retract_pin))
        .route("/v1/prune", post(prune))
        .route("/v1/local-index/materialize", post(materialize_index))
        .route("/v1/local-index/search", get(search))
        .route("/v1/watch", get(watch))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn hosted_service_manifest() -> impl IntoResponse {
    Json(json!({
        "service": "storage",
        "deviceLabel": "Constitute Storage",
        "serviceVersion": env!("CARGO_PKG_VERSION"),
        "apiBaseUrl": "",
        "healthUrl": "/health",
        "capabilities": [
            "encrypted_objects",
            "content_addressed_chunks",
            "encrypted_index_shards",
            "key_grants",
            "pin_leases",
            "prune",
            "local_search",
            "watch"
        ]
    }))
}

async fn health(State(state): State<ApiState>) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(state.engine.health()?))
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

async fn materialize_index(
    State(state): State<ApiState>,
    Json(request): Json<MaterializeIndexRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let count = state.engine.materialize_entries(&request.entries)?;
    Ok(Json(json!({ "status": "materialized", "entries": count })))
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
