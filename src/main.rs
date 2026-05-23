use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use constitute_storage::{StorageEngine, StorageServiceIdentity, api, edge_client};
use tracing::info;

#[derive(Debug, Parser)]
#[command(name = "constitute-storage")]
#[command(about = "CAAC Storage local encrypted object/index service")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:7478")]
    bind: SocketAddr,
    #[arg(long, default_value = "data")]
    data_dir: PathBuf,
    #[arg(long, env = "CONSTITUTE_SWARM_EDGE_ENDPOINT")]
    swarm_edge_endpoint: Option<String>,
    #[arg(long, default_value = "zone_lab", env = "CONSTITUTE_SWARM_ZONE_ID")]
    swarm_zone_id: String,
}

fn configured_swarm_edge_endpoint(args: &Args) -> Option<String> {
    args.swarm_edge_endpoint
        .clone()
        .or_else(|| std::env::var("CONSTITUTE_SWARM_EDGE_URL").ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "constitute_storage=info,tower_http=info".into()),
        )
        .init();

    let args = Args::parse();
    let engine = StorageEngine::open(&args.data_dir)?;
    let identity = StorageServiceIdentity::load_or_create(&args.data_dir)?;
    if let Some(gateway_endpoint) = configured_swarm_edge_endpoint(&args) {
        let edge_state = api::ApiState {
            engine: engine.clone(),
            service_identity: identity.clone(),
            caac_fixture_mode: false,
        };
        let edge_config = edge_client::default_config(
            gateway_endpoint,
            args.swarm_zone_id.clone(),
            identity.service_pk.clone(),
            identity.service_sk_hex.clone(),
        );
        tokio::spawn(async move {
            if let Err(err) = edge_client::run_swarm_edge_client(edge_state, edge_config).await {
                tracing::warn!(error = %err, "storage swarm edge client stopped");
            }
        });
    }
    let app = api::router(engine, identity);
    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    info!(bind = %args.bind, data_dir = %args.data_dir.display(), "constitute-storage ready");
    axum::serve(listener, app).await?;
    Ok(())
}
