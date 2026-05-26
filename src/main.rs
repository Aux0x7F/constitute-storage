use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use constitute_protocol::StoragePinLease;
use constitute_storage::{
    MaterializeIndexRequest, ModuleExecutableInstantiationRequest, ModuleMaterializationRequest,
    PutGraphEdgeRequest, PutObjectRequest, PutSourceObjectRequest, StorageEngine,
    StorageServiceIdentity, api, edge_client,
};
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
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    ObjectPut {
        #[arg(long)]
        input: PathBuf,
    },
    SourceObject {
        #[arg(long)]
        input: PathBuf,
    },
    ObjectRead {
        #[arg(long)]
        object_ref: String,
    },
    GraphEdgePut {
        #[arg(long)]
        input: PathBuf,
    },
    GraphEdges {
        #[arg(long)]
        container_id: Option<String>,
        #[arg(long)]
        from_ref: Option<String>,
        #[arg(long)]
        relation: Option<String>,
        #[arg(long)]
        to_ref: Option<String>,
        #[arg(long, default_value_t = 64)]
        limit: usize,
    },
    PinPut {
        #[arg(long)]
        input: PathBuf,
    },
    LocalIndexMaterialize {
        #[arg(long)]
        input: PathBuf,
    },
    LocalIndexSearch {
        #[arg(long)]
        container_id: Option<String>,
        #[arg(long)]
        record_type: Option<String>,
        #[arg(long)]
        subject: Option<String>,
        #[arg(long)]
        tag: Option<String>,
    },
    ModuleMaterialization {
        #[arg(long)]
        input: PathBuf,
    },
    ModuleExecutable {
        #[arg(long)]
        input: PathBuf,
    },
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
    if let Some(command) = args.command {
        match command {
            Command::ObjectPut { input } => {
                let bytes = std::fs::read(&input)?;
                let request: PutObjectRequest = serde_json::from_slice(&bytes)?;
                let response = engine.put_object(request)?;
                println!("{}", serde_json::to_string_pretty(&response)?);
                return Ok(());
            }
            Command::SourceObject { input } => {
                let bytes = std::fs::read(&input)?;
                let request: PutSourceObjectRequest = serde_json::from_slice(&bytes)?;
                let response = engine.put_source_object(request)?;
                println!("{}", serde_json::to_string_pretty(&response)?);
                return Ok(());
            }
            Command::ObjectRead { object_ref } => {
                let object_id = object_ref
                    .trim()
                    .strip_prefix("storage:object:")
                    .filter(|value| !value.trim().is_empty())
                    .ok_or_else(|| anyhow::anyhow!("object-ref must start with storage:object:"))?;
                let response = engine.get_object(object_id)?;
                println!("{}", serde_json::to_string_pretty(&response)?);
                return Ok(());
            }
            Command::GraphEdgePut { input } => {
                let bytes = std::fs::read(&input)?;
                let request: PutGraphEdgeRequest = serde_json::from_slice(&bytes)?;
                let response = engine.put_graph_edge(request.edge)?;
                println!("{}", serde_json::to_string_pretty(&response)?);
                return Ok(());
            }
            Command::GraphEdges {
                container_id,
                from_ref,
                relation,
                to_ref,
                limit,
            } => {
                let response = engine.graph_edges(
                    container_id.as_deref(),
                    from_ref.as_deref(),
                    relation.as_deref(),
                    to_ref.as_deref(),
                    limit,
                )?;
                println!("{}", serde_json::to_string_pretty(&response)?);
                return Ok(());
            }
            Command::PinPut { input } => {
                let bytes = std::fs::read(&input)?;
                let request: StoragePinLease = serde_json::from_slice(&bytes)?;
                let response = engine.put_pin(request)?;
                println!("{}", serde_json::to_string_pretty(&response)?);
                return Ok(());
            }
            Command::LocalIndexMaterialize { input } => {
                let bytes = std::fs::read(&input)?;
                let request: MaterializeIndexRequest = serde_json::from_slice(&bytes)?;
                let count = engine.materialize_entries(&request.entries)?;
                let mut pin_intents = 0usize;
                for intent in request.pin_intents {
                    engine.put_pin_intent(intent)?;
                    pin_intents += 1;
                }
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "status": "materialized",
                        "materializationBudgetRef": "materialization:storage:local-index:operator",
                        "consumerFloorRef": "consumer-floor:storage:local-index:operator",
                        "retentionPosture": {
                            "state": "indexed",
                            "retentionClass": "operator-local-index"
                        },
                        "entries": count,
                        "pinIntents": pin_intents
                    }))?
                );
                return Ok(());
            }
            Command::LocalIndexSearch {
                container_id,
                record_type,
                subject,
                tag,
            } => {
                let response = engine.search(
                    container_id.as_deref(),
                    record_type.as_deref(),
                    subject.as_deref(),
                    tag.as_deref(),
                )?;
                println!("{}", serde_json::to_string_pretty(&response)?);
                return Ok(());
            }
            Command::ModuleMaterialization { input } => {
                let bytes = std::fs::read(&input)?;
                let request: ModuleMaterializationRequest = serde_json::from_slice(&bytes)?;
                let response = engine.materialize_module(request)?;
                println!("{}", serde_json::to_string_pretty(&response)?);
                return Ok(());
            }
            Command::ModuleExecutable { input } => {
                let bytes = std::fs::read(&input)?;
                let request: ModuleExecutableInstantiationRequest = serde_json::from_slice(&bytes)?;
                let response = engine.instantiate_module_executable(request)?;
                println!("{}", serde_json::to_string_pretty(&response)?);
                return Ok(());
            }
        }
    }
    let identity = StorageServiceIdentity::load_or_create(&args.data_dir)?;
    if let Some(gateway_endpoint) = args.swarm_edge_endpoint.clone() {
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
