use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use constitute_storage::{StorageEngine, api};
use tracing::info;

#[derive(Debug, Parser)]
#[command(name = "constitute-storage")]
#[command(about = "CAAC Storage local encrypted object/index service")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:7478")]
    bind: SocketAddr,
    #[arg(long, default_value = "data")]
    data_dir: PathBuf,
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
    let app = api::router(engine);
    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    info!(bind = %args.bind, data_dir = %args.data_dir.display(), "constitute-storage ready");
    axum::serve(listener, app).await?;
    Ok(())
}
