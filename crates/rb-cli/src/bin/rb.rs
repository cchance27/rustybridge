use anyhow::Result;
use client_core::run_client;
use rb_cli::{client_cli::ClientArgs, init_tracing};

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let config = ClientArgs::parse_config()?;
    run_client(config).await
}
