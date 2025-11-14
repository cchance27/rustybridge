mod cli;
mod client;
mod crypto;
mod server;
mod session;
mod terminal;

use crate::{cli::CliConfig, client::run_client, server::run_server};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    match CliConfig::parse()? {
        CliConfig::Server(cfg) => run_server(cfg).await?,
        CliConfig::Client(cfg) => run_client(cfg).await?,
    }

    Ok(())
}

fn init_tracing() {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(env_filter).try_init();
}
