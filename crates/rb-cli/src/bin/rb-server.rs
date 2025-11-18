use anyhow::Result;
use rb_cli::{
    init_tracing, server_cli::{ServerArgs, ServerCommand}
};
use server_core::{add_relay_host, run_server};

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    match ServerArgs::parse_command()? {
        ServerCommand::Run(cfg) => run_server(cfg).await?,
        ServerCommand::AddRelayHost { endpoint, name } => add_relay_host(&endpoint, &name).await?,
    }
    Ok(())
}
