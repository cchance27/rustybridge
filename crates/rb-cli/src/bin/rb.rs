use anyhow::Result;
use clap::{CommandFactory, FromArgMatches, error::ErrorKind};
use client_core::{ClientConfig, run_client};
use rb_cli::{client_cli::ClientArgs, init_tracing};

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    // Build command so we can augment help with database path dynamically
    let cmd = ClientArgs::command();
    let args = match cmd.try_get_matches() {
        Ok(m) => ClientArgs::from_arg_matches(&m).map_err(|e| anyhow::anyhow!(e.to_string()))?,
        Err(e) => {
            if e.kind() == ErrorKind::DisplayHelp {
                e.print()?;
                println!("\nDatabase: {}", state_store::display_client_db_path());
                return Ok(());
            } else if e.kind() == ErrorKind::DisplayVersion {
                e.print()?;
                return Ok(());
            } else {
                return Err(anyhow::anyhow!(e));
            }
        }
    };
    let config = ClientConfig::try_from(args)?;
    run_client(config).await.map_err(|e| anyhow::anyhow!(e))
}
