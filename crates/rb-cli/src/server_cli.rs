use anyhow::{Result, anyhow};
use clap::{ArgAction, Parser};
use server_core::ServerConfig;

const DEFAULT_SERVER_PORT: u16 = 2222;

#[derive(Debug, Parser)]
#[command(name = "rb-server", about = "Embedded jump host / relay manager")]
pub struct ServerArgs {
    /// Address to bind the embedded server to (defaults to 0.0.0.0)
    #[arg(long, value_name = "ADDR")]
    pub bind: Option<String>,
    /// Override the listening port (defaults to 2222)
    #[arg(short = 'P', long, value_name = "PORT")]
    pub port: Option<u16>,
    /// Force regeneration of the stored server host key on startup
    #[arg(long, action = ArgAction::SetTrue)]
    pub roll_hostkey: bool,
    /// Add or update a relay host entry (ip:port)
    #[arg(long = "add-host", value_name = "IP:PORT")]
    pub add_host: Option<String>,
    /// Friendly name to associate with --add-host
    #[arg(long = "hostname", value_name = "NAME", requires = "add_host")]
    pub add_hostname: Option<String>,
}

#[derive(Clone)]
pub enum ServerCommand {
    Run(ServerConfig),
    AddRelayHost { endpoint: String, name: String },
}

impl ServerArgs {
    pub fn parse_command() -> Result<ServerCommand> {
        let args = ServerArgs::parse();
        ServerCommand::try_from(args)
    }
}

impl TryFrom<ServerArgs> for ServerCommand {
    type Error = anyhow::Error;

    fn try_from(args: ServerArgs) -> Result<Self> {
        if let Some(endpoint) = args.add_host {
            let name = args
                .add_hostname
                .ok_or_else(|| anyhow!("--hostname is required when using --add-host"))?;
            return Ok(ServerCommand::AddRelayHost { endpoint, name });
        }

        let bind = args.bind.unwrap_or_else(|| "0.0.0.0".to_string());
        let port = args.port.unwrap_or(DEFAULT_SERVER_PORT);

        Ok(ServerCommand::Run(ServerConfig {
            bind,
            port,
            roll_hostkey: args.roll_hostkey,
        }))
    }
}
