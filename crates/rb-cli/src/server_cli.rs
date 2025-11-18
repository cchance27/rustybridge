use std::path::PathBuf;

use clap::{Parser, Subcommand};
use server_core::ServerConfig;

const DEFAULT_SERVER_PORT: u16 = 2222;

#[derive(Debug, Parser)]
#[command(name = "rb-server", about = "Embedded jump host / relay manager")]
pub struct ServerArgs {
    /// Address to bind the embedded server to (defaults to 127.0.0.1)
    #[arg(long, value_name = "ADDR")]
    pub bind: Option<String>,
    /// Override the listening port (defaults to 2222)
    #[arg(short = 'P', long, value_name = "PORT")]
    pub port: Option<u16>,
    /// Force regeneration of the stored server host key on startup
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub roll_hostkey: bool,

    #[command(subcommand)]
    pub cmd: Option<ServerSubcommand>,
}

impl ServerArgs {
    pub fn to_run_config(&self) -> ServerConfig {
        ServerConfig {
            bind: self.bind.clone().unwrap_or_else(|| "127.0.0.1".to_string()),
            port: self.port.unwrap_or(DEFAULT_SERVER_PORT),
            roll_hostkey: self.roll_hostkey,
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum ServerSubcommand {
    /// Manage relay hosts
    Hosts {
        #[command(subcommand)]
        cmd: HostsCmd,
    },
    /// Manage server users
    Users {
        #[command(subcommand)]
        cmd: UsersCmd,
    },
    /// Manage generic relay credentials
    Creds {
        #[command(subcommand)]
        cmd: CredsCmd,
    },
    /// Manage server secrets
    Secrets {
        #[command(subcommand)]
        cmd: SecretsCmd,
    },
    /// Launch a TUI application locally
    Tui {
        #[command(subcommand)]
        cmd: TuiCmd,
    },
}

#[derive(Debug, Subcommand)]
pub enum TuiCmd {
    /// Launch the Relay Selector app
    RelaySelector,
    /// Launch the Management app
    Management,
}

#[derive(Debug, Subcommand)]
pub enum HostsCmd {
    /// Add or update a relay host (ip:port)
    Add { name: String, endpoint: String },
    /// List configured relay hosts
    List,
    /// Delete a relay host (cascades options and ACLs)
    Delete { name: String },
    /// Relay host options
    #[command(subcommand)]
    Options(HostsOptionsCmd),
    /// Access control (ACLs) for a host
    #[command(subcommand)]
    Access(HostsAccessCmd),
    /// Refetch and store the host key for a host
    RefreshHostkey { name: String },
    /// Assign/unassign credentials to a host
    #[command(subcommand)]
    Creds(HostsCredsCmd),
}

#[derive(Debug, Subcommand)]
pub enum HostsOptionsCmd {
    /// List all options for a host
    List { name: String },
    /// Set a key to a value (stored encrypted at rest)
    Set { name: String, key: String, value: String },
    /// Remove an option
    Unset { name: String, key: String },
}

#[derive(Debug, Subcommand)]
pub enum HostsAccessCmd {
    /// Grant a user access to a host
    Grant { name: String, user: String },
    /// Revoke a user's access from a host
    Revoke { name: String, user: String },
    /// List users with access to a host
    List { name: String },
}

#[derive(Debug, Subcommand)]
pub enum HostsCredsCmd {
    /// Assign a credential to a host
    Assign { name: String, cred_name: String },
    /// Unassign any credential from a host
    Unassign { name: String },
}

#[derive(Debug, Subcommand)]
pub enum UsersCmd {
    /// Add a user (prompts for password if omitted)
    Add {
        user: String,
        #[arg(long)]
        password: Option<String>,
    },
    /// Remove a user (revokes all access)
    Remove { user: String },
    /// List users
    List,
}

#[derive(Debug, Subcommand)]
pub enum CredsCmd {
    /// Create a credential
    #[command(subcommand)]
    Create(CredsCreateCmd),
    /// Delete a credential
    Delete {
        name: String,
        #[arg(long)]
        force: bool,
    },
    /// List credentials
    List,
}

#[derive(Debug, Subcommand)]
pub enum CredsCreateCmd {
    /// Create a password credential
    Password {
        name: String,
        #[arg(long)]
        username: String,
        #[arg(long)]
        value: Option<String>,
    },
    /// Create an SSH key credential
    SshKey {
        name: String,
        #[arg(long)]
        username: String,
        #[arg(long)]
        key_file: Option<PathBuf>,
        #[arg(long)]
        value: Option<String>,
        #[arg(long)]
        cert_file: Option<PathBuf>,
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// Create an agent credential (restrict agent auth to this public key)
    Agent {
        name: String,
        #[arg(long)]
        username: String,
        #[arg(long)]
        pubkey_file: Option<PathBuf>,
        #[arg(long)]
        value: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum SecretsCmd {
    /// Rotate the server secrets key (re-encrypt credentials and options)
    RotateKey,
}
