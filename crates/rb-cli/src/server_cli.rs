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
    /// Hostname used across admin operations (add-host, grant/revoke, set/unset, list)
    #[arg(long = "hostname", value_name = "NAME")]
    pub hostname: Option<String>,

    /// Grant a user access to a relay host
    #[arg(long = "grant-access", action = ArgAction::SetTrue, requires = "hostname", conflicts_with_all = ["set_option_key", "unset_option_key", "revoke_access", "list_hosts", "list_options", "list_access"])]
    pub grant_access: bool,
    /// Username for --grant-access/--revoke-access
    #[arg(long = "user", value_name = "USER")]
    pub user: Option<String>,

    /// Set an option key/value for a relay host
    #[arg(long = "set-option", value_name = "KEY", requires = "hostname", conflicts_with_all = ["grant_access", "revoke_access", "unset_option_key", "list_hosts", "list_options", "list_access"])]
    pub set_option_key: Option<String>,
    /// Value for --set-option
    #[arg(long = "value", value_name = "VALUE", requires = "set_option_key")]
    pub set_option_value: Option<String>,

    /// Unset (remove) an option for a relay host
    #[arg(long = "unset-option", value_name = "KEY", requires = "hostname", conflicts_with_all = ["grant_access", "revoke_access", "set_option_key", "list_hosts", "list_options", "list_access"])]
    pub unset_option_key: Option<String>,

    /// Revoke a user's access to a relay host
    #[arg(long = "revoke-access", action = ArgAction::SetTrue, requires = "hostname", conflicts_with_all = ["grant_access", "set_option_key", "unset_option_key", "list_hosts", "list_options", "list_access"])]
    pub revoke_access: bool,

    /// List all relay hosts
    #[arg(long = "list-hosts", action = ArgAction::SetTrue, conflicts_with_all = ["grant_access", "revoke_access", "set_option_key", "unset_option_key", "hostname", "list_options", "list_access"])]
    pub list_hosts: bool,

    /// List all options for the target hostname
    #[arg(long = "list-options", action = ArgAction::SetTrue, requires = "hostname", conflicts_with_all = ["grant_access", "revoke_access", "set_option_key", "unset_option_key", "list_hosts", "list_access"])]
    pub list_options: bool,

    /// List all users with access to the target hostname
    #[arg(long = "list-access", action = ArgAction::SetTrue, requires = "hostname", conflicts_with_all = ["grant_access", "revoke_access", "set_option_key", "unset_option_key", "list_hosts", "list_options"])]
    pub list_access: bool,

    /// Add a new user (prompts for password if not provided)
    #[arg(long = "add-user", action = ArgAction::SetTrue, conflicts_with_all = ["list_hosts", "list_options", "list_access", "grant_access", "revoke_access", "set_option_key", "unset_option_key", "add_host", "hostname"])]
    pub add_user: bool,
    /// Remove a user and revoke all of their access
    #[arg(long = "remove-user", action = ArgAction::SetTrue, conflicts_with_all = ["list_hosts", "list_options", "list_access", "grant_access", "revoke_access", "set_option_key", "unset_option_key", "add_host", "hostname"])]
    pub remove_user: bool,
    /// Password for --add-user; omit to be prompted securely
    #[arg(long = "password", value_name = "PASSWORD")]
    pub password: Option<String>,

    /// List all users (prints one username per line)
    #[arg(long = "list-user", action = ArgAction::SetTrue, visible_alias = "list-users", conflicts_with_all = ["list_hosts", "list_options", "list_access", "grant_access", "revoke_access", "set_option_key", "unset_option_key", "add_host", "hostname", "add_user", "remove_user", "user", "password"])]
    pub list_user: bool,

    /// Refresh target's stored host key by refetching it (prompts to store)
    #[arg(long = "refresh-target-hostkey", action = ArgAction::SetTrue, requires = "hostname", conflicts_with_all = ["list_hosts", "list_options", "list_access", "grant_access", "revoke_access", "set_option_key", "unset_option_key", "add_host", "add_user", "remove_user", "user", "password", "list_user"])]
    pub refresh_target_hostkey: bool,
}

#[derive(Clone)]
pub enum ServerCommand {
    Run(ServerConfig),
    AddRelayHost { endpoint: String, name: String },
    GrantAccess { name: String, user: String },
    SetOption { name: String, key: String, value: String },
    UnsetOption { name: String, key: String },
    RevokeAccess { name: String, user: String },
    ListHosts,
    ListOptions { name: String },
    ListAccess { name: String },
    AddUser { user: String, password: Option<String> },
    RemoveUser { user: String },
    ListUsers,
    RefreshTargetHostkey { name: String },
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
                .hostname
                .ok_or_else(|| anyhow!("--hostname is required when using --add-host"))?;
            return Ok(ServerCommand::AddRelayHost { endpoint, name });
        }

        if args.grant_access {
            let name = args
                .hostname
                .ok_or_else(|| anyhow!("--hostname is required when using --grant-access"))?;
            let user = args
                .user
                .ok_or_else(|| anyhow!("--user is required when using --grant-access"))?;
            return Ok(ServerCommand::GrantAccess { name, user });
        }

        if let Some(key) = args.set_option_key {
            let name = args
                .hostname
                .ok_or_else(|| anyhow!("--hostname is required when using --set-option"))?;
            let value = args
                .set_option_value
                .ok_or_else(|| anyhow!("--value is required when using --set-option"))?;
            return Ok(ServerCommand::SetOption { name, key, value });
        }

        if let Some(key) = args.unset_option_key {
            let name = args
                .hostname
                .ok_or_else(|| anyhow!("--hostname is required when using --unset-option"))?;
            return Ok(ServerCommand::UnsetOption { name, key });
        }

        if args.revoke_access {
            let name = args
                .hostname
                .ok_or_else(|| anyhow!("--hostname is required when using --revoke-access"))?;
            let user = args
                .user
                .ok_or_else(|| anyhow!("--user is required when using --revoke-access"))?;
            return Ok(ServerCommand::RevokeAccess { name, user });
        }

        if args.list_hosts {
            return Ok(ServerCommand::ListHosts);
        }

        if args.list_options {
            let name = args
                .hostname
                .ok_or_else(|| anyhow!("--hostname is required when using --list-options"))?;
            return Ok(ServerCommand::ListOptions { name });
        }

        if args.list_access {
            let name = args
                .hostname
                .ok_or_else(|| anyhow!("--hostname is required when using --list-access"))?;
            return Ok(ServerCommand::ListAccess { name });
        }

        if args.add_user {
            let user = args.user.ok_or_else(|| anyhow!("--user is required with --add-user"))?;
            return Ok(ServerCommand::AddUser { user, password: args.password });
        }

        if args.remove_user {
            let user = args.user.ok_or_else(|| anyhow!("--user is required with --remove-user"))?;
            return Ok(ServerCommand::RemoveUser { user });
        }

        if args.list_user {
            return Ok(ServerCommand::ListUsers);
        }

        if args.refresh_target_hostkey {
            let name = args
                .hostname
                .ok_or_else(|| anyhow!("--hostname is required when using --refresh-target-hostkey"))?;
            return Ok(ServerCommand::RefreshTargetHostkey { name });
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
