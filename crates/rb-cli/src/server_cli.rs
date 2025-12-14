use clap::{Parser, Subcommand, ValueEnum};
use rb_types::{
    auth::ClaimType,
    config::{ServerConfig, WebServerConfig, WebTlsConfig},
};
use std::path::PathBuf;

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

    #[command(flatten)]
    pub web: WebArgs,

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

    pub fn to_web_config(&self) -> anyhow::Result<Option<WebServerConfig>> {
        self.web.to_config()
    }
}

#[derive(Debug, Parser, Default)]
pub struct WebArgs {
    /// Start the embedded web server alongside SSH
    #[arg(long = "web", action = clap::ArgAction::SetTrue, help_heading = "Web Server")]
    pub enable: bool,
    /// Address to bind the web server to
    #[arg(long = "web-bind", value_name = "ADDR", help_heading = "Web Server")]
    pub web_bind: Option<String>,
    /// Listening port for the web server
    #[arg(long = "web-port", value_name = "PORT", help_heading = "Web Server")]
    pub web_port: Option<u16>,
    /// Optional path to static assets directory (dev override)
    #[arg(long = "web-static", value_name = "PATH", help_heading = "Web Server")]
    pub web_static_dir: Option<PathBuf>,
    /// Path to TLS certificate (PEM) for native HTTPS
    #[arg(long = "web-tls-cert", value_name = "PATH", help_heading = "Web Server")]
    pub web_tls_cert: Option<PathBuf>,
    /// Path to TLS private key (PEM) for native HTTPS
    #[arg(long = "web-tls-key", value_name = "PATH", help_heading = "Web Server")]
    pub web_tls_key: Option<PathBuf>,
    /// Public mount path for built assets (defaults to /assets)
    #[arg(long = "web-assets-mount", value_name = "PATH", help_heading = "Web Server")]
    pub web_assets_mount: Option<String>,
}

impl WebArgs {
    pub fn to_config(&self) -> anyhow::Result<Option<WebServerConfig>> {
        if !self.enable {
            return Ok(None);
        }

        let tls = match (&self.web_tls_cert, &self.web_tls_key) {
            (Some(cert), Some(key)) => Some(WebTlsConfig {
                cert_path: cert.clone(),
                key_path: key.clone(),
            }),
            (None, None) => None,
            _ => {
                return Err(anyhow::anyhow!("--web-tls-cert and --web-tls-key must be provided together"));
            }
        };

        Ok(Some(WebServerConfig {
            bind: self.web_bind.clone().unwrap_or_else(|| "127.0.0.1".to_string()),
            port: self.web_port.unwrap_or(8080),
            static_dir: self.web_static_dir.clone(),
            tls,
            assets_mount: self.web_assets_mount.clone().unwrap_or_else(|| "/assets".to_string()),
        }))
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
    /// Manage groups and memberships
    Groups {
        #[command(subcommand)]
        cmd: GroupsCmd,
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
    /// Manage roles and claims
    Roles {
        #[command(subcommand)]
        cmd: RolesCmd,
    },
    /// Manage web server settings
    Web {
        #[command(subcommand)]
        cmd: WebCmd,
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
pub enum WebCmd {
    /// Set a web server option (limited to known keys)
    Set {
        #[arg(value_enum, value_name = "OPTION", help = "Option key to set (e.g. server-url)")]
        key: WebOptionKey,
        #[arg(value_name = "VALUE", help = "Value to store for the option")]
        value: String,
    },
}

#[derive(Debug, Clone, ValueEnum)]
pub enum WebOptionKey {
    /// Base URL used to generate web/SSH OIDC links (stored as web_base_url)
    #[value(name = "server-url")]
    #[value(alias = "server_url")]
    #[value(alias = "web-base-url")]
    #[value(alias = "base-url")]
    ServerUrl,
    /// OIDC issuer discovery URL
    #[value(name = "oidc-issuer-url")]
    #[value(alias = "oidc_issuer_url")]
    OidcIssuerUrl,
    /// OIDC client ID
    #[value(name = "oidc-client-id")]
    #[value(alias = "oidc_client_id")]
    OidcClientId,
    /// OIDC client secret (stored as plaintext; ensure db is encrypted at rest)
    #[value(name = "oidc-client-secret")]
    #[value(alias = "oidc_client_secret")]
    OidcClientSecret,
    /// OIDC redirect/callback URL
    #[value(name = "oidc-redirect-url")]
    #[value(alias = "oidc_redirect_url")]
    OidcRedirectUrl,
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
    /// Grant a principal (user or group) access to a host
    Grant {
        name: String,
        #[arg(long, conflicts_with = "group", required_unless_present = "group")]
        user: Option<String>,
        #[arg(long, conflicts_with = "user", required_unless_present = "user")]
        group: Option<String>,
    },
    /// Revoke a principal's access from a host
    Revoke {
        name: String,
        #[arg(long, conflicts_with = "group", required_unless_present = "group")]
        user: Option<String>,
        #[arg(long, conflicts_with = "user", required_unless_present = "user")]
        group: Option<String>,
    },
    /// List principals with access to a host
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
    /// Add an SSH public key to a user
    AddPubkey {
        /// Username to attach the public key to
        user: String,
        /// Read the public key from a file instead of a positional value
        #[arg(long, value_name = "PATH", conflicts_with = "public_key")]
        key_file: Option<PathBuf>,
        /// Public key in OpenSSH format (e.g. "ssh-ed25519 AAAA...")
        #[arg(value_name = "PUBLIC_KEY", required_unless_present = "key_file")]
        public_key: Option<String>,
        /// Optional comment/label stored alongside the key
        #[arg(long)]
        comment: Option<String>,
    },
    /// List public keys for a user
    ListPubkeys {
        /// Username whose keys will be listed
        user: String,
    },
    /// Remove a public key by id for a user
    RemovePubkey {
        /// Username that owns the key (used for validation)
        user: String,
        /// Key id as shown by `list-pubkeys`
        key_id: i64,
    },
    /// Remove a user (revokes all access)
    Remove { user: String },
    /// List users
    List,
    /// Assign a role to a user
    AssignRole { user: String, role: String },
    /// Revoke a role from a user
    RevokeRole { user: String, role: String },
}

#[derive(Debug, Subcommand)]
pub enum GroupsCmd {
    /// Add a group
    Add { group: String },
    /// Remove a group (revokes access)
    Remove { group: String },
    /// List groups
    List,
    /// Manage group membership
    Members {
        #[command(subcommand)]
        cmd: GroupMembersCmd,
    },
    /// List groups for a user
    UserGroups { user: String },
}

#[derive(Debug, Subcommand)]
pub enum GroupMembersCmd {
    /// Add a user to a group
    Add { group: String, user: String },
    /// Remove a user from a group
    Remove { group: String, user: String },
    /// List members of a group
    List { group: String },
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
        /// Optional passphrase for the private key. If provided without a value, prompts securely.
        #[arg(long, value_name = "PASSPHRASE", num_args = 0..=1, require_equals = true)]
        passphrase: Option<Option<String>>,
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

#[derive(Debug, Subcommand)]
pub enum RolesCmd {
    /// Create a new role
    Create {
        name: String,
        #[arg(long)]
        description: Option<String>,
    },
    /// Delete a role
    Delete { name: String },
    /// List roles
    List,
    /// Add a claim to a role
    AddClaim { role: String, claim: ClaimType<'static> },
    /// Remove a claim from a role
    RemoveClaim { role: String, claim: ClaimType<'static> },
}
