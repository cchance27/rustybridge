use std::env;

use anyhow::{Context, Result, anyhow, bail};
use clap::{ArgAction, Parser};
use rpassword::prompt_password;

use crate::terminal::{NewlineMode, newline_mode_from_env};

const DEFAULT_SERVER_PORT: u16 = 2222;

#[derive(Debug, Parser)]
#[command(
    name = "lssh",
    about = "Legacy-friendly SSH client with relaxed crypto preferences"
)]
struct RawArgs {
    /// Start an embedded SSH server instead of connecting to one
    #[arg(long, action = ArgAction::SetTrue)]
    server: bool,
    /// Address to bind the embedded server to (defaults to 0.0.0.0)
    #[arg(long, value_name = "ADDR", requires = "server")]
    bind: Option<String>,
    /// Target host; supports optional [user@]host[:port] syntax
    #[arg(value_name = "HOST", required_unless_present = "server")]
    target: Option<String>,
    /// Optional remote command (everything after HOST)
    #[arg(value_name = "COMMAND", trailing_var_arg = true, requires = "target")]
    command: Vec<String>,
    /// Override remote username (defaults to user@host or current user)
    #[arg(short = 'l', long = "username", value_name = "USER")]
    username: Option<String>,
    /// Provide password non-interactively; otherwise we prompt like OpenSSH
    #[arg(short = 'p', long = "password", value_name = "PASSWORD")]
    password: Option<String>,
    /// Override the parsed port (defaults to 22 or the :port suffix)
    #[arg(short, long, value_name = "PORT")]
    port: Option<u16>,
    /// Override the newline translation mode (defaults to env or LF)
    #[arg(long, value_enum, value_name = "MODE")]
    newline: Option<NewlineMode>,
    /// Force local echo regardless of environment defaults
    #[arg(long, action = ArgAction::SetTrue)]
    local_echo: bool,
}

#[derive(Clone)]
pub enum CliConfig {
    Client(ClientConfig),
    Server(ServerConfig),
}

#[derive(Clone)]
pub struct ClientConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub command: Option<String>,
    pub newline_mode: NewlineMode,
    pub local_echo: bool,
}

#[derive(Clone)]
pub struct ServerConfig {
    pub bind: String,
    pub port: u16,
}

impl CliConfig {
    pub fn parse() -> Result<Self> {
        let args = RawArgs::parse();
        Self::try_from(args)
    }
}

impl TryFrom<RawArgs> for CliConfig {
    type Error = anyhow::Error;

    fn try_from(mut args: RawArgs) -> Result<Self> {
        if args.server {
            if !args.command.is_empty() {
                bail!("command arguments are not supported when --server is present");
            }
            let bind = args
                .bind
                .or_else(|| args.target.take())
                .unwrap_or_else(|| "0.0.0.0".to_string());
            let port = args.port.unwrap_or(DEFAULT_SERVER_PORT);
            return Ok(CliConfig::Server(ServerConfig { bind, port }));
        }

        let target_raw = args
            .target
            .ok_or_else(|| anyhow!("missing HOST argument"))?;
        let target = parse_target(&target_raw)?;
        let port = args.port.unwrap_or(target.port);
        let newline_mode = args
            .newline
            .or_else(newline_mode_from_env)
            .unwrap_or_default();

        let local_echo = if args.local_echo {
            true
        } else {
            env::var("LSSH_LOCAL_ECHO")
                .map(|v| v != "0")
                .unwrap_or(false)
        };

        let username = args
            .username
            .or(target.inferred_username)
            .or_else(fallback_username)
            .ok_or_else(|| anyhow!("unable to determine username; use --username or user@host"))?;

        let password = resolve_password(args.password.as_deref(), &username, &target.host)?;

        let command = if args.command.is_empty() {
            None
        } else {
            Some(args.command.join(" "))
        };

        Ok(CliConfig::Client(ClientConfig {
            host: target.host,
            port,
            username,
            password,
            command,
            newline_mode,
            local_echo,
        }))
    }
}

struct TargetParts {
    host: String,
    port: u16,
    inferred_username: Option<String>,
}

fn parse_target(input: &str) -> Result<TargetParts> {
    let (username_part, host_part) = if let Some((user, host)) = input.rsplit_once('@') {
        (Some(user.to_string()), host.to_string())
    } else {
        (None, input.to_string())
    };

    let (host, port) = if host_part.starts_with('[') {
        parse_bracketed_host(&host_part)?
    } else if let Some((host, port_str)) = host_part.rsplit_once(':') {
        let port = port_str.parse::<u16>().context("invalid port")?;
        (host.to_string(), port)
    } else {
        (host_part, 22)
    };

    Ok(TargetParts {
        host,
        port,
        inferred_username: username_part,
    })
}

fn parse_bracketed_host(input: &str) -> Result<(String, u16)> {
    if let Some((host, port)) = input.rsplit_once("]:") {
        let host = host.trim_start_matches('[');
        let port = port.parse::<u16>().context("invalid port")?;
        Ok((host.to_string(), port))
    } else {
        let host = input.trim_start_matches('[').trim_end_matches(']');
        Ok((host.to_string(), 22))
    }
}

fn fallback_username() -> Option<String> {
    for key in ["LSSH_USER", "USER", "LOGNAME", "USERNAME"] {
        if let Ok(value) = env::var(key) && !value.is_empty() {
            return Some(value);
        }
    }
    let current = whoami::username();
    if current.is_empty() {
        None
    } else {
        Some(current)
    }
}

fn resolve_password(provided: Option<&str>, username: &str, host: &str) -> Result<String> {
    if let Some(value) = provided {
        return Ok(value.to_string());
    }

    if let Ok(value) = env::var("LSSH_PASSWORD") {
        return Ok(value);
    }

    let prompt = format!("{username}@{host} password: ");
    prompt_password(prompt).context("failed to read password interactively")
}
