use std::{collections::HashMap, env, path::PathBuf, time::Duration};

use anyhow::{Context, Result, anyhow, bail};
use clap::{ArgAction, Parser, ValueEnum};
use client_core::{ClientConfig, ClientIdentity};
use secrecy::SecretString;
use ssh_core::{
    forwarding::{self, ForwardingConfig, LocaleMode}, terminal::{NewlineMode, newline_mode_from_env}
};

#[derive(Debug, Parser)]
#[command(name = "rb", about = "Legacy-friendly SSH client with relaxed crypto options")]
pub struct ClientArgs {
    /// Target host; supports optional [user@]host[:port] syntax
    #[arg(value_name = "HOST")]
    target: String,
    /// Optional remote command (everything after HOST)
    #[arg(value_name = "COMMAND", trailing_var_arg = true, help_heading = "Client Options")]
    command: Vec<String>,
    /// Override remote username (defaults to user@host or current user)
    #[arg(short = 'l', long = "username", value_name = "USER", help_heading = "Client Options")]
    username: Option<String>,
    /// Provide password non-interactively; otherwise prompt like OpenSSH
    #[arg(short = 'p', long = "password", value_name = "PASSWORD", help_heading = "Client Options")]
    password: Option<String>,
    /// Override the parsed port (defaults to 22 or the :port suffix)
    #[arg(short = 'P', long, value_name = "PORT")]
    port: Option<u16>,
    /// Override the newline translation mode (defaults to env or LF)
    #[arg(long, value_enum, value_name = "MODE", help_heading = "Client Options")]
    newline: Option<NewlineMode>,
    /// Force local echo regardless of environment defaults
    #[arg(long, action = ArgAction::SetTrue, help_heading = "Client Options")]
    local_echo: bool,
    /// Prefer zlib compression (similar to OpenSSH's -C)
    #[arg(short = 'C', long, action = ArgAction::SetTrue, help_heading = "Client Options")]
    compress: bool,
    /// Rekey interval in seconds (default 3600)
    #[arg(long = "rekey-interval", value_name = "SECONDS", help_heading = "Client Options")]
    rekey_interval: Option<u64>,
    /// Rekey after this many bytes in each direction (default 1 GiB)
    #[arg(long = "rekey-bytes", value_name = "BYTES", help_heading = "Client Options")]
    rekey_bytes: Option<u64>,
    /// Send keepalive probes every N seconds (default 30)
    #[arg(long = "keepalive-interval", value_name = "SECONDS", help_heading = "Client Options")]
    keepalive_interval: Option<u64>,
    /// Disconnect after this many unanswered keepalives (default 3)
    #[arg(long = "keepalive-max", value_name = "COUNT", help_heading = "Client Options")]
    keepalive_max: Option<usize>,
    /// Accept an unknown host key for this session only
    #[arg(long = "accept-hostkey", action = ArgAction::SetTrue, help_heading = "Client Options")]
    accept_hostkey_once: bool,
    /// Accept and store an unknown host key for future sessions
    #[arg(long = "accept-store-hostkey", action = ArgAction::SetTrue, help_heading = "Client Options")]
    accept_store_hostkey: bool,
    /// Replace any cached host key for the target before connecting
    #[arg(long = "replace-hostkey", action = ArgAction::SetTrue, help_heading = "Client Options")]
    replace_hostkey: bool,
    /// Allow legacy/insecure crypto suites (equivalent to old behavior)
    #[arg(short = 'i', long = "insecure", action = ArgAction::SetTrue, help_heading = "Client Options")]
    insecure: bool,
    /// Private key to use for public-key authentication (repeatable)
    #[arg(long = "identity", value_name = "KEY", action = ArgAction::Append, help_heading = "Auth Options")]
    identities: Vec<PathBuf>,
    /// Explicit certificate mapping in KEY=CERT form (repeatable)
    #[arg(long = "identity-cert", value_name = "KEY=CERT", action = ArgAction::Append, help_heading = "Auth Options")]
    identity_certs: Vec<String>,
    /// Attempt authentication via the SSH agent specified in SSH_AUTH_SOCK
    #[arg(long = "agent-auth", action = ArgAction::SetTrue, help_heading = "Auth Options")]
    agent_auth: bool,
    /// Request OpenSSH agent forwarding for the interactive session
    #[arg(long = "forward-agent", action = ArgAction::SetTrue, help_heading = "Auth Options")]
    forward_agent: bool,
    /// Disable keyboard-interactive authentication
    #[arg(long = "no-keyboard-interactive", action = ArgAction::SetTrue, help_heading = "Auth Options")]
    no_keyboard_interactive: bool,
    /// Suppress password prompts (useful for key-only auth)
    #[arg(long = "no-password", action = ArgAction::SetTrue, help_heading = "Auth Options")]
    no_password: bool,
    /// Forward a local TCP port; format [bind_address:]port:host:hostport
    #[arg(short = 'L', long = "local-forward", value_name = "SPEC", action = ArgAction::Append, help_heading = "Forwarding Options")]
    local_forward: Vec<String>,
    /// Forward a remote TCP port back to the client; format [bind_address:]port:host:hostport
    #[arg(short = 'R', long = "remote-forward", value_name = "SPEC", action = ArgAction::Append, help_heading = "Forwarding Options")]
    remote_forward: Vec<String>,
    /// Start a local SOCKS proxy; format [bind_address:]port
    #[arg(short = 'D', long = "dynamic-forward", value_name = "SPEC", action = ArgAction::Append, help_heading = "Forwarding Options")]
    dynamic_forward: Vec<String>,
    /// Forward a local Unix socket path to a remote path (format local=remote)
    #[cfg(unix)]
    #[arg(long = "local-unix-forward", value_name = "LOCAL=REMOTE", action = ArgAction::Append, help_heading = "Forwarding Options")]
    local_unix_forward: Vec<String>,
    /// Forward a remote Unix socket back to a local path (format remote=local)
    #[cfg(unix)]
    #[arg(long = "remote-unix-forward", value_name = "REMOTE=LOCAL", action = ArgAction::Append, help_heading = "Forwarding Options")]
    remote_unix_forward: Vec<String>,
    /// [unimplemented] Request X11 forwarding (optionally override display via --x11-display)
    #[arg(short = 'X', long = "forward-x11", action = ArgAction::SetTrue, help_heading = "Forwarding Options")]
    forward_x11: bool,
    /// [unimplemented] Override the forwarded DISPLAY value
    #[arg(long = "x11-display", value_name = "DISPLAY", help_heading = "Forwarding Options")]
    x11_display: Option<String>,
    /// [unimplemented] Request trusted X11 cookies (similar to -Y)
    #[arg(long = "x11-trusted", action = ArgAction::SetTrue, help_heading = "Forwarding Options")]
    x11_trusted: bool,
    /// [unimplemented] Allow only a single forwarded X11 connection
    #[arg(long = "x11-single-connection", action = ArgAction::SetTrue, help_heading = "Forwarding Options")]
    x11_single_connection: bool,
    /// Request additional subsystems (e.g. sftp)
    #[arg(long = "subsystem", value_name = "NAME", action = ArgAction::Append, help_heading = "Forwarding Options")]
    subsystems: Vec<String>,
    /// Send environment variables to the remote session
    #[arg(long = "send-env", value_name = "NAME[=VALUE]", action = ArgAction::Append, help_heading = "Forwarding Options")]
    send_env: Vec<String>,
    /// Propagate locale variables (none, lang, all)
    #[arg(long = "forward-locale", value_enum, default_value_t = LocaleModeArg::None, help_heading = "Forwarding Options")]
    forward_locale: LocaleModeArg,
}

impl ClientArgs {
    pub fn parse_config() -> Result<ClientConfig> {
        let args = ClientArgs::parse();
        ClientConfig::try_from(args)
    }
}

impl TryFrom<ClientArgs> for ClientConfig {
    type Error = anyhow::Error;

    fn try_from(args: ClientArgs) -> Result<Self> {
        let ClientArgs {
            target,
            command,
            username,
            password,
            port,
            newline,
            local_echo,
            compress,
            rekey_interval,
            rekey_bytes,
            keepalive_interval,
            keepalive_max,
            accept_hostkey_once,
            accept_store_hostkey,
            replace_hostkey,
            insecure,
            identities,
            identity_certs,
            agent_auth,
            forward_agent,
            no_keyboard_interactive,
            no_password,
            local_forward,
            remote_forward,
            dynamic_forward,
            #[cfg(unix)]
            local_unix_forward,
            #[cfg(unix)]
            remote_unix_forward,
            forward_x11,
            x11_display,
            x11_trusted,
            x11_single_connection,
            subsystems,
            send_env,
            forward_locale,
        } = args;

        let target = parse_target(&target)?;
        let port = port.unwrap_or(target.port);
        let newline_mode = newline.or_else(newline_mode_from_env).unwrap_or_default();

        let local_echo = if local_echo {
            true
        } else {
            env::var("RB_LOCAL_ECHO").map(|v| v != "0").unwrap_or(false)
        };

        let username = username
            .or(target.inferred_username)
            .or_else(fallback_username)
            .ok_or_else(|| anyhow!("unable to determine username; use --username or user@host"))?;

        let (password, prompt_password) = resolve_password_source(password.as_deref(), no_password)?;

        let command = if command.is_empty() { None } else { Some(command.join(" ")) };

        if !subsystems.is_empty() && command.is_some() {
            bail!("--subsystem cannot be combined with remote commands");
        }

        let rekey_interval = rekey_interval.map(Duration::from_secs);
        let rekey_bytes = rekey_bytes.map(validate_rekey_bytes).transpose()?;
        let keepalive_interval = keepalive_interval.map(Duration::from_secs);

        let mut cert_overrides = parse_cert_overrides(&identity_certs)?;
        let identities = build_identities(&identities, &mut cert_overrides)?;
        if !cert_overrides.is_empty() {
            bail!("unused --identity-cert entries: {:?}", cert_overrides.keys().collect::<Vec<_>>());
        }

        let agent_socket = env::var_os("SSH_AUTH_SOCK").map(PathBuf::from);
        if (agent_auth || forward_agent) && agent_socket.is_none() {
            bail!("SSH_AUTH_SOCK must be set to use --agent-auth or --forward-agent");
        }

        let password_prompt = if prompt_password {
            Some(format!("{username}@{} password: ", target.host))
        } else {
            None
        };

        if forward_x11 || x11_display.is_some() || x11_trusted || x11_single_connection {
            bail!("X11 forwarding flags are unimplemented; see FORWARDING.md for status");
        }

        let mut forwarding_config = ForwardingConfig::default();
        for spec in local_forward {
            forwarding_config.local_tcp.push(forwarding::parse_local_tcp(&spec)?);
        }
        for spec in remote_forward {
            forwarding_config.remote_tcp.push(forwarding::parse_remote_tcp(&spec)?);
        }
        for spec in dynamic_forward {
            forwarding_config.dynamic_socks.push(forwarding::parse_dynamic_socks(&spec)?);
        }
        #[cfg(unix)]
        {
            for spec in local_unix_forward {
                forwarding_config.local_unix.push(forwarding::parse_local_unix(&spec)?);
            }
            for spec in remote_unix_forward {
                forwarding_config.remote_unix.push(forwarding::parse_remote_unix(&spec)?);
            }
        }
        for subsystem in subsystems {
            forwarding_config.subsystems.push(forwarding::parse_subsystem(&subsystem)?);
        }
        for entry in send_env {
            forwarding_config.env.entries.push(forwarding::parse_env_entry(&entry)?);
        }
        forwarding_config.env.locale_mode = forward_locale.into();

        Ok(ClientConfig {
            host: target.host,
            port,
            username,
            password,
            command,
            newline_mode,
            local_echo,
            prefer_compression: compress,
            rekey_interval,
            rekey_bytes,
            keepalive_interval,
            keepalive_max,
            accept_hostkey_once,
            accept_store_hostkey,
            replace_hostkey,
            insecure,
            identities,
            allow_keyboard_interactive: !no_keyboard_interactive,
            agent_auth,
            forward_agent,
            ssh_agent_socket: agent_socket,
            prompt_password,
            password_prompt,
            forwarding: forwarding_config,
        })
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
    for key in ["RB_USER", "USER", "LOGNAME", "USERNAME"] {
        if let Ok(value) = env::var(key)
            && !value.is_empty()
        {
            return Some(value);
        }
    }
    let current = whoami::username();
    if current.is_empty() { None } else { Some(current) }
}

fn resolve_password_source(provided: Option<&str>, no_password: bool) -> Result<(Option<SecretString>, bool)> {
    if no_password {
        return Ok((None, false));
    }
    if let Some(value) = provided {
        return Ok((Some(SecretString::new(value.to_string().into_boxed_str())), false));
    }
    if let Ok(value) = env::var("RB_PASSWORD") {
        return Ok((Some(SecretString::new(value.into_boxed_str())), false));
    }
    Ok((None, true))
}

#[derive(Clone, Copy, Debug, ValueEnum, Default)]
enum LocaleModeArg {
    #[default]
    None,
    Lang,
    All,
}

impl From<LocaleModeArg> for LocaleMode {
    fn from(value: LocaleModeArg) -> Self {
        match value {
            LocaleModeArg::None => LocaleMode::None,
            LocaleModeArg::Lang => LocaleMode::Lang,
            LocaleModeArg::All => LocaleMode::All,
        }
    }
}

fn validate_rekey_bytes(value: u64) -> Result<usize> {
    const MAX: u64 = 1 << 30; // 1 GiB per RFC 4253 recommendations
    if value == 0 {
        bail!("--rekey-bytes must be greater than zero");
    }
    if value > MAX {
        bail!("--rekey-bytes must be <= {MAX} bytes");
    }
    Ok(value as usize)
}
fn parse_cert_overrides(values: &[String]) -> Result<HashMap<PathBuf, PathBuf>> {
    let mut map = HashMap::new();
    for value in values {
        let (key, cert) = value
            .split_once('=')
            .ok_or_else(|| anyhow!("--identity-cert entries must be KEY=CERT"))?;
        map.insert(PathBuf::from(key), PathBuf::from(cert));
    }
    Ok(map)
}

fn build_identities(paths: &[PathBuf], overrides: &mut HashMap<PathBuf, PathBuf>) -> Result<Vec<ClientIdentity>> {
    let mut out = Vec::with_capacity(paths.len());
    for path in paths {
        let cert = overrides.remove(path);
        out.push(ClientIdentity {
            key_path: path.clone(),
            cert_path: cert,
        });
    }
    Ok(out)
}
