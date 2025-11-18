#[cfg(unix)]
use std::fs;
use std::{collections::HashSet, env, net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use russh::{Channel, ChannelStream, client};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy_bidirectional}, net::{TcpListener, TcpStream}, task::JoinHandle
};
use tracing::{info, warn};

use crate::session::{SessionHandle, SharedSessionHandle};

#[derive(Clone, Debug, Default)]
pub struct ForwardingConfig {
    pub local_tcp: Vec<LocalTcpForward>,
    pub remote_tcp: Vec<RemoteTcpForward>,
    pub dynamic_socks: Vec<DynamicSocksForward>,
    pub local_unix: Vec<LocalUnixForward>,
    pub remote_unix: Vec<RemoteUnixForward>,
    pub x11: Option<X11Forward>,
    pub subsystems: Vec<SubsystemRequest>,
    pub env: EnvPropagation,
}

#[derive(Clone, Debug)]
pub struct LocalTcpForward {
    pub bind_address: Option<String>,
    pub bind_port: u16,
    pub target_host: String,
    pub target_port: u16,
}

#[derive(Clone, Debug)]
pub struct RemoteTcpForward {
    pub bind_address: Option<String>,
    pub bind_port: u16,
    pub target_host: String,
    pub target_port: u16,
}

#[derive(Clone, Debug)]
pub struct DynamicSocksForward {
    pub bind_address: Option<String>,
    pub bind_port: u16,
}

#[derive(Clone, Debug)]
pub struct LocalUnixForward {
    pub local_socket: PathBuf,
    pub remote_socket: PathBuf,
}

#[derive(Clone, Debug)]
pub struct RemoteUnixForward {
    pub remote_socket: PathBuf,
    pub local_socket: PathBuf,
}

#[derive(Clone, Debug)]
pub struct X11Forward {
    pub display: Option<String>,
    pub trusted: bool,
    pub single_connection: bool,
}

#[derive(Clone, Debug, Default)]
pub struct EnvPropagation {
    pub entries: Vec<EnvEntry>,
    pub locale_mode: LocaleMode,
}

#[derive(Clone, Debug)]
pub struct EnvEntry {
    pub name: String,
    pub value: Option<String>,
}

#[derive(Clone, Copy, Debug, Default)]
pub enum LocaleMode {
    #[default]
    None,
    Lang,
    All,
}

#[derive(Clone, Debug)]
pub struct SubsystemRequest {
    pub name: String,
}

pub trait ForwardStreamIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> ForwardStreamIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub type ForwardStream = Box<dyn ForwardStreamIo>;

#[async_trait]
pub trait ForwardSession: Clone + Send + Sync + 'static {
    async fn open_direct_tcpip(
        &self,
        target_host: String,
        target_port: u16,
        origin_host: String,
        origin_port: u16,
    ) -> Result<ForwardStream>;
    #[cfg(unix)]
    async fn open_direct_streamlocal(&self, remote_socket: PathBuf) -> Result<ForwardStream>;
    async fn cancel_tcpip_forwarding(&self, bind_address: String, port: u32) -> Result<()>;
    #[cfg(unix)]
    async fn cancel_streamlocal_forwarding(&self, remote_socket: String) -> Result<()>;
}

#[async_trait]
pub trait RemoteForwardChannel: Send {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;
    fn into_stream(self) -> Self::Stream;
    async fn close(self) -> Result<()>;
}

#[async_trait]
pub trait RemoteRegistrar {
    async fn request_tcpip_forward(&mut self, bind_address: String, bind_port: u16) -> Result<u32>;
    #[cfg(unix)]
    async fn request_streamlocal_forward(&mut self, remote_socket: String) -> Result<()>;
}

impl ForwardingConfig {
    pub fn is_empty(&self) -> bool {
        self.local_tcp.is_empty()
            && self.remote_tcp.is_empty()
            && self.dynamic_socks.is_empty()
            && self.local_unix.is_empty()
            && self.remote_unix.is_empty()
            && self.x11.is_none()
            && self.subsystems.is_empty()
            && self.env.entries.is_empty()
            && matches!(self.env.locale_mode, LocaleMode::None)
    }
}

pub fn parse_local_tcp(spec: &str) -> Result<LocalTcpForward> {
    let fields = split_colon_parts(spec);
    if fields.len() == 4 {
        Ok(LocalTcpForward {
            bind_address: normalize_host(&fields[0]),
            bind_port: parse_port(&fields[1])?,
            target_host: normalize_host(&fields[2]).unwrap_or_else(|| "127.0.0.1".to_string()),
            target_port: parse_port(&fields[3])?,
        })
    } else if fields.len() == 3 {
        Ok(LocalTcpForward {
            bind_address: None,
            bind_port: parse_port(&fields[0])?,
            target_host: normalize_host(&fields[1]).unwrap_or_else(|| "127.0.0.1".to_string()),
            target_port: parse_port(&fields[2])?,
        })
    } else {
        bail!("local forward spec must be [bind_address:]port:host:hostport");
    }
}

pub fn parse_remote_tcp(spec: &str) -> Result<RemoteTcpForward> {
    let fields = split_colon_parts(spec);
    if fields.len() == 4 {
        Ok(RemoteTcpForward {
            bind_address: normalize_host(&fields[0]),
            bind_port: parse_port(&fields[1])?,
            target_host: normalize_host(&fields[2]).unwrap_or_else(|| "127.0.0.1".to_string()),
            target_port: parse_port(&fields[3])?,
        })
    } else if fields.len() == 3 {
        Ok(RemoteTcpForward {
            bind_address: None,
            bind_port: parse_port(&fields[0])?,
            target_host: normalize_host(&fields[1]).unwrap_or_else(|| "127.0.0.1".to_string()),
            target_port: parse_port(&fields[2])?,
        })
    } else {
        bail!("remote forward spec must be [bind_address:]port:host:hostport");
    }
}

pub fn parse_dynamic_socks(spec: &str) -> Result<DynamicSocksForward> {
    let fields = split_colon_parts(spec);
    if fields.is_empty() || fields.len() > 2 {
        bail!("dynamic forward spec must be [bind_address:]port");
    }
    let bind_address = if fields.len() == 2 { normalize_host(&fields[0]) } else { None };
    let port_str = fields.last().expect("port field present");
    Ok(DynamicSocksForward {
        bind_address,
        bind_port: parse_port(port_str)?,
    })
}

pub fn parse_local_unix(spec: &str) -> Result<LocalUnixForward> {
    let (local, remote) = split_socket_pair(spec)?;
    Ok(LocalUnixForward {
        local_socket: local,
        remote_socket: remote,
    })
}

pub fn parse_remote_unix(spec: &str) -> Result<RemoteUnixForward> {
    let (remote, local) = split_socket_pair(spec)?;
    Ok(RemoteUnixForward {
        remote_socket: remote,
        local_socket: local,
    })
}

pub fn parse_env_entry(entry: &str) -> Result<EnvEntry> {
    let (name, value) = if let Some((name, value)) = entry.split_once('=') {
        (name.trim(), Some(value.to_string()))
    } else {
        (entry.trim(), None)
    };
    if name.is_empty() {
        bail!("environment variable name must not be empty");
    }
    if !name.chars().all(|c| c == '_' || c.is_ascii_alphanumeric()) {
        bail!("invalid environment variable name: {name}");
    }
    Ok(EnvEntry {
        name: name.to_string(),
        value,
    })
}

pub fn parse_subsystem(name: &str) -> Result<SubsystemRequest> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        bail!("subsystem name must not be empty");
    }
    Ok(SubsystemRequest { name: trimmed.to_string() })
}

fn split_socket_pair(spec: &str) -> Result<(PathBuf, PathBuf)> {
    let (lhs, rhs) = spec.split_once('=').context("unix forward spec must use local=remote format")?;
    if lhs.trim().is_empty() || rhs.trim().is_empty() {
        bail!("unix forward spec must not contain empty paths");
    }
    Ok((PathBuf::from(lhs.trim()), PathBuf::from(rhs.trim())))
}

fn parse_port(value: &str) -> Result<u16> {
    value.trim().parse::<u16>().context("port must be a valid number between 0-65535")
}

fn normalize_host(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let no_brackets = trimmed
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .map(|inner| inner.to_string());
    no_brackets.or_else(|| Some(trimmed.to_string()))
}

fn split_colon_parts(input: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut bracket_depth = 0;
    for ch in input.chars() {
        match ch {
            ':' if bracket_depth == 0 => {
                parts.push(current.trim().to_string());
                current.clear();
            }
            '[' => {
                bracket_depth += 1;
                current.push(ch);
            }
            ']' => {
                if bracket_depth > 0 {
                    bracket_depth -= 1;
                }
                current.push(ch);
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        parts.push(current.trim().to_string());
    }
    parts.into_iter().filter(|p| !p.is_empty()).collect()
}

#[derive(Default, Clone)]
struct RemoteRegistration {
    bind_address: Option<String>,
    actual_port: u32,
    target_host: String,
    target_port: u16,
}

#[cfg(unix)]
#[derive(Default, Clone)]
struct RemoteStreamLocalRegistration {
    remote_socket: String,
    local_socket: PathBuf,
}

#[derive(Default)]
struct ForwardingState {
    config: ForwardingConfig,
    tasks: tokio::sync::Mutex<Vec<JoinHandle<()>>>,
    remote_bindings: tokio::sync::Mutex<Vec<RemoteRegistration>>,
    #[cfg(unix)]
    remote_streamlocals: tokio::sync::Mutex<Vec<RemoteStreamLocalRegistration>>,
    #[cfg(unix)]
    local_unix_paths: tokio::sync::Mutex<Vec<PathBuf>>,
}

#[derive(Clone, Default)]
pub struct ForwardingManager {
    state: Arc<ForwardingState>,
}

impl ForwardingManager {
    pub fn new(config: ForwardingConfig) -> Self {
        Self {
            state: Arc::new(ForwardingState {
                config,
                tasks: tokio::sync::Mutex::new(Vec::new()),
                remote_bindings: tokio::sync::Mutex::new(Vec::new()),
                #[cfg(unix)]
                remote_streamlocals: tokio::sync::Mutex::new(Vec::new()),
                #[cfg(unix)]
                local_unix_paths: tokio::sync::Mutex::new(Vec::new()),
            }),
        }
    }

    pub fn config(&self) -> &ForwardingConfig {
        &self.state.config
    }

    pub fn has_requests(&self) -> bool {
        !self.state.config.is_empty()
    }

    pub fn descriptors(&self) -> Vec<String> {
        let mut entries = Vec::new();
        for fwd in &self.state.config.local_tcp {
            let bind = fwd.bind_address.as_deref().unwrap_or("127.0.0.1");
            entries.push(format!("local {bind}:{} -> {}:{}", fwd.bind_port, fwd.target_host, fwd.target_port));
        }
        for fwd in &self.state.config.remote_tcp {
            let bind = fwd.bind_address.as_deref().unwrap_or("");
            let bind_desc = if bind.is_empty() {
                format!("remote :{}", fwd.bind_port)
            } else {
                format!("remote {bind}:{}", fwd.bind_port)
            };
            entries.push(format!("{bind_desc} -> {}:{}", fwd.target_host, fwd.target_port));
        }
        for fwd in &self.state.config.dynamic_socks {
            let bind = fwd.bind_address.as_deref().unwrap_or("127.0.0.1");
            entries.push(format!("socks {bind}:{}", fwd.bind_port));
        }
        for fwd in &self.state.config.local_unix {
            entries.push(format!(
                "local unix {} -> {}",
                fwd.local_socket.display(),
                fwd.remote_socket.display()
            ));
        }
        for fwd in &self.state.config.remote_unix {
            entries.push(format!(
                "remote unix {} -> {}",
                fwd.remote_socket.display(),
                fwd.local_socket.display()
            ));
        }
        if self.state.config.x11.is_some() {
            entries.push("x11".to_string());
        }
        if !self.state.config.subsystems.is_empty() {
            for subsystem in &self.state.config.subsystems {
                entries.push(format!("subsystem {}", subsystem.name));
            }
        }
        if !self.state.config.env.entries.is_empty() {
            entries.push("env".to_string());
        }
        match self.state.config.env.locale_mode {
            LocaleMode::None => {}
            LocaleMode::Lang => entries.push("locale:lang".to_string()),
            LocaleMode::All => entries.push("locale:all".to_string()),
        }
        entries
    }

    pub async fn prepare_channel(&self, channel: &Channel<client::Msg>) -> Result<()> {
        self.apply_environment(channel).await
    }

    pub async fn start_local_tcp_forwarders<S>(&self, session: S) -> Result<()>
    where
        S: ForwardSession,
    {
        for spec in &self.state.config.local_tcp {
            self.spawn_local_tcp_forwarder(spec.clone(), session.clone()).await?;
        }
        Ok(())
    }

    pub async fn start_local_unix_forwarders<S>(&self, session: S) -> Result<()>
    where
        S: ForwardSession,
    {
        #[cfg(unix)]
        {
            for spec in &self.state.config.local_unix {
                self.spawn_local_unix_forwarder(spec.clone(), session.clone()).await?;
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            if !self.state.config.local_unix.is_empty() {
                bail!("unix socket forwarding is only supported on Unix platforms");
            }
            Ok(())
        }
    }

    pub async fn start_dynamic_socks<S>(&self, session: S) -> Result<()>
    where
        S: ForwardSession,
    {
        for spec in &self.state.config.dynamic_socks {
            self.spawn_socks_forwarder(spec.clone(), session.clone()).await?;
        }
        Ok(())
    }

    pub async fn start_remote_tcp_forwarders<R>(&self, session: &mut R) -> Result<()>
    where
        R: RemoteRegistrar + Send,
    {
        for spec in &self.state.config.remote_tcp {
            self.register_remote_forward(spec.clone(), session).await?;
        }
        Ok(())
    }

    pub async fn start_remote_unix_forwarders<R>(&self, session: &mut R) -> Result<()>
    where
        R: RemoteRegistrar + Send,
    {
        #[cfg(unix)]
        {
            for spec in &self.state.config.remote_unix {
                self.register_remote_streamlocal(spec.clone(), session).await?;
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            if !self.state.config.remote_unix.is_empty() {
                bail!("unix socket forwarding is only supported on Unix platforms");
            }
            Ok(())
        }
    }

    pub async fn shutdown<S>(&self, session: Option<S>) -> Result<()>
    where
        S: ForwardSession,
    {
        self.cancel_tasks().await;
        if let Some(session) = session {
            let mut registrations = self.state.remote_bindings.lock().await;
            for entry in registrations.drain(..) {
                let address = entry.bind_address.clone().unwrap_or_else(|| "127.0.0.1".to_string());
                if let Err(err) = session.cancel_tcpip_forwarding(address.clone(), entry.actual_port).await {
                    warn!(?err, bind = &address, port = entry.actual_port, "failed to cancel remote forward");
                }
            }
            #[cfg(unix)]
            {
                let mut registrations = self.state.remote_streamlocals.lock().await;
                if registrations.is_empty() && !self.state.config.remote_unix.is_empty() {
                    for spec in &self.state.config.remote_unix {
                        let remote = spec.remote_socket.to_string_lossy().to_string();
                        if let Err(err) = session.cancel_streamlocal_forwarding(remote.clone()).await {
                            warn!(?err, socket = remote, "failed to cancel configured remote streamlocal forward");
                        }
                    }
                } else {
                    for entry in registrations.drain(..) {
                        if let Err(err) = session.cancel_streamlocal_forwarding(entry.remote_socket.clone()).await {
                            warn!(?err, socket = entry.remote_socket, "failed to cancel remote streamlocal forward");
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn cancel_tasks(&self) {
        let mut tasks = self.state.tasks.lock().await;
        for handle in tasks.drain(..) {
            handle.abort();
        }
        #[cfg(unix)]
        self.cleanup_local_unix_sockets().await;
    }

    #[cfg(unix)]
    async fn cleanup_local_unix_sockets(&self) {
        let mut paths = self.state.local_unix_paths.lock().await;
        for path in paths.drain(..) {
            if let Err(err) = std::fs::remove_file(&path) {
                if err.kind() != std::io::ErrorKind::NotFound {
                    warn!(?err, socket = %path.display(), "failed to remove unix socket");
                }
            }
        }
    }

    pub async fn handle_remote_forward_channel<C>(
        &self,
        channel: C,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
    ) -> Result<()>
    where
        C: RemoteForwardChannel,
    {
        if let Some((target_host, target_port)) = self.resolve_remote_target(host_to_connect, port_to_connect).await {
            info!(
                remote = %format!("{host_to_connect}:{port_to_connect}"),
                target = %format!("{target_host}:{target_port}"),
                origin = %format!("{originator_address}:{originator_port}"),
                "proxying remote forwarded connection"
            );
            let remote_stream = channel.into_stream();
            self.proxy_remote_tcp_stream(remote_stream, &target_host, target_port).await?;
        } else {
            warn!(
                address = host_to_connect,
                port = port_to_connect,
                "received forwarded-tcpip with no matching --remote-forward spec"
            );
            let _ = channel.close().await;
        }
        Ok(())
    }

    async fn proxy_remote_tcp_stream<S>(&self, remote_stream: S, target_host: &str, target_port: u16) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let local = TcpStream::connect((target_host, target_port)).await?;
        Self::proxy_stream_pair(remote_stream, local).await
    }

    #[cfg(any(test, feature = "forwarding-tests"))]
    pub async fn proxy_streams<R, L>(&self, remote_stream: R, local_stream: L) -> Result<()>
    where
        R: AsyncRead + AsyncWrite + Unpin,
        L: AsyncRead + AsyncWrite + Unpin,
    {
        Self::proxy_stream_pair(remote_stream, local_stream).await
    }

    async fn proxy_stream_pair<R, L>(mut remote_stream: R, mut local_stream: L) -> Result<()>
    where
        R: AsyncRead + AsyncWrite + Unpin,
        L: AsyncRead + AsyncWrite + Unpin,
    {
        let copy_result = copy_bidirectional(&mut local_stream, &mut remote_stream).await;
        let _ = remote_stream.shutdown().await;
        let _ = local_stream.shutdown().await;
        match copy_result {
            Ok(_) => {}
            Err(err)
                if err.kind() == std::io::ErrorKind::BrokenPipe
                    || err.kind() == std::io::ErrorKind::NotConnected
                    || err.kind() == std::io::ErrorKind::ConnectionReset =>
            {
                // Treat common half-close races as graceful termination.
            }
            Err(err) => return Err(err.into()),
        }
        Ok(())
    }

    pub async fn handle_remote_streamlocal_channel<C>(&self, channel: C, socket_path: &str) -> Result<()>
    where
        C: RemoteForwardChannel,
    {
        #[cfg(unix)]
        {
            if let Some(local_path) = self.resolve_streamlocal_target(socket_path).await {
                let local = UnixStream::connect(&local_path).await?;
                let remote = channel.into_stream();
                Self::proxy_stream_pair(remote, local).await?;
            } else {
                warn!(
                    socket = socket_path,
                    "received streamlocal channel with no matching --remote-unix-forward spec"
                );
                let _ = channel.close().await;
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = channel.close().await;
            warn!(socket = socket_path, "streamlocal forwarding is not supported on this platform");
            Ok(())
        }
    }

    pub async fn resolve_remote_target(&self, bound_address: &str, bound_port: u32) -> Option<(String, u16)> {
        let registrations = self.state.remote_bindings.lock().await;
        registrations.iter().find_map(|entry| {
            if entry.actual_port != bound_port {
                return None;
            }
            let matches_address = match (&entry.bind_address, bound_address) {
                (None, _) => true,
                (Some(addr), _) if addr.is_empty() => true,
                (Some(addr), got) => addr == got,
            };
            if matches_address {
                Some((entry.target_host.clone(), entry.target_port))
            } else {
                None
            }
        })
    }

    #[cfg(unix)]
    async fn resolve_streamlocal_target(&self, socket_path: &str) -> Option<PathBuf> {
        let registrations = self.state.remote_streamlocals.lock().await;
        registrations
            .iter()
            .find(|entry| entry.remote_socket == socket_path)
            .map(|entry| entry.local_socket.clone())
    }

    async fn apply_environment(&self, channel: &Channel<client::Msg>) -> Result<()> {
        if self.state.config.env.entries.is_empty() && matches!(self.state.config.env.locale_mode, LocaleMode::None) {
            return Ok(());
        }
        let mut sent = HashSet::new();
        for entry in &self.state.config.env.entries {
            if let Some(value) = entry.value.clone().or_else(|| env::var(&entry.name).ok()) {
                channel.set_env(false, entry.name.clone(), value).await?;
                sent.insert(entry.name.clone());
            } else {
                warn!(name = %entry.name, "send-env variable has no value; skipping request");
            }
        }
        match self.state.config.env.locale_mode {
            LocaleMode::None => {}
            LocaleMode::Lang => {
                self.send_locale_var("LANG", &mut sent, channel).await?;
            }
            LocaleMode::All => {
                self.send_locale_var("LANG", &mut sent, channel).await?;
                for (name, value) in env::vars() {
                    if !name.starts_with("LC_") {
                        continue;
                    }
                    if sent.insert(name.clone()) {
                        channel.set_env(false, name, value).await?;
                    }
                }
            }
        }
        Ok(())
    }

    async fn send_locale_var(&self, key: &str, sent: &mut HashSet<String>, channel: &Channel<client::Msg>) -> Result<()> {
        if let Ok(value) = env::var(key) {
            if sent.insert(key.to_string()) {
                channel.set_env(false, key, value).await?;
            }
        }
        Ok(())
    }

    async fn spawn_local_tcp_forwarder<S>(&self, spec: LocalTcpForward, session: S) -> Result<()>
    where
        S: ForwardSession,
    {
        let bind_host = spec.bind_address.clone().unwrap_or_else(|| "127.0.0.1".to_string());
        let listener = TcpListener::bind((bind_host.as_str(), spec.bind_port)).await?;
        info!(
            bind = %format!("{}:{}", bind_host, spec.bind_port),
            target = %format!("{}:{}", spec.target_host, spec.target_port),
            "local TCP forward listening"
        );
        let task = tokio::spawn(run_local_tcp_listener(listener, spec, session));
        self.state.tasks.lock().await.push(task);
        Ok(())
    }

    #[cfg(unix)]
    async fn spawn_local_unix_forwarder<S>(&self, spec: LocalUnixForward, session: S) -> Result<()>
    where
        S: ForwardSession,
    {
        let path = spec.local_socket.clone();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        if path.exists() {
            let _ = fs::remove_file(&path);
        }
        let listener = UnixListener::bind(&path)?;
        self.state.local_unix_paths.lock().await.push(path.clone());
        info!(
            local = %path.display(),
            remote = %spec.remote_socket.display(),
            "local unix forward listening"
        );
        let task = tokio::spawn(run_local_unix_listener(listener, spec.remote_socket, session));
        self.state.tasks.lock().await.push(task);
        Ok(())
    }

    async fn spawn_socks_forwarder<S>(&self, spec: DynamicSocksForward, session: S) -> Result<()>
    where
        S: ForwardSession,
    {
        let bind_host = spec.bind_address.clone().unwrap_or_else(|| "127.0.0.1".to_string());
        let listener = TcpListener::bind((bind_host.as_str(), spec.bind_port)).await?;
        info!(
            bind = %format!("{}:{}", bind_host, spec.bind_port),
            "dynamic SOCKS forward listening"
        );
        let task = tokio::spawn(run_socks_listener(listener, session));
        self.state.tasks.lock().await.push(task);
        Ok(())
    }

    async fn register_remote_forward<R>(&self, spec: RemoteTcpForward, session: &mut R) -> Result<()>
    where
        R: RemoteRegistrar + Send,
    {
        let address = spec.bind_address.clone().unwrap_or_else(|| "127.0.0.1".to_string());
        let requested = spec.bind_port;
        let assigned = session.request_tcpip_forward(address.clone(), requested).await?;
        let actual_port = if assigned != 0 { assigned } else { requested as u32 };
        info!(
            bind = %format!("{}:{}", address, actual_port),
            target = %format!("{}:{}", spec.target_host, spec.target_port),
            "remote TCP forward registered"
        );
        self.state.remote_bindings.lock().await.push(RemoteRegistration {
            bind_address: spec.bind_address,
            actual_port,
            target_host: spec.target_host,
            target_port: spec.target_port,
        });
        Ok(())
    }

    #[cfg(unix)]
    async fn register_remote_streamlocal<R>(&self, spec: RemoteUnixForward, session: &mut R) -> Result<()>
    where
        R: RemoteRegistrar + Send,
    {
        let remote = spec.remote_socket.to_string_lossy().to_string();
        session.request_streamlocal_forward(remote.clone()).await?;
        info!(
            remote = %spec.remote_socket.display(),
            local = %spec.local_socket.display(),
            "remote unix forward registered"
        );
        self.state.remote_streamlocals.lock().await.push(RemoteStreamLocalRegistration {
            remote_socket: remote,
            local_socket: spec.local_socket,
        });
        Ok(())
    }
}

async fn run_local_tcp_listener<S>(listener: TcpListener, spec: LocalTcpForward, session: S)
where
    S: ForwardSession,
{
    loop {
        match listener.accept().await {
            Ok((stream, origin)) => {
                let spec = spec.clone();
                let session = session.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_local_tcp_connection(stream, origin, spec, session).await {
                        warn!(?err, "local TCP forward connection failed");
                    }
                });
            }
            Err(err) => {
                warn!(?err, "local TCP forward listener accept error");
                break;
            }
        }
    }
}

async fn handle_local_tcp_connection<S>(mut stream: TcpStream, origin: SocketAddr, spec: LocalTcpForward, session: S) -> Result<()>
where
    S: ForwardSession,
{
    stream.set_nodelay(true).ok();
    let mut remote = session
        .open_direct_tcpip(spec.target_host.clone(), spec.target_port, origin.ip().to_string(), origin.port())
        .await?;
    let copy_result = copy_bidirectional(&mut stream, remote.as_mut()).await;
    let _ = remote.as_mut().shutdown().await;
    copy_result?;
    Ok(())
}

#[cfg(unix)]
async fn run_local_unix_listener<S>(listener: UnixListener, remote_socket: PathBuf, session: S)
where
    S: ForwardSession,
{
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let session = session.clone();
                let remote_socket = remote_socket.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_local_unix_connection(stream, remote_socket, session).await {
                        warn!(?err, "local unix forward connection failed");
                    }
                });
            }
            Err(err) => {
                warn!(?err, "local unix forward listener accept error");
                break;
            }
        }
    }
}

#[cfg(unix)]
async fn handle_local_unix_connection<S>(mut stream: UnixStream, remote_socket: PathBuf, session: S) -> Result<()>
where
    S: ForwardSession,
{
    let mut remote = session.open_direct_streamlocal(remote_socket).await?;
    let copy_result = copy_bidirectional(&mut stream, remote.as_mut()).await;
    let _ = remote.as_mut().shutdown().await;
    copy_result?;
    Ok(())
}

async fn run_socks_listener<S>(listener: TcpListener, session: S)
where
    S: ForwardSession,
{
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let session = session.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_socks_client(stream, session).await {
                        warn!(?err, "SOCKS client failed");
                    }
                });
            }
            Err(err) => {
                warn!(?err, "dynamic SOCKS listener accept error");
                break;
            }
        }
    }
}

async fn handle_socks_client<S>(mut stream: TcpStream, session: S) -> Result<()>
where
    S: ForwardSession,
{
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;
    if header[0] != 0x05 {
        return Ok(()); // only SOCKS5 supported
    }
    let method_count = header[1] as usize;
    let mut methods = vec![0u8; method_count];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        stream.write_all(&[0x05, 0xFF]).await?;
        return Ok(());
    }
    stream.write_all(&[0x05, 0x00]).await?;

    let mut request = [0u8; 4];
    stream.read_exact(&mut request).await?;
    if request[0] != 0x05 || request[1] != 0x01 {
        send_socks_reply(&mut stream, 0x07).await?;
        return Ok(());
    }
    let target_host = match request[3] {
        0x01 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            std::net::Ipv4Addr::from(addr).to_string()
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            stream.read_exact(&mut name).await?;
            String::from_utf8_lossy(&name).to_string()
        }
        0x04 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            std::net::Ipv6Addr::from(addr).to_string()
        }
        _ => {
            send_socks_reply(&mut stream, 0x08).await?;
            return Ok(());
        }
    };
    let mut port_buf = [0u8; 2];
    stream.read_exact(&mut port_buf).await?;
    let target_port = u16::from_be_bytes(port_buf);
    let origin = stream.peer_addr().ok();
    let origin_host = origin.map(|addr| addr.ip().to_string()).unwrap_or_else(|| "0.0.0.0".to_string());
    let origin_port = origin.map(|addr| addr.port()).unwrap_or(0);
    let mut remote = match session
        .open_direct_tcpip(target_host.clone(), target_port, origin_host, origin_port)
        .await
    {
        Ok(stream) => stream,
        Err(err) => {
            warn!(?err, target = %format!("{target_host}:{target_port}"), "failed to open SOCKS target");
            send_socks_reply(&mut stream, 0x05).await?;
            return Ok(());
        }
    };
    send_socks_reply(&mut stream, 0x00).await?;
    let copy_result = copy_bidirectional(&mut stream, remote.as_mut()).await;
    let _ = remote.as_mut().shutdown().await;
    copy_result?;
    Ok(())
}

async fn send_socks_reply<W>(stream: &mut W, status: u8) -> Result<()>
where
    W: AsyncWrite + Unpin + Send,
{
    let mut response = [0u8; 10];
    response[0] = 0x05;
    response[1] = status;
    response[2] = 0x00;
    response[3] = 0x01;
    stream.write_all(&response).await?;
    Ok(())
}

#[async_trait]
impl<H> ForwardSession for SharedSessionHandle<H>
where
    H: client::Handler + Send + Sync + 'static,
{
    async fn open_direct_tcpip(
        &self,
        target_host: String,
        target_port: u16,
        origin_host: String,
        origin_port: u16,
    ) -> Result<ForwardStream> {
        let channel = self
            .as_ref()
            .channel_open_direct_tcpip(target_host, target_port.into(), origin_host, origin_port.into())
            .await?;
        Ok(Box::new(channel.into_stream()))
    }

    #[cfg(unix)]
    async fn open_direct_streamlocal(&self, remote_socket: PathBuf) -> Result<ForwardStream> {
        let remote_path = remote_socket.to_string_lossy().to_string();
        let channel = self.as_ref().channel_open_direct_streamlocal(remote_path).await?;
        Ok(Box::new(channel.into_stream()))
    }

    async fn cancel_tcpip_forwarding(&self, bind_address: String, port: u32) -> Result<()> {
        self.as_ref().cancel_tcpip_forward(bind_address, port).await?;
        Ok(())
    }

    #[cfg(unix)]
    async fn cancel_streamlocal_forwarding(&self, remote_socket: String) -> Result<()> {
        self.as_ref().cancel_streamlocal_forward(remote_socket).await?;
        Ok(())
    }
}

#[async_trait]
impl<H> RemoteRegistrar for SessionHandle<H>
where
    H: client::Handler + Send,
{
    async fn request_tcpip_forward(&mut self, bind_address: String, bind_port: u16) -> Result<u32> {
        let assigned = self.tcpip_forward(bind_address, bind_port.into()).await?;
        Ok(assigned)
    }

    #[cfg(unix)]
    async fn request_streamlocal_forward(&mut self, remote_socket: String) -> Result<()> {
        self.streamlocal_forward(remote_socket).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_local_forward_with_bind_host() {
        let spec = parse_local_tcp("127.0.0.1:2222:server:22").unwrap();
        assert_eq!(spec.bind_address.as_deref(), Some("127.0.0.1"));
        assert_eq!(spec.bind_port, 2222);
        assert_eq!(spec.target_host, "server");
        assert_eq!(spec.target_port, 22);
    }

    #[test]
    fn parses_dynamic_forward_ipv6() {
        let spec = parse_dynamic_socks("[::1]:1080").unwrap();
        assert_eq!(spec.bind_address.as_deref(), Some("::1"));
        assert_eq!(spec.bind_port, 1080);
    }

    #[test]
    fn rejects_invalid_env_name() {
        assert!(parse_env_entry("LANG-TEST").is_err());
    }

    #[test]
    fn descriptors_include_all_forward_types() {
        let mut config = ForwardingConfig::default();
        config.local_tcp.push(LocalTcpForward {
            bind_address: Some("127.0.0.1".into()),
            bind_port: 8080,
            target_host: "internal".into(),
            target_port: 80,
        });
        config.remote_tcp.push(RemoteTcpForward {
            bind_address: Some("0.0.0.0".into()),
            bind_port: 9090,
            target_host: "remote".into(),
            target_port: 9090,
        });
        config.dynamic_socks.push(DynamicSocksForward {
            bind_address: None,
            bind_port: 1080,
        });
        config.local_unix.push(LocalUnixForward {
            local_socket: PathBuf::from("/tmp/local.sock"),
            remote_socket: PathBuf::from("/var/run/remote.sock"),
        });
        config.remote_unix.push(RemoteUnixForward {
            remote_socket: PathBuf::from("/tmp/remote.sock"),
            local_socket: PathBuf::from("/tmp/local2.sock"),
        });
        config.subsystems.push(SubsystemRequest { name: "sftp".into() });
        config.env.entries.push(EnvEntry {
            name: "LANG".into(),
            value: Some("en_US.UTF-8".into()),
        });
        config.env.locale_mode = LocaleMode::All;
        let manager = ForwardingManager::new(config);
        let descriptors = manager.descriptors();
        assert!(descriptors.iter().any(|d| d.starts_with("local 127.0.0.1:8080")));
        assert!(descriptors.iter().any(|d| d.contains("remote 0.0.0.0:9090")));
        assert!(descriptors.iter().any(|d| d.contains("socks 127.0.0.1:1080")));
        assert!(descriptors.iter().any(|d| d.contains("local unix /tmp/local.sock")));
        assert!(descriptors.iter().any(|d| d.contains("remote unix /tmp/remote.sock")));
        assert!(descriptors.iter().any(|d| d == "subsystem sftp"));
        assert!(descriptors.iter().any(|d| d == "env"));
        assert!(descriptors.iter().any(|d| d == "locale:all"));
    }
}

#[async_trait]
impl RemoteForwardChannel for Channel<client::Msg> {
    type Stream = ChannelStream<client::Msg>;

    fn into_stream(self) -> Self::Stream {
        Channel::into_stream(self)
    }

    async fn close(self) -> Result<()> {
        Channel::close(&self).await?;
        Ok(())
    }
}
