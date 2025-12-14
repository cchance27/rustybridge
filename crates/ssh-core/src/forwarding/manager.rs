#[cfg(unix)]
use super::remote::{RemoteStreamLocalRegistration, handle_remote_streamlocal_channel, register_remote_streamlocal};
use super::{
    local::{spawn_local_tcp_forwarder, spawn_local_unix_forwarder},
    remote::{RemoteRegistration, handle_remote_forward_channel, register_remote_forward},
    socks::spawn_socks_forwarder,
    traits::{ForwardSession, RemoteForwardChannel, RemoteRegistrar},
};
use rb_types::ssh::{ForwardingConfig, LocaleMode};
use russh::{Channel, client};
use std::{collections::HashSet, env, path::PathBuf, sync::Arc};
use tokio::task::JoinHandle;
use tracing::warn;

type Result<T> = crate::SshResult<T>;

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

/// Manages SSH port forwarding, SOCKS proxies, and environment propagation.
#[derive(Clone, Default)]
pub struct ForwardingManager {
    state: Arc<ForwardingState>,
}

impl ForwardingManager {
    /// Create a new forwarding manager with the given configuration.
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

    /// Get a reference to the forwarding configuration.
    pub fn config(&self) -> &ForwardingConfig {
        &self.state.config
    }

    /// Check if there are any forwarding requests configured.
    pub fn has_requests(&self) -> bool {
        !self.state.config.is_empty()
    }

    /// Get human-readable descriptors of all configured forwards.
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

    /// Prepare a channel by applying environment variables.
    pub async fn prepare_channel(&self, channel: &Channel<client::Msg>) -> Result<()> {
        self.apply_environment(channel).await
    }

    /// Start all local TCP forwarders.
    pub async fn start_local_tcp_forwarders<S>(&self, session: S) -> Result<()>
    where
        S: ForwardSession,
    {
        for spec in &self.state.config.local_tcp {
            spawn_local_tcp_forwarder(spec.clone(), session.clone(), &self.state.tasks).await?;
        }
        Ok(())
    }

    /// Start all local Unix socket forwarders.
    pub async fn start_local_unix_forwarders<S>(&self, session: S) -> Result<()>
    where
        S: ForwardSession,
    {
        #[cfg(unix)]
        {
            for spec in &self.state.config.local_unix {
                spawn_local_unix_forwarder(spec.clone(), session.clone(), &self.state.tasks, &self.state.local_unix_paths).await?;
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            if !self.state.config.local_unix.is_empty() {
                return Err(crate::SshCoreError::Other(
                    "unix socket forwarding is only supported on Unix platforms".into(),
                ));
            }
            Ok(())
        }
    }

    /// Start all dynamic SOCKS forwarders.
    pub async fn start_dynamic_socks<S>(&self, session: S) -> Result<()>
    where
        S: ForwardSession,
    {
        for spec in &self.state.config.dynamic_socks {
            spawn_socks_forwarder(spec.clone(), session.clone(), &self.state.tasks).await?;
        }
        Ok(())
    }

    /// Start all remote TCP forwarders.
    pub async fn start_remote_tcp_forwarders<R>(&self, session: &mut R) -> Result<()>
    where
        R: RemoteRegistrar + Send,
    {
        for spec in &self.state.config.remote_tcp {
            register_remote_forward(spec.clone(), session, &self.state.remote_bindings).await?;
        }
        Ok(())
    }

    /// Start all remote Unix socket forwarders.
    pub async fn start_remote_unix_forwarders<R>(&self, session: &mut R) -> Result<()>
    where
        R: RemoteRegistrar + Send,
    {
        #[cfg(unix)]
        {
            for spec in &self.state.config.remote_unix {
                register_remote_streamlocal(spec.clone(), session, &self.state.remote_streamlocals).await?;
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            if !self.state.config.remote_unix.is_empty() {
                return Err(crate::SshCoreError::Other(
                    "unix socket forwarding is only supported on Unix platforms".into(),
                ));
            }
            Ok(())
        }
    }

    /// Shutdown all forwarding tasks and cancel remote forwards.
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

    /// Handle an incoming remote TCP forward channel.
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
        handle_remote_forward_channel(
            channel,
            host_to_connect,
            port_to_connect,
            originator_address,
            originator_port,
            &self.state.remote_bindings,
        )
        .await
    }

    /// Handle an incoming remote Unix socket forward channel.
    #[cfg(unix)]
    pub async fn handle_remote_streamlocal_channel<C>(&self, channel: C, socket_path: &str) -> Result<()>
    where
        C: RemoteForwardChannel,
    {
        handle_remote_streamlocal_channel(channel, socket_path, &self.state.remote_streamlocals).await
    }

    /// Handle an incoming remote Unix socket forward channel (non-Unix platforms).
    #[cfg(not(unix))]
    pub async fn handle_remote_streamlocal_channel<C>(&self, channel: C, socket_path: &str) -> Result<()>
    where
        C: RemoteForwardChannel,
    {
        let _ = channel.close().await;
        warn!(socket = socket_path, "streamlocal forwarding is not supported on this platform");
        Ok(())
    }

    /// Resolve the target for a remote TCP forward.
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
        use std::fs;
        let mut paths = self.state.local_unix_paths.lock().await;
        for path in paths.drain(..) {
            if let Err(err) = fs::remove_file(&path)
                && err.kind() != std::io::ErrorKind::NotFound
            {
                warn!(?err, socket = %path.display(), "failed to remove unix socket");
            }
        }
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
        if let Ok(value) = env::var(key)
            && sent.insert(key.to_string())
        {
            channel.set_env(false, key, value).await?;
        }
        Ok(())
    }

    /// Public test helper for proxying arbitrary streams.
    #[cfg(any(test, feature = "forwarding-tests"))]
    pub async fn proxy_streams<R, L>(&self, remote_stream: R, local_stream: L) -> Result<()>
    where
        R: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
        L: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        super::remote::proxy_streams(remote_stream, local_stream).await
    }
}

#[cfg(test)]
#[path = "manager_tests.rs"]
mod tests;
