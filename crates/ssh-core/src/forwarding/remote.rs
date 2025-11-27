use rb_types::ssh::{RemoteTcpForward, RemoteUnixForward};
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, copy_bidirectional}, net::TcpStream
};
use tracing::{info, warn};

use super::traits::{RemoteForwardChannel, RemoteRegistrar};

type Result<T> = crate::SshResult<T>;

#[derive(Default, Clone)]
pub(super) struct RemoteRegistration {
    pub bind_address: Option<String>,
    pub actual_port: u32,
    pub target_host: String,
    pub target_port: u16,
}

#[cfg(unix)]
#[derive(Default, Clone)]
pub(super) struct RemoteStreamLocalRegistration {
    pub remote_socket: String,
    pub local_socket: std::path::PathBuf,
}

/// Register a remote TCP forward with the server.
pub(super) async fn register_remote_forward<R>(
    spec: RemoteTcpForward,
    session: &mut R,
    remote_bindings: &tokio::sync::Mutex<Vec<RemoteRegistration>>,
) -> Result<()>
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
    remote_bindings.lock().await.push(RemoteRegistration {
        bind_address: spec.bind_address,
        actual_port,
        target_host: spec.target_host,
        target_port: spec.target_port,
    });
    Ok(())
}

/// Register a remote Unix socket forward with the server.
#[cfg(unix)]
pub(super) async fn register_remote_streamlocal<R>(
    spec: RemoteUnixForward,
    session: &mut R,
    remote_streamlocals: &tokio::sync::Mutex<Vec<RemoteStreamLocalRegistration>>,
) -> Result<()>
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
    remote_streamlocals.lock().await.push(RemoteStreamLocalRegistration {
        remote_socket: remote,
        local_socket: spec.local_socket,
    });
    Ok(())
}

/// Handle an incoming remote TCP forward channel.
pub(super) async fn handle_remote_forward_channel<C>(
    channel: C,
    host_to_connect: &str,
    port_to_connect: u32,
    originator_address: &str,
    originator_port: u32,
    remote_bindings: &tokio::sync::Mutex<Vec<RemoteRegistration>>,
) -> Result<()>
where
    C: RemoteForwardChannel,
{
    if let Some((target_host, target_port)) = resolve_remote_target(host_to_connect, port_to_connect, remote_bindings).await {
        info!(
            remote = %format!("{host_to_connect}:{port_to_connect}"),
            target = %format!("{target_host}:{target_port}"),
            origin = %format!("{originator_address}:{originator_port}"),
            "proxying remote forwarded connection"
        );
        let remote_stream = channel.into_stream();
        proxy_remote_tcp_stream(remote_stream, &target_host, target_port).await?;
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

/// Handle an incoming remote Unix socket forward channel.
#[cfg(unix)]
pub(super) async fn handle_remote_streamlocal_channel<C>(
    channel: C,
    socket_path: &str,
    remote_streamlocals: &tokio::sync::Mutex<Vec<RemoteStreamLocalRegistration>>,
) -> Result<()>
where
    C: RemoteForwardChannel,
{
    if let Some(local_path) = resolve_streamlocal_target(socket_path, remote_streamlocals).await {
        let local = UnixStream::connect(&local_path).await?;
        let remote = channel.into_stream();
        proxy_stream_pair(remote, local).await?;
    } else {
        warn!(
            socket = socket_path,
            "received streamlocal channel with no matching --remote-unix-forward spec"
        );
        let _ = channel.close().await;
    }
    Ok(())
}

/// Resolve the target for a remote TCP forward.
async fn resolve_remote_target(
    bound_address: &str,
    bound_port: u32,
    remote_bindings: &tokio::sync::Mutex<Vec<RemoteRegistration>>,
) -> Option<(String, u16)> {
    let registrations = remote_bindings.lock().await;
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

/// Resolve the target for a remote Unix socket forward.
#[cfg(unix)]
async fn resolve_streamlocal_target(
    socket_path: &str,
    remote_streamlocals: &tokio::sync::Mutex<Vec<RemoteStreamLocalRegistration>>,
) -> Option<std::path::PathBuf> {
    let registrations = remote_streamlocals.lock().await;
    registrations
        .iter()
        .find(|entry| entry.remote_socket == socket_path)
        .map(|entry| entry.local_socket.clone())
}

async fn proxy_remote_tcp_stream<S>(remote_stream: S, target_host: &str, target_port: u16) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let local = TcpStream::connect((target_host, target_port)).await?;
    proxy_stream_pair(remote_stream, local).await
}

/// Proxy data between two streams bidirectionally.
pub(super) async fn proxy_stream_pair<R, L>(mut remote_stream: R, mut local_stream: L) -> Result<()>
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

/// Public test helper for proxying arbitrary streams.
#[cfg(any(test, feature = "forwarding-tests"))]
pub async fn proxy_streams<R, L>(remote_stream: R, local_stream: L) -> Result<()>
where
    R: AsyncRead + AsyncWrite + Unpin,
    L: AsyncRead + AsyncWrite + Unpin,
{
    proxy_stream_pair(remote_stream, local_stream).await
}
