use super::traits::ForwardSession;
use rb_types::ssh::{LocalTcpForward, LocalUnixForward};
use std::net::SocketAddr;
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::{
    io::{AsyncWriteExt, copy_bidirectional},
    net::TcpStream,
    task::JoinHandle,
};
use tracing::warn;

type Result<T> = crate::SshResult<T>;

/// Spawn a local TCP forwarder task.
pub(super) async fn spawn_local_tcp_forwarder<S>(
    spec: LocalTcpForward,
    session: S,
    tasks: &tokio::sync::Mutex<Vec<JoinHandle<()>>>,
) -> Result<()>
where
    S: ForwardSession,
{
    use tokio::net::TcpListener;
    use tracing::info;

    let bind_host = spec.bind_address.clone().unwrap_or_else(|| "127.0.0.1".to_string());
    let listener = TcpListener::bind((bind_host.as_str(), spec.bind_port)).await?;
    info!(
        bind = %format!("{}:{}", bind_host, spec.bind_port),
        target = %format!("{}:{}", spec.target_host, spec.target_port),
        "local TCP forward listening"
    );
    let task = tokio::spawn(run_local_tcp_listener(listener, spec, session));
    tasks.lock().await.push(task);
    Ok(())
}

/// Spawn a local Unix socket forwarder task.
#[cfg(unix)]
pub(super) async fn spawn_local_unix_forwarder<S>(
    spec: LocalUnixForward,
    session: S,
    tasks: &tokio::sync::Mutex<Vec<JoinHandle<()>>>,
    local_unix_paths: &tokio::sync::Mutex<Vec<std::path::PathBuf>>,
) -> Result<()>
where
    S: ForwardSession,
{
    use std::fs;
    use tracing::info;

    let path = spec.local_socket.clone();
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    if path.exists() {
        let _ = fs::remove_file(&path);
    }
    let listener = UnixListener::bind(&path)?;
    local_unix_paths.lock().await.push(path.clone());
    info!(
        local = %path.display(),
        remote = %spec.remote_socket.display(),
        "local unix forward listening"
    );
    let task = tokio::spawn(run_local_unix_listener(listener, spec.remote_socket, session));
    tasks.lock().await.push(task);
    Ok(())
}

async fn run_local_tcp_listener<S>(listener: tokio::net::TcpListener, spec: LocalTcpForward, session: S)
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
async fn run_local_unix_listener<S>(listener: UnixListener, remote_socket: std::path::PathBuf, session: S)
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
async fn handle_local_unix_connection<S>(mut stream: UnixStream, remote_socket: std::path::PathBuf, session: S) -> Result<()>
where
    S: ForwardSession,
{
    let mut remote = session.open_direct_streamlocal(remote_socket).await?;
    let copy_result = copy_bidirectional(&mut stream, remote.as_mut()).await;
    let _ = remote.as_mut().shutdown().await;
    copy_result?;
    Ok(())
}
