use super::traits::ForwardSession;
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, copy_bidirectional},
    net::TcpStream,
    task::JoinHandle,
};
use tracing::warn;

type Result<T> = crate::SshResult<T>;

/// Spawn a SOCKS5 proxy listener task.
pub(super) async fn spawn_socks_forwarder<S>(
    spec: rb_types::ssh::DynamicSocksForward,
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
        "dynamic SOCKS forward listening"
    );
    let task = tokio::spawn(run_socks_listener(listener, session));
    tasks.lock().await.push(task);
    Ok(())
}

async fn run_socks_listener<S>(listener: tokio::net::TcpListener, session: S)
where
    S: ForwardSession,
{
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let session = session.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_socks_client(stream, session).await {
                        warn!(?err, "socks client failed");
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
            warn!(?err, target = %format!("{target_host}:{target_port}"), "failed to open socks target");
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
