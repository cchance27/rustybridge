//! Integration tests for SSH port forwarding functionality.
//!
//! These tests verify local TCP forwarding, SOCKS proxy handling, remote forwarding,
//! and the bidirectional stream proxying. Requires network access to bind sockets.
//!
//! Feature gated behind `forwarding-tests` to avoid running in normal test suites.
#![cfg(feature = "forwarding-tests")]

use anyhow::{Result, anyhow};
use async_trait::async_trait;
#[cfg(unix)]
use rb_types::ssh::RemoteUnixForward;
use rb_types::ssh::{DynamicSocksForward, ForwardingConfig, LocalTcpForward, RemoteTcpForward};
use ssh_core::{
    SshCoreError,
    SshResult,
    forwarding::{ForwardSession, ForwardStream, ForwardingManager, RemoteForwardChannel, RemoteRegistrar},
};
use std::{
    collections::VecDeque,
    net::TcpListener,
    path::PathBuf,
    sync::{
        Arc,
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener as TokioTcpListener, TcpStream},
    sync::mpsc,
    time::{Duration, sleep},
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_forward_round_trip_moves_bytes() -> Result<()> {
    let tcp_port = pick_free_port();
    let mut config = ForwardingConfig::default();
    config.local_tcp.push(LocalTcpForward {
        bind_address: Some("127.0.0.1".into()),
        bind_port: tcp_port,
        target_host: "backend.local".into(),
        target_port: 9000,
    });
    let manager = ForwardingManager::new(config);
    let (session, mut rx) = MockForwardSession::new();
    manager.start_local_tcp_forwarders(session.clone()).await?;
    sleep(Duration::from_millis(25)).await;

    let mut local = TcpStream::connect(("127.0.0.1", tcp_port)).await?;
    let mut remote = rx.recv().await.expect("tcp forward stream");
    local.write_all(b"abc").await?;
    let mut buf = [0u8; 3];
    remote.read_exact(&mut buf).await?;
    assert_eq!(&buf, b"abc");
    remote.write_all(b"123").await?;
    local.read_exact(&mut buf).await?;
    assert_eq!(&buf, b"123");

    assert!(
        session.ops.lock().unwrap().iter().any(|entry| entry.contains("backend.local:9000")),
        "missing tcp forward request"
    );
    manager.shutdown(Some(session)).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks_proxy_handles_ipv4_and_hostnames() -> Result<()> {
    let socks_port = pick_free_port();
    let mut config = ForwardingConfig::default();
    config.dynamic_socks.push(DynamicSocksForward {
        bind_address: Some("127.0.0.1".into()),
        bind_port: socks_port,
    });
    let manager = ForwardingManager::new(config);
    let (session, mut rx) = MockForwardSession::new();
    manager.start_dynamic_socks(session.clone()).await?;
    sleep(Duration::from_millis(25)).await;

    handshake_ipv4(socks_port, &mut rx).await?;
    handshake_hostname(socks_port, &mut rx).await?;

    let ops = session.ops.lock().unwrap().clone();
    assert!(
        ops.iter().any(|op| op.contains("198.51.100.1:443")),
        "expected IPv4 request in {ops:?}"
    );
    assert!(
        ops.iter().any(|op| op.contains("example.com:2222")),
        "expected hostname request in {ops:?}"
    );

    manager.shutdown(Some(session)).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks_rejects_clients_without_noauth() -> Result<()> {
    let socks_port = pick_free_port();
    let mut config = ForwardingConfig::default();
    config.dynamic_socks.push(DynamicSocksForward {
        bind_address: Some("127.0.0.1".into()),
        bind_port: socks_port,
    });
    let manager = ForwardingManager::new(config);
    let (session, _rx) = MockForwardSession::new();
    manager.start_dynamic_socks(session.clone()).await?;
    sleep(Duration::from_millis(25)).await;

    let mut client = TcpStream::connect(("127.0.0.1", socks_port)).await?;
    client.write_all(&[0x05, 0x01, 0x02]).await?;
    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await?;
    assert_eq!(resp, [0x05, 0xFF], "expected NO AUTH method rejection");
    assert_eq!(session.ops.lock().unwrap().len(), 0, "session should not open channels");
    let mut term = [0u8; 1];
    let read = client.read(&mut term).await?;
    assert_eq!(read, 0, "SOCKS server should close connection after rejection");

    manager.shutdown(Some(session)).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks_rejects_wrong_version() -> Result<()> {
    let socks_port = pick_free_port();
    let mut config = ForwardingConfig::default();
    config.dynamic_socks.push(DynamicSocksForward {
        bind_address: Some("127.0.0.1".into()),
        bind_port: socks_port,
    });
    let manager = ForwardingManager::new(config);
    let (session, _rx) = MockForwardSession::new();
    manager.start_dynamic_socks(session.clone()).await?;
    sleep(Duration::from_millis(25)).await;

    let mut client = TcpStream::connect(("127.0.0.1", socks_port)).await?;
    client.write_all(&[0x04, 0x01, 0x00]).await?;
    let mut buf = [0; 1];
    match client.read(&mut buf).await {
        Ok(0) => {}
        Err(err) if err.kind() == std::io::ErrorKind::ConnectionReset => {}
        other => panic!("unexpected read result: {other:?}"),
    }
    assert!(session.ops.lock().unwrap().is_empty(), "no session operations expected");

    manager.shutdown(Some(session)).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks_rejects_invalid_command() -> Result<()> {
    let socks_port = pick_free_port();
    let mut config = ForwardingConfig::default();
    config.dynamic_socks.push(DynamicSocksForward {
        bind_address: Some("127.0.0.1".into()),
        bind_port: socks_port,
    });
    let manager = ForwardingManager::new(config);
    let (session, mut rx) = MockForwardSession::new();
    manager.start_dynamic_socks(session.clone()).await?;
    sleep(Duration::from_millis(25)).await;

    let mut client = TcpStream::connect(("127.0.0.1", socks_port)).await?;
    client.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut ack = [0u8; 2];
    client.read_exact(&mut ack).await?;
    assert_eq!(ack, [0x05, 0x00]);

    client.write_all(&[0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50]).await?;
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await?;
    assert_eq!(reply[1], 0x07, "expected command not supported");
    assert!(rx.try_recv().is_err(), "no remote stream should be opened");
    assert!(session.ops.lock().unwrap().is_empty(), "session should see no tcpip opens");

    manager.shutdown(Some(session)).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resolve_remote_targets_matches_assigned_ports() -> Result<()> {
    let mut config = ForwardingConfig::default();
    config.remote_tcp.push(RemoteTcpForward {
        bind_address: Some("0.0.0.0".into()),
        bind_port: 7000,
        target_host: "intranet".into(),
        target_port: 7000,
    });
    let manager = ForwardingManager::new(config);
    let mut registrar = MockRegistrar::new();
    manager.start_remote_tcp_forwarders(&mut registrar).await?;

    let assigned = registrar.ports.lock().unwrap()[0];
    let resolved = manager.resolve_remote_target("0.0.0.0", assigned).await;
    assert_eq!(resolved, Some(("intranet".into(), 7000)));
    manager.shutdown::<MockForwardSession>(None).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remote_forward_without_bind_defaults_to_loopback() -> Result<()> {
    let mut config = ForwardingConfig::default();
    config.remote_tcp.push(RemoteTcpForward {
        bind_address: None,
        bind_port: 4100,
        target_host: "localhost".into(),
        target_port: 22,
    });
    let manager = ForwardingManager::new(config);
    let mut registrar = MockRegistrar::new();
    manager.start_remote_tcp_forwarders(&mut registrar).await?;
    assert_eq!(registrar.addresses(), vec!["127.0.0.1".to_string()]);
    manager.shutdown::<MockForwardSession>(None).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handle_remote_forward_channel_proxies_known_target() -> Result<()> {
    let listener = TokioTcpListener::bind(("127.0.0.1", 0)).await?;
    let target_port = listener.local_addr()?.port();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4];
        socket.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        socket.write_all(b"pong").await.unwrap();
    });

    let mut config = ForwardingConfig::default();
    config.remote_tcp.push(RemoteTcpForward {
        bind_address: None,
        bind_port: 4000,
        target_host: "127.0.0.1".into(),
        target_port,
    });
    let manager = ForwardingManager::new(config);
    let mut registrar = MockRegistrar::new();
    manager.start_remote_tcp_forwarders(&mut registrar).await?;
    let assigned = registrar.ports.lock().unwrap()[0];

    let (mut remote_client, remote_stream) = io::duplex(64);
    let channel = MockRemoteChannel::new(remote_stream, Arc::new(AtomicBool::new(false)));
    let forward = {
        let mgr = manager.clone();
        tokio::spawn(async move {
            mgr.handle_remote_forward_channel(channel, "0.0.0.0", assigned, "origin", 1234)
                .await
                .unwrap();
        })
    };

    remote_client.write_all(b"ping").await?;
    let mut buf = [0u8; 4];
    remote_client.read_exact(&mut buf).await?;
    assert_eq!(&buf, b"pong");
    drop(remote_client);
    forward.await.unwrap();
    server.await.unwrap();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handle_remote_forward_channel_closes_unknown_target() -> Result<()> {
    let manager = ForwardingManager::new(ForwardingConfig::default());
    let closed = Arc::new(AtomicBool::new(false));
    let (_client, stream) = io::duplex(16);
    let channel = MockRemoteChannel::new(stream, closed.clone());
    manager
        .handle_remote_forward_channel(channel, "127.0.0.1", 5000, "origin", 0)
        .await?;
    assert!(closed.load(Ordering::SeqCst));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_streams_round_trip() -> Result<()> {
    let manager = ForwardingManager::new(ForwardingConfig::default());
    let (mut remote_client, remote_server) = io::duplex(64);
    let (mut local_client, local_server) = io::duplex(64);
    let proxy = tokio::spawn({
        let mgr = manager.clone();
        async move {
            let _ = mgr.proxy_streams(remote_server, local_server).await;
        }
    });

    remote_client.write_all(b"ping").await?;
    let mut buf = [0u8; 4];
    local_client.read_exact(&mut buf).await?;
    assert_eq!(&buf, b"ping");

    local_client.write_all(b"pong").await?;
    remote_client.read_exact(&mut buf).await?;
    assert_eq!(&buf, b"pong");

    drop(remote_client);
    drop(local_client);
    let _ = proxy.await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_streams_handles_remote_drop() -> Result<()> {
    let manager = ForwardingManager::new(ForwardingConfig::default());
    let (mut remote_client, remote_server) = io::duplex(32);
    let (local_client, local_server) = io::duplex(32);
    let proxy = {
        let mgr = manager.clone();
        tokio::spawn(async move {
            let _ = mgr.proxy_streams(remote_server, local_server).await;
        })
    };

    let _ = remote_client.write_all(b"bye").await;
    drop(remote_client);
    drop(local_client);
    let _ = proxy.await;
    Ok(())
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handle_remote_streamlocal_channel_proxies_data() -> Result<()> {
    use tokio::net::UnixListener;

    let local_path = temp_socket_path("forwarding-local.sock");
    if local_path.exists() {
        let _ = std::fs::remove_file(&local_path);
    }
    let listener = UnixListener::bind(&local_path)?;
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 5];
        socket.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
        socket.write_all(b"world").await.unwrap();
    });

    let remote_socket = temp_socket_path("forwarding-remote.sock");
    let mut config = ForwardingConfig::default();
    config.remote_unix.push(RemoteUnixForward {
        remote_socket: remote_socket.clone(),
        local_socket: local_path.clone(),
    });
    let manager = ForwardingManager::new(config);
    let mut registrar = MockRegistrar::new();
    manager.start_remote_unix_forwarders(&mut registrar).await?;

    let (mut remote_client, remote_stream) = io::duplex(32);
    let channel = MockRemoteChannel::new(remote_stream, Arc::new(AtomicBool::new(false)));
    let remote_socket_clone = remote_socket.clone();
    let forward = {
        let mgr = manager.clone();
        tokio::spawn(async move {
            let remote_str = remote_socket_clone.to_string_lossy().into_owned();
            mgr.handle_remote_streamlocal_channel(channel, &remote_str).await.unwrap();
        })
    };

    remote_client.write_all(b"hello").await?;
    let mut buf = [0u8; 5];
    remote_client.read_exact(&mut buf).await?;
    assert_eq!(&buf, b"world");
    drop(remote_client);
    forward.await.unwrap();
    server.await.unwrap();
    let _ = std::fs::remove_file(&local_path);
    if remote_socket.exists() {
        let _ = std::fs::remove_file(&remote_socket);
    }
    Ok(())
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handle_remote_streamlocal_channel_closes_unknown_target() -> Result<()> {
    let manager = ForwardingManager::new(ForwardingConfig::default());
    let closed = Arc::new(AtomicBool::new(false));
    let (_client, stream) = io::duplex(16);
    let channel = MockRemoteChannel::new(stream, closed.clone());
    manager.handle_remote_streamlocal_channel(channel, "/tmp/missing.sock").await?;
    assert!(closed.load(Ordering::SeqCst));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_handles_tcp_cancel_errors() -> Result<()> {
    let mut config = ForwardingConfig::default();
    config.remote_tcp.push(RemoteTcpForward {
        bind_address: None,
        bind_port: 4000,
        target_host: "target".into(),
        target_port: 4000,
    });
    let manager = ForwardingManager::new(config);
    let mut registrar = MockRegistrar::new();
    manager.start_remote_tcp_forwarders(&mut registrar).await?;
    #[cfg(unix)]
    let session = ShutdownMockSession::new(true, false);
    #[cfg(not(unix))]
    let session = ShutdownMockSession::new(true);
    manager.shutdown(Some(session.clone())).await?;
    let calls = session.tcp_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "127.0.0.1");
    assert_eq!(calls[0].1, 4200);
    Ok(())
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_handles_streamlocal_cancel_errors() -> Result<()> {
    let mut config = ForwardingConfig::default();
    let remote_path = "/tmp/shutdown-remote.sock";
    config.remote_unix.push(RemoteUnixForward {
        remote_socket: PathBuf::from(remote_path),
        local_socket: PathBuf::from("/tmp/shutdown-local.sock"),
    });
    let manager = ForwardingManager::new(config);
    let mut registrar = MockRegistrar::new();
    manager.start_remote_unix_forwarders(&mut registrar).await?;
    let session = ShutdownMockSession::new(false, true);
    manager.shutdown(Some(session.clone())).await?;
    let calls = session.stream_calls();
    assert_eq!(calls, vec![remote_path.to_string()]);
    Ok(())
}

async fn handshake_ipv4(port: u16, rx: &mut mpsc::UnboundedReceiver<io::DuplexStream>) -> Result<()> {
    let mut client = TcpStream::connect(("127.0.0.1", port)).await?;
    client.write_all(&[0x05, 0x02, 0x01, 0x00]).await?;
    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await?;
    assert_eq!(resp, [0x05, 0x00]);
    client.write_all(&[0x05, 0x01, 0x00, 0x01, 198, 51, 100, 1, 0x01, 0xBB]).await?;
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await?;
    assert_eq!(reply[1], 0x00);
    let mut remote = rx.recv().await.expect("socks stream");
    remote.write_all(b"hi").await?;
    let mut buf = [0u8; 2];
    client.read_exact(&mut buf).await?;
    assert_eq!(&buf, b"hi");
    Ok(())
}

async fn handshake_hostname(port: u16, rx: &mut mpsc::UnboundedReceiver<io::DuplexStream>) -> Result<()> {
    let mut client = TcpStream::connect(("127.0.0.1", port)).await?;
    client.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await?;
    assert_eq!(resp, [0x05, 0x00]);
    let mut payload = vec![0x05, 0x01, 0x00, 0x03, 0x0B];
    payload.extend_from_slice(b"example.com");
    payload.extend_from_slice(&[0x08, 0xAE]);
    client.write_all(&payload).await?;
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await?;
    assert_eq!(reply[1], 0x00);
    let mut remote = rx.recv().await.expect("hostname stream");
    remote.write_all(b"zz").await?;
    let mut buf = [0u8; 2];
    client.read_exact(&mut buf).await?;
    assert_eq!(&buf, b"zz");
    Ok(())
}

fn pick_free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .and_then(|listener| listener.local_addr())
        .map(|addr| addr.port())
        .unwrap()
}

#[derive(Clone)]
struct MockForwardSession {
    ops: Arc<Mutex<Vec<String>>>,
    streams: mpsc::UnboundedSender<io::DuplexStream>,
}

impl MockForwardSession {
    fn new() -> (Self, mpsc::UnboundedReceiver<io::DuplexStream>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let session = Self {
            ops: Arc::new(Mutex::new(Vec::new())),
            streams: tx,
        };
        (session, rx)
    }
}

#[async_trait]
impl ForwardSession for MockForwardSession {
    async fn open_direct_tcpip(
        &self,
        target_host: String,
        target_port: u16,
        origin_host: String,
        origin_port: u16,
    ) -> SshResult<ForwardStream> {
        self.ops
            .lock()
            .unwrap()
            .push(format!("tcpip {}:{} <- {}:{}", target_host, target_port, origin_host, origin_port));
        let (client, server) = io::duplex(1024);
        self.streams.send(server).unwrap();
        Ok(Box::new(client))
    }

    async fn cancel_tcpip_forwarding(&self, _bind_address: String, _port: u32) -> SshResult<()> {
        Ok(())
    }

    #[cfg(unix)]
    async fn open_direct_streamlocal(&self, _remote_socket: std::path::PathBuf) -> SshResult<ForwardStream> {
        let (client, server) = io::duplex(1024);
        self.streams.send(server).unwrap();
        Ok(Box::new(client))
    }

    #[cfg(unix)]
    async fn cancel_streamlocal_forwarding(&self, _remote_socket: String) -> SshResult<()> {
        Ok(())
    }
}

struct MockRegistrar {
    ports: Arc<Mutex<VecDeque<u32>>>,
    addresses: Arc<Mutex<Vec<String>>>,
}

impl MockRegistrar {
    fn new() -> Self {
        Self {
            ports: Arc::new(Mutex::new(VecDeque::new())),
            addresses: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn addresses(&self) -> Vec<String> {
        self.addresses.lock().unwrap().clone()
    }
}

#[async_trait]
impl RemoteRegistrar for MockRegistrar {
    async fn request_tcpip_forward(&mut self, bind_address: String, bind_port: u16) -> SshResult<u32> {
        let assigned = bind_port as u32 + 200;
        self.addresses.lock().unwrap().push(bind_address);
        self.ports.lock().unwrap().push_back(assigned);
        Ok(assigned)
    }

    #[cfg(unix)]
    async fn request_streamlocal_forward(&mut self, _remote_socket: String) -> SshResult<()> {
        Ok(())
    }
}

struct MockRemoteChannel {
    stream: Option<io::DuplexStream>,
    closed: Arc<AtomicBool>,
}

impl MockRemoteChannel {
    fn new(stream: io::DuplexStream, closed: Arc<AtomicBool>) -> Self {
        Self {
            stream: Some(stream),
            closed,
        }
    }
}

#[derive(Clone)]
struct ShutdownMockSession {
    tcp_calls: Arc<Mutex<Vec<(String, u32)>>>,
    #[cfg(unix)]
    stream_calls: Arc<Mutex<Vec<String>>>,
    fail_tcp: bool,
    #[cfg(unix)]
    fail_stream: bool,
}

impl ShutdownMockSession {
    #[cfg(unix)]
    fn new(fail_tcp: bool, fail_stream: bool) -> Self {
        Self {
            tcp_calls: Arc::new(Mutex::new(Vec::new())),
            #[cfg(unix)]
            stream_calls: Arc::new(Mutex::new(Vec::new())),
            fail_tcp,
            #[cfg(unix)]
            fail_stream,
        }
    }

    #[cfg(not(unix))]
    fn new(fail_tcp: bool) -> Self {
        Self {
            tcp_calls: Arc::new(Mutex::new(Vec::new())),
            fail_tcp,
        }
    }

    fn tcp_calls(&self) -> Vec<(String, u32)> {
        self.tcp_calls.lock().unwrap().clone()
    }

    #[cfg(unix)]
    fn stream_calls(&self) -> Vec<String> {
        self.stream_calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl ForwardSession for ShutdownMockSession {
    async fn open_direct_tcpip(
        &self,
        _target_host: String,
        _target_port: u16,
        _origin_host: String,
        _origin_port: u16,
    ) -> SshResult<ForwardStream> {
        Err(SshCoreError::Other("not used".into()))
    }

    #[cfg(unix)]
    async fn open_direct_streamlocal(&self, _remote_socket: PathBuf) -> SshResult<ForwardStream> {
        Err(SshCoreError::Other("not used".into()))
    }

    async fn cancel_tcpip_forwarding(&self, bind_address: String, port: u32) -> SshResult<()> {
        self.tcp_calls.lock().unwrap().push((bind_address, port));
        if self.fail_tcp {
            Err(SshCoreError::Other("tcp cancel failure".into()))
        } else {
            Ok(())
        }
    }

    #[cfg(unix)]
    async fn cancel_streamlocal_forwarding(&self, remote_socket: String) -> SshResult<()> {
        self.stream_calls.lock().unwrap().push(remote_socket.clone());
        if self.fail_stream {
            Err(SshCoreError::Other("streamlocal cancel failure".into()))
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl RemoteForwardChannel for MockRemoteChannel {
    type Stream = io::DuplexStream;

    fn into_stream(mut self) -> Self::Stream {
        self.stream.take().expect("stream available")
    }

    async fn close(self) -> SshResult<()> {
        self.closed.store(true, Ordering::SeqCst);
        Ok(())
    }
}

#[cfg(unix)]
fn temp_socket_path(name: &str) -> PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut path = std::env::temp_dir();
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    path.push(format!("rb-{name}-{}-{}", std::process::id(), nanos));
    path
}
