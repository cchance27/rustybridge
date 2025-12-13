//! Integration tests for SSH forwarding functionality.
//!
//! These tests verify the local TCP, dynamic SOCKS, and remote TCP forwarding
//! startup sequences and shutdown behavior. They use mock sessions and registrars
//! to validate the ForwardingManager's coordination logic.
//!
//! Feature gated behind `forwarding-tests` to avoid running in normal test suites.
#![cfg(feature = "forwarding-tests")]

use std::{
    collections::VecDeque, net::TcpListener, path::PathBuf, sync::{Arc, Mutex}
};

use anyhow::Result;
use async_trait::async_trait;
use rb_types::ssh::{DynamicSocksForward, ForwardingConfig, LocalTcpForward, RemoteTcpForward};
#[cfg(unix)]
use rb_types::ssh::{LocalUnixForward, RemoteUnixForward};
use ssh_core::{
    SshResult, forwarding::{ForwardSession, ForwardStream, ForwardingManager, RemoteRegistrar}
};
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt}, net::TcpStream, sync::mpsc, time::{Duration, sleep}
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forwarding_startup_sequences() -> Result<()> {
    let tcp_port = pick_free_port();
    let socks_port = pick_free_port();
    let mut config = ForwardingConfig::default();
    config.local_tcp.push(LocalTcpForward {
        bind_address: Some("127.0.0.1".into()),
        bind_port: tcp_port,
        target_host: "internal.service".into(),
        target_port: 8080,
    });
    config.dynamic_socks.push(DynamicSocksForward {
        bind_address: Some("127.0.0.1".into()),
        bind_port: socks_port,
    });
    config.remote_tcp.push(RemoteTcpForward {
        bind_address: Some("0.0.0.0".into()),
        bind_port: 2222,
        target_host: "dest".into(),
        target_port: 22,
    });

    let manager = ForwardingManager::new(config);
    let mut registrar = MockRegistrar::new();
    manager.start_remote_tcp_forwarders(&mut registrar).await?;
    #[cfg(unix)]
    manager.start_remote_unix_forwarders(&mut registrar).await?;

    let (session, mut stream_rx) = MockForwardSession::new();
    manager.start_local_tcp_forwarders(session.clone()).await?;
    manager.start_dynamic_socks(session.clone()).await?;
    sleep(Duration::from_millis(50)).await;

    // Local TCP forward piping.
    let mut local = TcpStream::connect(("127.0.0.1", tcp_port)).await?;
    let mut remote = stream_rx.recv().await.expect("tcp forward stream");
    local.write_all(b"ping").await?;
    let mut buf = [0u8; 4];
    remote.read_exact(&mut buf).await?;
    assert_eq!(&buf, b"ping");
    remote.write_all(b"pong").await?;
    local.read_exact(&mut buf).await?;
    assert_eq!(&buf, b"pong");

    // SOCKS handshake and payload relay.
    let mut socks = TcpStream::connect(("127.0.0.1", socks_port)).await?;
    socks.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut reply = [0u8; 2];
    socks.read_exact(&mut reply).await?;
    assert_eq!(reply, [0x05, 0x00]);

    socks.write_all(&[0x05, 0x01, 0x00, 0x01, 203, 0, 113, 10, 0x1F, 0x90]).await?;
    let mut resp = [0u8; 10];
    socks.read_exact(&mut resp).await?;
    assert_eq!(resp[1], 0x00);
    let mut socks_remote = stream_rx.recv().await.expect("socks remote stream");
    socks_remote.write_all(b"ok").await?;
    let mut ok_buf = [0u8; 2];
    socks.read_exact(&mut ok_buf).await?;
    assert_eq!(&ok_buf, b"ok");

    // Verify the session observed the expected direct opens.
    let ops = session.requests();
    assert!(
        ops.iter().any(|s| s.contains("internal.service:8080")),
        "missing tcp forward request in {ops:?}"
    );
    assert!(
        ops.iter().any(|s| s.contains("203.0.113.10:8080")),
        "missing socks forward request in {ops:?}"
    );
    assert_eq!(registrar.calls.lock().unwrap().len(), 1, "expected single remote tcp registration");

    manager.shutdown(Some(session)).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_cancels_remote_and_unix_state() -> Result<()> {
    #[cfg(unix)]
    let sock_path = temp_socket("rb-forward-local.sock");
    let mut config = ForwardingConfig::default();
    config.remote_tcp.push(RemoteTcpForward {
        bind_address: Some("127.0.0.1".into()),
        bind_port: 3555,
        target_host: "mirror".into(),
        target_port: 3555,
    });
    #[cfg(unix)]
    {
        config.local_unix.push(LocalUnixForward {
            local_socket: sock_path.clone(),
            remote_socket: PathBuf::from("/tmp/remote.sock"),
        });
        config.remote_unix.push(RemoteUnixForward {
            remote_socket: PathBuf::from("/tmp/daemon.sock"),
            local_socket: PathBuf::from("/tmp/backhaul.sock"),
        });
    }

    let manager = ForwardingManager::new(config);
    let mut registrar = MockRegistrar::new();
    manager.start_remote_tcp_forwarders(&mut registrar).await?;

    let (session, _stream_rx) = MockForwardSession::new();
    #[cfg(unix)]
    manager.start_local_unix_forwarders(session.clone()).await?;

    sleep(Duration::from_millis(25)).await;
    manager.shutdown(Some(session.clone())).await?;

    let cancellations = session.cancelled_tcp.lock().unwrap().clone();
    assert!(
        cancellations.iter().any(|(addr, _)| addr == "127.0.0.1"),
        "expected tcp cancel entry, got {cancellations:?}"
    );
    #[cfg(unix)]
    {
        assert!(
            session.cancelled_streamlocals.lock().unwrap().len() >= 1,
            "expected remote unix cancel"
        );
        assert!(!sock_path.exists(), "local unix socket should be removed on shutdown");
    }

    Ok(())
}

fn pick_free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .and_then(|listener| listener.local_addr())
        .map(|addr| addr.port())
        .unwrap()
}

#[cfg(unix)]
fn temp_socket(name: &str) -> PathBuf {
    use std::{fs, time::SystemTime};

    let mut path = std::env::temp_dir();
    let nanos = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_nanos();
    path.push(format!("rb-{name}-{}-{nanos}", std::process::id()));
    if path.exists() {
        let _ = fs::remove_file(&path);
    }
    path
}

#[derive(Clone)]
struct MockForwardSession {
    ops: Arc<Mutex<Vec<String>>>,
    streams: mpsc::UnboundedSender<io::DuplexStream>,
    pub cancelled_tcp: Arc<Mutex<Vec<(String, u32)>>>,
    #[cfg(unix)]
    pub cancelled_streamlocals: Arc<Mutex<Vec<String>>>,
}

impl MockForwardSession {
    fn new() -> (Self, mpsc::UnboundedReceiver<io::DuplexStream>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let session = Self {
            ops: Arc::new(Mutex::new(Vec::new())),
            streams: tx,
            cancelled_tcp: Arc::new(Mutex::new(Vec::new())),
            #[cfg(unix)]
            cancelled_streamlocals: Arc::new(Mutex::new(Vec::new())),
        };
        (session, rx)
    }

    fn requests(&self) -> Vec<String> {
        self.ops.lock().unwrap().clone()
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
        let (client, server) = io::duplex(4096);
        self.streams.send(server).unwrap();
        Ok(Box::new(client))
    }

    #[cfg(unix)]
    async fn open_direct_streamlocal(&self, remote_socket: PathBuf) -> SshResult<ForwardStream> {
        self.ops.lock().unwrap().push(format!("streamlocal {}", remote_socket.display()));
        let (client, server) = io::duplex(4096);
        self.streams.send(server).unwrap();
        Ok(Box::new(client))
    }

    async fn cancel_tcpip_forwarding(&self, bind_address: String, port: u32) -> SshResult<()> {
        self.cancelled_tcp.lock().unwrap().push((bind_address, port));
        Ok(())
    }

    #[cfg(unix)]
    async fn cancel_streamlocal_forwarding(&self, remote_socket: String) -> SshResult<()> {
        self.cancelled_streamlocals.lock().unwrap().push(remote_socket);
        Ok(())
    }
}

struct MockRegistrar {
    calls: Arc<Mutex<VecDeque<String>>>,
}

impl MockRegistrar {
    fn new() -> Self {
        Self {
            calls: Arc::new(Mutex::new(VecDeque::new())),
        }
    }
}

#[async_trait]
impl RemoteRegistrar for MockRegistrar {
    async fn request_tcpip_forward(&mut self, bind_address: String, bind_port: u16) -> SshResult<u32> {
        self.calls.lock().unwrap().push_back(format!("{bind_address}:{bind_port}"));
        Ok(bind_port as u32 + 100)
    }

    #[cfg(unix)]
    async fn request_streamlocal_forward(&mut self, remote_socket: String) -> SshResult<()> {
        self.calls.lock().unwrap().push_back(remote_socket);
        Ok(())
    }
}
