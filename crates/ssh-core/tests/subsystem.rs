#![cfg(feature = "forwarding-tests")]

use std::{
    net::TcpListener, sync::{Arc, Mutex}, time::Duration
};

use anyhow::Result;
use russh::{
    Channel, ChannelId, CryptoVec, client::{self, Handler}, keys::{Algorithm, PrivateKey, PublicKey, ssh_key::rand_core::OsRng}, server::{self, Auth, MethodKind, MethodSet, Server as _, Session}
};
use ssh_core::{
    crypto::legacy_preferred, forwarding::{ForwardingConfig, ForwardingManager}, session::run_subsystem_with_io
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subsystem_round_trip_streams_data() -> Result<()> {
    let port = pick_free_port();
    let subsystems = Arc::new(Mutex::new(Vec::new()));
    let mut server_config = server::Config {
        preferred: legacy_preferred(),
        auth_rejection_time: Duration::from_millis(50),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        ..Default::default()
    };
    let mut methods = MethodSet::empty();
    methods.push(MethodKind::Password);
    server_config.methods = methods;
    server_config.keys.push(PrivateKey::random(&mut OsRng, Algorithm::Ed25519)?);

    let mut server = EchoServer {
        subsystems: subsystems.clone(),
    };
    let running = server.run_on_address(Arc::new(server_config), ("127.0.0.1", port));
    let handle = running.handle();
    let server_task = tokio::spawn(async move {
        running.await.expect("server run");
    });

    let mut client_config = client::Config {
        preferred: legacy_preferred(),
        ..Default::default()
    };
    client_config.keepalive_interval = Some(Duration::from_secs(5));
    let handler = TestClientHandler;
    let mut session = client::connect(Arc::new(client_config), ("127.0.0.1", port), handler).await?;
    session.authenticate_password("tester", "secret").await.expect("password auth");
    let session = Arc::new(session);

    let forwarding = ForwardingManager::new(ForwardingConfig::default());
    let (mut stdin_writer, stdin_reader) = duplex(128);
    let (stdout_writer, mut stdout_reader) = duplex(128);

    let session_clone = Arc::clone(&session);
    let forwarding_clone = forwarding.clone();
    let subsystem_task = tokio::spawn(async move {
        run_subsystem_with_io(&session_clone, "echo", false, &forwarding_clone, stdin_reader, stdout_writer)
            .await
            .expect("subsystem run");
    });

    stdin_writer.write_all(b"ping").await?;
    stdin_writer.shutdown().await?;

    let mut buf = [0u8; 4];
    stdout_reader.read_exact(&mut buf).await?;
    assert_eq!(&buf, b"ping");

    subsystem_task.await?;
    drop(session);

    handle.shutdown("test complete".into());
    server_task.await?;

    let recorded = subsystems.lock().unwrap().clone();
    assert!(
        recorded.iter().any(|name| name == "echo"),
        "server did not observe subsystem request: {recorded:?}"
    );

    Ok(())
}

fn pick_free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .and_then(|listener| listener.local_addr())
        .map(|addr| addr.port())
        .unwrap()
}

struct EchoServer {
    subsystems: Arc<Mutex<Vec<String>>>,
}

impl server::Server for EchoServer {
    type Handler = EchoHandler;

    fn new_client(&mut self, _addr: Option<std::net::SocketAddr>) -> Self::Handler {
        EchoHandler {
            subsystems: self.subsystems.clone(),
        }
    }
}

struct EchoHandler {
    subsystems: Arc<Mutex<Vec<String>>>,
}

impl server::Handler for EchoHandler {
    type Error = anyhow::Error;

    fn auth_password(&mut self, _user: &str, _password: &str) -> impl std::future::Future<Output = Result<Auth, Self::Error>> + Send {
        async { Ok(Auth::Accept) }
    }

    fn channel_open_session(
        &mut self,
        _channel: Channel<server::Msg>,
        _session: &mut Session,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        async { Ok(true) }
    }

    fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        let subsystems = self.subsystems.clone();
        let name = name.to_string();
        async move {
            subsystems.lock().unwrap().push(name);
            session.channel_success(channel)?;
            Ok(())
        }
    }

    fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        let mut payload = CryptoVec::new();
        payload.extend(data);
        async move {
            session.data(channel, payload)?;
            Ok(())
        }
    }

    fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        async move {
            session.exit_status_request(channel, 0)?;
            session.close(channel)?;
            Ok(())
        }
    }
}

#[derive(Clone)]
struct TestClientHandler;

impl Handler for TestClientHandler {
    type Error = anyhow::Error;

    fn check_server_key(&mut self, _server_public_key: &PublicKey) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        async { Ok(true) }
    }
}
