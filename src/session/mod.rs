use anyhow::Result;
use russh::{ChannelMsg, Disconnect, client, client::Handle, keys::PublicKey};
use tokio::io::AsyncWriteExt;

mod shell;

pub use shell::{ShellOptions, run_shell};

pub struct AcceptAllKeys;

impl client::Handler for AcceptAllKeys {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _server_public_key: &PublicKey) -> Result<bool, russh::Error> {
        Ok(true)
    }
}

pub type SessionHandle = Handle<AcceptAllKeys>;

pub async fn run_command(session: &mut SessionHandle, command: &str) -> Result<()> {
    let mut channel = session.channel_open_session().await?;
    channel.exec(true, command.as_bytes()).await?;

    let mut stdout = tokio::io::stdout();
    let mut exit_code = None;

    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { data } => {
                stdout.write_all(&data).await?;
                stdout.flush().await?;
            }
            ChannelMsg::ExtendedData { data, .. } => {
                stdout.write_all(&data).await?;
                stdout.flush().await?;
            }
            ChannelMsg::ExitStatus { exit_status } => {
                exit_code = Some(exit_status);
            }
            ChannelMsg::Close | ChannelMsg::Eof => break,
            _ => {}
        }
    }

    if let Some(code) = exit_code {
        println!("\nremote exit status: {code}");
    }

    channel.close().await?;
    Ok(())
}

pub async fn disconnect(session: &mut SessionHandle) {
    let _ = session.disconnect(Disconnect::ByApplication, "", "").await;
}
