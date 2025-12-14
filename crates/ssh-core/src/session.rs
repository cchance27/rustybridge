use russh::{
    ChannelMsg,
    Disconnect,
    client::{self, Handle},
};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

mod shell;
mod subsystem;

use crate::forwarding::ForwardingManager;
pub use shell::{ShellOptions, run_shell};
pub use subsystem::{run_subsystem, run_subsystem_with_io};

pub type SessionHandle<H> = Handle<H>;
pub type SharedSessionHandle<H> = Arc<Handle<H>>;

pub async fn run_command<H>(
    session: &SharedSessionHandle<H>,
    command: &str,
    forward_agent: bool,
    forwarding: &ForwardingManager,
) -> crate::SshResult<()>
where
    H: client::Handler + Send,
{
    let mut channel = session.channel_open_session().await?;
    if forward_agent {
        channel.agent_forward(false).await?;
    }
    forwarding.prepare_channel(&channel).await?;
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

pub async fn disconnect<H>(session: &SharedSessionHandle<H>)
where
    H: client::Handler + Send,
{
    let _ = session.disconnect(Disconnect::ByApplication, "", "").await;
}
