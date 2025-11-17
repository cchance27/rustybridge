use anyhow::Result;
use russh::{
    ChannelMsg, Disconnect, client::{self, Handle}
};
use tokio::io::AsyncWriteExt;

mod shell;

pub use shell::{ShellOptions, run_shell};

pub type SessionHandle<H> = Handle<H>;

pub async fn run_command<H>(session: &mut SessionHandle<H>, command: &str) -> Result<()>
where
    H: client::Handler + Send,
{
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

pub async fn disconnect<H>(session: &mut SessionHandle<H>)
where
    H: client::Handler + Send,
{
    let _ = session.disconnect(Disconnect::ByApplication, "", "").await;
}
