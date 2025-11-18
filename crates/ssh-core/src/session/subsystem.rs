use std::io::Cursor;

use anyhow::{Result, anyhow};
use russh::{ChannelMsg, client};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::mpsc::{UnboundedSender, unbounded_channel},
};

use crate::forwarding::ForwardingManager;

use super::SharedSessionHandle;

/// Run an SSH subsystem using the process STDIN/STDOUT streams.
pub async fn run_subsystem<H>(
    session: &SharedSessionHandle<H>,
    subsystem: &str,
    forward_agent: bool,
    forwarding: &ForwardingManager,
) -> Result<()>
where
    H: client::Handler + Send,
{
    run_subsystem_with_io(
        session,
        subsystem,
        forward_agent,
        forwarding,
        tokio::io::stdin(),
        tokio::io::stdout(),
    )
    .await
}

/// Run an SSH subsystem using the provided input/output streams.
pub async fn run_subsystem_with_io<H, R, W>(
    session: &SharedSessionHandle<H>,
    subsystem: &str,
    forward_agent: bool,
    forwarding: &ForwardingManager,
    input: R,
    mut output: W,
) -> Result<()>
where
    H: client::Handler + Send,
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin,
{
    let mut channel = session.channel_open_session().await?;
    if forward_agent {
        channel.agent_forward(false).await?;
    }
    forwarding.prepare_channel(&channel).await?;
    channel.request_subsystem(true, subsystem).await?;

    let (tx, mut rx) = unbounded_channel::<InputChunk>();
    tokio::spawn(async move {
        pump_input(input, tx).await;
    });

    let mut stdin_closed = false;
    let mut exit_code = None;

    loop {
        tokio::select! {
            maybe_chunk = rx.recv() => {
                match maybe_chunk {
                    Some(InputChunk::Data(bytes)) => {
                        if !bytes.is_empty() {
                            let mut cursor = Cursor::new(bytes);
                            channel.data(&mut cursor).await?;
                        }
                    }
                    Some(InputChunk::Eof) | None => {
                        if !stdin_closed {
                            channel.eof().await?;
                            stdin_closed = true;
                        }
                    }
                    Some(InputChunk::Error(err)) => return Err(err),
                }
            }
            msg = channel.wait() => {
                match msg {
                    Some(ChannelMsg::Data { data }) => {
                        output.write_all(&data).await?;
                        output.flush().await?;
                    }
                    Some(ChannelMsg::ExtendedData { data, .. }) => {
                        output.write_all(&data).await?;
                        output.flush().await?;
                    }
                    Some(ChannelMsg::ExitStatus { exit_status }) => {
                        exit_code = Some(exit_status);
                    }
                    Some(ChannelMsg::Close) | Some(ChannelMsg::Eof) | None => break,
                    _ => {}
                }
            }
        }
    }

    output.flush().await?;

    if let Some(code) = exit_code {
        println!("subsystem {subsystem} exit status: {code}");
    }

    channel.close().await?;
    Ok(())
}

enum InputChunk {
    Data(Vec<u8>),
    Eof,
    Error(anyhow::Error),
}

async fn pump_input<R>(mut reader: R, tx: UnboundedSender<InputChunk>)
where
    R: AsyncRead + Send + Unpin + 'static,
{
    let mut buf = vec![0u8; 4096];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => {
                let _ = tx.send(InputChunk::Eof);
                break;
            }
            Ok(n) => {
                let mut chunk = Vec::with_capacity(n);
                chunk.extend_from_slice(&buf[..n]);
                if tx.send(InputChunk::Data(chunk)).is_err() {
                    break;
                }
            }
            Err(err) => {
                let _ = tx.send(InputChunk::Error(anyhow!(err)));
                break;
            }
        }
    }
}
