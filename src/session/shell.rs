use std::env;
use std::io::{self, Cursor, Read, Write};
use std::thread;
use std::time::Duration;

use anyhow::Result;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, size as term_size};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};

use crate::session::SessionHandle;
use crate::terminal::{NewlineMode, map_input};

#[derive(Clone, Copy)]
pub struct ShellOptions {
    pub newline_mode: NewlineMode,
    pub local_echo: bool,
}

pub async fn run_shell(session: &mut SessionHandle, options: ShellOptions) -> Result<()> {
    let mut channel = session.channel_open_session().await?;
    let (cols, rows) = term_size().unwrap_or((80, 24));
    channel
        .request_pty(
            true,
            &env::var("TERM").unwrap_or_else(|_| "xterm".into()),
            cols as u32,
            rows as u32,
            0,
            0,
            &[],
        )
        .await?;
    channel.request_shell(true).await?;

    let _raw_guard = RawModeGuard::activate()?;

    let (tx, mut rx) = unbounded_channel::<InputEvent>();
    spawn_input_thread(tx.clone());
    spawn_resize_thread(tx);

    let mut stdout = tokio::io::stdout();
    let mut stdin_closed = false;

    loop {
        tokio::select! {
            maybe_event = rx.recv() => {
                match maybe_event {
                    Some(InputEvent::Data(data)) => {
                        if !data.is_empty() {
                            let mapped = map_input(&data, options.newline_mode);
                            if options.local_echo {
                                let _ = io::stdout().write_all(&mapped);
                                let _ = io::stdout().flush();
                            }
                            let mut cursor = Cursor::new(mapped);
                            channel.data(&mut cursor).await?;
                        }
                    }
                    Some(InputEvent::Resize(cols, rows)) => {
                        let cols = cols.max(1);
                        let rows = rows.max(1);
                        channel
                            .window_change(cols as u32, rows as u32, 0, 0)
                            .await?;
                    }
                    Some(InputEvent::Eof) | None => {
                        if !stdin_closed {
                            channel.eof().await?;
                            stdin_closed = true;
                        }
                    }
                }
            }
            msg = channel.wait() => {
                match msg {
                    Some(russh::ChannelMsg::Data { data }) => {
                        stdout.write_all(&data).await?;
                        stdout.flush().await?;
                    }
                    Some(russh::ChannelMsg::ExtendedData { data, .. }) => {
                        stdout.write_all(&data).await?;
                        stdout.flush().await?;
                    }
                    Some(russh::ChannelMsg::ExitStatus { .. }) | Some(russh::ChannelMsg::Close) | None => {
                        break;
                    }
                    _ => {}
                }
            }
        }
    }

    channel.close().await?;
    Ok(())
}

fn spawn_input_thread(tx: UnboundedSender<InputEvent>) {
    thread::spawn(move || {
        let stdin = io::stdin();
        let mut stdin = stdin.lock();
        let mut buf = [0u8; 1024];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => {
                    let _ = tx.send(InputEvent::Eof);
                    break;
                }
                Ok(n) => {
                    if n == 1 && buf[0] == 0x04 {
                        let _ = tx.send(InputEvent::Eof);
                        break;
                    }
                    let _ = tx.send(InputEvent::Data(buf[..n].to_vec()));
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    let _ = tx.send(InputEvent::Eof);
                    break;
                }
            }
        }
    });
}

fn spawn_resize_thread(tx: UnboundedSender<InputEvent>) {
    thread::spawn(move || {
        let mut last_size = term_size().unwrap_or((80, 24));
        loop {
            thread::sleep(Duration::from_millis(200));
            match term_size() {
                Ok(size) => {
                    if size != last_size {
                        last_size = size;
                        if tx.send(InputEvent::Resize(size.0, size.1)).is_err() {
                            break;
                        }
                    }
                }
                Err(_) => {}
            }
        }
    });
}

struct RawModeGuard;

impl RawModeGuard {
    fn activate() -> io::Result<Self> {
        enable_raw_mode().map_err(io::Error::other)?;
        Ok(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
    }
}

enum InputEvent {
    Data(Vec<u8>),
    Resize(u16, u16),
    Eof,
}
