use std::env;
use std::io::{self, Cursor, Read, Write};
use std::thread;
use std::time::Duration;

use anyhow::Result;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, size as term_size};
use signal_hook::iterator::Signals;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};

use crate::session::SessionHandle;
use crate::terminal::{NewlineMode, default_pty_modes, map_input};
use russh::Sig;

#[derive(Clone, Copy)]
pub struct ShellOptions {
    pub newline_mode: NewlineMode,
    pub local_echo: bool,
}

pub async fn run_shell(session: &mut SessionHandle, options: ShellOptions) -> Result<()> {
    let mut channel = session.channel_open_session().await?;
    let (cols, rows) = term_size().unwrap_or((80, 24));
    let pty_modes = default_pty_modes();
    channel
        .request_pty(
            true,
            &env::var("TERM").unwrap_or_else(|_| "xterm".into()),
            cols as u32,
            rows as u32,
            0,
            0,
            &pty_modes,
        )
        .await?;
    channel.request_shell(true).await?;

    let _raw_guard = RawModeGuard::activate()?;

    let (tx, mut rx) = unbounded_channel::<InputEvent>();
    spawn_input_thread(tx.clone());
    spawn_resize_thread(tx.clone());
    spawn_signal_thread(tx);

    let mut stdout = tokio::io::stdout();
    let mut stdin_closed = false;

    loop {
        tokio::select! {
            maybe_event = rx.recv() => {
                match maybe_event {
                    Some(InputEvent::Data(data)) => {
                        if !data.is_empty() {
                            let (printable, signals) = partition_signals(&data);
                            for signal in signals {
                                channel.signal(signal).await?;
                            }
                            if printable.is_empty() {
                                continue;
                            }
                            let mapped = map_input(&printable, options.newline_mode);
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
                    Some(InputEvent::OsSignal(code)) => {
                        if code == signal_hook::consts::SIGWINCH {
                            let (cols, rows) = term_size().unwrap_or((80, 24));
                            channel
                                .window_change(cols as u32, rows as u32, 0, 0)
                                .await?;
                        }
                        if let Some(sig) = signal_for_os(code) {
                            channel.signal(sig).await?;
                        }
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

fn spawn_signal_thread(tx: UnboundedSender<InputEvent>) {
    thread::spawn(move || {
        let mut signals = Signals::new([
            signal_hook::consts::SIGINT,
            signal_hook::consts::SIGQUIT,
            signal_hook::consts::SIGTSTP,
            signal_hook::consts::SIGTERM,
            signal_hook::consts::SIGHUP,
            signal_hook::consts::SIGWINCH,
        ])
        .expect("install signal handlers");
        for signal in signals.forever() {
            if tx.send(InputEvent::OsSignal(signal)).is_err() {
                break;
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
    OsSignal(i32),
    Eof,
}

fn partition_signals(data: &[u8]) -> (Vec<u8>, Vec<Sig>) {
    let mut printable = Vec::with_capacity(data.len());
    let mut signals = Vec::new();
    for &byte in data {
        if let Some(sig) = signal_for_byte(byte) {
            signals.push(sig);
        } else {
            printable.push(byte);
        }
    }
    (printable, signals)
}

fn signal_for_byte(byte: u8) -> Option<Sig> {
    match byte {
        0x03 => Some(Sig::INT),
        0x1c => Some(Sig::QUIT),
        0x1a => Some(Sig::Custom("TSTP".into())),
        _ => None,
    }
}

fn signal_for_os(code: i32) -> Option<Sig> {
    match code {
        x if x == signal_hook::consts::SIGINT => Some(Sig::INT),
        x if x == signal_hook::consts::SIGQUIT => Some(Sig::QUIT),
        x if x == signal_hook::consts::SIGTSTP => Some(Sig::Custom("TSTP".into())),
        x if x == signal_hook::consts::SIGTERM => Some(Sig::TERM),
        x if x == signal_hook::consts::SIGHUP => Some(Sig::HUP),
        x if x == signal_hook::consts::SIGWINCH => Some(Sig::Custom("WINCH".into())),
        _ => None,
    }
}
