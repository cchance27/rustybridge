use std::{
    env, io::{self, Cursor, Read, Write}, thread, time::Duration
};

use anyhow::Result;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, size as term_size};
use russh::Sig;
use signal_hook::iterator::Signals;
use tokio::{
    io::AsyncWriteExt, sync::mpsc::{UnboundedSender, unbounded_channel}
};

use super::SharedSessionHandle;
use crate::logging;
use crate::{
    forwarding::ForwardingManager, terminal::{NewlineMode, current_pty_modes, map_input}
};

#[derive(Clone)]
pub struct ShellOptions {
    pub newline_mode: NewlineMode,
    pub local_echo: bool,
    pub forward_agent: bool,
    pub forwarding: ForwardingManager,
}

pub async fn run_shell<H>(session: &SharedSessionHandle<H>, options: ShellOptions) -> Result<()>
where
    H: russh::client::Handler + Send,
{
    let mut channel = session.channel_open_session().await?;
    if options.forward_agent {
        channel.agent_forward(false).await?;
    }
    options.forwarding.prepare_channel(&channel).await?;
    let (cols, rows) = term_size().unwrap_or((80, 24));
    let pty_modes = current_pty_modes();
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
    let mut detached_stdin = false;

    let mut esc = EscapeParser::default();

    loop {
        tokio::select! {
            maybe_event = rx.recv() => {
                match maybe_event {
                    Some(InputEvent::Data(data)) => {
                        if detached_stdin || data.is_empty() { continue; }

                        let (actions, forwarded) = esc.process(&data);

                        for action in actions {
                            match action {
                                EscapeAction::Disconnect => {
                                    // Immediate disconnect requested by user.
                                    let _ = session.disconnect(russh::Disconnect::ByApplication, "user disconnect", "").await;
                                    return Ok(());
                                }
                                EscapeAction::Rekey => {
                                    let _ = session.rekey_soon().await;
                                    let _ = io::stdout().write_all(format!("\r\n{} rekey requested\r\n", tag()).as_bytes());
                                    let _ = io::stdout().flush();
                                }
                                EscapeAction::Break => {
                                    // Not supported by russh as a dedicated request; inform the user.
                                    let _ = io::stdout().write_all(format!("\r\n{} BREAK not supported by client\r\n", tag()).as_bytes());
                                    let _ = io::stdout().flush();
                                }
                                EscapeAction::VerbosityUp => {
                                    if let Some(level) = logging::increase_verbosity() {
                                        let _ = io::stdout().write_all(format!("\r\n{} log level -> {level}\r\n", tag()).as_bytes());
                                        let _ = io::stdout().flush();
                                    }
                                }
                                EscapeAction::VerbosityDown => {
                                    if let Some(level) = logging::decrease_verbosity() {
                                        let _ = io::stdout().write_all(format!("\r\n{} log level -> {level}\r\n", tag()).as_bytes());
                                        let _ = io::stdout().flush();
                                    }
                                }
                                EscapeAction::Suspend => {
                                    #[cfg(unix)]
                                    unsafe {
                                        libc::kill(libc::getpid(), libc::SIGSTOP);
                                    }
                                    #[cfg(not(unix))]
                                    {
                                        let _ = io::stdout().write_all(format!("\r\n{} suspend not supported on this platform\r\n", tag()).as_bytes());
                                        let _ = io::stdout().flush();
                                    }
                                }
                                EscapeAction::Background => {
                                    detached_stdin = true;
                                    let pid = std::process::id();
                                    let _ = io::stdout().write_all(format!("\r\n{} backgrounding: detaching stdin (send SIGUSR1 to PID {} to reattach)\r\n", tag(), pid).as_bytes());
                                    let _ = io::stdout().flush();
                                }
                                EscapeAction::ListForwards => {
                                    let mut lines = Vec::new();
                                    lines.push(format!("\r\n{} active forwards:", tag()));
                                    for d in options.forwarding.descriptors() {
                                        lines.push(format!("  - {d}"));
                                    }
                                    if lines.len() == 1 { lines.push("  (none)".into()); }
                                    let msg = lines.join("\r\n");
                                    let _ = io::stdout().write_all(msg.as_bytes());
                                    let _ = io::stdout().write_all(b"\r\n");
                                    let _ = io::stdout().flush();
                                }
                                EscapeAction::ShowMenu => {
                                    let msg = escape_help_text();
                                    let _ = io::stdout().write_all(msg.as_bytes());
                                    let _ = io::stdout().write_all(format!("\r\n\r\n{} escape> ", tag()).as_bytes());
                                    let _ = io::stdout().flush();
                                }
                                EscapeAction::LiteralTilde => {
                                    // handled by forwarded bytes below
                                }
                            }
                        }

                        if !forwarded.is_empty() {
                            let (printable, signals) = partition_signals(&forwarded);
                            for signal in signals {
                                channel.signal(signal).await?;
                            }
                            if !printable.is_empty() {
                                let mapped = map_input(&printable, options.newline_mode);
                                if options.local_echo {
                                    let _ = io::stdout().write_all(&mapped);
                                    let _ = io::stdout().flush();
                                }
                                let mut cursor = Cursor::new(mapped);
                                channel.data(&mut cursor).await?;
                            }
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
                        #[cfg(unix)]
                        if code == signal_hook::consts::SIGCONT {
                            esc.at_line_start = true;
                        }
                        #[cfg(unix)]
                        if code == signal_hook::consts::SIGUSR1 && detached_stdin {
                            detached_stdin = false;
                            let _ = io::stdout().write_all(format!("\r\n{} stdin reattached\r\n", tag()).as_bytes());
                            let _ = io::stdout().flush();
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
            if let Ok(size) = term_size()
                && size != last_size
            {
                last_size = size;
                if tx.send(InputEvent::Resize(size.0, size.1)).is_err() {
                    break;
                }
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
            #[cfg(unix)]
            signal_hook::consts::SIGCONT,
            #[cfg(unix)]
            signal_hook::consts::SIGUSR1,
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

#[derive(Default)]
struct EscapeParser {
    at_line_start: bool,
    in_escape: bool,
    escape: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EscapeAction {
    Disconnect,
    Break,
    Rekey,
    VerbosityUp,
    VerbosityDown,
    Suspend,
    Background,
    ListForwards,
    LiteralTilde,
    ShowMenu,
}

impl Default for EscapeAction {
    fn default() -> Self { EscapeAction::LiteralTilde }
}

impl EscapeParser {
    fn default() -> Self {
        Self { at_line_start: true, in_escape: false, escape: b'~' }
    }

    fn process(&mut self, data: &[u8]) -> (Vec<EscapeAction>, Vec<u8>) {
        let mut actions = Vec::new();
        let mut out = Vec::with_capacity(data.len());
        for &b in data {
            if self.in_escape {
                // Interpret second byte
                self.in_escape = false;
                match b {
                    b'.' => actions.push(EscapeAction::Disconnect),
                    b'B' | b'b' => actions.push(EscapeAction::Break),
                    b'R' | b'r' => actions.push(EscapeAction::Rekey),
                    b'V' => actions.push(EscapeAction::VerbosityUp),
                    b'v' => actions.push(EscapeAction::VerbosityDown),
                    0x1A => actions.push(EscapeAction::Suspend), // ^Z
                    b'&' => actions.push(EscapeAction::Background),
                    b'#' => actions.push(EscapeAction::ListForwards),
                    b'h' => actions.push(EscapeAction::ShowMenu),
                    x if x == self.escape => {
                        out.push(self.escape);
                        actions.push(EscapeAction::LiteralTilde);
                        self.at_line_start = false;
                    }
                    _ => {
                        // Unknown: ignore and stay at line start
                    }
                }
                // After an escape command, we're still considered at line start
                self.at_line_start = true;
                continue;
            }

            if self.at_line_start && b == self.escape {
                self.in_escape = true;
                actions.push(EscapeAction::ShowMenu);
                continue;
            }

            out.push(b);
            // Track line start state
            self.at_line_start = matches!(b, b'\n' | b'\r');
        }
        (actions, out)
    }
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

fn tag() -> &'static str { "\x1b[97;41m [rustybridge] \x1b[0m" }

fn escape_help_text() -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!("\r\n{} escape commands (type at start of line):", tag()));
    lines.push("  ~.   Disconnect now".into());
    lines.push("  ~R   Rekey (trigger key exchange)".into());
    lines.push("  ~V   Increase client verbosity".into());
    lines.push("  ~v   Decrease client verbosity".into());
    lines.push("  ~&   Background client (detach stdin)".into());
    lines.push("  ~#   List active forwards".into());
    lines.push("  ~~   Send a literal ~".into());
    lines.push("  ~^Z  Suspend (Unix only)".into());
    lines.join("\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_at_line_start_disconnect_and_literal() {
        let mut p = EscapeParser::default();
        let (actions, out) = p.process(b"~.");
        assert!(out.is_empty());
        assert!(actions.iter().any(|a| matches!(a, EscapeAction::Disconnect)));

        // literal ~~ should output a single ~ and not produce actions (other than LiteralTilde)
        let (actions2, out2) = p.process(b"~~x\n");
        assert_eq!(out2, b"~x\n");
        assert!(actions2.iter().any(|a| matches!(a, EscapeAction::LiteralTilde)));
    }

    #[test]
    fn escape_only_at_line_start() {
        let mut p = EscapeParser::default();
        let (_a1, out1) = p.process(b"abc");
        assert_eq!(out1, b"abc");
        // Not at line start, so '~R' should pass through
        let (a2, out2) = p.process(b"~R\n");
        assert!(a2.is_empty());
        assert_eq!(out2, b"~R\n");
        // Now at line start; '~#' triggers action
        let (a3, out3) = p.process(b"~#");
        assert!(out3.is_empty());
        assert!(a3.iter().any(|a| matches!(a, EscapeAction::ListForwards)));
    }
}
