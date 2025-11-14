use std::env;

use clap::ValueEnum;
use russh::Pty;

#[derive(Clone, Copy, Debug, ValueEnum, Default)]
pub enum NewlineMode {
    #[default]
    Lf,
    Cr,
    CrLf,
}

pub fn newline_mode_from_env() -> Option<NewlineMode> {
    if let Ok(mode) = env::var("LSSH_NL") {
        match mode.to_ascii_lowercase().as_str() {
            "cr" => return Some(NewlineMode::Cr),
            "crlf" => return Some(NewlineMode::CrLf),
            "lf" => return Some(NewlineMode::Lf),
            _ => {}
        }
    }

    if env::var("LSSH_CRLF").map(|v| v != "0").unwrap_or(false) {
        Some(NewlineMode::CrLf)
    } else {
        None
    }
}

pub fn map_input(data: &[u8], mode: NewlineMode) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() * 2);
    for &b in data {
        match mode {
            NewlineMode::CrLf if b == b'\r' || b == b'\n' => {
                out.push(b'\r');
                out.push(b'\n');
            }
            NewlineMode::Cr if b == b'\r' || b == b'\n' => out.push(b'\r'),
            _ => out.push(b),
        }
    }
    out
}

/// Return a reasonable default set of terminal mode flags/characters for remote PTYs.
pub fn default_pty_modes() -> Vec<(Pty, u32)> {
    const CTRL_C: u32 = 0x03;
    const CTRL_BACKSLASH: u32 = 0x1c;
    const CTRL_D: u32 = 0x04;
    const CTRL_Q: u32 = 0x11;
    const CTRL_S: u32 = 0x13;
    const CTRL_Z: u32 = 0x1a;
    const CTRL_R: u32 = 0x12;
    const CTRL_W: u32 = 0x17;
    const CTRL_V: u32 = 0x16;
    const CTRL_O: u32 = 0x0f;
    const CTRL_U: u32 = 0x15;
    const BACKSPACE: u32 = 0x7f;
    const DEFAULT_SPEED: u32 = 38400;

    let mut modes = Vec::new();

    modes.push((Pty::VINTR, CTRL_C));
    modes.push((Pty::VQUIT, CTRL_BACKSLASH));
    modes.push((Pty::VERASE, BACKSPACE));
    modes.push((Pty::VKILL, CTRL_U));
    modes.push((Pty::VEOF, CTRL_D));
    modes.push((Pty::VSTART, CTRL_Q));
    modes.push((Pty::VSTOP, CTRL_S));
    modes.push((Pty::VSUSP, CTRL_Z));
    modes.push((Pty::VREPRINT, CTRL_R));
    modes.push((Pty::VWERASE, CTRL_W));
    modes.push((Pty::VLNEXT, CTRL_V));
    modes.push((Pty::VDISCARD, CTRL_O));

    modes.push((Pty::ISIG, 1));
    modes.push((Pty::ICANON, 1));
    modes.push((Pty::ECHO, 1));
    modes.push((Pty::ECHOE, 1));
    modes.push((Pty::ECHOK, 1));
    modes.push((Pty::ECHOCTL, 1));
    modes.push((Pty::IEXTEN, 1));
    modes.push((Pty::IXON, 1));
    modes.push((Pty::IXOFF, 0));
    modes.push((Pty::INPCK, 0));
    modes.push((Pty::ISTRIP, 0));
    modes.push((Pty::ICRNL, 1));
    modes.push((Pty::IGNCR, 0));
    modes.push((Pty::IMAXBEL, 1));
    modes.push((Pty::OPOST, 1));
    modes.push((Pty::ONLCR, 1));
    modes.push((Pty::OCRNL, 0));
    modes.push((Pty::ONOCR, 0));
    modes.push((Pty::ONLRET, 0));
    modes.push((Pty::CS8, 1));
    modes.push((Pty::PARENB, 0));
    modes.push((Pty::PARODD, 0));
    modes.push((Pty::TTY_OP_OSPEED, DEFAULT_SPEED));
    modes.push((Pty::TTY_OP_ISPEED, DEFAULT_SPEED));
    modes
}
