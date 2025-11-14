use std::env;
use std::os::fd::AsFd;

use clap::ValueEnum;
use russh::Pty;
use rustix::termios::{
    self, ControlModes, InputModes, LocalModes, OutputModes, SpecialCodeIndex as Sc, Termios,
};
use tracing::warn;

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

/// Read the host terminal settings if possible and convert them into SSH PTY modes.
pub fn current_pty_modes() -> Vec<(Pty, u32)> {
    let stdin = std::io::stdin();
    match termios::tcgetattr(&stdin.as_fd()) {
        Ok(term) => modes_from_termios(&term),
        Err(err) => {
            warn!(?err, "failed to read local termios; falling back to defaults");
            default_pty_modes()
        }
    }
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

fn modes_from_termios(term: &Termios) -> Vec<(Pty, u32)> {
    let mut modes = Vec::new();
    let codes = &term.special_codes;
    push_code(&mut modes, codes[Sc::VINTR] as u32, Pty::VINTR);
    push_code(&mut modes, codes[Sc::VQUIT] as u32, Pty::VQUIT);
    push_code(&mut modes, codes[Sc::VERASE] as u32, Pty::VERASE);
    push_code(&mut modes, codes[Sc::VKILL] as u32, Pty::VKILL);
    push_code(&mut modes, codes[Sc::VEOF] as u32, Pty::VEOF);
    push_code(&mut modes, codes[Sc::VSTART] as u32, Pty::VSTART);
    push_code(&mut modes, codes[Sc::VSTOP] as u32, Pty::VSTOP);
    push_code(&mut modes, codes[Sc::VSUSP] as u32, Pty::VSUSP);
    push_code(&mut modes, codes[Sc::VEOL] as u32, Pty::VEOL);
    push_code(&mut modes, codes[Sc::VEOL2] as u32, Pty::VEOL2);

    #[cfg(not(target_os = "haiku"))]
    {
        push_code(&mut modes, codes[Sc::VREPRINT] as u32, Pty::VREPRINT);
        push_code(&mut modes, codes[Sc::VLNEXT] as u32, Pty::VLNEXT);
    }
    #[cfg(not(any(target_os = "aix", target_os = "haiku")))]
    {
        push_code(&mut modes, codes[Sc::VDISCARD] as u32, Pty::VDISCARD);
        push_code(&mut modes, codes[Sc::VWERASE] as u32, Pty::VWERASE);
    }

    let local = term.local_modes;
    push_flag(&mut modes, local.contains(LocalModes::ISIG), Pty::ISIG);
    push_flag(&mut modes, local.contains(LocalModes::ICANON), Pty::ICANON);
    push_flag(&mut modes, local.contains(LocalModes::ECHO), Pty::ECHO);
    push_flag(&mut modes, local.contains(LocalModes::ECHOE), Pty::ECHOE);
    push_flag(&mut modes, local.contains(LocalModes::ECHOK), Pty::ECHOK);
    push_flag(&mut modes, local.contains(LocalModes::IEXTEN), Pty::IEXTEN);
    #[cfg(not(target_os = "redox"))]
    {
        push_flag(
            &mut modes,
            local.contains(LocalModes::ECHOCTL),
            Pty::ECHOCTL,
        );
    }

    let input = term.input_modes;
    push_flag(&mut modes, input.contains(InputModes::IXON), Pty::IXON);
    push_flag(&mut modes, input.contains(InputModes::IXOFF), Pty::IXOFF);
    push_flag(&mut modes, input.contains(InputModes::IGNPAR), Pty::IGNPAR);
    push_flag(&mut modes, input.contains(InputModes::INPCK), Pty::INPCK);
    push_flag(&mut modes, input.contains(InputModes::ISTRIP), Pty::ISTRIP);
    push_flag(&mut modes, input.contains(InputModes::ICRNL), Pty::ICRNL);
    push_flag(&mut modes, input.contains(InputModes::IGNCR), Pty::IGNCR);
    #[cfg(not(any(target_os = "redox", target_os = "haiku")))]
    {
        push_flag(
            &mut modes,
            input.contains(InputModes::IMAXBEL),
            Pty::IMAXBEL,
        );
    }

    let output = term.output_modes;
    push_flag(&mut modes, output.contains(OutputModes::OPOST), Pty::OPOST);
    push_flag(&mut modes, output.contains(OutputModes::ONLCR), Pty::ONLCR);
    push_flag(&mut modes, output.contains(OutputModes::OCRNL), Pty::OCRNL);
    push_flag(&mut modes, output.contains(OutputModes::ONOCR), Pty::ONOCR);
    push_flag(
        &mut modes,
        output.contains(OutputModes::ONLRET),
        Pty::ONLRET,
    );

    let control = term.control_modes;
    push_flag(
        &mut modes,
        control.contains(ControlModes::PARENB),
        Pty::PARENB,
    );
    push_flag(
        &mut modes,
        control.contains(ControlModes::PARODD),
        Pty::PARODD,
    );
    if control.contains(ControlModes::CS8) {
        modes.push((Pty::CS8, 1));
    } else if control.contains(ControlModes::CS7) {
        modes.push((Pty::CS7, 1));
    }

    modes.push((Pty::TTY_OP_OSPEED, term.output_speed()));
    modes.push((Pty::TTY_OP_ISPEED, term.input_speed()));
    modes
}

fn push_code(modes: &mut Vec<(Pty, u32)>, value: u32, pty: Pty) {
    modes.push((pty, value));
}

fn push_flag(modes: &mut Vec<(Pty, u32)>, enabled: bool, pty: Pty) {
    modes.push((pty, if enabled { 1 } else { 0 }));
}
