use std::env;

use clap::ValueEnum;

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
