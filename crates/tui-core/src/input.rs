//! Input normalization and canonical sequences for TUI apps.
//!
//! This module defines canonical byte sequences for common keys and provides
//! normalization utilities to make input handling consistent between local and
//! remote (SSH) environments.
//!
//! Make sure we map these in crates/rb-cli/src/tui_input.rs as well.

/// Canonical byte for Enter. We normalize to carriage return (\r).
pub const ENTER: &[u8] = b"\r";
/// Canonical byte for Escape key.
pub const ESC: &[u8] = &[0x1b];
/// Canonical byte for Tab.
pub const TAB: &[u8] = b"\t";
/// Canonical byte for Backspace (we normalize 0x08 to 0x7f).
pub const BACKSPACE: &[u8] = &[0x7f];

/// Arrow key sequences (ANSI CSI)
pub const ARROW_UP: &[u8] = &[0x1b, b'[', b'A'];
pub const ARROW_DOWN: &[u8] = &[0x1b, b'[', b'B'];
pub const ARROW_RIGHT: &[u8] = &[0x1b, b'[', b'C'];
pub const ARROW_LEFT: &[u8] = &[0x1b, b'[', b'D'];

/// Delete key sequence (ANSI CSI 3~). We normalize it to BACKSPACE by default.
pub const DELETE_SEQ: &[u8] = &[0x1b, b'[', b'3', b'~'];

/// Home/End canonical sequences
pub const HOME: &[u8] = &[0x1b, b'[', b'H'];
pub const END: &[u8] = &[0x1b, b'[', b'F'];

/// PageUp/PageDown canonical sequences (CSI 5~ and 6~)
pub const PAGE_UP: &[u8] = &[0x1b, b'[', b'5', b'~'];
pub const PAGE_DOWN: &[u8] = &[0x1b, b'[', b'6', b'~'];

/// Normalize a raw byte buffer into canonical form expected by TUI apps:
/// - Map '\n' (LF) to ENTER ('\r')
/// - Map 0x08 (BS) to BACKSPACE (0x7f)
/// - Map CSI 3~ (Delete) to BACKSPACE
/// - Preserve standard CSI arrow sequences
pub fn canonicalize(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let b = input[i];
        // ESC-based sequences
        if b == 0x1b {
            if i + 1 < input.len() && input[i + 1] == b'[' {
                // CSI sequence
                if i + 2 < input.len() {
                    let code = input[i + 2];
                    // Delete: ESC [ 3 ~
                    if code == b'3' && i + 3 < input.len() && input[i + 3] == b'~' {
                        out.extend_from_slice(BACKSPACE);
                        i += 4;
                        continue;
                    }
                    // PageUp/PageDown: ESC [ 5 ~ / ESC [ 6 ~ (pass through)
                    if (code == b'5' || code == b'6') && i + 3 < input.len() && input[i + 3] == b'~' {
                        let seq = &input[i..i + 4];
                        out.extend_from_slice(seq);
                        i += 4;
                        continue;
                    }
                    // Home/End canonicalization variants:
                    // ESC [ H and ESC [ F (pass through)
                    if code == b'H' || code == b'F' {
                        out.extend_from_slice(&input[i..i + 3]);
                        i += 3;
                        continue;
                    }
                    // ESC [ 1 ~ => HOME
                    if code == b'1' && i + 3 < input.len() && input[i + 3] == b'~' {
                        out.extend_from_slice(HOME);
                        i += 4;
                        continue;
                    }
                    // ESC [ 4 ~ => END
                    if code == b'4' && i + 3 < input.len() && input[i + 3] == b'~' {
                        out.extend_from_slice(END);
                        i += 4;
                        continue;
                    }
                    // Arrow keys we pass through unchanged
                    if code == b'A' || code == b'B' || code == b'C' || code == b'D' {
                        out.extend_from_slice(&input[i..i + 3]);
                        i += 3;
                        continue;
                    }
                }
            } else if i + 1 < input.len() && (input[i + 1] == b'O') {
                // SS3 sequences for Home/End in some terminals: ESC O H / ESC O F
                if i + 2 < input.len() {
                    let code = input[i + 2];
                    if code == b'H' {
                        out.extend_from_slice(HOME);
                        i += 3;
                        continue;
                    } else if code == b'F' {
                        out.extend_from_slice(END);
                        i += 3;
                        continue;
                    }
                }
            }
            // Fallback: pass ESC through
            out.push(b);
            i += 1;
            continue;
        }

        match b {
            b'\n' => out.extend_from_slice(ENTER),
            0x08 => out.extend_from_slice(BACKSPACE),
            _ => out.push(b),
        }
        i += 1;
    }
    out
}
