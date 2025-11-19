use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// Map a crossterm KeyEvent into canonical TUI byte sequences.
/// Make sure we map these in crates/tui-core/src/input.rs as well.
/// Returns None for keys we don't handle.
pub fn map_key_to_bytes(key: &KeyEvent) -> Option<Vec<u8>> {
    // Ctrl+C
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        if let KeyCode::Char('c' | 'C') = key.code {
            return Some(vec![0x03]);
        }
    }

    let bytes: Option<Vec<u8>> = match key.code {
        KeyCode::Char(c) => {
            let mut tmp = [0u8; 4];
            let s = c.encode_utf8(&mut tmp);
            Some(s.as_bytes().to_vec())
        }
        KeyCode::Enter => Some(tui_core::input::ENTER.to_vec()),
        KeyCode::Esc => Some(tui_core::input::ESC.to_vec()),
        KeyCode::Tab => Some(tui_core::input::TAB.to_vec()),
        KeyCode::Up => Some(tui_core::input::ARROW_UP.to_vec()),
        KeyCode::Down => Some(tui_core::input::ARROW_DOWN.to_vec()),
        KeyCode::Right => Some(tui_core::input::ARROW_RIGHT.to_vec()),
        KeyCode::Left => Some(tui_core::input::ARROW_LEFT.to_vec()),
        KeyCode::Backspace => Some(tui_core::input::BACKSPACE.to_vec()),
        KeyCode::Delete => Some(tui_core::input::BACKSPACE.to_vec()),
        KeyCode::Home => Some(tui_core::input::HOME.to_vec()),
        KeyCode::End => Some(tui_core::input::END.to_vec()),
        KeyCode::PageUp => Some(tui_core::input::PAGE_UP.to_vec()),
        KeyCode::PageDown => Some(tui_core::input::PAGE_DOWN.to_vec()),
        _ => None,
    };

    // Ensure canonicalization (for any edge cases)
    bytes.map(|b| tui_core::input::canonicalize(&b))
}
