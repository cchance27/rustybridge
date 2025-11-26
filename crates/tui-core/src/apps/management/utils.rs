use ratatui::{buffer::Buffer, layout::Rect, style::Style};
use unicode_width::UnicodeWidthChar;

pub fn clear_line(buffer: &mut Buffer, area: Rect) {
    for dx in 0..area.width {
        let cell = &mut buffer[(area.x + dx, area.y)];
        cell.reset();
    }
}

pub fn draw_segment(buffer: &mut Buffer, area: Rect, mut col: usize, text: &str, style: Style) -> usize {
    for ch in text.chars() {
        let width = UnicodeWidthChar::width(ch).unwrap_or(0);
        if width == 0 {
            continue;
        }
        if col + width > area.width as usize {
            break;
        }
        let mut utf8 = [0u8; 4];
        let symbol = ch.encode_utf8(&mut utf8);
        let cell = &mut buffer[(area.x + col as u16, area.y)];
        cell.set_symbol(symbol);
        cell.set_style(style);
        if width == 2 {
            if col + 1 >= area.width as usize {
                break;
            }
            let next = &mut buffer[(area.x + col as u16 + 1, area.y)];
            next.set_symbol(" ");
            next.set_style(style);
        }
        col += width;
    }
    col
}
