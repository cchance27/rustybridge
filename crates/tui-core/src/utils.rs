use ratatui::layout::{Constraint, Direction, Layout, Rect};
use std::time::Duration;

pub fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    let hours = secs / 3600;
    let mins = (secs % 3600) / 60;
    let secs = secs % 60;
    if hours > 0 {
        format!("{:02}:{:02}:{:02}", hours, mins, secs)
    } else {
        format!("{:02}:{:02}", mins, secs)
    }
}

pub fn desired_rect(size: (u16, u16)) -> ratatui::layout::Rect {
    ratatui::layout::Rect::new(0, 0, size.0, size.1)
}

/// Helper function to create a centered rect using up certain percentage of the available rect `r`
pub fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Percentage((100 - percent_y) / 2),
                Constraint::Percentage(percent_y),
                Constraint::Percentage((100 - percent_y) / 2),
            ]
            .as_ref(),
        )
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Percentage((100 - percent_x) / 2),
                Constraint::Percentage(percent_x),
                Constraint::Percentage((100 - percent_x) / 2),
            ]
            .as_ref(),
        )
        .split(popup_layout[1])[1]
}

/// Build a lightweight escape sequence that updates only the status-bar timer at the bottom right.
pub fn status_tick_sequence(_size: (u16, u16), connected_for: std::time::Duration) -> Option<Vec<u8>> {
    // We ignore the passed size because it might be stale (e.g. 80x24 default) while the terminal is larger.
    // Instead, we use absolute positioning to target the bottom-right corner.

    let uptime_str = format!("Connected: {}", format_duration(connected_for));
    let len = uptime_str.len();

    use std::fmt::Write;
    let mut buffer = String::new();
    // Save cursor (\x1b[s)
    // Move to absolute bottom-right (\x1b[999;999H)
    // Move left by string length (\x1b[<len>D)
    // Print string
    // Restore cursor (\x1b[u)
    let _ = write!(&mut buffer, "\x1b[s\x1b[999;999H\x1b[{}D{}\x1b[u", len, uptime_str);
    Some(buffer.into_bytes())
}
