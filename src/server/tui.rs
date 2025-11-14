//! Stateless widgets and helpers that describe the embedded echo TUI.

use std::collections::VecDeque;
use std::fmt::Write as FmtWrite;
use std::time::Duration;

use ratatui::Frame;
use ratatui::layout::{Alignment, Position, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};

pub(super) const HELLO_BANNER: &str = r"
▄▖▄▖▖▖
▚ ▚ ▙▌
▄▌▄▌▌▌";
pub(super) const INSTRUCTIONS: &str =
    "Type anything to have it echoed back, or 'exit' to disconnect.";
const PROMPT: &str = "echo> ";
const MAX_LOG_LINES: usize = 512;
const STATUS_HEIGHT: u16 = 3;
const STATUS_MESSAGE: &str = "Echo session ready";

/// Minimal line-buffered echo UI that knows how to draw itself with ratatui.
pub(super) struct EchoTui {
    lines: VecDeque<String>,
    input: String,
}

impl EchoTui {
    /// Build a TUI pre-populated with the hello banner and usage instructions.
    pub(super) fn with_default_messages() -> Self {
        let mut tui = Self {
            lines: VecDeque::new(),
            input: String::new(),
        };
        tui.push_multiline(HELLO_BANNER);
        tui.push_multiline(INSTRUCTIONS);
        tui
    }

    /// Push a log line, trimming the oldest entries when we hit the cap.
    pub(super) fn push_line<S: Into<String>>(&mut self, line: S) {
        if self.lines.len() == MAX_LOG_LINES {
            self.lines.pop_front();
        }
        self.lines.push_back(line.into());
    }

    /// Push each line from the provided string, making it easy to display ASCII art.
    pub(super) fn push_multiline(&mut self, text: &str) {
        let mut pushed = false;
        for line in text.lines() {
            pushed = true;
            self.push_line(line);
        }
        if !pushed || text.ends_with('\n') {
            self.push_line("");
        }
    }

    /// Append a printable character to the input buffer.
    pub(super) fn push_char(&mut self, ch: char) -> bool {
        if ch.is_control() {
            return false;
        }
        self.input.push(ch);
        true
    }

    /// Remove the most recent character from the input buffer.
    pub(super) fn pop_char(&mut self) -> bool {
        self.input.pop().is_some()
    }

    /// Take ownership of the buffered input, clearing the prompt.
    pub(super) fn take_input(&mut self) -> String {
        std::mem::take(&mut self.input)
    }

    /// Render the log region, status bar, and prompt into the provided frame.
    pub(super) fn render(&self, frame: &mut Frame, connected_for: Duration) {
        let area = frame.area();
        if area.width == 0 || area.height == 0 {
            return;
        }

        let status_height = status_height_for(area.height);
        if status_height > 0 {
            let status_area = Rect::new(area.x, area.y, area.width, status_height);
            self.render_status_bar(frame, status_area, connected_for);
        }

        if area.height <= status_height {
            return;
        }

        let content_area = Rect::new(
            area.x,
            area.y + status_height,
            area.width,
            area.height - status_height,
        );
        let prompt_row = content_area.height.saturating_sub(1);
        if prompt_row > 0 {
            let log_area = Rect::new(
                content_area.x,
                content_area.y,
                content_area.width,
                prompt_row,
            );
            let rows = prompt_row as usize;
            let lines = self.visible_lines(rows);
            let log = Paragraph::new(Text::from(lines)).wrap(Wrap { trim: false });
            frame.render_widget(log, log_area);
        }

        let prompt_area = Rect::new(
            content_area.x,
            content_area.y + prompt_row,
            content_area.width,
            1,
        );
        if prompt_area.width == 0 {
            return;
        }
        let full_prompt = format!("{PROMPT}{}", self.input);
        let (display, cursor_col) = visible_prompt_line(&full_prompt, prompt_area.width as usize);
        let prompt_line = Line::from(Span::styled(display, Style::default().fg(Color::Yellow)));
        frame.render_widget(Paragraph::new(prompt_line), prompt_area);
        let cursor_x = prompt_area.x + cursor_col as u16;
        frame.set_cursor_position(Position {
            x: cursor_x.min(prompt_area.x + prompt_area.width.saturating_sub(1)),
            y: prompt_area.y,
        });
    }

    /// Render a bordered status bar and reserve space for the server-driven timer.
    fn render_status_bar(&self, frame: &mut Frame, area: Rect, connected_for: Duration) {
        if area.width == 0 || area.height == 0 {
            return;
        }

        frame.render_widget(Clear, area);
        if area.height < 3 || area.width < 3 {
            let status_line = Line::from(vec![
                Span::styled(STATUS_MESSAGE, Style::default().fg(Color::Green)),
                Span::raw(" "),
                Span::styled(
                    format!("connected {}", format_duration(connected_for)),
                    Style::default().fg(Color::Cyan),
                ),
            ]);
            frame.render_widget(Paragraph::new(status_line), area);
            return;
        }

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray));
        frame.render_widget(block.clone(), area);

        let inner = block.inner(area);
        if inner.width == 0 || inner.height == 0 {
            return;
        }
        frame.render_widget(Clear, inner);
        let status_line = Line::from(Span::styled(
            STATUS_MESSAGE,
            Style::default().fg(Color::Green),
        ));
        frame.render_widget(
            Paragraph::new(status_line).alignment(Alignment::Left),
            inner,
        );

        let timer_line = Line::from(Span::styled(
            format!("connected {}", format_duration(connected_for)),
            Style::default().fg(Color::Cyan),
        ));
        frame.render_widget(
            Paragraph::new(timer_line).alignment(Alignment::Right),
            inner,
        );
    }

    fn visible_lines(&self, rows: usize) -> Vec<Line<'static>> {
        let rows = rows.max(1);
        let start = self.lines.len().saturating_sub(rows);
        self.lines
            .iter()
            .skip(start)
            .map(|line| Line::from(line.clone()))
            .collect()
    }
}

/// Convert a raw PTY size into a ratatui `Rect` (ensuring the size is never zero).
pub(super) fn desired_rect(size: (u16, u16)) -> Rect {
    Rect::new(0, 0, size.0.max(1), size.1.max(1))
}

/// Return the visible prompt substring along with where the cursor should land.
fn visible_prompt_line(full: &str, max_width: usize) -> (String, usize) {
    if max_width == 0 {
        return (String::new(), 0);
    }

    let total_chars = full.chars().count();
    let skip = total_chars.saturating_sub(max_width);
    let mut visible: String = full.chars().skip(skip).collect();

    if skip > 0 && !visible.is_empty() {
        let mut chars: Vec<char> = visible.chars().collect();
        chars[0] = '…';
        visible = chars.into_iter().collect();
    }

    let cursor = (total_chars - skip).min(max_width);
    (visible, cursor)
}

/// Format a duration as HH:MM:SS for the status bar.
fn format_duration(duration: Duration) -> String {
    let total_seconds = duration.as_secs();
    let hours = total_seconds / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;
    format!("{hours:02}:{minutes:02}:{seconds:02}")
}

/// Build a lightweight escape sequence that updates only the status-bar timer.
pub(super) fn status_tick_sequence(size: (u16, u16), connected_for: Duration) -> Option<Vec<u8>> {
    let (width, height) = size;
    if width < 3 || height < 3 {
        return None;
    }

    let status_height = status_height_for(height);
    if status_height < 3 {
        return None;
    }

    let inner_width = width.saturating_sub(2);
    if inner_width == 0 {
        return None;
    }

    let uptime_full = format!("connected {}", format_duration(connected_for));
    if uptime_full.is_empty() {
        return None;
    }

    let chars: Vec<char> = uptime_full.chars().collect();
    let timer_width = chars.len().min(inner_width as usize);
    if timer_width == 0 {
        return None;
    }

    let timer_width_u16 = timer_width as u16;
    let display: String = chars[chars.len() - timer_width..].iter().collect();
    let timer_row = 1u16; // inner area starts at y=1
    let inner_left = 1u16;
    let timer_col = inner_left + inner_width - timer_width_u16;
    let blanks = " ".repeat(timer_width);

    let mut buffer = String::new();
    let _ = write!(
        &mut buffer,
        "\x1b[s\x1b[{};{}H{}",
        timer_row + 1,
        timer_col + 1,
        blanks
    );
    let _ = write!(
        &mut buffer,
        "\x1b[{};{}H{}",
        timer_row + 1,
        timer_col + 1,
        display
    );
    buffer.push_str("\x1b[u");
    Some(buffer.into_bytes())
}

fn status_height_for(total_height: u16) -> u16 {
    if total_height == 0 {
        return 0;
    }
    let reserved_for_prompt = total_height.min(1);
    let available = total_height.saturating_sub(reserved_for_prompt);
    STATUS_HEIGHT.min(available)
}
