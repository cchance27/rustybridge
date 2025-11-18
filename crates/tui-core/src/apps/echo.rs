//! Echo TUI app - simple line-buffered echo application
//!
//! Migrated from server-core/src/tui.rs

use std::time::{Duration, Instant};
use ratatui::{
    Frame,
    layout::Rect,
};
use crate::{
    TuiApp, TuiResult, RE_RENDER, CONTINUE,
    widgets::{Input, ScrollableLog, StatusBar},
};

pub const HELLO_BANNER: &str = r"
▄▖▄▖▖▖
▚ ▚ ▙▌
▄▌▄▌▌▌";
pub const INSTRUCTIONS: &str = "Type anything to have it echoed back, or 'exit' to disconnect.";
const PROMPT: &str = "echo> ";
const MAX_LOG_LINES: usize = 512;
const STATUS_HEIGHT: u16 = 3;
const STATUS_MESSAGE: &str = "Echo session ready";

/// Simple echo application that displays user input
pub struct EchoApp {
    log: ScrollableLog,
    input: Input,
    should_exit: bool,
    started_at: Instant,
    last_tick: Instant,
}

impl EchoApp {
    /// Create a new echo app with a welcome message
    pub fn new() -> Self {
        let mut log = ScrollableLog::new(MAX_LOG_LINES);
        log.push_multiline(HELLO_BANNER);
        log.push_multiline(INSTRUCTIONS);
        
        Self {
            log,
            input: Input::new(PROMPT),
            should_exit: false,
            started_at: Instant::now(),
            last_tick: Instant::now(),
        }
    }
}

impl Default for EchoApp {
    fn default() -> Self {
        Self::new()
    }
}

impl TuiApp for EchoApp {
    fn handle_input(&mut self, input: &[u8]) -> TuiResult<bool> {
        for &byte in input {
            match byte {
                b'\r' | b'\n' => {
                    let line = self.input.clear();
                    if line == "exit" {
                        self.should_exit = true;
                    } else {
                        self.log.push_line(format!("{}{}", PROMPT, line));
                    }
                }
                0x7f | 0x08 => {
                    // Backspace
                    self.input.pop_char();
                }
                b if b.is_ascii() && !b.is_ascii_control() => {
                    self.input.push_char(b as char);
                }
                _ => {}
            }
        }
        Ok(RE_RENDER)
    }
    
    fn render(&self, frame: &mut Frame) {
        let area = frame.area();
        if area.width == 0 || area.height == 0 {
            return;
        }

        let status_height = status_height_for(area.height);
        
        if status_height > 0 {
            let status_area = Rect::new(area.x, area.y, area.width, status_height);
            let connected_for = self.started_at.elapsed();
            let _status = StatusBar::new(
                STATUS_MESSAGE,
                "",
                format!("connected {}", format_duration(connected_for))
            );
            // TODO: Actually use StatusBar _status
            // Note: StatusBar widget currently doesn't support borders/styling exactly like EchoTui
            // We might want to enhance StatusBar or just use custom rendering here if strict parity is needed.
            // For now, let's use custom rendering to match EchoTui exactly.
            // TODO: Remove this once StatusBar supports borders/styling exactly like EchoTui
            self.render_status_bar(frame, status_area, connected_for);
        }

        if area.height <= status_height {
            return;
        }

        let content_area = Rect::new(area.x, area.y + status_height, area.width, area.height - status_height);
        let prompt_row = content_area.height.saturating_sub(1);
        
        if prompt_row > 0 {
            let log_area = Rect::new(content_area.x, content_area.y, content_area.width, prompt_row);
            self.log.render(frame, log_area);
        }

        let prompt_area = Rect::new(content_area.x, content_area.y + prompt_row, content_area.width, 1);
        self.input.render(frame, prompt_area);
    }
    
    fn tick(&mut self) -> TuiResult<bool> {
        let now = Instant::now();
        if now.duration_since(self.last_tick) >= Duration::from_secs(1) {
            self.last_tick = now;
            Ok(RE_RENDER)
        } else {
            Ok(CONTINUE)
        }
    }
    
    fn should_exit(&self) -> bool {
        self.should_exit
    }
    
    fn name(&self) -> &str {
        "Echo"
    }
}

impl EchoApp {
    fn render_status_bar(&self, frame: &mut Frame, area: Rect, connected_for: Duration) {
        use ratatui::{
            widgets::{Block, Borders, Paragraph, Clear},
            style::{Style, Color},
            text::{Span, Line},
            layout::Alignment,
        };

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
        let status_line = Line::from(Span::styled(STATUS_MESSAGE, Style::default().fg(Color::Green)));
        frame.render_widget(Paragraph::new(status_line).alignment(Alignment::Left), inner);

        let timer_line = Line::from(Span::styled(
            format!("connected {}", format_duration(connected_for)),
            Style::default().fg(Color::Cyan),
        ));
        frame.render_widget(Paragraph::new(timer_line).alignment(Alignment::Right), inner);
    }
}

fn status_height_for(total_height: u16) -> u16 {
    if total_height == 0 {
        return 0;
    }
    let reserved_for_prompt = total_height.min(1);
    let available = total_height.saturating_sub(reserved_for_prompt);
    STATUS_HEIGHT.min(available)
}

fn format_duration(duration: Duration) -> String {
    let total_seconds = duration.as_secs();
    let hours = total_seconds / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;
    format!("{hours:02}:{minutes:02}:{seconds:02}")
}

/// Build a lightweight escape sequence that updates only the status-bar timer.
pub fn status_tick_sequence(size: (u16, u16), connected_for: Duration) -> Option<Vec<u8>> {
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

    use std::fmt::Write;
    let mut buffer = String::new();
    let _ = write!(&mut buffer, "\x1b[s\x1b[{};{}H{}", timer_row + 1, timer_col + 1, blanks);
    let _ = write!(&mut buffer, "\x1b[{};{}H{}", timer_row + 1, timer_col + 1, display);
    buffer.push_str("\x1b[u");
    Some(buffer.into_bytes())
}

/// Convert a raw PTY size into a ratatui `Rect` (ensuring the size is never zero).
pub fn desired_rect(size: (u16, u16)) -> Rect {
    Rect::new(0, 0, size.0.max(1), size.1.max(1))
}
