//! Status bar widget for TUI apps

use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

/// A status bar widget showing left, center, and right aligned text
pub struct StatusBar {
    left: String,
    center: String,
    right: String,
}

impl StatusBar {
    /// Create a new status bar
    pub fn new(left: impl Into<String>, center: impl Into<String>, right: impl Into<String>) -> Self {
        Self {
            left: left.into(),
            center: center.into(),
            right: right.into(),
        }
    }

    /// Render the status bar to the given area
    pub fn render(&self, frame: &mut Frame, area: Rect) {
        let width = area.width as usize;
        let left_len = self.left.len();
        let right_len = self.right.len();
        let center_len = self.center.len();

        // Calculate spacing
        let remaining = width.saturating_sub(left_len + right_len);
        let center_padding = remaining.saturating_sub(center_len) / 2;

        // Build line
        let line = vec![
            Span::raw(&self.left),
            Span::raw(" ".repeat(center_padding)),
            Span::raw(&self.center),
            Span::raw(" ".repeat(center_padding)),
            Span::raw(&self.right),
        ];

        let paragraph = Paragraph::new(Line::from(line)).style(Style::default().bg(Color::DarkGray).fg(Color::White));

        frame.render_widget(paragraph, area);
    }
}
