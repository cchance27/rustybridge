use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Text},
    widgets::{Paragraph, Wrap},
};
use std::collections::VecDeque;

/// A scrollable log widget that maintains a fixed number of lines
pub struct ScrollableLog {
    lines: VecDeque<String>,
    max_lines: usize,
}

impl ScrollableLog {
    pub fn new(max_lines: usize) -> Self {
        Self {
            lines: VecDeque::new(),
            max_lines,
        }
    }

    pub fn push_line(&mut self, line: impl Into<String>) {
        if self.lines.len() >= self.max_lines {
            self.lines.pop_front();
        }
        self.lines.push_back(line.into());
    }

    pub fn push_multiline(&mut self, text: &str) {
        let mut pushed = false;
        for line in text.lines() {
            pushed = true;
            self.push_line(line);
        }
        if !pushed || text.ends_with('\n') {
            self.push_line("");
        }
    }

    pub fn render(&self, frame: &mut Frame, area: Rect) {
        if area.height == 0 {
            return;
        }
        let rows = area.height as usize;
        let visible_lines = self.visible_lines(rows);
        let log = Paragraph::new(Text::from(visible_lines)).wrap(Wrap { trim: false });
        frame.render_widget(log, area);
    }

    fn visible_lines(&self, rows: usize) -> Vec<Line<'static>> {
        let rows = rows.max(1);
        let start = self.lines.len().saturating_sub(rows);
        self.lines.iter().skip(start).map(|line| Line::from(line.clone())).collect()
    }
}
