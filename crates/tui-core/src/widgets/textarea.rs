use ratatui::{
    Frame, layout::Rect, text::{Line, Span, Text}, widgets::{Block, Borders, Paragraph, Wrap}
};

#[derive(Clone)]
pub struct TextArea {
    label: String,
    value: String,
    cursor_row: usize,
    cursor_col: usize,
    scroll_row: usize,
}

impl TextArea {
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            value: String::new(),
            cursor_row: 0,
            cursor_col: 0,
            scroll_row: 0,
        }
    }

    pub fn with_value(mut self, value: impl Into<String>) -> Self {
        self.set_value(value.into());
        self
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    pub fn set_value(&mut self, value: String) {
        self.value = value;
        let lines: Vec<&str> = self.value.split('\n').collect();
        self.cursor_row = lines.len().saturating_sub(1);
        self.cursor_col = lines.last().map(|l| l.chars().count()).unwrap_or(0);
        self.ensure_cursor_visible(usize::MAX);
    }

    pub fn push_char(&mut self, ch: char) {
        let idx = self.char_pos_to_char_index(self.cursor_row, self.cursor_col);
        insert_char_at(&mut self.value, idx, ch);
        self.cursor_col += 1;
    }

    pub fn insert_newline(&mut self) {
        let idx = self.char_pos_to_char_index(self.cursor_row, self.cursor_col);
        insert_char_at(&mut self.value, idx, '\n');
        self.cursor_row += 1;
        self.cursor_col = 0;
    }

    pub fn backspace(&mut self) -> Option<char> {
        if self.cursor_col > 0 {
            let idx = self.char_pos_to_char_index(self.cursor_row, self.cursor_col) - 1;
            let ch = remove_char_at_char_index(&mut self.value, idx)?;
            self.cursor_col -= 1;
            Some(ch)
        } else if self.cursor_row > 0 {
            // Merge with previous line
            let prev_len = self.line_len(self.cursor_row - 1);
            let idx = self.char_pos_to_char_index(self.cursor_row, 0) - 1; // the '\n'
            let ch = remove_char_at_char_index(&mut self.value, idx)?;
            self.cursor_row -= 1;
            self.cursor_col = prev_len;
            Some(ch)
        } else {
            None
        }
    }

    pub fn delete_char(&mut self) -> Option<char> {
        let idx = self.char_pos_to_char_index(self.cursor_row, self.cursor_col);
        remove_char_at_char_index(&mut self.value, idx)
    }

    pub fn move_left(&mut self) {
        if self.cursor_col > 0 {
            self.cursor_col -= 1;
        } else if self.cursor_row > 0 {
            self.cursor_row -= 1;
            self.cursor_col = self.line_len(self.cursor_row);
        }
    }

    pub fn move_right(&mut self) {
        let len = self.line_len(self.cursor_row);
        if self.cursor_col < len {
            self.cursor_col += 1;
        } else {
            // move to next line start if available
            let total_lines = self.line_count();
            if self.cursor_row + 1 < total_lines {
                self.cursor_row += 1;
                self.cursor_col = 0;
            }
        }
    }

    pub fn move_up(&mut self) {
        if self.cursor_row > 0 {
            self.cursor_row -= 1;
        }
        let len = self.line_len(self.cursor_row);
        if self.cursor_col > len {
            self.cursor_col = len;
        }
    }

    pub fn move_down(&mut self) {
        let total_lines = self.line_count();
        if self.cursor_row + 1 < total_lines {
            self.cursor_row += 1;
        }
        let len = self.line_len(self.cursor_row);
        if self.cursor_col > len {
            self.cursor_col = len;
        }
    }

    pub fn move_home(&mut self) {
        self.cursor_col = 0;
    }
    pub fn move_end(&mut self) {
        self.cursor_col = self.line_len(self.cursor_row);
    }

    fn line_len(&self, row: usize) -> usize {
        self.value.split('\n').nth(row).map(|l| l.chars().count()).unwrap_or(0)
    }

    fn line_count(&self) -> usize {
        self.value.split('\n').count()
    }

    fn char_pos_to_char_index(&self, row: usize, col: usize) -> usize {
        // Convert row/col to char index in the whole string
        let mut idx = 0usize;
        for (i, line) in self.value.split('\n').enumerate() {
            if i < row {
                idx += line.chars().count();
                // add newline char except after last line
                idx += 1;
            } else if i == row {
                idx += col.min(line.chars().count());
                break;
            }
        }
        idx
    }

    fn ensure_cursor_visible(&mut self, height: usize) {
        if height == 0 {
            return;
        }
        if self.cursor_row < self.scroll_row {
            self.scroll_row = self.cursor_row;
        } else if self.cursor_row >= self.scroll_row + height {
            self.scroll_row = self.cursor_row + 1 - height;
        }
    }

    pub fn render(&self, frame: &mut Frame, area: Rect, focused: bool) {
        // Draw block with label
        let block = Block::default()
            .borders(Borders::ALL)
            .title(self.label.clone())
            .style(ratatui::style::Style::default().fg(ratatui::style::Color::Yellow));
        frame.render_widget(block.clone(), area);
        let inner = block.inner(area);

        // Compute content height in rows; reserve for cursor visibility, then build lines
        let height_rows = inner.height as usize;
        // Compute desired scroll to keep cursor visible without mutating state
        let mut scroll = self.scroll_row;
        if self.cursor_row < scroll {
            scroll = self.cursor_row;
        } else if self.cursor_row >= scroll + height_rows {
            scroll = self.cursor_row + 1 - height_rows;
        }

        let lines: Vec<Line> = if self.value.is_empty() {
            vec![Line::from("")]
        } else {
            self.value
                .split('\n')
                .map(|s| Line::from(Span::styled(s, ratatui::style::Style::default().fg(ratatui::style::Color::Yellow))))
                .collect()
        };

        let mut p = Paragraph::new(Text::from(lines)).wrap(Wrap { trim: false });
        p = p.scroll((scroll as u16, 0));
        frame.render_widget(p, inner);

        if focused {
            let cursor_y = inner.y + (self.cursor_row.saturating_sub(scroll)) as u16;
            let cursor_x = inner.x + self.cursor_col as u16;
            frame.set_cursor_position(ratatui::layout::Position {
                x: cursor_x.min(inner.x + inner.width.saturating_sub(1)),
                y: cursor_y.min(inner.y + inner.height.saturating_sub(1)),
            });
        }
    }
}

fn insert_char_at(s: &mut String, char_idx: usize, ch: char) {
    if char_idx == 0 {
        s.insert(0, ch);
        return;
    }
    for (count, (i, _)) in s.char_indices().enumerate() {
        if count == char_idx {
            s.insert(i, ch);
            return;
        }
    }
    s.push(ch);
}

fn remove_char_at_char_index(s: &mut String, char_idx: usize) -> Option<char> {
    for (count, (i, ch)) in s.char_indices().enumerate() {
        if count == char_idx {
            let end = i + ch.len_utf8();
            s.replace_range(i..end, "");
            return Some(ch);
        }
    }
    None
}
