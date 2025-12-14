use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

/// A text input widget with a prompt
#[derive(Clone)]
pub struct Input {
    prompt: String,
    value: String,
    /// Cursor position in characters within `value` (0..=len)
    cursor: usize,
}

impl Input {
    pub fn new(prompt: impl Into<String>) -> Self {
        Self {
            prompt: prompt.into(),
            value: String::new(),
            cursor: 0,
        }
    }

    pub fn with_value(mut self, value: impl Into<String>) -> Self {
        self.value = value.into();
        self.cursor = self.value.chars().count();
        self
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    pub fn push_char(&mut self, ch: char) {
        let idx = char_to_byte_idx(&self.value, self.cursor);
        self.value.insert(idx, ch);
        self.cursor = (self.cursor + 1).min(self.value.chars().count());
    }

    pub fn pop_char(&mut self) -> Option<char> {
        // Backspace behavior (remove before cursor)
        if self.cursor == 0 {
            return None;
        }
        let removed = remove_char_at(&mut self.value, self.cursor - 1);
        if removed.is_some() {
            self.cursor -= 1;
        }
        removed
    }

    /// Delete character at the cursor (if any)
    pub fn delete_char(&mut self) -> Option<char> {
        remove_char_at(&mut self.value, self.cursor)
    }

    pub fn move_left(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
        }
    }

    pub fn move_right(&mut self) {
        let len = self.value.chars().count();
        if self.cursor < len {
            self.cursor += 1;
        }
    }

    pub fn move_home(&mut self) {
        self.cursor = 0;
    }

    pub fn move_end(&mut self) {
        self.cursor = self.value.chars().count();
    }

    pub fn clear(&mut self) -> String {
        self.cursor = 0;
        std::mem::take(&mut self.value)
    }

    pub fn render(&self, frame: &mut Frame, area: Rect, show_cursor: bool) {
        if area.width == 0 {
            return;
        }
        let prompt_chars = self.prompt.chars().count();
        let cursor_in_full = prompt_chars + self.cursor;
        let full_prompt = format!("{}{}", self.prompt, self.value);
        let (display, cursor_col) = visible_prompt_line(&full_prompt, area.width as usize, cursor_in_full);
        let prompt_line = Line::from(Span::styled(display, Style::default().fg(Color::Yellow)));
        frame.render_widget(Paragraph::new(prompt_line), area);

        if show_cursor {
            let cursor_x = area.x + cursor_col as u16;
            frame.set_cursor_position(ratatui::layout::Position {
                x: cursor_x.min(area.x + area.width.saturating_sub(1)),
                y: area.y,
            });
        }
    }
}

/// Return the visible prompt substring along with where the cursor should land.
/// `cursor_full` is the cursor column in characters within `full`.
fn visible_prompt_line(full: &str, max_width: usize, cursor_full: usize) -> (String, usize) {
    if max_width == 0 {
        return (String::new(), 0);
    }

    let total_chars = full.chars().count();
    let mut start = 0usize;
    if total_chars > max_width {
        // Scroll so that cursor is visible, biasing to place it at the right edge
        start = cursor_full.saturating_sub(max_width.saturating_sub(1));
        if start + max_width > total_chars {
            start = total_chars - max_width;
        }
    }
    let mut visible: String = full.chars().skip(start).take(max_width).collect();
    if start > 0 && !visible.is_empty() {
        let mut chars: Vec<char> = visible.chars().collect();
        chars[0] = '…';
        visible = chars.into_iter().collect();
    }
    let cursor = cursor_full.saturating_sub(start).min(max_width);
    (visible, cursor)
}

fn char_to_byte_idx(s: &str, char_idx: usize) -> usize {
    if char_idx == 0 {
        return 0;
    }
    for (count, (i, _)) in s.char_indices().enumerate() {
        if count == char_idx {
            return i;
        }
    }
    s.len()
}

fn remove_char_at(s: &mut String, char_idx: usize) -> Option<char> {
    for (count, (i, ch)) in s.char_indices().enumerate() {
        if count == char_idx {
            let start = i;
            let end = i + ch.len_utf8();
            s.replace_range(start..end, "");
            return Some(ch);
        }
    }
    None
}
