use ratatui::{
    Frame, layout::Rect, style::{Color, Style}, text::{Line, Span}, widgets::Paragraph
};

/// A text input widget with a prompt
pub struct Input {
    prompt: String,
    value: String,
}

impl Input {
    pub fn new(prompt: impl Into<String>) -> Self {
        Self {
            prompt: prompt.into(),
            value: String::new(),
        }
    }

    pub fn with_value(mut self, value: impl Into<String>) -> Self {
        self.value = value.into();
        self
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    pub fn push_char(&mut self, ch: char) {
        self.value.push(ch);
    }

    pub fn pop_char(&mut self) -> Option<char> {
        self.value.pop()
    }

    pub fn clear(&mut self) -> String {
        std::mem::take(&mut self.value)
    }

    pub fn render(&self, frame: &mut Frame, area: Rect) {
        if area.width == 0 {
            return;
        }
        let full_prompt = format!("{}{}", self.prompt, self.value);
        let (display, cursor_col) = visible_prompt_line(&full_prompt, area.width as usize);
        let prompt_line = Line::from(Span::styled(display, Style::default().fg(Color::Yellow)));
        frame.render_widget(Paragraph::new(prompt_line), area);

        let cursor_x = area.x + cursor_col as u16;
        frame.set_cursor_position(ratatui::layout::Position {
            x: cursor_x.min(area.x + area.width.saturating_sub(1)),
            y: area.y,
        });
    }
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
