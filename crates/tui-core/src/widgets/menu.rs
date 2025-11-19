use ratatui::{
    Frame, layout::Rect, style::{Color, Modifier, Style}, text::{Line, Span}, widgets::{Block, Borders, List, ListItem, ListState}
};

/// A generic menu widget for selecting items from a list
pub struct Menu<T> {
    items: Vec<T>,
    state: ListState,
    title: String,
}

impl<T> Menu<T> {
    pub fn new(title: impl Into<String>, items: Vec<T>) -> Self {
        let mut state = ListState::default();
        if !items.is_empty() {
            state.select(Some(0));
        }
        Self {
            items,
            state,
            title: title.into(),
        }
    }

    pub fn items(&self) -> &[T] {
        &self.items
    }

    pub fn selected_index(&self) -> Option<usize> {
        self.state.selected()
    }

    pub fn selected_item(&self) -> Option<&T> {
        self.state.selected().and_then(|i| self.items.get(i))
    }

    pub fn next(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i >= self.items.len().saturating_sub(1) {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }

    pub fn previous(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i == 0 {
                    self.items.len().saturating_sub(1)
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }
}

impl<T: std::fmt::Display> Menu<T> {
    pub fn render(&mut self, frame: &mut Frame, area: Rect) {
        let items: Vec<ListItem> = self
            .items
            .iter()
            .map(|i| {
                let line = Line::from(Span::raw(format!(" {} ", i)));
                ListItem::new(line)
            })
            .collect();

        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(self.title.as_str()))
            .highlight_style(Style::default().bg(Color::Blue).fg(Color::White).add_modifier(Modifier::BOLD))
            .highlight_symbol("> ");

        frame.render_stateful_widget(list, area, &mut self.state);
    }
}
