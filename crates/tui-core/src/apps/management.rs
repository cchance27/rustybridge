use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Tabs},
};
use crate::{TuiApp, TuiResult, AppAction};

/// Admin management interface
pub struct ManagementApp {
    tabs: Vec<String>,
    selected_tab: usize,
    should_exit: bool,
}

impl ManagementApp {
    pub fn new() -> Self {
        Self {
            tabs: vec![
                "Relay Hosts".to_string(),
                "Credentials".to_string(),
                "Options".to_string(),
                "Server Stats".to_string(),
            ],
            selected_tab: 0,
            should_exit: false,
        }
    }

    fn next_tab(&mut self) {
        self.selected_tab = (self.selected_tab + 1) % self.tabs.len();
    }

    fn previous_tab(&mut self) {
        if self.selected_tab > 0 {
            self.selected_tab -= 1;
        } else {
            self.selected_tab = self.tabs.len() - 1;
        }
    }
}

impl Default for ManagementApp {
    fn default() -> Self {
        Self::new()
    }
}

impl TuiApp for ManagementApp {
    fn handle_input(&mut self, input: &[u8]) -> TuiResult<AppAction> {
        for &byte in input {
            match byte {
                b'q' | 0x03 => { // q or Ctrl+C
                    return Ok(AppAction::Exit);
                }
                b'\t' => { // Tab
                    self.next_tab();
                    return Ok(AppAction::Render);
                }
                b'r' => {
                    return Ok(AppAction::SwitchTo("RelaySelector".into()));
                }
                0x1b => {
                    if input.len() == 1 {
                        return Ok(AppAction::Exit);
                    }
                }
                _ => {}
            }
        }
        
        // Handle arrow keys
        if input.len() >= 3 && input[0] == 0x1b && input[1] == b'[' {
            match input[2] {
                b'C' => { // Right
                    self.next_tab();
                    return Ok(AppAction::Render);
                }
                b'D' => { // Left
                    self.previous_tab();
                    return Ok(AppAction::Render);
                }
                _ => {}
            }
        }

        Ok(AppAction::Continue)
    }

    fn render(&mut self, frame: &mut Frame, _uptime: std::time::Duration) {
        let area = frame.area();
        
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(0), Constraint::Length(1)].as_ref())
            .split(area);

        let titles: Vec<Line> = self
            .tabs
            .iter()
            .map(|t| {
                let (first, rest) = t.split_at(1);
                Line::from(vec![
                    Span::styled(first, Style::default().fg(Color::Yellow)),
                    Span::styled(rest, Style::default().fg(Color::Green)),
                ])
            })
            .collect();

        let tabs = Tabs::new(titles)
            .block(Block::default().borders(Borders::ALL).title("Management Console"))
            .select(self.selected_tab)
            .style(Style::default().fg(Color::Cyan))
            .highlight_style(
                Style::default()
                    .add_modifier(Modifier::BOLD)
                    .bg(Color::Black),
            );
        frame.render_widget(tabs, chunks[0]);

        let inner = match self.selected_tab {
            0 => self.render_relay_hosts(),
            1 => self.render_credentials(),
            2 => self.render_options(),
            3 => self.render_stats(),
            _ => unreachable!(),
        };
        frame.render_widget(inner, chunks[1]);


        let footer_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Min(0), Constraint::Length(25)].as_ref())
            .split(chunks[2]);

        let commands = Paragraph::new("Tab/Arrows: Switch Tab | r: Relay Selector | q/Esc: Exit")
            .style(Style::default().fg(Color::DarkGray));
        frame.render_widget(commands, footer_chunks[0]);

        // We let the server's tick_task handle the status update to avoid conflicts/overwriting.
        // By not rendering to footer_chunks[1], ratatui should leave it alone after the initial clear.
    }


    fn should_exit(&self) -> bool {
        self.should_exit
    }

    fn name(&self) -> &str {
        "Management"
    }
}

impl ManagementApp {
    fn render_relay_hosts(&self) -> Paragraph<'static> {
        Paragraph::new("Relay Hosts Management (Coming Soon)")
            .block(Block::default().borders(Borders::ALL).title("Relay Hosts"))
    }

    fn render_credentials(&self) -> Paragraph<'static> {
        Paragraph::new("Credentials Management (Coming Soon)")
            .block(Block::default().borders(Borders::ALL).title("Credentials"))
    }

    fn render_options(&self) -> Paragraph<'static> {
        Paragraph::new("Global Options (Coming Soon)")
            .block(Block::default().borders(Borders::ALL).title("Options"))
    }

    fn render_stats(&self) -> Paragraph<'static> {
        Paragraph::new("Server Statistics (Coming Soon)")
            .block(Block::default().borders(Borders::ALL).title("Stats"))
    }
}
