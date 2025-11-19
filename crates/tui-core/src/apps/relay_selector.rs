use std::fmt;

use ratatui::Frame;

use crate::{AppAction, TuiApp, TuiResult, widgets::Menu};

/// Represents a relay host option in the menu
#[derive(Clone, Debug)]
pub struct RelayItem {
    pub name: String,
    pub description: String,
    pub id: i64,
}

impl fmt::Display for RelayItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:<20} {}", self.name, self.description)
    }
}

/// App for selecting a relay host to connect to
pub struct RelaySelectorApp {
    menu: Menu<RelayItem>,
    should_exit: bool,
    selected_relay: Option<RelayItem>,
    is_admin: bool,
}

impl RelaySelectorApp {
    pub fn new(relays: Vec<RelayItem>) -> Self {
        Self {
            menu: Menu::new("Select Relay Host", relays),
            should_exit: false,
            selected_relay: None,
            is_admin: false,
        }
    }

    pub fn new_for_admin(relays: Vec<RelayItem>) -> Self {
        Self {
            menu: Menu::new("Select Relay Host", relays),
            should_exit: false,
            selected_relay: None,
            is_admin: true,
        }
    }

    pub fn selected_relay(&self) -> Option<&RelayItem> {
        self.selected_relay.as_ref()
    }
}

impl TuiApp for RelaySelectorApp {
    fn handle_input(&mut self, input: &[u8]) -> TuiResult<AppAction> {
        for &byte in input {
            match byte {
                b'q' | 0x03 => {
                    // q or Ctrl+C
                    return Ok(AppAction::Exit);
                }
                b'\r' | b'\n' => {
                    // Enter
                    if let Some(item) = self.menu.selected_item() {
                        self.selected_relay = Some(item.clone());
                        return Ok(AppAction::ConnectToRelay {
                            id: item.id,
                            name: item.name.clone(),
                        });
                    }
                    return Ok(AppAction::Render);
                }
                b'm' => {
                    // Only admins can access management
                    if self.is_admin {
                        return Ok(AppAction::SwitchTo("Management".into()));
                    }
                }
                0x1b => {
                    // If this is a standalone escape (not followed by [), treat as exit
                    if input.len() == 1 {
                        return Ok(AppAction::Exit);
                    }
                }
                b'j' => {
                    self.menu.next();
                    return Ok(AppAction::Render);
                }
                b'k' => {
                    self.menu.previous();
                    return Ok(AppAction::Render);
                }
                _ => {}
            }
        }

        // Handle arrow keys if they appear in the buffer
        if input.len() >= 3 && input[0] == 0x1b && input[1] == b'[' {
            match input[2] {
                b'A' => {
                    // Up
                    self.menu.previous();
                    return Ok(AppAction::Render);
                }
                b'B' => {
                    // Down
                    self.menu.next();
                    return Ok(AppAction::Render);
                }
                _ => {}
            }
        }

        Ok(AppAction::Continue)
    }

    fn render(&mut self, frame: &mut Frame, _uptime: std::time::Duration) {
        let area = frame.area();

        use ratatui::layout::{Constraint, Direction, Layout};
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(1)].as_ref())
            .split(area);

        self.menu.render(frame, chunks[0]);

        use ratatui::{
            style::{Color, Style}, widgets::Paragraph
        };

        let footer_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Min(0), Constraint::Length(25)].as_ref())
            .split(chunks[1]);

        let commands_text = if self.is_admin {
            "j/k: Navigate | Enter: Select | m: Management | q/Esc: Exit"
        } else {
            "j/k: Navigate | Enter: Select | q/Esc: Exit"
        };
        let commands = Paragraph::new(commands_text).style(Style::default().fg(Color::DarkGray));
        frame.render_widget(commands, footer_chunks[0]);

        // We let the server's tick_task handle the status update to avoid conflicts/overwriting.
        // By not rendering to footer_chunks[1], ratatui should leave it alone after the initial clear.
    }

    fn should_exit(&self) -> bool {
        self.should_exit
    }

    fn name(&self) -> &str {
        "RelaySelector"
    }
}
