use std::{collections::HashMap, time::Duration};

use ratatui::{
    Frame, layout::{Constraint, Direction, Layout}, style::{Color, Modifier, Style}, text::{Line, Span}, widgets::{Block, Borders, Clear, Paragraph, TableState, Tabs}
};
use rb_types::relay::HostkeyReview;

use super::types::{CredentialItem, PopupState};
use crate::{
    AppAction, TuiApp, TuiResult, app::{StatusKind, StatusLine}, apps::relay_selector::RelayItem
};

/// Admin management interface
pub struct ManagementApp {
    pub tabs: Vec<String>,
    pub selected_tab: usize,
    pub should_exit: bool,
    // Cache for relay hosts
    pub relay_hosts: Vec<RelayItem>,
    pub relay_host_creds: HashMap<i64, String>,
    pub relay_host_hostkeys: HashMap<i64, bool>,
    pub table_state: TableState,
    pub popup: PopupState,
    pub credentials: Vec<CredentialItem>,
    pub creds_state: TableState,
    pub status: Option<StatusLine>,
}

impl ManagementApp {
    /// Create a new ManagementApp with pre-loaded relay hosts
    pub fn new(
        relay_hosts: Vec<RelayItem>,
        relay_host_creds: HashMap<i64, String>,
        relay_host_hostkeys: HashMap<i64, bool>,
        credentials: Vec<CredentialItem>,
        status: Option<StatusLine>,
        hostkey_review: Option<HostkeyReview>,
    ) -> Self {
        let mut table_state = TableState::default();
        if !relay_hosts.is_empty() {
            table_state.select(Some(0));
        }
        let mut creds_state = TableState::default();
        if !credentials.is_empty() {
            creds_state.select(Some(0));
        }
        let popup = if let Some(r) = hostkey_review {
            PopupState::HostkeyReview(r)
        } else {
            PopupState::None
        };
        Self {
            tabs: vec![
                "Relay Hosts".to_string(),
                "Credentials".to_string(),
                "Options".to_string(),
                "Server Stats".to_string(),
            ],
            selected_tab: 0,
            should_exit: false,
            relay_hosts,
            relay_host_creds,
            relay_host_hostkeys,
            table_state,
            popup,
            credentials,
            creds_state,
            status,
        }
    }

    pub fn with_selected_tab(mut self, idx: usize) -> Self {
        if !self.tabs.is_empty() {
            self.selected_tab = idx.min(self.tabs.len() - 1);
        }
        self
    }

    /// Prefer to keep the currently selected relay host by name after reloads
    pub fn with_selected_host_name(mut self, name: &str) -> Self {
        if let Some(i) = self.relay_hosts.iter().position(|h| h.name == name) {
            self.table_state.select(Some(i));
        }
        self
    }

    /// Prefer to keep the currently selected credential by name after reloads
    pub fn with_selected_cred_name(mut self, name: &str) -> Self {
        if let Some(i) = self.credentials.iter().position(|c| c.name == name) {
            self.creds_state.select(Some(i));
        }
        self
    }
}

impl Default for ManagementApp {
    fn default() -> Self {
        Self::new(Vec::new(), HashMap::new(), HashMap::new(), Vec::new(), None, None)
    }
}

impl TuiApp for ManagementApp {
    fn set_status(&mut self, status: Option<StatusLine>) {
        self.status = status;
    }

    fn handle_input(&mut self, input: &[u8]) -> TuiResult<AppAction> {
        self.handle_input(input)
    }

    fn render(&mut self, frame: &mut Frame, _uptime: Duration) {
        let area = frame.area();

        // Build layout with a fixed flash row to ensure stable height and visibility
        let layout = vec![
            Constraint::Length(3), // tabs
            Constraint::Min(0),    // content
            Constraint::Length(1), // commands
            Constraint::Length(1), // flash (always present to avoid layout shifts)
        ];
        let chunks = Layout::default().direction(Direction::Vertical).constraints(layout).split(area);

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
            .highlight_style(Style::default().add_modifier(Modifier::BOLD).bg(Color::Black));
        frame.render_widget(tabs, chunks[0]);

        match self.selected_tab {
            0 => {
                self.render_relay_hosts(frame, chunks[1]);
            }
            1 => {
                self.render_credentials(frame, chunks[1]);
            }
            2 => {
                let w = self.render_options();
                frame.render_widget(w, chunks[1]);
            }
            3 => {
                let w = self.render_stats();
                frame.render_widget(w, chunks[1]);
            }
            _ => unreachable!(),
        }

        // Dynamic commands: include 'c: Set/Clear Credential' on Relay Hosts depending on state
        let command_text = match self.selected_tab {
            0 => {
                let mut text = "Tab/Arrows: Switch Tab | j/k: Navigate | a: Add | e: Edit | d: Delete".to_string();
                if let Some(sel) = self.table_state.selected()
                    && let Some(h) = self.relay_hosts.get(sel)
                {
                    let label = self.relay_host_creds.get(&h.id).cloned().unwrap_or_else(|| "<none>".to_string());
                    if label == "<none>" {
                        text.push_str(" | c: Set Credential");
                    } else if label != "<custom>" {
                        text.push_str(" | c: Clear Credential");
                    }
                    text.push_str(" | h: Hostkey");
                }
                text.push_str(" | r: Relay Selector | q/Esc: Exit");
                text
            }
            1 => "Tab/Arrows: Switch Tab | j/k: Navigate | a: Add | d: Delete | r: Relay Selector | q/Esc: Exit".to_string(),
            _ => "Tab/Arrows: Switch Tab | r: Relay Selector | q/Esc: Exit".to_string(),
        };
        // Commands on the row above the flash
        let cmd_chunk = chunks[chunks.len() - 2];
        self.render_command_line(frame, cmd_chunk, &command_text);

        // Status row (always rendered, empty when no status)
        let flash_chunk = chunks[chunks.len() - 1];
        frame.render_widget(Clear, flash_chunk);
        if let Some(st) = &self.status {
            let color = match st.kind {
                StatusKind::Info => Color::Yellow,
                StatusKind::Success => Color::Green,
                StatusKind::Error => Color::Red,
            };
            let p = Paragraph::new(st.text.clone()).style(Style::default().fg(color));
            frame.render_widget(p, flash_chunk);
        }

        // Render Popup
        self.render_popup(frame, area);

        // Leave status until explicitly changed
    }

    fn should_exit(&self) -> bool {
        self.should_exit
    }

    fn name(&self) -> &str {
        "Management"
    }
}
