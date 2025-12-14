use super::utils::{clear_line, draw_segment};
use ratatui::{
    Frame,
    layout::{Constraint, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
};

impl super::ManagementApp {
    pub fn render_command_line(&self, frame: &mut Frame, area: Rect, commands: &str) {
        let buffer = frame.buffer_mut();
        clear_line(buffer, area);
        // Allow disabling dynamic footer to minimize diffs during troubleshooting
        if std::env::var("RB_TUI_NO_FOOTER")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
        {
            return;
        }
        let col = 0;
        // Only render the static command help here; flash lives on the dedicated status row.
        let _ = draw_segment(buffer, area, col, commands, Style::default().fg(Color::DarkGray));
    }

    pub fn render_relay_hosts(&mut self, frame: &mut Frame, area: Rect) {
        let header_cells = ["ID", "Name", "Endpoint", "Credential", "Hostkey"]
            .iter()
            .map(|h| Cell::from(*h).style(Style::default().fg(Color::White)));
        let header = Row::new(header_cells)
            .style(Style::default().bg(Color::DarkGray))
            .height(1)
            .bottom_margin(1);

        let rows = self.relay_hosts.iter().map(|item| {
            let cells = vec![
                Cell::from(item.id.to_string()),
                Cell::from(item.name.clone()),
                Cell::from(item.description.clone()),
                Cell::from(self.relay_host_creds.get(&item.id).cloned().unwrap_or_else(|| "<none>".to_string())),
                Cell::from(if *self.relay_host_hostkeys.get(&item.id).unwrap_or(&false) {
                    "yes"
                } else {
                    "no"
                }),
            ];
            Row::new(cells).height(1)
        });

        // Fix widths so Credential doesn't get pushed to the far right by a growing Endpoint column
        let t = Table::new(
            rows,
            [
                Constraint::Length(5),  // ID
                Constraint::Length(20), // Name
                Constraint::Length(24), // Endpoint
                Constraint::Length(20), // Credential
                Constraint::Length(9),  // Hostkey
            ],
        )
        .header(header)
        .block(Block::default().borders(Borders::ALL).title("Relay Hosts"))
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));

        frame.render_stateful_widget(t, area, &mut self.table_state);
    }

    pub fn render_credentials(&mut self, frame: &mut Frame, area: Rect) {
        let header_cells = ["ID", "Name", "Kind", "Assigned"]
            .iter()
            .map(|h| Cell::from(*h).style(Style::default().fg(Color::White)));
        let header = Row::new(header_cells)
            .style(Style::default().bg(Color::DarkGray))
            .height(1)
            .bottom_margin(1);

        let rows = self.credentials.iter().map(|c| {
            Row::new(vec![
                Cell::from(c.id.to_string()),
                Cell::from(c.name.clone()),
                Cell::from(c.kind.clone()),
                Cell::from(c.assigned.to_string()),
            ])
        });

        let t = Table::new(
            rows,
            [
                Constraint::Length(5),
                Constraint::Length(24),
                Constraint::Length(12),
                Constraint::Length(9),
            ],
        )
        .header(header)
        .block(Block::default().borders(Borders::ALL).title("Credentials"))
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));
        frame.render_stateful_widget(t, area, &mut self.creds_state);
    }

    pub fn render_options(&self) -> Paragraph<'static> {
        Paragraph::new("Global Options (Coming Soon)").block(Block::default().borders(Borders::ALL).title("Options"))
    }

    pub fn render_stats(&self) -> Paragraph<'static> {
        Paragraph::new("Server Statistics (Coming Soon)").block(Block::default().borders(Borders::ALL).title("Stats"))
    }
}
