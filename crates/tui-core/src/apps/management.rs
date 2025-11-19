use ratatui::{
    Frame, layout::{Constraint, Direction, Layout, Rect}, style::{Color, Modifier, Style}, text::{Line, Span}, widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Tabs, Wrap}
};

use crate::{AppAction, TuiApp, TuiResult, apps::relay_selector::RelayItem, utils::centered_rect, widgets::input::Input};

#[derive(Clone)]
struct HostForm {
    name: Input,
    description: Input,
    error: Option<String>,
}

impl HostForm {
    fn new() -> Self {
        Self {
            name: Input::new("Name: "),
            description: Input::new("Endpoint (IP:Port): "),
            error: None,
        }
    }

    fn from_relay(relay: &RelayItem) -> Self {
        Self {
            name: Input::new("Name: ").with_value(&relay.name),
            description: Input::new("Endpoint (IP:Port): ").with_value(&relay.description),
            error: None,
        }
    }
}

enum PopupState {
    None,
    AddHost(HostForm, usize),       // usize tracks which field is focused (0=name, 1=desc)
    EditHost(HostForm, usize, i64), // i64 is the ID of the host being edited
    DeleteConfirm(i64, String),     // ID and Name of host to delete
}

/// Admin management interface
pub struct ManagementApp {
    tabs: Vec<String>,
    selected_tab: usize,
    should_exit: bool,
    // Cache for relay hosts
    relay_hosts: Vec<RelayItem>,
    table_state: TableState,
    popup: PopupState,
}

impl ManagementApp {
    /// Create a new ManagementApp with pre-loaded relay hosts
    pub fn new(relay_hosts: Vec<RelayItem>) -> Self {
        let mut table_state = TableState::default();
        if !relay_hosts.is_empty() {
            table_state.select(Some(0));
        }
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
            table_state,
            popup: PopupState::None,
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

    fn next_row(&mut self) {
        if self.relay_hosts.is_empty() {
            return;
        }
        let i = match self.table_state.selected() {
            Some(i) => {
                if i >= self.relay_hosts.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    fn previous_row(&mut self) {
        if self.relay_hosts.is_empty() {
            return;
        }
        let i = match self.table_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.relay_hosts.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    fn open_add_popup(&mut self) {
        self.popup = PopupState::AddHost(HostForm::new(), 0);
    }

    fn open_edit_popup(&mut self) {
        if let Some(selected) = self.table_state.selected()
            && let Some(host) = self.relay_hosts.get(selected) {
                self.popup = PopupState::EditHost(HostForm::from_relay(host), 0, host.id);
            }
    }

    fn open_delete_popup(&mut self) {
        if let Some(selected) = self.table_state.selected()
            && let Some(host) = self.relay_hosts.get(selected) {
                self.popup = PopupState::DeleteConfirm(host.id, host.name.clone());
            }
    }

    fn close_popup(&mut self) {
        self.popup = PopupState::None;
    }
}

impl Default for ManagementApp {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

impl TuiApp for ManagementApp {
    fn handle_input(&mut self, input: &[u8]) -> TuiResult<AppAction> {
        tracing::trace!("ManagementApp input: {:?}", input);

        // Helper for form input handling
        enum FormAction {
            Continue,
            Render,
            Submit,
            Cancel,
        }

        fn handle_form_input(form: &mut HostForm, focus: &mut usize, input: &[u8]) -> FormAction {
            let mut i = 0;
            let mut render = false;
            while i < input.len() {
                let byte = input[i];
                i += 1;
                match byte {
                    0x1b => {
                        if i < input.len() && input[i] == b'[' {
                            // Handle CSI
                            i += 1;
                            if i < input.len() {
                                let code = input[i];
                                i += 1;
                                match code {
                                    b'A' => {
                                        // Up -> previous field
                                        *focus = if *focus > 0 { *focus - 1 } else { 1 };
                                        render = true;
                                    }
                                    b'B' => {
                                        // Down -> next field
                                        *focus = (*focus + 1) % 2;
                                        render = true;
                                    }
                                    b'C' => {
                                        // Right
                                        match *focus {
                                            0 => form.name.move_right(),
                                            1 => form.description.move_right(),
                                            _ => {}
                                        }
                                        render = true;
                                    }
                                    b'D' => {
                                        // Left
                                        match *focus {
                                            0 => form.name.move_left(),
                                            1 => form.description.move_left(),
                                            _ => {}
                                        }
                                        render = true;
                                    }
                                    b'H' => {
                                        // Home
                                        match *focus {
                                            0 => form.name.move_home(),
                                            1 => form.description.move_home(),
                                            _ => {}
                                        }
                                        render = true;
                                    }
                                    b'F' => {
                                        // End
                                        match *focus {
                                            0 => form.name.move_end(),
                                            1 => form.description.move_end(),
                                            _ => {}
                                        }
                                        render = true;
                                    }
                                    b'3' => {
                                        // Delete key sequence: expect '~'
                                        if i < input.len() && input[i] == b'~' {
                                            i += 1;
                                        }
                                        match *focus {
                                            0 => {
                                                let _ = form.name.delete_char();
                                            }
                                            1 => {
                                                let _ = form.description.delete_char();
                                            }
                                            _ => {}
                                        }
                                        render = true;
                                    }
                                    b'5' => {
                                        // PageUp -> previous field, expect '~'
                                        if i < input.len() && input[i] == b'~' {
                                            i += 1;
                                        }
                                        *focus = focus.saturating_sub(1);
                                        if *focus > 1 {
                                            *focus = 1;
                                        }
                                        render = true;
                                    }
                                    b'6' => {
                                        // PageDown -> next field, expect '~'
                                        if i < input.len() && input[i] == b'~' {
                                            i += 1;
                                        }
                                        *focus = (*focus + 1) % 2;
                                        render = true;
                                    }
                                    _ => {}
                                }
                            }
                        } else {
                            return FormAction::Cancel;
                        }
                    }
                    b'\t' => {
                        *focus = (*focus + 1) % 2;
                        render = true;
                    }
                    b'\r' | b'\n' => {
                        return FormAction::Submit;
                    }
                    0x7f | 0x08 => {
                        match *focus {
                            0 => {
                                let _ = form.name.pop_char();
                            }
                            1 => {
                                let _ = form.description.pop_char();
                            }
                            _ => {}
                        }
                        render = true;
                    }
                    c if (32..=126).contains(&c) => {
                        let char = c as char;
                        match *focus {
                            0 => form.name.push_char(char),
                            1 => form.description.push_char(char),
                            _ => {}
                        }
                        render = true;
                    }
                    _ => {}
                }
            }
            if render { FormAction::Render } else { FormAction::Continue }
        }

        // Handle Popup Input
        match &mut self.popup {
            PopupState::AddHost(form, focus) => {
                match handle_form_input(form, focus, input) {
                    FormAction::Cancel => {
                        self.close_popup();
                        return Ok(AppAction::Render);
                    }
                    FormAction::Submit => {
                        // Validate inputs
                        let name = form.name.value().trim();
                        let endpoint = form.description.value().trim();
                        if name.is_empty() || endpoint.is_empty() {
                            form.error = Some("Name and endpoint are required".to_string());
                            return Ok(AppAction::Render);
                        }
                        if let Some((host, port_str)) = endpoint.rsplit_once(':') {
                            if host.is_empty() || port_str.parse::<u16>().ok().filter(|p| *p > 0).is_none() {
                                form.error = Some("Endpoint must be host:port with a valid port".to_string());
                                return Ok(AppAction::Render);
                            }
                        } else {
                            form.error = Some("Endpoint must include ':' and port".to_string());
                            return Ok(AppAction::Render);
                        }

                        form.error = None;
                        let new_host = RelayItem {
                            name: name.to_string(),
                            description: endpoint.to_string(),
                            id: 0,
                        };
                        self.close_popup();
                        return Ok(AppAction::AddRelay(new_host));
                    }
                    FormAction::Render => return Ok(AppAction::Render),
                    FormAction::Continue => return Ok(AppAction::Continue),
                }
            }
            PopupState::EditHost(form, focus, id) => {
                match handle_form_input(form, focus, input) {
                    FormAction::Cancel => {
                        self.close_popup();
                        return Ok(AppAction::Render);
                    }
                    FormAction::Submit => {
                        // Validate inputs
                        let name = form.name.value().trim();
                        let endpoint = form.description.value().trim();
                        if name.is_empty() || endpoint.is_empty() {
                            form.error = Some("Name and endpoint are required".to_string());
                            return Ok(AppAction::Render);
                        }
                        if let Some((host, port_str)) = endpoint.rsplit_once(':') {
                            if host.is_empty() || port_str.parse::<u16>().ok().filter(|p| *p > 0).is_none() {
                                form.error = Some("Endpoint must be host:port with a valid port".to_string());
                                return Ok(AppAction::Render);
                            }
                        } else {
                            form.error = Some("Endpoint must include ':' and port".to_string());
                            return Ok(AppAction::Render);
                        }

                        form.error = None;
                        let updated_host = RelayItem {
                            name: name.to_string(),
                            description: endpoint.to_string(),
                            id: *id,
                        };
                        self.close_popup();
                        return Ok(AppAction::UpdateRelay(updated_host));
                    }
                    FormAction::Render => return Ok(AppAction::Render),
                    FormAction::Continue => return Ok(AppAction::Continue),
                }
            }
            PopupState::DeleteConfirm(id, _) => {
                for &byte in input {
                    match byte {
                        b'y' | b'Y' | b'\r' | b'\n' => {
                            let id_to_delete = *id;
                            self.close_popup();
                            return Ok(AppAction::DeleteRelay(id_to_delete));
                        }
                        b'n' | b'N' | 0x1b => {
                            self.close_popup();
                            return Ok(AppAction::Render);
                        }
                        _ => {}
                    }
                }
                return Ok(AppAction::Continue);
            }
            PopupState::None => {}
        }

        // Handle Main Input
        for &byte in input {
            match byte {
                b'q' | 0x03 => {
                    // q or Ctrl+C
                    return Ok(AppAction::Exit);
                }
                b'\t' => {
                    // Tab
                    self.next_tab();
                    return Ok(AppAction::Render);
                }
                b'r' => {
                    return Ok(AppAction::SwitchTo("RelaySelector".into()));
                }
                b'a' => {
                    if self.selected_tab == 0 {
                        self.open_add_popup();
                        return Ok(AppAction::Render);
                    }
                }
                b'e' => {
                    if self.selected_tab == 0 {
                        self.open_edit_popup();
                        return Ok(AppAction::Render);
                    }
                }
                b'd' => {
                    if self.selected_tab == 0 {
                        self.open_delete_popup();
                        return Ok(AppAction::Render);
                    }
                }
                0x1b => {
                    if input.len() == 1 {
                        return Ok(AppAction::Exit);
                    }
                }
                b'j' => {
                    if self.selected_tab == 0 {
                        self.next_row();
                        return Ok(AppAction::Render);
                    }
                }
                b'k' => {
                    if self.selected_tab == 0 {
                        self.previous_row();
                        return Ok(AppAction::Render);
                    }
                }
                _ => {}
            }
        }

        // Handle arrow keys
        if input.len() >= 3 && input[0] == 0x1b && input[1] == b'[' {
            match input[2] {
                b'C' => {
                    // Right
                    self.next_tab();
                    return Ok(AppAction::Render);
                }
                b'D' => {
                    // Left
                    self.previous_tab();
                    return Ok(AppAction::Render);
                }
                b'A' => {
                    // Up
                    if self.selected_tab == 0 {
                        self.previous_row();
                        return Ok(AppAction::Render);
                    }
                }
                b'B' => {
                    // Down
                    if self.selected_tab == 0 {
                        self.next_row();
                        return Ok(AppAction::Render);
                    }
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
            .highlight_style(Style::default().add_modifier(Modifier::BOLD).bg(Color::Black));
        frame.render_widget(tabs, chunks[0]);

        let inner = match self.selected_tab {
            0 => {
                self.render_relay_hosts(frame, chunks[1]);
                None
            }
            1 => Some(self.render_credentials()),
            2 => Some(self.render_options()),
            3 => Some(self.render_stats()),
            _ => unreachable!(),
        };

        if let Some(widget) = inner {
            frame.render_widget(widget, chunks[1]);
        }

        let commands = if self.selected_tab == 0 {
            Paragraph::new("Tab/Arrows: Switch Tab | j/k: Navigate | a: Add | e: Edit | d: Delete | r: Relay Selector | q/Esc: Exit")
                .style(Style::default().fg(Color::DarkGray))
        } else {
            Paragraph::new("Tab/Arrows: Switch Tab | r: Relay Selector | q/Esc: Exit").style(Style::default().fg(Color::DarkGray))
        };
        frame.render_widget(commands, chunks[2]);

        // Render Popup
        self.render_popup(frame, area);
    }

    fn should_exit(&self) -> bool {
        self.should_exit
    }

    fn name(&self) -> &str {
        "Management"
    }
}

impl ManagementApp {
    fn render_relay_hosts(&mut self, frame: &mut Frame, area: Rect) {
        let header_cells = ["ID", "Name", "Endpoint"]
            .iter()
            .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow)));
        let header = Row::new(header_cells)
            .style(Style::default().bg(Color::Blue))
            .height(1)
            .bottom_margin(1);

        let rows = self.relay_hosts.iter().map(|item| {
            let cells = vec![
                Cell::from(item.id.to_string()),
                Cell::from(item.name.clone()),
                Cell::from(item.description.clone()),
            ];
            Row::new(cells).height(1)
        });

        let t = Table::new(rows, [Constraint::Length(5), Constraint::Length(20), Constraint::Min(10)])
            .header(header)
            .block(Block::default().borders(Borders::ALL).title("Relay Hosts"))
            .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));

        frame.render_stateful_widget(t, area, &mut self.table_state);
    }

    fn render_credentials(&self) -> Paragraph<'static> {
        Paragraph::new("Credentials Management (Coming Soon)").block(Block::default().borders(Borders::ALL).title("Credentials"))
    }

    fn render_options(&self) -> Paragraph<'static> {
        Paragraph::new("Global Options (Coming Soon)").block(Block::default().borders(Borders::ALL).title("Options"))
    }

    fn render_stats(&self) -> Paragraph<'static> {
        Paragraph::new("Server Statistics (Coming Soon)").block(Block::default().borders(Borders::ALL).title("Stats"))
    }

    fn render_popup(&self, frame: &mut Frame, area: Rect) {
        match &self.popup {
            PopupState::None => {}
            PopupState::AddHost(form, focus) => {
                let block = Block::default().title("Add Relay Host").borders(Borders::ALL);
                let area = centered_rect(60, 40, area);
                frame.render_widget(Clear, area);
                frame.render_widget(block, area);

                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .margin(2)
                    .constraints(
                        [
                            Constraint::Length(3),
                            Constraint::Length(3),
                            Constraint::Length(1),
                            Constraint::Min(1),
                        ]
                        .as_ref(),
                    )
                    .split(area);

                form.name.render(frame, chunks[0], *focus == 0);
                form.description.render(frame, chunks[1], *focus == 1);

                // Error line (if any)
                if let Some(err) = &form.error {
                    let err_p = Paragraph::new(err.as_str()).style(Style::default().fg(Color::Red));
                    frame.render_widget(err_p, chunks[2]);
                }

                // Draw focus indicator
                // Since Input::render handles the cursor, I might not need to do much else.
                // But I want to highlight the active field.
                // I can draw a block around them?
                // Or just rely on the cursor.

                let instructions =
                    Paragraph::new("Tab/Up/Down: Switch Field | Left/Right/Home/End: Move Cursor | Enter: Submit | Esc: Cancel")
                        .style(Style::default().fg(Color::DarkGray));
                frame.render_widget(instructions, chunks[3]);
            }
            PopupState::EditHost(form, focus, _id) => {
                let block = Block::default().title("Edit Relay Host").borders(Borders::ALL);
                let area = centered_rect(60, 40, area);
                frame.render_widget(Clear, area);
                frame.render_widget(block, area);

                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .margin(2)
                    .constraints(
                        [
                            Constraint::Length(3),
                            Constraint::Length(3),
                            Constraint::Length(1),
                            Constraint::Min(1),
                        ]
                        .as_ref(),
                    )
                    .split(area);

                form.name.render(frame, chunks[0], *focus == 0);
                form.description.render(frame, chunks[1], *focus == 1);

                // Error line (if any)
                if let Some(err) = &form.error {
                    let err_p = Paragraph::new(err.as_str()).style(Style::default().fg(Color::Red));
                    frame.render_widget(err_p, chunks[2]);
                }

                let instructions =
                    Paragraph::new("Tab/Up/Down: Switch Field | Left/Right/Home/End: Move Cursor | Enter: Save | Esc: Cancel")
                        .style(Style::default().fg(Color::DarkGray));
                frame.render_widget(instructions, chunks[3]);
            }
            PopupState::DeleteConfirm(_id, name) => {
                let block = Block::default()
                    .title("Confirm Delete")
                    .borders(Borders::ALL)
                    .style(Style::default().fg(Color::Red));
                let area = centered_rect(40, 20, area);
                frame.render_widget(Clear, area);
                frame.render_widget(block, area);

                let text = format!("Are you sure you want to delete '{}'?", name);
                let p = Paragraph::new(text)
                    .wrap(Wrap { trim: true })
                    .alignment(ratatui::layout::Alignment::Center);

                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .margin(2)
                    .constraints([Constraint::Min(1), Constraint::Length(1)].as_ref())
                    .split(area);

                frame.render_widget(p, chunks[0]);

                let instructions = Paragraph::new("y/Enter: Yes | n/Esc: No")
                    .alignment(ratatui::layout::Alignment::Center)
                    .style(Style::default().fg(Color::DarkGray));
                frame.render_widget(instructions, chunks[1]);
            }
        }
    }
}
