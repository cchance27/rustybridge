use std::{collections::HashMap, fmt};

use ratatui::{
    Frame, layout::{Constraint, Direction, Layout, Rect}, style::{Color, Modifier, Style}, text::{Line, Span}, widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Tabs, Wrap}
};

use crate::{
    AppAction, TuiApp, TuiResult, apps::relay_selector::RelayItem, utils::centered_rect, widgets::{Input, Menu, TextArea}
};

// Public types for credentials used by AppAction
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialItem {
    pub id: i64,
    pub name: String,
    pub kind: String,
    pub assigned: i64,
}

impl fmt::Display for CredentialItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:<24} ({})", self.name, self.kind)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialSpec {
    Password {
        name: String,
        username: Option<String>,
        password: String,
    },
    SshKey {
        name: String,
        username: Option<String>,
        key_file: Option<String>,
        value: Option<String>,
        cert_file: Option<String>,
        passphrase: Option<String>,
    },
    Agent {
        name: String,
        username: Option<String>,
        public_key: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum CredentialType {
    Password,
    SshKey,
    Agent,
}

impl CredentialType {
    fn as_str(&self) -> &'static str {
        match self {
            CredentialType::Password => "password",
            CredentialType::SshKey => "ssh_key",
            CredentialType::Agent => "agent",
        }
    }
    fn next(&self) -> Self {
        match self {
            CredentialType::Password => Self::SshKey,
            CredentialType::SshKey => Self::Agent,
            CredentialType::Agent => Self::Password,
        }
    }
    fn prev(&self) -> Self {
        match self {
            CredentialType::Password => Self::Agent,
            CredentialType::SshKey => Self::Password,
            CredentialType::Agent => Self::SshKey,
        }
    }
}

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
    AddCredential(Box<CredentialForm>, usize),
    DeleteCredentialConfirm(String),
    ClearCredentialConfirm(i64, String, String),      // host_id, host_name, cred_name
    SetCredential(i64, String, Menu<CredentialItem>), // host_id, host_name, menu of creds
}

/// Admin management interface
pub struct ManagementApp {
    tabs: Vec<String>,
    selected_tab: usize,
    should_exit: bool,
    // Cache for relay hosts
    relay_hosts: Vec<RelayItem>,
    relay_host_creds: HashMap<i64, String>,
    table_state: TableState,
    popup: PopupState,
    credentials: Vec<CredentialItem>,
    creds_state: TableState,
    flash: Option<String>,
}

impl ManagementApp {
    /// Create a new ManagementApp with pre-loaded relay hosts
    pub fn new(
        relay_hosts: Vec<RelayItem>,
        relay_host_creds: HashMap<i64, String>,
        credentials: Vec<CredentialItem>,
        flash: Option<String>,
    ) -> Self {
        let mut table_state = TableState::default();
        if !relay_hosts.is_empty() {
            table_state.select(Some(0));
        }
        let mut creds_state = TableState::default();
        if !credentials.is_empty() {
            creds_state.select(Some(0));
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
            relay_host_creds,
            table_state,
            popup: PopupState::None,
            credentials,
            creds_state,
            flash,
        }
    }

    pub fn with_selected_tab(mut self, idx: usize) -> Self {
        if !self.tabs.is_empty() {
            self.selected_tab = idx.min(self.tabs.len() - 1);
        }
        self
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
            && let Some(host) = self.relay_hosts.get(selected)
        {
            self.popup = PopupState::EditHost(HostForm::from_relay(host), 0, host.id);
        }
    }

    fn open_delete_popup(&mut self) {
        if let Some(selected) = self.table_state.selected()
            && let Some(host) = self.relay_hosts.get(selected)
        {
            self.popup = PopupState::DeleteConfirm(host.id, host.name.clone());
        }
    }

    fn close_popup(&mut self) {
        self.popup = PopupState::None;
    }

    fn next_cred_row(&mut self) {
        if self.credentials.is_empty() {
            return;
        }
        let i = match self.creds_state.selected() {
            Some(i) => {
                if i >= self.credentials.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.creds_state.select(Some(i));
    }

    fn previous_cred_row(&mut self) {
        if self.credentials.is_empty() {
            return;
        }
        let i = match self.creds_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.credentials.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.creds_state.select(Some(i));
    }

    fn open_add_credential_popup(&mut self) {
        self.popup = PopupState::AddCredential(Box::new(CredentialForm::new()), 0);
    }

    fn open_delete_credential_popup(&mut self) {
        if let Some(i) = self.creds_state.selected()
            && let Some(c) = self.credentials.get(i)
        {
            self.popup = PopupState::DeleteCredentialConfirm(c.name.clone());
        }
    }

    fn open_clear_credential_popup(&mut self) {
        if let Some(selected) = self.table_state.selected()
            && let Some(host) = self.relay_hosts.get(selected)
            && let Some(label) = self.relay_host_creds.get(&host.id)
            && label != "<custom>"
            && label != "<none>"
        {
            self.popup = PopupState::ClearCredentialConfirm(host.id, host.name.clone(), label.clone());
        }
    }

    fn open_set_credential_popup(&mut self) {
        if let Some(selected) = self.table_state.selected()
            && let Some(host) = self.relay_hosts.get(selected)
        {
            let label = self.relay_host_creds.get(&host.id).cloned().unwrap_or_else(|| "<none>".to_string());
            if label == "<none>" {
                let menu = Menu::new(format!("Set Credential for {}", host.name), self.credentials.clone());
                self.popup = PopupState::SetCredential(host.id, host.name.clone(), menu);
            }
        }
    }
}

impl Default for ManagementApp {
    fn default() -> Self {
        Self::new(Vec::new(), HashMap::new(), Vec::new(), None)
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

        // Clear flash on next keystroke (without consuming this input)
        if self.flash.is_some() && matches!(self.popup, PopupState::None) {
            self.flash = None;
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
            PopupState::AddCredential(form, focus) => match handle_credential_form_input(form, focus, input) {
                CFAction::Cancel => {
                    self.close_popup();
                    return Ok(AppAction::Render);
                }
                CFAction::Submit => {
                    if let Some(spec) = form.validate_and_build() {
                        self.close_popup();
                        return Ok(AppAction::AddCredential(spec));
                    } else {
                        return Ok(AppAction::Render);
                    }
                }
                CFAction::Render => return Ok(AppAction::Render),
                CFAction::Continue => return Ok(AppAction::Continue),
            },
            PopupState::DeleteCredentialConfirm(name) => {
                for &b in input {
                    match b {
                        b'y' | b'Y' | b'\r' | b'\n' => {
                            let n = name.clone();
                            self.close_popup();
                            return Ok(AppAction::DeleteCredential(n));
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
            PopupState::SetCredential(_hid, host, menu) => {
                // Navigate menu and submit
                for &byte in input {
                    match byte {
                        b'j' => {
                            menu.next();
                            return Ok(AppAction::Render);
                        }
                        b'k' => {
                            menu.previous();
                            return Ok(AppAction::Render);
                        }
                        0x1b => {
                            // Only cancel on a standalone ESC, not on CSI sequences
                            if input.len() == 1 {
                                self.close_popup();
                                return Ok(AppAction::Render);
                            }
                        }
                        b'\r' | b'\n' => {
                            if let Some(sel) = menu.selected_item() {
                                let action = AppAction::AssignCredential {
                                    host: host.clone(),
                                    cred_name: sel.name.clone(),
                                };
                                self.close_popup();
                                return Ok(action);
                            } else {
                                return Ok(AppAction::Render);
                            }
                        }
                        _ => {}
                    }
                }
                // Handle CSI arrows
                if input.len() >= 3 && input[0] == 0x1b && input[1] == b'[' {
                    match input[2] {
                        b'A' => {
                            menu.previous();
                            return Ok(AppAction::Render);
                        }
                        b'B' => {
                            menu.next();
                            return Ok(AppAction::Render);
                        }
                        _ => {}
                    }
                }
                return Ok(AppAction::Continue);
            }
            PopupState::ClearCredentialConfirm(_id, host, _cred) => {
                for &b in input {
                    match b {
                        b'y' | b'Y' | b'\r' | b'\n' => {
                            let name = host.clone();
                            self.close_popup();
                            return Ok(AppAction::UnassignCredential(name));
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
                b'a' => match self.selected_tab {
                    0 => {
                        self.open_add_popup();
                        return Ok(AppAction::Render);
                    }
                    1 => {
                        self.open_add_credential_popup();
                        return Ok(AppAction::Render);
                    }
                    _ => {}
                },
                b'e' => {
                    if self.selected_tab == 0 {
                        self.open_edit_popup();
                        return Ok(AppAction::Render);
                    }
                }
                b'd' => match self.selected_tab {
                    0 => {
                        self.open_delete_popup();
                        return Ok(AppAction::Render);
                    }
                    1 => {
                        self.open_delete_credential_popup();
                        return Ok(AppAction::Render);
                    }
                    _ => {}
                },
                b'c' => {
                    if self.selected_tab == 0 {
                        // Decide whether to open Set or Clear
                        if let Some(sel) = self.table_state.selected()
                            && let Some(h) = self.relay_hosts.get(sel)
                        {
                            let label = self.relay_host_creds.get(&h.id).cloned().unwrap_or_else(|| "<none>".to_string());
                            if label == "<none>" {
                                self.open_set_credential_popup();
                            } else if label != "<custom>" {
                                self.open_clear_credential_popup();
                            }
                            return Ok(AppAction::Render);
                        }
                    }
                }
                0x1b => {
                    if input.len() == 1 {
                        return Ok(AppAction::Exit);
                    }
                }
                b'j' => match self.selected_tab {
                    0 => {
                        self.next_row();
                        return Ok(AppAction::Render);
                    }
                    1 => {
                        self.next_cred_row();
                        return Ok(AppAction::Render);
                    }
                    _ => {}
                },
                b'k' => match self.selected_tab {
                    0 => {
                        self.previous_row();
                        return Ok(AppAction::Render);
                    }
                    1 => {
                        self.previous_cred_row();
                        return Ok(AppAction::Render);
                    }
                    _ => {}
                },
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
                    match self.selected_tab {
                        0 => {
                            self.previous_row();
                            return Ok(AppAction::Render);
                        }
                        1 => {
                            self.previous_cred_row();
                            return Ok(AppAction::Render);
                        }
                        _ => {}
                    }
                }
                b'B' => {
                    // Down
                    match self.selected_tab {
                        0 => {
                            self.next_row();
                            return Ok(AppAction::Render);
                        }
                        1 => {
                            self.next_cred_row();
                            return Ok(AppAction::Render);
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }

        Ok(AppAction::Continue)
    }

    fn render(&mut self, frame: &mut Frame, _uptime: std::time::Duration) {
        let area = frame.area();

        // Build layout with optional flash line below commands
        let mut layout = vec![Constraint::Length(3), Constraint::Min(0), Constraint::Length(1)];
        if self.flash.is_some() {
            layout.push(Constraint::Length(1));
        }
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
        let commands = match self.selected_tab {
            0 => {
                let mut base = "Tab/Arrows: Switch Tab | j/k: Navigate | a: Add | e: Edit | d: Delete".to_string();
                if let Some(sel) = self.table_state.selected()
                    && let Some(h) = self.relay_hosts.get(sel)
                {
                    let label = self.relay_host_creds.get(&h.id).cloned().unwrap_or_else(|| "<none>".to_string());
                    if label == "<none>" {
                        base.push_str(" | c: Set Credential");
                    } else if label != "<custom>" {
                        base.push_str(" | c: Clear Credential");
                    }
                }
                base.push_str(" | r: Relay Selector | q/Esc: Exit");
                Paragraph::new(base).style(Style::default().fg(Color::DarkGray))
            }
            1 => Paragraph::new("Tab/Arrows: Switch Tab | j/k: Navigate | a: Add | d: Delete | r: Relay Selector | q/Esc: Exit")
                .style(Style::default().fg(Color::DarkGray)),
            _ => Paragraph::new("Tab/Arrows: Switch Tab | r: Relay Selector | q/Esc: Exit").style(Style::default().fg(Color::DarkGray)),
        };
        let cmd_idx = if self.flash.is_some() { chunks.len() - 2 } else { chunks.len() - 1 };
        frame.render_widget(commands, chunks[cmd_idx]);
        if let Some(msg) = &self.flash {
            let p = Paragraph::new(msg.clone()).style(Style::default().fg(Color::Red));
            frame.render_widget(p, chunks[chunks.len() - 1]);
        }

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
        let header_cells = ["ID", "Name", "Endpoint", "Credential"]
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
            ],
        )
        .header(header)
        .block(Block::default().borders(Borders::ALL).title("Relay Hosts"))
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));

        frame.render_stateful_widget(t, area, &mut self.table_state);
    }

    fn render_credentials(&mut self, frame: &mut Frame, area: Rect) {
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

    fn render_options(&self) -> Paragraph<'static> {
        Paragraph::new("Global Options (Coming Soon)").block(Block::default().borders(Borders::ALL).title("Options"))
    }

    fn render_stats(&self) -> Paragraph<'static> {
        Paragraph::new("Server Statistics (Coming Soon)").block(Block::default().borders(Borders::ALL).title("Stats"))
    }

    fn render_popup(&mut self, frame: &mut Frame, area: Rect) {
        match &mut self.popup {
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
            PopupState::AddCredential(form, focus) => {
                let block = Block::default().title("Add Credential").borders(Borders::ALL);
                let area = centered_rect(70, 60, area);
                frame.render_widget(Clear, area);
                frame.render_widget(block, area);

                // Build constraints: type(1), name(3), username(3), then per-type fields
                let mut constraints: Vec<Constraint> = vec![Constraint::Length(1), Constraint::Length(3), Constraint::Length(3)];
                match form.ctype {
                    CredentialType::Password => {
                        constraints.push(Constraint::Length(3));
                    }
                    CredentialType::SshKey => {
                        constraints.push(Constraint::Length(7));
                        constraints.push(Constraint::Length(7));
                        constraints.push(Constraint::Length(3));
                    }
                    CredentialType::Agent => {
                        constraints.push(Constraint::Length(5));
                    }
                }
                constraints.push(Constraint::Length(1)); // error
                constraints.push(Constraint::Min(1)); // instructions

                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .margin(2)
                    .constraints(constraints)
                    .split(area);

                // 0: Type selector
                let type_text = format!("Type: {}", form.ctype.as_str());
                let type_style = if *focus == 0 {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default()
                };
                frame.render_widget(Paragraph::new(type_text).style(type_style), chunks[0]);

                // 1: Name
                form.name.render(frame, chunks[1], *focus == 1);
                // 2: Username (optional)
                form.username.render(frame, chunks[2], *focus == 2);

                let mut line = 3usize;
                match form.ctype {
                    CredentialType::Password => {
                        form.password.render(frame, chunks[line], *focus == line);
                        line += 1;
                    }
                    CredentialType::SshKey => {
                        form.key_value.render(frame, chunks[line], *focus == line);
                        line += 1;
                        form.cert_value.render(frame, chunks[line], *focus == line);
                        line += 1;
                        form.passphrase.render(frame, chunks[line], *focus == line);
                        line += 1;
                    }
                    CredentialType::Agent => {
                        form.public_key.render(frame, chunks[line], *focus == line);
                        line += 1;
                    }
                }

                // Error
                if let Some(err) = &form.error {
                    let err_p = Paragraph::new(err.as_str()).style(Style::default().fg(Color::Red));
                    frame.render_widget(err_p, chunks[line]);
                }
                // Instructions
                let instr = "Tab/Up/Down: Switch Field | Left/Right/Home/End: Move | Enter: Submit (TextArea: newline) | Esc: Cancel | Left/Right on Type to change";
                let instr_p = Paragraph::new(instr).style(Style::default().fg(Color::DarkGray));
                frame.render_widget(instr_p, chunks[chunks.len() - 1]);
            }
            PopupState::DeleteCredentialConfirm(name) => {
                let block = Block::default()
                    .title("Delete Credential")
                    .borders(Borders::ALL)
                    .style(Style::default().fg(Color::Red));
                let area = centered_rect(50, 20, area);
                frame.render_widget(Clear, area);
                frame.render_widget(block, area);
                let text = format!("Delete credential '{name}'?");
                let p = Paragraph::new(text).alignment(ratatui::layout::Alignment::Center);
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .margin(2)
                    .constraints([Constraint::Min(1), Constraint::Length(1)].as_ref())
                    .split(area);
                frame.render_widget(p, chunks[0]);
                let instr = Paragraph::new("y/Enter: Yes | n/Esc: No")
                    .alignment(ratatui::layout::Alignment::Center)
                    .style(Style::default().fg(Color::DarkGray));
                frame.render_widget(instr, chunks[1]);
            }
            PopupState::ClearCredentialConfirm(_id, host, cred) => {
                let block = Block::default()
                    .title("Clear Credential")
                    .borders(Borders::ALL)
                    .style(Style::default().fg(Color::Red));
                let area = centered_rect(60, 24, area);
                frame.render_widget(Clear, area);
                frame.render_widget(block, area);
                let text = format!("Clear shared credential '{cred}' from host '{host}'?");
                let p = Paragraph::new(text).alignment(ratatui::layout::Alignment::Center);
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .margin(2)
                    .constraints([Constraint::Min(1), Constraint::Length(1)].as_ref())
                    .split(area);
                frame.render_widget(p, chunks[0]);
                let instr = Paragraph::new("y/Enter: Yes | n/Esc: No")
                    .alignment(ratatui::layout::Alignment::Center)
                    .style(Style::default().fg(Color::DarkGray));
                frame.render_widget(instr, chunks[1]);
            }
            PopupState::SetCredential(_hid, _host, menu) => {
                let area = centered_rect(60, 60, area);
                frame.render_widget(Clear, area);
                // Render the menu directly (title already includes host)
                menu.render(frame, area);
                // Draw instructions below if space allows (best-effort)
            }
        }
    }
}

// -------------------------
// Credential form handling
// -------------------------

#[derive(Clone)]
struct CredentialForm {
    ctype: CredentialType,
    name: Input,
    username: Input,
    // Password
    password: Input,
    // SSH key (multiline)
    key_value: TextArea,
    cert_value: TextArea,
    passphrase: Input,
    // Agent (often multiline)
    public_key: TextArea,
    error: Option<String>,
}

impl CredentialForm {
    fn new() -> Self {
        Self {
            ctype: CredentialType::Password,
            name: Input::new("Name: "),
            username: Input::new("Username (optional): "),
            password: Input::new("Password: "),
            key_value: TextArea::new("Private key (PEM/OpenSSH): "),
            cert_value: TextArea::new("Certificate (OpenSSH, optional): "),
            passphrase: Input::new("Key passphrase (optional): "),
            public_key: TextArea::new("Public key (OpenSSH): "),
            error: None,
        }
    }

    fn fields_len(&self) -> usize {
        match self.ctype {
            CredentialType::Password => 4,
            CredentialType::SshKey => 6,
            CredentialType::Agent => 4,
        } // includes type row at index 0
    }

    fn validate_and_build(&mut self) -> Option<CredentialSpec> {
        let name = self.name.value().trim();
        if name.is_empty() {
            self.error = Some("Name is required".to_string());
            return None;
        }
        let username = if self.username.value().trim().is_empty() {
            None
        } else {
            Some(self.username.value().trim().to_string())
        };
        match self.ctype {
            CredentialType::Password => {
                let pw = self.password.value().to_string();
                if pw.is_empty() {
                    self.error = Some("Password is required".to_string());
                    return None;
                }
                self.error = None;
                Some(CredentialSpec::Password {
                    name: name.to_string(),
                    username,
                    password: pw,
                })
            }
            CredentialType::SshKey => {
                let key_val = self.key_value.value().trim().to_string();
                if key_val.is_empty() {
                    self.error = Some("Private key content is required".to_string());
                    return None;
                }
                // Optional certificate content (OpenSSH format)
                let cert_val = self.cert_value.value().trim();
                let cert_opt = if cert_val.is_empty() { None } else { Some(cert_val.to_string()) };
                let passphrase = if self.passphrase.value().trim().is_empty() {
                    None
                } else {
                    Some(self.passphrase.value().to_string())
                };
                self.error = None;
                Some(CredentialSpec::SshKey {
                    name: name.to_string(),
                    username,
                    key_file: None,
                    value: Some(key_val),
                    cert_file: cert_opt,
                    passphrase,
                })
            }
            CredentialType::Agent => {
                let pk = self.public_key.value().trim().to_string();
                if pk.is_empty() {
                    self.error = Some("Public key is required".to_string());
                    return None;
                }
                self.error = None;
                Some(CredentialSpec::Agent {
                    name: name.to_string(),
                    username,
                    public_key: pk,
                })
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CFAction {
    Continue,
    Render,
    Submit,
    Cancel,
}

fn handle_credential_form_input(form: &mut CredentialForm, focus: &mut usize, input: &[u8]) -> CFAction {
    let mut i = 0usize;
    let mut render = false;
    while i < input.len() {
        let b = input[i];
        i += 1;
        match b {
            0x1b => {
                if i < input.len() && input[i] == b'[' {
                    i += 1;
                    if i < input.len() {
                        let code = input[i];
                        i += 1;
                        match code {
                            b'A' => {
                                // Up
                                // If focused on a textarea field, move within it; else switch field
                                let is_textarea =
                                    matches!((&form.ctype, *focus), (CredentialType::SshKey, 3 | 4) | (CredentialType::Agent, 3));
                                if is_textarea {
                                    match *focus {
                                        3 => {
                                            if let CredentialType::SshKey | CredentialType::Agent = form.ctype {
                                                if form.ctype == CredentialType::SshKey {
                                                    form.key_value.move_up();
                                                } else {
                                                    form.public_key.move_up();
                                                }
                                            }
                                        }
                                        4 => {
                                            if form.ctype == CredentialType::SshKey {
                                                form.cert_value.move_up()
                                            }
                                        }
                                        _ => {}
                                    }
                                } else {
                                    let total = form.fields_len();
                                    *focus = if *focus == 0 { total - 1 } else { *focus - 1 };
                                }
                                render = true;
                            }
                            b'B' => {
                                // Down
                                let is_textarea =
                                    matches!((&form.ctype, *focus), (CredentialType::SshKey, 3 | 4) | (CredentialType::Agent, 3));
                                if is_textarea {
                                    match *focus {
                                        3 => {
                                            if form.ctype == CredentialType::SshKey {
                                                form.key_value.move_down();
                                            } else {
                                                form.public_key.move_down();
                                            }
                                        }
                                        4 => {
                                            if form.ctype == CredentialType::SshKey {
                                                form.cert_value.move_down()
                                            }
                                        }
                                        _ => {}
                                    }
                                } else {
                                    let total = form.fields_len();
                                    *focus = (*focus + 1) % total;
                                }
                                render = true;
                            }
                            b'C' => {
                                // Right
                                if *focus == 0 {
                                    form.ctype = form.ctype.next();
                                    render = true;
                                } else {
                                    match *focus {
                                        1 => form.name.move_right(),
                                        2 => form.username.move_right(),
                                        3 => match form.ctype {
                                            CredentialType::Password => form.password.move_right(),
                                            CredentialType::SshKey => form.key_value.move_right(),
                                            CredentialType::Agent => form.public_key.move_right(),
                                        },
                                        4 => {
                                            if form.ctype == CredentialType::SshKey {
                                                form.cert_value.move_right()
                                            }
                                        }
                                        5 => {
                                            if form.ctype == CredentialType::SshKey {
                                                form.passphrase.move_right()
                                            }
                                        }
                                        _ => {}
                                    }
                                    render = true;
                                }
                            }
                            b'D' => {
                                // Left
                                if *focus == 0 {
                                    form.ctype = form.ctype.prev();
                                    render = true;
                                } else {
                                    match *focus {
                                        1 => form.name.move_left(),
                                        2 => form.username.move_left(),
                                        3 => match form.ctype {
                                            CredentialType::Password => form.password.move_left(),
                                            CredentialType::SshKey => form.key_value.move_left(),
                                            CredentialType::Agent => form.public_key.move_left(),
                                        },
                                        4 => {
                                            if form.ctype == CredentialType::SshKey {
                                                form.cert_value.move_left()
                                            }
                                        }
                                        5 => {
                                            if form.ctype == CredentialType::SshKey {
                                                form.passphrase.move_left()
                                            }
                                        }
                                        _ => {}
                                    }
                                    render = true;
                                }
                            }
                            b'H' => {
                                if *focus != 0 {
                                    match *focus {
                                        1 => form.name.move_home(),
                                        2 => form.username.move_home(),
                                        3 => match form.ctype {
                                            CredentialType::Password => form.password.move_home(),
                                            CredentialType::SshKey => form.key_value.move_home(),
                                            CredentialType::Agent => form.public_key.move_home(),
                                        },
                                        4 => {
                                            if form.ctype == CredentialType::SshKey {
                                                form.cert_value.move_home()
                                            }
                                        }
                                        5 => {
                                            if form.ctype == CredentialType::SshKey {
                                                form.passphrase.move_home()
                                            }
                                        }
                                        _ => {}
                                    }
                                    render = true;
                                }
                            }
                            b'F' => {
                                if *focus != 0 {
                                    match *focus {
                                        1 => form.name.move_end(),
                                        2 => form.username.move_end(),
                                        3 => match form.ctype {
                                            CredentialType::Password => form.password.move_end(),
                                            CredentialType::SshKey => form.key_value.move_end(),
                                            CredentialType::Agent => form.public_key.move_end(),
                                        },
                                        4 => {
                                            if form.ctype == CredentialType::SshKey {
                                                form.cert_value.move_end()
                                            }
                                        }
                                        5 => {
                                            if form.ctype == CredentialType::SshKey {
                                                form.passphrase.move_end()
                                            }
                                        }
                                        _ => {}
                                    }
                                    render = true;
                                }
                            }
                            b'3' => {
                                if i < input.len() && input[i] == b'~' {
                                    i += 1;
                                } else if *focus != 0 {
                                    match *focus {
                                        1 => {
                                            let _ = form.name.delete_char();
                                        }
                                        2 => {
                                            let _ = form.username.delete_char();
                                        }
                                        3 => match form.ctype {
                                            CredentialType::Password => {
                                                let _ = form.password.delete_char();
                                            }
                                            CredentialType::SshKey => {
                                                let _ = form.key_value.delete_char();
                                            }
                                            CredentialType::Agent => {
                                                let _ = form.public_key.delete_char();
                                            }
                                        },
                                        4 => {
                                            if let CredentialType::SshKey = form.ctype {
                                                let _ = form.cert_value.delete_char();
                                            }
                                        }
                                        5 => {
                                            if let CredentialType::SshKey = form.ctype {
                                                let _ = form.passphrase.delete_char();
                                            }
                                        }
                                        _ => {}
                                    }
                                    render = true;
                                }
                            }
                            _ => {}
                        }
                    }
                } else {
                    return CFAction::Cancel;
                }
            }
            b'\t' => {
                let total = form.fields_len();
                *focus = (*focus + 1) % total;
                render = true;
            }
            b'\r' | b'\n' => {
                // In textarea fields, Enter inserts newline; otherwise submit
                let is_textarea = matches!((&form.ctype, *focus), (CredentialType::SshKey, 3 | 4) | (CredentialType::Agent, 3));
                if is_textarea {
                    match *focus {
                        3 => {
                            if form.ctype == CredentialType::SshKey {
                                form.key_value.insert_newline();
                            } else {
                                form.public_key.insert_newline();
                            }
                        }
                        4 => {
                            if form.ctype == CredentialType::SshKey {
                                form.cert_value.insert_newline()
                            }
                        }
                        _ => {}
                    }
                    render = true;
                } else {
                    return CFAction::Submit;
                }
            }
            0x7f | 0x08 => {
                if *focus != 0 {
                    match *focus {
                        1 => {
                            let _ = form.name.pop_char();
                        }
                        2 => {
                            let _ = form.username.pop_char();
                        }
                        3 => match form.ctype {
                            CredentialType::Password => {
                                let _ = form.password.pop_char();
                            }
                            CredentialType::SshKey => {
                                let _ = form.key_value.backspace();
                            }
                            CredentialType::Agent => {
                                let _ = form.public_key.backspace();
                            }
                        },
                        4 => {
                            if let CredentialType::SshKey = form.ctype {
                                let _ = form.cert_value.backspace();
                            }
                        }
                        5 => {
                            if let CredentialType::SshKey = form.ctype {
                                let _ = form.passphrase.pop_char();
                            }
                        }
                        _ => {}
                    }
                    render = true;
                }
            }
            c if (32..=126).contains(&c) => {
                if *focus != 0 {
                    let ch = c as char;
                    match *focus {
                        1 => form.name.push_char(ch),
                        2 => form.username.push_char(ch),
                        3 => match form.ctype {
                            CredentialType::Password => form.password.push_char(ch),
                            CredentialType::SshKey => form.key_value.push_char(ch),
                            CredentialType::Agent => form.public_key.push_char(ch),
                        },
                        4 => {
                            if let CredentialType::SshKey = form.ctype {
                                form.cert_value.push_char(ch);
                            }
                        }
                        5 => {
                            if let CredentialType::SshKey = form.ctype {
                                form.passphrase.push_char(ch);
                            }
                        }
                        _ => {}
                    }
                    render = true;
                }
            }
            _ => {}
        }
    }
    if render { CFAction::Render } else { CFAction::Continue }
}
