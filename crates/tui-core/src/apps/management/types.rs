use crate::apps::relay_selector::RelayItem;
use rb_types::relay::HostkeyReview;
use std::fmt;

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
        username_mode: String,
        password_required: bool,
        password: String,
    },
    SshKey {
        name: String,
        username: Option<String>,
        username_mode: String,
        key_file: Option<String>,
        value: Option<String>,
        cert_file: Option<String>,
        passphrase: Option<String>,
    },
    Agent {
        name: String,
        username: Option<String>,
        username_mode: String,
        public_key: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialType {
    Password,
    SshKey,
    Agent,
}

impl CredentialType {
    pub fn as_str(&self) -> &'static str {
        match self {
            CredentialType::Password => "password",
            CredentialType::SshKey => "ssh_key",
            CredentialType::Agent => "agent",
        }
    }
    pub fn next(&self) -> Self {
        match self {
            CredentialType::Password => Self::SshKey,
            CredentialType::SshKey => Self::Agent,
            CredentialType::Agent => Self::Password,
        }
    }
    pub fn prev(&self) -> Self {
        match self {
            CredentialType::Password => Self::Agent,
            CredentialType::SshKey => Self::Password,
            CredentialType::Agent => Self::SshKey,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialUsernameMode {
    Fixed,
    Blank,
    Passthrough,
}

impl CredentialUsernameMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            CredentialUsernameMode::Fixed => "fixed",
            CredentialUsernameMode::Blank => "blank",
            CredentialUsernameMode::Passthrough => "passthrough",
        }
    }
    pub fn next(&self) -> Self {
        match self {
            CredentialUsernameMode::Fixed => Self::Blank,
            CredentialUsernameMode::Blank => Self::Passthrough,
            CredentialUsernameMode::Passthrough => Self::Fixed,
        }
    }
    pub fn prev(&self) -> Self {
        match self {
            CredentialUsernameMode::Fixed => Self::Passthrough,
            CredentialUsernameMode::Blank => Self::Fixed,
            CredentialUsernameMode::Passthrough => Self::Blank,
        }
    }
}

#[derive(Clone)]
pub struct HostForm {
    pub name: crate::widgets::Input,
    pub description: crate::widgets::Input,
    pub error: Option<String>,
}

impl Default for HostForm {
    fn default() -> Self {
        Self::new()
    }
}

impl HostForm {
    pub fn new() -> Self {
        Self {
            name: crate::widgets::Input::new("Name: "),
            description: crate::widgets::Input::new("Endpoint (IP:Port): "),
            error: None,
        }
    }

    pub fn from_relay(relay: &RelayItem) -> Self {
        Self {
            name: crate::widgets::Input::new("Name: ").with_value(&relay.name),
            description: crate::widgets::Input::new("Endpoint (IP:Port): ").with_value(&relay.description),
            error: None,
        }
    }
}

/// Helper to generate consistent input hints for modals
#[derive(Clone)]
pub struct ModalInputHints;

impl ModalInputHints {
    /// Generate yes/no confirmation prompt
    /// - `yes_default`: if true, (Y)es is capitalized; if false, (N)o is capitalized
    /// - `allow_enter`: if true, Enter key confirms the default option
    pub fn yes_no(yes_default: bool, allow_enter: bool) -> ratatui::text::Line<'static> {
        ratatui::text::Line::from(Self::yes_no_segments(None, yes_default, allow_enter))
    }

    /// Generate yes/no prompt prefixed with a message (e.g., "Store item?")
    pub fn yes_no_with_prompt(prompt: &str, yes_default: bool, allow_enter: bool) -> ratatui::text::Line<'static> {
        ratatui::text::Line::from(Self::yes_no_segments(Some(prompt), yes_default, allow_enter))
    }

    /// Form navigation hints
    pub fn form_navigation() -> &'static str {
        "Tab/↑/↓: Switch Field | ←/→/Home/End: Move Cursor | Enter: Submit | Esc: Cancel"
    }

    fn yes_no_segments(prompt: Option<&str>, yes_default: bool, allow_enter: bool) -> Vec<ratatui::text::Span<'static>> {
        let mut spans = Vec::new();
        if let Some(prefix) = prompt
            && !prefix.is_empty()
        {
            spans.push(ratatui::text::Span::raw(format!("{prefix} ")));
        }
        let yes_is_default = yes_default && allow_enter;
        let no_is_default = !yes_default && allow_enter;
        let yes_label = if yes_is_default { "(Y)es" } else { "(y)es" };
        let no_label = if no_is_default { "(N)o" } else { "(n)o" };
        let yes_style = if yes_is_default {
            ratatui::style::Style::default().add_modifier(ratatui::style::Modifier::UNDERLINED)
        } else {
            ratatui::style::Style::default()
        };
        let no_style = if no_is_default {
            ratatui::style::Style::default().add_modifier(ratatui::style::Modifier::UNDERLINED)
        } else {
            ratatui::style::Style::default()
        };

        spans.push(ratatui::text::Span::styled(yes_label.to_string(), yes_style));
        spans.push(ratatui::text::Span::raw(" / "));
        spans.push(ratatui::text::Span::styled(no_label.to_string(), no_style));
        spans.push(ratatui::text::Span::raw(" / Esc"));
        spans
    }
}

#[derive(Clone)]
pub enum PopupState {
    None,
    AddHost(HostForm, usize),       // usize tracks which field is focused (0=name, 1=desc)
    EditHost(HostForm, usize, i64), // i64 is the ID of the host being edited
    DeleteConfirm(i64, String),     // ID and Name of host to delete
    AddCredential(Box<CredentialForm>, usize),
    DeleteCredentialConfirm(i64, String),
    ClearCredentialConfirm(i64, String, String), // host_id, host_name, cred_name
    SetCredential(i64, String, crate::widgets::Menu<CredentialItem>), // host_id, host_name, menu of creds
    HostkeyReview(HostkeyReview),                // pending hostkey review
}

#[derive(Clone)]
pub struct CredentialForm {
    pub ctype: CredentialType,
    pub name: crate::widgets::Input,
    pub username: crate::widgets::Input,
    pub username_mode: CredentialUsernameMode,
    pub password_required: bool,
    // Password
    pub password: crate::widgets::Input,
    // SSH key (multiline)
    pub key_value: crate::widgets::TextArea,
    pub cert_value: crate::widgets::TextArea,
    pub passphrase: crate::widgets::Input,
    // Agent (often multiline)
    pub public_key: crate::widgets::TextArea,
    pub error: Option<String>,
}

impl Default for CredentialForm {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialForm {
    pub fn new() -> Self {
        Self {
            ctype: CredentialType::Password,
            name: crate::widgets::Input::new("Name: "),
            username: crate::widgets::Input::new("Username: "),
            username_mode: CredentialUsernameMode::Fixed,
            password_required: true,
            password: crate::widgets::Input::new("Password: "),
            key_value: crate::widgets::TextArea::new("Private key (PEM/OpenSSH): "),
            cert_value: crate::widgets::TextArea::new("Certificate (OpenSSH, optional): "),
            passphrase: crate::widgets::Input::new("Key passphrase (optional): "),
            public_key: crate::widgets::TextArea::new("Public key (OpenSSH): "),
            error: None,
        }
    }

    pub fn fields_len(&self) -> usize {
        match self.ctype {
            CredentialType::Password => 6, // Type, Name, UMode, User, PwReq, Pass
            CredentialType::SshKey => 7,   // Type, Name, UMode, User, Key, Cert, Passphrase
            CredentialType::Agent => 5,    // Type, Name, UMode, User, PubKey
        } // includes type row at index 0
    }

    pub fn validate_and_build(&mut self) -> Option<CredentialSpec> {
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
                if self.password_required && pw.is_empty() {
                    self.error = Some("Password is required".to_string());
                    return None;
                }
                self.error = None;
                Some(CredentialSpec::Password {
                    name: name.to_string(),
                    username,
                    username_mode: self.username_mode.as_str().to_string(),
                    password_required: self.password_required,
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
                    username_mode: self.username_mode.as_str().to_string(),
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
                    username_mode: self.username_mode.as_str().to_string(),
                    public_key: pk,
                })
            }
        }
    }
}
