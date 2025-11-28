use ratatui::{
    Frame, layout::{Constraint, Direction, Layout, Rect}, style::{Color, Modifier, Style}, widgets::{Block, Borders, Clear, Paragraph, Wrap}
};

use super::types::{CredentialType, ModalInputHints, PopupState};
use crate::utils::centered_rect;

impl super::ManagementApp {
    pub fn render_popup(&mut self, frame: &mut Frame, area: Rect) {
        match &mut self.popup {
            PopupState::None => {}
            PopupState::AddHost(form, focus) => {
                let block = Block::default().title("Add Relay Host").borders(Borders::ALL);
                let area = centered_rect(50, 30, area);
                frame.render_widget(Clear, area);
                frame.render_widget(block, area);

                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .margin(2)
                    .constraints(
                        [
                            Constraint::Length(3), // Name field
                            Constraint::Length(3), // Endpoint field
                            Constraint::Length(1), // Error line
                            Constraint::Min(1),    // Spacer
                            Constraint::Length(1), // Instructions at bottom
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

                let instructions = Paragraph::new(ModalInputHints::form_navigation()).style(Style::default().fg(Color::DarkGray));
                frame.render_widget(instructions, chunks[4]);
            }
            PopupState::EditHost(form, focus, _id) => {
                let block = Block::default().title("Edit Relay Host").borders(Borders::ALL);
                let area = centered_rect(50, 30, area);
                frame.render_widget(Clear, area);
                frame.render_widget(block, area);

                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .margin(2)
                    .constraints(
                        [
                            Constraint::Length(3), // Name field
                            Constraint::Length(3), // Endpoint field
                            Constraint::Length(1), // Error line
                            Constraint::Min(1),    // Spacer
                            Constraint::Length(1), // Instructions at bottom
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

                let instructions = Paragraph::new(ModalInputHints::form_navigation()).style(Style::default().fg(Color::DarkGray));
                frame.render_widget(instructions, chunks[4]);
            }
            PopupState::DeleteConfirm(_id, name) => {
                let block = Block::default()
                    .title("Confirm Delete")
                    .borders(Borders::ALL)
                    .style(Style::default().fg(Color::Red));
                let area = centered_rect(50, 25, area);
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

                let instructions = Paragraph::new(ModalInputHints::yes_no(true, true))
                    .alignment(ratatui::layout::Alignment::Center)
                    .style(Style::default().fg(Color::DarkGray));
                frame.render_widget(instructions, chunks[1]);
            }
            PopupState::AddCredential(form, focus) => {
                let block = Block::default().title("Add Credential").borders(Borders::ALL);
                let area = centered_rect(60, 50, area);
                frame.render_widget(Clear, area);
                frame.render_widget(block, area);

                // Build constraints: type(1), name(3), umode(1), username(3), then per-type fields, error(1), instructions(1)
                let mut constraints: Vec<Constraint> = vec![
                    Constraint::Length(1), // Type selector
                    Constraint::Length(3), // Name
                    Constraint::Length(1), // Username Mode
                    Constraint::Length(3), // Username
                ];
                match form.ctype {
                    CredentialType::Password => {
                        constraints.push(Constraint::Length(1)); // Password Required
                        constraints.push(Constraint::Length(3)); // Password
                    }
                    CredentialType::SshKey => {
                        constraints.push(Constraint::Length(7)); // Key
                        constraints.push(Constraint::Length(7)); // Cert
                        constraints.push(Constraint::Length(3)); // Passphrase
                    }
                    CredentialType::Agent => {
                        constraints.push(Constraint::Length(5)); // Public key
                    }
                }
                constraints.push(Constraint::Length(1)); // Error line
                constraints.push(Constraint::Min(1)); // Spacer
                constraints.push(Constraint::Length(1)); // Instructions at bottom

                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .margin(2)
                    .constraints(constraints)
                    .split(area);

                // 0: Type selector
                let type_text = if *focus == 0 {
                    format!("Type: < {} >  (use ←/→ to change)", form.ctype.as_str())
                } else {
                    format!("Type: {}", form.ctype.as_str())
                };
                let type_style = if *focus == 0 {
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::REVERSED)
                } else {
                    Style::default().fg(Color::Yellow)
                };
                frame.render_widget(Paragraph::new(type_text).style(type_style), chunks[0]);

                // 1: Name
                form.name.render(frame, chunks[1], *focus == 1);

                // 2: Username Mode
                let umode_text = if *focus == 2 {
                    format!("Username Mode: < {} >", form.username_mode.as_str())
                } else {
                    format!("Username Mode: {}", form.username_mode.as_str())
                };
                let umode_style = if *focus == 2 {
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::REVERSED)
                } else {
                    Style::default().fg(Color::Yellow)
                };
                frame.render_widget(Paragraph::new(umode_text).style(umode_style), chunks[2]);

                // 3: Username (optional)
                form.username.render(frame, chunks[3], *focus == 3);

                let mut line = 4usize;
                match form.ctype {
                    CredentialType::Password => {
                        // 4: Password Required
                        let pw_req_text = if form.password_required {
                            "[x] Password Required"
                        } else {
                            "[ ] Password Required"
                        };
                        let pw_req_style = if *focus == line {
                            Style::default().fg(Color::Yellow).add_modifier(Modifier::REVERSED)
                        } else {
                            Style::default().fg(Color::Yellow)
                        };
                        frame.render_widget(Paragraph::new(pw_req_text).style(pw_req_style), chunks[line]);
                        line += 1;

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
                // Instructions at the last chunk
                let instr = "Tab/Up/Down: Switch Field | Left/Right/Home/End: Move | Enter: Submit (TextArea: newline) | Esc: Cancel | Left/Right on Type to change";
                let instr_p = Paragraph::new(instr).style(Style::default().fg(Color::DarkGray));
                frame.render_widget(instr_p, chunks[chunks.len() - 1]);
            }
            PopupState::DeleteCredentialConfirm(_id, name) => {
                let block = Block::default()
                    .title("Delete Credential")
                    .borders(Borders::ALL)
                    .style(Style::default().fg(Color::Red));
                let area = centered_rect(50, 25, area);
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
                let instr = Paragraph::new(ModalInputHints::yes_no(true, true))
                    .alignment(ratatui::layout::Alignment::Center)
                    .style(Style::default().fg(Color::DarkGray));
                frame.render_widget(instr, chunks[1]);
            }
            PopupState::ClearCredentialConfirm(_id, host, cred) => {
                let block = Block::default()
                    .title("Clear Credential")
                    .borders(Borders::ALL)
                    .style(Style::default().fg(Color::Red));
                let area = centered_rect(60, 25, area);
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
                let instr = Paragraph::new(ModalInputHints::yes_no(true, true))
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
            PopupState::HostkeyReview(review) => {
                let block = Block::default().title("Verify Host Key").borders(Borders::ALL);
                let area = centered_rect(70, 30, area);
                frame.render_widget(Clear, area);
                frame.render_widget(block, area);

                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .margin(2)
                    .constraints(
                        [
                            Constraint::Length(1), // Host header
                            Constraint::Length(2), // Old fingerprint
                            Constraint::Length(2), // New fingerprint
                            Constraint::Min(1),    // Spacer
                            Constraint::Length(1), // Instructions at bottom
                        ]
                        .as_ref(),
                    )
                    .split(area);
                let header = Paragraph::new(format!("Host: {}", review.host));
                frame.render_widget(header, chunks[0]);
                let old = review.old_fingerprint.as_deref().unwrap_or("<none>");
                let old_type = review.old_key_type.as_deref().unwrap_or("<unknown>");
                let oldp = Paragraph::new(format!("Existing: {}  ({})", old, old_type));
                frame.render_widget(oldp, chunks[1]);
                let newp = Paragraph::new(format!("New: {}  ({})", review.new_fingerprint, review.new_key_type));
                frame.render_widget(newp, chunks[2]);
                let inst = Paragraph::new(ModalInputHints::yes_no_with_prompt("Store/replace this host key?", true, true))
                    .alignment(ratatui::layout::Alignment::Center)
                    .style(Style::default().fg(Color::DarkGray));
                frame.render_widget(inst, chunks[4]);
            }
        }
    }
}
