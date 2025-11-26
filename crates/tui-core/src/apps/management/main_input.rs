//! Main input handler module for ManagementApp
//! Handles all input processing when no popups are active

use crate::{AppAction, TuiResult};

impl super::ManagementApp {
    pub fn handle_main_input(&mut self, input: &[u8]) -> TuiResult<AppAction> {
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
                b'h' => {
                    if self.selected_tab == 0
                        && let Some(sel) = self.table_state.selected()
                        && let Some(h) = self.relay_hosts.get(sel)
                    {
                        return Ok(AppAction::FetchHostkey {
                            id: h.id,
                            name: h.name.clone(),
                        });
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
}
