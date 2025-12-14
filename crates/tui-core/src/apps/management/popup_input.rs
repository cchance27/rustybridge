//! Popup input handler module for ManagementApp
//! Handles all input processing when popups are active

use super::{
    forms::{CFAction, FormAction, handle_credential_form_input, handle_form_input},
    types::PopupState,
};
use crate::{AppAction, TuiResult};

impl super::ManagementApp {
    pub fn handle_popup_input(&mut self, input: &[u8]) -> TuiResult<AppAction> {
        tracing::trace!(?input, "management app popup input");

        match &mut self.popup {
            PopupState::None => {
                // No popup is active, continue with main input handling
                Ok(AppAction::Continue)
            }
            PopupState::AddHost(form, focus) => {
                match handle_form_input(form, focus, input) {
                    FormAction::Cancel => {
                        self.close_popup();
                        Ok(AppAction::Render)
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
                        let new_host = crate::apps::relay_selector::RelayItem {
                            name: name.to_string(),
                            description: endpoint.to_string(),
                            id: 0,
                        };
                        self.close_popup();
                        Ok(AppAction::AddRelay(new_host))
                    }
                    FormAction::Render => Ok(AppAction::Render),
                    FormAction::Continue => Ok(AppAction::Continue),
                }
            }
            PopupState::EditHost(form, focus, id) => {
                match handle_form_input(form, focus, input) {
                    FormAction::Cancel => {
                        self.close_popup();
                        Ok(AppAction::Render)
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
                        let updated_host = crate::apps::relay_selector::RelayItem {
                            name: name.to_string(),
                            description: endpoint.to_string(),
                            id: *id,
                        };
                        self.close_popup();
                        Ok(AppAction::UpdateRelay(updated_host))
                    }
                    FormAction::Render => Ok(AppAction::Render),
                    FormAction::Continue => Ok(AppAction::Continue),
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
                Ok(AppAction::Continue)
            }
            PopupState::AddCredential(form, focus) => match handle_credential_form_input(form, focus, input) {
                CFAction::Cancel => {
                    self.close_popup();
                    Ok(AppAction::Render)
                }
                CFAction::Submit => {
                    if let Some(spec) = form.validate_and_build() {
                        self.close_popup();
                        Ok(AppAction::AddCredential(spec))
                    } else {
                        Ok(AppAction::Render)
                    }
                }
                CFAction::Render => Ok(AppAction::Render),
                CFAction::Continue => Ok(AppAction::Continue),
            },
            PopupState::DeleteCredentialConfirm(id, _name) => {
                for &b in input {
                    match b {
                        b'y' | b'Y' | b'\r' | b'\n' => {
                            let id_val = *id;
                            self.close_popup();
                            return Ok(AppAction::DeleteCredential(id_val));
                        }
                        b'n' | b'N' | 0x1b => {
                            self.close_popup();
                            return Ok(AppAction::Render);
                        }
                        _ => {}
                    }
                }
                Ok(AppAction::Continue)
            }
            PopupState::SetCredential(hid, _host, menu) => {
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
                                    host_id: *hid,
                                    cred_id: sel.id,
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
                Ok(AppAction::Continue)
            }
            PopupState::ClearCredentialConfirm(id, _host, _cred) => {
                for &b in input {
                    match b {
                        b'y' | b'Y' | b'\r' | b'\n' => {
                            let id_val = *id;
                            self.close_popup();
                            return Ok(AppAction::UnassignCredential(id_val));
                        }
                        b'n' | b'N' | 0x1b => {
                            self.close_popup();
                            return Ok(AppAction::Render);
                        }
                        _ => {}
                    }
                }
                Ok(AppAction::Continue)
            }
            PopupState::HostkeyReview(review) => match input.first() {
                Some(b'y') | Some(b'Y') | Some(b'\r') | Some(b'\n') => {
                    let action = AppAction::StoreHostkey {
                        id: review.host_id,
                        name: review.host.clone(),
                        key: review.new_key_pem.clone(),
                    };
                    Ok(action)
                }
                Some(b'n') | Some(b'N') | Some(0x1b) => {
                    let action = AppAction::CancelHostkey {
                        id: review.host_id,
                        name: review.host.clone(),
                    };
                    Ok(action)
                }
                _ => Ok(AppAction::Render),
            },
        }
    }
}
