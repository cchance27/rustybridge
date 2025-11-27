//! TUI action processing.

use russh::{ChannelId, CryptoVec, server::Session};
use tracing::warn;
use tui_core::AppAction;

use super::{AuthPromptState, ServerHandler};

impl ServerHandler {
    pub(super) async fn process_action(
        &mut self,
        action: AppAction,
        session: &mut Session,
        channel: ChannelId,
    ) -> Result<(), russh::Error> {
        match action {
            AppAction::Exit => {
                self.handle_exit(session, channel)?;
            }
            AppAction::Render => {
                self.render_terminal(session, channel)?;
            }
            AppAction::SwitchTo(app_name) => {
                self.switch_app(&app_name, session, channel).await?;
            }
            AppAction::ConnectToRelay { id: _, name } => {
                self.relay_target = Some(name.clone());
                self.drop_terminal(); // Stop TUI
                self.leave_alt_screen(session, channel)?; // Leave alt screen
                // Kick off background connect; prompts/results handled in data()
                self.connect_to_relay(session, channel, &name).await?;
            }
            AppAction::FetchHostkey { id, name } => {
                let status = tui_core::app::StatusLine {
                    text: format!("Fetching host key for '{}'...", name),
                    kind: tui_core::app::StatusKind::Info,
                };
                self.show_status_line(status, session, channel)?;
                // Kick off the fetch in the background; results are pushed through action_tx.
                let tx = self.action_tx.clone();
                let name_clone = name.clone();
                let server_handle = session.handle();
                tokio::spawn(async move {
                    let action = AppAction::FetchHostkey {
                        id,
                        name: name_clone.clone(),
                    };
                    match crate::handle_management_action(action).await {
                        Ok(Some(res_action)) => {
                            let _ = tx.send(res_action);
                        }
                        Ok(None) => {
                            let _ = tx.send(AppAction::Error(format!("Host '{}' did not present a host key", name_clone)));
                        }
                        Err(e) => {
                            let _ = tx.send(AppAction::Error(format!("Hostkey fetch failed: {}", e)));
                        }
                    }
                    // Trigger a DSR to wake the data loop even if the client stays idle.
                    let _ = server_handle.data(channel, CryptoVec::from_slice(b"\x1b[6n")).await;
                });
            }
            AppAction::ReviewHostkey(review) => {
                // Reload management app with the review data
                self.reload_management_app(session, channel, 0, Some(review)).await?;
            }
            AppAction::AddRelay(_)
            | AppAction::UpdateRelay(_)
            | AppAction::DeleteRelay(_)
            | AppAction::AddCredential(_)
            | AppAction::DeleteCredential(_)
            | AppAction::UnassignCredential(_)
            | AppAction::AssignCredential { .. }
            | AppAction::StoreHostkey { .. }
            | AppAction::CancelHostkey { .. } => {
                let cloned = action.clone();
                let tab = match action {
                    AppAction::AddCredential(_) | AppAction::DeleteCredential(_) => 1,
                    _ => 0,
                };
                match crate::handle_management_action(cloned.clone()).await {
                    Ok(_) => {
                        // Reload Management app with fresh data and redraw.
                        self.reload_management_app(session, channel, tab, None).await?;
                        // Success-specific status for certain actions
                        if let AppAction::StoreHostkey { name, .. } = &action
                            && let Some(app_session) = self.app_session.as_mut()
                        {
                            let status = tui_core::app::StatusLine {
                                text: format!("Stored host key for '{}'", name),
                                kind: tui_core::app::StatusKind::Success,
                            };
                            app_session.set_status(Some(status));
                            self.render_terminal(session, channel)?;
                        }
                    }
                    Err(e) => {
                        warn!("failed to apply management action: {}", e);
                        // Reload Management app anyway so the status message surfaces on the new instance.
                        self.reload_management_app(session, channel, tab, None).await?;
                        if let Some(app_session) = self.app_session.as_mut() {
                            let msg = crate::format_action_error(&cloned, &e);
                            let status = tui_core::app::StatusLine {
                                text: msg,
                                kind: tui_core::app::StatusKind::Error,
                            };
                            app_session.set_status(Some(status));
                            self.render_terminal(session, channel)?;
                        }
                    }
                }
            }
            AppAction::Error(msg) => {
                if let Some(app_session) = self.app_session.as_mut() {
                    let status = tui_core::app::StatusLine {
                        text: msg,
                        kind: tui_core::app::StatusKind::Error,
                    };
                    app_session.set_status(Some(status));
                    self.render_terminal(session, channel)?;
                }
            }
            AppAction::AuthPrompt { prompt, echo } => {
                // Send prompt to the user's terminal and start capturing input
                if !self.prompt_sink_active {
                    let _ = self.send_bytes(session, channel, prompt.as_bytes());
                    if echo {
                        let _ = self.send_bytes(session, channel, b" ");
                    }
                }
                if let Some(app_session) = self.app_session.as_mut() {
                    app_session.set_status_message(Some(prompt.clone()));
                    self.render_terminal(session, channel)?;
                }
                self.pending_auth = Some(AuthPromptState { buffer: Vec::new(), echo });
            }
            AppAction::BackendEvent(_) => {
                // Backend events are internal signals, not handled in server mode
            }
            AppAction::Continue => {
                // no background reloads; status and fetches are session-scoped
            }
        }
        Ok(())
    }
}
