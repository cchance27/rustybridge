//! User input processing and interactive authentication prompts.

use russh::{ChannelId, server::Session};
use tokio::sync::oneshot;

use super::ServerHandler;

impl ServerHandler {
    pub(super) async fn handle_data(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> Result<(), russh::Error> {
        if Some(channel) != self.channel {
            return Ok(());
        }

        // Process any queued background actions (e.g., results from hostkey fetch)
        while let Ok(action) = self.action_rx.try_recv() {
            self.process_action(action, session, channel).await?;
        }

        // If a relay connect is pending, poll its completion
        if let Some(rx) = self.pending_relay.as_mut() {
            match rx.try_recv() {
                Ok(Ok((handle, auth_tx))) => {
                    self.relay_handle = Some(handle);
                    self.auth_tx = Some(auth_tx);
                    self.pending_relay = None;
                    self.prompt_sink_active = false; // relay established; prompts will come from remote shell now
                    self.touch_session();
                    // We are leaving the TUI; retire the TUI session so it disappears from dashboards.
                    self.end_tui_session();
                }
                Ok(Err(err)) => {
                    let _ = self.send_line(session, channel, &format!("failed to start relay: {}", err));
                    self.pending_relay = None;
                    self.touch_session();
                    return self.handle_exit(session, channel);
                }
                Err(oneshot::error::TryRecvError::Empty) => {}
                Err(oneshot::error::TryRecvError::Closed) => {
                    let _ = self.send_line(session, channel, "failed to start relay: channel closed");
                    self.pending_relay = None;
                    self.touch_session();
                    return self.handle_exit(session, channel);
                }
            }
        }

        // If an auth prompt is active, capture input directly and bypass TUI apps
        if self.pending_auth.is_some() {
            let mut done = false;
            let mut response_to_send: Option<String> = None;
            let mut echo_out: Vec<u8> = Vec::new();
            let _echo_enabled = {
                let auth = self.pending_auth.as_mut().unwrap();
                let echo_flag = auth.echo;
                for b in data {
                    match *b {
                        0x03 => {
                            // Ctrl+C: cancel prompt and close session
                            let _ = self.send_bytes(session, channel, b"\r\n^C\r\n");
                            self.pending_auth = None;
                            return self.handle_exit(session, channel);
                        }
                        0x04 => {
                            // Ctrl+D: treat like cancel/EOF
                            let _ = self.send_bytes(session, channel, b"\r\n^D\r\n");
                            self.pending_auth = None;
                            return self.handle_exit(session, channel);
                        }
                        0x7f | 0x08 => {
                            // Backspace/delete
                            if let Some(_ch) = auth.buffer.pop()
                                && echo_flag
                            {
                                echo_out.extend_from_slice(b"\x08 \x08");
                            }
                        }
                        0x15 => {
                            // Ctrl+U: clear entire line
                            let count = auth.buffer.len();
                            auth.buffer.clear();
                            if echo_flag && count > 0 {
                                for _ in 0..count {
                                    echo_out.extend_from_slice(b"\x08");
                                }
                                for _ in 0..count {
                                    echo_out.extend_from_slice(b" ");
                                }
                                for _ in 0..count {
                                    echo_out.extend_from_slice(b"\x08");
                                }
                            }
                        }
                        0x17 => {
                            // Ctrl+W: delete word back to whitespace
                            let mut removed = 0usize;
                            while let Some(ch) = auth.buffer.pop() {
                                removed += 1;
                                if ch.is_ascii_whitespace() {
                                    break;
                                }
                            }
                            if echo_flag && removed > 0 {
                                for _ in 0..removed {
                                    echo_out.extend_from_slice(b"\x08 \x08");
                                }
                            }
                        }
                        b'\r' | b'\n' => {
                            response_to_send = Some(String::from_utf8_lossy(&auth.buffer).to_string());
                            done = true;
                            break;
                        }
                        byte => {
                            auth.buffer.push(byte);
                            if echo_flag {
                                echo_out.push(byte);
                            }
                        }
                    }
                }
                echo_flag
            }; // drop mutable borrow of pending_auth

            if !echo_out.is_empty() {
                let _ = self.send_bytes(session, channel, &echo_out);
            }

            if let Some(resp) = response_to_send
                && let Some(tx) = self.auth_tx.as_ref()
            {
                let _ = tx.send(resp);
            }
            if done {
                // Add a single newline after submit so next prompt/output is on a new line
                let _ = self.send_bytes(session, channel, b"\r\n");
                // If auth failed elsewhere, force a flush by sending an empty data packet
                if self.pending_relay.is_none() && self.relay_handle.is_none() {
                    let _ = self.send_bytes(session, channel, b"");
                }
                self.pending_auth = None;
            }
            self.touch_session();
            return Ok(());
        }

        if let Some(relay) = self.relay_handle.as_ref() {
            if !data.is_empty() {
                relay.send(data.to_vec());
            }
            self.touch_session();
            return Ok(());
        }

        if let Some(app_session) = self.app_session.as_mut() {
            // Normalize incoming SSH bytes to canonical TUI sequences
            let canonical = tui_core::input::canonicalize(data);

            // Filter out DSR response if we requested it (cursor position report)
            // \x1b[<row>;<col>R
            if canonical.starts_with(b"\x1b[") && canonical.ends_with(b"R") {
                return Ok(());
            }

            let action = app_session
                .handle_input(&canonical)
                .map_err(|e| russh::Error::IO(std::io::Error::other(e)))?;
            self.process_action(action, session, channel).await?;
        }
        self.touch_session();
        Ok(())
    }

    fn touch_session(&self) {
        if let (Some(user_id), Some(session_number)) = (self.user_id, self.session_number) {
            let relay_id = self.active_relay_id.unwrap_or(0);
            let registry = self.registry.clone();
            tokio::spawn(async move {
                if let Some(session) = registry.get_session(user_id, relay_id, session_number).await {
                    session.touch().await;
                }
            });
        }
    }
}
