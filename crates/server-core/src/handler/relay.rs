//! Relay connection establishment and management.

use std::{collections::HashMap, sync::Arc};

use russh::{ChannelId, CryptoVec, server::Session};
use secrecy::ExposeSecret;
use tokio::sync::{mpsc::unbounded_channel, oneshot};
use tracing::warn;

use super::{ServerHandler, display_addr};
use crate::{
    relay::start_bridge, secrets::{SecretBoxedString, decrypt_string_if_encrypted, encrypt_string}
};

impl ServerHandler {
    pub(super) async fn connect_to_relay(
        &mut self,
        session: &mut Session,
        channel: ChannelId,
        relay_name: &str,
    ) -> Result<(), russh::Error> {
        use state_store::{fetch_relay_host_by_name, fetch_relay_host_options, server_db, user_has_relay_access};
        let username = self.username.clone().unwrap_or_else(|| "<unknown>".into());
        match server_db().await {
            Ok(handle) => {
                let pool = handle.into_pool();
                match fetch_relay_host_by_name(&pool, relay_name).await {
                    Ok(Some(host)) => {
                        // First fetch user_id
                        let user_id_result = state_store::fetch_user_id_by_name(&pool, &username).await;
                        let user_id = match user_id_result {
                            Ok(Some(id)) => id,
                            Ok(None) => {
                                let _ = self.send_line(session, channel, &format!("user '{}' not found", username));
                                return self.handle_exit(session, channel);
                            }
                            Err(err) => {
                                let _ = self.send_line(session, channel, &format!("internal error looking up user: {err}"));
                                return self.handle_exit(session, channel);
                            }
                        };

                        match user_has_relay_access(&pool, user_id, host.id).await {
                            Ok(true) => {
                                let _ = self.send_line(
                                    session,
                                    channel,
                                    &format!("user authenticated; connecting to relay host '{}'...", relay_name),
                                );
                                let options = match fetch_relay_host_options(&pool, host.id).await {
                                    Ok(raw) => {
                                        // Decrypt any encrypted option values.
                                        let mut out = HashMap::with_capacity(raw.len());
                                        for (k, (v, is_secure)) in raw.into_iter() {
                                            if is_secure {
                                                match decrypt_string_if_encrypted(&v) {
                                                    Ok((val, is_legacy)) => {
                                                        if is_legacy {
                                                            warn!("Upgrading legacy v1 secret for relay option '{}'", k);
                                                            if let Ok(new_enc) = encrypt_string(SecretBoxedString::new(Box::new(
                                                                val.expose_secret().to_string(),
                                                            ))) {
                                                                let _ = sqlx::query("UPDATE relay_host_options SET value = ? WHERE relay_host_id = ? AND key = ?")
                                                                    .bind(new_enc)
                                                                    .bind(host.id)
                                                                    .bind(&k)
                                                                    .execute(&pool)
                                                                    .await;
                                                            }
                                                        }
                                                        out.insert(k, val);
                                                    }
                                                    Err(err) => {
                                                        let _ = self.send_line(
                                                            session,
                                                            channel,
                                                            &format!("internal error decrypting option '{k}': {err}"),
                                                        );
                                                        return self.handle_exit(session, channel);
                                                    }
                                                }
                                            } else {
                                                out.insert(k, SecretBoxedString::new(Box::new(v)));
                                            }
                                        }
                                        out
                                    }
                                    Err(err) => {
                                        let _ = self.send_line(session, channel, &format!("internal error loading relay options: {err}"));
                                        return self.handle_exit(session, channel);
                                    }
                                };
                                let server_handle = session.handle();
                                let server_handle_for_prompt = server_handle.clone();
                                let server_handle_for_error = server_handle.clone();
                                let size_rx = self.size_updates.subscribe();
                                let initial_size = self.view_size();
                                let (auth_tx, auth_rx) = unbounded_channel();
                                self.auth_tx = Some(auth_tx.clone());
                                let action_tx = self.action_tx.clone();
                                let peer = self.peer_addr;
                                let options_arc = Arc::new(options);
                                let host_clone = host.clone();
                                let username_clone = username.clone();

                                // Spawn background connect; result delivered via oneshot
                                let (tx_done, rx_done) = oneshot::channel();
                                tokio::spawn(async move {
                                    let res = start_bridge(
                                        server_handle,
                                        channel,
                                        &host_clone,
                                        &username_clone,
                                        initial_size,
                                        size_rx,
                                        options_arc.as_ref(),
                                        peer,
                                        Some(action_tx),
                                        Some(tokio::sync::Mutex::new(auth_rx)),
                                        Some((server_handle_for_prompt, channel)),
                                    )
                                    .await
                                    .map(|h| (h, auth_tx));

                                    match res {
                                        Ok(ok) => {
                                            let _ = tx_done.send(Ok(ok));
                                        }
                                        Err(e) => {
                                            // Inform client immediately
                                            let mut payload = CryptoVec::new();
                                            payload.extend(format!("failed to start relay: {e}\r\n").as_bytes());
                                            let _ = server_handle_for_error.data(channel, payload).await;
                                            let _ = server_handle_for_error.close(channel).await;
                                            let _ = tx_done.send(Err(russh::Error::IO(std::io::Error::other(e))));
                                        }
                                    }
                                });

                                self.prompt_sink_active = true;
                                self.pending_relay = Some(rx_done);

                                // Drain any immediate AuthPrompt actions queued during connect spawn
                                while let Ok(action) = self.action_rx.try_recv() {
                                    if let tui_core::AppAction::AuthPrompt { prompt, echo } = action {
                                        if !self.prompt_sink_active {
                                            let _ = self.send_bytes(session, channel, prompt.as_bytes());
                                            if echo {
                                                let _ = self.send_bytes(session, channel, b" ");
                                            }
                                        }
                                        self.pending_auth = Some(super::AuthPromptState { buffer: Vec::new(), echo });
                                    } else {
                                        // re-queue other actions by pushing back into action_rx? drop for now
                                    }
                                }
                                Ok(())
                            }
                            Ok(false) => {
                                warn!(
                                    peer = %display_addr(self.peer_addr),
                                    user = %username,
                                    relay = %relay_name,
                                    "relay access denied for user"
                                );
                                let _ = self.send_line(
                                    session,
                                    channel,
                                    &format!("access denied: user '{}' is not permitted to connect to '{}'", username, relay_name),
                                );
                                self.handle_exit(session, channel)
                            }
                            Err(err) => {
                                let _ = self.send_line(session, channel, &format!("internal error checking access: {err}"));
                                self.handle_exit(session, channel)
                            }
                        }
                    }
                    Ok(None) => {
                        warn!(
                            peer = %display_addr(self.peer_addr),
                            user = %username,
                            relay = %relay_name,
                            "relay host not found"
                        );
                        let _ = self.send_line(session, channel, &format!("unknown relay host '{}'", relay_name));
                        self.handle_exit(session, channel)
                    }
                    Err(err) => {
                        let _ = self.send_line(session, channel, &format!("internal error resolving relay host: {err}"));
                        self.handle_exit(session, channel)
                    }
                }
            }
            Err(err) => {
                let _ = self.send_line(session, channel, &format!("internal error opening server database: {err}"));
                self.handle_exit(session, channel)
            }
        }
    }
}
