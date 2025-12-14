//! Relay connection establishment and management.

use super::{ServerHandler, display_addr};
use crate::{
    relay::start_bridge_backend,
    secrets::{SecretBoxedString, decrypt_string_if_encrypted, encrypt_string},
};
use rb_types::{relay::RelayInfo, ssh::ConnectionType};
use russh::{ChannelId, CryptoVec, server::Session};
use secrecy::ExposeSecret;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{mpsc::unbounded_channel, oneshot};
use tracing::{info, warn};

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
                                                            warn!(key = %k, "upgrading legacy v1 secret for relay option");
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
                                let server_handle_for_error = server_handle.clone();
                                let mut size_rx = self.size_updates.subscribe();
                                let view_size = self.view_size();
                                let initial_size = (view_size.0 as u32, view_size.1 as u32);
                                let (auth_tx, auth_rx) = unbounded_channel();
                                self.auth_tx = Some(auth_tx.clone());
                                let options_arc = Arc::new(options);
                                let username_clone = username.clone();
                                let ip_address = self.peer_addr.map(|addr| addr.ip().to_string());

                                // Convert to RelayInfo for start_bridge_backend
                                let relay_info = RelayInfo {
                                    id: host.id,
                                    name: host.name.clone(),
                                    ip: host.ip.clone(),
                                    port: host.port,
                                };

                                // We are transitioning out of the TUI; drop any existing TUI session (relay_id = 0)
                                // so dashboards don't show both the TUI and the active relay at once.
                                let tui_session_number = self.tui_session_number;
                                self.end_tui_session();

                                // Spawn background connect; result delivered via oneshot
                                let (tx_done, rx_done) = oneshot::channel();
                                let registry_clone = self.registry.clone();
                                let server_handle_for_bridge = server_handle.clone();
                                let connection_id = self.connection_session_id.clone();

                                tokio::spawn(async move {
                                    // Connect using unified backend
                                    let backend_result = start_bridge_backend(
                                        &relay_info,
                                        &username_clone,
                                        initial_size,
                                        options_arc.as_ref(),
                                        None, // No prompt_tx for SSH clients (prompts handled via action_tx)
                                        Some(Arc::new(tokio::sync::Mutex::new(auth_rx))),
                                    )
                                    .await;

                                    match backend_result {
                                        Ok((backend, initial_rx)) => {
                                            let backend = Arc::new(backend);
                                            let initial_rx_for_bridge = initial_rx;

                                            // Register session with unified backend
                                            let (session_number, ssh_session) = registry_clone
                                                .create_next_session(
                                                    user_id,
                                                    relay_info.id,
                                                    relay_info.name.clone(),
                                                    username_clone.clone(),
                                                    backend.clone(),
                                                    rb_types::ssh::SessionOrigin::Ssh { user_id },
                                                    ip_address.clone(),
                                                    None,
                                                    Some(initial_size),
                                                    connection_id.clone(),
                                                )
                                                .await;

                                            // Log SessionStarted audit event
                                            if let Some(conn_id) = &connection_id {
                                                // Use relay session UUID from recorder as the session_id in payloads
                                                let relay_session_id = ssh_session.recorder.session_id().to_string();
                                                // Use connection_id (UUID) as session_id in context - this is what timeline queries by
                                                let ctx = rb_types::audit::AuditContext::ssh(
                                                    user_id,
                                                    username_clone.clone(),
                                                    ip_address.clone().unwrap_or_else(|| "ssh".to_string()),
                                                    conn_id.clone(),
                                                    Some(relay_session_id.clone()),
                                                );

                                                // Log session transfer from TUI to relay (if we had a TUI session)
                                                if let Some(tui_num) = tui_session_number {
                                                    // TUI session doesn't have a relay session - use session number for now
                                                    let tui_session_str = format!("tui_session_{}", tui_num);
                                                    crate::audit!(
                                                        &ctx,
                                                        SessionTransferToRelay {
                                                            from_session_id: tui_session_str,
                                                            to_session_id: relay_session_id.clone(),
                                                            relay_name: relay_info.name.clone(),
                                                            relay_id: relay_info.id,
                                                            username: username_clone.clone(),
                                                            client_type: rb_types::audit::ClientType::Ssh,
                                                        }
                                                    );
                                                }

                                                crate::audit!(
                                                    &ctx,
                                                    SessionStarted {
                                                        session_id: relay_session_id.clone(),
                                                        relay_name: relay_info.name.clone(),
                                                        relay_id: relay_info.id,
                                                        username: username_clone.clone(),
                                                        client_type: rb_types::audit::ClientType::Ssh,
                                                    }
                                                );

                                                // Log relay connection and viewer joined
                                                crate::audit!(
                                                    &ctx,
                                                    SessionRelayConnected {
                                                        session_id: relay_session_id.clone(),
                                                        relay_id: relay_info.id,
                                                        relay_name: relay_info.name.clone(),
                                                        username: username_clone.clone(),
                                                        client_type: rb_types::audit::ClientType::Ssh,
                                                    }
                                                );

                                                crate::audit!(
                                                    &ctx,
                                                    SessionViewerJoined {
                                                        session_id: relay_session_id.clone(),
                                                        username: username_clone.clone(),
                                                        user_id,
                                                        is_admin: false,
                                                        client_type: rb_types::audit::ClientType::Ssh,
                                                    }
                                                );
                                            }

                                            // Track SSH connection + viewer
                                            ssh_session.increment_connection(rb_types::ssh::ConnectionType::Ssh).await;
                                            ssh_session.increment_viewers(rb_types::ssh::ConnectionType::Ssh).await;

                                            // Spawn bridge task to connect backend to SSH channel
                                            use crate::sessions::session_backend::SessionBackend;
                                            let backend_for_bridge = backend.clone();
                                            let session_for_bridge = ssh_session.clone();
                                            let session_id_for_log = connection_id.clone();
                                            let relay_name_for_log = relay_info.name.clone();
                                            let relay_id_for_log = relay_info.id;
                                            let username_for_log = username_clone.clone();
                                            let ip_address_for_log = ip_address.clone();

                                            tokio::spawn(async move {
                                                let mut output_rx = initial_rx_for_bridge;
                                                let mut close_rx = session_for_bridge.close_tx.subscribe();
                                                let mut relay_closed = false;
                                                let mut ping = tokio::time::interval(std::time::Duration::from_secs(5));
                                                ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

                                                loop {
                                                    tokio::select! {
                                                        // Force-close signal from admin
                                                        _ = close_rx.recv() => {
                                                            info!(
                                                                session_number = session_for_bridge.session_number,
                                                                "session force-closed, terminating SSH bridge"
                                                            );
                                                            let _ = server_handle_for_bridge.close(channel).await;
                                                            relay_closed = true;
                                                            break;
                                                        }
                                                        // Backend output -> SSH channel
                                                        Ok(data) = output_rx.recv() => {
                                                            if data.is_empty() {
                                                                // EOF from backend/relay - close the SSH channel but
                                                                // keep the shared session so web clients can observe
                                                                // the closed state and clean up gracefully.
                                                                let _ = server_handle_for_bridge.close(channel).await;
                                                                relay_closed = true;
                                                                break;
                                                            }
                                                            let mut payload = CryptoVec::new();
                                                            payload.extend(&data);
                                                            if server_handle_for_bridge.data(channel, payload).await.is_err() {
                                                                // SSH channel went away (client dropped) - stop
                                                                // trying to write to it, but don't treat this as
                                                                // a relay failure.
                                                                break;
                                                            }
                                                            // Append to history
                                                            session_for_bridge.touch().await;
                                                            session_for_bridge.append_to_history(&data).await;
                                                        }
                                                        // Resize events
                                                        Ok(_) = size_rx.changed() => {
                                                            let (cols, rows) = *size_rx.borrow();
                                                            let _ = backend_for_bridge.resize(cols as u32, rows as u32).await;
                                                        }

                                                        // Periodic ping to detect dropped SSH client channels while idle.
                                                        _ = ping.tick() => {
                                                            // Send an empty data packet; if the SSH channel is gone, this write will fail.
                                                            let payload = CryptoVec::new();
                                                            if server_handle_for_bridge.data(channel, payload).await.is_err() {
                                                                info!(
                                                                    session_number = session_for_bridge.session_number,
                                                                    "ssh_bridge_ping_failed; closing ssh side"
                                                                );
                                                                break;
                                                            }
                                                        }
                                                    }
                                                }

                                                // Decrement SSH connection + viewer counts when the SSH bridge ends.
                                                session_for_bridge.decrement_connection(ConnectionType::Ssh).await;
                                                session_for_bridge.decrement_viewers(ConnectionType::Ssh).await;

                                                // Log SSH client disconnect events ALWAYS when bridge ends
                                                // (even if web clients are still attached)
                                                if let Some(sid) = session_id_for_log.clone() {
                                                    let duration = (chrono::Utc::now() - session_for_bridge.created_at).num_milliseconds();
                                                    // Use relay session UUID from recorder as the session_id in payloads
                                                    let relay_session_id = session_for_bridge.recorder.session_id().to_string();
                                                    // Use connection_id (sid) as session_id in context - this is what timeline queries by
                                                    let ctx = rb_types::audit::AuditContext::ssh(
                                                        user_id,
                                                        username_for_log.clone(),
                                                        ip_address_for_log.clone().unwrap_or_else(|| "ssh".to_string()),
                                                        sid.clone(),
                                                        Some(relay_session_id.clone()),
                                                    );

                                                    // Log viewer left and relay disconnected for this SSH client
                                                    crate::audit!(
                                                        &ctx,
                                                        SessionViewerLeft {
                                                            session_id: relay_session_id.clone(),
                                                            username: username_for_log.clone(),
                                                            user_id,
                                                            is_admin: false,
                                                            duration_ms: duration,
                                                            client_type: rb_types::audit::ClientType::Ssh,
                                                        }
                                                    );

                                                    crate::audit!(
                                                        &ctx,
                                                        SessionRelayDisconnected {
                                                            session_id: relay_session_id.clone(),
                                                            relay_id: relay_id_for_log,
                                                            relay_name: relay_name_for_log.clone(),
                                                            username: username_for_log.clone(),
                                                            client_type: rb_types::audit::ClientType::Ssh,
                                                        }
                                                    );
                                                }

                                                // If the underlying relay actually closed, or there are no more
                                                // active connections of any type, then close and remove the session.
                                                let total_connections = session_for_bridge.connection_count();
                                                if relay_closed || total_connections == 0 {
                                                    session_for_bridge.close().await;
                                                    registry_clone.remove_session(user_id, relay_info.id, session_number).await;

                                                    // Log SessionEnded only when session is fully closing
                                                    if let Some(sid) = session_id_for_log {
                                                        let duration =
                                                            (chrono::Utc::now() - session_for_bridge.created_at).num_milliseconds();
                                                        let relay_session_id = session_for_bridge.recorder.session_id().to_string();
                                                        let ctx = rb_types::audit::AuditContext::ssh(
                                                            user_id,
                                                            username_for_log.clone(),
                                                            ip_address_for_log.clone().unwrap_or_else(|| "ssh".to_string()),
                                                            sid.clone(),
                                                            Some(relay_session_id.clone()),
                                                        );

                                                        crate::audit!(
                                                            &ctx,
                                                            SessionEnded {
                                                                session_id: relay_session_id,
                                                                relay_name: relay_name_for_log,
                                                                relay_id: relay_id_for_log,
                                                                username: username_for_log,
                                                                duration_ms: duration,
                                                                client_type: rb_types::audit::ClientType::Ssh,
                                                            }
                                                        );
                                                    }
                                                }
                                            });

                                            let _ = tx_done.send(Ok((session_number, auth_tx)));
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

                                // Store session info locally (will be set after backend connects)
                                self.user_id = Some(user_id);
                                self.active_relay_id = Some(host.id);

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
