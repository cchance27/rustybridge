//! SSH authentication handler methods.

use std::borrow::Cow;

use rb_types::{
    audit::{AuthMethod, EventType}, auth::{AuthDecision, LoginTarget}
};
use russh::server::Auth;
use tracing::{error, info, warn};

use super::{ServerHandler, display_addr};
use crate::auth::{
    authenticate_password, parse_login_target, ssh_auth::{
        check_ssh_auth_session, create_ssh_auth_session, mark_ssh_auth_session_used, reject_ssh_auth_session, verify_user_public_key
    }
};

impl ServerHandler {
    pub(super) fn oidc_failed_prompt() -> Auth {
        Auth::Partial {
            name: Cow::Borrowed(""),
            instructions: Cow::Borrowed("OIDC Failed\r\n"),
            prompts: Cow::Owned(vec![]),
        }
    }

    pub(super) async fn handle_auth_password(&mut self, user: &str, password: &str) -> Result<Auth, russh::Error> {
        let login: LoginTarget = parse_login_target(user);

        // Attempt to resolve user_id early for better audit logging, even if auth fails later
        if let Ok(handle) = state_store::server_db().await {
            let pool = handle.into_pool();
            if let Ok(uid) = state_store::fetch_user_id_by_name(&pool, &login.username).await {
                self.user_id = uid;
            }
        }

        let decision = authenticate_password(&login, password)
            .await
            .map_err(|e| russh::Error::IO(std::io::Error::other(e)))?;

        match decision {
            AuthDecision::Accept => {
                self.username = Some(login.username.clone());
                self.relay_target = login.relay.clone();

                let connection_id = self.connection_session_id.clone().unwrap_or_else(|| {
                    let cf = uuid::Uuid::now_v7().to_string();
                    self.connection_session_id = Some(cf.clone());
                    cf
                });

                self.log_audit_event(EventType::LoginSuccess {
                    method: AuthMethod::Password,
                    connection_id,
                    username: login.username.clone(),
                    client_type: rb_types::audit::ClientType::Ssh,
                })
                .await;

                info!(
                    peer = %display_addr(self.peer_addr),
                    user = %login.username,
                    relay = %login.relay.as_deref().unwrap_or("<none>"),
                    "password authentication accepted"
                );
                Ok(Auth::Accept)
            }
            AuthDecision::Reject => {
                self.log_audit_event(EventType::LoginFailure {
                    method: AuthMethod::Password,
                    reason: "invalid credentials".to_string(),
                    username: Some(login.username.clone()),
                    client_type: rb_types::audit::ClientType::Ssh,
                })
                .await;

                warn!(
                    peer = %display_addr(self.peer_addr),
                    user = %login.username,
                    "password authentication rejected"
                );
                Ok(Auth::reject())
            }
        }
    }

    pub(super) async fn handle_auth_publickey(&mut self, user: &str, public_key: &russh::keys::PublicKey) -> Result<Auth, russh::Error> {
        let login = parse_login_target(user);

        // Attempt to resolve user_id early for better audit logging
        if let Ok(handle) = state_store::server_db().await {
            let pool = handle.into_pool();
            if let Ok(uid) = state_store::fetch_user_id_by_name(&pool, &login.username).await {
                self.user_id = uid;
            }
        }

        let key_bytes = match public_key.to_bytes() {
            Ok(b) => b,
            Err(e) => {
                error!(error = %e, "failed to encode ssh key");
                return Ok(Auth::reject());
            }
        };

        // Check if it's a certificate (future enhancement)
        if let Ok(parsed_key) = ssh_key::PublicKey::from_bytes(&key_bytes)
            && parsed_key.algorithm().as_str().contains("-cert-")
        {
            error!("ssh certificate auth attempted but CA not configured");
            return Ok(Auth::reject());
        }

        // Standard public key authentication
        match verify_user_public_key(&login.username, &key_bytes).await {
            Ok(true) => {
                self.username = Some(login.username.clone());
                self.relay_target = login.relay.clone();

                let connection_id = self.connection_session_id.clone().unwrap_or_else(|| {
                    let cf = uuid::Uuid::now_v7().to_string();
                    self.connection_session_id = Some(cf.clone());
                    cf
                });

                self.log_audit_event(EventType::LoginSuccess {
                    method: AuthMethod::PublicKey,
                    connection_id,
                    username: login.username.clone(),
                    client_type: rb_types::audit::ClientType::Ssh,
                })
                .await;

                info!(
                    peer = %display_addr(self.peer_addr),
                    user = %login.username,
                    "public key authentication accepted"
                );
                Ok(Auth::Accept)
            }
            Ok(false) => {
                self.log_audit_event(EventType::LoginFailure {
                    method: AuthMethod::PublicKey,
                    reason: "key not found".to_string(),
                    username: Some(login.username.clone()),
                    client_type: rb_types::audit::ClientType::Ssh,
                })
                .await;

                warn!(
                    peer = %display_addr(self.peer_addr),
                    user = %login.username,
                    "public key authentication rejected (key not found)"
                );
                Ok(Auth::reject())
            }
            Err(e) => {
                error!(error = %e, "failed to verify public key");
                Ok(Auth::reject())
            }
        }
    }

    pub(super) async fn handle_auth_keyboard_interactive(
        &mut self,
        user: &str,
        _submethods: &str,
        response: Option<russh::server::Response<'_>>,
    ) -> Result<Auth, russh::Error> {
        use rb_types::auth::ssh::SshAuthStatus;
        use russh::server::Auth;

        let login = parse_login_target(user);

        if self.deny_keyboard_interactive {
            if !self.ssh_auth_failure_banner_sent {
                // Send a one-time failure notice so the client sees why OIDC ended
                self.ssh_auth_failure_banner_sent = true;
                return Ok(Self::oidc_failed_prompt());
            }
            return Ok(Auth::reject());
        }

        // First call: no response yet, create session and send auth URL
        if response.is_none() && self.pending_ssh_auth_code.is_none() {
            match create_ssh_auth_session(&login.username).await {
                Ok(session) => {
                    let prompt = format!("\nAuthenticate via OIDC:\n{}\n\nWaiting for authentication...", session.auth_url);

                    // Store session code
                    self.pending_ssh_auth_code = Some(session.code);
                    self.ssh_auth_message_shown = true;

                    info!(
                        peer = %display_addr(self.peer_addr),
                        user = %login.username,
                        "ssh oidc keyboard-interactive session created"
                    );

                    return Ok(Auth::Partial {
                        name: Cow::Borrowed("OIDC Authentication"),
                        instructions: Cow::Owned(prompt),
                        prompts: Cow::Owned(vec![]),
                    });
                }
                Err(e) => {
                    error!(error = %e, "failed to create ssh auth session");
                    return Ok(Auth::reject());
                }
            }
        }

        // Subsequent calls: check status once and yield; avoids long blocking so disconnects are observed promptly.
        if let Some(code) = &self.pending_ssh_auth_code {
            // Rate-limit polling to avoid tight loops and CPU churn.
            const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(1000);
            let now = std::time::Instant::now();
            if let Some(last) = self.last_ssh_auth_check {
                let elapsed = now.duration_since(last);
                if elapsed < POLL_INTERVAL {
                    tokio::time::sleep(POLL_INTERVAL - elapsed).await;
                }
            }
            self.last_ssh_auth_check = Some(std::time::Instant::now());

            match check_ssh_auth_session(code).await {
                Ok(Some(session)) => match session.status {
                    SshAuthStatus::Authenticated(auth_user_id) => {
                        if auth_user_id == session.requested_user_id {
                            // One-time consume on success
                            if let Err(e) = mark_ssh_auth_session_used(code, auth_user_id).await {
                                error!(error = %e, "failed to mark ssh auth session as used");
                                return Ok(Auth::reject());
                            }

                            self.username = Some(login.username.clone());
                            self.relay_target = login.relay.clone();
                            self.pending_ssh_auth_code = None;
                            self.last_ssh_auth_check = None;
                            self.ssh_auth_message_shown = false;

                            // Set user_id so log_audit_event can produce a full context
                            self.user_id = Some(auth_user_id);

                            let connection_id = self.connection_session_id.clone().unwrap_or_else(|| {
                                let cf = uuid::Uuid::now_v7().to_string();
                                self.connection_session_id = Some(cf.clone());
                                cf
                            });

                            self.log_audit_event(EventType::LoginSuccess {
                                method: AuthMethod::Oidc,
                                connection_id,
                                username: login.username.clone(),
                                client_type: rb_types::audit::ClientType::Ssh,
                            })
                            .await;

                            info!(
                                peer = %display_addr(self.peer_addr),
                                user = %login.username,
                                user_id = %auth_user_id,
                                "oidc keyboard-interactive authentication accepted"
                            );
                            return Ok(Auth::Accept);
                        } else {
                            // Mismatch: reject and invalidate the session
                            if let Err(e) = reject_ssh_auth_session(code, Some(auth_user_id)).await {
                                error!(error = %e, "failed to reject mismatched ssh auth session");
                            }

                            self.pending_ssh_auth_code = None;
                            self.last_ssh_auth_check = None;
                            self.ssh_auth_message_shown = false;

                            warn!(
                                    peer = %display_addr(self.peer_addr),
                                    requested_user = %login.username,
                                requested_user_id = %session.requested_user_id,
                                authenticated_user_id = %auth_user_id,
                                "oidc authentication user mismatch for ssh login"
                            );
                            self.deny_keyboard_interactive = true;
                            if !self.ssh_auth_failure_banner_sent {
                                self.ssh_auth_failure_banner_sent = true;
                                return Ok(Self::oidc_failed_prompt());
                            }
                            return Ok(Auth::reject());
                        }
                    }
                    SshAuthStatus::Rejected | SshAuthStatus::Expired | SshAuthStatus::Used | SshAuthStatus::Abandoned => {
                        self.pending_ssh_auth_code = None;
                        self.last_ssh_auth_check = None;
                        self.ssh_auth_message_shown = false;
                        self.deny_keyboard_interactive = true;
                        warn!(
                            peer = %display_addr(self.peer_addr),
                            user = %login.username,
                            "oidc authentication rejected or expired"
                        );
                        if !self.ssh_auth_failure_banner_sent {
                            self.ssh_auth_failure_banner_sent = true;
                            return Ok(Self::oidc_failed_prompt());
                        }
                        return Ok(Auth::reject());
                    }
                    SshAuthStatus::Pending => {
                        // Still waiting: don't re-prompt; just return Partial with empty fields.
                        return Ok(Auth::Partial {
                            name: Cow::Borrowed(""),
                            instructions: Cow::Borrowed(""),
                            prompts: Cow::Owned(vec![]),
                        });
                    }
                },
                Ok(None) => {
                    // Session disappeared (expired/cleaned/invalid code) — no chance to succeed
                    self.pending_ssh_auth_code = None;
                    self.last_ssh_auth_check = None;
                    self.ssh_auth_message_shown = false;
                    self.deny_keyboard_interactive = true;
                    warn!(
                        peer = %display_addr(self.peer_addr),
                        user = %login.username,
                        "oidc ssh auth session missing or expired"
                    );
                    if !self.ssh_auth_failure_banner_sent {
                        self.ssh_auth_failure_banner_sent = true;
                        return Ok(Self::oidc_failed_prompt());
                    }
                    return Ok(Auth::reject());
                }
                Err(e) => {
                    error!(error = %e, "failed to check ssh auth session");
                    self.pending_ssh_auth_code = None;
                    self.last_ssh_auth_check = None;
                    self.ssh_auth_message_shown = false;
                    self.deny_keyboard_interactive = true;
                    if !self.ssh_auth_failure_banner_sent {
                        self.ssh_auth_failure_banner_sent = true;
                        return Ok(Self::oidc_failed_prompt());
                    }
                    return Ok(Auth::reject());
                }
            }
        }

        // Fallback: no session code available
        Ok(Auth::reject())
    }

    pub(super) async fn handle_auth_succeeded(&mut self) -> Result<(), russh::Error> {
        info!(
            peer = %display_addr(self.peer_addr),
            user = %self.username.as_deref().unwrap_or("<unknown>"),
            "user authenticated"
        );

        // Record SSH connection to audit DB
        if let (Some(user_id), Some(peer_addr)) = (self.user_id, self.peer_addr) {
            let registry = self.registry.clone();
            let ip_address = peer_addr.ip().to_string();

            // Generate connection ID and record metadata
            match crate::record_ssh_connection(&registry, user_id, ip_address, None, self.connection_session_id.clone()).await {
                Ok(conn_id) => {
                    info!(conn_id = %conn_id, "recorded ssh connection");
                    self.connection_session_id = Some(conn_id);
                }
                Err(e) => {
                    error!(error = %e, "failed to record ssh connection");
                }
            }
        }

        Ok(())
    }

    /// Check if the current user has management access (any *:view claim or wildcard).
    pub(super) async fn check_management_access(username: &str) -> (bool, Option<i64>) {
        if let Ok(handle) = state_store::server_db().await {
            let pool = handle.into_pool();
            if let Ok(mut conn) = pool.acquire().await {
                if let Some(uid) = state_store::fetch_user_id_by_name(&mut *conn, username).await.ok().flatten() {
                    if let Ok(claims) = state_store::get_user_claims_by_id(&mut conn, uid).await {
                        let can_manage = claims.iter().any(|c| {
                            let claim_str = c.to_string();
                            claim_str == "*" || claim_str.ends_with(":view")
                        });
                        return (can_manage, Some(uid));
                    } else {
                        return (false, Some(uid));
                    }
                } else {
                    return (false, None);
                }
            }
        }
        (false, None)
    }
}
