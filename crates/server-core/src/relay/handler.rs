//! Handler for relay connections.
//!
//! This module contains the shared handler used for all relay connections.

use russh::{client, keys};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

pub type WarningCallback = std::sync::Arc<dyn Fn(String) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> + Send + Sync>;

pub struct SharedRelayHandler {
    pub expected_key: Option<String>,
    pub relay_name: String,
    pub warning_callback: WarningCallback,
    pub action_tx: Option<UnboundedSender<tui_core::AppAction>>,
    pub auth_rx: Option<std::sync::Arc<tokio::sync::Mutex<UnboundedReceiver<String>>>>,
}

impl client::Handler for SharedRelayHandler {
    type Error = russh::Error;

    fn check_server_key(
        &mut self,
        server_public_key: &keys::PublicKey,
    ) -> impl std::future::Future<Output = std::result::Result<bool, Self::Error>> + Send {
        let expected = self.expected_key.clone();
        let callback = self.warning_callback.clone();
        let key_str_res = server_public_key.to_openssh().map(|k| k.to_string());

        async move {
            let key_str = match key_str_res {
                Ok(k) => k,
                Err(_) => return Ok(false),
            };

            if let Some(ref exp) = expected
                && key_str != *exp
            {
                callback(format!("HOST KEY MISMATCH: expected '{}', got '{}'", exp, key_str)).await;
                return Ok(false);
            }
            Ok(true)
        }
    }
}
