//! Session backend abstraction for unified I/O handling.
//!
//! This module provides trait-based abstractions for session I/O backends,
//! allowing sessions to be created from and attached to by both web and SSH clients.

use std::sync::Arc;

use tokio::sync::{broadcast, mpsc};

use crate::relay::RelayHandle;

/// Errors that can occur in session backend operations
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("Backend is closed")]
    BackendClosed,
    #[error("Send failed: {0}")]
    SendFailed(String),
    #[error("Resize failed: {0}")]
    ResizeFailed(String),
}

/// Mouse event for terminal interaction (future use)
#[derive(Debug, Clone)]
pub struct MouseEvent {
    pub x: u16,
    pub y: u16,
    pub button: MouseButton,
    pub action: MouseAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseButton {
    Left,
    Middle,
    Right,
    WheelUp,
    WheelDown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseAction {
    Press,
    Release,
    Move,
}

/// Trait for session I/O backends (Web, SSH, or unified)
///
/// This trait abstracts the underlying transport mechanism, allowing sessions
/// to work with both WebSocket and SSH channel backends transparently.
pub trait SessionBackend: Send + Sync {
    /// Send data to the backend (user input -> relay)
    fn send(&self, data: Vec<u8>) -> Result<(), SessionError>;

    /// Subscribe to data from the backend (relay output -> clients)
    /// Returns a broadcast receiver that can be cloned for multiple viewers
    fn subscribe(&self) -> broadcast::Receiver<Vec<u8>>;

    /// Send resize event to the backend
    fn resize(&self, cols: u32, rows: u32) -> Result<(), SessionError>;

    /// Send mouse event (for future TUI mouse support)
    fn mouse_event(&self, event: MouseEvent) -> Result<(), SessionError>;

    /// Close the backend connection
    fn close(&self) -> Result<(), SessionError>;
}

/// Legacy backend that wraps existing mpsc/broadcast channels for backward compatibility
/// This allows gradual migration of existing code to the new backend system
pub struct LegacyChannelBackend {
    input_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    output_tx: broadcast::Sender<Vec<u8>>,
}

impl LegacyChannelBackend {
    pub fn new(input_tx: tokio::sync::mpsc::Sender<Vec<u8>>, output_tx: broadcast::Sender<Vec<u8>>) -> Self {
        Self { input_tx, output_tx }
    }
}

impl SessionBackend for LegacyChannelBackend {
    fn send(&self, data: Vec<u8>) -> Result<(), SessionError> {
        self.input_tx
            .blocking_send(data)
            .map_err(|e| SessionError::SendFailed(e.to_string()))
    }

    fn subscribe(&self) -> broadcast::Receiver<Vec<u8>> {
        self.output_tx.subscribe()
    }

    fn resize(&self, _cols: u32, _rows: u32) -> Result<(), SessionError> {
        // Legacy backend doesn't support resize
        // This will be handled by the old code path
        Ok(())
    }

    fn mouse_event(&self, _event: MouseEvent) -> Result<(), SessionError> {
        // Legacy backend doesn't support mouse events
        Ok(())
    }

    fn close(&self) -> Result<(), SessionError> {
        // Closing handled by old code path
        Ok(())
    }
}

/// Unified backend that manages relay channel + broadcast for multi-viewer support
pub struct RelayBackend {
    /// Handle to the relay connection
    relay_handle: Arc<RelayHandle>,
    /// Broadcast channel for distributing output to multiple viewers
    output_broadcast: broadcast::Sender<Vec<u8>>,
    /// Channel for sending resize events to the relay loop
    resize_tx: mpsc::Sender<(u32, u32)>,
}

impl RelayBackend {
    /// Create a new RelayBackend
    ///
    /// # Arguments
    /// * `relay_handle` - Handle to the established relay connection
    /// * `resize_tx` - Channel for sending resize events to the relay loop
    pub fn new(relay_handle: RelayHandle, resize_tx: mpsc::Sender<(u32, u32)>) -> Self {
        // Create broadcast channel with reasonable buffer (100 messages)
        let (output_broadcast, _) = broadcast::channel(100);

        Self {
            relay_handle: Arc::new(relay_handle),
            output_broadcast,
            resize_tx,
        }
    }

    /// Get a reference to the output broadcast sender
    /// This is used by the relay loop to broadcast output to all viewers
    pub fn output_tx(&self) -> broadcast::Sender<Vec<u8>> {
        self.output_broadcast.clone()
    }

    /// Get the input sender for the relay
    /// This is used to send user input to the relay connection
    pub fn input_tx(&self) -> mpsc::UnboundedSender<Vec<u8>> {
        self.relay_handle.input_tx.clone()
    }
}

impl SessionBackend for RelayBackend {
    fn send(&self, data: Vec<u8>) -> Result<(), SessionError> {
        self.relay_handle
            .input_tx
            .send(data)
            .map_err(|e| SessionError::SendFailed(e.to_string()))
    }

    fn subscribe(&self) -> broadcast::Receiver<Vec<u8>> {
        self.output_broadcast.subscribe()
    }

    fn resize(&self, cols: u32, rows: u32) -> Result<(), SessionError> {
        self.resize_tx
            .blocking_send((cols, rows))
            .map_err(|e| SessionError::ResizeFailed(e.to_string()))
    }

    fn mouse_event(&self, _event: MouseEvent) -> Result<(), SessionError> {
        // TODO: Implement mouse event forwarding when needed
        // For now, this is a no-op as mouse events aren't yet supported
        Ok(())
    }

    fn close(&self) -> Result<(), SessionError> {
        // Signal EOF to all subscribers and close input to stop the relay loop
        let _ = self.output_broadcast.send(Vec::new());
        let _ = self.relay_handle.input_tx.send(Vec::new());
        Ok(())
    }
}
