use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum SessionStatus {
    Connecting,
    Connected,
    Closed,
    Error(String),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WindowGeometry {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub relay_name: String,
    pub relay_id: Option<i64>,
    pub title: String,
    pub status: SessionStatus,
    pub minimized: bool,
    pub fullscreen: bool,
    pub geometry: WindowGeometry,
    pub started_at: DateTime<Utc>,
    pub thumbnail_data_url: Option<String>,
    // Add a field to track last focus time for z-index management
    pub last_focused_at: DateTime<Utc>,
    // Cached z-index to avoid recalculation on every render
    pub z_index: usize,
    // Optional backend SSH session number used for detach/reattach across browsers
    pub session_number: Option<u32>,
    // Track number of active connections to this session (for multi-viewer support)
    pub active_connections: u32,
    // Track number of active viewers (non-minimized windows)
    pub active_viewers: u32,
    // Whether this session can be attached to from the web (web-origin vs ssh-origin)
    pub attachable: bool,
}

impl Session {
    pub fn new(relay_name: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            title: format!("SSH: {}", relay_name), // Initial title, can be updated later
            relay_name,
            relay_id: None, // Will be set when session_number is received
            status: SessionStatus::Connecting,
            minimized: false,
            fullscreen: false,
            geometry: WindowGeometry {
                x: 100,
                y: 100,
                width: 800,
                height: 600,
            },
            started_at: Utc::now(),
            thumbnail_data_url: None,
            last_focused_at: Utc::now(),
            z_index: 60, // Default base z-index
            session_number: None,
            active_connections: 1, // Default to 1 (this connection)
            active_viewers: 1,     // Default to 1 (this connection)
            attachable: true,      // New windows opened from web are attachable
        }
    }
}
