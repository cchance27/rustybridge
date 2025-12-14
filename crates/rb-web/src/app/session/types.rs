use chrono::{DateTime, Utc};
use rb_types::ssh::ConnectionAmounts;
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
    // Track connections and viewers broken down by origin
    pub connections: ConnectionAmounts,
    pub viewers: ConnectionAmounts,
    // Whether this session can be attached to from the web (web-origin vs ssh-origin)
    pub attachable: bool,
    // Optional target user ID for attaching to other users' sessions (requires admin claim)
    pub target_user_id: Option<i64>,
    // Whether this is an admin-attached session (viewing another user's session)
    pub is_admin_attached: bool,
    // Username of the user whose session is being attached to (for admin attach)
    pub attached_to_username: Option<String>,
    // List of admin user IDs currently viewing this session
    pub admin_viewers: Vec<i64>,
}

impl Session {
    pub fn new(relay_name: String) -> Self {
        Self {
            id: uuid::Uuid::now_v7().to_string(),
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
            connections: ConnectionAmounts { web: 1, ssh: 0 },
            viewers: ConnectionAmounts { web: 1, ssh: 0 },
            attachable: true, // New windows opened from web are attachable
            target_user_id: None,
            is_admin_attached: false,
            attached_to_username: None,
            admin_viewers: Vec::new(),
        }
    }
}
