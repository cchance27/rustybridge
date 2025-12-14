//! Session Timeline API
//!
//! Provides endpoints for fetching session timeline data for visualization.

use crate::error::ApiError;
use dioxus::prelude::*;
use serde::{Deserialize, Serialize};
#[cfg(feature = "server")]
use {
    crate::server::auth::guards::{WebAuthSession, ensure_claim},
    rb_types::auth::{ClaimLevel, ClaimType},
};

// ==== Types ====

/// Session metadata for timeline header
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct SessionInfo {
    pub session_id: String,
    pub username: Option<String>,
    pub user_id: i64,
    pub relay_name: Option<String>,
    pub relay_id: i64,
    pub session_number: i64,
    pub start_time: i64,
    pub end_time: Option<i64>,
    pub status: String,
}

/// A single event on the timeline
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct TimelineEvent {
    pub id: String,
    pub timestamp: i64,
    pub event_type: String,
    pub track: String,
    pub label: String,
    pub end_timestamp: Option<i64>,
    pub details: serde_json::Value,
}

/// Complete timeline data for a session
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct RelaySessionTimelineData {
    pub session_info: SessionInfo,
    pub events: Vec<TimelineEvent>,
}

// ==== API Endpoint ====

#[cfg(feature = "server")]
fn ensure_audit_claim(auth: &WebAuthSession, level: ClaimLevel) -> Result<(), ApiError> {
    ensure_claim(auth, &ClaimType::Server(level))
}

/// Get timeline data for a specific session
#[post("/api/audit/relay_session/{session_id}/timeline", auth: WebAuthSession)]
pub async fn get_relay_session_timeline(session_id: String) -> Result<RelaySessionTimelineData, ApiError> {
    ensure_audit_claim(&auth, ClaimLevel::View)?;

    // 1. Get session info from recorded sessions
    let session_record = server_core::api::get_session_summary(&session_id)
        .await
        .map_err(|e| ApiError::internal(format!("Session lookup failed: {}", e)))?
        .ok_or_else(|| ApiError::NotFound {
            kind: "Session".to_string(),
            identifier: session_id.clone(),
        })?;

    let session_info = SessionInfo {
        session_id: session_record.id.clone(),
        username: session_record.username,
        user_id: session_record.user_id,
        relay_name: session_record.relay_name,
        relay_id: session_record.relay_id,
        session_number: session_record.session_number,
        start_time: session_record.start_time,
        end_time: session_record.end_time,
        status: if session_record.end_time.is_some() { "Ended" } else { "Active" }.to_string(),
    };

    // 2. Query connection IDs that participated in this relay session
    let connection_ids = server_core::api::get_session_participant_connection_ids(&session_id)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to get participants: {}", e)))?;

    // 3. Query events for all connection IDs
    let mut all_events: Vec<rb_types::audit::AuditEvent> = Vec::new();

    if !connection_ids.is_empty()
        && let Ok(events) = server_core::audit::query_events_by_session_ids(connection_ids, Some(1000)).await
    {
        all_events.extend(events);
    }

    // 4. Also query for lifecycle events (SessionTimedOut, SessionForceClosed) that reference
    // this relay session by its ID in the event_type data. These are logged by the cleanup job
    // with a system context (no connection ID), so they won't be found by the connection query.
    if let Ok(lifecycle_events) = server_core::audit::query_events_by_relay_session_id(&session_id, Some(100)).await {
        // Only add events that aren't already in our list (avoid duplicates)
        // Collect to owned strings to avoid borrow issues
        let existing_ids: std::collections::HashSet<String> = all_events.iter().map(|e| e.id.clone()).collect();
        for event in lifecycle_events {
            if !existing_ids.contains(&event.id) {
                all_events.push(event);
            }
        }
    }

    // 4. Transform events into timeline format
    let mut timeline_events: Vec<TimelineEvent> = all_events
        .into_iter()
        .map(|e| {
            let (track, label) = categorize_event(&e);
            TimelineEvent {
                id: e.id,
                timestamp: e.timestamp,
                event_type: e.event_type.action_type().to_string(),
                track: track.to_string(),
                label,
                end_timestamp: None, // Will be matched with end events below
                details: serde_json::to_value(&e.event_type).unwrap_or_default(),
            }
        })
        .collect();

    // Sort by timestamp
    timeline_events.sort_by_key(|e| e.timestamp);

    // Match start/end events for spans (connections, viewers)
    match_span_events(&mut timeline_events);

    Ok(RelaySessionTimelineData {
        session_info,
        events: timeline_events,
    })
}

/// Categorize an event into track and label
#[cfg(feature = "server")]
fn categorize_event(event: &rb_types::audit::AuditEvent) -> (&'static str, String) {
    use rb_types::audit::EventType;

    match &event.event_type {
        // Lifecycle track
        EventType::SessionStarted { relay_name, .. } => ("lifecycle", format!("Session started on {}", relay_name)),
        EventType::SessionEnded { .. } => ("lifecycle", "Session ended".to_string()),
        EventType::SessionForceClosed { reason, .. } => ("lifecycle", format!("Force closed: {}", reason)),

        // Connections track
        EventType::SessionRelayConnected { username, .. } => ("connections", format!("{} connected", username)),
        EventType::SessionRelayDisconnected { username, .. } => ("connections", format!("{} disconnected", username)),

        // Viewers track
        EventType::SessionViewerJoined { username, .. } => ("viewers", format!("{} started viewing", username)),
        EventType::SessionViewerLeft { username, .. } => ("viewers", format!("{} stopped viewing", username)),

        // Events track (misc)
        EventType::SessionResized { cols, rows, .. } => ("events", format!("Resized to {}x{}", cols, rows)),

        // Login events that may be associated with session
        EventType::LoginSuccess { username, .. } => ("lifecycle", format!("{} logged in", username)),
        EventType::Logout { username, reason, .. } => ("lifecycle", format!("{} logged out: {}", username, reason)),

        // Timeout events
        EventType::SessionTimedOut { reason, .. } => ("lifecycle", format!("Session timed out ({})", reason)),

        // Other events
        EventType::SessionTransferToRelay { relay_name, .. } => ("lifecycle", format!("Transferred to {}", relay_name)),
        _ => ("events", event.event_type.action_type().replace('_', " ")),
    }
}

/// Match start/end events to create spans
/// Uses session_id from event details to uniquely identify each connection
#[cfg(feature = "server")]
fn match_span_events(events: &mut [TimelineEvent]) {
    use std::collections::HashMap;

    // Track open spans by session_id (connection_id) from event details
    // Key: session_id from the event details, Value: index in events vec
    let mut open_connections: HashMap<String, usize> = HashMap::new();
    let mut open_viewers: HashMap<String, usize> = HashMap::new();

    for i in 0..events.len() {
        let event = &events[i];

        // Extract session_id from event details - this is the connection UUID
        let session_id = event.details.get("session_id").and_then(|v| v.as_str()).map(|s| s.to_string());

        match event.event_type.as_str() {
            "session_relay_connected" => {
                if let Some(sid) = &session_id {
                    open_connections.insert(sid.clone(), i);
                }
            }
            "session_relay_disconnected" => {
                if let Some(sid) = &session_id
                    && let Some(start_idx) = open_connections.remove(sid)
                {
                    // Set end_timestamp on the start event
                    events[start_idx].end_timestamp = Some(events[i].timestamp);
                }
            }
            "session_viewer_joined" => {
                if let Some(sid) = &session_id {
                    open_viewers.insert(sid.clone(), i);
                }
            }
            "session_viewer_left" => {
                if let Some(sid) = &session_id
                    && let Some(start_idx) = open_viewers.remove(sid)
                {
                    events[start_idx].end_timestamp = Some(events[i].timestamp);
                }
            }
            "session_started" => {
                // For lifecycle, session_id in the event is the connection that started
                if let Some(sid) = &session_id {
                    open_connections.insert(format!("lifecycle_{}", sid), i);
                }
            }
            "session_ended" | "session_timed_out" => {
                if let Some(sid) = &session_id
                    && let Some(start_idx) = open_connections.remove(&format!("lifecycle_{}", sid))
                {
                    events[start_idx].end_timestamp = Some(events[i].timestamp);
                }
            }
            _ => {}
        }
    }
}
