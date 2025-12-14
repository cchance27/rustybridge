//! Query filters for searching audit events.

use super::EventCategory;
use serde::{Deserialize, Serialize};

/// Query filter for searching audit events with various criteria.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventFilter {
    /// Filter by actor user ID
    pub actor_id: Option<i64>,
    /// If true, filter to only events where actor_id IS NULL
    pub actor_is_null: bool,
    /// Filter by event category
    pub category: Option<EventCategory>,
    /// Filter by specific action types (e.g., ["user_created", "user_deleted"])
    pub action_types: Option<Vec<String>>,
    /// Filter by resource ID
    pub resource_id: Option<String>,
    /// Filter by minimum timestamp (Unix milliseconds)
    pub start_time: Option<i64>,
    /// Filter by maximum timestamp (Unix milliseconds)
    pub end_time: Option<i64>,
    /// Filter by session ID
    pub session_id: Option<String>,
    /// Filter by multiple session IDs (OR logic)
    pub session_ids: Option<Vec<String>>,
    /// If true, filter to only events where session_id IS NULL or empty
    pub session_is_null: bool,
    /// Filter by parent session ID (e.g. relay session ID for terminal sessions)
    pub parent_session_id: Option<String>,
    /// Maximum number of results to return
    pub limit: Option<i64>,
    /// Number of results to skip (for pagination)
    pub offset: Option<i64>,
}

impl EventFilter {
    /// Create a new empty filter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder: Filter by actor ID.
    pub fn with_actor(mut self, actor_id: i64) -> Self {
        self.actor_id = Some(actor_id);
        self
    }

    /// Builder: Filter by category.
    pub fn with_category(mut self, category: EventCategory) -> Self {
        self.category = Some(category);
        self
    }

    /// Builder: Filter by action types.
    pub fn with_action_types(mut self, action_types: Vec<String>) -> Self {
        self.action_types = Some(action_types);
        self
    }

    /// Builder: Filter by resource ID.
    pub fn with_resource_id(mut self, resource_id: impl Into<String>) -> Self {
        self.resource_id = Some(resource_id.into());
        self
    }

    /// Builder: Filter by time range.
    pub fn with_time_range(mut self, start: i64, end: i64) -> Self {
        self.start_time = Some(start);
        self.end_time = Some(end);
        self
    }

    /// Builder: Set result limit.
    pub fn with_limit(mut self, limit: i64) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Builder: Set result offset for pagination.
    pub fn with_offset(mut self, offset: i64) -> Self {
        self.offset = Some(offset);
        self
    }

    /// Builder: Filter by parent session ID.
    pub fn with_parent_session_id(mut self, parent_session_id: impl Into<String>) -> Self {
        self.parent_session_id = Some(parent_session_id.into());
        self
    }
    /// Builder: Filter by multiple session IDs.
    pub fn with_session_ids(mut self, session_ids: Vec<String>) -> Self {
        self.session_ids = Some(session_ids);
        self
    }
}
