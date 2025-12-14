//! Task registry for tracking stats and history.

use chrono::Utc;
use rb_types::tasks::*;
use std::collections::{HashMap, VecDeque};

/// Default history depth if not configured in server_options.
const DEFAULT_MAX_HISTORY: usize = 50;

/// In-memory registry tracking task metadata, state, and execution history.
pub struct TaskRegistry {
    tasks: HashMap<TaskId, TaskEntry>,
    max_history: usize,
}

struct TaskEntry {
    name: String,
    description: String,
    schedule_display: String,
    state: TaskState,
    run_count: u64,
    failure_count: u64,
    last_run: Option<TaskRunRecord>,
    history: VecDeque<TaskRunRecord>,
}

impl TaskRegistry {
    /// Create a new registry with specified history depth per task.
    pub fn new(max_history: usize) -> Self {
        Self {
            tasks: HashMap::new(),
            max_history: if max_history == 0 { DEFAULT_MAX_HISTORY } else { max_history },
        }
    }

    /// Register a new task entry.
    pub fn register(&mut self, id: TaskId, name: String, description: String, schedule_display: String) {
        self.tasks.insert(
            id,
            TaskEntry {
                name,
                description,
                schedule_display,
                state: TaskState::Idle,
                run_count: 0,
                failure_count: 0,
                last_run: None,
                history: VecDeque::with_capacity(self.max_history),
            },
        );
    }

    /// Update task state (Idle, Running, Paused, Failed).
    pub fn update_state(&mut self, id: &TaskId, state: TaskState) {
        if let Some(entry) = self.tasks.get_mut(id) {
            entry.state = state;
        }
    }

    /// Update the displayed schedule string.
    pub fn update_schedule(&mut self, id: &TaskId, schedule: String) {
        if let Some(entry) = self.tasks.get_mut(id) {
            entry.schedule_display = schedule;
        }
    }

    /// Record a task execution outcome and update history.
    pub fn record_outcome(&mut self, id: &TaskId, outcome: TaskOutcome) {
        if let Some(entry) = self.tasks.get_mut(id) {
            let now = Utc::now();
            let record = TaskRunRecord {
                started_at: now,
                outcome: outcome.clone(),
            };

            entry.run_count += 1;
            entry.last_run = Some(record.clone());
            entry.state = match outcome {
                TaskOutcome::Success { .. } => TaskState::Idle,
                _ => {
                    entry.failure_count += 1;
                    TaskState::Failed
                }
            };

            entry.history.push_front(record);
            if entry.history.len() > self.max_history {
                entry.history.pop_back();
            }
        }
    }

    /// Build a summary for a single task.
    pub fn get_summary(&self, id: &TaskId) -> Option<TaskSummary> {
        use std::str::FromStr;
        self.tasks.get(id).map(|entry| {
            // Use croner to generate human-readable description
            let schedule_human = croner::Cron::from_str(&entry.schedule_display)
                .map(|c| c.pattern.describe())
                .unwrap_or_else(|_| {
                    tracing::warn!("Invalid cron schedule: {}", entry.schedule_display);
                    entry.schedule_display.clone()
                });
            TaskSummary {
                id: id.clone(),
                name: entry.name.clone(),
                description: entry.description.clone(),
                schedule_display: entry.schedule_display.clone(),
                schedule_human,
                state: entry.state,
                last_run: entry.last_run.clone(),
                next_run: None, // Filled manager side using scheduler
                run_count: entry.run_count,
                failure_count: entry.failure_count,
                history: entry.history.iter().cloned().collect(),
            }
        })
    }

    /// List summaries for all registered tasks.
    pub fn list_summaries(&self) -> Vec<TaskSummary> {
        self.tasks.keys().filter_map(|id| self.get_summary(id)).collect()
    }

    /// Get task name by ID.
    pub fn get_name(&self, id: &TaskId) -> Option<String> {
        self.tasks.get(id).map(|e| e.name.clone())
    }
}
