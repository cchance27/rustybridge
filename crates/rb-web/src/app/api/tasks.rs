//! Task scheduler admin API endpoints.

use crate::error::ApiError;
use dioxus::prelude::*;
use rb_types::tasks::{TaskId, TaskSummary, ToggleTaskRequest, UpdateTaskScheduleRequest};
#[cfg(feature = "server")]
use {
    crate::server::auth::guards::{WebAuthSession, ensure_claim},
    rb_types::auth::{ClaimLevel, ClaimType},
    rb_types::tasks::CronSchedule,
};

/// List all registered scheduled tasks with their current state.
#[get(
    "/api/admin/tasks/list",
    auth: WebAuthSession
)]
pub async fn list_tasks() -> Result<Vec<TaskSummary>, ApiError> {
    ensure_claim(&auth, &ClaimType::Server(ClaimLevel::View))?;

    let manager = server_core::scheduler::get_manager().ok_or_else(|| ApiError::internal("Scheduler not initialized"))?;

    Ok(manager.list_tasks().await)
}

/// Enable or disable a scheduled task.
#[post(
    "/api/admin/tasks/{id}/toggle",
    auth: WebAuthSession
)]
pub async fn toggle_task(id: TaskId, req: ToggleTaskRequest) -> Result<(), ApiError> {
    ensure_claim(&auth, &ClaimType::Server(ClaimLevel::Edit))?;

    let manager = server_core::scheduler::get_manager().ok_or_else(|| ApiError::internal("Scheduler not initialized"))?;

    if req.enabled {
        manager.resume_task(&id).await.map_err(|e| ApiError::internal(e.to_string()))?;
    } else {
        manager.pause_task(&id).await.map_err(|e| ApiError::internal(e.to_string()))?;
    }
    Ok(())
}

/// Update a task's cron schedule.
#[post(
    "/api/admin/tasks/{id}/schedule",
    auth: WebAuthSession
)]
pub async fn update_task_schedule(id: TaskId, req: UpdateTaskScheduleRequest) -> Result<(), ApiError> {
    ensure_claim(&auth, &ClaimType::Server(ClaimLevel::Edit))?;

    let cron = CronSchedule::parse(&req.schedule).map_err(|e| ApiError::bad_request(format!("Invalid cron: {}", e)))?;

    let manager = server_core::scheduler::get_manager().ok_or_else(|| ApiError::internal("Scheduler not initialized"))?;
    manager
        .update_schedule(&id, cron)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(())
}

/// Trigger immediate execution of a task (fire and forget).
#[post(
    "/api/admin/tasks/{id}/trigger",
    auth: WebAuthSession
)]
pub async fn trigger_task(id: TaskId) -> Result<(), ApiError> {
    ensure_claim(&auth, &ClaimType::Server(ClaimLevel::Edit))?;

    let manager = server_core::scheduler::get_manager().ok_or_else(|| ApiError::internal("Scheduler not initialized"))?;
    manager.trigger_task(&id).await.map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(())
}
