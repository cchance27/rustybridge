//! Scheduled Tasks admin page.

use crate::{
    app::{
        api::tasks::{list_tasks, toggle_task, trigger_task, update_task_schedule},
        components::{Layout, PageRefreshControls},
    },
    components::use_toast,
};
use chrono::Utc;
use dioxus::prelude::*;
use rb_types::tasks::{TaskOutcome, TaskState, TaskSummary, ToggleTaskRequest, UpdateTaskScheduleRequest};

#[component]
pub fn SystemTasks() -> Element {
    let mut tasks = use_resource(list_tasks);

    rsx! {
        Layout {
            div { class: "container mx-auto p-6",
                div { class: "flex justify-between items-center mb-6",
                    h1 { class: "text-3xl font-bold", "Scheduled Tasks" }
                    PageRefreshControls {
                        page_id: "scheduled-tasks".to_string(),
                        on_refresh: move |_| tasks.restart(),
                    }
                }

                match tasks() {
                    Some(Ok(list)) => rsx! {
                        div { class: "grid gap-6 md:grid-cols-2 xl:grid-cols-3",
                            for task in list.iter().cloned() {
                                TaskCard {
                                    task: task,
                                    on_refresh: move |_| tasks.restart()
                                }
                            }
                        }
                        if list.is_empty() {
                            div { class: "text-center opacity-50 py-10", "No scheduled tasks found." }
                        }
                    },
                    Some(Err(e)) => rsx! {
                        div { class: "alert alert-error", "Failed to load tasks: {e}" }
                    },
                    None => rsx! {
                        div { class: "flex justify-center p-10",
                            span { class: "loading loading-spinner loading-lg" }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn TaskCard(task: TaskSummary, on_refresh: EventHandler<()>) -> Element {
    let toast = use_toast();
    let mut is_editing = use_signal(|| false);
    let mut edit_schedule = use_signal(|| task.schedule_display.clone());

    // Toggle handler
    let handle_toggle = {
        let task_id = task.id.clone();
        let new_state = task.state == TaskState::Paused; // Toggle logic
        move |_| {
            let task_id = task_id.clone();
            let on_refresh = on_refresh;
            let toast = toast;
            spawn(async move {
                match toggle_task(task_id, ToggleTaskRequest { enabled: new_state }).await {
                    Ok(_) => {
                        toast.success(if new_state { "Task enabled" } else { "Task disabled" });
                        on_refresh.call(());
                    }
                    Err(e) => toast.error(&format!("Failed to toggle task: {}", e)),
                }
            });
        }
    };

    // Trigger handler
    let handle_trigger = {
        let task_id = task.id.clone();
        move |_| {
            let task_id = task_id.clone();
            let on_refresh = on_refresh;
            let toast = toast;
            spawn(async move {
                match trigger_task(task_id).await {
                    Ok(_) => {
                        toast.success("Task triggered");
                        on_refresh.call(());
                    }
                    Err(e) => toast.error(&format!("Failed to trigger task: {}", e)),
                }
            });
        }
    };

    // Save Schedule
    let handle_save_schedule = {
        let task_id = task.id.clone();
        move |_| {
            let task_id = task_id.clone();
            let schedule = edit_schedule();
            let on_refresh = on_refresh;
            let toast = toast;
            spawn(async move {
                match update_task_schedule(task_id, UpdateTaskScheduleRequest { schedule }).await {
                    Ok(_) => {
                        toast.success("Schedule updated");
                        is_editing.set(false);
                        on_refresh.call(());
                    }
                    Err(e) => toast.error(&format!("Failed to update schedule: {}", e)),
                }
            });
        }
    };

    let state_badge = match task.state {
        TaskState::Idle => "badge-ghost",
        TaskState::Running => "badge-info animate-pulse",
        TaskState::Paused => "badge-warning",
        TaskState::Failed => "badge-error",
    };

    rsx! {
        div { class: "card bg-base-200 shadow-sm",
            div { class: "card-body p-6",
                div { class: "flex justify-between items-start",
                    div {
                        h2 { class: "card-title text-base", "{task.name}" }
                        p { class: "text-xs opacity-60", "{task.description}" }
                    }
                    div { class: "badge {state_badge}", "{task.state}" }
                }

                div { class: "divider my-2" }

                div { class: "space-y-3",
                    // Controls Row
                    div { class: "flex justify-between items-center rounded-lg bg-base-300 p-2",
                        // Enable/Disable Switch
                        div { class: "form-control",
                            label { class: "label cursor-pointer gap-2",
                                span { class: "label-text text-xs font-bold", "Enabled" }
                                input {
                                    type: "checkbox",
                                    class: "toggle toggle-xs toggle-success",
                                    checked: task.state != TaskState::Paused,
                                    onchange: handle_toggle
                                }
                            }
                        }

                        // Action Buttons
                        div { class: "flex gap-2",
                             // Run Now
                             button {
                                 class: "btn btn-xs btn-circle btn-ghost",
                                 title: "Run Now",
                                 disabled: task.state == TaskState::Running,
                                 onclick: handle_trigger,
                                 svg { class: "h-4 w-4 text-success", fill: "none", view_box: "0 0 24 24", stroke: "currentColor",
                                     path { stroke_linecap: "round", stroke_linejoin: "round", stroke_width: "2", d: "M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" }
                                     path { stroke_linecap: "round", stroke_linejoin: "round", stroke_width: "2", d: "M21 12a9 9 0 11-18 0 9 9 0 0118 0z" }
                                 }
                             }
                        }
                    }

                    // Schedule Row
                    div { class: "flex items-center justify-between text-xs",
                        span { "Schedule:" }
                        if is_editing() {
                            div { class: "flex items-center gap-1",
                                input {
                                    class: "input input-bordered input-xs w-32 font-mono",
                                    value: "{edit_schedule}",
                                    oninput: move |e| edit_schedule.set(e.value())
                                }
                                button { class: "btn btn-xs btn-square btn-success", onclick: handle_save_schedule, "✓" }
                                button { class: "btn btn-xs btn-square btn-ghost", onclick: move |_| is_editing.set(false), "✕" }
                            }
                        } else {
                            div {
                                class: "tooltip tooltip-left group flex items-center gap-2 cursor-pointer",
                                "data-tip": "{task.schedule_display}",
                                onclick: move |_| is_editing.set(true),
                                span { class: "font-bold", "{task.schedule_human}" }
                                span { class: "hidden group-hover:inline opacity-50", "✎" }
                            }
                        }
                    }

                    // Next Run & Stats
                    div { class: "text-xs space-y-1 opacity-80",
                        div { class: "flex justify-between font-mono",
                            span { "Next Run:" }
                            span {
                                {
                                    if let Some(next) = &task.next_run {
                                         let now = Utc::now();
                                         let duration = *next - now;
                                         let secs = duration.num_seconds();
                                         if secs < 0 {
                                              "Due now".to_string()
                                         } else if secs < 60 {
                                              format!("{}s", secs)
                                         } else if secs < 3600 {
                                              let mins = secs / 60;
                                              let remaining_secs = secs % 60;
                                              format!("{}m {}s", mins, remaining_secs)
                                         } else if secs < 86400 {
                                              let hours = secs / 3600;
                                              let mins = (secs % 3600) / 60;
                                              format!("{}h {}m", hours, mins)
                                         } else {
                                              next.format("%Y-%m-%d %H:%M").to_string()
                                         }
                                    } else if task.state == TaskState::Paused {
                                        "Paused".to_string()
                                    } else {
                                        "Unknown".to_string()
                                    }
                                }
                            }
                        }
                        div { class: "flex justify-between",
                             span { "Last Run:" }
                             span {
                                 if let Some(run) = &task.last_run {
                                     match &run.outcome {
                                         TaskOutcome::Success { duration_ms } => rsx!{ span { class: "text-success", "Success ({duration_ms}ms)" } },
                                         TaskOutcome::Failed { .. } => rsx!{ span { class: "text-error", "Failed" } },
                                         TaskOutcome::TimedOut { .. } => rsx!{ span { class: "text-warning", "Timed Out" } },
                                         TaskOutcome::Panicked { .. } => rsx!{ span { class: "text-error font-bold", "Panic" } },
                                         TaskOutcome::Skipped { .. } => rsx!{ span { class: "opacity-50", "Skipped" } },
                                     }
                                 } else {
                                     span { class: "opacity-50", "Never" }
                                 }
                             }
                        }
                        div { class: "flex justify-between",
                            span { "Runs / Failures:" }
                            span { "{task.run_count} / {task.failure_count}" }
                        }
                    }
                }

                // History Visualization
                div { class: "mt-4 pt-2 border-t border-base-content/10",
                    div { class: "text-xs mb-2 opacity-50 block", "History (Last 25)" }
                    div { class: "flex gap-1 justify-end",
                        // Render last 10 runs or placeholders
                        {
                            let max_dots: usize = 25;
                            let history = &task.history;
                            let count = history.len();
                            let empty = max_dots.saturating_sub(count);
                            let to_show = if count > max_dots { max_dots } else { count };

                            // Render empty dots (oldest/future) - Darker/more visible
                            rsx! {
                                for _ in 0..empty {
                                    div { class: "w-2 h-2 rounded-full bg-base-content/20" }
                                }
                                // Render actual runs (oldest to newest)
                                // history is newest-first. So take(to_show), then reverse iterator.
                                for run in history.iter().take(to_show).rev() {
                                    {
                                        let tooltip_content = match &run.outcome {
                                            TaskOutcome::Success { duration_ms } => format!("Success in {}ms", duration_ms),
                                            TaskOutcome::Failed { error, duration_ms } => format!("Failed after {}ms: {}", duration_ms, error),
                                            TaskOutcome::TimedOut { timeout_secs } => format!("Timed out after {}s", timeout_secs),
                                            TaskOutcome::Panicked { message } => format!("Panic: {}", message),
                                            TaskOutcome::Skipped { reason } => format!("Skipped: {}", reason),
                                        };
                                        let tooltip_title = run.started_at.to_rfc2822();

                                        let color_class = match &run.outcome {
                                            TaskOutcome::Success { .. } => "bg-success",
                                            TaskOutcome::Failed { .. } => "bg-error",
                                            TaskOutcome::TimedOut { .. } => "bg-warning",
                                            TaskOutcome::Panicked { .. } => "bg-error animate-pulse",
                                            TaskOutcome::Skipped { .. } => "bg-base-content/30",
                                        };

                                        rsx! {
                                            div {
                                                class: "tooltip tooltip-primary",
                                                "data-tip": "{tooltip_title}: {tooltip_content}",
                                                div { class: "w-2 h-2 rounded-full {color_class}" }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
