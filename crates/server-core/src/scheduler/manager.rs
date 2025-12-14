//! TaskManager - central scheduler controller.

use super::{TaskConfig, executor, registry::TaskRegistry};
use futures::future::BoxFuture;
use rb_types::tasks::*;
use sqlx::{Pool, Sqlite};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;
use tokio_cron_scheduler::{Job, JobScheduler};
use tracing::info;
use uuid::Uuid;

type TaskFactory = Arc<dyn Fn() -> BoxFuture<'static, Result<(), String>> + Send + Sync + 'static>;

struct TaskDefinition {
    name: String,
    #[allow(dead_code)]
    description: String,
    default_schedule: CronSchedule,
    config: TaskConfig,
    factory: TaskFactory,
}

/// Central task scheduler with monitoring capabilities.
#[derive(Clone)]
pub struct TaskManager {
    scheduler: JobScheduler,
    registry: Arc<RwLock<TaskRegistry>>,
    pool: Pool<Sqlite>,
    definitions: Arc<RwLock<HashMap<TaskId, TaskDefinition>>>,
    job_map: Arc<RwLock<HashMap<TaskId, Uuid>>>,
}

impl TaskManager {
    /// Create new task manager (call once at server startup).
    pub async fn new(pool: Pool<Sqlite>) -> Result<Self, TaskError> {
        let scheduler = JobScheduler::new().await.map_err(|e| TaskError::Scheduler(e.to_string()))?;
        let registry = Arc::new(RwLock::new(TaskRegistry::new(50)));

        Ok(Self {
            scheduler,
            registry,
            pool,
            definitions: Arc::new(RwLock::new(HashMap::new())),
            job_map: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Register a cron-scheduled task.
    pub async fn register<F, Fut, E>(
        &self,
        name: impl Into<String>,
        description: impl Into<String>,
        schedule: CronSchedule,
        config: TaskConfig,
        task_fn: F,
    ) -> Result<TaskId, TaskError>
    where
        F: Fn() -> Fut + Send + Sync + 'static + Clone,
        Fut: std::future::Future<Output = Result<(), E>> + Send + 'static,
        E: std::fmt::Display + Send + 'static,
    {
        let name_str = name.into();
        let desc_str = description.into();
        let default_schedule = schedule.clone();

        let task_fn_clone = task_fn.clone();
        let factory: TaskFactory = Arc::new(move || {
            let fut = task_fn_clone();
            Box::pin(async move { fut.await.map_err(|e| e.to_string()) })
        });

        let (active_schedule, enabled) = self.load_overrides(&name_str, &default_schedule).await;

        let id = TaskId::new();

        {
            let mut defs = self.definitions.write().await;
            defs.insert(
                id.clone(),
                TaskDefinition {
                    name: name_str.clone(),
                    description: desc_str.clone(),
                    default_schedule,
                    config: config.clone(),
                    factory: factory.clone(),
                },
            );
        }

        {
            let mut reg = self.registry.write().await;
            reg.register(id.clone(), name_str.clone(), desc_str.clone(), active_schedule.to_string());
            if !enabled {
                reg.update_state(&id, TaskState::Paused);
            }
        }

        if enabled {
            self.schedule_job_dynamic(&id, &name_str, &active_schedule, &config, &factory)
                .await?;
        }

        Ok(id)
    }

    /// Pause a task (remove from scheduler, persist state).
    pub async fn pause_task(&self, id: &TaskId) -> Result<(), TaskError> {
        let name = {
            let defs = self.definitions.read().await;
            let def = defs.get(id).ok_or_else(|| TaskError::NotFound(id.clone()))?;
            def.name.clone()
        };

        self.unschedule_job(id).await?;

        {
            let mut reg = self.registry.write().await;
            reg.update_state(id, TaskState::Paused);
        }

        state_store::set_server_option(&self.pool, &format!("task:{}:enabled", name), "false")
            .await
            .map_err(|e| TaskError::Scheduler(format!("DB error: {}", e)))?;

        info!(task = name, "task paused");
        Ok(())
    }

    /// Resume a task (add to scheduler, persist state).
    pub async fn resume_task(&self, id: &TaskId) -> Result<(), TaskError> {
        let (name, schedule, config, factory) = {
            let defs = self.definitions.read().await;
            let def = defs.get(id).ok_or_else(|| TaskError::NotFound(id.clone()))?;
            let (sched, _) = self.load_overrides(&def.name, &def.default_schedule).await;
            (def.name.clone(), sched, def.config.clone(), def.factory.clone())
        };

        self.schedule_job_dynamic(id, &name, &schedule, &config, &factory).await?;

        {
            let mut reg = self.registry.write().await;
            reg.update_state(id, TaskState::Idle);
            reg.update_schedule(id, schedule.to_string());
        }

        state_store::set_server_option(&self.pool, &format!("task:{}:enabled", name), "true")
            .await
            .map_err(|e| TaskError::Scheduler(format!("DB error: {}", e)))?;

        info!(task = name, "task resumed");
        Ok(())
    }

    /// Update task schedule.
    pub async fn update_schedule(&self, id: &TaskId, new_schedule: CronSchedule) -> Result<(), TaskError> {
        let (name, config, factory, was_running) = {
            let defs = self.definitions.read().await;
            let def = defs.get(id).ok_or_else(|| TaskError::NotFound(id.clone()))?;
            let map = self.job_map.read().await;
            let running = map.contains_key(id);
            (def.name.clone(), def.config.clone(), def.factory.clone(), running)
        };

        state_store::set_server_option(&self.pool, &format!("task:{}:schedule", name), new_schedule.as_str())
            .await
            .map_err(|e| TaskError::Scheduler(format!("DB error: {}", e)))?;

        if was_running {
            self.unschedule_job(id).await?;
            self.schedule_job_dynamic(id, &name, &new_schedule, &config, &factory).await?;
        }

        {
            let mut reg = self.registry.write().await;
            reg.update_schedule(id, new_schedule.to_string());
        }

        info!(task = name, schedule = %new_schedule, "task rescheduled");
        Ok(())
    }

    /// Trigger task immediately (fire and forget).
    pub async fn trigger_task(&self, id: &TaskId) -> Result<(), TaskError> {
        let (name, config, factory) = {
            let defs = self.definitions.read().await;
            let def = defs.get(id).ok_or_else(|| TaskError::NotFound(id.clone()))?;
            (def.name.clone(), def.config.clone(), def.factory.clone())
        };

        let registry = self.registry.clone();
        let id = id.clone();

        info!(task = name, "manual task trigger initiated");

        tokio::spawn(async move {
            {
                let mut reg = registry.write().await;
                reg.update_state(&id, TaskState::Running);
            }

            let outcome = executor::execute_with_middleware(&name, &config, move || factory()).await;

            {
                let mut reg = registry.write().await;
                reg.record_outcome(&id, outcome);
            }
        });

        Ok(())
    }

    async fn unschedule_job(&self, id: &TaskId) -> Result<(), TaskError> {
        let job_uuid = {
            let mut map = self.job_map.write().await;
            map.remove(id)
        };

        if let Some(uuid) = job_uuid {
            self.scheduler
                .remove(&uuid)
                .await
                .map_err(|e| TaskError::Scheduler(e.to_string()))?;
        }
        Ok(())
    }

    async fn schedule_job_dynamic(
        &self,
        id: &TaskId,
        name: &str,
        schedule: &CronSchedule,
        config: &TaskConfig,
        factory: &TaskFactory,
    ) -> Result<(), TaskError> {
        let task_name = name.to_string();
        let registry_clone = self.registry.clone();
        let id_clone = id.clone();
        let config_clone = config.clone();
        let factory_inner = factory.clone();

        let job = Job::new_async(schedule.as_str(), move |_uuid, _l| {
            let task_name = task_name.clone();
            let registry = registry_clone.clone();
            let id = id_clone.clone();
            let config = config_clone.clone();
            let factory_inner = factory_inner.clone();

            Box::pin(async move {
                {
                    let mut reg = registry.write().await;
                    reg.update_state(&id, TaskState::Running);
                }
                info!(task = task_name, "task starting");

                let outcome = executor::execute_with_middleware(&task_name, &config, move || factory_inner()).await;

                {
                    let mut reg = registry.write().await;
                    reg.record_outcome(&id, outcome);
                }
            })
        })
        .map_err(|e| TaskError::Scheduler(e.to_string()))?;

        let scheduler = self.scheduler.clone();
        let job_uuid = scheduler.add(job).await.map_err(|e| TaskError::Scheduler(e.to_string()))?;

        let mut map = self.job_map.write().await;
        map.insert(id.clone(), job_uuid);

        Ok(())
    }

    async fn load_overrides(&self, name: &str, default_schedule: &CronSchedule) -> (CronSchedule, bool) {
        let schedule_key = format!("task:{}:schedule", name);
        let enabled_key = format!("task:{}:enabled", name);

        let schedule = match state_store::get_server_option(&self.pool, &schedule_key).await {
            Ok(Some(s)) => CronSchedule::parse(&s).unwrap_or(default_schedule.clone()),
            _ => default_schedule.clone(),
        };

        let enabled = match state_store::get_server_option(&self.pool, &enabled_key).await {
            Ok(Some(s)) => s != "false",
            _ => true,
        };

        (schedule, enabled)
    }

    /// Start the scheduler.
    pub async fn start(&self) -> Result<(), TaskError> {
        let scheduler = self.scheduler.clone();
        scheduler.start().await.map_err(|e| TaskError::Scheduler(e.to_string()))?;
        Ok(())
    }

    /// Graceful shutdown.
    pub async fn shutdown(&self) -> Result<(), TaskError> {
        info!("shutting down task scheduler");
        let mut scheduler = self.scheduler.clone();
        scheduler.shutdown().await.map_err(|e| TaskError::Scheduler(e.to_string()))?;
        Ok(())
    }

    /// List all tasks with current state and computed next-run times.
    pub async fn list_tasks(&self) -> Vec<TaskSummary> {
        use std::str::FromStr;
        let reg = self.registry.read().await;
        let mut summaries = reg.list_summaries();

        let map = self.job_map.read().await;
        let now = chrono::Utc::now();
        for summary in &mut summaries {
            if map.contains_key(&summary.id)
                && let Ok(cron) = croner::Cron::from_str(&summary.schedule_display)
                && let Ok(next) = cron.find_next_occurrence(&now, false)
            {
                summary.next_run = Some(next);
            }
        }
        summaries
    }

    /// Get a single task's summary by ID.
    pub async fn get_task(&self, task_id: &TaskId) -> Option<TaskSummary> {
        use std::str::FromStr;
        let reg = self.registry.read().await;
        let mut summary = reg.get_summary(task_id)?;

        let map = self.job_map.read().await;
        if map.contains_key(task_id)
            && let Ok(cron) = croner::Cron::from_str(&summary.schedule_display)
            && let Ok(next) = cron.find_next_occurrence(&chrono::Utc::now(), false)
        {
            summary.next_run = Some(next);
        }

        Some(summary)
    }
}
