use dioxus::prelude::*;
use uuid::Uuid;

#[derive(Clone, PartialEq, Debug)]
pub enum ToastType {
    Success,
    Error,
    Warning,
    Info,
}

#[derive(Clone, PartialEq, Debug)]
pub struct ToastMessage {
    pub id: String,
    pub message: String,
    pub toast_type: ToastType,
    pub count: u32,
    pub duration: u64,
}

#[derive(Clone, Copy)]
pub struct ToastContext {
    toasts: Signal<Vec<ToastMessage>>,
}

impl ToastContext {
    pub fn new(toasts: Signal<Vec<ToastMessage>>) -> Self {
        Self { toasts }
    }

    pub fn add(&self, message: String, toast_type: ToastType, duration_ms: Option<u64>) {
        let id = Uuid::new_v4().to_string();
        let duration_ms = duration_ms.unwrap_or(5000); // Default 5s
        let mut toasts = self.toasts; // Copy the Signal

        {
            let mut current_toasts = toasts.write();

            // Check for duplicate message to group
            if let Some(existing) = current_toasts
                .iter_mut()
                .find(|t| t.message == message && t.toast_type == toast_type)
            {
                existing.count += 1;
                // Reset timer logic would be complex here without individual timers,
                // for now we just increment count.
                // Ideally we'd extend the duration but the removal logic is separate.
                return;
            }

            current_toasts.push(ToastMessage {
                id: id.clone(),
                message,
                toast_type,
                count: 1,
                duration: duration_ms,
            });
        }

        // Spawn removal task
        spawn(async move {
            #[cfg(feature = "server")]
            tokio::time::sleep(tokio::time::Duration::from_millis(duration_ms)).await;
            #[cfg(feature = "web")]
            gloo_timers::future::TimeoutFuture::new(duration_ms as u32).await;
            toasts.write().retain(|t| t.id != id);
        });
    }

    pub fn success(&self, message: &str) {
        self.add(message.to_string(), ToastType::Success, None);
    }

    pub fn error(&self, message: &str) {
        self.add(message.to_string(), ToastType::Error, None);
    }

    pub fn warning(&self, message: &str) {
        self.add(message.to_string(), ToastType::Warning, None);
    }

    pub fn info(&self, message: &str) {
        self.add(message.to_string(), ToastType::Info, None);
    }

    pub fn remove(&self, id: &str) {
        let mut toasts = self.toasts; // Copy the Signal
        toasts.write().retain(|t| t.id != id);
    }
}

pub fn use_toast() -> ToastContext {
    // Use try_consume_context to avoid panicking if ToastProvider isn't available yet
    // This can happen during initial render before the provider is set up
    try_consume_context::<ToastContext>().unwrap_or_else(|| {
        // Fallback: create a dummy context with a signal that won't be used
        // This prevents panics but the toasts won't actually display
        ToastContext::new(use_signal(Vec::new))
    })
}

#[component]
pub fn ToastProvider(children: Element) -> Element {
    let toasts = use_signal(Vec::new);

    use_context_provider(|| ToastContext::new(toasts));

    rsx! {
        {children}
        ToastContainer {}
    }
}

#[component]
fn ToastContainer() -> Element {
    let toast_ctx = use_toast();
    let toasts = toast_ctx.toasts.read();

    if toasts.is_empty() {
        return rsx! {};
    }

    rsx! {
        div { class: "toast toast-bottom toast-end z-[9999] flex flex-col gap-2",
            for toast in toasts.iter() {
                ToastItem {
                    key: "{toast.id}",
                    toast: toast.clone()
                }
            }
        }
    }
}

#[component]
fn ToastItem(toast: ToastMessage) -> Element {
    let toast_ctx = use_toast();

    let alert_class = match toast.toast_type {
        ToastType::Success => "alert-success",
        ToastType::Error => "alert-error",
        ToastType::Warning => "alert-warning",
        ToastType::Info => "alert-info",
    };

    rsx! {
        div {
            class: "alert {alert_class} shadow-lg min-w-[300px] animate-in slide-in-from-right fade-in duration-300",
            style: "max-width: 30vw; word-wrap: break-word; white-space: normal;",

            div { class: "flex-1 flex items-center gap-2",
                if toast.count > 1 {
                    span { class: "badge badge-sm badge-ghost font-bold", "{toast.count}x" }
                }
                span { "{toast.message}" }
            }

            button {
                class: "btn btn-sm btn-circle btn-ghost ml-2",
                onclick: move |_| toast_ctx.remove(&toast.id),
                "✕"
            }
        }
    }
}
