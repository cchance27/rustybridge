//! Page refresh controls component with auto-refresh toggle and manual refresh button.
//! Persists auto-refresh preference to localStorage per page.

use crate::app::storage::{BrowserStorage, StorageType};
use dioxus::prelude::*;

/// Props for PageRefreshControls component
#[derive(Props, Clone, PartialEq)]
pub struct PageRefreshControlsProps {
    /// Unique identifier for this page (used for localStorage key)
    pub page_id: String,
    /// Refresh interval in milliseconds (default: 1000)
    #[props(default = 1000)]
    pub interval_ms: u64,
    /// Whether auto-refresh is enabled by default (default: false)
    #[props(default = false)]
    pub default_enabled: bool,
    /// Callback to trigger a refresh
    pub on_refresh: EventHandler<()>,
}

/// Reusable auto-refresh toggle + manual refresh button component.
///
/// Saves auto-refresh preference to localStorage using the `page_id` as key prefix.
///
/// # Example
/// ```rust
/// PageRefreshControls {
///     page_id: "scheduled-tasks".to_string(),
///     on_refresh: move |_| my_resource.restart(),
/// }
/// ```
#[component]
pub fn PageRefreshControls(props: PageRefreshControlsProps) -> Element {
    let storage_key = format!("rb-autorefresh-{}", props.page_id);
    let default_enabled = props.default_enabled;

    // Start with default value - will be updated from localStorage on client side
    let mut auto_refresh = use_signal(move || default_enabled);
    let mut initialized = use_signal(|| false);

    // Load state from localStorage on client side (runs after hydration)
    let storage_key_load = storage_key.clone();
    use_effect(move || {
        if !initialized() {
            let storage = BrowserStorage::new(StorageType::Local);
            if let Some(stored) = storage.get_json::<bool>(&storage_key_load) {
                auto_refresh.set(stored);
            }
            initialized.set(true);
        }
    });

    // Save state to localStorage when it changes (but only after initialization)
    let storage_key_save = storage_key.clone();
    use_effect(move || {
        if initialized() {
            let enabled = auto_refresh();
            let storage = BrowserStorage::new(StorageType::Local);
            let _ = storage.set_json(&storage_key_save, &enabled);
        }
    });

    // Auto-refresh loop
    let on_refresh = props.on_refresh;
    let interval_ms = props.interval_ms;
    use_effect(move || {
        spawn(async move {
            loop {
                #[cfg(feature = "server")]
                tokio::time::sleep(tokio::time::Duration::from_millis(interval_ms)).await;
                #[cfg(feature = "web")]
                gloo_timers::future::TimeoutFuture::new(interval_ms as u32).await;
                if auto_refresh() {
                    on_refresh.call(());
                }
            }
        });
    });

    let on_refresh_manual = props.on_refresh;

    rsx! {
        div { class: "flex items-center gap-3",
            // Auto-refresh toggle - only render interactive state after client init
            label { class: "label cursor-pointer gap-2",
                span { class: "label-text text-xs", "Auto-refresh" }
                if initialized() {
                    input {
                        type: "checkbox",
                        class: "toggle toggle-xs toggle-primary",
                        checked: auto_refresh(),
                        onchange: move |_| auto_refresh.set(!auto_refresh())
                    }
                } else {
                    // Show unchecked placeholder during SSR/hydration
                    input {
                        type: "checkbox",
                        class: "toggle toggle-xs toggle-primary",
                        checked: false,
                        disabled: true
                    }
                }
            }
            // Manual refresh button
            button {
                class: "btn btn-ghost btn-sm",
                title: "Refresh now",
                onclick: move |_| on_refresh_manual.call(()),
                svg { class: "h-4 w-4", fill: "none", view_box: "0 0 24 24", stroke: "currentColor",
                    path {
                        stroke_linecap: "round",
                        stroke_linejoin: "round",
                        stroke_width: "2",
                        d: "M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
                    }
                }
            }
        }
    }
}
