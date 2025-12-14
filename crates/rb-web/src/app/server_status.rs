use crate::app::{auth::hooks::use_auth, components::use_toast};
use dioxus::{fullstack::use_websocket, prelude::*};
use tracing::debug;

#[derive(Clone, PartialEq, Debug)]
pub enum ConnectionState {
    Connected,
    Disconnected,
    Reconnecting,
}

#[derive(Clone, Copy)]
pub struct ServerStatusContext {
    pub state: Signal<ConnectionState>,
}

pub fn use_server_status() -> ServerStatusContext {
    use_context::<ServerStatusContext>()
}

#[component]
pub fn ServerStatusProvider(children: Element) -> Element {
    let state = use_signal(|| ConnectionState::Connected); // Assume connected initially
    let auth = use_auth();

    use_context_provider(|| ServerStatusContext { state });

    // Only monitor connection if user is authenticated
    // This prevents showing "Connection Lost" on login page
    let is_authenticated = auth.read().user.is_some();

    let current_state = state.read();
    let show_overlay = is_authenticated && *current_state != ConnectionState::Connected;

    rsx! {
        {children}

        if is_authenticated {
            ServerStatusMonitor { state }
        }

        if show_overlay {
            div {
                class: "fixed inset-0 bg-black/50 z-[9998] flex items-center justify-center backdrop-blur-sm",
                div {
                    class: "bg-[#1e1e1e] border border-red-500/50 rounded-lg p-6 shadow-2xl flex flex-col items-center gap-4 max-w-md text-center",
                    div { class: "loading loading-ring loading-lg text-error" }
                    div {
                        h3 { class: "text-xl font-bold text-white", "Connection Lost" }
                        p { class: "text-gray-400 mt-2",
                            "Attempting to reconnect to server..."
                        }
                    }
                }
            }
        }
    }
}

/// Dedicated child component so hook ordering stays stable while login state toggles.
#[component]
fn ServerStatusMonitor(state: Signal<ConnectionState>) -> Element {
    use crate::{app::api::ws::session_events::ssh_web_events, error::ApiError};
    use dioxus::fullstack::WebSocketOptions;

    let toast = use_toast();

    // Base connection; we'll manage reconnection ourselves.
    // Use a fixed client ID for status monitor to prevent duplicate registrations
    let mut ws = use_websocket(move || async move {
        debug!("server status monitor: opening websocket connection");
        ssh_web_events("status-monitor".to_string(), None, WebSocketOptions::new()).await
    });

    // Log component lifecycle for debugging
    use_effect(move || {
        debug!("server status monitor: mounted, websocket connection active");
    });

    use_coroutine(move |_rx: UnboundedReceiver<()>| async move {
        let mut delay_secs = 1u64;
        loop {
            match ws.recv().await {
                Ok(_) => {
                    // Any message (or initial connect) means the socket is healthy.
                    if *state.read() != ConnectionState::Connected {
                        state.set(ConnectionState::Connected);
                        toast.success("Connected to server");
                    }
                    // Reset backoff after a healthy message.
                    delay_secs = 1;
                }
                Err(_) => {
                    // Connection dropped or failed to establish.
                    if *state.read() == ConnectionState::Connected {
                        toast.error("Connection to server lost");
                    }

                    state.set(ConnectionState::Reconnecting);

                    // Actively retry with exponential backoff until we can recreate the socket.
                    loop {
                        match ssh_web_events("status-monitor".to_string(), None, WebSocketOptions::new()).await {
                            Ok(socket) => {
                                ws.set(Ok::<_, ApiError>(socket));
                                // We'll wait for the next Ok from `recv` before marking Connected.
                                break;
                            }
                            Err(_) => {
                                state.set(ConnectionState::Disconnected);
                                // FIXME: We do this in a few places to use tokio on server and gloo on web, we should refactor to a hook or helper or something.
                                #[cfg(feature = "server")]
                                tokio::time::sleep(tokio::time::Duration::from_secs(delay_secs)).await;
                                #[cfg(feature = "web")]
                                gloo_timers::future::TimeoutFuture::new(delay_secs as u32 * 1000).await;
                                delay_secs = (delay_secs.saturating_mul(2)).min(60);
                            }
                        }
                    }
                }
            }
        }
    });

    // Render nothing; this component only drives connection state.
    rsx! {}
}
