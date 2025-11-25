use dioxus::prelude::*;
use serde::Serialize;

#[derive(Clone, Props, PartialEq, Serialize)]
pub struct TerminalProps {
    /// DOM id to attach xterm to. Must be unique in the page.
    #[props(into)]
    pub id: String,

    /// Enable fit addon
    #[props(default = true)]
    pub fit: bool,

    /// Enable web-links addon
    #[props(default = true)]
    pub web_links: bool,

    /// Enable WebGL addon
    #[props(default = true)]
    pub webgl: bool,

    /// Optional relay name for SSH connection
    #[serde(skip)]
    #[props(default = None)]
    pub relay_name: Option<String>,
}

#[component]
pub fn Terminal(props: TerminalProps) -> Element {
    #[allow(unused_mut)]
    let mut script_started = use_signal(|| false);
    let mut mounted = use_signal(|| false);

    // Component logic
    #[cfg(feature = "web")]
    {
        use dioxus::core::use_drop;

        web_sys::console::log_1(&format!("Terminal component rendering. Relay prop: {:?}", props.relay_name).into());

        let id = props.id.clone();
        let id_for_ws = props.id.clone();

        let opts_json = serde_json::to_string(&props).expect("TerminalOptions should always serialize");

        use_effect({
            let mounted = mounted.clone();
            let mut script_started = script_started.clone();
            let id = id.clone();
            let opts_json = opts_json.clone();

            move || {
                if mounted() && !script_started() {
                    // Trigger only once
                    script_started.set(true);

                    // Clone inside the effect so the outer closure is not consumed
                    let terminal_id = id.clone();
                    let options_json = opts_json.clone();

                    // Serialize terminal_id to JSON to prevent XSS
                    let terminal_id_json = serde_json::to_string(&terminal_id).unwrap_or_else(|_| "\"\"".to_string());

                    spawn(async move {
                        let script = format!(
                            r#"
                    (async () => {{
                        if (!window.initRustyBridgeTerminal) {{
                            await new Promise((resolve, reject) => {{
                                const s = document.createElement('script');
                                s.src = '/xterm/xterm-init.js';
                                s.onload = resolve;
                                s.onerror = reject;
                                document.head.appendChild(s);
                            }});
                        }}
                        await window.initRustyBridgeTerminal({terminal_id_json}, {options_json});
                    }})();
                    "#
                        );

                        let _ = dioxus::document::eval(&script).await;
                    });
                }
            }
        });

        // Create signals to track the relay name prop and a connection token
        let mut relay_signal = use_signal(|| props.relay_name.clone());
        let mut connect_token = use_signal(|| 0u64);

        // Sync prop to signal (runs every render)
        if *relay_signal.peek() != props.relay_name {
            relay_signal.set(props.relay_name.clone());
        }

        // WebSocket connection for SSH - reactive to relay_name prop changes via signal
        let ws_id = id_for_ws.clone();
        use_effect(move || {
            let relay = relay_signal();
            web_sys::console::log_1(&format!("[rb-web] effect tick: relay={:?}, current_token={}", relay, *connect_token.peek()).into());
            let terminal_id = ws_id.clone();
            let relay_reader = relay_signal.clone();

            // Increment a token so we can detect stale async work
            let attempt_token = {
                let next = *connect_token.peek() + 1;
                connect_token.set(next);
                next
            };

            // Cancellation flag for this effect instance
            let cancel_flag = std::rc::Rc::new(std::cell::Cell::new(false));
            let cancel_flag_task = cancel_flag.clone();

            spawn(async move {
                // ALWAYS cleanup existing connection first to prevent leaks
                let cleanup_script = format!(
                    r#"
                    if (window.terminals["{0}"] && window.terminals["{0}"].sshConnection) {{
                        console.log("[rb-web] cleanup before connect for terminal: {0}");
                        window.terminals["{0}"].sshConnection.disconnect();
                        delete window.terminals["{0}"].sshConnection;
                    }}
                    "#,
                    terminal_id
                );
                let _ = dioxus::document::eval(&cleanup_script).await;

                // Check if the relay selection has changed while we were waiting for cleanup
                if cancel_flag_task.get() || relay_reader() != relay {
                    web_sys::console::log_1(
                        &format!(
                            "[rb-web] aborting stale connection task: cancel={}, reader={:?}, relay={:?}",
                            cancel_flag_task.get(),
                            relay_reader(),
                            relay
                        )
                        .into(),
                    );
                    return;
                }

                if let Some(relay_name) = relay {
                    web_sys::console::log_1(
                        &format!(
                            "[rb-web] starting WebSocket connection: relay={}, token={}",
                            relay_name, attempt_token
                        )
                        .into(),
                    );

                    // Get the WebSocket URL
                    let protocol = if web_sys::window()
                        .and_then(|w| w.location().protocol().ok())
                        .map(|p| p == "https:")
                        .unwrap_or(false)
                    {
                        "wss"
                    } else {
                        "ws"
                    };

                    let host = web_sys::window()
                        .and_then(|w| w.location().host().ok())
                        // Preserve the original host so the session cookie remains same-origin.
                        // Rewriting localhost -> 127.0.0.1 caused auth cookies to be dropped (SameSite).
                        .unwrap_or_else(|| "127.0.0.1:8080".to_string());

                    let ws_url = format!("{}://{}/api/ssh/{}", protocol, host, relay_name);

                    let http_protocol = if web_sys::window()
                        .and_then(|w| w.location().protocol().ok())
                        .map(|p| p == "https:")
                        .unwrap_or(false)
                    {
                        "https"
                    } else {
                        "http"
                    };

                    let status_url = format!("{}://{}/api/ssh/{}/status", http_protocol, host, relay_name);

                    if cancel_flag_task.get() {
                        web_sys::console::log_1(&"[rb-web] cancelled before JS attach".into());
                        return;
                    }

                    web_sys::console::log_1(&"[rb-web] invoking attachWebSocketToTerminal".into());

                    // Attach WebSocket to terminal using the attach addon
                    // Serialize arguments to JSON to prevent XSS
                    let relay_name_json = serde_json::to_string(&relay_name).unwrap_or_else(|_| "\"unknown\"".to_string());
                    let terminal_id_json = serde_json::to_string(&terminal_id).unwrap_or_else(|_| "\"\"".to_string());
                    let ws_url_json = serde_json::to_string(&ws_url).unwrap_or_else(|_| "\"\"".to_string());
                    let status_url_json = serde_json::to_string(&status_url).unwrap_or_else(|_| "\"\"".to_string());

                    let script = format!(
                        r#"
                        (async () => {{
                            const connectToken = {attempt_token};
                            const term = window.terminals[{terminal_id_json}];
                            if (!term) {{
                                console.warn("Terminal instance missing, skipping WebSocket attach", {terminal_id_json});
                                return;
                            }}
                            term.activeSshToken = connectToken;
                            console.log("Starting WebSocket attachment for terminal:", {relay_name_json}, "token", connectToken);

                            const statusUrl = {status_url_json};
                            let statusAllowed = false;
                            try {{
                                const statusResponse = await fetch(statusUrl, {{ method: 'GET', credentials: 'include' }});
                                let payload = null;
                                try {{
                                    payload = await statusResponse.json();
                                }} catch (err) {{
                                    payload = null;
                                }}
                                if (statusResponse.ok && payload && payload.ok) {{
                                    statusAllowed = true;
                                }} else {{
                                    const message = (payload && payload.message) ? payload.message : `SSH access denied (${{statusResponse.status}})`;
                                    term.write(`\r\n\x1b[31m${{message}}\x1b[0m\r\n`);
                                }}
                            }} catch (err) {{
                                console.error('SSH status check failed', err);
                                term.write('\r\n\x1b[31mFailed to verify SSH access.\x1b[0m\r\n');
                            }}

                            if (!statusAllowed || term.activeSshToken !== connectToken) {{
                                return;
                            }}

                            const connection = await window.attachWebSocketToTerminal({terminal_id_json}, {ws_url_json}, connectToken, () => {{
                                if (term.activeSshToken !== connectToken) {{
                                    return;
                                }}
                                // Connection closed - dispatch event to Rust
                                window.dispatchEvent(new CustomEvent('ssh-connection-closed', {{
                                    detail: {{ terminalId: {terminal_id_json} }}
                                }}));
                            }});
                            if (connection && term.activeSshToken === connectToken) {{
                                console.log("SSH WebSocket attached successfully");
                                term.sshConnection = connection;
                            }} else if (connection) {{
                                console.log("Stale SSH WebSocket attach resolved; closing");
                                connection.disconnect();
                            }}
                        }})();
                        "#
                    );

                    let _ = dioxus::document::eval(&script).await;
                    web_sys::console::log_1(&"Terminal component: WebSocket attachment script executed".into());
                }
            });
        });

        // Cleanup when the component unmounts
        let cleanup_id = id_for_ws.clone();
        use_drop(move || {
            web_sys::console::log_1(&format!("[rb-web] use_drop cleanup for terminal {}", cleanup_id).into());
            spawn(async move {
                let cleanup_script = format!(
                    r#"
                    if (window.terminals["{0}"] && window.terminals["{0}"].sshConnection) {{
                        console.log("Cleanup (unmount) closing SSH connection for terminal: {0}");
                        window.terminals["{0}"].sshConnection.disconnect();
                        delete window.terminals["{0}"].sshConnection;
                    }}
                    if (window.terminals["{0}"]) {{
                        window.terminals["{0}"].activeSshToken = null;
                    }}
                    "#,
                    cleanup_id
                );
                let _ = dioxus::document::eval(&cleanup_script).await;
            });
        });
    }

    rsx! {
        div {
            id: "{props.id}",
            class: "w-full min-w-0 relative overflow-hidden h-full max-w-full min-h-[400px] bg-[#1e1e1e] rounded-lg overflow-hidden shadow-lg border border-gray-700 block",
            onmounted: move |_| mounted.set(true),
            if !script_started() {
                span { class: "text-gray-500", "Loading Terminal..." }
            }
        }
    }
}
