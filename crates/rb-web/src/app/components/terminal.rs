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

    /// Optional callback when session closes
    #[serde(skip)]
    #[props(default)]
    pub on_close: Option<EventHandler<()>>,
}

#[component]
pub fn Terminal(props: TerminalProps) -> Element {
    #[allow(unused_mut)]
    let mut script_started = use_signal(|| false);
    let mut mounted = use_signal(|| false);

    // Component logic
    #[cfg(feature = "web")]
    {
        use dioxus::fullstack::use_websocket;

        //web_sys::console::log_1(&format!("Terminal component rendering. Relay prop: {:?}", props.relay_name).into());

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
        let mut _connect_token = use_signal(|| 0u64);
        #[allow(unused_mut)]
        let mut last_connected_relay = use_signal(|| None::<String>);
        let connected = use_signal(|| false);

        // Sync prop to signal (runs every render)
        if *relay_signal.peek() != props.relay_name {
            relay_signal.set(props.relay_name.clone());
        }

        // WebSocket connection for SSH - reactive to relay_name prop changes via signal
        let ws_id = id_for_ws.clone();

        // Use the use_websocket hook
        // We need to pass the URL. Since relay_name is dynamic, we need to handle that.
        // Dioxus 0.7.1 use_websocket takes a closure that returns the server function call.
        // But here we need to call it with arguments.
        // The doc says: let mut socket = use_websocket(|| uppercase_ws("John Doe".into(), 30, WebSocketOptions::new()));

        let socket = use_websocket(move || async move { Err(ServerFnError::new("SSH relay not selected yet".to_string())) });

        // Connect or reconnect when the relay signal changes
        use_effect({
            let relay_signal = relay_signal.clone();
            let mut last_connected_relay = last_connected_relay.clone();
            let socket = socket; // Re-add mut here
            let mut connected = connected.clone();

            move || {
                let relay = relay_signal();

                if last_connected_relay() == relay {
                    return;
                }

                last_connected_relay.set(relay.clone());

                if let Some(relay_name) = relay {
                    spawn({
                        let mut socket = socket; // Re-add mut here
                        let mut connected = connected;
                        async move {
                            use dioxus::fullstack::WebSocketOptions;

                            use crate::app::api::ssh_websocket::ssh_terminal_ws;

                            web_sys::console::log_1(&format!("Terminal: attempting to connect relay {relay_name}").into());
                            let result = ssh_terminal_ws(relay_name, WebSocketOptions::new()).await;

                            match &result {
                                Ok(_) => {
                                    web_sys::console::log_1(&"Terminal: websocket handle acquired".into());
                                    connected.set(true);
                                }
                                Err(err) => {
                                    web_sys::console::error_1(&format!("Terminal: websocket connect failed: {err}").into());
                                    connected.set(false);
                                }
                            }

                            socket.set(result);
                        }
                    });
                } else {
                    connected.set(false);

                    spawn({
                        let socket = socket;
                        async move {
                            use crate::app::api::ssh_websocket::{SshClientMsg, SshControl};

                            let msg = SshClientMsg {
                                cmd: Some(SshControl::Close),
                                data: Vec::new(),
                            };

                            if let Err(err) = socket.send(msg).await {
                                web_sys::console::error_1(&format!("Terminal: failed to send close command: {err}").into());
                            }
                        }
                    });
                }
            }
        });

        let connected_read = connected.clone();
        let on_close = props.on_close.clone();

        // Effect to handle incoming data from WebSocket and write to terminal
        use_effect(move || {
            // Only start the IO bridge once we have an active websocket connection
            if !connected_read() {
                return;
            }

            let terminal_id = ws_id.clone();
            let socket_for_send = socket;
            let mut socket_for_recv = socket;
            let on_close = on_close.clone();

            spawn(async move {
                // Spawn input setup and handling in a separate task so it doesn't block receiving
                let socket_tx = socket_for_send;
                let terminal_id_input = terminal_id.clone();

                spawn(async move {
                    // Retry loop to ensure terminal is initialized before setting up input
                    let mut eval = loop {
                        let mut result = dioxus::document::eval(&format!(
                            r#"
                            console.log("Eval: Checking for setupTerminalInput...");
                            if (window.setupTerminalInput) {{
                                console.log("Eval: setupTerminalInput found, calling for {0}");
                                try {{
                                    let res = window.setupTerminalInput("{0}", (data) => {{
                                        dioxus.send(data);
                                    }});
                                    console.log("Eval: setupTerminalInput returned", res);
                                    dioxus.send(res);
                                }} catch (e) {{
                                    console.error("Eval: setupTerminalInput error", e);
                                    dioxus.send(false);
                                }}
                            }} else {{
                                console.log("Eval: setupTerminalInput NOT found");
                                dioxus.send(false);
                            }}
                            "#,
                            terminal_id_input
                        ));

                        match result.recv::<bool>().await {
                            Ok(val) => {
                                web_sys::console::log_1(&format!("Rust: Input setup attempt result: {}", val).into());
                                if val {
                                    break result;
                                }
                            }
                            Err(e) => {
                                web_sys::console::warn_1(&format!("Rust: Input setup recv error: {}", e).into());
                            }
                        }

                        // Wait a bit before retrying
                        gloo_timers::future::TimeoutFuture::new(500).await;
                    };

                    web_sys::console::log_1(&"Rust: Input setup successful, starting receive loop".into());

                    // Loop to read from terminal input and send to WebSocket
                    while let Ok(json_val) = eval.recv().await {
                        // data is Array<number> (bytes)
                        if let Ok(bytes) = serde_json::from_value::<Vec<u8>>(json_val) {
                            use crate::app::api::ssh_websocket::SshClientMsg;

                            let msg = SshClientMsg { cmd: None, data: bytes };

                            if let Err(err) = socket_tx.send(msg).await {
                                web_sys::console::error_1(&format!("WebSocket send error: {}", err).into());
                                break;
                            }
                        }
                    }
                });

                loop {
                    match socket_for_recv.recv().await {
                        Ok(msg) => {
                            if msg.eof {
                                web_sys::console::log_1(&"Terminal: received EOF from SSH session".into());

                                if let Some(handler) = on_close {
                                    handler.call(());
                                }

                                let _ = dioxus::document::eval(
                                    r#"
                                    window.dispatchEvent(new CustomEvent('ssh-connection-closed', {
                                        detail: 'ssh-eof'
                                    }));
                                    "#,
                                )
                                .await;

                                break;
                            }

                            let data = msg.data;
                            let script = if let Ok(s) = String::from_utf8(data.clone()) {
                                // Escape backticks and backslashes for JS template string
                                let escaped = s.replace("\\", "\\\\").replace("`", "\\`").replace("${", "\\${");
                                format!("window.writeToTerminal(\"{}\", `{}`);", terminal_id, escaped)
                            } else {
                                let json_data = serde_json::to_string(&data).unwrap_or_else(|_| "[]".to_string());
                                format!("window.writeToTerminal(\"{}\", new Uint8Array({}));", terminal_id, json_data)
                            };

                            let _ = dioxus::document::eval(&script).await;
                        }
                        Err(e) => {
                            let msg = format!("WebSocket error: {}", e);
                            if msg.contains("Connection closed") {
                                web_sys::console::warn_1(&msg.into());
                            } else {
                                web_sys::console::error_1(&msg.into());
                            }

                            if let Some(handler) = on_close {
                                handler.call(());
                            }

                            let _ = dioxus::document::eval(
                                r#"
                                window.dispatchEvent(new CustomEvent('ssh-connection-closed', {
                                    detail: 'ssh-websocket-closed'
                                }));
                                "#,
                            )
                            .await;

                            break;
                        }
                    }
                }
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
