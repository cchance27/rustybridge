use dioxus::prelude::*;
#[cfg(feature = "web")]
use gloo_events::EventListener;
#[cfg(feature = "web")]
use js_sys::Reflect;
use serde::Serialize;
#[cfg(feature = "web")]
use web_sys::wasm_bindgen::{JsCast, JsValue};

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

    /// Optional backend SSH session number for reattach
    #[serde(skip)]
    #[props(default = None)]
    pub session_number: Option<u32>,

    /// Optional callback when session closes
    #[serde(skip)]
    #[props(default)]
    pub on_close: Option<EventHandler<()>>,

    /// Optional callback when window is explicitly closed by user
    #[serde(skip)]
    #[props(default)]
    pub on_window_close: Option<EventHandler<()>>,

    /// Current minimized state of the parent window
    #[props(default = false)]
    pub minimized: bool,
}

#[component]
pub fn Terminal(props: TerminalProps) -> Element {
    #[allow(unused_mut)]
    let mut script_started = use_signal(|| false);
    let mut mounted = use_signal(|| false);

    // Component logic
    #[cfg(feature = "web")]
    {
        use crate::app::api::ws::ssh::SshWebSocket;

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
                    web_sys::console::log_1(&format!("Terminal script starting for {terminal_id_json}").into());
                    spawn(async move {
                        let script = format!(
                            r#"
                    (async () => {{
                        const termId = {terminal_id_json};
                        console.log("Terminal script started for " + termId);
                        try {{
                            if (!window.initRustyBridgeTerminal) {{
                                console.error("Terminal init failed for " + termId + ": xterm-init.js not loaded");
                                dioxus.send(false);
                            }}
                            await window.initRustyBridgeTerminal(termId, {options_json});
                            dioxus.send(true);
                        }} catch (e) {{
                            console.error("Terminal init failed for " + termId + ":", e);
                            dioxus.send(false);
                        }}
                    }})();
                    "#
                        );

                        match dioxus::document::eval(&script).recv::<bool>().await {
                            Ok(true) => web_sys::console::log_1(&format!("Terminal init success: {}", terminal_id).into()),
                            Ok(false) => web_sys::console::error_1(&format!("Terminal init failed: {}", terminal_id).into()),
                            Err(e) => web_sys::console::error_1(&format!("Terminal init recv error: {}", e).into()),
                        }
                    });
                }
            }
        });

        let _ws_id = id_for_ws.clone();
        let initial_session_number = props.session_number;

        #[derive(Clone)]
        struct TerminalDrop {
            #[allow(dead_code)]
            socket: Signal<Option<std::rc::Rc<SshWebSocket>>>,
        }

        impl Drop for TerminalDrop {
            fn drop(&mut self) {}
        }

        let socket = use_signal(|| None::<std::rc::Rc<SshWebSocket>>);
        let mut connected = use_signal(|| false);
        let mut relay_signal = use_signal(|| props.relay_name.clone());
        let mut last_connected_relay = use_signal(|| None::<String>);

        // Sync minimized state with server
        let mut prev_minimized = use_signal(|| props.minimized);
        if *prev_minimized.read() != props.minimized {
            let val = props.minimized;
            *prev_minimized.write() = val;

            if connected() {
                spawn({
                    let socket = socket.clone();
                    async move {
                        if let Some(ws) = socket.read().as_ref() {
                            use rb_types::ssh::{SshClientMsg, SshControl};
                            web_sys::console::log_1(&format!("Terminal: sending minimize state: {}", val).into());
                            let msg = SshClientMsg {
                                cmd: Some(SshControl::Minimize(val)),
                                data: Vec::new(),
                            };
                            let _ = ws.send(msg).await;
                        }
                    }
                });
            }
        }

        // Keep relay signal in sync with props so effects react to latest value
        if relay_signal.peek().as_ref() != props.relay_name.as_ref() {
            relay_signal.set(props.relay_name.clone());
        }

        // Listen for close requests initiated from session provider
        let close_listener = use_signal(|| None::<EventListener>);
        {
            let socket = socket.clone();
            let term_id = id.clone();
            let mut close_listener = close_listener.clone();

            use_effect(move || {
                #[cfg(feature = "web")]
                {
                    let window = web_sys::window().expect("window available");
                    let id = term_id.clone();
                    let listener = EventListener::new(&window, "terminal-close-requested", move |event| {
                        web_sys::console::log_1(&format!("Terminal: close request event received for id {}", id).into());
                        let detail = event
                            .dyn_ref::<web_sys::CustomEvent>()
                            .and_then(|evt| evt.detail().dyn_into::<JsValue>().ok());
                        if let Some(detail) = detail {
                            if let Ok(term_id_value) = Reflect::get(&detail, &JsValue::from_str("termId")) {
                                if term_id_value == JsValue::from_str(&id) {
                                    web_sys::console::log_1(
                                        &format!("Terminal: close request matched for term {} - sending SshControl::Close", id).into(),
                                    );
                                    spawn({
                                        let socket = socket.clone();
                                        async move {
                                            if let Some(ws) = socket.read().as_ref() {
                                                use rb_types::ssh::{SshClientMsg, SshControl};

                                                let msg = SshClientMsg {
                                                    cmd: Some(SshControl::Close),
                                                    data: Vec::new(),
                                                };
                                                match ws.send(msg).await {
                                                    Ok(_) => {
                                                        web_sys::console::log_1(&"Terminal: explicit close command sent to server".into());
                                                    }
                                                    Err(err) => {
                                                        web_sys::console::error_1(
                                                            &format!("Terminal: error sending explicit close command: {}", err).into(),
                                                        );
                                                    }
                                                }
                                            }
                                        }
                                    });
                                }
                            }
                        }
                    });
                    close_listener.set(Some(listener));
                }
            });
        }

        // Effect to send close command when component unmounts
        let socket_for_drop = socket.clone();
        use_hook(move || TerminalDrop { socket: socket_for_drop });

        // Effect to establish WebSocket connection when relay changes
        let ws_id = id_for_ws.clone();
        use_effect(move || {
            let relay = relay_signal.read().clone();

            if relay.is_none() {
                return;
            }

            if last_connected_relay() == relay {
                return;
            }

            last_connected_relay.set(relay.clone());

            if let Some(relay_name) = relay {
                let value = id_for_ws.clone();
                spawn({
                    let mut socket = socket;
                    let mut connected = connected;
                    let value = value.clone();
                    async move {
                        use std::rc::Rc;

                        use dioxus::fullstack::WebSocketOptions;

                        use crate::app::api::ws::ssh::ssh_terminal_ws;

                        web_sys::console::log_1(&format!("Terminal: attempting to connect relay {relay_name}").into());
                        let result = ssh_terminal_ws(relay_name, initial_session_number, WebSocketOptions::new()).await;

                        match &result {
                            Ok(_) => {
                                web_sys::console::log_1(&"Terminal: websocket handle acquired".into());
                                connected.set(true);

                                // Expose WebSocket to window object for close helper
                                let term_id = value.clone();
                                spawn(async move {
                                    let _ = dioxus::document::eval(&format!(
                                        r#"
                                        if (!window.terminalSockets) window.terminalSockets = {{}};
                                        // Store a reference that can send messages
                                        // We'll need to hook into the actual WS send later
                                        window.terminalSockets['{}'] = {{ termId: '{}' }};
                                        "#,
                                        term_id, term_id
                                    ))
                                    .await;
                                });
                            }
                            Err(err) => {
                                web_sys::console::error_1(&format!("Terminal: websocket connect failed: {err}").into());
                                connected.set(false);
                            }
                        }

                        if let Some(result) = result.ok() {
                            web_sys::console::log_1(&"Terminal: websocket connected".into());
                            socket.set(Some(Rc::new(result)));
                        } else {
                            web_sys::console::error_1(&"Terminal: websocket connect failed.".into());
                        }
                    }
                });
            } else {
                connected.set(false);
            }
        });

        // Effect to send initial ready and minimize state when connected
        use_effect(move || {
            if connected() {
                let is_minimized = props.minimized;
                spawn({
                    let socket = socket.clone();
                    async move {
                        if let Some(ws) = socket.read().as_ref() {
                            use rb_types::ssh::{SshClientMsg, SshControl};

                            // Send Ready signal first
                            web_sys::console::log_1(&"Terminal: sending Ready signal".into());
                            let ready_msg = SshClientMsg {
                                cmd: Some(SshControl::Ready),
                                data: Vec::new(),
                            };
                            let _ = ws.send(ready_msg).await;

                            // Then send minimize state if needed
                            if is_minimized {
                                web_sys::console::log_1(&format!("Terminal: sending initial minimize state: {}", is_minimized).into());
                                let msg = SshClientMsg {
                                    cmd: Some(SshControl::Minimize(true)),
                                    data: Vec::new(),
                                };
                                let _ = ws.send(msg).await;
                            }
                        }
                    }
                });
            }
        });

        let connected_read = connected.clone();
        let on_close = props.on_close.clone();

        // Effect to handle incoming data from WebSocket and write to terminal
        let value = ws_id.clone();
        use_effect(move || {
            // Only start the IO bridge once we have an active websocket connection
            if !connected_read() {
                return;
            }

            let terminal_id = value.clone();
            let socket_for_send = socket.clone();
            let socket_for_recv = socket;
            let on_close = on_close.clone();
            let _relay_name_for_storage = relay_signal.peek().clone();

            spawn(async move {
                let Some(socket_tx_handle) = socket_for_send.read().as_ref().cloned() else {
                    web_sys::console::warn_1(&"Terminal: websocket send handle missing".into());
                    return;
                };

                let Some(socket_rx_handle) = socket_for_recv.read().as_ref().cloned() else {
                    web_sys::console::warn_1(&"Terminal: websocket recv handle missing".into());
                    return;
                };

                // Spawn input setup and handling in a separate task so it doesn't block receiving
                let socket_tx = socket_tx_handle.clone();
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
                            use rb_types::ssh::SshClientMsg;

                            let msg = SshClientMsg { cmd: None, data: bytes };

                            if let Err(err) = socket_tx.send(msg).await {
                                web_sys::console::error_1(&format!("WebSocket send error: {}", err).into());
                                break;
                            }
                        }
                    }
                });

                // Ensure the terminal instance is created before we start processing
                // any incoming data (especially replayed scrollback history).
                // Otherwise, writeToTerminal would run before window.terminals[terminalId]
                // exists and the replay would be lost.
                loop {
                    let mut ready_eval = dioxus::document::eval(&format!(
                        r#"
                        (function() {{
                            if (window.terminals && window.terminals["{0}"]) {{
                                dioxus.send(true);
                            }} else {{
                                dioxus.send(false);
                            }}
                        }})();
                        "#,
                        terminal_id
                    ));

                    match ready_eval.recv::<bool>().await {
                        Ok(true) => {
                            web_sys::console::log_1(&format!("Terminal: instance ready for {}", terminal_id).into());
                            break;
                        }
                        Ok(false) => {}
                        Err(e) => {
                            web_sys::console::warn_1(&format!("Terminal: readiness check error for {}: {}", terminal_id, e).into());
                        }
                    }

                    gloo_timers::future::TimeoutFuture::new(200).await;
                }

                let mut session_number_set = false;

                loop {
                    match socket_rx_handle.recv().await {
                        Ok(msg) => {
                            // Server sends session_id in first message
                            if let Some(session_num) = msg.session_id {
                                web_sys::console::log_1(&format!("Terminal: connected to session #{}", session_num).into());

                                if !session_number_set {
                                    // Inform SessionContext which backend session number this window is bound to
                                    let term_id = terminal_id.clone();
                                    let relay_id = msg.relay_id;
                                    crate::app::session::provider::use_session().set_session_number_from_term_id(
                                        &term_id,
                                        session_num,
                                        relay_id,
                                    );
                                    session_number_set = true;
                                }
                            }

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
                            if !data.is_empty() {
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
