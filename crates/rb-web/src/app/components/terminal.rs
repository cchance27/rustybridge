use dioxus::prelude::*;
#[cfg(feature = "web")]
use futures::{StreamExt, channel::mpsc};
#[cfg(feature = "web")]
use gloo_events::EventListener;
#[cfg(feature = "web")]
use js_sys::Reflect;
use serde::Serialize;
#[cfg(feature = "web")]
use tracing::{debug, error, warn};
#[cfg(feature = "web")]
use wasm_bindgen::prelude::*;
#[cfg(feature = "web")]
use web_sys::wasm_bindgen::{JsCast, JsValue};

#[cfg(feature = "web")]
use crate::bindings::{
    get_terminal_dimensions, init_rusty_bridge_terminal, setup_terminal_input, setup_terminal_resize, write_to_terminal
};

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

    /// Optional target user ID for attaching to other users' sessions
    #[serde(skip)]
    #[props(default = None)]
    pub target_user_id: Option<i64>,
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

                    spawn(async move {
                        debug!(terminal_id = %terminal_id, "terminal script starting");
                        let options = match js_sys::JSON::parse(&options_json) {
                            Ok(options) => options,
                            Err(err) => {
                                error!(terminal_id = %terminal_id, error = ?err, "terminal init: failed to parse options json");
                                return;
                            }
                        };

                        match init_rusty_bridge_terminal(&terminal_id, &options).await {
                            Ok(_) => {
                                debug!(terminal_id = %terminal_id, "terminal init success");
                                // We don't need to manually send dioxus.send(true) equivalent here
                                // because the extern function returns a Promise that resolves.
                            }
                            Err(e) => {
                                error!(terminal_id = %terminal_id, error = ?e, "terminal init failed");
                            }
                        }
                    });
                }
            }
        });

        let _ws_id = id_for_ws.clone();
        let initial_session_number = props.session_number;
        let target_user_id = props.target_user_id;

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
                            debug!(minimized = val, "terminal: sending minimize state");
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
                        debug!(terminal_id = %id, "terminal: close request event received");
                        let detail = event
                            .dyn_ref::<web_sys::CustomEvent>()
                            .and_then(|evt| evt.detail().dyn_into::<JsValue>().ok());
                        if let Some(detail) = detail {
                            if let Ok(term_id_value) = Reflect::get(&detail, &JsValue::from_str("termId")) {
                                if term_id_value == JsValue::from_str(&id) {
                                    debug!(terminal_id = %id, "terminal: close request matched, sending SshControl::Close");
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
                                                        debug!("terminal: explicit close command sent to server");
                                                    }
                                                    Err(err) => {
                                                        error!(error = %err, "terminal: error sending explicit close command");
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

                        debug!(relay_name = %relay_name, "terminal: attempting to connect relay");
                        let result = ssh_terminal_ws(relay_name, initial_session_number, target_user_id, WebSocketOptions::new()).await;

                        match &result {
                            Ok(_) => {
                                debug!("terminal: websocket handle acquired");
                                connected.set(true);

                                // Expose WebSocket to window object for close helper
                                // window.terminalSockets[id] = { termId: id }
                                let term_id = value.clone();
                                if let Some(window) = web_sys::window() {
                                    if let Ok(sockets) = Reflect::get(&window, &"terminalSockets".into()) {
                                        let target = if sockets.is_undefined() {
                                            let obj = js_sys::Object::new();
                                            let _ = Reflect::set(&window, &"terminalSockets".into(), &obj);
                                            obj
                                        } else {
                                            sockets.dyn_into::<js_sys::Object>().unwrap_or_else(|_| {
                                                let obj = js_sys::Object::new();
                                                let _ = Reflect::set(&window, &"terminalSockets".into(), &obj);
                                                obj
                                            })
                                        };

                                        let entry = js_sys::Object::new();
                                        let _ = Reflect::set(&entry, &"termId".into(), &term_id.clone().into());
                                        let _ = Reflect::set(&target, &term_id.into(), &entry);
                                    } else {
                                        // Initialize if getting failed (likely undefined)
                                        let obj = js_sys::Object::new();
                                        let _ = Reflect::set(&window, &"terminalSockets".into(), &obj);

                                        let entry = js_sys::Object::new();
                                        let _ = Reflect::set(&entry, &"termId".into(), &term_id.clone().into());
                                        let _ = Reflect::set(&obj, &term_id.into(), &entry);
                                    }
                                }
                            }
                            Err(err) => {
                                error!(error = %err, "terminal: websocket connect failed");
                                connected.set(false);
                            }
                        }

                        if let Some(result) = result.ok() {
                            debug!("terminal: websocket connected");
                            socket.set(Some(Rc::new(result)));
                        } else {
                            error!("terminal: websocket connect failed");
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
                let term_id = id.clone();
                spawn({
                    let socket = socket.clone();
                    async move {
                        if let Some(ws) = socket.read().as_ref() {
                            use rb_types::ssh::{SshClientMsg, SshControl};

                            // Get terminal dimensions from xterm
                            let dims_val = get_terminal_dimensions(&term_id);

                            let (cols, rows) = if !dims_val.is_undefined() && !dims_val.is_null() {
                                // Try to parse manually using Reflect
                                let cols = Reflect::get(&dims_val, &"cols".into())
                                    .ok()
                                    .and_then(|v| v.as_f64())
                                    .map(|v| v as u32)
                                    .unwrap_or(80);
                                let rows = Reflect::get(&dims_val, &"rows".into())
                                    .ok()
                                    .and_then(|v| v.as_f64())
                                    .map(|v| v as u32)
                                    .unwrap_or(24);

                                debug!(cols, rows, "terminal: got dimensions");
                                (cols, rows)
                            } else {
                                warn!("terminal: failed to get dimensions, using default 80x24");
                                (80, 24)
                            };

                            // Send minimize state FIRST if needed, so server knows
                            // the state before Ready causes it to transition
                            if is_minimized {
                                debug!(minimized = is_minimized, "terminal: sending initial minimize state");
                                let msg = SshClientMsg {
                                    cmd: Some(SshControl::Minimize(true)),
                                    data: Vec::new(),
                                };
                                let _ = ws.send(msg).await;
                            }

                            // Send Ready signal with dimensions (this triggers server transition)
                            debug!(cols, rows, "terminal: sending ready signal");
                            let ready_msg = SshClientMsg {
                                cmd: Some(SshControl::Ready { cols, rows }),
                                data: Vec::new(),
                            };
                            let _ = ws.send(ready_msg).await;
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
                    warn!("terminal: websocket send handle missing");
                    return;
                };

                let Some(socket_rx_handle) = socket_for_recv.read().as_ref().cloned() else {
                    warn!("terminal: websocket recv handle missing");
                    return;
                };

                // Spawn input setup and handling in a separate task so it doesn't block receiving
                let socket_tx = socket_tx_handle.clone();
                let terminal_id_input = terminal_id.clone();

                spawn(async move {
                    // Create a channel to receive data from the closure
                    let (tx, mut rx) = mpsc::unbounded();

                    // Create a valid closure that sends data to our channel
                    let closure = Closure::wrap(Box::new(move |data: JsValue| {
                        // Data is expected to be an array of bytes or Uint8Array
                        // We need to convert JsValue to Vec<u8>
                        let bytes: Vec<u8> = if data.is_instance_of::<js_sys::Uint8Array>() {
                            js_sys::Uint8Array::from(data).to_vec()
                        } else if data.is_instance_of::<js_sys::Array>() {
                            let arr = js_sys::Array::from(&data);
                            arr.iter().map(|v| v.as_f64().unwrap_or(0.0) as u8).collect()
                        } else {
                            Vec::new()
                        };

                        if !bytes.is_empty() {
                            let _ = tx.unbounded_send(bytes);
                        }
                    }) as Box<dyn FnMut(JsValue)>);

                    // Retry loop to ensure terminal is initialized before setting up input
                    loop {
                        debug!("rust: attempting setupTerminalInput");
                        // We pass the closure by reference. The closure must live as long as the callback is used.
                        match setup_terminal_input(&terminal_id_input, &closure) {
                            Ok(true) => {
                                debug!("rust: input setup successful");
                                break;
                            }
                            _ => {
                                // Not ready or failed
                            }
                        }

                        // Wait a bit before retrying
                        gloo_timers::future::TimeoutFuture::new(500).await;
                    }

                    debug!("rust: input setup done, starting receive loop");

                    // Loop to read from channel and send to WebSocket
                    // The closure is kept alive by being in this async block's scope
                    // while we await on rx.
                    while let Some(bytes) = rx.next().await {
                        use rb_types::ssh::SshClientMsg;
                        let msg = SshClientMsg { cmd: None, data: bytes };

                        if let Err(err) = socket_tx.send(msg).await {
                            error!(error = %err, "websocket send error");
                            break;
                        }
                    }

                    // Explicitly keep closure alive until loop ends
                    drop(closure);
                });

                // Ensure the terminal instance is created before we start processing
                // any incoming data (especially replayed scrollback history).
                // Otherwise, writeToTerminal would run before window.terminals[terminalId]
                // exists and the replay would be lost.
                loop {
                    // Check if window.terminals[terminal_id] exists using web-sys/js-sys
                    let mut ready = false;
                    if let Some(window) = web_sys::window() {
                        if let Ok(terminals) = js_sys::Reflect::get(&window, &"terminals".into()) {
                            if !terminals.is_undefined() && !terminals.is_null() {
                                if let Ok(term) = js_sys::Reflect::get(&terminals, &terminal_id.clone().into()) {
                                    if !term.is_undefined() && !term.is_null() {
                                        ready = true;
                                    }
                                }
                            }
                        }
                    }

                    if ready {
                        debug!(terminal_id = %terminal_id, "terminal: instance ready");
                        break;
                    }

                    // Wait before retrying
                    gloo_timers::future::TimeoutFuture::new(100).await;
                }

                let mut session_number_set = false;

                loop {
                    match socket_rx_handle.recv().await {
                        Ok(msg) => {
                            // Server sends session_id in first message
                            if let Some(session_num) = msg.session_id {
                                debug!(session_number = session_num, "terminal: connected to session");

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
                                debug!("terminal: received EOF from SSH session");

                                if let Some(handler) = on_close {
                                    handler.call(());
                                }

                                if let Some(window) = web_sys::window() {
                                    let event_init = web_sys::CustomEventInit::new();
                                    event_init.set_detail(&JsValue::from_str("ssh-eof"));
                                    if let Ok(event) = web_sys::CustomEvent::new_with_event_init_dict("ssh-connection-closed", &event_init)
                                    {
                                        let _ = window.dispatch_event(&event);
                                    }
                                }

                                break;
                            }

                            let data = msg.data;
                            if !data.is_empty() {
                                // Pass raw bytes to xterm
                                write_to_terminal(&terminal_id, &data);
                            }
                        }
                        Err(e) => {
                            let msg = format!("WebSocket error: {}", e);
                            if msg.contains("Connection closed") {
                                warn!(error = %e, "websocket connection closed");
                            } else {
                                error!(error = %e, "websocket error");
                            }

                            if let Some(handler) = on_close {
                                handler.call(());
                            }

                            if let Some(window) = web_sys::window() {
                                let event_init = web_sys::CustomEventInit::new();
                                event_init.set_detail(&JsValue::from_str("ssh-websocket-closed"));
                                if let Ok(event) = web_sys::CustomEvent::new_with_event_init_dict("ssh-connection-closed", &event_init) {
                                    let _ = window.dispatch_event(&event);
                                }
                            }

                            break;
                        }
                    }
                }
            });
        });

        // Effect to handle resize events
        let value_resize = ws_id.clone();
        use_effect(move || {
            if !connected_read() {
                return;
            }

            let terminal_id = value_resize.clone();
            let socket_for_send = socket.clone();

            spawn(async move {
                let Some(socket_tx_handle) = socket_for_send.read().as_ref().cloned() else {
                    return;
                };

                let socket_tx = socket_tx_handle.clone();
                let terminal_id_resize = terminal_id.clone();

                spawn(async move {
                    // Create a channel to receive resize data from the closure
                    let (tx, mut rx) = mpsc::unbounded();

                    // Closure to handle resize callbacks from JS
                    let closure = Closure::wrap(Box::new(move |data: JsValue| {
                        // Data is {cols: number, rows: number}
                        let cols = Reflect::get(&data, &"cols".into())
                            .ok()
                            .and_then(|v| v.as_f64())
                            .map(|v| v as u32)
                            .unwrap_or(80);
                        let rows = Reflect::get(&data, &"rows".into())
                            .ok()
                            .and_then(|v| v.as_f64())
                            .map(|v| v as u32)
                            .unwrap_or(24);

                        let _ = tx.unbounded_send((cols, rows));
                    }) as Box<dyn FnMut(JsValue)>);

                    // Retry loop setup
                    loop {
                        match setup_terminal_resize(&terminal_id_resize, &closure) {
                            Ok(true) => {
                                debug!("rust: resize setup successful");
                                break;
                            }
                            _ => {}
                        }
                        gloo_timers::future::TimeoutFuture::new(500).await;
                    }

                    while let Some((cols, rows)) = rx.next().await {
                        use rb_types::ssh::{SshClientMsg, SshControl};

                        debug!(cols, rows, "rust: sending resize");

                        let msg = SshClientMsg {
                            cmd: Some(SshControl::Resize { cols, rows }),
                            data: Vec::new(),
                        };

                        if let Err(err) = socket_tx.send(msg).await {
                            error!(error = %err, "websocket send error (resize)");
                            break;
                        }
                    }

                    drop(closure);
                });
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
