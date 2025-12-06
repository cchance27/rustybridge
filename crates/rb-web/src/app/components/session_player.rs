use base64::{Engine as _, prelude::BASE64_STANDARD};
use dioxus::{
    fullstack::{WebSocketOptions, use_websocket}, prelude::*
};

use crate::app::{
    api::audit::{SessionChunk, SessionStreamClient, SessionStreamServer, get_session_events, session_stream_ws, session_summary}, components::structured_tooltip::{StructuredTooltip, TooltipSection}
};

/// Format milliseconds as MM:SS.mmm
fn format_duration(ms: i64) -> String {
    // Clamp to zero to avoid bizarre negative times if callers
    // accidentally pass an offset before the session start.
    let ms = ms.max(0);
    let total_seconds = ms / 1000;
    let minutes = total_seconds / 60;
    let seconds = total_seconds % 60;
    let millis = ms % 1000;
    format!("{:02}:{:02}.{:03}", minutes, seconds, millis)
}

fn format_bytes(bytes: i64) -> String {
    const UNIT: i64 = 1024;
    if bytes < UNIT {
        return format!("{} B", bytes);
    }
    let exp = (bytes as f64).ln() / (UNIT as f64).ln();
    let pre = "KMGTPE".chars().nth(exp as usize - 1).unwrap_or('?');
    format!("{:.1} {}B", bytes as f64 / (UNIT as f64).powi(exp as i32), pre)
}

#[cfg(feature = "web")]
use wasm_bindgen::{JsCast, JsValue};

#[cfg(feature = "web")]
fn init_terminal(terminal_id: &str, term_size: Option<(u16, u16)>) -> Result<(), JsValue> {
    let window = web_sys::window().ok_or_else(|| JsValue::from_str("no window"))?;
    let init_fn = js_sys::Reflect::get(&window, &JsValue::from_str("initRustyBridgeTerminal"))?;
    let func = init_fn.dyn_into::<js_sys::Function>()?;

    // Create options object
    let options = js_sys::Object::new();
    // If we have a recorded terminal size, prefer that and disable fit
    if let Some((cols, rows)) = term_size {
        js_sys::Reflect::set(&options, &JsValue::from_str("cols"), &JsValue::from_f64(cols as f64))?;
        js_sys::Reflect::set(&options, &JsValue::from_str("rows"), &JsValue::from_f64(rows as f64))?;
        js_sys::Reflect::set(&options, &JsValue::from_str("fit"), &JsValue::from_bool(false))?;
    } else {
        js_sys::Reflect::set(&options, &JsValue::from_str("fit"), &JsValue::from_bool(true))?;
    }
    js_sys::Reflect::set(&options, &JsValue::from_str("web_links"), &JsValue::from_bool(false))?;
    js_sys::Reflect::set(&options, &JsValue::from_str("webgl"), &JsValue::from_bool(false))?;

    func.call2(&JsValue::NULL, &JsValue::from_str(terminal_id), &options)?;
    Ok(())
}

#[cfg(feature = "web")]
fn write_to_terminal(terminal_id: &str, data: &str) -> Result<(), JsValue> {
    let window = web_sys::window().ok_or_else(|| JsValue::from_str("no window"))?;
    let write_fn = js_sys::Reflect::get(&window, &JsValue::from_str("writeToTerminal"))?;
    let func = write_fn.dyn_into::<js_sys::Function>()?;
    func.call2(&JsValue::NULL, &JsValue::from_str(terminal_id), &JsValue::from_str(data))?;
    Ok(())
}

#[cfg(feature = "web")]
fn clear_terminal(terminal_id: &str) -> Result<(), JsValue> {
    let window = web_sys::window().ok_or_else(|| JsValue::from_str("no window"))?;

    // Get the terminal from window.terminals
    let terminals = js_sys::Reflect::get(&window, &JsValue::from_str("terminals"))?;
    let term = js_sys::Reflect::get(&terminals, &JsValue::from_str(terminal_id))?;

    if !term.is_undefined() {
        // Call term.reset() to clear screen and scrollback and reset cursor
        let reset_fn = js_sys::Reflect::get(&term, &JsValue::from_str("reset"))?;
        let func = reset_fn.dyn_into::<js_sys::Function>()?;
        func.call0(&term)?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq)]
struct ParsedChunk {
    start_index: usize,
    end_index: usize,
    timestamp: i64,
    username: Option<String>,
    is_admin: bool,
    content: String,
    direction: u8,
}

fn render_event_content(text: &str) -> Element {
    let mut elements = Vec::new();
    let mut chars = text.chars().peekable();
    let mut current_text = String::new();

    while let Some(c) = chars.next() {
        let mut handled_special = false;
        if c == '\x1b' {
            // Potential escape sequence
            // Check ahead for CSI/SS3 sequences
            if let Some(&next) = chars.peek()
                && (next == '[' || next == 'O')
            {
                // Consume the introducer
                let intro = chars.next().unwrap();

                // Check the final byte
                if let Some(&final_char) = chars.peek() {
                    let symbol = match (intro, final_char) {
                        ('[', 'A') | ('O', 'A') => Some("▲"),
                        ('[', 'B') | ('O', 'B') => Some("▼"),
                        ('[', 'C') | ('O', 'C') => Some("▶︎"),
                        ('[', 'D') | ('O', 'D') => Some("◀︎"),
                        ('[', 'H') | ('O', 'H') => Some("Home"),
                        ('[', 'F') | ('O', 'F') => Some("End"),
                        ('O', 'P') => Some("F1"),
                        ('O', 'Q') => Some("F2"),
                        ('O', 'R') => Some("F3"),
                        ('O', 'S') => Some("F4"),
                        _ => None,
                    };

                    if let Some(sym) = symbol {
                        // Consume final char
                        chars.next();

                        // Flush accumulated text
                        if !current_text.is_empty() {
                            let t = current_text.clone();
                            elements.push(rsx! { span { "{t}" } });
                            current_text.clear();
                        }

                        elements.push(rsx! { kbd { class: "kbd", "{sym}" } });
                        handled_special = true;
                    } else {
                        // Not a recognized sequence, treat as individual chars
                        // We already consumed 'intro', so push it to buffer
                        // But first we need to handle the Esc we just processed
                        if !current_text.is_empty() {
                            let t = current_text.clone();
                            elements.push(rsx! { span { "{t}" } });
                            current_text.clear();
                        }
                        elements.push(rsx! { kbd { class: "kbd", "Esc" } });
                        current_text.push(intro);
                        handled_special = true;
                    }
                } else {
                    // EOF after intro
                    if !current_text.is_empty() {
                        let t = current_text.clone();
                        elements.push(rsx! { span { "{t}" } });
                        current_text.clear();
                    }
                    elements.push(rsx! { kbd { class: "kbd", "Esc" } });
                    current_text.push(intro);
                    handled_special = true;
                }
            }

            if !handled_special {
                // Just a lone Escape
                if !current_text.is_empty() {
                    let t = current_text.clone();
                    elements.push(rsx! { span { "{t}" } });
                    current_text.clear();
                }
                elements.push(rsx! { kbd { class: "kbd", "Esc" } });
                handled_special = true;
            }
        } else {
            // Check for other special control chars
            let special_sym = match c {
                '\r' | '\n' => Some("↵"),
                '\t' => Some("⇥"),
                '\x08' | '\x7f' => Some("⌫"),
                _ => None,
            };

            if let Some(sym) = special_sym {
                if !current_text.is_empty() {
                    let t = current_text.clone();
                    elements.push(rsx! { span { "{t}" } });
                    current_text.clear();
                }
                elements.push(rsx! { kbd { class: "kbd", "{sym}" } });
                handled_special = true;
            } else if c.is_control() {
                if !current_text.is_empty() {
                    let t = current_text.clone();
                    elements.push(rsx! { span { "{t}" } });
                    current_text.clear();
                }
                let code = (c as u8 + 64) as char;
                elements.push(rsx! { kbd { class: "kbd", "⌃{code}" } });
                handled_special = true;
            }
        }

        if !handled_special {
            current_text.push(c);
        }
    }

    if !current_text.is_empty() {
        elements.push(rsx! { span { "{current_text}" } });
    }

    rsx! {
        for el in elements {
            {el}
        }
    }
}

fn map_chunks(chunks: &[SessionChunk]) -> Vec<ParsedChunk> {
    chunks
        .iter()
        .enumerate()
        .map(|(i, chunk)| {
            let chunk_content = if let Ok(decoded) = BASE64_STANDARD.decode(&chunk.data) {
                String::from_utf8_lossy(&decoded).to_string()
            } else {
                "<binary>".to_string()
            };

            ParsedChunk {
                start_index: i,
                end_index: i,
                timestamp: chunk.timestamp,
                username: chunk.username.clone(),
                is_admin: chunk.is_admin_input,
                content: chunk_content,
                direction: chunk.direction,
            }
        })
        .collect()
}

#[component]
pub fn SessionPlayer(session_id: String) -> Element {
    // Websocket for streaming
    let session_id_ws = session_id.clone();
    let ws = use_websocket(move || {
        let id = session_id_ws.clone();
        async move { session_stream_ws(id, WebSocketOptions::new()).await }
    });

    // Streaming state
    let mut stream_started = use_signal(|| false);
    let mut stream_complete = use_signal(|| false);
    let mut stream_error = use_signal(|| None::<String>);
    let mut loaded_bytes = use_signal(|| 0usize);
    let mut total_chunks_stream = use_signal(|| 0usize);
    let mut total_db_chunks = use_signal(|| 0usize); // Real DB chunk count
    let mut chunk_list = use_signal(|| Vec::<SessionChunk>::new());

    let session_id_meta = session_id.clone();
    let session_meta = use_resource(move || {
        let id = session_id_meta.clone();
        async move { session_summary(id).await }
    });

    // Fetch input events for timeline/sidebar
    let session_id_events = session_id.clone();
    let input_events = use_resource(move || {
        let id = session_id_events.clone();
        async move { get_session_events(id).await }
    });

    // Active chunks (streamed replay buffer)
    let active_chunks = use_memo(move || chunk_list.read().clone());

    let mut is_playing = use_signal(|| false);
    let mut current_chunk_index = use_signal(|| 0);
    let mut current_time_ms = use_signal(|| None::<i64>);
    let mut playback_speed = use_signal(|| 1.0_f64);
    // Playback epoch: increments on seeks/resets so that
    // in-flight async playback tasks from previous epochs
    // can detect staleness and abort without mutating state.
    let mut playback_epoch = use_signal(|| 0u64);
    #[cfg(feature = "web")]
    let mut terminal_initialized = use_signal(|| false);
    #[cfg(feature = "web")]
    let mut terminal_error = use_signal(|| None::<String>);

    // Smooth animation state
    // Mutable for use in web effect
    #[allow(unused)]
    let mut animation_start_time = use_signal(|| None::<i64>);
    // Mutable for use in web effect
    #[allow(unused)]
    let mut animation_target_time = use_signal(|| None::<i64>);

    // Track the last processed chunk to prevent duplication
    #[cfg(feature = "web")]
    let mut last_processed_chunk = use_signal(|| None::<usize>);
    // (Initial delay from session start removed; playback starts immediately.)

    // Websocket receive loop
    use_future(move || {
        let mut ws = ws.clone();
        async move {
            while let Ok(msg) = ws.recv().await {
                match msg {
                    SessionStreamServer::ChunkBatch {
                        start_index: _,
                        total_chunks,
                        total_db_chunks: total_db_chunks_from_msg,
                        chunks,
                        done,
                    } => {
                        let was_playing = *is_playing.read();
                        let old_len = chunk_list.read().len();

                        if *total_chunks_stream.read() == 0 {
                            total_chunks_stream.set(total_chunks);
                        }
                        if *total_db_chunks.read() == 0 {
                            total_db_chunks.set(total_db_chunks_from_msg);
                        }

                        let mut list = chunk_list.write();
                        // Streaming always appends slices for the next DB chunks in order,
                        // so we simply extend our local buffer.
                        for ch in chunks.iter() {
                            list.push(ch.clone());
                            let inc = ch.data.len();
                            let new_bytes = {
                                let v = *loaded_bytes.read();
                                v.saturating_add(inc)
                            };
                            loaded_bytes.set(new_bytes);
                        }

                        // If playback had reached the end of the buffered data, advance to the first newly arrived chunk
                        if was_playing && list.len() > old_len && *current_chunk_index.read() >= old_len.saturating_sub(1) {
                            #[cfg(feature = "web")]
                            {
                                last_processed_chunk.set(None);
                            }
                            current_chunk_index.set(old_len);
                        }

                        if done {
                            stream_complete.set(true);
                        } else {
                            // Smart chunk requesting based on playback state
                            let is_currently_playing = *is_playing.read();

                            if is_currently_playing {
                            // When playing, always request more to ensure smooth playback
                            // and that we get all chunks to the end
                            let cursor = list.len();
                                let _ = ws
                                    .send(SessionStreamClient::RequestMore {
                                        cursor,
                                        byte_budget: 256 * 1024,
                                    })
                                    .await;
                            } else {
                                // When paused, only buffer a small amount ahead to save bandwidth
                                let current_pos = *current_chunk_index.read();

                                // Get the current and last buffered DB chunk indices
                                let current_db_chunk = list.get(current_pos).and_then(|c| c.db_chunk_index).unwrap_or(0);
                                let last_buffered_db_chunk = list.last().and_then(|c| c.db_chunk_index).unwrap_or(0);

                                // Keep 2 DB chunks ahead when paused
                                let db_buffer_window = 2;
                                let needs_more = last_buffered_db_chunk < current_db_chunk + db_buffer_window;

                                if needs_more {
                                    let cursor = list.len();
                                    let _ = ws
                                        .send(SessionStreamClient::RequestMore {
                                            cursor,
                                            byte_budget: 256 * 1024,
                                        })
                                        .await;
                                }
                            }
                        }
                    }
                    SessionStreamServer::Snapshot(snap) => {
                        #[cfg(feature = "web")]
                        {
                            let _ = clear_terminal("replay-terminal");
                            let _ = write_to_terminal("replay-terminal", &snap.screen_buffer);
                            // vt100::Screen reports cursor position as 0-based (row, col),
                            // while ANSI CUP expects 1-based coordinates. Adjust both.
                            let cursor_row = snap.cursor_row.saturating_add(1);
                            let cursor_col = snap.cursor_col.saturating_add(1);
                            let cursor_move = format!("\x1b[{};{}H", cursor_row, cursor_col);
                            let _ = write_to_terminal("replay-terminal", &cursor_move);

                            // Reset playback tracking so the chunk at the new seek position
                            // is processed again by the playback loop.
                            last_processed_chunk.set(None);

                            // Bump playback epoch so any in-flight playback tasks
                            // from the previous seek are treated as stale.
                            let current_epoch = *playback_epoch.read();
                            playback_epoch.set(current_epoch.wrapping_add(1));

                            // Clear any in-flight animation so time jumps cleanly
                            animation_start_time.set(None);
                            animation_target_time.set(None);
                        }

                        // Reset state for the new seek position
                        current_time_ms.set(Some(snap.timestamp));
                        // Local playback always starts at the first buffered slice after this seek
                        current_chunk_index.set(0);

                        // Rebuild chunk_list to match the new position; we start with the
                        // snapshot's DB chunk and let streaming append subsequent slices.
                        let mut list = chunk_list.write();
                        list.clear();

                        // Add the snapshot chunk itself with the correct timestamp
                        // and DB chunk index; streaming will resume from snap.chunk_index + 1.
                        list.push(SessionChunk {
                            timestamp: snap.timestamp,
                            direction: 0,
                            data: String::new(), // Data is already in the terminal snapshot
                            connection_id: None,
                            user_id: None,
                            username: None,
                            connection_type: None,
                            ip_address: None,
                            user_agent: None,
                            ssh_client: None,
                            is_admin_input: false,
                            timing_markers: None,
                            db_chunk_index: Some(snap.chunk_index),
                        });

                        // Reset loaded bytes as we cleared the list
                        loaded_bytes.set(0);
                    }
                    SessionStreamServer::End { reason: _ } => {
                        stream_complete.set(true);
                    }
                    SessionStreamServer::Error { message, chunk_index: _ } => {
                        stream_error.set(Some(message));
                        stream_complete.set(true);
                    }
                }
            }
        }
    });

    // Calculate session metadata
    let session_info = use_memo(move || {
        if let Some(Ok(summary)) = session_meta.read().as_ref() {
            let start_time = summary.session.start_time;
            // Prefer last_chunk_ts for timeline scaling to avoid showing empty tail time
            // This ensures the timeline and progress bar fill the width based on actual content
            let end_time = summary.last_chunk_ts.or(summary.session.end_time).unwrap_or(start_time);
            let duration_ms = end_time.saturating_sub(start_time);

            #[cfg(feature = "web")]
            web_sys::console::log_1(
                &format!(
                    "Session Info: start={}, end={}, last_chunk={:?}, duration={}",
                    start_time, end_time, summary.last_chunk_ts, duration_ms
                )
                .into(),
            );

            Some((start_time, end_time, duration_ms))
        } else {
            None
        }
    });

    // Recorded terminal size (cols, rows) from session metadata, if available.
    #[cfg(feature = "web")]
    let session_terminal_size = use_memo(move || {
        if let Some(Ok(summary)) = session_meta.read().as_ref() {
            let meta = &summary.session.metadata;
            let cols = meta
                .get("terminal")
                .and_then(|t| t.get("cols"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u16;
            let rows = meta
                .get("terminal")
                .and_then(|t| t.get("rows"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u16;
            if cols > 0 && rows > 0 {
                Some((cols, rows))
            } else {
                None
            }
        } else {
            None
        }
    });

    // Group chunks for the sidebar
    let grouped_events = use_memo(move || {
        if let Some(Ok(events)) = input_events.read().as_ref() {
            map_chunks(events)
        } else {
            Vec::new()
        }
    });

    // Initialize terminal when component mounts with retry logic.
    // For recordings with a stored terminal size, wait until metadata is ready
    // so we can initialize xterm with the correct cols/rows instead of fitting
    // to the container.
    #[cfg(feature = "web")]
    let session_meta_for_terminal = session_meta.clone();

    #[cfg(feature = "web")]
    use_effect(move || {
        // Ensure we have attempted to load session metadata before initializing
        // so that `session_terminal_size()` reflects the recording geometry.
        let meta_ready = session_meta_for_terminal.read().is_some();
        if !meta_ready {
            return;
        }

        let term_size = session_terminal_size();
        if !*terminal_initialized.read() && terminal_error.read().is_none() {
            spawn(async move {
                const MAX_RETRIES: u32 = 5;

                for retry_count in 0..MAX_RETRIES {
                    // Exponential backoff: 100ms, 200ms, 400ms, 800ms, 1600ms
                    let delay_ms = 100 * (1 << retry_count);
                    gloo_timers::future::TimeoutFuture::new(delay_ms).await;

                    // Check if the DOM element exists before calling init
                    #[cfg(feature = "web")]
                    {
                        if let Some(window) = web_sys::window() {
                            if let Some(document) = window.document() {
                                if document.get_element_by_id("replay-terminal").is_some() {
                                    match init_terminal(
                                        "replay-terminal",
                                        term_size,
                                    ) {
                                        Ok(()) => {
                                            terminal_initialized.set(true);
                                            return; // Success - exit the retry loop
                                        }
                                        Err(e) => {
                                            #[cfg(feature = "web")]
                                            web_sys::console::warn_1(
                                                &format!("Failed to initialize terminal (attempt {}): {:?}", retry_count + 1, e).into(),
                                            );
                                            // Continue to next retry
                                        }
                                    }
                                } else {
                                    #[cfg(feature = "web")]
                                    web_sys::console::warn_1(
                                        &format!("Terminal container not found (attempt {}), retrying...", retry_count + 1).into(),
                                    );
                                    // Continue to next retry
                                }
                            }
                        }
                    }
                }

                // If we get here, all retries failed
                terminal_error.set(Some(format!(
                    "Failed to initialize terminal after {} attempts. The terminal container may not be ready.",
                    MAX_RETRIES
                )));
            });
        }
    });

    // Smooth animation loop for time display
    #[cfg(feature = "web")]
    use_effect(move || {
        let playing = *is_playing.read();
        let start = *animation_start_time.read();
        let target = *animation_target_time.read();
        let current_speed = *playback_speed.read(); // Capture current speed

        if playing && start.is_some() && target.is_some() {
            let start_val = start.unwrap();
            let target_val = target.unwrap();
            let duration = (target_val - start_val).max(1);

            let epoch = *playback_epoch.read();
            let playback_epoch = playback_epoch.clone();
            spawn(async move {
                let frame_duration = 16; // ~60fps
                let total_frames = ((duration as f64 / current_speed) / frame_duration as f64).ceil() as u32;

                for frame in 0..=total_frames {
                    if *playback_epoch.read() != epoch || !*is_playing.read() {
                        break;
                    }
                    let progress = (frame as f64) / (total_frames as f64);
                    let interpolated = start_val + ((target_val - start_val) as f64 * progress) as i64;
                    current_time_ms.set(Some(interpolated));

                    if frame < total_frames && *is_playing.read() {
                        gloo_timers::future::TimeoutFuture::new(frame_duration).await;
                    } else {
                        break;
                    }
                }
            });
        }
    });

    #[cfg(feature = "web")]
    use_effect(move || {
        let playing = *is_playing.read();
        let initialized = *terminal_initialized.read();
        let current_idx = *current_chunk_index.read();
        let last_processed = *last_processed_chunk.read();

        if !playing || !initialized {
            return;
        }

        // Only process if this chunk hasn't been processed yet
        if Some(current_idx) == last_processed {
            return;
        }

        let chunk_list = active_chunks();
        let total_chunks = chunk_list.len();

        if total_chunks == 0 {
            // Nothing to play yet; keep the play state so playback resumes when data arrives
            return;
        }

        if current_idx >= total_chunks {
            if *stream_complete.read() {
                is_playing.set(false);
            }
            return;
        }

        // Write current chunk to terminal
        if let Some(chunk) = chunk_list.get(current_idx) {
            if chunk.direction == 0 {
                // Output only
                if let Ok(decoded) = BASE64_STANDARD.decode(&chunk.data) {
                    let text_lossy = String::from_utf8_lossy(&decoded);
                    let text = text_lossy.to_string();
                    // Check if chunk has timing markers
                    if let Some(ref markers) = chunk.timing_markers {
                        if !markers.is_empty() {
                            // Stream the chunk with timing markers
                            let markers_clone: Vec<(usize, i64)> = markers.clone();
                            let current_speed = *playback_speed.read();
                            let next_idx = current_idx + 1;
                            let mut current_chunk_index = current_chunk_index.clone();
                            let mut last_processed_chunk = last_processed_chunk.clone();
                            let mut animation_target_time = animation_target_time.clone();
                            let mut _is_playing = is_playing.clone();
                            let epoch = *playback_epoch.read();
                            let playback_epoch = playback_epoch.clone();

                            // Capture timestamps for gap calculation
                            let current_ts = chunk.timestamp;
                            let next_chunk_ts = if next_idx < total_chunks {
                                Some(chunk_list[next_idx].timestamp)
                            } else {
                                None
                            };

                            // Prevent re-processing this chunk while marker streaming is in flight
                            last_processed_chunk.set(Some(current_idx));

                            // Set animation times BEFORE spawn - animate from current chunk to next chunk
                            if let Some(next_ts) = next_chunk_ts {
                                let should_animate = match *animation_start_time.read() {
                                    Some(start) => current_ts >= start && next_ts > current_ts, // Never go backward, only forward
                                    None => next_ts > current_ts,                               // Only animate forward
                                };
                                if should_animate {
                                    animation_start_time.set(Some(current_ts));
                                    animation_target_time.set(Some(next_ts));
                                }
                            }

                            spawn(async move {
                                if *playback_epoch.read() != epoch || !*_is_playing.read() {
                                    return;
                                }
                                // Note: Animation times are set by the outer code
                                // We just wait for the delays here

                                // Calculate total time gap to next chunk
                                let total_gap_ms = if let Some(next_ts) = next_chunk_ts {
                                    next_ts.saturating_sub(current_ts)
                                } else {
                                    0
                                };

                                let mut time_spent_ms = 0;
                                let mut last_offset = 0;

                                for (byte_offset, delay_ms) in &markers_clone {
                                    // Write up to this marker
                                    if *byte_offset > last_offset && *byte_offset <= decoded.len() {
                                        let segment = &decoded[last_offset..*byte_offset];
                                        let segment_text = String::from_utf8_lossy(segment);
                                        let _ = write_to_terminal("replay-terminal", &segment_text);

                                        // Wait for the delay at this marker
                                        let scaled_delay = ((*delay_ms as f64) / current_speed).max(1.0) as u32;
                                        gloo_timers::future::TimeoutFuture::new(scaled_delay).await;

                                        time_spent_ms += scaled_delay;
                                        last_offset = *byte_offset;

                                        if *playback_epoch.read() != epoch || !*_is_playing.read() {
                                            return;
                                        }
                                    }
                                }

                                // Write remaining data after last marker
                                if last_offset < decoded.len() {
                                    let remaining = &decoded[last_offset..];
                                    let remaining_text = String::from_utf8_lossy(remaining);
                                    let _ = write_to_terminal("replay-terminal", &remaining_text);
                                }

                                // Wait for any remaining inter-chunk delay (idle time)
                                if total_gap_ms > 0 {
                                    let total_gap_scaled = ((total_gap_ms as f64) / current_speed) as u32;
                                    let remaining_wait = total_gap_scaled.saturating_sub(time_spent_ms);
                                    if remaining_wait > 0 {
                                        // Animate the remaining gap
                                        // We need to calculate where we are "virtually" in the gap
                                        // Virtual time spent = sum of marker delays
                                        let mut virtual_time_spent = 0;
                                        for (_, delay) in &markers_clone {
                                            virtual_time_spent += delay;
                                        }

                                        // However, we only played markers up to last_offset?
                                        // No, the loop iterates all markers.
                                        // And `time_spent_ms` accumulates scaled delays.

                                        // Just wait for the remaining gap
                                        // Animation is driven by the outer animation loop

                                        gloo_timers::future::TimeoutFuture::new(remaining_wait).await;
                                        if *playback_epoch.read() != epoch || !*_is_playing.read() {
                                            return;
                                        }
                                    }
                                }

                                // Always advance to next chunk after finishing markers and wait
                                // This ensures that if we paused, we are ready to play the next chunk when resumed
                                if *playback_epoch.read() != epoch || !*_is_playing.read() {
                                    return;
                                }
                                last_processed_chunk.set(Some(next_idx - 1));
                                // Don't clear animation target here - let the outer loop handle it
                                current_chunk_index.set(next_idx);
                            });
                            // Skip scheduling below; spawned task advances
                            return;
                        }
                    }
                    // No markers, write entire chunk at once
                    let _ = write_to_terminal("replay-terminal", &text);
                }
            }

            // Mark this chunk as processed
            last_processed_chunk.set(Some(current_idx));

            // Calculate delay to next chunk based on timestamp difference
            if current_idx + 1 < total_chunks {
                let next_chunk = &chunk_list[current_idx + 1];
                let time_diff_ms = next_chunk.timestamp - chunk.timestamp;

                // Only set animation times if we're transitioning to a new timestamp
                // (to avoid resetting the animation when processing mini-chunks with the same timestamp)
                let should_animate = match *animation_start_time.read() {
                    Some(start) => chunk.timestamp >= start && next_chunk.timestamp > chunk.timestamp, // Never go backward, only forward
                    None => next_chunk.timestamp > chunk.timestamp,                                    // Only animate forward
                };

                if should_animate {
                    animation_start_time.set(Some(chunk.timestamp));
                    animation_target_time.set(Some(next_chunk.timestamp));
                }

                // Read current speed for this chunk's timing
                let current_speed = *playback_speed.read();
                let delay_ms = ((time_diff_ms as f64) / current_speed).max(10.0) as u32; // enforce a small wait to keep ordering

                let epoch = *playback_epoch.read();
                let playback_epoch = playback_epoch.clone();
                spawn(async move {
                    gloo_timers::future::TimeoutFuture::new(delay_ms).await;
                    if *playback_epoch.read() != epoch || !*is_playing.read() {
                        return;
                    }
                    current_chunk_index.set(current_idx + 1);
                });
            } else {
                // Last buffered chunk. If stream still ongoing, keep playing and wait for more slices.
                if *stream_complete.read() {
                    current_time_ms.set(Some(chunk.timestamp));
                    animation_start_time.set(None);
                    animation_target_time.set(None);
                    is_playing.set(false);
                }
            }
        }
    });

    // If we're playing and reach the current buffered end while the stream is still ongoing, wait for more data instead of stopping.
    #[cfg(feature = "web")]
    use_effect(move || {
        let playing = *is_playing.read();
        let complete = *stream_complete.read();
        let idx = *current_chunk_index.read();
        let len = chunk_list.read().len();

        if !playing || complete || len == 0 {
            return;
        }

        if idx >= len.saturating_sub(1) {
            let mut is_playing = is_playing.clone();
            let stream_complete = stream_complete.clone();
            let chunk_list = chunk_list.clone();
            let current_chunk_index = current_chunk_index.clone();
            let mut last_processed_chunk = last_processed_chunk.clone();

            spawn(async move {
                loop {
                    gloo_timers::future::TimeoutFuture::new(120).await;

                    if !*is_playing.read() {
                        break;
                    }

                    let new_len = chunk_list.read().len();

                    if *stream_complete.read() && *current_chunk_index.read() >= new_len.saturating_sub(1) {
                        is_playing.set(false);
                        break;
                    }

                    if new_len > idx {
                        // New data arrived; let playback effect consume it
                        last_processed_chunk.set(None);
                        break;
                    }
                }
            });
        }
    });

    let mut show_sidebar = use_signal(|| true);

    rsx! {
        div { class: "flex flex-col",
            // Header with metadata
            div { class: "bg-base-200 p-4 border-b border-base-300",
                div { class: "flex justify-between items-start mb-2",
                    div {
                        h2 { class: "text-xl font-bold", "Session Replay" }
                        p { class: "text-sm text-base-content/60 font-mono", "{session_id}" }
                    }
                    div { class: "flex gap-2",
                        button {
                            class: "btn btn-sm btn-ghost",
                            onclick: move |_| {
                                let current = *show_sidebar.read();
                                show_sidebar.set(!current);
                            },
                            if *show_sidebar.read() { "Hide Log" } else { "Show Log" }
                        }
                        // Export dropdown
                        div { class: "dropdown dropdown-end",
                            div {
                                tabindex: "0",
                                role: "button",
                                class: "btn btn-sm btn-outline btn-primary",
                                "Export ▼"
                            }
                            ul {
                                tabindex: "0",
                                class: "dropdown-content menu bg-base-100 rounded-box z-[1] w-52 p-2 shadow",
                                li {
                                    a {
                                        href: "/api/audit/sessions/{session_id}/export/cast",
                                        target: "_blank",
                                        rel: "external",
                                        download: "session.cast",
                                        "Asciicinema (.cast)"
                                    }
                                }
                                li {
                                    a {
                                        href: "/api/audit/sessions/{session_id}/export/txt",
                                        target: "_blank",
                                        rel: "external",
                                        download: "session.txt",
                                        "Plain Text (.txt)"
                                    }
                                }
                            }
                        }
                    }
                    button {
                        class: "btn btn-sm btn-ghost",
                        onclick: move |_| {
                            // Go back in browser history
                            #[cfg(feature = "web")]
                            {
                                let _ = dioxus::document::eval(r#"window.history.back();"#);
                            }
                            #[cfg(not(feature = "web"))]
                            {
                                // Server-side: use navigator
                                let nav = navigator();
                                nav.go_back();
                            }
                        },
                        "← Back"
                    }
                }
            }

                // Session info & Metadata
            if let Some(Ok(response)) = session_meta.read().as_ref() {
                if let Some((start_time, _end_time, duration_ms)) = session_info() {
                div { class: "flex flex-col gap-2 mt-2",
                        // Primary info row
                        div { class: "flex gap-6 text-sm",
                            div {
                                span { class: "text-base-content/60", "Duration: " }
                                span { class: "font-mono font-semibold",
                                    {format_duration(duration_ms)}
                                }
                            }
                            div {
                                span { class: "text-base-content/60", "Current Time: " }
                                span { class: "font-mono font-semibold",
                                    {
                                        if let Some(current) = *current_time_ms.read() {
                                            format_duration(current - start_time)
                                        } else {
                                            "00:00.000".to_string()
                                        }
                                    }
                                }
                            }
                        }
                        // Extended Metadata
                        div { class: "flex flex-wrap gap-x-6 gap-y-1 text-xs opacity-70 border-t border-base-content/10 pt-2 mt-1",
                            if let Some(username) = &response.session.username {
                                div { span { class: "font-semibold", "User: " } "{username}" }
                            }
                            if let Some(relay) = &response.session.relay_name {
                                div { span { class: "font-semibold", "Relay: " } "{relay}" }
                            }
                            if let Some(size) = response.session.original_size_bytes {
                                div { span { class: "font-semibold", "Size: " } "{format_bytes(size)}" }
                            }
                            if let (Some(orig), Some(comp)) = (response.session.original_size_bytes, response.session.compressed_size_bytes) {
                                if orig > 0 {
                                    {
                                        let ratio = (1.0 - (comp as f64 / orig as f64)) * 100.0;
                                        rsx! {
                                            div { span { class: "font-semibold", "Compression: " } "{ratio:.1}%" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Main Content Area (Terminal + Sidebar)
        div { class: "flex-1 flex w-full max-w-full overflow-hidden",
                div { class: "flex-1 w-0 bg-black p-4 overflow-auto relative",
                    match &*session_meta.read_unchecked() {
                        Some(Ok(_response)) => {
                            #[cfg(feature = "web")]
                            {
                                let term_error = terminal_error.read().clone();
                                let term_init = *terminal_initialized.read();

                                rsx! {
                                    div { class: "h-fit w-fit relative",
                                        // Always render the terminal container so it exists for initialization
                                        div {
                                            id: "replay-terminal"
                                        }

                                        // Overlay loading or error state on top
                                        if let Some(error_msg) = term_error {
                                            div {
                                                class: "absolute inset-0 bg-black flex items-center justify-center",
                                                div { class: "alert alert-error flex flex-col gap-2 max-w-2xl",
                                                    h3 { class: "font-bold text-lg", "Terminal Initialization Failed" }
                                                    p { "{error_msg}" }
                                                    p { class: "text-sm opacity-80",
                                                        "This can happen with very large sessions. Try refreshing the page or using the export options above to download the session."
                                                    }
                                                }
                                            }
                                        } else if !term_init {
                                            div {
                                                class: "absolute inset-0 bg-black flex flex-col justify-center items-center gap-3",
                                                span { class: "loading loading-spinner loading-lg" }
                                                p { class: "text-base-content/60", "Initializing terminal..." }
                                            }
                                        }
                                    }
                                }
                            }

                            #[cfg(not(feature = "web"))]
                            rsx! {
                                div { class: "relative",
                                    div {
                                        id: "replay-terminal"
                                    }
                                }
                            }
                        },
                        Some(Err(e)) => rsx! {
                            div { class: "alert alert-error",
                                "Error loading session: {e}"
                            }
                        },
                        None => rsx! {
                            div { class: "flex flex-col justify-center items-center h-full gap-3",
                                span { class: "loading loading-spinner loading-lg" }
                                p { class: "text-base-content/60", "Loading session info..." }
                            }
                        }
                    }
                }

                // Event Log Sidebar
                if *show_sidebar.read() {
                    div { class: "w-80 flex-none bg-base-100 border-l border-base-300 flex flex-col",
                        div { class: "p-3 border-b border-base-300 font-bold text-sm bg-base-200",
                            "Event Log"
                        }
                        div { class: "flex-1 overflow-y-auto p-2 space-y-2",
                            if let Some(Ok(summary)) = session_meta.read().as_ref() {
                                {
                                    let events = grouped_events.read();
                                    let current_idx = *current_chunk_index.read();
                                    let start_time = summary.session.start_time;

                                    rsx! {
                                        for (i, event) in events.iter().enumerate() {
                                            // Show inputs (direction 1) and admin actions
                                            if event.direction == 1 || event.is_admin {
                                                {
                                                    let event_start_index = event.start_index;
                                                    rsx! {
                                                        div {
                                                    key: "{i}",
                                                    class: format!("p-2 rounded text-xs cursor-pointer hover:bg-base-200 transition-colors {}",
                                                        // Highlight if current chunk index is within this event's range
                                                        if current_idx >= event.start_index && current_idx <= event.end_index {
                                                            "bg-primary/10 border-l-2 border-primary"
                                                        } else {
                                                            "border-l-2 border-transparent"
                                                        }
                                                    ),
                                                    onclick: move |_| {
                                                        is_playing.set(false);
                                                        stream_started.set(true);
                                                        stream_complete.set(false);
                                                        stream_error.set(None);

                                                        // New seek epoch from event log
                                                        let current_epoch = *playback_epoch.read();
                                                        playback_epoch.set(current_epoch.wrapping_add(1));

                                                        // Get the DB chunk index from the event
                                                        // The event.start_index is relative to the input_events list, not the full stream
                                                        // We need to find the actual db_chunk_index from the event chunk
                                                        if let Some(Ok(events)) = input_events.read().as_ref() {
                                                            if let Some(chunk) = events.get(event_start_index) {
                                                                if let Some(db_idx) = chunk.db_chunk_index {
                                                                    let ws = ws.clone();
                                                                    spawn(async move {
                                                                        let _ = ws.send(SessionStreamClient::Seek {
                                                                            target_chunk: db_idx,
                                                                            want_snapshot: true
                                                                        }).await;
                                                                    });
                                                                }
                                                            }
                                                        }
                                                    },
                                                    div { class: "flex justify-between text-base-content/60 mb-1",
                                                        span { "{format_duration(event.timestamp - start_time)}" }
                                                        span { class: if event.is_admin { "text-error font-bold" } else { "" },
                                                            "{event.username.as_deref().unwrap_or(\"Unknown\")}"
                                                        }
                                                    }
                                                    div { class: "font-mono break-all bg-base-300 p-1 rounded whitespace-pre-wrap",
                                                        {render_event_content(&event.content)}
                                                    }
                                                }}}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        // Controls
        div { class: "bg-base-200 p-4 border-t border-base-300",
            {
                let chunks_for_controls = active_chunks();
                // Prefer the real DB chunk count from the streamer; fall back to summary.
                let total_db = *total_db_chunks.read();
                let summary_total = session_meta
                    .read()
                    .as_ref()
                    .and_then(|r| r.as_ref().ok())
                    .map(|meta| meta.chunk_count)
                    .unwrap_or(0);
                let total_chunks = if total_db > 0 { total_db } else { summary_total };

                let current_idx = (*current_chunk_index.read()).min(total_chunks.saturating_sub(1));

                let progress_pct = if let (Some((start_time, end_time, duration_ms)), Some(current)) =
                    (session_info(), *current_time_ms.read())
                {
                    if duration_ms > 0 {
                        // Clamp current time into the session window to avoid
                        // negative or out-of-range offsets after seeks.
                        let clamped_current = current.clamp(start_time, end_time);
                        let current_offset = clamped_current - start_time;
                        ((current_offset as f64 / duration_ms as f64) * 100.0).clamp(0.0, 100.0)
                    } else if total_chunks > 1 {
                        ((current_idx as f64) / ((total_chunks.saturating_sub(1)) as f64) * 100.0).min(100.0)
                    } else {
                        100.0
                    }
                } else if total_chunks > 1 {
                    ((current_idx as f64) / ((total_chunks - 1) as f64) * 100.0).min(100.0)
                } else {
                    0.0
                };

                                                rsx! {
                    div { class: "space-y-3",
                        div { class: "relative group",
                            div { class: "w-full bg-base-300 rounded-full h-4 relative overflow-hidden",
                                div {
                                    class: "bg-primary h-full rounded-full opacity-30",
                                    style: "width: {progress_pct}%"
                                }

                                {
                                    if let Some(Ok(events)) = input_events.read().as_ref() {
                                        rsx! {
                                            {events.iter().enumerate()
                                                .filter_map(|(i, chunk)| {
                                                    // Only show markers for chunks with db_chunk_index
                                                    let db_idx = chunk.db_chunk_index?;

                                                    // Only show the first mini-chunk for each DB chunk
                                                    // Since we are iterating all input events, we might have multiple per DB chunk if they were split?
                                                    // Actually input events are usually small and 1:1 with DB chunks unless very large.
                                                    // But let's keep the check just in case.
                                                    let is_first_in_db_chunk = if i == 0 {
                                                        true
                                                    } else {
                                                        events.get(i - 1)
                                                            .and_then(|prev| prev.db_chunk_index)
                                                            .map(|prev_idx| prev_idx != db_idx)
                                                            .unwrap_or(true)
                                                    };

                                                    if !is_first_in_db_chunk {
                                                        return None;
                                                    }

                                                    let position = if let Some((session_start_time, _session_end_time, session_duration_ms)) = session_info() {
                                                        if session_duration_ms > 0 {
                                                            ((chunk.timestamp - session_start_time) as f64 / session_duration_ms as f64) * 100.0
                                                        } else {
                                                            0.0
                                                        }
                                                    } else {
                                                        0.0
                                                    };
                                                    let is_output = chunk.direction == 0;
                                                    let is_admin = chunk.is_admin_input;

                                                    let color_class = if is_output {
                                                        "bg-success/40"
                                                    } else if is_admin {
                                                        "bg-error/80 w-1 z-10"
                                                    } else {
                                                        "bg-warning/60"
                                                    };

                                                    let mut sections = vec![];
                                                    let mut basic_items = vec![
                                                        format!("Type: {}", if is_output { "Output" } else { "Input" }),
                                                        format!("User: {}", chunk.username.as_deref().unwrap_or("Unknown")),
                                                        format!("DB Chunk: {}", db_idx),
                                                    ];
                                                    if is_admin {
                                                        basic_items.push("Role: Admin".to_string());
                                                    }
                                                    sections.push(
                                                        TooltipSection::new("Event Info")
                                                            .with_items(basic_items)
                                                            .with_max_items(10)
                                                    );

                                                    if !is_output {
                                                        let mut conn_items = vec![];
                                                        if let Some(conn_type) = &chunk.connection_type {
                                                            conn_items.push(format!("Type: {}", conn_type.to_uppercase()));
                                                        }
                                                        if let Some(ip) = &chunk.ip_address {
                                                            conn_items.push(format!("IP: {}", ip));
                                                        }
                                                        if let Some(ua) = &chunk.user_agent {
                                                            conn_items.push(format!("User-Agent: {}", ua));
                                                        }
                                                        if let Some(ssh) = &chunk.ssh_client {
                                                            conn_items.push(format!("SSH Client: {}", ssh));
                                                        }

                                                        if !conn_items.is_empty() {
                                                            sections.push(
                                                                TooltipSection::new("Connection")
                                                                    .with_items(conn_items)
                                                                    .with_max_items(10)
                                                            );
                                                        }
                                                    }

                                                    Some(rsx! {
                                                        StructuredTooltip {
                                                            sections: sections,
                                                            div {
                                                                key: "{db_idx}",
                                                                class: "absolute top-0 h-full {color_class}",
                                                                style: "left: {position}%; width: 0.2%; min-width: 1px;",
                                                            }
                                                        }
                                                    })
                                                })
                                                .take(500) // Limit to 500 markers
                                            }
                                        }
                                    } else {
                                        rsx! {}
                                    }
                                }
                            }

                            {
                                let (session_start, session_end, session_duration) = session_info().unwrap_or((0, 0, 0));
                                let raw_current = current_time_ms.read().unwrap_or(session_start);
                                // Keep the slider value within the known session window so we
                                // never emit negative or out-of-range offsets.
                                let clamped_current = if session_duration > 0 {
                                    raw_current.clamp(session_start, session_end)
                                } else {
                                    session_start
                                };
                                let current_offset = clamped_current - session_start;

                                rsx! {
                                    input {
                                        r#type: "range",
                                        min: "0",
                                        max: "{session_duration}",
                                        value: "{current_offset}",
                                        class: "range range-xs w-full absolute top-0 opacity-0 cursor-pointer h-4",
                                        onchange: move |evt| {
                                            if let Ok(offset) = evt.value().parse::<i64>() {
                                                is_playing.set(false);
                                                stream_started.set(true);
                                                stream_complete.set(false);
                                                stream_error.set(None);

                                                // New seek epoch from timeline
                                                let current_epoch = *playback_epoch.read();
                                                playback_epoch.set(current_epoch.wrapping_add(1));

                                                let target_time = session_start + offset;

                                                // Find the chunk closest to this time
                                                let mut target_chunk_idx = 0;
                                                if let Some(Ok(events)) = input_events.read().as_ref() {
                                                    // Find chunk with timestamp closest to target_time
                                                    if let Some(chunk) = events.iter().min_by_key(|c| (c.timestamp - target_time).abs()) {
                                                        target_chunk_idx = chunk.db_chunk_index.unwrap_or(0);
                                                    }
                                                }

                                                let ws = ws.clone();
                                                spawn(async move {
                                                    let _ = ws.send(SessionStreamClient::Seek {
                                                        target_chunk: target_chunk_idx,
                                                        want_snapshot: true
                                                    }).await;
                                                });
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        div { class: "flex items-center gap-3",
                            {
                                let chunk_count = total_chunks;
                                rsx! {
                                    button {
                                        class: "btn btn-sm btn-primary",
                                        onclick: move |_| {
                                            let current = *is_playing.read();

                                            if !*stream_started.read() {
                                                stream_started.set(true);
                                                stream_error.set(None);
                                                stream_complete.set(false);
                                                loaded_bytes.set(0);
                                                chunk_list.write().clear();
                                                let ws = ws.clone();
                                                        spawn(async move {
                                                            let _ = ws
                                                                .send(SessionStreamClient::Hello {
                                                                    start_index: 0,
                                                                    byte_budget: 256 * 1024,
                                                                })
                                                                .await;
                                                        });
                                                    }

                                            // Starting or restarting playback is a new epoch if
                                            // we are jumping back to the beginning.
                                            if !current && *current_chunk_index.read() == 0 {
                                                let current_epoch = *playback_epoch.read();
                                                playback_epoch.set(current_epoch.wrapping_add(1));
                                            }

                                            if !current && *current_chunk_index.read() >= chunk_count.saturating_sub(1) {
                                                current_chunk_index.set(0);
                                                #[cfg(feature = "web")]
                                                {
                                                    let _ = clear_terminal("replay-terminal");
                                                    last_processed_chunk.set(None);
                                                }
                                            }

                                            // If we're transitioning from paused to playing, check if we need more chunks
                                            if !current && *stream_started.read() && !*stream_complete.read() {
                                                let current_pos = *current_chunk_index.read();
                                                let chunk_list_read = chunk_list.read();

                                                // Get current and last buffered DB chunk indices
                                                let current_db_chunk = chunk_list_read.get(current_pos)
                                                    .and_then(|c| c.db_chunk_index)
                                                    .unwrap_or(0);
                                                let last_buffered_db_chunk = chunk_list_read.last()
                                                    .and_then(|c| c.db_chunk_index)
                                                    .unwrap_or(0);

                                                let db_buffer_window = 5; // Same as playing buffer

                                                if last_buffered_db_chunk < current_db_chunk + db_buffer_window {
                                                    let ws_clone = ws.clone();
                                                    let cursor = chunk_list_read.len();
                                                    drop(chunk_list_read); // Release the read lock
                                                    spawn(async move {
                                                        let _ = ws_clone
                                                            .send(SessionStreamClient::RequestMore {
                                                                cursor,
                                                                byte_budget: 256 * 1024,
                                                            })
                                                            .await;
                                                    });
                                                }
                                            }

                                            is_playing.set(!current);
                                        },
                                        if *is_playing.read() { "⏸ Pause" } else { "▶ Play" }
                                    }
                                }
                            }

                            button {
                                class: "btn btn-sm btn-ghost",
                                onclick: move |_| {
                                    is_playing.set(false);
                                    current_chunk_index.set(0);
                                    current_time_ms.set(None);
                                    #[cfg(feature = "web")]
                                    {
                                        let _ = clear_terminal("replay-terminal");
                                    }
                                },
                                "⏹ Reset"
                            }

                            div { class: "flex-1 text-center",
                                span { class: "text-sm font-mono",
                                    {
                                        // Use total_db_chunks if available (from streaming), otherwise fall back
                                        let db_count = *total_db_chunks.read();
                                        if db_count > 0 {
                                            // Calculate current DB chunk index from current mini-chunk
                                            let current_db_idx = chunks_for_controls
                                                .get(current_idx)
                                                .and_then(|c| c.db_chunk_index)
                                                .map(|idx| idx + 1)
                                                .unwrap_or(1);
                                            format!("Chunk {} / {}", current_db_idx, db_count)
                                        } else {
                                            format!("Chunk {} / {}", current_idx + 1, total_chunks.max(1))
                                        }
                                    }
                                }
                            }

                            div { class: "flex items-center gap-2",
                                span { class: "text-xs text-base-content/60", "Speed:" }
                                select {
                                    class: "select select-sm select-bordered",
                                    value: "{*playback_speed.read()}",
                                    onchange: move |evt| {
                                        if let Ok(speed) = evt.value().parse::<f64>() {
                                            playback_speed.set(speed);
                                        }
                                    },
                                    option { value: "0.25", selected: *playback_speed.read() == 0.25, "0.25x" }
                                    option { value: "0.5", selected: *playback_speed.read() == 0.5, "0.5x" }
                                    option { value: "1.0", selected: *playback_speed.read() == 1.0, "1.0x" }
                                    option { value: "2.0", selected: *playback_speed.read() == 2.0, "2.0x" }
                                    option { value: "4.0", selected: *playback_speed.read() == 4.0, "4.0x" }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
