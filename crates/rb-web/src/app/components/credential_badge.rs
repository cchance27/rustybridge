use dioxus::prelude::*;

/// Reusable pill that renders a friendly credential label for password/ssh/agent variants.
#[component]
pub fn CredentialBadge(
    kind: String,
    username_mode: Option<String>,
    password_required: Option<bool>,
    /// For inline/custom auth, prepend "Custom" to the type label.
    #[props(default = false)]
    custom_prefix: bool,
    /// Include the base kind ("Password") before the variant (User+Pass) for list views.
    #[props(default = false)]
    kind_prefix: bool,
    /// Mode hint ("saved" | "custom") to tweak ordering/labels in compound layout.
    #[props(default = None)]
    mode: Option<String>,
    /// Render as a single overlapping "combo" pill (type then name).
    #[props(default = false)]
    compound: bool,
    /// Optional display name; when provided the component shows "name  [type]"
    #[props(default = None)]
    name: Option<String>,
    #[props(default = true)] show_type: bool,
    /// Optional clear affordance; when provided, hovering replaces the pill with a red "Clear" pill.
    #[props(default = None)]
    on_clear: Option<EventHandler<()>>,
) -> Element {
    let mut hover = use_signal(|| false);

    let base_container = "relative inline-flex items-center gap-0 text-[11px] cursor-pointer select-none";
    let name_class = if compound {
        "badge-ghost text-[11px]"
    } else {
        "badge-primary text-[11px]"
    };
    let type_class = if let Some(badge_mode) = mode.clone() {
        if badge_mode == "custom" {
            "badge-info text-[11px]"
        } else {
            "badge-primary text-[11px]"
        }
    } else {
        "badge-primary text-[11px]"
    };

    let kind = kind.to_lowercase();
    let effective_custom_prefix = if mode.as_deref() == Some("custom") { false } else { custom_prefix };
    let type_label = render_label(
        &kind,
        username_mode.as_deref(),
        password_required,
        effective_custom_prefix,
        kind_prefix,
    );
    let is_custom = mode.as_deref() == Some("custom");
    let has_name = name.is_some();
    let clear_available = on_clear.is_some();

    let on_clear_handler = on_clear;

    let content = if compound && show_type && !type_label.is_empty() {
        // Overlapped two-tone pill
        match (is_custom, has_name) {
            (true, _) => {
                let right = type_label.clone().to_lowercase();
                let left_class = if hover() && clear_available {
                    "badge badge-secondary text-[11px] pr-7".to_string()
                } else {
                    format!("badge {type_class} text-[11px] pr-7")
                };
                let right_text = if hover() && clear_available {
                    "clear credential"
                } else {
                    right.as_str()
                };
                // Use the longer text length to set a fixed width
                let max_len = std::cmp::max(right.len(), "clear credential".len());
                let width = format!("{max_len}ch");
                rsx! { Fragment {
                    span { class: "{left_class}", "Custom" }
                    span {
                        class: "badge {name_class} -ml-5 shadow-sm inline-flex items-center justify-start whitespace-nowrap overflow-hidden",
                        style: "width: {width};",
                        "{right_text}"
                    }
                } }
            }
            (false, true) => {
                let n = name.unwrap();
                let left_class = if hover() && clear_available {
                    "badge badge-secondary text-[11px] pr-7".to_string()
                } else {
                    format!("badge {type_class} pr-7")
                };
                let right_text = if hover() && clear_available {
                    "clear credential"
                } else {
                    n.as_str()
                };
                // Use the longer text length to set a fixed width
                let max_len = std::cmp::max(n.len(), "clear credential".len());
                let width = format!("{max_len}ch");
                rsx! { Fragment {
                    span { class: "{left_class}", "{type_label}" }
                    span {
                        class: "badge {name_class} -ml-5 shadow-sm inline-flex items-center justify-start whitespace-nowrap overflow-hidden",
                        style: "width: {width};",
                        "{right_text}"
                    }
                } }
            }
            (false, false) => {
                rsx! { span { class: "badge {type_class}", "{type_label}" } }
            }
        }
    } else {
        rsx! { Fragment {
            if let Some(n) = name {
                span { class: "badge {name_class}", "{n}" }
            }
            if show_type && !type_label.is_empty() {
                span { class: "badge {type_class}", "{type_label}" }
            }
        } }
    };

    let container_class = format!("{base_container} {}", if compound { "rounded-full" } else { "" });
    let clear_available = on_clear_handler.is_some();

    rsx! {
        button {
            class: "{container_class}",
            r#type: "button",
            onmouseenter: move |_| hover.set(true),
            onmouseleave: move |_| hover.set(false),
            onclick: move |_| {
                if clear_available
                    && let Some(handler) = on_clear_handler.as_ref() {
                        handler.call(());
                    }
            },
            {content}
        }
    }
}

fn render_label(
    kind: &str,
    username_mode: Option<&str>,
    password_required: Option<bool>,
    custom_prefix: bool,
    kind_prefix: bool,
) -> String {
    let variant = match kind {
        "password" => match username_mode.unwrap_or("fixed") {
            "passthrough" => "Passthrough",
            "blank" => "Interactive",
            "fixed" => {
                if password_required.unwrap_or(true) {
                    "User & Pass"
                } else {
                    "User Only"
                }
            }
            _ => "Password",
        },
        "ssh_key" => "SSH Key",
        "agent" => "Agent",
        other => other,
    };

    let base = if kind_prefix {
        match kind {
            "password" => format!("Password · {}", variant),
            "ssh_key" => "SSH Key".to_string(),
            "agent" => "Agent".to_string(),
            _ => variant.to_string(),
        }
    } else {
        variant.to_string()
    };

    if custom_prefix { format!("Custom · {}", base) } else { base }
}
