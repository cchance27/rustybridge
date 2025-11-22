use dioxus::prelude::*;

fn on_mouse_enter(evt: MouseEvent, position: &mut Signal<(f64, f64)>, is_visible: &mut Signal<bool>) {
    #[cfg(feature = "web")]
    {
        // Calculate position using web_sys
        use dioxus::web::WebEventExt;
        use web_sys::wasm_bindgen::JsCast;

        if let Some(target) = evt.as_web_event().current_target() {
            if let Some(element) = target.dyn_ref::<web_sys::Element>() {
                let rect = element.get_bounding_client_rect();
                // Position above the element, centered horizontally
                // Add some spacing (10px)
                let top = rect.top() - 10.0;
                let left = rect.left() + (rect.width() / 2.0);

                position.set((top, left));
                is_visible.set(true);
            }
        }
    }
    #[cfg(not(feature = "web"))]
    {
        // Do nothing
        let _ = evt;
        let _ = position;
        is_visible.set(false);
    }
}

/// A structured tooltip component for displaying organized lists of items
/// Supports multiple sections with headers and item limits
#[component]
pub fn StructuredTooltip(
    /// Sections to display in the tooltip, each with a header and list of items
    sections: Vec<TooltipSection>,
    /// The content that triggers the tooltip (e.g., a badge or button)
    children: Element,
) -> Element {
    // Track visibility and position
    let mut is_visible = use_signal(|| false);
    #[allow(unused_mut)]
    let mut position = use_signal(|| (0.0, 0.0)); // (top, left)

    rsx! {
        div {
            class: "inline-block cursor-pointer",

            onmouseenter: move |evt| on_mouse_enter(evt, &mut position, &mut is_visible),
            onmouseleave: move |_| is_visible.set(false),
            {children}
        }

        if is_visible() {
            // Render tooltip with fixed positioning to break out of overflow containers
            // Use transform to center horizontally and move above the target
            div {
                class: "fixed z-[9999] bg-base-300 text-base-content p-3 rounded-lg shadow-lg border border-base-content/10 min-w-fit flex flex-row gap-6",
                style: "top: {position().0}px; left: {position().1}px; transform: translate(-50%, -100%);",
                for section in sections {
                    div { class: "flex-1 min-w-[120px]",
                        if let Some(header) = section.header {
                            div { class: "font-semibold text-sm mb-1 text-primary text-center", "{header}" }
                        }
                        if section.items.is_empty() {
                            div { class: "text-sm text-base-content/60 italic",
                                {section.empty_message.unwrap_or("None")}
                            }
                        } else {
                            div { class: "text-sm space-y-0.5",
                                for (idx, item) in section.items.iter().enumerate() {
                                    if idx < section.max_items {
                                        div { class: "text-base-content/80", "• {item}" }
                                    }
                                }
                                if section.items.len() > section.max_items {
                                    div { class: "text-base-content/60 italic text-xs mt-1",
                                        "and {section.items.len() - section.max_items} more..."
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// A section within a structured tooltip
#[derive(Clone, Debug, PartialEq)]
pub struct TooltipSection {
    /// Optional header for this section
    pub header: Option<String>,
    /// List of items to display
    pub items: Vec<String>,
    /// Maximum number of items to show before truncating
    pub max_items: usize,
    /// Message to show when items list is empty
    pub empty_message: Option<&'static str>,
}

impl TooltipSection {
    /// Create a new tooltip section
    pub fn new(header: impl Into<String>) -> Self {
        Self {
            header: Some(header.into()),
            items: Vec::new(),
            max_items: 5,
            empty_message: None,
        }
    }

    /// Create a section without a header
    pub fn without_header() -> Self {
        Self {
            header: None,
            items: Vec::new(),
            max_items: 5,
            empty_message: None,
        }
    }

    /// Set the items for this section
    pub fn with_items(mut self, items: Vec<String>) -> Self {
        self.items = items;
        self
    }

    /// Set the maximum number of items to display
    pub fn with_max_items(mut self, max: usize) -> Self {
        self.max_items = max;
        self
    }

    /// Set the message to show when empty
    pub fn with_empty_message(mut self, message: &'static str) -> Self {
        self.empty_message = Some(message);
        self
    }
}
