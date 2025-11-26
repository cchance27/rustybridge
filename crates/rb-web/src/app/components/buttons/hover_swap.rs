use dioxus::prelude::*;

#[component]
pub fn HoverSwapButton(
    /// Optional extra click handler
    #[props(default = None)]
    on_click: Option<EventHandler<MouseEvent>>,

    /// Content shown normally
    regular: Element,

    /// Content shown on hover
    hover: Element,

    /// Optional extra classes
    #[props(default = "badge badge-success gap-2 hover:badge-error")]
    class: &'static str,
) -> Element {
    rsx! {
        button {
            class: "group relative cursor-pointer transition-colors {class}",
            onclick: move |evt| {
                if let Some(handler) = &on_click {
                    handler.call(evt);
                }
            },

            span {
                class: "group-hover:hidden flex items-center gap-1",
                {regular}
            }

            span {
                class: "hidden group-hover:flex items-center gap-1",
                {hover}
            }
        }
    }
}
