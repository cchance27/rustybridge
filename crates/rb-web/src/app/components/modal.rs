use dioxus::prelude::*;

#[component]
pub fn Modal(open: bool, on_close: EventHandler<()>, title: String, children: Element, actions: Option<Element>) -> Element {
    if !open {
        return rsx! {};
    }

    rsx! {
        dialog { class: "modal modal-open modal-bottom sm:modal-middle",
            div { class: "modal-box",
                h3 { class: "font-bold text-lg", "{title}" }
                div { class: "py-4", {children} }
                div { class: "modal-action",
                    if let Some(actions) = actions {
                        {actions}
                    }
                    button { class: "btn", onclick: move |_| on_close.call(()), "Close" }
                }
            }
            // Backdrop to close
            div { class: "modal-backdrop", onclick: move |_| on_close.call(()), }
        }
    }
}
