use dioxus::prelude::*;

#[component]
pub fn Fab(onclick: EventHandler<()>) -> Element {
    rsx! {
        button {
            class: "btn btn-circle btn-primary fixed bottom-8 right-8 shadow-lg",
            onclick: move |_| onclick.call(()),
            svg {
                xmlns: "http://www.w3.org/2000/svg",
                class: "h-6 w-6",
                fill: "none",
                view_box: "0 0 24 24",
                stroke: "currentColor",
                path {
                    stroke_linecap: "round",
                    stroke_linejoin: "round",
                    stroke_width: "2",
                    d: "M12 4v16m8-8H4"
                }
            }
        }
    }
}
