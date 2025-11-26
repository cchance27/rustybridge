use dioxus::prelude::*;

#[component]
pub fn XIcon() -> Element {
    rsx! (
        svg {
            xmlns: "http://www.w3.org/2000/svg",
            class: "h-3 w-3",
            fill: "none",
            view_box: "0 0 24 24",
            stroke: "currentColor",
            path {
                stroke_linecap: "round",
                stroke_linejoin: "round",
                stroke_width: "2",
                d: "M6 18L18 6M6 6l12 12"
            }
        }
    )
}
