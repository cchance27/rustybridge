use dioxus::prelude::*;

#[component]
pub fn ChevronUpIcon(class: Option<String>) -> Element {
    rsx! {
        svg {
            class: class.unwrap_or_default(),
            xmlns: "http://www.w3.org/2000/svg",
            view_box: "0 0 20 20",
            fill: "currentColor",
            path {
                fill_rule: "evenodd",
                d: "M14.707 12.707a1 1 0 01-1.414 0L10 9.414l-3.293 3.293a1 1 0 01-1.414-1.414l4-4a1 1 0 011.414 0l4 4a1 1 0 010 1.414z",
                clip_rule: "evenodd"
            }
        }
    }
}

#[component]
pub fn ChevronDownIcon(class: Option<String>) -> Element {
    rsx! {
        svg {
            class: class.unwrap_or_default(),
            xmlns: "http://www.w3.org/2000/svg",
            view_box: "0 0 20 20",
            fill: "currentColor",
            path {
                fill_rule: "evenodd",
                d: "M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z",
                clip_rule: "evenodd"
            }
        }
    }
}

#[component]
pub fn ChevronUpDownIcon(class: Option<String>) -> Element {
    rsx! {
        svg {
            class: class.unwrap_or_default(),
            xmlns: "http://www.w3.org/2000/svg",
            view_box: "0 0 20 20",
            fill: "currentColor",
            path {
                fill_rule: "evenodd",
                d: "M5 10a1 1 0 011-1h8a1 1 0 110 2H6a1 1 0 01-1-1z",
                clip_rule: "evenodd"
            }
        }
    }
}
