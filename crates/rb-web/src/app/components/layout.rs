use dioxus::prelude::*;

use crate::components::{Footer, NavBar};

#[component]
pub fn Layout(children: Element) -> Element {
    rsx! {
        div {
            class: "rb-layout min-h-screen flex flex-col",
            header {
                NavBar {}
            }
            main {
                class: "rb-main flex-grow p-4", {
                    children
                }
            }
            Footer {}
        }
    }
}
