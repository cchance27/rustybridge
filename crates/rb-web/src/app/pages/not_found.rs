use dioxus::prelude::*;

use crate::components::Layout;

#[component]
pub fn NotFoundPage(route: Vec<String>) -> Element {
    let path = route.join("/");
    rsx!(Layout { p { "Not found: /{path}" } })
}
