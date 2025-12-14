use crate::components::Layout;
use dioxus::prelude::*;

#[component]
pub fn NotFoundPage(route: Vec<String>) -> Element {
    let path = route.join("/");
    rsx!(Layout { p { "Not found: /{path}" } })
}
