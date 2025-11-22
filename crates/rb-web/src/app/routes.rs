use dioxus::prelude::*;

use crate::{
    components::Layout, pages::{AccessPage, CredentialsPage, DashboardPage, LoginPage, RelaysPage}
};

#[component]
pub fn AppRouter() -> Element {
    rsx! {
        Router::<Routes> {}
    }
}

#[derive(Clone, Routable, PartialEq)]
pub enum Routes {
    #[route("/")]
    DashboardPage {},
    #[route("/relays")]
    RelaysPage {},
    #[route("/credentials")]
    CredentialsPage {},
    #[route("/access")]
    AccessPage {},
    #[route("/login")]
    LoginPage {},
    #[route("/:..route")]
    NotFound { route: Vec<String> },
}

#[component]
pub fn NotFound(route: Vec<String>) -> Element {
    let path = route.join("/");
    rsx!(Layout { p { "Not found: /{path}" } })
}
