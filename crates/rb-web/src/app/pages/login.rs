use dioxus::prelude::*;

use crate::{
    app::session::{SessionState, use_session}, components::Layout, routes::Routes
};

#[component]
pub fn LoginPage() -> Element {
    let mut session = use_session();
    let mut user = use_signal(String::new);

    let navigator = use_navigator();

    let on_submit = move |_| {
        let name = user().trim().to_string();
        if !name.is_empty() {
            session.set(SessionState::Authenticated { user: name });
            navigator.push(Routes::DashboardPage {});
        }
    };

    rsx! {
        Layout {
            section { class: "card",
                h2 { "Login" }
                p { "Placeholder login; wires to /api/login soon." }
                input {
                    r#type: "text",
                    placeholder: "username",
                    value: "{user}",
                    oninput: move |evt| user.set(evt.value())
                }
                button { onclick: on_submit, "Continue" }
            }
        }
    }
}
