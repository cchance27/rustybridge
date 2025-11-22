use dioxus::prelude::*;

// --------- Session plumbing (minimal placeholder) ---------

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SessionState {
    Unauthenticated,
    Authenticated { user: String },
}

#[component]
pub fn SessionProvider(children: Element, session: Signal<SessionState>) -> Element {
    use_context_provider(|| session);
    children
}

pub fn use_session() -> Signal<SessionState> {
    use_context::<Signal<SessionState>>()
}
