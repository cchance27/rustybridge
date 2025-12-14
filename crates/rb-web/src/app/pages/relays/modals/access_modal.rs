use crate::{
    app::pages::relays::state::RelayState,
    components::{Modal, RelayAccessForm},
};
use dioxus::prelude::*;

/// Modal for managing relay access
#[component]
pub fn AccessManagementModal(state: RelayState) -> Element {
    rsx! {
        Modal {
            open: (state.access_modal_open)(),
            title: format!("Manage Access: {}", (state.access_target_name)()),
            on_close: move |_| state.access_modal_open.set(false),
            RelayAccessForm {
                relay_id: (state.access_target_id)(),
                on_change: move |_| {
                    // Optionally refresh relays list or users list
                    state.relays.restart();
                }
            }
        }
    }
}
