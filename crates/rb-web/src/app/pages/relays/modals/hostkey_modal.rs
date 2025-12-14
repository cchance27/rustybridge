use crate::{
    app::{api::relays::store_relay_hostkey, pages::relays::state::RelayState},
    components::{Modal, use_toast},
};
use dioxus::prelude::*;

/// Modal for reviewing and storing relay hostkeys
#[component]
pub fn HostkeyReviewModal(state: RelayState) -> Element {
    let toast = use_toast();
    let on_refresh = move |_| {
        if let Some(review) = (state.refresh_review)() {
            let target_id = (state.refresh_target_id)();
            let target_name = (state.refresh_target_name)();
            let key_pem = review.new_key_pem.clone();
            spawn(async move {
                match store_relay_hostkey(target_id, key_pem).await {
                    Ok(_) => {
                        state.refresh_modal_open.set(false);
                        state.refresh_review.set(None);
                        toast.success(&format!("Hostkey for '{}' stored successfully", target_name));
                        state.relays.restart();
                    }
                    Err(e) => {
                        state.refresh_modal_open.set(false);
                        state.refresh_review.set(None);
                        toast.error(&format!("Failed to store hostkey: {}", e));
                    }
                }
            });
        }
    };

    rsx! {
        Modal {
            open: (state.refresh_modal_open)(),
            on_close: move |_| {
                state.refresh_modal_open.set(false);
                state.refresh_review.set(None);
            },
            title: "Refresh Hostkey",
            actions: rsx! {
                button { class: "btn btn-secondary", onclick: on_refresh, "Accept & Store" }
            },
            div { class: "flex flex-col gap-4",
                if let Some(review) = (state.refresh_review)() {
                    p { "Fetched hostkey for "{state.refresh_target_name}":" }

                    if let Some(old_fp) = review.old_fingerprint {
                        div { class: "alert alert-info",
                            div {
                                p { class: "font-semibold", "Current Hostkey:" }
                                p { class: "text-sm font-mono", "{old_fp}" }
                                if let Some(old_type) = review.old_key_type {
                                    p { class: "text-xs text-gray-500", "Type: {old_type}" }
                                }
                            }
                        }
                    } else {
                        div { class: "alert alert-warning",
                            p { "No hostkey currently stored for this relay" }
                        }
                    }

                    div { class: "alert alert-success",
                        div {
                            p { class: "font-semibold", "New Hostkey:" }
                            p { class: "text-sm font-mono", "{review.new_fingerprint}" }
                            p { class: "text-xs text-gray-500", "Type: {review.new_key_type}" }
                        }
                    }

                    p { class: "text-sm text-gray-500",
                        "Click 'Accept & Store' to save this hostkey, or 'Cancel' to discard."
                    }
                } else {
                    div { class: "flex justify-center p-4",
                        span { class: "loading loading-spinner" }
                        span { class: "ml-2", "Fetching hostkey..." }
                    }
                }
            }
        }
    }
}
