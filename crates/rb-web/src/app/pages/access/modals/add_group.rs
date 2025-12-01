use std::collections::HashMap;

use dioxus::prelude::*;
use rb_types::users::GroupInfo;

use crate::{
    app::api::groups::create_group, components::{Modal, use_toast}
};

/// Self-contained Add Group Modal
#[component]
pub fn AddGroupModal(open: Signal<bool>, groups: Resource<Result<Vec<GroupInfo>, ServerFnError>>) -> Element {
    let mut group_name = use_signal(String::new);
    let mut validation_errors = use_signal(HashMap::<String, String>::new);
    let toast = use_toast();

    let on_save = move |_| {
        validation_errors.set(HashMap::new());

        let name_val = group_name();
        let mut errors = HashMap::new();

        if name_val.trim().is_empty() {
            errors.insert("name".to_string(), "Group name is required".to_string());
        }

        if !errors.is_empty() {
            validation_errors.set(errors);
            return;
        }

        spawn(async move {
            match create_group(name_val.clone()).await {
                Ok(_) => {
                    open.set(false);
                    group_name.set(String::new());
                    toast.success(&format!("Group '{}' created successfully", name_val));
                    groups.restart();
                }
                Err(e) => {
                    toast.error(&format!("Failed to create group: {}", e));
                }
            }
        });
    };

    rsx! {
        Modal {
            open: open(),
            on_close: move |_| {
                open.set(false);
                group_name.set(String::new());
                validation_errors.set(HashMap::new());
            },
            title: "Add Group",
            actions: rsx! {
                button { class: "btn btn-primary", onclick: on_save, "Create" }
            },
            div { class: "flex flex-col gap-4",
                label { class: "form-control w-full",
                    div { class: "label", span { class: "label-text", "Group Name" } }
                    input {
                        r#type: "text",
                        class: if validation_errors().contains_key("name") {
                            "input input-bordered w-full input-error"
                        } else {
                            "input input-bordered w-full"
                        },
                        placeholder: "developers",
                        value: "{group_name}",
                        oninput: move |e| {
                            group_name.set(e.value());
                            if validation_errors().contains_key("name") {
                                let mut errs = validation_errors();
                                errs.remove("name");
                                validation_errors.set(errs);
                            }
                        }
                    }
                    if let Some(err) = validation_errors().get("name") {
                        div { class: "text-error text-sm mt-1", "{err}" }
                    }
                }
            }
        }
    }
}
