use std::collections::HashMap;

use dioxus::prelude::*;
use rb_types::users::RoleInfo;

use crate::{
    app::api::roles::create_role, components::{Modal, use_toast}
};

/// Self-contained Add Role Modal
#[component]
pub fn AddRoleModal(open: Signal<bool>, roles: Resource<Result<Vec<RoleInfo>, ServerFnError>>) -> Element {
    let mut role_name = use_signal(String::new);
    let mut role_description = use_signal(String::new);
    let mut validation_errors = use_signal(HashMap::<String, String>::new);
    let toast = use_toast();

    let on_save = move |_| {
        validation_errors.set(HashMap::new());

        let name_val = role_name();
        let desc_val = role_description();
        let mut errors = HashMap::new();

        if name_val.trim().is_empty() {
            errors.insert("name".to_string(), "Role name is required".to_string());
        }

        if !errors.is_empty() {
            validation_errors.set(errors);
            return;
        }

        spawn(async move {
            let description_opt = if desc_val.trim().is_empty() { None } else { Some(desc_val) };

            match create_role(name_val.clone(), description_opt).await {
                Ok(_) => {
                    open.set(false);
                    role_name.set(String::new());
                    role_description.set(String::new());
                    toast.success(&format!("Role '{}' created successfully", name_val));
                    roles.restart();
                }
                Err(e) => {
                    toast.error(&format!("Failed to create role: {}", e));
                }
            }
        });
    };

    rsx! {
        Modal {
            open: open(),
            on_close: move |_| {
                open.set(false);
                role_name.set(String::new());
                role_description.set(String::new());
                validation_errors.set(HashMap::new());
            },
            title: "Add Role",
            actions: rsx! {
                button { class: "btn btn-primary", onclick: on_save, "Create" }
            },
            div { class: "flex flex-col gap-4",
                label { class: "form-control w-full",
                    div { class: "label", span { class: "label-text", "Role Name" } }
                    input {
                        r#type: "text",
                        class: if validation_errors().contains_key("name") {
                            "input input-bordered w-full input-error"
                        } else {
                            "input input-bordered w-full"
                        },
                        placeholder: "developer",
                        value: "{role_name}",
                        oninput: move |e| {
                            role_name.set(e.value());
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
                label { class: "form-control w-full",
                    div { class: "label", span { class: "label-text", "Description (optional)" } }
                    textarea {
                        class: "textarea textarea-bordered w-full",
                        placeholder: "Enter role description...",
                        value: "{role_description}",
                        rows: "3",
                        oninput: move |e| role_description.set(e.value())
                    }
                }
            }
        }
    }
}
