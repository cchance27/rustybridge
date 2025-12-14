use crate::{
    app::api::users::create_user,
    components::{Modal, use_toast},
    error::ApiError,
};
use dioxus::prelude::*;
use rb_types::users::{CreateUserRequest, UserGroupInfo};
use std::collections::HashMap;

/// Self-contained Add User Modal
#[component]
pub fn AddUserModal(open: Signal<bool>, users: Resource<Result<Vec<UserGroupInfo<'static>>, ApiError>>) -> Element {
    let mut username = use_signal(String::new);
    let mut password = use_signal(String::new);
    let mut validation_errors = use_signal(HashMap::<String, String>::new);
    let toast = use_toast();

    let on_save = move |_| {
        validation_errors.set(HashMap::new());

        let username_val = username();
        let password_val = password();
        let mut errors = HashMap::new();

        if username_val.trim().is_empty() {
            errors.insert("username".to_string(), "Username is required".to_string());
        }

        if password_val.trim().is_empty() {
            errors.insert("password".to_string(), "Password is required".to_string());
        } else if password_val.len() < 8 {
            errors.insert("password".to_string(), "Password must be at least 8 characters".to_string());
        }

        if !errors.is_empty() {
            validation_errors.set(errors);
            return;
        }

        spawn(async move {
            match create_user(CreateUserRequest {
                username: username_val.clone(),
                password: password_val.clone(),
            })
            .await
            {
                Ok(_) => {
                    open.set(false);
                    username.set(String::new());
                    password.set(String::new());
                    toast.success(&format!("User '{}' created successfully", username_val));
                    users.restart();
                }
                Err(e) => {
                    toast.error(&format!("Failed to create user: {}", e));
                }
            }
        });
    };

    rsx! {
        Modal {
            open: open(),
            on_close: move |_| {
                open.set(false);
                username.set(String::new());
                password.set(String::new());
                validation_errors.set(HashMap::new());
            },
            title: "Add User",
            actions: rsx! {
                button { class: "btn btn-primary", onclick: on_save, "Create" }
            },
            div { class: "flex flex-col gap-4",
                label { class: "form-control w-full",
                    div { class: "label", span { class: "label-text", "Username" } }
                    input {
                        r#type: "text",
                        class: if validation_errors().contains_key("username") {
                            "input input-bordered w-full input-error"
                        } else {
                            "input input-bordered w-full"
                        },
                        placeholder: "jdoe",
                        value: "{username}",
                        oninput: move |e| {
                            username.set(e.value());
                            if validation_errors().contains_key("username") {
                                let mut errs = validation_errors();
                                errs.remove("username");
                                validation_errors.set(errs);
                            }
                        }
                    }
                    if let Some(err) = validation_errors().get("username") {
                        div { class: "text-error text-sm mt-1", "{err}" }
                    }
                }
                label { class: "form-control w-full",
                    div { class: "label", span { class: "label-text", "Password" } }
                    input {
                        r#type: "password",
                        class: if validation_errors().contains_key("password") {
                            "input input-bordered w-full input-error"
                        } else {
                            "input input-bordered w-full"
                        },
                        placeholder: "••••••••",
                        value: "{password}",
                        oninput: move |e| {
                            password.set(e.value());
                            if validation_errors().contains_key("password") {
                                let mut errs = validation_errors();
                                errs.remove("password");
                                validation_errors.set(errs);
                            }
                        }
                    }
                    if let Some(err) = validation_errors().get("password") {
                        div { class: "text-error text-sm mt-1", "{err}" }
                    }
                }
                p { class: "text-xs text-gray-500",
                    "Password must be at least 8 characters."
                }
            }
        }
    }
}
