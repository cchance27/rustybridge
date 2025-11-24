use std::collections::HashMap;

use dioxus::prelude::*;
use rb_types::validation::ValidationError;

#[component]
pub fn CredentialForm(
    cred_type: String,
    on_type_change: EventHandler<String>,
    username: String,
    on_username_change: EventHandler<String>,
    username_mode: String,
    on_username_mode_change: EventHandler<String>,
    password_required: bool,
    on_password_required_change: EventHandler<bool>,
    password: String,
    on_password_change: EventHandler<String>,
    private_key: String,
    on_private_key_change: EventHandler<String>,
    public_key: String,
    on_public_key_change: EventHandler<String>,
    passphrase: String,
    on_passphrase_change: EventHandler<String>,
    validation_errors: HashMap<String, ValidationError>,
    show_hint: bool,
    is_editing: bool,
    has_existing_password: bool,
    has_existing_private_key: bool,
    has_existing_public_key: bool,
    show_type_selector: bool,
    #[props(default = true)] original_password_required: bool,
) -> Element {
    rsx! {
        div { class: "flex flex-col gap-4",
            if show_type_selector {
                div { class: "form-control w-full",
                    div { class: "label", span { class: "label-text", "Type" } }
                    select {
                        class: "select select-bordered w-full",
                        value: "{cred_type}",
                        onchange: move |e| on_type_change.call(e.value()),
                        option { value: "password", "Password" }
                        option { value: "ssh_key", "SSH Key" }
                        option { value: "agent", "Agent" }
                    }
                }
            }

            div { class: "form-control w-full",
                div { class: "label", span { class: "label-text", "Username Mode" } }
                select {
                    class: "select select-bordered w-full",
                    value: "{username_mode}",
                    onchange: move |e| on_username_mode_change.call(e.value()),
                    option { value: "fixed", "Fixed (Use value below)" }
                    option { value: "blank", "Interactive (Prompt user)" }
                    option { value: "passthrough", "Passthrough (Use relay user)" }
                }
            }

            if username_mode == "fixed" {
                label { class: "form-control w-full",
                    div { class: "label", span { class: "label-text", "Username" } }
                    input {
                        r#type: "text",
                        class: if validation_errors.contains_key("username") { "input input-bordered w-full input-error" } else { "input input-bordered w-full" },
                        placeholder: "username",
                        value: "{username}",
                        oninput: move |e| on_username_change.call(e.value())
                    }
                    if let Some(err) = validation_errors.get("username") {
                        div { class: "text-error text-sm mt-1", "{err}" }
                    }
                }
            }

            // Type-specific fields
            if cred_type == "password" {
                label { class: "form-control w-full",
                    div { class: "label items-center justify-between",
                        span { class: "label-text", "Password" }
                        // Only show "Required (stored)" checkbox if username_mode is "fixed"
                        if username_mode == "fixed" {
                            div { class: "flex items-center gap-2",
                                input {
                                    r#type: "checkbox",
                                    class: "checkbox checkbox-sm",
                                    checked: "{password_required}",
                                    onchange: move |e| on_password_required_change.call(e.value() == "true")
                                }
                                span { class: "label-text-alt", "Required (stored)" }
                            }
                        }
                        if has_existing_password && is_editing {
                            if original_password_required {
                                span { class: "badge badge-warning badge-xs", "Stored • not shown" }
                            } else {
                                span { class: "badge badge-info badge-xs", "Optional (not required previously)" }
                            }
                        }
                    }
                    // Show password input only if password_required is true AND username_mode is "fixed"
                    if password_required && username_mode == "fixed" {
                        input {
                            r#type: "password",
                            class: if validation_errors.contains_key("password") { "input input-bordered w-full input-error" } else { "input input-bordered w-full" },
                            placeholder: "••••••••",
                            value: "{password}",
                            oninput: move |e| on_password_change.call(e.value())
                        }
                    } else {
                        div { class: "alert alert-info text-xs py-2",
                            span {
                                if username_mode == "blank" || username_mode == "passthrough" {
                                    "Password will be prompted interactively during connection (username mode: {username_mode})."
                                } else {
                                    "Password will be prompted interactively during connection."
                                }
                            }
                        }
                    }
                    if let Some(err) = validation_errors.get("password") {
                        div { class: "text-error text-sm mt-1", "{err}" }
                    }
                }
            } else if cred_type == "ssh_key" {
                label { class: "form-control w-full",
                    div { class: "label items-center justify-between",
                        span { class: "label-text", "Private Key (PEM)" }
                        if has_existing_private_key && is_editing {
                            span { class: "badge badge-warning badge-xs", "Stored • not shown" }
                        }
                    }
                    textarea {
                        class: if validation_errors.contains_key("private_key") { "textarea textarea-bordered w-full h-32 textarea-error" } else { "textarea textarea-bordered w-full h-32" },
                        placeholder: "-----BEGIN OPENSSH PRIVATE KEY-----\\n...",
                        value: "{private_key}",
                        oninput: move |e| on_private_key_change.call(e.value())
                    }
                    if let Some(err) = validation_errors.get("private_key") {
                        div { class: "text-error text-sm mt-1", "{err}" }
                    }
                }

                label { class: "form-control w-full",
                    div { class: "label", span { class: "label-text", "Passphrase (optional, only if private key is encrypted)" } }
                    input {
                        r#type: "password",
                        class: "input input-bordered w-full",
                        placeholder: "passphrase",
                        value: "{passphrase}",
                        oninput: move |e| on_passphrase_change.call(e.value())
                    }
                }
            } else if cred_type == "agent" {
                label { class: "form-control w-full",
                    div { class: "label items-center justify-between",
                        span { class: "label-text", "Public Key (OpenSSH)" }
                        if has_existing_public_key && is_editing {
                            span { class: "badge badge-warning badge-xs", "Stored • not shown" }
                        }
                    }
                    textarea {
                        class: if validation_errors.contains_key("public_key") { "textarea textarea-bordered w-full h-24 textarea-error" } else { "textarea textarea-bordered w-full h-24" },
                        placeholder: "ssh-ed25519 AAAA...",
                        value: "{public_key}",
                        oninput: move |e| on_public_key_change.call(e.value())
                    }
                    if let Some(err) = validation_errors.get("public_key") {
                        div { class: "text-error text-sm mt-1", "{err}" }
                    }
                }
            }

            if show_hint {
                p { class: "text-xs text-gray-500",
                    "Secrets are encrypted and not displayed. Leave blank to keep the existing value."
                }
            }
        }
    }
}
