use dioxus::prelude::*;

#[component]
pub fn Table(headers: Vec<&'static str>, children: Element) -> Element {
    rsx! {
        div { class: "overflow-x-auto",
            table { class: "table table-zebra table-pin-rows",
                thead {
                    tr {
                        for (i, h) in headers.iter().enumerate() {
                            th {
                                class: if i == headers.len() - 1 { "text-right" } else { "" },
                                "{h}"
                            }
                        }
                    }
                }
                tbody {
                    {children}
                }
            }
        }
    }
}

#[component]
pub fn TableActions(on_edit: Option<EventHandler<()>>, on_delete: Option<EventHandler<()>>) -> Element {
    rsx! {
        div { class: "join",
            if let Some(on_edit) = on_edit {
                button {
                    class: "btn btn-xs btn-info join-item",
                    onclick: move |_| on_edit.call(()),
                    "Edit"
                }
            }
            if let Some(on_delete) = on_delete {
                button {
                    class: "btn btn-xs btn-error join-item",
                    onclick: move |_| on_delete.call(()),
                    "Delete"
                }
            }
        }
    }
}
