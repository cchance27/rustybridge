use dioxus::prelude::*;

#[component]
pub fn Table(
    #[props(default = "table table-zebra table-pin-rows")] class: &'static str,
    #[props(default = vec![])] header_widths: Vec<&'static Option<&'static str>>,
    headers: Vec<&'static str>,
    children: Element,
) -> Element {
    let headers = if headers.len() == header_widths.len() {
        headers
            .iter()
            .zip(header_widths.iter())
            .map(|(h, w)| (h, w.unwrap_or("")))
            .collect::<Vec<_>>()
    } else {
        headers.iter().map(|h| (h, "")).collect::<Vec<_>>()
    };

    rsx! {
        div { class: "overflow-x-auto",
            table { class: class,
                thead {
                    tr {
                        for (i, (h, width)) in headers.iter().enumerate() {
                            th {
                                class: if i == 0 {
                                    format!("text-left {width}")
                                } else if i == headers.len() - 1 {
                                    format!("text-right {width}")
                                } else {
                                    format!("text-center {width}")
                                },
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
                    class: "btn btn-xs btn-primary join-item",
                    onclick: move |_| on_edit.call(()),
                    "Edit"
                }
            }
            if let Some(on_delete) = on_delete {
                button {
                    class: "btn btn-xs btn-secondary join-item",
                    onclick: move |_| on_delete.call(()),
                    "Delete"
                }
            }
        }
    }
}
