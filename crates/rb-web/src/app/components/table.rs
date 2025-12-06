use dioxus::prelude::*;

use crate::app::components::icons::{ChevronDownIcon, ChevronUpDownIcon, ChevronUpIcon};

#[derive(Clone, PartialEq, Debug)]
pub struct TableColumn {
    pub title: String,
    pub width: Option<&'static str>,
    pub sort_key: Option<String>,
    pub filter_key: Option<String>,
    pub alignment: ColumnAlignment,
}

#[derive(Clone, PartialEq, Debug, Default)]
pub enum ColumnAlignment {
    Left,
    #[default]
    Center,
    Right,
}

impl TableColumn {
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            width: None,
            sort_key: None,
            filter_key: None,
            alignment: ColumnAlignment::Center,
        }
    }

    pub fn with_width(mut self, width: &'static str) -> Self {
        self.width = Some(width);
        self
    }

    pub fn with_sort(mut self, key: impl Into<String>) -> Self {
        self.sort_key = Some(key.into());
        self
    }

    pub fn with_filter(mut self, key: impl Into<String>) -> Self {
        self.filter_key = Some(key.into());
        self
    }

    pub fn align_left(mut self) -> Self {
        self.alignment = ColumnAlignment::Left;
        self
    }

    pub fn align_right(mut self) -> Self {
        self.alignment = ColumnAlignment::Right;
        self
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct PaginationConfig {
    pub current_page: i64,
    pub total_pages: i64,
    pub limit: i64,
}

#[derive(Clone, PartialEq, Debug)]
pub enum SortDirection {
    Asc,
    Desc,
}

#[component]
pub fn Table(
    #[props(default = "table table-zebra table-pin-rows")] class: &'static str,

    // Legacy support (to be deprecated/removed or mapped)
    #[props(default = vec![])] headers: Vec<&'static str>,
    #[props(default = vec![])] header_widths: Vec<&'static Option<&'static str>>,

    // New props
    #[props(default = vec![])] columns: Vec<TableColumn>,
    #[props(default = None)] sort_by: Option<String>,
    #[props(default = SortDirection::Desc)] sort_direction: SortDirection,
    #[props(default = None)] pagination: Option<PaginationConfig>,

    // Event handlers
    on_sort: Option<EventHandler<String>>,
    on_filter: Option<EventHandler<(String, String)>>,
    on_page_change: Option<EventHandler<i64>>,

    children: Element,
) -> Element {
    // Adapter for legacy headers
    let final_columns = if !columns.is_empty() {
        columns
    } else {
        headers
            .iter()
            .enumerate()
            .map(|(i, h)| {
                let width = if i < header_widths.len() {
                    header_widths[i].unwrap_or("")
                } else {
                    ""
                };
                let mut col = TableColumn::new(*h).with_width(width);
                if i == 0 {
                    col = col.align_left();
                } else if i == headers.len() - 1 {
                    col = col.align_right();
                }
                col
            })
            .collect()
    };

    let handle_sort = move |key: String| {
        if let Some(handler) = on_sort {
            handler.call(key);
        }
    };

    rsx! {
        div { class: "flex flex-col gap-2",
            div { class: "overflow-x-auto",
                table { class: class,
                    thead {
                        tr {
                            for col in final_columns {
                                th {
                                    class: format!("{} {}",
                                        match col.alignment {
                                            ColumnAlignment::Left => "text-left",
                                            ColumnAlignment::Center => "text-center",
                                            ColumnAlignment::Right => "text-right",
                                        },
                                        col.width.unwrap_or("")
                                    ),
                                    onclick: move |_| {
                                        if let Some(key) = &col.sort_key {
                                            handle_sort(key.clone());
                                        }
                                    },
                                    div {
                                        class: format!("flex items-center gap-1 cursor-pointer select-none group {}",
                                            match col.alignment {
                                                ColumnAlignment::Left => "justify-start",
                                                ColumnAlignment::Center => "justify-center",
                                                ColumnAlignment::Right => "justify-end",
                                            }
                                        ),
                                        span { "{col.title}" }
                                        if let Some(key) = &col.sort_key {
                                            if Some(key) == sort_by.as_ref() {
                                                if sort_direction == SortDirection::Asc {
                                                    ChevronUpIcon { class: "w-4 h-4" }
                                                } else {
                                                    ChevronDownIcon { class: "w-4 h-4" }
                                                }
                                            } else {
                                                // Show faint placeholder on hover to indicate sortability
                                                ChevronUpDownIcon { class: "w-4 h-4 opacity-40 group-hover:opacity-100 transition-opacity" }
                                            }
                                        }
                                    }
                                    {
                                        col.filter_key.as_ref().map(|filter_key| {
                                            let key_clone = filter_key.clone();
                                            rsx! {
                                                div { class: "mt-1",
                                                    onclick: move |evt| evt.stop_propagation(),
                                                    input {
                                                        class: "input input-bordered input-xs w-full max-w-[150px] font-normal text-xs",
                                                        placeholder: "Filter...",
                                                        oninput: move |evt| {
                                                            if let Some(handler) = on_filter {
                                                                handler.call((key_clone.clone(), evt.value()));
                                                            }
                                                        },
                                                        onclick: move |evt| evt.stop_propagation(),
                                                    }
                                                }
                                            }
                                        })
                                    }
                                }
                            }
                        }
                    }
                    tbody {
                        {children}
                    }
                }
            }

            if let Some(config) = pagination {
                div { class: "flex justify-center mt-2",
                    div { class: "join",
                        button {
                            class: "join-item btn btn-sm btn-outline",
                            disabled: config.current_page <= 1,
                            onclick: move |_| if let Some(h) = on_page_change { h.call(config.current_page - 1) },
                            "«"
                        }
                        button { class: "join-item btn btn-sm no-animation pointer-events-none btn-disabled",
                            "Page {config.current_page} of {config.total_pages}"
                        }
                        button {
                            class: "join-item btn btn-sm btn-outline",
                            disabled: config.current_page >= config.total_pages,
                            onclick: move |_| if let Some(h) = on_page_change { h.call(config.current_page + 1) },
                            "»"
                        }
                    }
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
