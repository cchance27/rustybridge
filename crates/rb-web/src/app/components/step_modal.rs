use dioxus::prelude::*;

#[component]
pub fn StepModal(
    open: bool,
    on_close: EventHandler<()>,
    title: String,
    steps: Vec<String>,
    current_step: usize,
    on_next: EventHandler<()>,
    on_back: EventHandler<()>,
    on_save: EventHandler<()>,
    can_proceed: bool,
    children: Element,
) -> Element {
    if !open {
        return rsx! {};
    }

    let total_steps = steps.len();
    let is_first_step = current_step == 1;
    let is_last_step = current_step == total_steps;

    rsx! {
        div {
            class: "modal modal-open modal-bottom sm:modal-middle",
            div {
                class: "modal-box max-w-2xl",
                // Header
                div { class: "flex justify-between items-center mb-4",
                    h3 { class: "font-bold text-lg", "{title}" }
                    button {
                        class: "btn btn-sm btn-circle btn-ghost",
                        onclick: move |_| on_close.call(()),
                        "✕"
                    }
                }

                // Steps indicator
                ul { class: "steps w-full mb-6",
                    {steps.iter().enumerate().map(|(idx, step_name)| {
                        let step_num = idx + 1;
                        let step_class = if step_num <= current_step {
                            "step step-primary"
                        } else {
                            "step"
                        };
                        rsx! {
                            li { key: "{idx}", class: "{step_class}", "{step_name}" }
                        }
                    })}
                }

                // Content
                div { class: "min-h-[300px]",
                    {children}
                }

                // Actions
                div { class: "modal-action justify-between",
                    div { class: "flex gap-2",
                        if !is_first_step {
                            button {
                                class: "btn",
                                onclick: move |_| on_back.call(()),
                                "Back"
                            }
                        }
                    }
                    div { class: "flex gap-2",
                        button {
                            class: "btn",
                            onclick: move |_| on_close.call(()),
                            "Cancel"
                        }
                        if is_last_step {
                            button {
                                class: "btn btn-primary",
                                disabled: !can_proceed,
                                onclick: move |_| on_save.call(()),
                                "Save"
                            }
                        } else {
                            button {
                                class: "btn btn-primary",
                                disabled: !can_proceed,
                                onclick: move |_| on_next.call(()),
                                "Next"
                            }
                        }
                    }
                }
            }
        }
    }
}
