use dioxus::prelude::*;

#[component]
pub fn AvatarDropDown() -> Element {
    rsx! {
        div { class: "dropdown dropdown-end pl-2",
            div {
                tabindex: "0",
                role: "button",
                class: "btn btn-ghost btn-circle avatar",
                div { class: "w-10 rounded-full",
                    img {
                        alt: "RustyBridge User",
                        src: "https://img.daisyui.com/images/stock/photo-1534528741775-53994a69daeb.webp"
                    }
                }
            }
            ul {
                tabindex: "-1",
                class: "menu menu-sm dropdown-content bg-base-100 rounded-box z-1 mt-3 w-52 p-2 shadow",
                li {
                    a { "Profile" }
                }
                li {
                    a { "Settings" }
                }
                li {
                    a { "Logout" }
                }
            }
        }
    }
}
