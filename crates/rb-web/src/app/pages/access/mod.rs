mod fab;
mod groups;
mod modals;
mod roles;
mod users;

use dioxus::prelude::*;
use rb_types::auth::{ClaimLevel, ClaimType};

use crate::{
    app::api::{groups::*, roles::list_roles, users::*}, components::{Layout, RequireAuth, Toast, ToastMessage}
};

#[component]
pub fn AccessPage() -> Element {
    // Load users and groups from server
    let users = use_resource(|| async move { list_users().await });
    let groups = use_resource(|| async move { list_groups().await });
    let roles = use_resource(|| async move { list_roles().await });

    // Toast notification state
    let toast = use_signal(|| None::<ToastMessage>);

    rsx! {
        RequireAuth {
            any_claims: vec![ClaimType::Users(ClaimLevel::View), ClaimType::Groups(ClaimLevel::View)],
            Toast { message: toast }
            Layout {
                div { class: "grid grid-cols-1 xl:grid-cols-2 gap-6 items-start",
                    // Left Column: Users
                    div { class: "flex flex-col gap-6 w-full",
                        users::UsersSection {
                            users,
                            toast,
                            roles, // Pass roles resource to UsersSection for effective claims calculation
                            groups, // Pass groups resource to UsersSection for effective claims calculation
                        }
                    }

                    // Right Column: Groups and Roles
                    div { class: "flex flex-col gap-6 w-full",
                        groups::GroupsSection {
                            groups,
                            users,
                            roles, // Pass roles resource to GroupsSection
                            toast,
                        },
                        roles::RolesSection {
                            roles,
                            users,
                            groups,
                            toast,
                        }
                    }
                }

                // Multi-action FAB
                fab::AccessFab {
                    users,
                    groups,
                    roles,
                    toast,
                }
            }
        }
    }
}
