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
                div { class: "flex flex-col gap-6",
                    // Users Section
                    users::UsersSection {
                        users,
                        toast,
                    },
                    // Groups Section
                    groups::GroupsSection {
                        groups,
                        users,
                        toast,
                    },
                    // Roles Section
                    roles::RolesSection {
                        roles,
                        users,
                        groups,
                        toast,
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
