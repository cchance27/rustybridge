mod fab;
mod groups;
mod modals;
mod roles;
mod users;

use crate::{
    app::api::{groups::*, roles::list_roles, users::*},
    components::{Layout, RequireAuth},
};
use dioxus::prelude::*;
use rb_types::auth::{ClaimLevel, ClaimType};

#[component]
pub fn AccessPage() -> Element {
    // Load users and groups from server
    let users = use_resource(|| async move { list_users().await });
    let groups = use_resource(|| async move { list_groups().await });
    let roles = use_resource(|| async move { list_roles().await });

    rsx! {
        RequireAuth {
            any_claims: vec![ClaimType::Users(ClaimLevel::View), ClaimType::Groups(ClaimLevel::View)],
            Layout {
                div { class: "grid grid-cols-1 gap-6 items-start",
                    users::UsersSection {
                        users,
                        roles, // Pass roles resource to UsersSection for effective claims calculation
                        groups, // Pass groups resource to UsersSection for effective claims calculation
                    }
                    groups::GroupsSection {
                        groups,
                        users,
                        roles, // Pass roles resource to GroupsSection
                    },
                    roles::RolesSection {
                        roles,
                        users,
                        groups,
                    }
                }

                // Multi-action FAB
                fab::AccessFab {
                    users,
                    groups,
                    roles,
                }
            }
        }
    }
}
