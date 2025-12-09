//! FAB (Floating Action Button) and Add modals for Access page
//! Each component is self-contained with its own state, validation, and handlers.

use dioxus::prelude::*;
use rb_types::{
    auth::{ClaimLevel, ClaimType}, users::{GroupInfo, RoleInfo, UserGroupInfo}
};

use crate::{
    app::components::{MultiFab, Protected}, pages::access::modals::{AddGroupModal, AddRoleModal, AddUserModal}
};

/// Main FAB component - just controls which modals are open
#[component]
pub fn AccessFab(
    users: Resource<Result<Vec<UserGroupInfo<'static>>, ServerFnError>>,
    groups: Resource<Result<Vec<GroupInfo<'static>>, ServerFnError>>,
    roles: Resource<Result<Vec<RoleInfo<'static>>, ServerFnError>>,
) -> Element {
    let mut user_modal_open = use_signal(|| false);
    let mut group_modal_open = use_signal(|| false);
    let mut role_modal_open = use_signal(|| false);

    rsx! {
        Protected {
            any_claims: vec![
                ClaimType::Users(ClaimLevel::Create),
                ClaimType::Groups(ClaimLevel::Create),
                ClaimType::Roles(ClaimLevel::Create)
            ],
            MultiFab {
                on_add_user: move |_| user_modal_open.set(true),
                on_add_group: move |_| group_modal_open.set(true),
                on_add_role: move |_| role_modal_open.set(true),
            }
        }

        AddUserModal { open: user_modal_open, users }
        AddGroupModal { open: group_modal_open, groups }
        AddRoleModal { open: role_modal_open, roles }
    }
}
