use dioxus::prelude::*;
use rb_types::auth::AuthUserInfo;

use crate::app::api::auth::get_current_user;

/// Authentication state
#[derive(Clone, PartialEq, Debug)]
pub struct AuthState {
    pub user: Option<AuthUserInfo>,
    pub loading: bool,
}

impl Default for AuthState {
    fn default() -> Self {
        Self { user: None, loading: true }
    }
}

/// Initialize auth provider and fetch current user
pub fn use_auth_provider() -> Signal<AuthState> {
    let mut auth = use_signal(AuthState::default);

    // Fetch current user on mount
    use_effect(move || {
        spawn(async move {
            match get_current_user().await {
                Ok(user) => {
                    auth.set(AuthState { user, loading: false });
                }
                Err(_) => {
                    auth.set(AuthState {
                        user: None,
                        loading: false,
                    });
                }
            }
        });
    });

    auth
}
