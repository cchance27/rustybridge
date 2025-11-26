//! Popup manager module for ManagementApp
//! Handles all popup-related methods and logic

use super::types::{HostForm, PopupState};
use crate::widgets::Menu;

impl super::ManagementApp {
    pub fn open_add_popup(&mut self) {
        self.popup = PopupState::AddHost(HostForm::new(), 0);
    }

    pub fn open_edit_popup(&mut self) {
        if let Some(selected) = self.table_state.selected()
            && let Some(host) = self.relay_hosts.get(selected)
        {
            self.popup = PopupState::EditHost(HostForm::from_relay(host), 0, host.id);
        }
    }

    pub fn open_delete_popup(&mut self) {
        if let Some(selected) = self.table_state.selected()
            && let Some(host) = self.relay_hosts.get(selected)
        {
            self.popup = PopupState::DeleteConfirm(host.id, host.name.clone());
        }
    }

    pub fn close_popup(&mut self) {
        self.popup = PopupState::None;
    }

    pub fn open_add_credential_popup(&mut self) {
        self.popup = PopupState::AddCredential(Box::default(), 0);
    }

    pub fn open_delete_credential_popup(&mut self) {
        if let Some(i) = self.creds_state.selected()
            && let Some(c) = self.credentials.get(i)
        {
            self.popup = PopupState::DeleteCredentialConfirm(c.name.clone());
        }
    }

    pub fn open_clear_credential_popup(&mut self) {
        if let Some(selected) = self.table_state.selected()
            && let Some(host) = self.relay_hosts.get(selected)
            && let Some(label) = self.relay_host_creds.get(&host.id)
            && label != "<custom>"
            && label != "<none>"
        {
            self.popup = PopupState::ClearCredentialConfirm(host.id, host.name.clone(), label.clone());
        }
    }

    pub fn open_set_credential_popup(&mut self) {
        if let Some(selected) = self.table_state.selected()
            && let Some(host) = self.relay_hosts.get(selected)
        {
            let label = self.relay_host_creds.get(&host.id).cloned().unwrap_or_else(|| "<none>".to_string());
            if label == "<none>" {
                let menu = Menu::new(format!("Set Credential for {}", host.name), self.credentials.clone());
                self.popup = PopupState::SetCredential(host.id, host.name.clone(), menu);
            }
        }
    }
}
