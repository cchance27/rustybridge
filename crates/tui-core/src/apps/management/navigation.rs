//! Navigation module for ManagementApp
//! Handles all navigation-related methods and logic

impl super::ManagementApp {
    pub fn next_tab(&mut self) {
        self.selected_tab = (self.selected_tab + 1) % self.tabs.len();
    }

    pub fn previous_tab(&mut self) {
        if self.selected_tab > 0 {
            self.selected_tab -= 1;
        } else {
            self.selected_tab = self.tabs.len() - 1;
        }
    }

    pub fn next_row(&mut self) {
        if self.relay_hosts.is_empty() {
            return;
        }
        let i = match self.table_state.selected() {
            Some(i) => {
                if i >= self.relay_hosts.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    pub fn previous_row(&mut self) {
        if self.relay_hosts.is_empty() {
            return;
        }
        let i = match self.table_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.relay_hosts.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    pub fn next_cred_row(&mut self) {
        if self.credentials.is_empty() {
            return;
        }
        let i = match self.creds_state.selected() {
            Some(i) => {
                if i >= self.credentials.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.creds_state.select(Some(i));
    }

    pub fn previous_cred_row(&mut self) {
        if self.credentials.is_empty() {
            return;
        }
        let i = match self.creds_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.credentials.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.creds_state.select(Some(i));
    }
}
