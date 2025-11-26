//! Input handler module for ManagementApp
//! Orchestrates input processing between popups and main interface

use crate::{AppAction, TuiResult};

impl super::ManagementApp {
    pub fn handle_input(&mut self, input: &[u8]) -> TuiResult<AppAction> {
        tracing::trace!("ManagementApp input: {:?}", input);

        // Handle popup input first
        let popup_result = self.handle_popup_input(input)?;
        if popup_result != AppAction::Continue {
            return Ok(popup_result);
        }

        // Handle main input if no popup handled it
        self.handle_main_input(input)
    }
}
