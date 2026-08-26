// Single source of truth for VaultMaid's runtime state.
//
// This file exists to hold the state the application renders and mutates in
// one flat struct. Keeping State flat rather than nested is a deliberate
// choice: Iced's update/view model favors a single struct passed by reference,
// and nesting sub-states behind Option<Box<...>> would force every view to
// unwrap layers before rendering. Flat fields with an explicit Screen
// discriminator make the active flow obvious and keep matches shallow.
//
// Sub-states (login form, PIN entry, vault data) are added as optional fields
// here as later steps introduce them; this file only establishes the skeleton.

use crate::config::Config;
use crate::message::Screen;

/// The entire runtime state of the application.
///
/// `screen` is the top-level discriminator: every view pattern-matches on it
/// first, then reads only the fields relevant to that screen. `config` is
/// loaded once at startup and mutated in place so views never talk to the
/// filesystem. `toasts` is a placeholder that later steps replace with a
/// structured toast stack.
#[derive(Debug, Default)]
pub struct State {
    pub screen: Screen,
    pub config: Config,
    #[allow(dead_code)] // toast stack is a Step 16 concern; field exists so State stays flat
    pub toasts: Vec<String>,
    /// Live PIN field value. Kept here (not in the widget) so the update
    /// function can hash and zero it without the view holding a copy.
    pub pin_input: String,
    /// Confirm field on the setup form.
    pub pin_confirm: String,
    /// Inline error for the PIN forms ("PINs do not match", "Incorrect PIN").
    pub pin_error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_state_starts_at_login() {
        let state = State::default();
        assert_eq!(state.screen, Screen::Login);
        assert!(state.toasts.is_empty());
        assert_eq!(state.config, crate::config::Config::default());
    }
}
