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

use crate::message::Screen;

/// The entire runtime state of the application.
///
/// `screen` is the top-level discriminator: every view pattern-matches on it
/// first, then reads only the fields relevant to that screen. `toasts` is a
/// placeholder that later steps replace with a structured toast stack.
#[derive(Debug, Default)]
pub struct State {
    pub screen: Screen,
    pub toasts: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_state_starts_at_login() {
        let state = State::default();
        assert_eq!(state.screen, Screen::Login);
        assert!(state.toasts.is_empty());
    }
}
