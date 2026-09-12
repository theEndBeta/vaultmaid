// Single source of truth for VaultMaid's runtime state.
//
// This file exists to hold the state the application renders and mutates in
// one flat struct. Keeping State flat rather than nested is a deliberate
// choice: Iced's update/view model favors a single struct passed by reference,
// and nesting sub-states behind Option<Box<...>> would force every view to
// unwrap layers before rendering. Flat fields with an explicit Screen
// discriminator make the active flow obvious and keep matches shallow.
//
// The authenticated session lives here as an `Option<Session>` whose Debug
// is masked, so deriving Debug on State cannot leak tokens into logs. The
// PIN form fields are cleared as soon as they are consumed; the same
// discipline applies when auth material is dropped on logout.

use crate::api::auth::{DeviceCode, Session};
use crate::config::Config;
use crate::message::Screen;
use crate::pin::CacheKey;

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
    /// Authenticated session; `None` until login or silent refresh.
    pub session: Option<Session>,
    /// Device code currently awaiting browser approval.
    pub device_code: Option<DeviceCode>,
    /// Live 2FA code entry.
    pub two_factor_input: String,
    /// A network auth step is in flight; views show a spinner.
    pub auth_busy: bool,
    /// User-facing authentication error.
    pub auth_error: Option<String>,
    /// AES key derived from the PIN on unlock. Held for the session so
    /// sync can re-encrypt the snapshot without re-prompting for the PIN.
    pub cache_key: Option<CacheKey>,
    /// Decrypted snapshot loaded from the cache, if one was readable.
    pub cached_vault: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_state_starts_at_login() {
        let state = State::default();
        assert_eq!(state.screen, Screen::Login);
        assert!(state.toasts.is_empty());
        assert!(state.session.is_none());
        assert!(!state.auth_busy);
        assert_eq!(state.config, crate::config::Config::default());
    }
}
