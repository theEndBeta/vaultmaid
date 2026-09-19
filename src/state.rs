// Single source of truth for VaultMaid's runtime state.
//
// This file exists to hold the state the application renders and mutates in
// one flat struct. Keeping State flat rather than nested is a deliberate
// choice: Iced's update/view model favors a single struct passed by reference,
// and nesting sub-states behind Option<Box<...>> would force every view to
// unwrap layers before rendering. Flat fields with an explicit Screen
// discriminator make the active flow obvious and keep matches shallow.
//
// Debug is hand-written, not derived, because several fields are secrets in
// transit: the PIN as typed, the confirm field, the live 2FA code, and the
// decrypted vault snapshot. A derived Debug would print all of them into any
// tracing line that touches State; the masked impl keeps only non-secret
// fields and placeholders for the rest. Auth token types already mask
// themselves the same way.

use crate::api::auth::{DeviceCode, Session};
use crate::config::Config;
use crate::message::Screen;
use crate::pin::CacheKey;
use std::fmt;

/// The entire runtime state of the application.
///
/// `screen` is the top-level discriminator: every view pattern-matches on it
/// first, then reads only the fields relevant to that screen. `config` is
/// loaded once at startup and mutated in place so views never talk to the
/// filesystem. `toasts` is a placeholder that later steps replace with a
/// structured toast stack.
#[derive(Default)]
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
    /// Provider id chosen from the server's `TwoFactorProviders` payload.
    pub two_factor_provider: Option<u8>,
    /// Extra seconds added to every remaining poll after `slow_down`
    /// (RFC 8628 §3.5); reset when a new device code or flow starts.
    pub poll_backoff: u64,
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

impl fmt::Debug for State {
    /// Sensitive fields are placeholders, never values: the typed PIN, its
    /// confirm, the 2FA code, and the decrypted vault would otherwise be
    /// one stray log statement away from the terminal.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("State")
            .field("screen", &self.screen)
            .field("config", &self.config)
            .field("toasts", &self.toasts)
            .field("pin_input", &"***")
            .field("pin_confirm", &"***")
            .field("pin_error", &self.pin_error)
            .field("session", &self.session)
            .field("device_code", &self.device_code)
            .field("two_factor_input", &"***")
            .field("two_factor_provider", &self.two_factor_provider)
            .field("poll_backoff", &self.poll_backoff)
            .field("auth_busy", &self.auth_busy)
            .field("auth_error", &self.auth_error)
            .field("cache_key", &self.cache_key)
            .field(
                "cached_vault",
                &self.cached_vault.as_ref().map(|json| json.len()),
            )
            .finish()
    }
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

    #[test]
    fn debug_never_prints_pin_totp_or_decrypted_vault() {
        // Initializer syntax, not field reassignment: keeps the test clean
        // under `clippy --all-targets` once Step 19 adopts it.
        let state = State {
            pin_input: "1234".to_owned(),
            pin_confirm: "1234".to_owned(),
            two_factor_input: "654321".to_owned(),
            cached_vault: Some(r#"{"items":[{"login":"s3cret"}]}"#.to_owned()),
            ..State::default()
        };

        let printed = format!("{state:?}");
        assert!(!printed.contains("1234"));
        assert!(!printed.contains("654321"));
        assert!(!printed.contains("s3cret"));
        // Length, not content, is the only thing Debug reveals about the
        // snapshot — enough to debug the cache without leaking it.
        assert!(printed.contains("cached_vault: Some("));
    }
}
