// Navigation and event vocabulary for VaultMaid.
//
// This file exists to define the finite set of screens the application can
// display and the messages that drive state transitions. Separating navigation
// (Screen) from events (Message) keeps the state machine explicit and testable.
//
// Screen represents the top-level UI state — each variant corresponds to a
// distinct user flow (login, 2FA, PIN setup, etc.). Message is the union of
// all user and system events the app can handle. Keeping them separate allows
// the view layer to pattern-match on Screen without knowing about every Message.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[allow(dead_code)] // later steps construct every variant as the state machine grows
pub enum Screen {
    #[default]
    Login,
    DeviceCode,
    TwoFa,
    SetPin,
    Unlock,
    Main,
}

#[derive(Debug, Clone)]
#[allow(dead_code)] // constructed by widgets that do not exist until the login view
pub enum Message {
    Noop,
    /// The login field changed. Persisted immediately so a crash after
    /// typing a self-hosted URL does not fall back to Bitwarden Cloud.
    ServerUrlChanged(String),
    /// PIN entry field changed on either the setup or unlock form.
    PinInput(String),
    /// Confirm field changed on the setup form only.
    PinConfirmInput(String),
    /// First-launch setup completed. Carries the typed PIN as a
    /// zeroizing `Pin`; the update function hashes it into the config
    /// verifier before anything else touches it.
    PinSet(crate::pin::Pin),
    /// Unlock attempted. Verified against the config verifier in the
    /// update function; a failure shows an error, never a lockout.
    PinSubmitted(crate::pin::Pin),
}
