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

use crate::api::auth::{AuthTokens, DeviceCode, PollOutcome};
use crate::pin::Pin;

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
#[allow(dead_code)] // Logout/Noop are emitted by views landing in later steps
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
    PinSet(Pin),
    /// Unlock attempted. Verified against the config verifier in the
    /// update function; a failure shows an error, never a lockout.
    PinSubmitted(Pin),
    /// User asked to begin device-code login.
    StartDeviceCode,
    /// Device authorization succeeded; carries the code to display.
    DeviceCodeReceived(DeviceCode),
    /// Poll the token endpoint once (no second factor).
    PollDeviceCode,
    /// One poll finished; the update function decides whether to keep
    /// polling, show 2FA, or proceed.
    PollFinished(PollOutcome),
    /// Code entry changed on the 2FA form.
    TwoFactorInput(String),
    /// User submitted a second factor; resubmits the poll with the code.
    TwoFactorSubmitted,
    /// Open the verification URI in the system browser.
    OpenVerificationUri(String),
    /// A silent refresh succeeded at launch.
    SessionRestored(AuthTokens),
    /// A silent refresh failed; stays on the login screen.
    SessionRestoreFailed(String),
    /// A device-code or refresh step failed with a user-facing message.
    AuthFailed(String),
    /// Clear all session material and return to the login screen.
    Logout,
}
