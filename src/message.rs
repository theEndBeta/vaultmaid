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
pub enum Message {
    Noop,
}
