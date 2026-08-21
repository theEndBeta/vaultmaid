// Iced application shell: dispatches messages and renders the active screen.
//
// This file exists to be the only place that knows how a Screen maps to a
// view. It owns the update/view/theme functions Iced calls, while the actual
// per-screen widgets live in `ui/` and are composed here. Keeping this file
// thin ensures the event loop stays readable as the app grows.
//
// The system theme is resolved through the `dark-light` crate at view time
// rather than stored in State, because theme is a function of the OS
// environment, not of application state — storing it would risk divergence
// when the OS switches themes while the app is running.

use crate::message::{Message, Screen};
use crate::state::State;
use iced::widget::{column, text};
use iced::{Element, Theme};

/// Launches the application event loop.
///
/// This is the single entry point called from `main.rs`; it returns Iced's
/// `Result` so the process exit code reflects startup failures.
pub fn run() -> iced::Result {
    iced::application("VaultMaid", update, view)
        .theme(theme)
        .run()
}

/// Applies a message to the state.
///
/// This is a pure function over `State` — no side effects here. Commands that
/// need to reach the network or filesystem are returned from `update` in later
/// steps; for the skeleton every message is inert.
fn update(_state: &mut State, message: Message) {
    match message {
        Message::Noop => {}
    }
}

/// Renders the active screen.
///
/// Each screen is currently a centered label so the navigation skeleton is
/// verifiable before real views exist. The match on `Screen` is the extension
/// point where `ui/` modules plug in.
fn view(state: &State) -> Element<'_, Message> {
    let label = match state.screen {
        Screen::Login => "Login",
        Screen::DeviceCode => "Device Code",
        Screen::TwoFa => "Two-Factor Authentication",
        Screen::SetPin => "Set PIN",
        Screen::Unlock => "Unlock",
        Screen::Main => "Main",
    };

    column![text(label).size(24)].into()
}

/// Resolves the Iced theme from the OS light/dark preference.
///
/// Falls back to the default theme when detection is unavailable, which keeps
/// the app usable on platforms where `dark-light` cannot probe the environment.
fn theme(_state: &State) -> Theme {
    match dark_light::detect() {
        dark_light::Mode::Dark => Theme::Dark,
        dark_light::Mode::Light => Theme::Light,
        dark_light::Mode::Default => Theme::default(),
    }
}
