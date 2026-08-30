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

use crate::config::Config;
use crate::message::{Message, Screen};
use crate::state::State;
use crate::ui;
use iced::widget::{column, text};
use iced::{Element, Theme};

/// Launches the application event loop.
///
/// Config is loaded in `boot` rather than `State::default` so unit
/// tests can still construct a default state without touching the XDG
/// config directory.
pub fn run() -> iced::Result {
    iced::application(boot, update, view)
        .title("VaultMaid")
        .theme(theme)
        .run()
}

/// Builds the initial state before the first view is rendered.
///
/// Iced 0.14 calls this once at startup via the `BootFn` contract; a
/// plain `State` is enough because no startup task is needed yet (later
/// steps will return a sync command from here).
fn boot() -> State {
    State {
        config: Config::load_or_default(),
        ..State::default()
    }
}

/// Applies a message to the state.
///
/// `ServerUrlChanged` writes through to disk here instead of returning a
/// Task: the file is a few hundred bytes and a failed write must not
/// roll back the in-memory URL the user just typed. PIN messages follow
/// the same rule — the hash/verify is fast, and the plaintext PIN must
/// not survive the message longer than the update frame that handles it.
fn update(state: &mut State, message: Message) {
    match message {
        Message::Noop => {}
        Message::ServerUrlChanged(url) => {
            state.config.server_url = url;
            if let Err(error) = state.config.save() {
                tracing::error!(%error, "failed to persist server URL");
            }
        }
        Message::PinInput(pin) => {
            state.pin_input = pin;
            state.pin_error = None;
        }
        Message::PinConfirmInput(confirm) => {
            state.pin_confirm = confirm;
            state.pin_error = None;
        }
        Message::PinSet(pin) => match crate::pin::hash_pin(&pin) {
            Ok(verifier) => {
                state.config.pin_verifier = Some(verifier);
                if let Err(error) = state.config.save() {
                    tracing::error!(%error, "failed to persist PIN verifier");
                }
                clear_pin_fields(state);
                // Follows the state machine: SetPin -> Locked, so the user
                // proves the PIN they just chose actually unlocks.
                state.screen = Screen::Unlock;
            }
            Err(error) => {
                state.pin_error = Some(error.to_string());
            }
        },
        Message::PinSubmitted(pin) => {
            let result = state
                .config
                .pin_verifier
                .as_ref()
                .map(|verifier| crate::pin::verify(&pin, verifier));
            clear_pin_fields(state);
            match result {
                Some(Ok(true)) => {
                    // Cache decryption lands in Step 7; for now a correct
                    // PIN simply opens the main view.
                    state.screen = Screen::Main;
                }
                Some(Ok(false)) => {
                    state.pin_error = Some("Incorrect PIN".to_owned());
                }
                Some(Err(error)) => {
                    tracing::error!(?error, "unlock attempted with a corrupt verifier");
                    state.pin_error = Some("PIN verifier is missing or corrupt".to_owned());
                }
                None => {
                    // A missing verifier here means the unlock screen was
                    // reached without setup — a logic bug, not a user error.
                    tracing::error!("unlock attempted without a verifier");
                    state.pin_error = Some("PIN verifier is missing or corrupt".to_owned());
                }
            }
        }
    }
}

/// Wipes the plaintext PIN fields after set/unlock completes.
///
/// The raw PIN must not linger in state once it has been hashed or
/// verified; the same discipline applies on vault lock in Step 10.
fn clear_pin_fields(state: &mut State) {
    state.pin_input.clear();
    state.pin_confirm.clear();
}

/// Renders the active screen.
///
/// The match on `Screen` is the extension point where `ui/` modules plug
/// in. Screens without a real view yet render a centered label so the
/// navigation skeleton stays visible while those modules are built.
fn view(state: &State) -> Element<'_, Message> {
    match state.screen {
        Screen::SetPin => ui::set_pin::view(
            &state.pin_input,
            &state.pin_confirm,
            state.pin_error.as_deref(),
        ),
        Screen::Unlock => ui::unlock::view(&state.pin_input, state.pin_error.as_deref()),
        screen => {
            let label = match screen {
                Screen::Login => "Login",
                Screen::DeviceCode => "Device Code",
                Screen::TwoFa => "Two-Factor Authentication",
                Screen::Main => "Main",
                // Covered above; the arm exists so this match stays exhaustive.
                Screen::SetPin | Screen::Unlock => unreachable!(),
            };
            column![text(label).size(24)].into()
        }
    }
}

/// Resolves the Iced theme from the OS light/dark preference.
///
/// Falls back to the light theme when detection reports no preference;
/// 0.14 removed `Theme::default()`, so the fallback is explicit rather
/// than delegated.
fn theme(_state: &State) -> Theme {
    match dark_light::detect() {
        dark_light::Mode::Dark => Theme::Dark,
        dark_light::Mode::Light | dark_light::Mode::Default => Theme::Light,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serializes tests that write config through the XDG path. Env vars
    /// are process-global, so only one test at a time may redirect them.
    static CONFIG_ENV_LOCK: Mutex<()> = Mutex::new(());

    fn state_at_screen(screen: Screen) -> State {
        State {
            screen,
            ..State::default()
        }
    }

    /// Runs `f` with XDG_CONFIG_HOME pointing at a throwaway directory.
    ///
    /// `update` persists config through the real XDG path; without this,
    /// a test would clobber the user's `~/.config/vaultmaid/config.toml`.
    fn with_temp_config_dir(f: impl FnOnce()) {
        let _guard = CONFIG_ENV_LOCK.lock().expect("config env lock");
        let dir = std::env::temp_dir().join(format!("vaultmaid-app-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp config dir");
        std::env::set_var("XDG_CONFIG_HOME", &dir);
        f();
        std::env::remove_var("XDG_CONFIG_HOME");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pin_set_hashes_verifier_and_locks() {
        with_temp_config_dir(|| {
            let mut state = state_at_screen(Screen::SetPin);
            update(&mut state, Message::PinSet(crate::pin::Pin::new("1234")));

            assert_eq!(state.screen, Screen::Unlock);
            let verifier = state.config.pin_verifier.as_ref().expect("verifier stored");
            assert!(crate::pin::verify(&crate::pin::Pin::new("1234"), verifier).expect("verify"));
            // Plaintext must not survive the update frame.
            assert!(state.pin_input.is_empty());
            assert!(state.pin_confirm.is_empty());
            assert!(state.pin_error.is_none());
        });
    }

    #[test]
    fn pin_submitted_with_correct_pin_opens_main() {
        let verifier = crate::pin::hash_pin(&crate::pin::Pin::new("1234")).expect("hash");
        let mut state = state_at_screen(Screen::Unlock);
        state.config.pin_verifier = Some(verifier);
        update(
            &mut state,
            Message::PinSubmitted(crate::pin::Pin::new("1234")),
        );

        assert_eq!(state.screen, Screen::Main);
        assert!(state.pin_error.is_none());
        assert!(state.pin_input.is_empty());
    }

    #[test]
    fn pin_submitted_with_wrong_pin_shows_error() {
        let verifier = crate::pin::hash_pin(&crate::pin::Pin::new("1234")).expect("hash");
        let mut state = state_at_screen(Screen::Unlock);
        state.config.pin_verifier = Some(verifier);
        update(
            &mut state,
            Message::PinSubmitted(crate::pin::Pin::new("9999")),
        );

        assert_eq!(
            state.screen,
            Screen::Unlock,
            "failed unlock must not navigate"
        );
        assert_eq!(state.pin_error.as_deref(), Some("Incorrect PIN"));
    }

    #[test]
    fn pin_submitted_without_verifier_shows_error() {
        let mut state = state_at_screen(Screen::Unlock);
        update(
            &mut state,
            Message::PinSubmitted(crate::pin::Pin::new("1234")),
        );
        assert_eq!(
            state.pin_error.as_deref(),
            Some("PIN verifier is missing or corrupt")
        );
    }

    #[test]
    fn pin_input_clears_previous_error() {
        let mut state = state_at_screen(Screen::Unlock);
        state.pin_error = Some("Incorrect PIN".to_owned());
        update(&mut state, Message::PinInput("1".to_owned()));
        assert_eq!(state.pin_input, "1");
        assert!(state.pin_error.is_none());
    }
}
