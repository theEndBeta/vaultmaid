// Iced application shell: dispatches messages and renders the active screen.
//
// This file exists to be the only place that knows how a Screen maps to a
// view. It owns the update/view/theme functions Iced calls, while the actual
// per-screen widgets live in `ui/` and are composed here. Keeping this file
// thin ensures the event loop stays readable as the app grows.
//
// Update returns a `Task`, which is how the device-code flow reaches the
// network without blocking the UI thread: each auth step is a future whose
// result comes back as a `Message`. The polling loop is driven by delayed
// `PollDeviceCode` messages rather than a busy loop, so the interval the
// server hands us is honored and the UI stays responsive.
//
// The system theme is resolved through the `dark-light` crate at view time
// rather than stored in State, because theme is a function of the OS
// environment, not of application state — storing it would risk divergence
// when the OS switches themes while the app is running.

use crate::api;
use crate::api::auth::{self, AuthTokens, DeviceInfo, PollOutcome, Session};
use crate::cache::Cache;
use crate::config::Config;
use crate::message::{Message, Screen};
use crate::state::State;
use crate::ui;
use iced::widget::{column, text};
use iced::{Element, Task, Theme};
use std::time::Duration;

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

/// Builds the initial state and kicks off silent session restore.
///
/// A returning user has a PIN verifier in config and a refresh token in
/// the keyring; when both are present the session is refreshed in the
/// background so the unlock screen appears without a login round trip.
/// The device identifier is generated eagerly so the very first auth
/// request already carries a stable id.
fn boot() -> (State, Task<Message>) {
    let mut config = Config::load_or_default();
    if config.device_identifier.is_none() {
        config.device_identifier = Some(uuid::Uuid::new_v4().to_string());
        if let Err(error) = config.save() {
            tracing::warn!(%error, "could not persist device identifier");
        }
    }

    let state = State {
        config,
        ..State::default()
    };
    let restore = restore_session(&state);
    (state, restore)
}

/// Applies a message to the state, returning any async work to perform.
///
/// Messages that only touch memory return `Task::none()`. Messages that
/// reach the network return a `Task::perform`; the plaintext PIN must not
/// survive the update frame that handles it.
fn update(state: &mut State, message: Message) -> Task<Message> {
    match message {
        Message::Noop => Task::none(),
        Message::ServerUrlChanged(url) => {
            state.config.server_url = url;
            if let Err(error) = state.config.save() {
                tracing::error!(%error, "failed to persist server URL");
            }
            Task::none()
        }
        Message::PinInput(pin) => {
            state.pin_input = pin;
            state.pin_error = None;
            Task::none()
        }
        Message::PinConfirmInput(confirm) => {
            state.pin_confirm = confirm;
            state.pin_error = None;
            Task::none()
        }
        Message::PinSet(pin) => {
            match crate::pin::hash_pin(&pin) {
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
            }
            Task::none()
        }
        Message::PinSubmitted(pin) => {
            let result = state
                .config
                .pin_verifier
                .as_ref()
                .map(|verifier| crate::pin::verify(&pin, verifier));
            clear_pin_fields(state);
            match result {
                Some(Ok(true)) => {
                    state.screen = Screen::Main;
                    // The PIN is still held here, so derive the cache key and
                    // load any stored snapshot before the field is dropped.
                    unlock_cache(state, &pin);
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
            Task::none()
        }
        Message::StartDeviceCode => start_device_code(state),
        Message::DeviceCodeReceived(code) => {
            let interval = code.interval.max(1);
            state.device_code = Some(code);
            state.auth_busy = false;
            state.screen = Screen::DeviceCode;
            Task::perform(wait_for(interval), |()| Message::PollDeviceCode)
        }
        Message::PollDeviceCode => poll_once(state, None),
        Message::PollFinished(outcome) => handle_poll(state, outcome),
        Message::TwoFactorInput(code) => {
            state.two_factor_input = code;
            state.auth_error = None;
            Task::none()
        }
        Message::TwoFactorSubmitted => {
            let token = std::mem::take(&mut state.two_factor_input);
            poll_once(state, Some(token))
        }
        Message::OpenVerificationUri(uri) => Task::perform(
            async move {
                if let Err(error) = open::that(uri) {
                    tracing::warn!(%error, "could not open verification URI");
                }
            },
            |()| Message::Noop,
        ),
        Message::SessionRestored(tokens) => complete_login(state, tokens),
        Message::SessionRestoreFailed(error) => {
            // Silencing this is deliberate: a failed silent refresh should
            // look like a normal login screen, not an error for a user who
            // never asked to be signed in.
            tracing::info!(%error, "silent session restore failed");
            state.auth_busy = false;
            Task::none()
        }
        Message::AuthFailed(error) => {
            state.auth_busy = false;
            state.auth_error = Some(error);
            Task::none()
        }
        Message::Logout => logout(state),
    }
}

/// Starts the device flow and requests a user code.
fn start_device_code(state: &mut State) -> Task<Message> {
    state.auth_error = None;
    state.device_code = None;
    let Some(client) = build_client(state) else {
        state.auth_error = Some("Server URL is not valid".to_owned());
        return Task::none();
    };

    state.auth_busy = true;
    let device = device_info(state);
    Task::perform(
        async move { auth::start_device_code(&client, &device).await },
        |result| match result {
            Ok(code) => Message::DeviceCodeReceived(code),
            Err(error) => Message::AuthFailed(error.to_string()),
        },
    )
}

/// Polls the token endpoint once, optionally with a second factor.
fn poll_once(state: &mut State, two_factor: Option<String>) -> Task<Message> {
    let Some(code) = state.device_code.clone() else {
        return Task::none();
    };
    let Some(client) = build_client(state) else {
        return Task::none();
    };

    let device = device_info(state);
    state.auth_busy = true;
    Task::perform(
        async move {
            auth::poll_device_code(&client, &device, &code.device_code, two_factor.as_deref()).await
        },
        |result| match result {
            Ok(outcome) => Message::PollFinished(outcome),
            Err(error) => Message::AuthFailed(error.to_string()),
        },
    )
}

/// Reacts to a poll result, scheduling the next attempt when appropriate.
fn handle_poll(state: &mut State, outcome: PollOutcome) -> Task<Message> {
    match outcome {
        PollOutcome::Authorized(tokens) => complete_login(state, tokens),
        PollOutcome::Pending => {
            state.auth_busy = true;
            let interval = poll_interval(state);
            Task::perform(wait_for(interval), |()| Message::PollDeviceCode)
        }
        PollOutcome::SlowDown => {
            // RFC 8628: on slow_down the client must increase its interval
            // by 5 seconds for all subsequent requests.
            let interval = poll_interval(state) + 5;
            Task::perform(wait_for(interval), |()| Message::PollDeviceCode)
        }
        PollOutcome::TwoFactorRequired => {
            state.auth_busy = false;
            state.auth_error = None;
            state.screen = Screen::TwoFa;
            Task::none()
        }
        PollOutcome::Expired => fail_login(state, "The device code expired. Try again."),
        PollOutcome::Denied => fail_login(state, "The login request was denied."),
    }
}

/// Stores the session and routes to PIN setup or unlock.
///
/// The refresh token is written to the keyring and the user id to config
/// so the next launch can restore silently. The access token stays in
/// memory only.
fn complete_login(state: &mut State, tokens: AuthTokens) -> Task<Message> {
    let refresh_token = tokens.refresh_token.clone();
    let session = Session::from_tokens(tokens);

    if let (Some(user_id), Some(refresh)) = (session.user_id.as_deref(), refresh_token.as_deref()) {
        if let Err(error) = auth::save_refresh_token(user_id, refresh) {
            tracing::warn!(%error, "could not store refresh token");
        }
    }
    if let Some(user_id) = session.user_id.clone() {
        state.config.last_user_id = Some(user_id);
        if let Err(error) = state.config.save() {
            tracing::warn!(%error, "could not persist last user id");
        }
    }

    state.session = Some(session);
    state.auth_busy = false;
    state.auth_error = None;
    state.two_factor_input.clear();
    state.device_code = None;
    state.screen = if state.config.pin_verifier.is_some() {
        Screen::Unlock
    } else {
        Screen::SetPin
    };
    Task::none()
}

/// Abandons an in-progress device flow and reports why.
fn fail_login(state: &mut State, message: &str) -> Task<Message> {
    state.auth_busy = false;
    state.device_code = None;
    state.auth_error = Some(message.to_owned());
    state.screen = Screen::Login;
    Task::none()
}

/// Clears session material locally and returns to the login screen.
///
/// The refresh token is deleted from the keyring; there is nothing
/// server-side to revoke from the client, and the access token dies with
/// the process.
fn logout(state: &mut State) -> Task<Message> {
    if let Some(user_id) = state.config.last_user_id.clone() {
        if let Err(error) = auth::clear_refresh_token(&user_id) {
            tracing::warn!(%error, "could not clear refresh token");
        }
        match Cache::open_default() {
            Ok(cache) => {
                if let Err(error) = cache.discard(&user_id) {
                    tracing::warn!(%error, "could not clear cached vault");
                }
            }
            Err(error) => tracing::warn!(%error, "could not open cache database"),
        }
    }
    state.session = None;
    state.device_code = None;
    state.two_factor_input.clear();
    state.auth_error = None;
    state.auth_busy = false;
    state.cache_key = None;
    state.cached_vault = None;
    state.config.last_user_id = None;
    if let Err(error) = state.config.save() {
        tracing::warn!(%error, "could not persist logout");
    }
    state.screen = Screen::Login;
    Task::none()
}

/// Attempts a silent refresh for the remembered user, if one exists.
fn restore_session(state: &State) -> Task<Message> {
    let Some(user_id) = state.config.last_user_id.clone() else {
        return Task::none();
    };
    let refresh_token = match auth::load_refresh_token(&user_id) {
        Ok(Some(token)) => token,
        Ok(None) => return Task::none(),
        Err(error) => {
            tracing::warn!(%error, "could not read stored refresh token");
            return Task::none();
        }
    };
    let Some(client) = build_client(state) else {
        return Task::none();
    };

    Task::perform(
        async move { auth::silent_refresh(&client, &refresh_token).await },
        |result| match result {
            Ok(tokens) => Message::SessionRestored(tokens),
            Err(error) => Message::SessionRestoreFailed(error.to_string()),
        },
    )
}

/// Builds an unauthenticated client from the configured server URL.
///
/// Authentication happens over `/identity`, which never needs a bearer
/// token, so this stays token-free; later steps wrap it with `with_token`
/// once a session exists.
fn build_client(state: &State) -> Option<api::client::Client> {
    match url::Url::parse(&state.config.server_url) {
        Ok(url) => Some(api::client::Client::new(url)),
        Err(error) => {
            tracing::error!(%error, "invalid server URL in config");
            None
        }
    }
}

/// Describes this installation to the server.
fn device_info(state: &State) -> DeviceInfo {
    let name = std::env::var("HOSTNAME")
        .ok()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "vaultmaid".to_owned());
    DeviceInfo::new(
        state.config.device_identifier.clone().unwrap_or_default(),
        name,
    )
}

/// Polling interval from the current device code, never below one second.
fn poll_interval(state: &State) -> u64 {
    state
        .device_code
        .as_ref()
        .map(|code| code.interval)
        .unwrap_or(5)
        .max(1)
}

/// Sleeps for the given number of seconds without blocking the UI thread.
async fn wait_for(seconds: u64) {
    tokio::time::sleep(Duration::from_secs(seconds)).await;
}

/// Wipes the plaintext PIN fields after set/unlock completes.
///
/// The raw PIN must not linger in state once it has been hashed or
/// verified; the same discipline applies on vault lock in Step 10.
fn clear_pin_fields(state: &mut State) {
    state.pin_input.clear();
    state.pin_confirm.clear();
}

/// Derives the cache key and loads the stored snapshot after unlock.
///
/// Runs only on a successful PIN check, so the key exists in memory only
/// for the life of the session. A missing snapshot is normal on a first
/// unlock and simply leaves `cached_vault` empty for sync to fill in.
fn unlock_cache(state: &mut State, pin: &crate::pin::Pin) {
    let Some(verifier) = state.config.pin_verifier.as_ref() else {
        return;
    };
    match crate::pin::derive_cache_key(pin, verifier) {
        Ok(key) => {
            state.cache_key = Some(key);
            load_cached_vault(state);
        }
        Err(error) => tracing::error!(%error, "could not derive cache key"),
    }
}

/// Loads the cached snapshot for the current session, if any.
///
/// Requires both a derived key and a known user id; before login
/// completes there is no user to look up, so this is a no-op.
fn load_cached_vault(state: &mut State) {
    let Some(key) = state.cache_key.clone() else {
        return;
    };
    let Some(user_id) = state
        .session
        .as_ref()
        .and_then(|session| session.user_id.clone())
    else {
        return;
    };

    match Cache::open_default() {
        Ok(cache) => match cache.load_vault(&user_id, &key) {
            Ok(snapshot) => {
                if let Some(json) = &snapshot {
                    tracing::info!(bytes = json.len(), "loaded cached vault snapshot");
                }
                state.cached_vault = snapshot;
            }
            Err(error) => tracing::warn!(%error, "could not load cached vault"),
        },
        Err(error) => tracing::warn!(%error, "could not open cache database"),
    }
}

/// Renders the active screen.
fn view(state: &State) -> Element<'_, Message> {
    match state.screen {
        Screen::Login | Screen::DeviceCode => ui::login::view(
            &state.config.server_url,
            state.device_code.as_ref(),
            state.auth_busy,
            state.auth_error.as_deref(),
        ),
        Screen::TwoFa => ui::login::two_factor_view(
            &state.two_factor_input,
            state.auth_busy,
            state.auth_error.as_deref(),
        ),
        Screen::SetPin => ui::set_pin::view(
            &state.pin_input,
            &state.pin_confirm,
            state.pin_error.as_deref(),
        ),
        Screen::Unlock => ui::unlock::view(&state.pin_input, state.pin_error.as_deref()),
        Screen::Main => {
            let label = match &state.cached_vault {
                Some(json) => format!("Main — cached snapshot: {} bytes", json.len()),
                None => "Main".to_owned(),
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
    use crate::pin::Verifier;
    use base64::Engine;
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

    /// Builds a JWT-shaped token whose payload carries `sub`.
    ///
    /// Only the middle segment is read, and its signature is never
    /// checked, so a fake is enough to exercise user-id extraction.
    fn fake_access_token(sub: &str) -> String {
        let claims = serde_json::json!({ "sub": sub });
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&claims).unwrap());
        format!("header.{payload}.signature")
    }

    fn sample_device_code() -> crate::api::auth::DeviceCode {
        crate::api::auth::DeviceCode {
            device_code: "dev-abc".to_owned(),
            user_code: "ABCD-EFGH".to_owned(),
            verification_uri: "https://vault.example/device".to_owned(),
            interval: 2,
        }
    }

    #[test]
    fn pin_set_hashes_verifier_and_locks() {
        with_temp_config_dir(|| {
            let mut state = state_at_screen(Screen::SetPin);
            let _ = update(&mut state, Message::PinSet(crate::pin::Pin::new("1234")));

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
        let _ = update(
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
        let _ = update(
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
        let _ = update(
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
        let _ = update(&mut state, Message::PinInput("1".to_owned()));
        assert_eq!(state.pin_input, "1");
        assert!(state.pin_error.is_none());
    }

    #[test]
    fn invalid_server_url_reports_error_without_network() {
        let mut state = State::default();
        state.config.server_url = "not-a-url".to_owned();
        let _ = update(&mut state, Message::StartDeviceCode);
        assert_eq!(state.auth_error.as_deref(), Some("Server URL is not valid"));
        assert!(!state.auth_busy);
    }

    #[test]
    fn device_code_received_shows_waiting_state() {
        let mut state = state_at_screen(Screen::Login);
        let _ = update(
            &mut state,
            Message::DeviceCodeReceived(sample_device_code()),
        );
        assert_eq!(state.screen, Screen::DeviceCode);
        assert_eq!(
            state
                .device_code
                .as_ref()
                .map(|code| code.user_code.as_str()),
            Some("ABCD-EFGH")
        );
        assert!(!state.auth_busy);
    }

    #[test]
    fn two_factor_required_switches_screen() {
        let mut state = state_at_screen(Screen::DeviceCode);
        state.device_code = Some(sample_device_code());
        let _ = update(
            &mut state,
            Message::PollFinished(PollOutcome::TwoFactorRequired),
        );
        assert_eq!(state.screen, Screen::TwoFa);
        assert!(!state.auth_busy);
    }

    #[test]
    fn expired_code_returns_to_login_with_error() {
        let mut state = state_at_screen(Screen::DeviceCode);
        state.device_code = Some(sample_device_code());
        let _ = update(&mut state, Message::PollFinished(PollOutcome::Expired));
        assert_eq!(state.screen, Screen::Login);
        assert!(state.device_code.is_none());
        assert!(state.auth_error.is_some());
    }

    #[test]
    fn denied_login_returns_to_login_with_error() {
        let mut state = state_at_screen(Screen::DeviceCode);
        state.device_code = Some(sample_device_code());
        let _ = update(&mut state, Message::PollFinished(PollOutcome::Denied));
        assert_eq!(state.screen, Screen::Login);
        assert!(state.auth_error.is_some());
    }

    #[test]
    fn session_restored_requires_pin_setup_on_first_launch() {
        with_temp_config_dir(|| {
            let mut state = State::default();
            let tokens = AuthTokens {
                access_token: fake_access_token("user-7"),
                // No refresh token avoids a keyring write in this test.
                refresh_token: None,
            };
            let _ = update(&mut state, Message::SessionRestored(tokens));

            assert_eq!(state.screen, Screen::SetPin);
            assert_eq!(
                state
                    .session
                    .as_ref()
                    .and_then(|session| session.user_id.as_deref()),
                Some("user-7")
            );
            assert_eq!(state.config.last_user_id.as_deref(), Some("user-7"));
            assert!(state.auth_error.is_none());
        });
    }

    #[test]
    fn session_restored_routes_to_unlock_when_pin_exists() {
        with_temp_config_dir(|| {
            let mut state = State::default();
            state.config.pin_verifier = Some(Verifier::new("$argon2id$v=19$test"));
            let tokens = AuthTokens {
                access_token: fake_access_token("user-7"),
                refresh_token: None,
            };
            let _ = update(&mut state, Message::SessionRestored(tokens));
            assert_eq!(state.screen, Screen::Unlock);
        });
    }

    #[test]
    fn logout_clears_session_material() {
        with_temp_config_dir(|| {
            let mut state = State::default();
            state.session = Some(Session {
                access_token: "token".to_owned(),
                user_id: Some("user-7".to_owned()),
            });
            state.config.last_user_id = Some("user-7".to_owned());
            state.device_code = Some(sample_device_code());

            let _ = update(&mut state, Message::Logout);

            assert!(state.session.is_none());
            assert!(state.device_code.is_none());
            assert!(state.config.last_user_id.is_none());
            assert!(state.cache_key.is_none());
            assert!(state.cached_vault.is_none());
            assert_eq!(state.screen, Screen::Login);
        });
    }

    #[test]
    fn unlock_loads_cached_snapshot() {
        with_temp_config_dir(|| {
            let pin = crate::pin::Pin::new("1234");
            let verifier = crate::pin::hash_pin(&pin).expect("hash");

            let mut state = State::default();
            state.config.pin_verifier = Some(verifier.clone());
            state.session = Some(Session {
                access_token: "token".to_owned(),
                user_id: Some("user-9".to_owned()),
            });

            // Persist a snapshot under the key the same PIN will derive,
            // mirroring what a prior sync would have written.
            let key = crate::pin::derive_cache_key(&pin, &verifier).expect("derive");
            crate::cache::Cache::open_default()
                .expect("open cache")
                .save_vault("user-9", &key, "{\"folders\":[]}")
                .expect("save");

            let _ = update(
                &mut state,
                Message::PinSubmitted(crate::pin::Pin::new("1234")),
            );

            assert_eq!(state.screen, Screen::Main);
            assert!(state.cache_key.is_some());
            assert_eq!(state.cached_vault.as_deref(), Some("{\"folders\":[]}"));
        });
    }

    #[test]
    fn logout_discards_cached_snapshot() {
        with_temp_config_dir(|| {
            let key = crate::pin::CacheKey {
                key: [3u8; 32],
                salt: b"salt".to_vec(),
            };
            let cache = crate::cache::Cache::open_default().expect("open cache");
            cache.save_vault("user-9", &key, "{}").expect("save");

            let mut state = State::default();
            state.config.last_user_id = Some("user-9".to_owned());
            state.cache_key = Some(key.clone());
            state.cached_vault = Some("{}".to_owned());

            let _ = update(&mut state, Message::Logout);

            assert!(state.cached_vault.is_none());
            assert!(cache.load_vault("user-9", &key).expect("load").is_none());
        });
    }
}
