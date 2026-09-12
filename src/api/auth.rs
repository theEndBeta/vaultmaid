//! Device-code authentication and persistent session.
//!
//! This file exists to obtain an OAuth session from the Bitwarden server
//! without ever handling the user's master password. The SDK ships
//! password and API-key login only, so the device authorization grant is
//! implemented here against the identity service with `reqwest`.
//!
//! The flow follows RFC 8628 in two steps. First `start_device_code`
//! asks `/identity/connect/device-authorization` for a short user code
//! and a long device code; the user approves the user code in a browser.
//! Then the app polls `/identity/connect/token` with
//! `grant_type=urn:ietf:params:oauth:grant-type:device_code` until the
//! server answers with tokens or a terminal error. Two-factor is handled
//! by resubmitting the poll with a `two_factor_token`.
//!
//! The refresh token is the only artifact that outlives the process; it
//! is stored in the OS keyring keyed by user id, never in the TOML
//! config. The access token lives in memory and is dropped on exit.
//!
//! This module does not sync or decrypt the vault, and it does not
//! implement the auth-request (public-key approval) variant that some
//! Bitwarden clients use. If a live server rejects the device
//! authorization endpoint, this file is the single swap point.

use crate::api::client::{ApiError, ApiPrefix, Client};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// RFC 8628 device authorization endpoint, relative to `/identity`.
///
/// Bitwarden and Vaultwarden both expose the OAuth endpoints under
/// `/identity/connect`; if a server version uses a different path this
/// constant is the only change needed.
const DEVICE_AUTHORIZATION_PATH: &str = "connect/device-authorization";

/// OAuth token endpoint, relative to `/identity`.
const TOKEN_PATH: &str = "connect/token";

/// Grant type for the polling half of the device flow.
const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// Client id Bitwarden expects from desktop clients.
const CLIENT_ID: &str = "desktop";

/// Bitwarden `DeviceType` value for a Linux desktop client.
const DEVICE_TYPE_LINUX_DESKTOP: u32 = 8;

/// Keyring service name; the user field carries the per-user suffix.
const KEYRING_SERVICE: &str = "vaultmaid";

/// Requested scopes: API access plus a refresh token.
const SCOPE: &str = "api offline_access";

/// Identity of this installation, sent with every auth request.
///
/// Bitwarden uses `device_identifier` to recognize a returning device and
/// avoid re-prompting for 2FA on every login, so it must stay stable
/// across restarts; the caller persists it in config and passes it back
/// in. `device_name` is purely cosmetic.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub device_identifier: String,
    pub device_name: String,
}

impl DeviceInfo {
    pub fn new(device_identifier: impl Into<String>, device_name: impl Into<String>) -> Self {
        Self {
            device_identifier: device_identifier.into(),
            device_name: device_name.into(),
        }
    }
}

/// Short code the user approves in a browser, plus the polling handle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCode {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    #[serde(default = "default_interval")]
    pub interval: u64,
}

fn default_interval() -> u64 {
    5
}

/// Tokens returned once the user approves (or refreshes) the session.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
}

impl fmt::Debug for AuthTokens {
    /// Masked so a stray `{:?}` in logs cannot leak a usable credential.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthTokens")
            .field("access_token", &"***")
            .field("refresh_token", &self.refresh_token.as_ref().map(|_| "***"))
            .finish()
    }
}

/// In-memory authenticated session.
///
/// Holds the access token and the user id extracted from it. Never
/// serialized; the refresh token in the keyring is the durable half.
#[derive(Clone, PartialEq, Eq)]
pub struct Session {
    pub access_token: String,
    pub user_id: Option<String>,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("access_token", &"***")
            .field("user_id", &self.user_id)
            .finish()
    }
}

impl Session {
    pub fn from_tokens(tokens: AuthTokens) -> Self {
        let user_id = user_id_from_token(&tokens.access_token);
        Self {
            access_token: tokens.access_token,
            user_id,
        }
    }
}

/// Result of one poll against the token endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PollOutcome {
    /// User approved; the session is ready.
    Authorized(AuthTokens),
    /// Not approved yet; poll again after `interval`.
    Pending,
    /// Server asked for slower polling; back off before retrying.
    SlowDown,
    /// Server requires a second factor; resubmit with a `two_factor_token`.
    TwoFactorRequired,
    /// Device code expired; the whole flow must restart.
    Expired,
    /// User declined the request.
    Denied,
}

/// Failures from the authentication flow.
///
/// `SessionExpired` is the one callers branch on: a silent refresh that
/// returns it must fall back to a fresh device-code login. Everything
/// else is surfaced as an error message.
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("invalid server URL: {0}")]
    Url(#[from] url::ParseError),
    #[error("{0}")]
    Api(#[from] ApiError),
    #[error("could not decode server response: {0}")]
    Decode(String),
    #[error("authentication was rejected: {0}")]
    Rejected(String),
    #[error("session expired; sign in again")]
    SessionExpired,
    #[error("keyring error: {0}")]
    Keyring(String),
}

/// Begin the device flow by requesting a user code to approve.
pub async fn start_device_code(
    client: &Client,
    device: &DeviceInfo,
) -> Result<DeviceCode, AuthError> {
    let url = client.url(DEVICE_AUTHORIZATION_PATH, ApiPrefix::Identity)?;
    let form = [
        ("client_id", CLIENT_ID.to_owned()),
        ("deviceType", DEVICE_TYPE_LINUX_DESKTOP.to_string()),
        ("deviceIdentifier", device.device_identifier.clone()),
        ("deviceName", device.device_name.clone()),
        ("scope", SCOPE.to_owned()),
    ];

    let response = client.http().post(url).form(&form).send().await?;
    let api_error = ApiError::from_response(&response);
    if response.status().is_success() {
        return response
            .json::<DeviceCode>()
            .await
            .map_err(|error| AuthError::Decode(error.to_string()));
    }

    Err(fallback_error(api_error, response).await)
}

/// Poll the token endpoint once.
///
/// The caller owns the loop and the delay; this returns a single
/// outcome so scheduling stays testable and observable. `two_factor_token`
/// is `Some` only when retrying after `TwoFactorRequired`.
pub async fn poll_device_code(
    client: &Client,
    device: &DeviceInfo,
    device_code: &str,
    two_factor_token: Option<&str>,
) -> Result<PollOutcome, AuthError> {
    let url = client.url(TOKEN_PATH, ApiPrefix::Identity)?;
    let mut form = vec![
        ("grant_type", DEVICE_CODE_GRANT.to_owned()),
        ("device_code", device_code.to_owned()),
        ("client_id", CLIENT_ID.to_owned()),
        ("deviceType", DEVICE_TYPE_LINUX_DESKTOP.to_string()),
        ("deviceIdentifier", device.device_identifier.clone()),
        ("deviceName", device.device_name.clone()),
    ];
    if let Some(token) = two_factor_token {
        form.push(("two_factor_token", token.to_owned()));
    }

    let response = client.http().post(url).form(&form).send().await?;
    let api_error = ApiError::from_response(&response);
    let status = response.status();
    let body = response.text().await.unwrap_or_default();

    if status.is_success() {
        let tokens: TokenResponse =
            serde_json::from_str(&body).map_err(|error| AuthError::Decode(error.to_string()))?;
        return Ok(PollOutcome::Authorized(AuthTokens {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
        }));
    }

    let error: TokenErrorBody = serde_json::from_str(&body).unwrap_or_default();
    Ok(match error.error.as_deref() {
        Some("authorization_pending") => PollOutcome::Pending,
        Some("slow_down") => PollOutcome::SlowDown,
        Some("expired_token") => PollOutcome::Expired,
        Some("access_denied") => PollOutcome::Denied,
        // Bitwarden signals a second factor with a provider payload
        // rather than an OAuth error string.
        _ if error.two_factor_providers.is_some() => PollOutcome::TwoFactorRequired,
        // The body is already consumed here, so the API status mapping is
        // the only extra context left to attach.
        _ => {
            return Err(api_error
                .map(AuthError::Api)
                .unwrap_or(AuthError::Rejected(body)))
        }
    })
}

/// Exchange a refresh token for a new access token.
///
/// Returns `SessionExpired` when the server rejects the refresh token so
/// the caller can silently drop back to the login screen instead of
/// showing a raw protocol error.
pub async fn silent_refresh(client: &Client, refresh_token: &str) -> Result<AuthTokens, AuthError> {
    let url = client.url(TOKEN_PATH, ApiPrefix::Identity)?;
    let form = [
        ("grant_type", "refresh_token".to_owned()),
        ("refresh_token", refresh_token.to_owned()),
        ("client_id", CLIENT_ID.to_owned()),
    ];

    let response = client.http().post(url).form(&form).send().await?;
    match response.status().as_u16() {
        200 => {
            let tokens: TokenResponse = response
                .json()
                .await
                .map_err(|error| AuthError::Decode(error.to_string()))?;
            Ok(AuthTokens {
                access_token: tokens.access_token,
                refresh_token: tokens.refresh_token,
            })
        }
        // invalid_grant/401 both mean the stored token is no longer valid.
        400 | 401 => {
            // Drain the body so the connection can be reused; the content
            // is not needed to know the refresh failed.
            let _ = response.text().await;
            Err(AuthError::SessionExpired)
        }
        _ => {
            let api_error = ApiError::from_response(&response);
            Err(fallback_error(api_error, response).await)
        }
    }
}

/// Extract the `sub` claim from a JWT without verifying its signature.
///
/// The access token is issued by the server we just talked to and is used
/// only as a keyring/cache namespace, never as a security boundary, so
/// signature verification (which needs the server's keys) is unnecessary
/// and would force a network round trip.
pub fn user_id_from_token(access_token: &str) -> Option<String> {
    use base64::Engine;

    let payload = access_token.split('.').nth(1)?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(payload))
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    claims.get("sub")?.as_str().map(str::to_owned)
}

/// Store the refresh token for `user_id` in the OS keyring.
pub fn save_refresh_token(user_id: &str, refresh_token: &str) -> Result<(), AuthError> {
    keyring_entry(user_id)?
        .set_password(refresh_token)
        .map_err(|error| AuthError::Keyring(error.to_string()))
}

/// Load the refresh token for `user_id`, if one is stored.
pub fn load_refresh_token(user_id: &str) -> Result<Option<String>, AuthError> {
    match keyring_entry(user_id)?.get_password() {
        Ok(secret) => Ok(Some(secret)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(AuthError::Keyring(error.to_string())),
    }
}

/// Remove the stored refresh token; missing entries are not an error.
pub fn clear_refresh_token(user_id: &str) -> Result<(), AuthError> {
    match keyring_entry(user_id)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(error) => Err(AuthError::Keyring(error.to_string())),
    }
}

fn keyring_entry(user_id: &str) -> Result<keyring::Entry, AuthError> {
    keyring::Entry::new(KEYRING_SERVICE, &format!("refresh:{user_id}"))
        .map_err(|error| AuthError::Keyring(error.to_string()))
}

/// Pick the most specific error available for a failed response.
async fn fallback_error(api_error: Option<ApiError>, response: reqwest::Response) -> AuthError {
    if let Some(error) = api_error {
        return AuthError::Api(error);
    }
    let body = response.text().await.unwrap_or_default();
    AuthError::Rejected(body)
}

/// Token endpoint error envelope (RFC 6749 plus Bitwarden extras).
#[derive(Debug, Default, Deserialize)]
struct TokenErrorBody {
    #[serde(default)]
    error: Option<String>,
    #[serde(rename = "TwoFactorProviders", default)]
    two_factor_providers: Option<serde_json::Value>,
}

/// Successful token response; only the fields the app needs.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn device() -> DeviceInfo {
        DeviceInfo::new("device-123", "test-host")
    }

    fn client_for(server: &MockServer) -> Client {
        Client::new(url::Url::parse(&server.uri()).expect("mock url"))
    }

    #[tokio::test]
    async fn start_device_code_parses_codes() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/identity/connect/device-authorization"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "device_code": "dev-abc",
                "user_code": "ABCD-EFGH",
                "verification_uri": "https://vault.example/device",
                "interval": 2
            })))
            .mount(&server)
            .await;

        let code = start_device_code(&client_for(&server), &device())
            .await
            .expect("start");
        assert_eq!(code.device_code, "dev-abc");
        assert_eq!(code.user_code, "ABCD-EFGH");
        assert_eq!(code.verification_uri, "https://vault.example/device");
        assert_eq!(code.interval, 2);
    }

    #[tokio::test]
    async fn start_device_code_defaults_interval_when_absent() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/identity/connect/device-authorization"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "device_code": "dev-abc",
                "user_code": "ABCD-EFGH",
                "verification_uri": "https://vault.example/device"
            })))
            .mount(&server)
            .await;

        let code = start_device_code(&client_for(&server), &device())
            .await
            .expect("start");
        assert_eq!(code.interval, 5);
    }

    #[tokio::test]
    async fn start_device_code_maps_server_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/identity/connect/device-authorization"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let error = start_device_code(&client_for(&server), &device())
            .await
            .expect_err("should fail");
        assert!(matches!(
            error,
            AuthError::Api(ApiError::ServerError { .. })
        ));
    }

    #[tokio::test]
    async fn poll_pending_then_authorized() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/identity/connect/token"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_json(json!({ "error": "authorization_pending" })),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/identity/connect/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "access-1",
                "refresh_token": "refresh-1"
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let first = poll_device_code(&client, &device(), "dev-abc", None)
            .await
            .expect("poll");
        assert_eq!(first, PollOutcome::Pending);

        let second = poll_device_code(&client, &device(), "dev-abc", None)
            .await
            .expect("poll");
        match second {
            PollOutcome::Authorized(tokens) => {
                assert_eq!(tokens.access_token, "access-1");
                assert_eq!(tokens.refresh_token.as_deref(), Some("refresh-1"));
            }
            other => panic!("expected authorized, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn poll_maps_terminal_errors() {
        for (error, expected) in [
            ("slow_down", PollOutcome::SlowDown),
            ("expired_token", PollOutcome::Expired),
            ("access_denied", PollOutcome::Denied),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/identity/connect/token"))
                .respond_with(ResponseTemplate::new(400).set_body_json(json!({ "error": error })))
                .mount(&server)
                .await;

            let outcome = poll_device_code(&client_for(&server), &device(), "dev-abc", None)
                .await
                .expect("poll");
            assert_eq!(outcome, expected, "error {error}");
        }
    }

    #[tokio::test]
    async fn poll_detects_two_factor_required() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/identity/connect/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "error": "invalid_grant",
                "TwoFactorProviders": [0]
            })))
            .mount(&server)
            .await;

        let outcome = poll_device_code(&client_for(&server), &device(), "dev-abc", None)
            .await
            .expect("poll");
        assert_eq!(outcome, PollOutcome::TwoFactorRequired);
    }

    #[tokio::test]
    async fn poll_uses_two_factor_token_when_provided() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/identity/connect/token"))
            .and(wiremock::matchers::body_string_contains(
                "two_factor_token=123456",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "access-2",
                "refresh_token": "refresh-2"
            })))
            .mount(&server)
            .await;

        let outcome = poll_device_code(&client_for(&server), &device(), "dev-abc", Some("123456"))
            .await
            .expect("poll");
        assert!(matches!(outcome, PollOutcome::Authorized(_)));
    }

    #[tokio::test]
    async fn silent_refresh_returns_tokens() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/identity/connect/token"))
            .and(wiremock::matchers::body_string_contains(
                "grant_type=refresh_token",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "access-new"
            })))
            .mount(&server)
            .await;

        let tokens = silent_refresh(&client_for(&server), "refresh-old")
            .await
            .expect("refresh");
        assert_eq!(tokens.access_token, "access-new");
        assert!(tokens.refresh_token.is_none());
    }

    #[tokio::test]
    async fn silent_refresh_reports_expired_session() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/identity/connect/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "error": "invalid_grant"
            })))
            .mount(&server)
            .await;

        let error = silent_refresh(&client_for(&server), "stale")
            .await
            .expect_err("should expire");
        assert!(matches!(error, AuthError::SessionExpired));
    }

    #[test]
    fn user_id_extracted_from_jwt_payload() {
        use base64::Engine;
        let claims = json!({ "sub": "user-42", "scope": "api" });
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&claims).unwrap());
        let token = format!("header.{payload}.signature");
        assert_eq!(user_id_from_token(&token).as_deref(), Some("user-42"));
    }

    #[test]
    fn user_id_is_none_for_non_jwt() {
        assert_eq!(user_id_from_token("not-a-jwt"), None);
    }

    #[test]
    fn auth_tokens_debug_is_masked() {
        let tokens = AuthTokens {
            access_token: "super-secret".to_owned(),
            refresh_token: Some("also-secret".to_owned()),
        };
        let printed = format!("{tokens:?}");
        assert!(!printed.contains("super-secret"));
        assert!(!printed.contains("also-secret"));
    }
}
