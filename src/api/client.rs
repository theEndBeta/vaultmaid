//! HTTP client for Bitwarden Cloud/Vaultwarden REST API.
//!
//! This file exists to wrap `reqwest::Client` with Bitwarden-specific
//! concerns: base URL construction (server + `/api` or `/identity`
//! prefix) and bearer token injection. Isolating these here means the
//! rest of the application never sees raw URLs or auth headers.
//!
//! The `Client` struct holds the server URL, an optional bearer token,
//! and the underlying `reqwest::Client`. Methods like `url(path)` join
//! the server URL with the appropriate prefix, and `auth_header()`
//! returns the Authorization header value when a token is present.
//!
//! Error mapping is centralized in `ApiError`: 401/403/429/5xx are
//! distinct variants so callers can implement retry logic (429 with
//! backoff, 401 to trigger re-auth, 403 to show permission errors).
//! Other status codes become `Other` with the status code preserved.

// Device-code auth (Step 6) uses `new`/`url`/`http`. The bearer helpers
// (`with_token`, `auth_header`) and `ApiPrefix::Api` are exercised from
// Step 8's authenticated sync onward; the allow is removed then.
#![allow(dead_code)]

use reqwest::StatusCode;
use thiserror::Error;
use url::Url;

/// HTTP client for Bitwarden REST API.
///
/// `server_url` is the base URL (e.g., `https://vault.bitwarden.com`).
/// `token` is the bearer token for authenticated requests; `None` means
/// unauthenticated (e.g., device-code flow before login completes).
/// `http` is the underlying reqwest client.
#[derive(Debug, Clone)]
pub struct Client {
    server_url: Url,
    token: Option<String>,
    http: reqwest::Client,
}

impl Client {
    /// Create a new client for the given server URL.
    ///
    /// The token starts as `None`; call `with_token` after authentication
    /// completes. The reqwest client uses default settings (no timeout,
    /// default TLS backend).
    pub fn new(server_url: Url) -> Self {
        Self {
            server_url,
            token: None,
            http: reqwest::Client::new(),
        }
    }

    /// Return a copy of this client with the given bearer token.
    ///
    /// This is a builder-style method that doesn't mutate the original.
    /// The token is injected into the Authorization header for all
    /// subsequent requests made through the returned client.
    pub fn with_token(mut self, token: String) -> Self {
        self.token = Some(token);
        self
    }

    /// Construct the Authorization header value.
    ///
    /// Returns `Some("Bearer <token>")` if a token is present, `None`
    /// otherwise. Callers should skip the header when this returns
    /// `None` (unauthenticated endpoints like device-code start).
    pub fn auth_header(&self) -> Option<String> {
        self.token.as_ref().map(|t| format!("Bearer {}", t))
    }

    /// Join the server URL with a Bitwarden API path.
    ///
    /// `path` is relative to `/api` or `/identity`. The `prefix` argument
    /// selects which: `ApiPrefix::Api` for vault operations,
    /// `ApiPrefix::Identity` for authentication. Any leading slash on
    /// `path` is stripped because `Url::join` treats a leading slash as
    /// an absolute path and would reset the URL to the host root,
    /// dropping the `/api` prefix.
    ///
    /// Example: `url("/ciphers", ApiPrefix::Api)` on server
    /// `https://vault.bitwarden.com` returns
    /// `https://vault.bitwarden.com/api/ciphers`.
    pub fn url(&self, path: &str, prefix: ApiPrefix) -> Result<Url, url::ParseError> {
        let segment = match prefix {
            ApiPrefix::Api => "api/",
            ApiPrefix::Identity => "identity/",
        };
        let path = path.trim_start_matches('/');
        self.server_url.join(segment)?.join(path)
    }

    /// Access the underlying reqwest client.
    ///
    /// Exposed for advanced use cases (custom headers, streaming responses)
    /// that the wrapper doesn't cover. Most callers should use higher-level
    /// methods in `api/auth.rs`, `api/sync.rs`, etc.
    pub fn http(&self) -> &reqwest::Client {
        &self.http
    }
}

/// Bitwarden API path prefix.
///
/// The Bitwarden REST API splits endpoints into two groups: `/api` for
/// vault operations (ciphers, folders, collections) and `/identity` for
/// authentication (device-code, token refresh). This enum selects which
/// prefix to use when constructing URLs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiPrefix {
    Api,
    Identity,
}

/// API errors mapped from HTTP status codes.
///
/// Each variant corresponds to a status code that requires distinct
/// handling: `Unauthorized` (401) triggers re-auth, `Forbidden` (403)
/// shows a permission error, `RateLimited` (429) triggers backoff with
/// retry, `ServerError` (5xx) is transient and retryable, `Other` is
/// everything else (4xx client errors that aren't 401/403/429).
///
/// The `message` field is a human-readable description suitable for
/// display in a toast or modal.
#[derive(Debug, Error)]
pub enum ApiError {
    #[error("unauthorized: {message}")]
    Unauthorized { message: String },
    #[error("forbidden: {message}")]
    Forbidden { message: String },
    #[error("rate limited: {message}")]
    RateLimited { message: String },
    #[error("server error: {message}")]
    ServerError { message: String },
    #[error("API error {status}: {message}")]
    Other { status: StatusCode, message: String },
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),
}

impl ApiError {
    /// Map an HTTP response to an `ApiError`.
    ///
    /// Returns `None` for 2xx responses (success). For non-2xx, extracts
    /// the status code and constructs the appropriate variant. The error
    /// message is derived from the status text; callers can override it
    /// if the response body contains a more specific error. Status-code
    /// coverage is exercised in Step 6's wiremock tests, not here —
    /// constructing a reqwest::Response without a live server is not
    /// supported by reqwest's public API.
    pub fn from_response(response: &reqwest::Response) -> Option<Self> {
        let status = response.status();
        if status.is_success() {
            return None;
        }

        let message = status
            .canonical_reason()
            .unwrap_or("unknown error")
            .to_string();

        Some(match status.as_u16() {
            401 => ApiError::Unauthorized { message },
            403 => ApiError::Forbidden { message },
            429 => ApiError::RateLimited { message },
            500..=599 => ApiError::ServerError { message },
            _ => ApiError::Other { status, message },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_with_server(url: &str) -> Client {
        Client::new(Url::parse(url).unwrap())
    }

    #[test]
    fn url_joining_with_api_prefix() {
        let client = client_with_server("https://vault.bitwarden.com");
        let url = client.url("/ciphers", ApiPrefix::Api).unwrap();
        assert_eq!(url.as_str(), "https://vault.bitwarden.com/api/ciphers");
    }

    #[test]
    fn url_joining_with_identity_prefix() {
        let client = client_with_server("https://vault.bitwarden.com");
        let url = client.url("/connect/token", ApiPrefix::Identity).unwrap();
        assert_eq!(
            url.as_str(),
            "https://vault.bitwarden.com/identity/connect/token"
        );
    }

    #[test]
    fn url_joining_handles_trailing_slash_on_server() {
        let client = client_with_server("https://vault.bitwarden.com/");
        let url = client.url("/ciphers", ApiPrefix::Api).unwrap();
        assert_eq!(url.as_str(), "https://vault.bitwarden.com/api/ciphers");
    }

    #[test]
    fn url_joining_with_nested_path() {
        let client = client_with_server("https://vault.bitwarden.com");
        let url = client.url("/ciphers/123/import", ApiPrefix::Api).unwrap();
        assert_eq!(
            url.as_str(),
            "https://vault.bitwarden.com/api/ciphers/123/import"
        );
    }

    #[test]
    fn auth_header_with_token() {
        let client =
            client_with_server("https://vault.bitwarden.com").with_token("abc123".to_string());
        assert_eq!(client.auth_header(), Some("Bearer abc123".to_string()));
    }

    #[test]
    fn auth_header_without_token() {
        let client = client_with_server("https://vault.bitwarden.com");
        assert_eq!(client.auth_header(), None);
    }
}
