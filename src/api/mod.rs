//! HTTP client wrapper for Bitwarden Cloud/Vaultwarden.
//!
//! This module exists to isolate the base URL and authentication header
//! logic from the rest of the application. The Bitwarden API uses two
//! distinct path prefixes: `/api` for vault operations and `/identity`
//! for authentication. Centralizing URL construction here prevents
//! call sites from hardcoding path prefixes and makes server URL
//! changes (e.g., self-hosted Vaultwarden) transparent to callers.
//!
//! The wrapper also owns the bearer token, so auth header construction
//! is consistent across all requests. Callers never manually prepend
//! the server URL or add Authorization headers.

pub mod auth;
pub mod client;
