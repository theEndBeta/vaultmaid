//! Local PIN as the cache-encryption root of trust.
//!
//! This file exists to establish the PIN as the sole local secret that
//! unlocks the encrypted vault cache. The PIN is not authentication —
//! that is device-code OAuth with the Bitwarden server. The PIN is the
//! key that decrypts the locally cached vault when the app restarts or
//! the user unlocks after idle. Separating these two concerns means the
//! server never sees the PIN, and the PIN never grants network access.
//!
//! Argon2id is used for both hashing (verifier) and key derivation
//! (cache key) because it is memory-hard and resistant to GPU/ASIC
//! attacks. The verifier stores the salt in its encoding; the cache key
//! derivation extracts that salt so the same PIN always produces the
//! same 32-byte key. This avoids storing the salt separately in config.
//!
//! PINs and verifiers are distinct newtypes, not bare strings: the
//! operations here take two string-like arguments, and swapping them at
//! a call site would compile silently without the type distinction.
//!
//! This module does not talk to the network, store the PIN in the
//! keyring (that is for refresh tokens), or implement biometric unlock
//! (future work via `keyring` Secret Service backend).

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use zeroize::Zeroizing;

/// A plaintext PIN entered by the user.
///
/// Wraps `Zeroizing<String>` so the bytes are wiped on drop — plaintext
/// PINs must not outlive the frame that hashes or verifies them, which
/// is the same discipline vault-lock applies to decrypted data. `Debug`
/// is masked so tracing never prints the value.
#[derive(Clone)]
pub struct Pin(Zeroizing<String>);

impl Pin {
    pub fn new(pin: impl Into<String>) -> Self {
        Self(Zeroizing::new(pin.into()))
    }

    /// Borrow the plaintext for hashing or verification.
    ///
    /// Named `expose` rather than `as_str` on purpose: every call site
    /// widens the window in which the plaintext is visible, so the name
    /// should make callers think twice.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Pin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Pin(***)")
    }
}

/// An Argon2 verifier in PHC string format.
///
/// Newtype so callers cannot pass a PIN where a verifier is expected or
/// vice versa. Serde is transparent, so `config.toml` keeps storing a
/// plain string and stays hand-editable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Verifier(String);

impl Verifier {
    pub fn new(verifier: impl Into<String>) -> Self {
        Self(verifier.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for Verifier {
    fn from(value: String) -> Self {
        Self(value)
    }
}

/// Failures that prevent PIN operations.
///
/// These are surfaced to the UI as error messages; they never crash the
/// process. A wrong PIN is not an error here — `verify` reports it as
/// `Ok(false)` — so this enum only carries system failures (bad crypto
/// input, corrupt verifier). Keeping the two classes separate lets the
/// UI show "incorrect PIN" without exposing internal failures.
#[derive(Debug, Error)]
pub enum PinError {
    #[error("could not hash PIN: {0}")]
    HashError(String),
    #[error("verifier is malformed: {0}")]
    MalformedVerifier(String),
}

/// Hash a PIN into a verifier.
///
/// The returned verifier embeds the salt, Argon2 parameters, and hash in
/// the standard PHC format. This is what gets stored in `config.toml` as
/// `pin_verifier`. The salt is random per call, so hashing the same PIN
/// twice produces different verifier strings — that is intentional and
/// prevents offline comparison of verifiers across users.
pub fn hash_pin(pin: &Pin) -> Result<Verifier, PinError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(pin.expose().as_bytes(), &salt)
        .map(|hash| Verifier::new(hash.to_string()))
        .map_err(|e| PinError::HashError(e.to_string()))
}

/// Verify a PIN against a verifier.
///
/// Returns `Ok(true)` on match and `Ok(false)` on mismatch; `Err` is
/// reserved for a malformed verifier. This separation lets the UI
/// distinguish "wrong PIN" (user error) from "corrupt config" (system
/// error) without an extra error variant.
pub fn verify(pin: &Pin, verifier: &Verifier) -> Result<bool, PinError> {
    let parsed = PasswordHash::new(verifier.as_str())
        .map_err(|e| PinError::MalformedVerifier(e.to_string()))?;
    let argon2 = Argon2::default();
    match argon2.verify_password(pin.expose().as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(PinError::MalformedVerifier(e.to_string())),
    }
}

/// The AES-256 key that encrypts the vault cache, plus the salt it was
/// derived with.
///
/// The salt is carried alongside the key because the cache row records
/// the derivation inputs that produced its ciphertext; without it a
/// future key-rotation path could not tell which salt to reuse. It is
/// not secret — the PIN is the secret.
#[derive(Clone, PartialEq, Eq)]
pub struct CacheKey {
    pub key: [u8; 32],
    pub salt: Vec<u8>,
}

impl fmt::Debug for CacheKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CacheKey")
            .field("key", &"***")
            .field("salt", &self.salt)
            .finish()
    }
}

/// Derive a cache key from a PIN and its verifier.
///
/// The cache key is what encrypts the vault snapshot in SQLite. It must
/// be deterministic: the same PIN + verifier always produces the same
/// key, so the app can decrypt the cache on restart. We extract the salt
/// from the verifier (which Argon2 embedded during `hash_pin`) and
/// re-run Argon2id with that salt to produce a 32-byte output.
///
/// This is deliberately not the session token or any server-derived
/// secret. The cache key is local-only; if the user forgets the PIN,
/// the cache is unrecoverable (by design — there is no "forgot PIN"
/// flow because the server never saw it).
pub fn derive_cache_key(pin: &Pin, verifier: &Verifier) -> Result<CacheKey, PinError> {
    let parsed = PasswordHash::new(verifier.as_str())
        .map_err(|e| PinError::MalformedVerifier(e.to_string()))?;
    let salt = parsed
        .salt
        .as_ref()
        .ok_or_else(|| PinError::MalformedVerifier("verifier has no salt".into()))?;
    let argon2 = Argon2::default();
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(pin.expose().as_bytes(), salt.as_str().as_bytes(), &mut key)
        .map_err(|e| PinError::HashError(e.to_string()))?;
    Ok(CacheKey {
        key,
        salt: salt.as_str().as_bytes().to_vec(),
    })
}

/// Biometric unlock hook (stub).
///
/// Future work: on platforms with biometric hardware (Touch ID, Windows
/// Hello, Linux fingerprint readers), the PIN could be stored in the OS
/// keyring's Secure Enclave / TPM and retrieved via biometric prompt.
/// The `keyring` crate's Secret Service backend supports this on Linux
/// via `org.freedesktop.secrets`. On macOS, the `keyring` crate already
/// uses the Keychain, which can be configured to require biometric
/// unlock. This stub documents the integration point; implementation
/// depends on platform testing and user demand.
#[allow(dead_code)]
fn biometric_unlock_stub() {
    // Future: keyring::Entry::new_with_target("vaultmaid", "pin")
    // with biometric prompt configuration.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_round_trip() {
        let pin = Pin::new("1234");
        let verifier = hash_pin(&pin).expect("hash");
        assert!(verify(&pin, &verifier).expect("verify"));
    }

    #[test]
    fn wrong_pin_returns_false() {
        let verifier = hash_pin(&Pin::new("1234")).expect("hash");
        assert!(!verify(&Pin::new("5678"), &verifier).expect("verify"));
    }

    #[test]
    fn same_pin_produces_different_verifiers() {
        let pin = Pin::new("1234");
        let v1 = hash_pin(&pin).expect("hash");
        let v2 = hash_pin(&pin).expect("hash");
        assert_ne!(v1, v2, "random salt should produce different verifiers");
        // but both verify
        assert!(verify(&pin, &v1).expect("verify"));
        assert!(verify(&pin, &v2).expect("verify"));
    }

    #[test]
    fn derive_cache_key_is_deterministic() {
        let pin = Pin::new("1234");
        let verifier = hash_pin(&pin).expect("hash");
        let k1 = derive_cache_key(&pin, &verifier).expect("derive");
        let k2 = derive_cache_key(&pin, &verifier).expect("derive");
        assert_eq!(k1, k2, "same PIN + verifier must produce same key");
    }

    #[test]
    fn derive_cache_key_differs_for_different_pins() {
        let v1 = hash_pin(&Pin::new("1234")).expect("hash");
        let v2 = hash_pin(&Pin::new("5678")).expect("hash");
        let k1 = derive_cache_key(&Pin::new("1234"), &v1).expect("derive");
        let k2 = derive_cache_key(&Pin::new("5678"), &v2).expect("derive");
        assert_ne!(k1, k2, "different PINs must produce different keys");
    }

    #[test]
    fn malformed_verifier_returns_error() {
        let pin = Pin::new("1234");
        let garbage = Verifier::new("not-a-verifier");
        assert!(matches!(
            verify(&pin, &garbage),
            Err(PinError::MalformedVerifier(_))
        ));
        assert!(matches!(
            derive_cache_key(&pin, &garbage),
            Err(PinError::MalformedVerifier(_))
        ));
    }

    #[test]
    fn pin_debug_is_masked() {
        let pin = Pin::new("1234");
        let printed = format!("{:?}", pin);
        assert_eq!(printed, "Pin(***)");
    }

    #[test]
    fn verifier_serde_is_transparent() {
        // Serde must treat the verifier as a plain string so config.toml
        // stays hand-editable; verify via a table, since TOML cannot
        // serialize bare top-level values.
        #[derive(Serialize, Deserialize)]
        struct Wrapper {
            pin_verifier: Option<Verifier>,
        }
        let wrapper = Wrapper {
            pin_verifier: Some(Verifier::new("$argon2id$v=19$test")),
        };
        let encoded = toml::to_string(&wrapper).expect("serialize");
        assert_eq!(encoded.trim(), "pin_verifier = \"$argon2id$v=19$test\"");
        let decoded: Wrapper = toml::from_str(&encoded).expect("deserialize");
        assert_eq!(decoded.pin_verifier, wrapper.pin_verifier);
    }
}
