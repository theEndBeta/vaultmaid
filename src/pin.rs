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
//! This module does not talk to the network, store the PIN in the
//! keyring (that is for refresh tokens), or implement biometric unlock
//! (future work via `keyring` Secret Service backend).

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use thiserror::Error;

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

/// Hash a PIN into a verifier string.
///
/// The returned string embeds the salt, Argon2 parameters, and hash in
/// the standard PHC format. This is what gets stored in `config.toml` as
/// `pin_verifier`. The salt is random per call, so hashing the same PIN
/// twice produces different verifier strings — that is intentional and
/// prevents offline comparison of verifiers across users.
pub fn hash_pin(pin: &str) -> Result<String, PinError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(pin.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| PinError::HashError(e.to_string()))
}

/// Verify a PIN against a verifier.
///
/// Returns `Ok(true)` on match and `Ok(false)` on mismatch; `Err` is
/// reserved for a malformed verifier. This separation lets the UI
/// distinguish "wrong PIN" (user error) from "corrupt config" (system
/// error) without an extra error variant.
pub fn verify(pin: &str, verifier: &str) -> Result<bool, PinError> {
    let parsed =
        PasswordHash::new(verifier).map_err(|e| PinError::MalformedVerifier(e.to_string()))?;
    let argon2 = Argon2::default();
    match argon2.verify_password(pin.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(PinError::MalformedVerifier(e.to_string())),
    }
}

/// Derive a 32-byte cache key from a PIN and its verifier.
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
#[allow(dead_code)] // wired in Step 7, where the encrypted cache uses this key
pub fn derive_cache_key(pin: &str, verifier: &str) -> Result<[u8; 32], PinError> {
    let parsed =
        PasswordHash::new(verifier).map_err(|e| PinError::MalformedVerifier(e.to_string()))?;
    let salt = parsed
        .salt
        .as_ref()
        .ok_or_else(|| PinError::MalformedVerifier("verifier has no salt".into()))?;
    let argon2 = Argon2::default();
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(pin.as_bytes(), salt.as_str().as_bytes(), &mut key)
        .map_err(|e| PinError::HashError(e.to_string()))?;
    Ok(key)
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
        let pin = "1234";
        let verifier = hash_pin(pin).expect("hash");
        assert!(verify(pin, &verifier).expect("verify"));
    }

    #[test]
    fn wrong_pin_returns_false() {
        let verifier = hash_pin("1234").expect("hash");
        assert!(!verify("5678", &verifier).expect("verify"));
    }

    #[test]
    fn same_pin_produces_different_verifiers() {
        let pin = "1234";
        let v1 = hash_pin(pin).expect("hash");
        let v2 = hash_pin(pin).expect("hash");
        assert_ne!(v1, v2, "random salt should produce different verifiers");
        // but both verify
        assert!(verify(pin, &v1).expect("verify"));
        assert!(verify(pin, &v2).expect("verify"));
    }

    #[test]
    fn derive_cache_key_is_deterministic() {
        let pin = "1234";
        let verifier = hash_pin(pin).expect("hash");
        let k1 = derive_cache_key(pin, &verifier).expect("derive");
        let k2 = derive_cache_key(pin, &verifier).expect("derive");
        assert_eq!(k1, k2, "same PIN + verifier must produce same key");
    }

    #[test]
    fn derive_cache_key_differs_for_different_pins() {
        let v1 = hash_pin("1234").expect("hash");
        let v2 = hash_pin("5678").expect("hash");
        let k1 = derive_cache_key("1234", &v1).expect("derive");
        let k2 = derive_cache_key("5678", &v2).expect("derive");
        assert_ne!(k1, k2, "different PINs must produce different keys");
    }

    #[test]
    fn malformed_verifier_returns_error() {
        assert!(matches!(
            verify("1234", "not-a-verifier"),
            Err(PinError::MalformedVerifier(_))
        ));
        assert!(matches!(
            derive_cache_key("1234", "not-a-verifier"),
            Err(PinError::MalformedVerifier(_))
        ));
    }
}
