//! AES-256-GCM encryption of vault snapshot blobs.
//!
//! This file exists to hide every byte of the cached vault at rest: the
//! SQLite file contains ciphertext, nonces, and derivation salts only,
//! so a stolen cache reveals nothing without the PIN.
//!
//! The snapshot is encrypted as one blob rather than per record. Per-row
//! encryption would leak structure (row counts, sizes, update patterns),
//! and the app never needs to query inside the cache — it loads the
//! whole snapshot or nothing. The cost is that any change re-encrypts
//! the entire blob, which is acceptable at vault scale (thousands of
//! items serialize to a few megabytes).
//!
//! The 96-bit nonce is freshly random per encryption. A blob is written
//! rarely (sync and unlock), so nonce collision odds are negligible with
//! a random nonce per write; a counter would need durable state and buys
//! nothing here.
//!
//! This module does not choose keys, store anything, or handle JSON —
//! it only transforms bytes.

use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use thiserror::Error;

/// GCM nonce width in bytes, as required by the spec.
pub const NONCE_LEN: usize = 12;

/// Failures from encrypting or decrypting a snapshot.
///
/// `Decrypt` does not distinguish "wrong key" from "tampered data" on
/// purpose: GCM authentication failure covers both, and callers react
/// the same way (discard the blob and re-sync).
#[derive(Debug, Error)]
pub enum EncryptionError {
    #[error("could not encrypt snapshot")]
    Encrypt,
    #[error("could not decrypt snapshot: wrong key or corrupted data")]
    Decrypt,
    #[error("nonce has {0} bytes, expected {NONCE_LEN}")]
    Nonce(usize),
}

/// Encrypt a blob under `key`, returning the fresh nonce and ciphertext.
///
/// The nonce is random per call; storing it next to the ciphertext is
/// safe and expected with GCM.
pub fn encrypt(
    plaintext: &[u8],
    key: &[u8; 32],
) -> Result<([u8; NONCE_LEN], Vec<u8>), EncryptionError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| EncryptionError::Encrypt)?;
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| EncryptionError::Encrypt)?;
    Ok((nonce, ciphertext))
}

/// Decrypt a blob; any authentication failure becomes `Decrypt`.
pub fn decrypt(
    nonce: &[u8],
    ciphertext: &[u8],
    key: &[u8; 32],
) -> Result<Vec<u8>, EncryptionError> {
    if nonce.len() != NONCE_LEN {
        return Err(EncryptionError::Nonce(nonce.len()));
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| EncryptionError::Decrypt)?;
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| EncryptionError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_a() -> [u8; 32] {
        [7u8; 32]
    }

    fn key_b() -> [u8; 32] {
        [9u8; 32]
    }

    #[test]
    fn round_trip_recovers_plaintext() {
        let plaintext = b"{\"folders\": [], \"items\": []}".to_vec();
        let (nonce, ciphertext) = encrypt(&plaintext, &key_a()).expect("encrypt");
        let recovered = decrypt(&nonce, &ciphertext, &key_a()).expect("decrypt");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let plaintext = b"secret vault".to_vec();
        let (nonce, ciphertext) = encrypt(&plaintext, &key_a()).expect("encrypt");
        let error = decrypt(&nonce, &ciphertext, &key_b()).expect_err("wrong key");
        assert!(matches!(error, EncryptionError::Decrypt));
    }

    #[test]
    fn tampered_ciphertext_fails_to_decrypt() {
        let plaintext = b"secret vault".to_vec();
        let (nonce, mut ciphertext) = encrypt(&plaintext, &key_a()).expect("encrypt");
        ciphertext[0] ^= 0xFF;
        let error = decrypt(&nonce, &ciphertext, &key_a()).expect_err("tampered");
        assert!(matches!(error, EncryptionError::Decrypt));
    }

    #[test]
    fn each_encryption_uses_a_fresh_nonce() {
        let plaintext = b"same input".to_vec();
        let (nonce1, ciphertext1) = encrypt(&plaintext, &key_a()).expect("encrypt 1");
        let (nonce2, ciphertext2) = encrypt(&plaintext, &key_a()).expect("encrypt 2");
        assert_ne!(nonce1, nonce2, "random nonce must not repeat");
        assert_ne!(ciphertext1, ciphertext2);
    }
}
