//! Encrypted, per-user vault snapshot cache.
//!
//! This module is the cache's public surface: open the database, save or
//! load one user's snapshot, and drop it on logout. It ties the SQL row
//! store (`storage`) to the AES-256-GCM blob encryption (`encryption`)
//! and owns the one decision they cannot make on their own — what counts
//! as a usable snapshot.
//!
//! A snapshot is treated as disposable. If decryption fails the entry is
//! deleted and `Ok(None)` is returned, because a cache that cannot be
//! read is worth less than the sync that will replace it; the alternative
//! (surfacing a crypto error) would strand a user behind a corrupt file
//! that the app can simply rebuild. Wrong-key and tampering are
//! indistinguishable at this layer and are handled identically.
//!
//! The row id is a hash of the user id so the file does not name its
//! owner, and ciphertext is keyed to the AES key derived from the local
//! PIN — the server never sees either.
//!
//! This module does not parse the vault JSON, decide when to sync, or
//! zero memory on lock; those belong to the sync and lock paths.

pub mod encryption;
pub mod storage;

use crate::pin::CacheKey;
use base64::Engine;
use sha2::{Digest, Sha256};
use std::path::Path;
use storage::{SnapshotRow, Storage, StorageError};
use thiserror::Error;

/// Failures from the cache subsystem.
#[derive(Debug, Error)]
pub enum CacheError {
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("encryption error: {0}")]
    Encryption(#[from] encryption::EncryptionError),
    #[error("cached snapshot is not valid UTF-8")]
    InvalidSnapshot(#[from] std::string::FromUtf8Error),
}

/// Owner of the cache database.
pub struct Cache {
    storage: Storage,
}

impl Cache {
    /// Open the cache at the standard config-dir location.
    pub fn open_default() -> Result<Self, CacheError> {
        Self::open(&storage::default_path())
    }

    /// Open a cache at an explicit path; used by tests and future CLI tools.
    pub fn open(path: &Path) -> Result<Self, CacheError> {
        Ok(Self {
            storage: Storage::open(path)?,
        })
    }

    #[cfg(test)]
    fn open_in_memory() -> Result<Self, CacheError> {
        Ok(Self {
            storage: Storage::open_in_memory()?,
        })
    }

    /// Encrypt and store `json` as this user's snapshot.
    ///
    /// The salt is persisted with the ciphertext so the derivation inputs
    /// are recoverable; the key itself is never written.
    #[allow(dead_code)] // called by Step 8 sync once there is a vault to persist
    pub fn save_vault(&self, user_id: &str, key: &CacheKey, json: &str) -> Result<(), CacheError> {
        let (nonce, ciphertext) = encryption::encrypt(json.as_bytes(), &key.key)?;
        let row = SnapshotRow {
            blob: ciphertext,
            nonce: nonce.to_vec(),
            salt: key.salt.clone(),
            updated_at: now_epoch_secs(),
        };
        self.storage.put(&cache_id(user_id), &row)?;
        Ok(())
    }

    /// Decrypt this user's snapshot, or `None` if absent or unreadable.
    ///
    /// An unreadable row is deleted so the next sync starts clean.
    pub fn load_vault(&self, user_id: &str, key: &CacheKey) -> Result<Option<String>, CacheError> {
        let id = cache_id(user_id);
        let Some(row) = self.storage.get(&id)? else {
            return Ok(None);
        };

        match encryption::decrypt(&row.nonce, &row.blob, &key.key) {
            Ok(bytes) => Ok(Some(String::from_utf8(bytes)?)),
            Err(error) => {
                tracing::warn!(%error, "discarding unreadable cache entry");
                self.storage.delete(&id)?;
                Ok(None)
            }
        }
    }

    /// Forget this user's snapshot, e.g. on logout or PIN reset.
    pub fn discard(&self, user_id: &str) -> Result<(), CacheError> {
        self.storage.delete(&cache_id(user_id))?;
        Ok(())
    }
}

/// Stable, non-secret row key for `user_id`.
///
/// SHA-256 of the user id, base64url encoded: stable across runs so the
/// same user maps to the same row, and opaque so the file does not leak
/// the account identity.
fn cache_id(user_id: &str) -> String {
    let digest = Sha256::digest(user_id.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

/// Seconds since the Unix epoch, as a string column.
///
/// Epoch seconds rather than a formatted date: no timezone library is
/// needed, it sorts lexicographically for the same digit count, and the
/// UI formats relative time ("synced 3m ago") from the number anyway.
fn now_epoch_secs() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs().to_string(),
        Err(_) => "0".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> CacheKey {
        CacheKey {
            key: [byte; 32],
            salt: b"c2FsdA".to_vec(),
        }
    }

    #[test]
    fn cache_id_is_stable_and_opaque() {
        let a = cache_id("user-42");
        assert_eq!(a, cache_id("user-42"));
        assert_ne!(a, cache_id("user-43"));
        assert!(!a.contains("user-42"));
    }

    #[test]
    fn save_then_load_round_trips() {
        let cache = Cache::open_in_memory().expect("open");
        let json = r#"{"folders":[{"id":"f1","name":"Finance"}]}"#;
        cache.save_vault("user-42", &key(1), json).expect("save");

        let loaded = cache.load_vault("user-42", &key(1)).expect("load");
        assert_eq!(loaded.as_deref(), Some(json));
    }

    #[test]
    fn load_missing_returns_none() {
        let cache = Cache::open_in_memory().expect("open");
        assert!(cache.load_vault("nobody", &key(1)).expect("load").is_none());
    }

    #[test]
    fn users_do_not_collide() {
        let cache = Cache::open_in_memory().expect("open");
        cache
            .save_vault("user-a", &key(1), "{\"a\":1}")
            .expect("save a");
        cache
            .save_vault("user-b", &key(2), "{\"b\":2}")
            .expect("save b");

        assert_eq!(
            cache
                .load_vault("user-a", &key(1))
                .expect("load a")
                .as_deref(),
            Some("{\"a\":1}")
        );
        assert_eq!(
            cache
                .load_vault("user-b", &key(2))
                .expect("load b")
                .as_deref(),
            Some("{\"b\":2}")
        );
    }

    #[test]
    fn wrong_key_discards_entry_and_returns_none() {
        let cache = Cache::open_in_memory().expect("open");
        cache
            .save_vault("user-42", &key(1), "{\"secret\":true}")
            .expect("save");

        let loaded = cache
            .load_vault("user-42", &key(2))
            .expect("load wrong key");
        assert!(loaded.is_none(), "wrong key must not decrypt");

        // The unreadable row was deleted, so the correct key now finds nothing.
        assert!(cache
            .load_vault("user-42", &key(1))
            .expect("load after discard")
            .is_none());
    }

    #[test]
    fn discard_removes_snapshot() {
        let cache = Cache::open_in_memory().expect("open");
        cache
            .save_vault("user-42", &key(1), "{\"x\":1}")
            .expect("save");
        cache.discard("user-42").expect("discard");
        assert!(cache
            .load_vault("user-42", &key(1))
            .expect("load")
            .is_none());
    }
}
