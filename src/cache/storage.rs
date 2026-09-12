//! SQLite persistence for encrypted snapshot rows.
//!
//! This file exists to own the on-disk shape of the cache: one row per
//! user holding an opaque ciphertext, its nonce, the derivation salt,
//! and a timestamp. It knows nothing about encryption or JSON, so the
//! crypto can change without touching SQL.
//!
//! The row id is a hash of the user id rather than the id itself, so the
//! cache file does not disclose who uses the machine. WAL journaling is
//! enabled because the app writes a snapshot while other reads may be in
//! flight and WAL survives an abrupt exit more gracefully than the
//! default rollback journal.
//!
//! This module does not decide when to save, what to save, or how to
//! encrypt — it only moves rows in and out of `cache.db`.

use rusqlite::{params, Connection, OptionalExtension};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Failures from the cache database.
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("could not create cache directory: {0}")]
    Io(#[from] std::io::Error),
}

/// One stored snapshot plus everything needed to attempt decryption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotRow {
    pub blob: Vec<u8>,
    pub nonce: Vec<u8>,
    pub salt: Vec<u8>,
    pub updated_at: String,
}

/// Handle to the cache database.
///
/// Not `Clone` or `Sync`: rusqlite connections are single-threaded, and
/// the app touches the cache only from the update path.
pub struct Storage {
    conn: Connection,
}

impl Storage {
    /// Open (creating if needed) the cache at `path`.
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        Self::from_connection(Connection::open(path)?)
    }

    #[cfg(test)]
    pub(crate) fn open_in_memory() -> Result<Self, StorageError> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(conn: Connection) -> Result<Self, StorageError> {
        // execute_batch is used because `journal_mode` returns a row, which
        // `pragma_update` rejects; batch discards results.
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS cache (
                 id TEXT PRIMARY KEY,
                 blob BLOB NOT NULL,
                 nonce BLOB NOT NULL,
                 salt BLOB NOT NULL,
                 updated_at TEXT NOT NULL
             );",
        )?;
        Ok(Self { conn })
    }

    /// Insert or replace the row for `id`.
    pub fn put(&self, id: &str, row: &SnapshotRow) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT INTO cache (id, blob, nonce, salt, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET
                 blob = excluded.blob,
                 nonce = excluded.nonce,
                 salt = excluded.salt,
                 updated_at = excluded.updated_at",
            params![id, row.blob, row.nonce, row.salt, row.updated_at],
        )?;
        Ok(())
    }

    /// Fetch the row for `id`, if present.
    pub fn get(&self, id: &str) -> Result<Option<SnapshotRow>, StorageError> {
        self.conn
            .query_row(
                "SELECT blob, nonce, salt, updated_at FROM cache WHERE id = ?1",
                params![id],
                |row| {
                    Ok(SnapshotRow {
                        blob: row.get(0)?,
                        nonce: row.get(1)?,
                        salt: row.get(2)?,
                        updated_at: row.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(StorageError::from)
    }

    /// Remove the row for `id`; missing rows are not an error.
    pub fn delete(&self, id: &str) -> Result<(), StorageError> {
        self.conn
            .execute("DELETE FROM cache WHERE id = ?1", params![id])?;
        Ok(())
    }
}

/// `~/.config/vaultmaid/cache.db`, mirroring the config location.
pub fn default_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("vaultmaid")
        .join("cache.db")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_row() -> SnapshotRow {
        SnapshotRow {
            blob: vec![1, 2, 3],
            nonce: vec![0; 12],
            salt: b"c2FsdA".to_vec(),
            updated_at: "1700000000".to_owned(),
        }
    }

    #[test]
    fn put_then_get_round_trips() {
        let storage = Storage::open_in_memory().expect("open");
        storage.put("user-hash", &sample_row()).expect("put");
        let loaded = storage.get("user-hash").expect("get").expect("row");
        assert_eq!(loaded, sample_row());
    }

    #[test]
    fn put_replaces_existing_row() {
        let storage = Storage::open_in_memory().expect("open");
        storage.put("user-hash", &sample_row()).expect("put");
        let mut updated = sample_row();
        updated.blob = vec![9, 9, 9];
        updated.updated_at = "1700000099".to_owned();
        storage.put("user-hash", &updated).expect("put again");

        let loaded = storage.get("user-hash").expect("get").expect("row");
        assert_eq!(loaded, updated);
    }

    #[test]
    fn get_missing_returns_none() {
        let storage = Storage::open_in_memory().expect("open");
        assert!(storage.get("absent").expect("get").is_none());
    }

    #[test]
    fn delete_removes_row_and_is_idempotent() {
        let storage = Storage::open_in_memory().expect("open");
        storage.put("user-hash", &sample_row()).expect("put");
        storage.delete("user-hash").expect("delete");
        assert!(storage.get("user-hash").expect("get").is_none());
        storage.delete("user-hash").expect("delete again");
    }
}
