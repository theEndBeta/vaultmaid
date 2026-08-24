//! Persists non-secret user preferences as TOML on disk.
//!
//! VaultMaid needs a durable home for values that are not credentials —
//! server URL, window geometry, which tree nodes are expanded, and the PIN
//! verifier string. Those belong on disk so a restart can reconstruct the
//! last session without prompting. Secrets (refresh tokens) stay in the
//! OS keyring; this file never writes them.
//!
//! TOML is the persistence format because it is the language of Rust
//! tooling, stays readable when a human opens the file to fix a URL, and
//! needs no extra runtime beyond `serde`. JSON would work but invites
//! accidental nesting and is harder to edit by hand. SQLite is reserved
//! for the encrypted vault cache: mixing preferences into that blob would
//! couple UI chrome to the PIN-derived key and make a corrupt cache wipe
//! the server URL.
//!
//! This module does not size or position the Iced window, hash PINs, or
//! talk to the network. It only serializes what later steps ask it to
//! remember. Callers that need a custom path (tests) go through
//! `load_from` / `save_to` so production code can keep using the XDG
//! location without tests mutating a real home directory.

use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Bitwarden Cloud is the only URL a first-run user can be expected to
/// recognize. Self-hosted and Vaultwarden users replace it on the login
/// screen; that edit is what `ServerUrlChanged` persists.
pub const DEFAULT_SERVER_URL: &str = "https://vault.bitwarden.com";

const APP_DIR: &str = "vaultmaid";
const FILE_NAME: &str = "config.toml";

/// Non-secret preferences that survive a process restart.
///
/// `pin_verifier` is an opaque Argon2 string, not the PIN. Storing the
/// verifier here (rather than in the keyring) keeps unlock possible when
/// the keyring is locked or unavailable, and keeps the keyring reserved
/// for tokens that grant network access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub server_url: String,
    pub window: WindowState,
    pub expanded_nodes: Vec<String>,
    pub pin_verifier: Option<String>,
}

/// Last-known window size only.
///
/// Position is omitted: multi-monitor layouts make a restored origin more
/// surprising than a default placement, and Iced 0.13 does not give us a
/// reliable way to query the current monitor's work area at save time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowState {
    pub width: u32,
    pub height: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_url: DEFAULT_SERVER_URL.to_owned(),
            window: WindowState::default(),
            expanded_nodes: Vec::new(),
            pin_verifier: None,
        }
    }
}

impl Default for WindowState {
    fn default() -> Self {
        Self {
            width: 1200,
            height: 800,
        }
    }
}

impl Config {
    /// Load from the XDG config path, or materialize a default file.
    ///
    /// Missing and corrupt files both become `Config::default()` so the
    /// app can always start. Corrupt content is renamed aside first —
    /// overwriting it would destroy the only clue a human has when the
    /// file was hand-edited badly.
    pub fn load_or_default() -> Self {
        Self::load_from(&Self::path())
    }

    /// Persist to the XDG config path, creating the directory if needed.
    pub fn save(&self) -> Result<(), ConfigError> {
        self.save_to(&Self::path())
    }

    /// Same policy as `load_or_default`, but the caller chooses the file.
    ///
    /// Tests pass a temp path so a failing assertion cannot leave a
    /// half-written file in `~/.config/vaultmaid`.
    pub fn load_from(path: &Path) -> Self {
        if !path.exists() {
            let config = Self::default();
            if let Err(error) = config.save_to(path) {
                tracing::warn!(%error, path = %path.display(), "could not create default config");
            }
            return config;
        }

        match fs::read_to_string(path) {
            Ok(raw) => match toml::from_str(&raw) {
                Ok(config) => config,
                Err(error) => {
                    tracing::warn!(
                        %error,
                        path = %path.display(),
                        "config is not valid TOML; backing up and replacing with defaults"
                    );
                    backup_corrupt(path);
                    let config = Self::default();
                    if let Err(save_error) = config.save_to(path) {
                        tracing::warn!(%save_error, "could not write replacement config");
                    }
                    config
                }
            },
            Err(error) => {
                tracing::warn!(
                    %error,
                    path = %path.display(),
                    "config unreadable; using defaults without replacing the file"
                );
                // Leave the existing file alone: a permission error is not
                // corruption, and replacing it would make the situation worse.
                Self::default()
            }
        }
    }

    /// Write pretty TOML so a user can edit the server URL by hand.
    pub fn save_to(&self, path: &Path) -> Result<(), ConfigError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let rendered = toml::to_string_pretty(self)?;
        fs::write(path, rendered)?;
        Ok(())
    }

    /// XDG config dir plus `vaultmaid/config.toml`.
    ///
    /// `dirs::config_dir` already encodes the platform convention
    /// (`~/.config` on Linux). Falling back to the current directory is a
    /// last resort for environments with no home; it keeps tests and
    /// unusual hosts from panicking at startup.
    pub fn path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(APP_DIR)
            .join(FILE_NAME)
    }
}

/// Failures that prevent a successful write.
///
/// Load never surfaces these: a preference file must not be able to stop
/// the process. Save does, because the caller just mutated state and
/// needs to know the disk copy lagged.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("could not write config: {0}")]
    Io(#[from] io::Error),
    #[error("could not serialize config: {0}")]
    Serialize(#[from] toml::ser::Error),
}

fn backup_corrupt(path: &Path) {
    let backup = corrupt_backup_path(path);
    match fs::rename(path, &backup) {
        Ok(()) => {
            tracing::info!(backup = %backup.display(), "moved corrupt config aside");
        }
        Err(error) => {
            tracing::warn!(
                %error,
                backup = %backup.display(),
                "could not move corrupt config; replacement will overwrite it"
            );
        }
    }
}

fn corrupt_backup_path(path: &Path) -> PathBuf {
    let mut backup = path.as_os_str().to_os_string();
    backup.push(".bak");
    PathBuf::from(backup)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_DIR_SEQ: AtomicU64 = AtomicU64::new(0);

    fn isolated_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "vaultmaid-config-{}-{}-{}",
            std::process::id(),
            TEST_DIR_SEQ.fetch_add(1, Ordering::Relaxed),
            name
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("temp config dir");
        dir.join(FILE_NAME)
    }

    fn cleanup(path: &Path) {
        if let Some(parent) = path.parent() {
            let _ = fs::remove_dir_all(parent);
        }
    }

    #[test]
    fn default_uses_bitwarden_cloud() {
        let config = Config::default();
        assert_eq!(config.server_url, DEFAULT_SERVER_URL);
        assert!(config.pin_verifier.is_none());
        assert!(config.expanded_nodes.is_empty());
    }

    #[test]
    fn toml_round_trip_preserves_all_fields() {
        let original = Config {
            server_url: "https://vault.example.test".to_owned(),
            window: WindowState {
                width: 1600,
                height: 900,
            },
            expanded_nodes: vec!["Finance".into(), "Finance/Banks".into()],
            pin_verifier: Some("$argon2id$v=19$test".into()),
        };

        let encoded = toml::to_string(&original).expect("serialize");
        let decoded: Config = toml::from_str(&encoded).expect("deserialize");
        assert_eq!(decoded, original);
    }

    #[test]
    fn missing_file_is_created_with_defaults() {
        let path = isolated_path("missing");
        let loaded = Config::load_from(&path);
        assert_eq!(loaded, Config::default());
        assert!(path.exists(), "load_from should recreate a deleted config");
        let on_disk: Config =
            toml::from_str(&fs::read_to_string(&path).unwrap()).expect("written toml");
        assert_eq!(on_disk, Config::default());
        cleanup(&path);
    }

    #[test]
    fn save_then_load_preserves_fields() {
        let path = isolated_path("roundtrip");
        let original = Config {
            server_url: "https://vw.example.test".to_owned(),
            window: WindowState {
                width: 800,
                height: 600,
            },
            expanded_nodes: vec!["Work".into()],
            pin_verifier: None,
        };
        original.save_to(&path).expect("save");
        let loaded = Config::load_from(&path);
        assert_eq!(loaded, original);
        cleanup(&path);
    }

    #[test]
    fn corrupt_toml_is_backed_up_and_replaced() {
        let path = isolated_path("corrupt");
        fs::write(&path, "this is { not toml").expect("write garbage");
        let loaded = Config::load_from(&path);
        assert_eq!(loaded, Config::default());

        let backup = corrupt_backup_path(&path);
        assert!(backup.exists(), "original bytes should be renamed aside");
        let leftover = fs::read_to_string(&backup).unwrap();
        assert!(leftover.contains("not toml"));

        let replacement: Config =
            toml::from_str(&fs::read_to_string(&path).unwrap()).expect("replacement toml");
        assert_eq!(replacement, Config::default());
        cleanup(&path);
    }
}
