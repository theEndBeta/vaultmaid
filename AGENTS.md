# VaultMaid Agent Guidelines

## Project Context

Greenfield Rust + Iced desktop application to organize a Bitwarden vault. Target: Linux-first, bare release binary. Working directory: `/data/development/vaultmaid/main`.

**Environment**: Lima VM (Fedora 44) with Rust 1.98 via rustup, Homebrew, mise. Tools: just, jj, hyperfine. Container: `kilo.vaultmaid`.

## Core Workflow

**For each implementation step:**
1. Re-assess the plan at the start — verify nothing needs adjustment based on previous step output
2. Implement the step according to the plan
3. Write automated tests for all components where feasible
4. Verify all goals achieved and tests passing
5. Review whether any `#[allow(...)]` attributes or TODO.md items have become obsolete; triage TODO.md items (fix, defer into the plan with a pointer, or close) and integrate accepted feedback into the plan and AGENTS.md
6. **Pause and prompt for confirmation before continuing to the next step**

**Never skip verification.** Each step must pass `cargo check`, `cargo test`, `cargo fmt --check`, and `cargo clippy` (when lint config exists) before commit.

## Literate Programming Contract (MANDATORY)

Every `.rs` file must follow these rules — enforced at review and commit time:

1. **Narrative preamble** in module doc-comment before any `use`: why the file exists, key design decisions, explicit non-goals. One-sentence concern statement first. **No file opens with imports or type declarations.**

2. **Docs explain reasoning, not signatures.** Function/type docs explain WHY/tradeoffs/constraints, not WHAT the name already says.

3. **Presentation follows understanding:** high-level orchestration before helpers, domain model before mechanics.

4. **One concern per file** named in preamble; if unsayable in one sentence, split the file.

5. **Inline comments explain WHY**, never restate the next line. Example: `// nil user is valid — unauthenticated allowed` not `// check if nil`.

**Red flags — stop and rewrite:**
- File opens with `import` or type/function declaration
- Function comment could be auto-generated from signature
- Helper functions before code that calls them
- Preamble lists contents instead of naming role
- Inline comment restates next line

## Commit Discipline

- **One commit per step** from the implementation plan
- Format: `type(scope): summary` + body with Why / What / Validation
- Before each step: verify precondition against current `main` (`cargo check`, `git log --oneline`)
- After each step: `git status`/`git diff --stat` must show only that step's files
- **No broken builds merge** — repo must pass `cargo check` + `cargo test` at each commit

Example:
```
feat(config): add TOML persistence for server URL and PIN verifier

Why: login needs a durable server_url and PIN verifier without using keyring.
What: config.rs with Config {server_url, window, expanded, pin_verifier},
      load_or_default and save, ensured dir creation.
Validation: cargo check; manual rm config.toml -> restart recreates default.
```

## Tech Stack (Exact Versions)

```
iced 0.13 (tokio, advanced)
bitwarden 0.5
reqwest 0.12 json
tokio 1 (full)
serde 1 (derive), serde_json 1
keyring 3
rusqlite 0.32 (bundled)
aes-gcm 0.10
argon2 0.5
dirs 5
url 2
thiserror 1
tracing 0.1, tracing-subscriber 0.3
toml 0.8
dark-light 1
open 5

[dev-dependencies]
wiremock 0.6
```

## Architecture Decisions

**Auth**: OAuth/device-code only (no master password in app). 2FA via in-app TOTP/email modal; WebAuthn → browser fallback. Refresh token + server + user in keyring.

**Server**: Login screen Server URL field (default `https://vault.bitwarden.com`) persisted to TOML. All API calls use it.

**Scope**: Organization-only — mutate `folderId`, `collectionIds`, `organizationId`. **Never edit item fields.**

**Cache**: SQLite `~/.config/vaultmaid/cache.db`, single encrypted blob per user. Key derived from local PIN via Argon2 + AES-256-GCM. Load behind PIN, then sync.

**PIN**: Local PIN set on first launch. Argon2 verifier in config, cache key derived from PIN (not session token). Biometric hook stub for future keyring Secret Service path.

**Vault lock**: 15 min idle + manual Lock. Wipes decrypted vault from memory (zeroize via `Option::take`), shows PIN unlock. Undo entries store only IDs/ops, never decrypted fields.

**Session**: Persistent silent refresh on launch; 401 → device-code fallback.

**Sync**: Manual Sync button + auto on launch/reconnect. No interval. Status bar "Last synced X ago".

**Offline**: Read-only cache; banner + disabled mutates; no mutation queue.

**Errors**: Optimistic update → API → revert + non-blocking toast with Retry. 429 backoff, 403 permission hint.

**Bulk**: Batch move progress, sequential API calls, partial-failure "N ok, M failed" with per-item Retry.

**Undo**: In-memory last 10 bulk/single moves; success toast `[Undo]` replays reverse; cleared on re-sync/restart.

**Theming**: System light/dark via `dark-light` crate + Iced Theme.

**Config**: TOML `~/.config/vaultmaid/config.toml` (server_url, window, expanded nodes, PIN verifier). Secrets in keyring only. Corrupt TOML is backed up to `*.bak` and replaced with defaults; values that parse but break the app (unparseable server_url, zero-size window) are repaired in place so a hand-edit typo does not discard correct fields. Config never blocks startup; corruption notices surface as non-blocking toasts (Step 16).

**Platform**: Linux first, platform-agnostic code, `cargo build --release` only.

## State Machine

```
Launch -> (keyring session?) --yes--> RestoreSession --ok--> Locked (need PIN) -> PinUnlock -> Syncing -> MainView
                             \--401--> Login                                    \
                         --no--> Login -> ServerUrl -> DeviceCode -> [TwoFa] -> AuthSuccess -> SetPin(first launch only) -> Locked -> ^

MainView <-> Locked (idle 15m / manual Lock wipes VaultState)
MainView -> OfflineReadOnly (network loss, CacheLoaded) -> MainView (reconnect+sync)
Logout -> wipe keyring/cache/PIN verifier -> Login
```

## Project Structure

```
main/src/
  main.rs       # Wires config, tracing, and Iced application entry point.
  app.rs        # Owns Screen/State dispatch and iced Application impl.
  state.rs      # Defines the single source-of-truth State and sub-states.
  message.rs    # Enumerates every user and system event the app can handle.
  config.rs     # Persists non-secret user preferences as TOML on disk.
  pin.rs        # Establishes the local PIN as the cache-encryption root of trust.
  models/       # Holds the decrypted vault domain model.
    mod.rs vault.rs folder.rs collection.rs item.rs organization.rs
  api/          # Speaks to Bitwarden Cloud/Vaultwarden over SDK and REST.
    mod.rs client.rs auth.rs sync.rs folders.rs collections.rs items.rs
  cache/        # Persists an encrypted snapshot for offline read-only browsing.
    mod.rs storage.rs encryption.rs
  ui/           # Renders pure views over State; no business logic.
    mod.rs login.rs set_pin.rs unlock.rs main_view.rs tree.rs item_list.rs detail.rs components.rs
```

## Key Technical Gotchas

- **Bitwarden SDK may lack share endpoints** — verify early in Step 15, fallback to raw REST with bearer token
- **Device-code 2FA response shapes differ** between Bitwarden Cloud and Vaultwarden — test both in Step 6
- **Iced 0.13 drag-drop is manual implementation** — buttons/context menus are canonical path, drag is enhancement
- **Cache key derivation**: Argon2 with per-user salt + PIN, never use raw session token
- **Slash-split tree**: `a` and `a/b` can both be real folders, so node can be both leaf and parent — handle explicitly in tree building
- **Org share changes item IDs** (clones) — always re-sync after share, don't patch IDs locally
- **Lock must zero decrypted vault from memory** (not just hide UI) and not retain in undo history — undo entries store only IDs/ops

## Testing Strategy

- **Unit tests**: state reducers (optimistic/revert/undo/bulk partial-failure), encryption round-trip, PIN verify/derive, config ser/de, slash-split tree (including `a` + `a/b` coexistence)
- **API tests**: `wiremock` for device-code flow, folder/collection CRUD, share, 429/403 handling
- **Performance targets** (validation checkpoints, not hard requirements): sync 1k items <5s, UI responsiveness <100ms, cache load <1s

## Git Configuration

Repo-local git identity configured: `vaultmaid@local` / `VaultMaid`. Use this for all commits.

## Verification Discipline

**Per step:**
- Precondition check (verify prior steps' outputs exist)
- Post-step: `cargo check` + `cargo fmt --check` + `cargo clippy -- -D warnings` (when lint config present)
- Behavioral check listed per step in plan
- **No step merges broken builds**

**End-to-end validation** (after all steps):
- Manual: device-code + TOTP, Vaultwarden server URL, persistent session restart, sync 1k items <5s, folder CRUD with `a/b`, bulk move 12 with progress + partial-failure, collection CRUD, personal->org clone via web verification, org->org error, offline banner + read-only, restart+PIN cache load <1s, rapid ops 429 retry, Undo, selective confirms, Trash read-only, idle 15m + PIN unlock + manual lock, system theme
- Automated: `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check`

## Implementation Plan

Full implementation plan with 19 steps across 7 phases is at:
`plans/1787254773478-vaultmaid-implementation-plan.md` (relative to repo root)

**Read this file before starting any step.** It is the single source of truth.

## Planning Files

All planning documents live in `plans/` within the repository and are version-controlled alongside the implementation. This ensures:
- Plans evolve with the code and are discoverable by any agent
- Historical context is preserved in git history
- No external dependencies on ephemeral session paths

When creating new plans, use the naming convention `<timestamp>-<topic>.md` and place them in `plans/`.
