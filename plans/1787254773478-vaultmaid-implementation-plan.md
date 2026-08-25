# VaultMaid Implementation Plan

## Context
Greenfield Rust + Iced desktop app to organize a Bitwarden vault. Target ` /data/development/vaultmaid` is empty aside from `.justfile`/`.lima.yml`; Rust toolchain via Lima VM (Fedora 44). Goal: create/manage folders & collections, add/remove items from collections/folders, move between folders and orgs. Linux-first, bare release binary.

## Decisions Locked
- **Backend:** `bitwarden` Rust SDK for auth/sync/decrypt + `reqwest` REST to `{{server}}/api` for collection/org admin gaps.
- **Auth:** OAuth/device-code only (no master password in app). `2fa_required` -> in-app TOTP/email modal; WebAuthn/unsupported -> browser fallback. Refresh token + server + user in `keyring`.
- **Server:** Login screen Server URL field (`https://vault.bitwarden.com` default) persisted to TOML; all calls use it.
- **Scope:** Organization-only: mutate `folderId`, `collectionIds`, `organizationId`. Never edit item fields.
- **UX:** Three-pane (left slash-split tree `Finance/Banks` -> Finance > Banks + Trash + orgs->collections, center filtered item list with debounced search 150ms + type/org filters + multi-select Ctrl/Cmd+Shift, right detail/actions). Drag-drop + context menu + shortcuts.
- **Org moves:** Detect direction. `personal->org` / `org->personal` -> confirm then `POST /ciphers/{id}/share` (clone+delete fallback). `org->org` forbidden -> error modal with manual steps.
- **Errors:** Optimistic update -> API -> revert + non-blocking toast with Retry. 429 backoff, 403 permission hint.
- **Bulk:** Batch move progress, sequential API calls, partial-failure "N ok, M failed" with per-item Retry.
- **Offline:** Read-only cache; banner + disabled mutates; no mutation queue.
- **Cache:** SQLite `~/.config/vaultmaid/cache.db` single encrypted blob per user. Key derived from local PIN via Argon2 + AES-256-GCM. Load behind PIN, then sync.
- **Session:** Persistent silent refresh on launch; 401 -> device-code fallback.
- **Vault lock:** 15 min idle + manual Lock; wipes decrypted vault, shows PIN unlock. First launch requires setting local PIN (Argon2 verifier in config, key derived from PIN). Biometric where OS supports.
- **Sync trigger:** Manual Sync button + auto on launch/reconnect. No interval. Status bar "Last synced X ago".
- **Trash:** Read-only Trash node; no restore.
- **Confirmations:** Selective (deletes, org share/clone, remove-from-collection). Folder moves no confirm (undo).
- **Undo:** In-memory last 10 bulk/single moves; success toast `[Undo]` replays reverse; cleared on re-sync/restart.
- **Theming:** System light/dark via Iced Theme.
- **Config:** TOML `~/.config/vaultmaid/config.toml` (server_url, window, expanded nodes, PIN verifier). Secrets in keyring only.
- **Platform/packaging:** Linux first, platform-agnostic code, `cargo build --release` only.

## Literate-Programming Contract (applies to every source file)
Every file is writing for the next reader. Enforced at review and commit time.
1. **Preamble** in top module doc-comment before any `use`: why the file exists, key design decisions that shaped it, explicit non-goals. One-sentence concern statement first. No file opens with imports.
2. **Docs explain reasoning, not signatures.** Function/type docs explain WHY/the tradeoff/constraint, not WHAT the name already says.
3. **Presentation follows understanding:** high-level orchestration before helpers, domain model before mechanics. Forward refs are acceptable for readability.
4. **One concern per file** named in preamble; if unsayable in one sentence, split the file.
5. **Inline comments explain WHY**, never restate the next line. Vale: `// nil user is valid — unauthenticated allowed` not `// check if nil`.

## Commit Discipline
- One commit per Step below; repo must pass `cargo check` (and `cargo test` when tests exist) at each commit.
- Commit message format: `type(scope): summary` + body with Why / What / Validation. Example:
  ```
  feat(config): add TOML persistence for server URL and PIN verifier

  Why: login needs a durable server_url and PIN verifier without using keyring.
  What: config.rs with Config {server_url, window, expanded, pin_verifier},
        load_or_default and save, ensured dir creation.
  Validation: cargo check; manual rm config.toml -> restart recreates default.
  ```
- Before each Step, verify Precondition against current `main` (list files, `cargo check`, `git log --oneline`); if precondition fails, fix before proceeding. After each Step, `git status`/`git diff --stat` must show only Step's files.

## Verification Discipline (per Step)
Precondition check + post-Step `cargo check` (+ `cargo fmt --check`, `cargo clippy` when lint config present) + behavioral check listed per Step. No Step merges broken builds.

## Stack
`iced 0.13 (tokio, advanced)`, `bitwarden 0.5`, `reqwest 0.12 json`, `tokio full`, `serde/serde_json`, `keyring 3`, `rusqlite 0.32 bundled`, `aes-gcm 0.10`, `argon2 0.5`, `dirs 5`, `url 2`, `thiserror`, `tracing`/`tracing-subscriber`, `toml 0.8`, `wiremock` (dev).

## State Machine
```
Launch -> (keyring session?) --yes--> RestoreSession --ok--> Locked (need PIN) -> PinUnlock -> Syncing -> MainView
                             \--401--> Login                                    \
                         --no--> Login -> ServerUrl -> DeviceCode -> [TwoFa] -> AuthSuccess -> SetPin(first launch only) -> Locked -> ^

MainView <-> Locked (idle 15m / manual Lock wipes VaultState) ; MainView -> OfflineReadOnly (network loss, CacheLoaded) -> MainView (reconnect+sync)
Logout -> wipe keyring/cache/PIN verifier -> Login
```

## Project Structure (one-sentence concern per file)
```
main/Cargo.toml
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

## Implementation Phases — Steps with Sub-Steps and Commits

### Phase 1 — Foundation

#### Step 1 — Project bootstrap
Precondition: `main/` has only `.justfile`/`.lima.yml`, no `Cargo.toml`, `git log` empty.
- 1a. Plan: `cargo init --bin --name vaultmaid` in `main/`; verify `.gitignore` ignores `/target` and `cache.db`.
- 1b. Plan: Fill `Cargo.toml` with Stack deps (exact versions), `edition = "2021"`, `[profile]`, add `wiremock` under `[dev-dependencies]`.
- 1c. Plan: `rustfmt.toml` + `clippy.toml` + `tracing_subscriber::fmt::init()` placeholder in `main.rs` with literate preamble (why tracing, not what).
- Validation: `cargo check` passes; `cargo fmt --check` passes.
- Commit: `chore(bootstrap): initialize Cargo project with literate preamble`

#### Step 2 — Iced application skeleton
Precondition: Step 1 committed; `cargo check` green.
- 2a. Plan: `message.rs` with minimal `Screen` enum (`Login|DeviceCode|TwoFa|SetPin|Unlock|Main`) and `Message::Noop` — preamble states navigation concern.
- 2b. Plan: `state.rs` with `State { screen, toasts }` and sub-state stubs; docs explain why State is flat not nested.
- 2c. Plan: `app.rs` implements `iced::Application` (or `iced::application` per 0.13 API) returning empty centered text per screen; `main.rs` launches it; system Theme detection branch.
- Validation: `cargo run` opens window switching screens via temporary key; `cargo check` green.
- Commit: `feat(app): add Iced skeleton with Screen navigation and system theme`

#### Step 3 — Non-secret config persistence
Precondition: Skeleton renders; no config file yet.
- 3a. Plan: `config.rs` defines `Config { server_url, window, expanded_nodes, pin_verifier }` with `Default` (`https://vault.bitwarden.com`); preamble states TOML choice over JSON/SQLite.
- 3b. Plan: Implement `load_or_default()` and `save()` via `dirs::config_dir()/vaultmaid/config.toml`, ensure dir creation; handle corrupt TOML -> backup + default. Values that parse but break the app (unparseable `server_url`, zero-size `window`) are repaired in place and the file rewritten, so a hand-edit typo does not discard fields the user got right.
- 3c. Plan: Wire `Config::load_or_default()` into `app.rs` init and persist on `ServerUrlChanged`; unit test for ser/de round-trip.
- Validation: `cargo test config` passes; deleting config recreates default.
- Commit: `feat(config): persist server URL and window state as TOML`

#### Step 4 — Local PIN as trust root
Precondition: Config persists; no PIN verifier yet.
- 4a. Plan: `pin.rs` defines `PinError`, `hash_pin(pin)->String` via Argon2 with random salt, `verify(pin, verifier)->bool`; preamble says why PIN is cache key not auth.
- 4b. Plan: Key derivation `derive_cache_key(pin, salt)->[u8;32]` (Argon2id, stable per-user salt stored alongside verifier); document why not raw token.
- 4c. Plan: `ui/set_pin.rs` first-launch form (pin + confirm + strength hint) emitting `PinSet`; `ui/unlock.rs` PIN entry with error feedback; `pin.rs` biometric hook stub behind `cfg` with doc explaining future `keyring` Secret Service path.
- Validation: `cargo test pin::tests` hash/verify and key determinism; UI screens render.
- Commit: `feat(pin): add local PIN setup/verify and cache-key derivation`

#### Step 5 — HTTP client wrapper
Precondition: Config and PIN modules committed; no network code.
- 5a. Plan: `api/client.rs` struct `Client { server_url: Url, token: Option<String>, http: reqwest::Client }`; preamble says why wrapper isolates base-url and auth header.
- 5b. Plan: Methods `with_token`, `auth_header`, `url(path)` joining `{{server}}/api` or `/identity`; unit test for URL joining with trailing slash variants.
- 5c. Plan: Error type `ApiError` (`thiserror`) mapping 401/403/429/5xx to variants with user message; docs explain retry semantics per variant.
- Validation: `cargo test api::client` URL tests; `cargo check` green.
- Commit: `feat(api): add HTTP client wrapper with URL and error mapping`

#### Step 6 — Device-code auth + persistent session
Precondition: Client wrapper exists; no auth flow.
- 6a. Plan: `api/auth.rs` `start_device_code(client)` -> POST `{{server}}/identity/connect/token` with `grant_type=device_code`; parse `device_code, user_code, verification_uri, interval`.
- 6b. Plan: `poll_device_code(client, device_code)` loop with interval, mapping `authorization_pending`/`slow_down`/`2fa_required`/`expired_token`; store `refresh_token` in `keyring` (`vaultmaid:refresh:{user_id}`).
- 6c. Plan: In-app TOTP/email prompt flow (emit `TwoFACodeSubmitted` -> retry poll with `two_factor_token`); WebAuthn fallback opens `verification_uri` via `open` crate; `silent_refresh()` on launch and logout wipe; `ui/login.rs` wired to show `user_code` + link + polling spinner.
- Validation: `wiremock` tests for device-code start/poll/2fa/refresh/401 fallback; manual against Vaultwarden optional.
- Commit: `feat(auth): implement device-code flow with 2FA and keyring session`

#### Step 7 — Encrypted SQLite cache
Precondition: Auth stores refresh token; no cache yet.
- 7a. Plan: `cache/encryption.rs` `encrypt(blob, key)->(nonce,ciphertext)` and `decrypt` via AES-256-GCM with random 96-bit nonce; preamble states blob-level encryption tradeoff.
- 7b. Plan: `cache/storage.rs` init SQLite at `cache.db`, table `cache(id TEXT PK, blob BLOB, nonce BLOB, salt BLOB, updated_at TEXT)`; per-user `id = hash(user_id)`; ensure `PRAGMA journal_mode=WAL`.
- 7c. Plan: `cache/mod.rs` `save_vault(user_id, pin_key, json)` and `load_vault(user_id, pin_key)->Option<json>` using encryption; test round-trip; app loads cache behind PIN before sync.
- Validation: `cargo test cache::` encrypt/decrypt + storage round-trip; corrupt blob handled.
- Commit: `feat(cache): add encrypted SQLite vault snapshot`

### Phase 2 — Sync + Shell UI

#### Step 8 — Vault sync and domain model
Precondition: Cache ready; no vault model.
- 8a. Plan: `models/*` define `VaultData { folders, collections, items, orgs }` with `serde` and `Folder {id,name}` etc.; preamble per file states invariant (e.g. folder names slash-delimited).
- 8b. Plan: `api/sync.rs` calls SDK `sync` with bearer token + server_url, decrypts, maps to `models`; emits `VaultSynced`; errors to `VaultSyncError` with 429/403 mapping.
- 8c. Plan: On `VaultSynced`, serialize vault JSON, encrypt with PIN key, upsert to SQLite; update `Last synced` timestamp in State.
- Validation: `wiremock` sync test; manual sync with real account decrypts and persists; `cargo check` green.
- Commit: `feat(sync): sync and decrypt vault into domain model with cache persist`

#### Step 9 — Three-pane shell and selection
Precondition: Sync populates VaultState; UI is still skeleton.
- 9a. Plan: `ui/components.rs` toast stack, modal, banner, progress bar, `Toast {id, message, kind, retry}` with preamble stating pure-view concern.
- 9b. Plan: `ui/tree.rs` slash-split `build_tree(names)` -> `TreeNode { name, children, id? }`; handles `a` and `a/b` coexisting (node is both leaf and parent); renders My Vault folders + Trash (read-only) + orgs->collections, dimmed when empty.
- 9c. Plan: `ui/item_list.rs` center list with debounced search (150ms via `subscription`), type/org dropdown filters, row checkboxes; `ui/detail.rs` shows selected item(s) count and read-only fields; `ui/main_view.rs` composes panes + status bar with Last-synced + Sync button.
- 9d. Plan: Wire selection messages `SelectFolder/SelectCollection/SelectTrash/ToggleItemSelection/RangeSelect` with Shift-range logic over filtered list; state reducer tests.
- Validation: slash-split tests; selection reducer tests; manual browse 1k items <5s target.
- Commit: `feat(ui): compose three-pane shell with slash-split tree and filtered list`

#### Step 10 — Lock screen and idle handling
Precondition: MainView renders decrypted vault.
- 10a. Plan: `app.rs` idle subscription tracking last `Message` timestamp; emit `VaultLocked` after 15 min; preamble explains why idle is subscription not polling.
- 10b. Plan: On `VaultLocked` or `LockRequested`, drop `VaultState` from memory (zeroize via `Option::take`), navigate to `Screen::Unlock`; manual Lock button in toolbar/menu.
- 10c. Plan: `ui/unlock.rs` PIN entry decrypts cache via `cache::load_vault`; on success re-hydrates in-memory VaultState and re-syncs; failed PIN shows error, no token exposure.
- Validation: idle reducer test; manual idle -> lock wipes vault (verify via debug log, not retained in undo).
- Commit: `feat(lock): add idle auto-lock and PIN unlock wiping decrypted vault`

### Phase 3 — Folders

#### Step 11 — Folder API with optimistic update
Precondition: Vault browsable; no folder mutations.
- 11a. Plan: `api/folders.rs` `create(name)->Folder`, `rename(id,name)`, `delete(id)` via `Client` + REST; each returns `Result`; preamble states idempotency expectation.
- 11b. Plan: `app.rs` reducers `CreateFolder/RenameFolder/DeleteFolder`: optimistic `State` patch + stash `UndoEntry::FolderCreate(id)` before `Command::perform`; on `FolderCreated` reconcile id; on `ApiError` revert + toast with Retry.
- 11c. Plan: Handle slash names server-side as opaque strings; tree rebuild after success reconciles `a/b` parent creation.
- Validation: `wiremock` folder CRUD + revert test; `cargo test state::folder_reducer`.
- Commit: `feat(folders): implement folder CRUD with optimistic update and revert`

#### Step 12 — Folder UI interactions
Precondition: Folder API wired; UI has no create/rename/delete or move.
- 12a. Plan: `ui/tree.rs` context menu (right-click) + toolbar "New Folder" + inline rename (F2) + Delete with selective confirm modal for delete only.
- 12b. Plan: Move selected items to folder via context-menu "Move to folder..." and drag-drop (Iced `advanced` drag source/target; buttons remain fallback); message `MoveItemsToFolder(ids, folder_id)` with optimistic `folderId` patch per item.
- 12c. Plan: Empty-folder placeholder "No items in this folder" + dimmed empty nodes; keyboard Delete on selected folder with confirm.
- Validation: Manual folder create/rename/delete + item move single + bulk via both paths; revert on forced 500.
- Commit: `feat(folders-ui): add folder tree actions and item-to-folder moves`

### Phase 4 — Collections

#### Step 13 — Collection and membership API
Precondition: Folder moves work; no collection mutations.
- 13a. Plan: `api/collections.rs` org-scoped `POST/PUT/DELETE /api/collections` with `organizationId` validation; errors map 403 permission hint.
- 13b. Plan: `api/items.rs` `update_collections(itemId, collectionIds)` via `PUT /api/ciphers/{id}`; for share use `POST /ciphers/{id}/share`; preamble explains why collectionIds is full-replace not delta.
- 13c. Plan: Reducers `CreateCollection/RenameCollection/DeleteCollection/AddItemsToCollection/RemoveItemsFromCollection` optimistic + revert, with selective confirm on remove.
- Validation: `wiremock` collection CRUD + membership update + 403 toast mapping.
- Commit: `feat(collections): implement collection CRUD and membership updates`

#### Step 14 — Collection UI
Precondition: Collection API wired; tree shows collections read-only.
- 14a. Plan: `ui/tree.rs` "New Collection" under org node, inline rename/delete (confirm on delete); dimmed empty collections.
- 14b. Plan: `ui/detail.rs` collection checkboxes for selected items (single + bulk counts), "Add to collection" picker; removing shows selective confirm modal.
- 14c. Plan: Wire `AddItemsToCollection/RemoveItemsFromCollection` through bulk path with progress (reused component).
- Validation: Manual collection create under org, add/remove 1 and N items, confirm modal appears only on remove.
- Commit: `feat(collections-ui): add collection actions and detail-pane membership`

### Phase 5 — Cross-Organization Moves

#### Step 15 — Org move orchestration
Precondition: Collections work within org; no cross-org logic.
- 15a. Plan: `api/items.rs` `share_item(itemId, orgId, collectionIds)` -> `POST /ciphers/{id}/share`; fallback clone+delete path documented; preamble states ID changes after share.
- 15b. Plan: `app.rs` direction detector `personal->org` / `org->personal` / `org->org` based on `item.organizationId`; `MoveItemsToOrg(ids, orgId)` shows confirm modal "This will copy N items into Org X" before any network.
- 15c. Plan: Sequential per-item share with progress bar; on success push reverse `UndoEntry::Share` and trigger `SyncRequested` to reconcile new IDs; `org->org` shows error modal with manual steps link.
- Validation: `wiremock` share sequence + partial failure + 403; manual personal->org clone verified via web vault.
- Commit: `feat(org-move): add cross-organization share with direction detection`

### Phase 6 — Errors, Undo, Offline

#### Step 16 — Toasts, modals, progress, and undo
Precondition: Org moves work but no unified error UI or undo.
- 16a. Plan: `ui/components.rs` finalize toast stack (auto-dismiss 5s, Retry/Undo buttons), modal, offline banner; docs explain non-blocking requirement. This is also where `config.toml` corruption reaches the user: a "config restored from backup" toast after startup, since the file itself must never block launch.
- 16b. Plan: `state.rs` `UndoEntry { op, reverse }` stack capped at 10; on success toast include `[Undo]`; `Undo(id)` replays reverse ops optimistically with same revert path; cleared on re-sync/restart and not retaining decrypted fields.
- 16c. Plan: Wire `Retry(id)` replaying stored `Operation` with exponential backoff for 429 (toast shows "Retrying in Ns").
- Validation: `cargo test state::undo` cap and replay; manual Retry and Undo from toast.
- Commit: `feat(feedback): add toast/modal/undo/retry with backoff`

#### Step 17 — Offline read-only and reconnect sync
Precondition: Feedback UI exists; app still assumes online.
- 17a. Plan: `app.rs` network subscription (periodic lightweight `GET /api/accounts/profile` or OS network check) emitting `NetworkChanged(bool)`.
- 17b. Plan: On `NetworkChanged(false)` disable all mutate `Command`s, show banner "Offline — reconnect to organize", load `CacheLoaded` from SQLite if memory empty; on `true` re-enable + auto `SyncRequested`.
- 17c. Plan: Ensure offline path never writes cache; ensure encrypted cache load requires PIN even offline.
- Validation: Toggle network off -> banner + disabled buttons; manual Sync while offline shows offline toast; reconnect triggers sync.
- Commit: `feat(offline): add read-only offline mode with reconnect sync`

### Phase 7 — Polish & Tests

#### Step 18 — Drag-drop polish and shortcuts
Precondition: Core flows work via buttons/menus; drag-drop is minimal.
- 18a. Plan: `ui/tree.rs` + `ui/item_list.rs` visual drag feedback (highlight drop target, ghost row), fallback to buttons preserved per Risk; preamble notes Iced 0.13 manual impl.
- 18b. Plan: Context menus finished (right-click item/folder/collection), keyboard: F2 rename, Delete remove, Ctrl+Z undo, Ctrl+A select all, Ctrl+F focus search; shortcuts listed in detail pane tooltip.
- 18c. Plan: Empty states and dimming pass; ensure trash node never offers move/drop.
- Validation: Manual drag-drop + all shortcuts; no regression on fallback buttons.
- Commit: `feat(ui-polish): add drag feedback, context menus, and shortcuts`

#### Step 19 — Comprehensive tests
Precondition: All features implemented; test coverage partial.
- 19a. Plan: Unit tests added/expanded: `cache/encryption` round-trip + corrupt handling, `pin` hash/verify/derive, `config` ser/de + corrupt backup, slash-split tree (including `a`+`a/b` coexistence), `state` reducers (optimistic/revert/undo/idle wipe/bulk partial-failure).
- 19b. Plan: `wiremock` integration: device-code + refresh + 2FA, folder/collection CRUD, share, 429/403, offline fallback.
- 19c. Plan: `cargo clippy -- -D warnings` and `cargo fmt --check` clean; literate-preamble linter (manual review checklist: every `src/**/*.rs` opens with doc comment, docs explain WHY).
- Validation: `cargo test` all green; `cargo clippy` + `cargo fmt` pass.
- Commit: `test: add unit and wiremock coverage plus lint checks`

## Risks / Gotchas
- `bitwarden` SDK may lack share endpoints -> verify in Step 15 early; raw REST bearer fallback.
- Device-code 2FA shapes differ Cloud vs Vaultwarden -> test both in Step 6.
- Iced 0.13 drag-drop manual -> buttons/menus are canonical; drag is enhancement (Step 18).
- Cache key: Argon2 with per-user salt + PIN-derived; never raw token; Step 4/7 must stay aligned.
- Slash-split `a` and `a/b` both real folders -> tree node is leaf+parent; covered in Step 9/19 tests.
- Org share changes item IDs -> always re-sync after Step 15; don't patch IDs locally.
- Lock wiping must not retain decrypted vault in undo history — undo entries store only IDs/ops (Step 10/16).

## Validation (end-to-end)
Manual: device-code + TOTP; Vaultwarden server URL; persistent session restart; sync 1k items <5s; folder CRUD with `a/b`; bulk move 12 with progress + partial-failure; collection CRUD; personal->org clone via web verification; org->org error; offline banner + read-only; restart+PIN cache load <1s; rapid ops 429 retry; Undo; selective confirms; Trash read-only; idle 15m + PIN unlock + manual lock; system theme.
Automated: `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check`.

## Open Questions
None — all scope resolved; item-field editing, offline mutation queue, restore-from-trash, and packaging remain out of scope.
