# RTK Privacy Hardening Plan (v3 — addressing v2 review)

**Status:** Revised after second GPT-5.4 review (REVISE → addressing all 3 CRITICALs + 7 WARNs + 3 NITs).
**Goal:** In the local SQLite tracking DB and tee filename slugs, never persist raw command-line content. Aggregate metrics, sanitized command patterns, timing, and a passthrough flag only. Preserve `rtk gain` UX best-effort. Tee file *contents* (raw stdout/stderr of failed commands) remain on disk by explicit user decision — see Non-goals.

## Threat model

All four of:

1. Sibling process on the local machine reading `~/Library/Application Support/rtk/`.
2. Time Machine / iCloud backup leaking data off-device.
3. Sharing dotfiles or screen.
4. Future LLM tool-use reading the SQLite DB or invoking RTK to dump history.

Implication: any plaintext command-line content on disk is treated as leaked. Mitigation is to never write it. Tee file contents are an explicit residual leak (filter-bug recovery requires it); see Non-goals.

## Scope

In scope:

- `~/Library/Application Support/rtk/history.db` schema and writers.
- All `rtk gain` analytics queries that read the affected columns (full enumeration below).
- Tee filename slug derivation (filenames are command-derived; sanitize to a `cmd_pattern`).
- Migration of the existing DB with explicit WAL/SHM sidecar handling and `PRAGMA user_version` gating.

Out of scope (explicit user decisions):

- Tee file contents (raw stdout/stderr written under `~/Library/Application Support/rtk/tee/*.log`).
- `rtk discover` and `rtk learn` commands.
- `project_path` column kept verbatim. Residual leak, accepted.
- Per-row `timestamp` (kept full RFC3339).
- DB location.

## Schema changes

```sql
-- BEFORE
CREATE TABLE commands (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    original_cmd TEXT NOT NULL,
    rtk_cmd TEXT NOT NULL,
    input_tokens INTEGER NOT NULL,
    output_tokens INTEGER NOT NULL,
    saved_tokens INTEGER NOT NULL,
    savings_pct REAL NOT NULL,
    exec_time_ms INTEGER DEFAULT 0,
    project_path TEXT DEFAULT ''
);

-- AFTER
CREATE TABLE commands (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    cmd_pattern TEXT NOT NULL,
    is_passthrough INTEGER NOT NULL DEFAULT 0,   -- new (replaces "rtk fallback:" prefix encoding)
    input_tokens INTEGER NOT NULL,
    output_tokens INTEGER NOT NULL,
    saved_tokens INTEGER NOT NULL,
    savings_pct REAL NOT NULL,
    exec_time_ms INTEGER DEFAULT 0,
    project_path TEXT DEFAULT ''
);

CREATE INDEX idx_timestamp ON commands(timestamp);
CREATE INDEX idx_project_path_timestamp ON commands(project_path, timestamp);
CREATE INDEX idx_cmd_pattern ON commands(cmd_pattern);
```

```sql
-- BEFORE
CREATE TABLE parse_failures (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    raw_command TEXT NOT NULL,
    error_message TEXT NOT NULL,
    fallback_succeeded INTEGER NOT NULL DEFAULT 0
);

-- AFTER
CREATE TABLE parse_failures (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    cmd_pattern TEXT NOT NULL,
    error_message TEXT NOT NULL,
    fallback_succeeded INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_pf_timestamp ON parse_failures(timestamp);
```

After table creation, set `PRAGMA user_version = 1` on the DB. This is the migration version gate (replaces the sidecar sentinel file from v2 — addresses CRITICAL 3).

`is_passthrough` is required (no longer "open question" — addresses WARN 1). It is the only signal that distinguishes filtered-and-tracked commands from passthrough fallback, replacing the `"rtk fallback:"` prefix encoding previously embedded in `rtk_cmd`.

## `cmd_pattern` value-construction pipeline

Implemented as `pub fn build_cmd_pattern(raw: &str) -> String` in a new module `src/core/cmd_pattern.rs`. Pure function; no DB access; never panics; on any error returns `"unknown"`.

### Step 0 — Behavior parity statement (revised premise)

The current passthrough fallback at `src/core/tracking.rs:1328` (`track_passthrough`) stores the **full raw command including operators and pipes** (`cargo test && git status` is stored verbatim). This plan deliberately changes that behavior: the new `cmd_pattern` operates on the **leftmost segment only**. This is **not parity with the existing tracking behavior** — it is an intentional privacy-motivated change. Compound commands collapse to the pattern of their leftmost segment. The user-visible effect: in `rtk gain --history`, a row that previously read `cargo test && git status` now reads `cargo test`. Documented as intentional. (Addresses WARN 7.)

### Pipeline steps

1. **Trim** leading/trailing whitespace. Empty → `"unknown"`.

2. **Strip env prefix + `sudo` + `env`.** Reuse `strip_env_prefix` from `src/discover/registry.rs` (the existing `ENV_PREFIX` regex used by the rewrite path). Establishes single-source-of-truth for env stripping. (Addresses WARN 2 partial reuse.)

3. **Tokenize the leftmost segment only.** Use `src/discover/lexer.rs`. Split on the first `Operator(&&|;|||)` or `Pipe`; tokenize the leftmost segment. (Intentional behavior change — see Step 0.)

4. **Strip trailing redirects** (`2>&1`, `>/dev/null`, `>file`, `>>file`).

5. **Normalize the command name** (token 0):
   - Strip absolute path: `/usr/local/bin/git` → `git`. `Path::file_name`.
   - Lowercase.
   - Empty → `"unknown"`.

6. **Look up command metadata** from `CMD_META` table in `cmd_pattern.rs` (see Metadata table below). Unknown command → treated as `max_depth=0`.

7. **Walk tokens** to capture up to `max_depth` non-flag tokens:
   - Skip flag tokens (start with `-`).
   - If a flag is in `flags_consume_arg`, also skip the next token.
   - If `module_dash_m=true` and current flag is `-m`, capture the following token as virtual subcommand 1 (e.g. `python -m pytest` → `python pytest`).
   - If `compose_subcmd=true` and the first non-flag token is `compose`, capture `compose` as subcommand 1 and the next non-flag token as subcommand 2 (e.g. `docker compose up` → `docker compose up`).
   - Stop walking when `max_depth` non-flag tokens captured.

8. **Path/secret guard on captured subcommand tokens.** Reject and stop walking if any captured token:
   - Starts with `/`, `~`, `./`, or `../`
   - Contains `/`, `=`, `:`, `"`, `'`, or backtick
   - Matches `^[0-9a-f]{7,}$`
   - Contains a digit run of length ≥4
   - Length > 24

   Token 0 (the command name itself) is **not** subjected to the guard.

   **Acceptable-loss bar (addresses WARN 4):** the guard collapses cases where granularity vs leak risk trade unfavorably. Examples documented in Worked Examples below show what gets collapsed (`cargo test foo::bar` → `cargo test`, `gh pr view 1234` → `gh pr view`, `npm install @scope/pkg` → `npm install`). The privacy floor is the goal; granularity preservation is best-effort. A test corpus drawn from real RTK fixtures (`tests/fixtures/`) verifies that the most common shapes round-trip to useful patterns; cases that collapse are documented, not bugs.

9. **Cap by token count.** Maximum 3 tokens (command + 2 captured). No raw character cap; tokens are atomic. (Addresses NIT 2.)

10. **Result.** `tokens.join(" ")`. Empty → `"unknown"`.

11. **Errors.** Any error path returns `"unknown"`. No `catch_unwind` (addresses NIT 1) — the lexer returns `Result`, downstream code matches on `Err` and falls through to `"unknown"`. If the lexer is found to panic on adversarial input during fuzz testing, the fix is to harden the lexer, not to wrap the caller.

## Metadata table (`CMD_META`)

The table is a deliberate, focused taxonomy for atomization. It does **not** claim parity with `src/discover/rules.rs` (addresses WARN 3 — original v2 claim of "covers every command currently classified" was false). It covers the high-traffic command families. Other commands (`yadm`, `npx`, `bundle`, `brew`, `terraform`, `liquibase`, `helm`, `gcloud`, `az`, `make`, `just`, `task`, `tox`, `nox`, `poetry`, `gradle`, `mvn`, etc.) deliberately fall through to `max_depth=0` → pattern is just the command name. Documented loss of granularity. Adding a new entry is a one-line PR.

| name | max_depth | flags_consume_arg | module_dash_m | compose_subcmd |
|---|---|---|---|---|
| git | 2 | `-C`, `--git-dir`, `--work-tree` | false | false |
| gh | 2 | `-R`, `--repo` | false | false |
| gt | 2 | — | false | false |
| aws | 2 | `--profile`, `--region`, `--endpoint-url` | false | false |
| kubectl | 2 | `-n`, `--namespace`, `--context`, `--kubeconfig` | false | false |
| docker | 2 | `-f`, `--file`, `--context`, `-H` | false | true |
| docker-compose | 1 | `-f`, `--file` | false | false |
| npm | 2 | `--prefix`, `-w`, `--workspace` | false | false |
| pnpm | 2 | `--filter`, `-C`, `-w` | false | false |
| yarn | 2 | `--cwd` | false | false |
| cargo | 2 | `--manifest-path`, `--target-dir`, `-p` | false | false |
| dotnet | 2 | `--project`, `--configuration` | false | false |
| go | 1 | `-C` | false | false |
| python, python3 | 0 | — | true | false |
| uv | 2 | — | false | false |
| pip, pip3 | 1 | — | false | false |
| ruff | 1 | — | false | false |
| pytest | 0 | `-c`, `--rootdir` | false | false |
| mypy | 0 | `--config-file` | false | false |
| rake | 1 | `-f` | false | false |
| rspec, rubocop | 0 | (`rubocop -c`) | false | false |
| golangci-lint | 1 | `-c` | false | false |
| playwright, vitest | 1 | — | false | false |
| jest | 0 | `-c` | false | false |
| next | 1 | — | false | false |
| tsc | 0 | `-p`, `--project` | false | false |
| prisma | 1 | — | false | false |
| prettier, curl, wget | 0 | — | false | false |
| psql | 0 | `-U`, `-d`, `-h`, `-p`, `-f` | false | false |
| rg, grep, find, fd, cat, wc, ls, cd, rm, cp, mv, source, ., env | 0 | — | false | false |
| head, tail | 0 | `-n` | false | false |
| tree | 0 | `-I` | false | false |
| sh, bash, zsh | 0 | `-c` | false | false |
| rtk | 1 | — | false | false |

**Drift-prevention test:** a unit test enumerates every command name extracted from `src/discover/rules.rs` and asserts it either has an entry in `CMD_META` or is in an explicit `INTENTIONALLY_UNCLASSIFIED: &[&str]` list. New rewrite rules without a metadata decision fail the test. (Addresses WARN 2.)

## Worked examples

(Same as v2; abbreviated here. Full table preserved in commit history.)

`git status` → `git status`
`git -C /home/x status` → `git status`
`AWS_SECRET=abc aws s3 ls s3://b/k` → `aws s3 ls`
`cargo test foo::bar::baz` → `cargo test`
`gh pr view 1234` → `gh pr view` (digit-run blocks `1234`)
`gh pr view 99` → `gh pr view 99`
`kubectl -n prod get pods` → `kubectl get pods`
`cat /etc/passwd` → `cat`
`npm run build:prod` → `npm run`
`docker compose up -d` → `docker compose up`
`docker compose -f /tmp/x.yml up` → `docker compose up`
`python -m pytest tests/` → `python pytest`
`uv pip install requests` → `uv pip install`
`/usr/local/bin/git status` → `git status`
`source ./scripts/env.sh` → `source`
`bash -c "rm -rf /"` → `bash`
`FOO=1 BAR="x y" sudo env BAZ=2 git status` → `git status`
`git log | head -20` → `git log` (leftmost segment only — intentional)
`cargo test && git status` → `cargo test` (leftmost segment only — intentional)
Empty / whitespace / 1000-char garbage → `unknown`

## Code paths to modify

### `src/core/tracking.rs`

Schema (lines 262–323):
- Replace both `CREATE TABLE` statements with the v3 schema. Drop legacy `ALTER TABLE` migrations (replaced by fresh-file migration).
- Add `is_passthrough` column to `commands`.
- Add `idx_cmd_pattern` index.
- Set `PRAGMA user_version = 1` after table creation.

Writers:
- Lines 351–386: `Tracker::record` signature changes:
  ```rust
  // BEFORE
  pub fn record(&self, original_cmd: &str, rtk_cmd: &str, input: usize, output: usize, exec_ms: u64) -> Result<()>
  // AFTER
  pub fn record(&self, raw_command: &str, is_passthrough: bool, input: usize, output: usize, exec_ms: u64) -> Result<()>
  ```
  Internally calls `cmd_pattern::build_cmd_pattern(raw_command)`. Drop `rtk_cmd` parameter.
- Line 1328: `TimedExecution::track_passthrough(original_cmd, rtk_cmd)` → `TimedExecution::track_passthrough(raw_command)`. Internally calls `record(raw_command, /*is_passthrough=*/ true, 0, 0, elapsed_ms)`.
- Line 402–422: `Tracker::record_parse_failure(raw_command, error_message, succeeded)` external signature unchanged; internally atomizes.

Readers — full enumeration:
- Line 448 — `top_commands` SELECT in `get_summary`: `GROUP BY cmd_pattern`.
- Line 575 — top-10 stats `GROUP BY`: `cmd_pattern`.
- Line 912 — `pub fn top_commands(&self, limit) -> Result<Vec<String>>`: `SELECT cmd_pattern`.
- Line 962 — `pub fn top_passthrough(&self, limit)`: `WHERE is_passthrough = 1 GROUP BY cmd_pattern`.
- Line 989 — `pub fn low_savings_commands(&self, limit)`: `SELECT cmd_pattern`.
- Line 1007 — `pub fn avg_savings_per_command()`: `GROUP BY cmd_pattern`.
- Line 1021 — `pub fn count_meta_command(&self, name)`: `WHERE cmd_pattern = ?` (caller passes pattern like `"rtk gain"`).
- Line 1077 — `pub fn ecosystem_mix()`: `categorize_command(cmd_pattern)`.
- Line 1099 — call site of `categorize_command`: input is `cmd_pattern`.
- Line 1136 — `fn categorize_command(rtk_cmd: &str)`: rename parameter to `pattern: &str`. Substring match logic unchanged (still works since pattern starts with command name).

Structs:
- Line 103 — `CommandRecord.rtk_cmd` → `cmd_pattern`. Add `is_passthrough: bool` field.
- Line 1178 — `ParseFailureRecord.raw_command` → `cmd_pattern`.
- Line 1189 — `summary.top_commands` semantics change; type unchanged.

### `src/main.rs`

- Lines 1180, 1186, 1204, 1209: `record_parse_failure_silent` calls — no signature change.
- All `Tracker::record` callers: drop `rtk_cmd` argument, add `is_passthrough` boolean. (~5–10 sites; full list during implementation via `Grep`.)
- Lines 1162–1166: tee call site. Replace `&raw_command` slug with `&build_cmd_pattern(&raw_command)`. **Prevents tee filename leak (CRITICAL 3 from v1 review).**
- Line 1202: `track_passthrough(&raw_command, &format!("rtk fallback: {}", raw_command))` → `track_passthrough(&raw_command)`. The `rtk fallback:` prefix string is gone from the schema; replaced by `is_passthrough = true`.

### `src/cmds/cloud/aws_cmd.rs`

- Lines 349, 364, 369, 402, 413, 455: tee callers. Where slug is hardcoded (`"aws_s3_ls"` etc.), leave unchanged. Where slug is derived from raw command, replace with `build_cmd_pattern`. Audit each call site during implementation.

### `src/core/tee.rs`

- `sanitize_slug` (lines 19–35): kept as defense-in-depth.

### `src/analytics/gain.rs`

- Lines 692–695: `summary.top_commands` rendering — column header "Pattern" instead of "Command".
- Lines 716–719 (`--failures` view): `rec.raw_command` → `rec.cmd_pattern`.
- Sweep all UI strings for "command" → "pattern" where the displayed value is now a pattern. (Addresses NIT 3.)

### New file: `src/core/cmd_pattern.rs`

- `pub fn build_cmd_pattern(raw: &str) -> String` — 11-step pipeline.
- `const CMD_META: &[CmdMeta]` — metadata table.
- `const INTENTIONALLY_UNCLASSIFIED: &[&str]` — commands deliberately treated as `max_depth=0` (used by drift-prevention test).
- `fn lookup_meta(cmd_name: &str) -> Option<&CmdMeta>`.
- `fn token_passes_guard(tok: &str) -> bool`.

### Tests

`src/core/cmd_pattern.rs` unit tests:
- All 20+ worked examples plus edge cases (unicode, lone redirect, lone pipe, empty, whitespace).
- Random-fuzz: 1000 random byte sequences, none panic, all return non-empty string. Hand-rolled (no proptest dep).
- **Drift-prevention test:** parses `src/discover/rules.rs` (or its parsed registry) for command names; asserts every name is in `CMD_META` or `INTENTIONALLY_UNCLASSIFIED`. Fails when new rewrite rules are added without a metadata decision.

`src/core/tracking.rs` tests:
- `test_migration_v0_to_v1`: pre-create legacy DB with both old tables populated; run `Tracker::new()`; assert new schema, `PRAGMA user_version = 1`, no plaintext findable via `rusqlite` query against legacy column names.
- `test_migration_idempotent`: call `Tracker::new()` twice in sequence; assert migration runs only once (verify by adding a row between calls and checking it survives).
- `test_migration_partial_legacy`: pre-create DB with `commands` migrated but `parse_failures` legacy; `user_version = 0` initially. Run migration. Both tables clean. (Addresses CRITICAL 1 — version gate covers entire DB, not just `commands`.)
- `test_migration_wal_shm_cleanup`: pre-create `history.db-wal` and `history.db-shm` files with garbage; run migration; assert files deleted.
- `test_concurrent_open`: two threads simultaneously call `Tracker::new()` against the same path. Document via comment that the harder case — another process holding the legacy DB *open* during migration — is not tested here (see WARN 6 disclaimer in Migration section).
- `test_record_with_pattern`: insert via new `record(raw, false, ...)`; query; assert `cmd_pattern` matches expected.
- `test_record_passthrough`: insert via `track_passthrough(raw)`; assert `is_passthrough = 1` in row.
- `test_record_parse_failure_pattern`: insert via `record_parse_failure_silent("AWS_KEY=secret aws s3 ls", "err", false)`; assert stored `cmd_pattern = "aws s3 ls"`, no secret.

## Migration (rewritten — addresses CRITICAL 1, 2, 3)

```rust
// Pseudocode in src/core/tracking.rs::Tracker::new()
const SCHEMA_VERSION: i32 = 1;

fn new() -> Result<Self> {
    let db_path = get_db_path()?;
    let parent = db_path.parent().context("db_path has no parent")?;
    fs::create_dir_all(parent)?;

    if db_path.exists() {
        let current = read_user_version(&db_path)?;  // returns 0 if PRAGMA never set
        if current < SCHEMA_VERSION {
            migrate_to_v1(&db_path)?;
        }
    }

    let conn = Connection::open(&db_path)?;
    let _ = conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;");
    create_tables_if_missing(&conn)?;
    let v: i32 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if v < SCHEMA_VERSION {
        conn.execute_batch(&format!("PRAGMA user_version = {};", SCHEMA_VERSION))?;
    }
    Ok(Self { conn })
}

fn read_user_version(path: &Path) -> Result<i32> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    Ok(conn.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap_or(0))
}

fn migrate_to_v1(db_path: &Path) -> Result<()> {
    let parent = db_path.parent().unwrap();

    // 1. Build a brand-new DB at a temp path in DELETE journal mode.
    let tmp_path = parent.join(format!("history.db.migrating-{}", std::process::id()));
    let _ = fs::remove_file(&tmp_path);

    {
        let conn = Connection::open(&tmp_path)?;
        conn.execute_batch("PRAGMA journal_mode=DELETE;")?;
        create_tables_v1(&conn)?;       // creates fresh tables with v1 schema
        conn.execute_batch(&format!("PRAGMA user_version = {};", SCHEMA_VERSION))?;
    }

    // 2. Atomically replace.
    //    Unix: fs::rename is atomic and replaces existing.
    //    Windows: Rust's std::fs::rename uses MoveFileExW with MOVEFILE_REPLACE_EXISTING
    //    since Rust 1.5+, but documentation cautions about DACL and cross-device.
    //    Best-effort fallback: remove destination first if rename fails on Windows.
    if let Err(e) = fs::rename(&tmp_path, db_path) {
        #[cfg(windows)]
        {
            let _ = fs::remove_file(db_path);
            fs::rename(&tmp_path, db_path)
                .with_context(|| format!("Windows fallback rename failed: {}", e))?;
        }
        #[cfg(not(windows))]
        return Err(e).context("Atomic rename failed during privacy migration");
    }

    // 3. Remove WAL/SHM sidecars from the old DB.
    let _ = fs::remove_file(parent.join("history.db-wal"));
    let _ = fs::remove_file(parent.join("history.db-shm"));

    Ok(())
}
```

Key properties:

- **Single-source version gate.** `PRAGMA user_version` lives inside the DB file itself. Whatever DB path the user resolves to (default, `RTK_DB_PATH`, config override), the version travels with that file. No sidecar sentinel keyed to parent directory (addresses CRITICAL 3 from v2 review).
- **Whole-DB schema gate, not per-table.** `user_version < 1` triggers full rebuild including `parse_failures`. A DB cannot end up with one table migrated and one not (addresses CRITICAL 1 from v2 review).
- **Cross-platform atomic replace.** `fs::rename` is atomic on Unix and atomic on Windows since Rust 1.5+ (uses `MOVEFILE_REPLACE_EXISTING`). Defensive Windows fallback added: if rename fails, remove destination and retry. Documented as best-effort on Windows; on Unix it is fully atomic. (Addresses CRITICAL 2 from v2 review.)
- **WAL/SHM cleanup.** Old sidecars unlinked explicitly; new DB starts in DELETE journal mode for the migration step, switched to WAL for normal operation. Legacy plaintext that was in the old DB's WAL is unreferenced after the rename and the old inode is reclaimed.
- **Concurrent-RTK-instance disclaimer (addresses WARN 6).** If another process already holds the legacy DB open during migration: on Unix, the rename succeeds and the holder keeps reading the unlinked inode until it closes (no harm — it just doesn't see new data and the unlinked file's blocks are reclaimed when it closes). On Windows, the rename may fail with the file-in-use error; the fallback `remove_file` will also fail; the migration returns an error and the next RTK invocation retries. **Documented behavior, not tested in CI** because reproducing reliably requires platform-specific fixtures.

## User-facing migration notice (revised)

- Migration itself is silent.
- A second sidecar file `~/Library/Application Support/rtk/.privacy_migration_announced_v1` records that the user has been told.
- Only `rtk gain`, `rtk init`, and `rtk verify` (user-facing entry points with normal dispatch flow) check `if user_version >= 1 && !announced` and print one line:
  ```
  rtk: privacy migration v1 applied — pre-existing tracking data was wiped (history.db rebuilt with sanitized command patterns).
  ```
  Then create the announce-sidecar.
- **`rtk --version` does not print the notice (addresses WARN 5 from v2 review).** Clap's `DisplayVersion` exits before normal dispatch; injecting the notice there requires a custom early-exit handler that's not worth the complexity.
- Tracked-command paths (every Bash hook invocation through `rewrite`) **never** print the notice.

## Backward-compat fallout

- `rtk gain --history` displays `cmd_pattern` per row.
- `rtk gain --failures` displays `cmd_pattern` per failure.
- `rtk gain` top-10 commands shows pattern-grouped totals.
- Compound commands (`a && b`, `a | b`) collapse to the pattern of the leftmost segment in tracking. Documented behavior change.
- The user's existing 245 rows are forfeited. Documented.
- `CommandRecord` and `ParseFailureRecord` are internal types; no external library consumers.

## Open questions

(All previously-open items now decided. Remaining items are deferred polish, not blockers.)

1. **Length cap for captured tokens (currently 24).** Drops long branch/package/bucket names. Acceptable; raise to 32 if user feedback shows too many collapses to bare command name.
2. **Digit-run threshold (currently ≥4).** Drops `gh pr view 1234`. Defensible; PR numbers are weak fingerprints.
3. **`--version` notice.** Decided: not implemented. If user feedback shows confusion about the migration, revisit.

## Non-goals (explicit)

- Encrypting the SQLite DB at rest.
- Moving the DB to `~/Library/Caches/rtk/`.
- Adding a config flag to opt out.
- Removing or gating tee, `rtk discover`, `rtk learn`.
- Removing or hashing `project_path`.
- Sanitizing tee file *contents* (raw stdout/stderr written by tee). Out of scope; goal narrowed.
- `rtk --version` migration notice. See WARN 5 fix.

## Acceptance criteria

**Rust test gates (CI-blocking):**

1. `cargo test --all` passes including all new `cmd_pattern` and tracking tests.
2. `cargo clippy --all-targets` zero warnings.
3. `cargo fmt --all` clean.
4. `test_migration_v0_to_v1` passes — fresh build over legacy DB.
5. `test_migration_idempotent` passes — second `Tracker::new()` is a no-op.
6. `test_migration_partial_legacy` passes — `user_version` gate forces full rebuild even if one table appears modern.
7. `test_migration_wal_shm_cleanup` passes — sidecars unlinked.
8. `test_record_with_pattern` and `test_record_passthrough` pass — `is_passthrough` correctly set.
9. `test_record_parse_failure_pattern` passes — sensitive parse-failure input stored as sanitized pattern.
10. `cmd_pattern` drift-prevention test passes — every command in `discover/rules.rs` has a metadata decision.
11. `cmd_pattern` fuzz test passes — 1000 random byte sequences, no panic.

**Manual / optional verification (not CI-gated; addresses NIT 2 — these tools are not guaranteed everywhere):**

12. After migration, `sqlite3 ~/Library/Application\ Support/rtk/history.db ".schema"` shows `cmd_pattern`, `is_passthrough`, no legacy columns. (Requires `sqlite3`.)
13. After migration, `sqlite3 ... 'PRAGMA user_version'` returns `1`.
14. `strings -n 8 ~/Library/Application\ Support/rtk/history.db | grep -E 'AWS_|GITHUB_|/Users/|/home/' | wc -l` returns 0 immediately post-migration. (Requires `strings`.)
15. `ls ~/Library/Application\ Support/rtk/ | grep -E '\\-wal$|\\-shm$' | wc -l` returns 0 immediately post-migration.
16. After `AWS_SECRET=abc aws s3 ls s3://bucket/secrets/` is tracked, `sqlite3 ... 'SELECT cmd_pattern FROM commands ORDER BY id DESC LIMIT 1'` returns `aws s3 ls`.
17. `rtk gain --failures` runs without error.
18. Tee filename safety: `ls ~/Library/Application\ Support/rtk/tee/` shows filenames derived from patterns, not raw commands.
19. `hyperfine 'rtk git status' --warmup 3` shows <10ms. (Requires `hyperfine`.)
20. `ls -lh target/release/rtk` shows <5MB.

## Risk register

| Risk | Likelihood | Impact | Mitigation / Status |
|---|---|---|---|
| WAL/SHM sidecars retain legacy plaintext | Eliminated | — | Fresh-file rename + explicit sidecar removal + DELETE-mode migration DB |
| Partial-state migration leaves one table legacy | Eliminated | — | `PRAGMA user_version` gates the entire DB |
| Cross-platform atomic-rename failure | Mitigated | Medium | Unix: fully atomic. Windows: documented best-effort with remove-destination fallback |
| `rtk gain --failures` breaks at compile time | Eliminated | — | `parse_failures` keeps `cmd_pattern`; renderer reads new field |
| Tee filenames continue to leak full command | Eliminated | — | All tee callers pass `cmd_pattern` |
| `top_passthrough()` semantics lost | Eliminated | — | `is_passthrough` column added; `track_passthrough` writes it |
| Metadata table drifts from `discover/rules.rs` | Mitigated | Low | Drift-prevention test fails CI when new rules lack metadata decision |
| `cmd_pattern` pipeline panics on adversarial input | Low | Medium | All steps return `Result`/`Option`; fuzz test in CI; no `catch_unwind` (NIT 1) |
| Compound-command collapse surprises users | Certain | Low | Documented intentional behavior change in Step 0 + backward-compat section |
| Path/secret guard false-positive collapses useful tokens | Medium | Low | Acceptable-loss bar documented; test corpus from real fixtures |
| Path/secret guard false-negative leaks a token | Low | Medium | Multi-rule guard; adversarial test corpus in `cmd_pattern` tests |
| Concurrent RTK during migration on Windows | Low | Low | Documented behavior; not CI-tested |
| Tee file *contents* still leak raw output | Certain | High under (i)/(ii) | Out of scope by user decision (Non-goals) |
| `rtk discover` aggregation tool exists | Certain under (iv) | High | Out of scope by user decision (Non-goals) |
| `project_path` column leaks project locations | Certain | Medium | Out of scope by user decision (Non-goals) |

## Implementation order

1. Land `src/core/cmd_pattern.rs` with the metadata table, 11-step pipeline, fuzz test, drift-prevention test. Pure function; no DB or codebase coupling. Standalone PR if desired.
2. Land migration logic in `Tracker::new()`. `migrate_to_v1`, `read_user_version`. All migration tests pass.
3. Update writers: `Tracker::record` (drop `rtk_cmd`, add `is_passthrough`), `track_passthrough` (single arg, sets passthrough flag), `record_parse_failure` (internally atomizes).
4. Update readers: all 7+ helpers in `tracking.rs` plus renderers in `gain.rs`. Tests pass.
5. Update tee call sites: `main.rs:1162–1166` and audit `aws_cmd.rs`.
6. Migration notice plumbing: announce-sidecar plus `gain`/`init`/`verify` print path.
7. Terminology sweep: "command" → "pattern" in user-facing strings where the displayed value is a pattern.
8. Quality gate: `cargo fmt --all && cargo clippy --all-targets && cargo test --all`.
9. Manual smoke test: wipe local DB, run `rtk init -g`, run sensitive commands, inspect via `sqlite3 + strings`.
10. Performance benchmark with `hyperfine`.
11. Update `CLAUDE.md` and `docs/contributing/ARCHITECTURE.md`.
