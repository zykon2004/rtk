# Codex CLI Hooks

> Part of [`hooks/`](../README.md) — see also [`src/hooks/`](../../src/hooks/README.md) for installation code

## Specifics

- Prompt-level guidance via awareness document -- no programmatic hook
- `rtk-awareness.md` is injected into `AGENTS.md` with an `@RTK.md` reference
- Installed to `$CODEX_HOME` when set, otherwise `~/.codex/`, by `rtk init --codex`
- Global install (`rtk init -g --codex`) also offers to patch `$CODEX_HOME/config.toml` or `~/.codex/config.toml` so Codex can write RTK's platform data directory for `rtk gain`

## Gain Tracking

Codex runs shell commands in a workspace-write sandbox. RTK stores token savings in a SQLite database under the platform data directory, for example:

```toml
[sandbox_workspace_write]
writable_roots = [
  "/Users/you/Library/Application Support/rtk",
]
```

`rtk init -g --codex` prompts before adding that writable root. Use `--auto-patch` to apply it without prompting, or `--no-patch` to print manual instructions. This is required because SQLite may create `history.db`, `history.db-wal`, `history.db-shm`, and migration temp files in the RTK data directory.
