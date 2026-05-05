# Pi Coding Agent Hooks

> Part of [`hooks/`](../README.md) -- see also [`src/hooks/`](../../src/hooks/README.md) for installation code

## Specifics

- Prompt-level guidance via `AGENTS.md` -- no programmatic hook
- RTK instructions are written inline because Pi loads context files directly
- Local install: `rtk init --agent pi` writes `./AGENTS.md` and `./RTK.md`
- Global install: `rtk init -g --agent pi` writes `$PI_CODING_AGENT_DIR/AGENTS.md` when set, otherwise `~/.pi/agent/AGENTS.md`

Pi loads global and project `AGENTS.md` files at startup. Restart Pi or run `/reload` after installing.
