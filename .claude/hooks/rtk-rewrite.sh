#!/usr/bin/env bash
# rtk-hook-version: 3
# RTK auto-rewrite hook for Claude Code PreToolUse:Bash
# Transparently rewrites raw commands to their RTK equivalents.
# Uses `rtk rewrite` as single source of truth — no duplicate mapping logic here.
#
# To add support for new commands, update src/discover/registry.rs (PATTERNS + RULES).
#
# Exit code protocol for `rtk rewrite`:
#   0 + stdout  Rewrite found, no deny/ask rule matched → auto-allow
#   1           No RTK equivalent → pass through unchanged
#   2           Deny rule matched → pass through (Claude Code native deny handles it)
#   3 + stdout  Ask rule matched → rewrite but let Claude Code prompt the user

# Guards: skip silently if dependencies missing
if ! command -v rtk &>/dev/null || ! command -v jq &>/dev/null; then
  exit 0
fi

set -euo pipefail

INPUT=$(cat)
CMD=$(echo "$INPUT" | jq -r '.tool_input.command // empty')

if [ -z "$CMD" ]; then
  exit 0
fi

# Skip heredocs (rtk rewrite also skips them, but bail early)
case "$CMD" in
  *'<<'*) exit 0 ;;
esac

# Rewrite via rtk — single source of truth for all command mappings and permission checks.
# Use "|| EXIT_CODE=$?" to capture non-zero exit codes without triggering set -e.
EXIT_CODE=0
REWRITTEN=$(rtk rewrite "$CMD" 2>/dev/null) || EXIT_CODE=$?

case $EXIT_CODE in
  0)
    # Rewrite found, no permission rules matched — safe to auto-allow.
    if [ "$CMD" = "$REWRITTEN" ]; then
      exit 0
    fi
    ;;
  1)
    # No RTK equivalent — pass through unchanged.
    exit 0
    ;;
  2)
    # Deny rule matched — let Claude Code's native deny rule handle it.
    exit 0
    ;;
  3)
    # Ask rule matched — rewrite the command but do NOT auto-allow so that
    # Claude Code prompts the user for confirmation.
    ;;
  *)
    exit 0
    ;;
esac

# Build the updated tool_input with all original fields preserved, only command changed.
ORIGINAL_INPUT=$(echo "$INPUT" | jq -c '.tool_input')
UPDATED_INPUT=$(echo "$ORIGINAL_INPUT" | jq --arg cmd "$REWRITTEN" '.command = $cmd')

if [ "$EXIT_CODE" -eq 3 ]; then
  # Ask: rewrite the command, omit permissionDecision so Claude Code prompts.
  jq -n \
    --argjson updated "$UPDATED_INPUT" \
    '{
      "hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "updatedInput": $updated
      }
    }'
else
  # Allow: output the rewrite instruction in Claude Code hook format.
  jq -n \
    --argjson updated "$UPDATED_INPUT" \
    '{
      "hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "allow",
        "permissionDecisionReason": "RTK auto-rewrite",
        "updatedInput": $updated
      }
    }'
fi
