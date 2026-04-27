//! Privacy-preserving command-pattern atomization.
//!
//! Reduces a raw shell command to a short, sanitized "pattern" that captures
//! ecosystem and intent (e.g. `git status`, `npm run`, `aws s3 ls`) without
//! retaining file paths, identifiers, secrets, or compound-command tails.
//!
//! Used by the local SQLite tracker to populate `commands.cmd_pattern` and
//! `parse_failures.cmd_pattern` so that `~/Library/Application Support/rtk/history.db`
//! never contains raw command-line content.
//!
//! Design constraints:
//! - Pure function, no I/O.
//! - Never panics on adversarial input.
//! - On any error path returns the literal string `"unknown"`.
//! - Operates on the leftmost segment only — `cargo test && git status` collapses to
//!   `cargo test`. This is an intentional privacy-motivated change from the previous
//!   passthrough tracking behavior.

use std::path::Path;

use crate::discover::lexer::{tokenize, ParsedToken, TokenKind};
use crate::discover::registry::strip_env_prefix;

const FALLBACK: &str = "unknown";
const MAX_TOKEN_LEN: usize = 24;
const MAX_PATTERN_TOKENS: usize = 3;
const HEX_RE_MIN: usize = 7;
const DIGIT_RUN_THRESHOLD: usize = 4;

/// Per-command metadata controlling how many subcommand tokens to capture
/// and how to handle flags that consume an argument.
struct CmdMeta {
    name: &'static str,
    max_depth: usize,
    flags_consume_arg: &'static [&'static str],
    /// `python -m pkg` → capture `pkg` as virtual subcommand 1.
    module_dash_m: bool,
    /// `docker compose <subcmd>` → capture both `compose` and `<subcmd>`.
    compose_subcmd: bool,
}

const CMD_META: &[CmdMeta] = &[
    CmdMeta {
        name: "git",
        max_depth: 2,
        flags_consume_arg: &["-C", "--git-dir", "--work-tree", "-c"],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "gh",
        max_depth: 2,
        flags_consume_arg: &["-R", "--repo"],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "gt",
        max_depth: 2,
        flags_consume_arg: &[],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "aws",
        max_depth: 2,
        flags_consume_arg: &["--profile", "--region", "--endpoint-url"],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "kubectl",
        max_depth: 2,
        flags_consume_arg: &["-n", "--namespace", "--context", "--kubeconfig"],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "docker",
        max_depth: 2,
        flags_consume_arg: &["-f", "--file", "--context", "-H"],
        module_dash_m: false,
        compose_subcmd: true,
    },
    CmdMeta {
        name: "docker-compose",
        max_depth: 1,
        flags_consume_arg: &["-f", "--file"],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "npm",
        max_depth: 2,
        flags_consume_arg: &["--prefix", "-w", "--workspace"],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "pnpm",
        max_depth: 2,
        flags_consume_arg: &["--filter", "-C", "-w"],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "yarn",
        max_depth: 2,
        flags_consume_arg: &["--cwd"],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "cargo",
        max_depth: 2,
        flags_consume_arg: &["--manifest-path", "--target-dir", "-p"],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "dotnet",
        max_depth: 2,
        flags_consume_arg: &["--project", "--configuration"],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "go",
        max_depth: 1,
        flags_consume_arg: &["-C"],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "python",
        max_depth: 0,
        flags_consume_arg: &[],
        module_dash_m: true,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "python3",
        max_depth: 0,
        flags_consume_arg: &[],
        module_dash_m: true,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "uv",
        max_depth: 2,
        flags_consume_arg: &[],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "pip",
        max_depth: 1,
        flags_consume_arg: &[],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "pip3",
        max_depth: 1,
        flags_consume_arg: &[],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "ruff",
        max_depth: 1,
        flags_consume_arg: &[],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "pytest",
        max_depth: 0,
        flags_consume_arg: &["-c", "--rootdir"],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "mypy",
        max_depth: 0,
        flags_consume_arg: &["--config-file"],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "rake",
        max_depth: 1,
        flags_consume_arg: &["-f"],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "rspec",
        max_depth: 0,
        flags_consume_arg: &[],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "rubocop",
        max_depth: 0,
        flags_consume_arg: &["-c"],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "golangci-lint",
        max_depth: 1,
        flags_consume_arg: &["-c"],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "playwright",
        max_depth: 1,
        flags_consume_arg: &[],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "vitest",
        max_depth: 1,
        flags_consume_arg: &[],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "jest",
        max_depth: 0,
        flags_consume_arg: &["-c"],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "next",
        max_depth: 1,
        flags_consume_arg: &[],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "tsc",
        max_depth: 0,
        flags_consume_arg: &["-p", "--project"],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "prisma",
        max_depth: 1,
        flags_consume_arg: &[],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "prettier",
        max_depth: 0,
        flags_consume_arg: &[],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "curl",
        max_depth: 0,
        flags_consume_arg: &[],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "wget",
        max_depth: 0,
        flags_consume_arg: &[],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "psql",
        max_depth: 0,
        flags_consume_arg: &["-U", "-d", "-h", "-p", "-f"],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "rg",
        max_depth: 0,
        flags_consume_arg: &[],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "grep",
        max_depth: 0,
        flags_consume_arg: &[],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "find",
        max_depth: 0,
        flags_consume_arg: &[],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "fd",
        max_depth: 0,
        flags_consume_arg: &[],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "cat",
        max_depth: 0,
        flags_consume_arg: &[],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "wc",
        max_depth: 0,
        flags_consume_arg: &[],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "ls",
        max_depth: 0,
        flags_consume_arg: &[],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "cd",
        max_depth: 0,
        flags_consume_arg: &[],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "rm",
        max_depth: 0,
        flags_consume_arg: &[],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "cp",
        max_depth: 0,
        flags_consume_arg: &[],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "mv",
        max_depth: 0,
        flags_consume_arg: &[],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "source",
        max_depth: 0,
        flags_consume_arg: &[],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: ".",
        max_depth: 0,
        flags_consume_arg: &[],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "env",
        max_depth: 0,
        flags_consume_arg: &[],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "head",
        max_depth: 0,
        flags_consume_arg: &["-n"],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "tail",
        max_depth: 0,
        flags_consume_arg: &["-n"],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "tree",
        max_depth: 0,
        flags_consume_arg: &["-I"],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "sh",
        max_depth: 0,
        flags_consume_arg: &["-c"],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "bash",
        max_depth: 0,
        flags_consume_arg: &["-c"],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "zsh",
        max_depth: 0,
        flags_consume_arg: &["-c"],
        module_dash_m: false,
        compose_subcmd: false,
    },
    CmdMeta {
        name: "rtk",
        max_depth: 1,
        flags_consume_arg: &[],
        module_dash_m: false,
        compose_subcmd: false,
    },
];

/// Commands present in `src/discover/rules.rs` whose pattern is intentionally
/// just the bare command name (no subcommand granularity captured). The
/// drift-prevention test asserts that every rule prefix is either in `CMD_META`
/// or in this list — so adding a new rewrite rule forces an explicit decision.
#[cfg(test)]
const INTENTIONALLY_UNCLASSIFIED: &[&str] = &[
    "yadm",
    "npx",
    "pnpx",
    "rails",
    "biome",
    "eslint",
    "lint",
    "diff",
    "bundle",
    "ansible-playbook",
    "brew",
    "composer",
    "df",
    "du",
    "fail2ban-client",
    "gcloud",
    "hadolint",
    "helm",
    "iptables",
    "make",
    "markdownlint",
    "mix",
    "mvn",
    "ping",
    "pio",
    "poetry",
    "pre-commit",
    "ps",
    "quarto",
    "rsync",
    "shellcheck",
    "shopify",
    "sops",
    "swift",
    "systemctl",
    "terraform",
    "tofu",
    "trunk",
    "yamllint",
    "liquibase",
    "golangci",
    "bin",
];

fn lookup_meta(name: &str) -> Option<&'static CmdMeta> {
    CMD_META.iter().find(|m| m.name == name)
}

/// Reject tokens that look like paths, identifiers, hex hashes, or anything
/// long enough to be a fingerprint of unique user data. Returns `true` if the
/// token is safe to keep as a captured subcommand.
fn token_passes_guard(tok: &str) -> bool {
    if tok.is_empty() || tok.len() > MAX_TOKEN_LEN {
        return false;
    }
    if tok.starts_with('/')
        || tok.starts_with('~')
        || tok.starts_with("./")
        || tok.starts_with("../")
    {
        return false;
    }
    for ch in tok.chars() {
        if matches!(ch, '/' | '=' | ':' | '"' | '\'' | '`') {
            return false;
        }
    }
    if tok.len() >= HEX_RE_MIN && tok.chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }
    let mut run = 0usize;
    for ch in tok.chars() {
        if ch.is_ascii_digit() {
            run += 1;
            if run >= DIGIT_RUN_THRESHOLD {
                return false;
            }
        } else {
            run = 0;
        }
    }
    true
}

/// Normalize the leftmost segment's first token: strip any absolute path,
/// lowercase it. Returns `None` for empty input.
fn normalize_cmd_name(tok: &str) -> Option<String> {
    if tok.is_empty() {
        return None;
    }
    let candidate = if tok.contains('/') {
        Path::new(tok)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(tok)
    } else {
        tok
    };
    if candidate.is_empty() {
        return None;
    }
    Some(candidate.to_ascii_lowercase())
}

/// Take the leftmost segment of a token list, dropping anything from the first
/// pipe or operator onward. Also drops trailing redirect tokens and their
/// targets.
fn leftmost_segment(tokens: Vec<ParsedToken>) -> Vec<ParsedToken> {
    let mut out = Vec::with_capacity(tokens.len());
    let mut iter = tokens.into_iter().peekable();
    while let Some(t) = iter.next() {
        match t.kind {
            TokenKind::Operator | TokenKind::Pipe => break,
            TokenKind::Redirect => {
                // Skip the redirect plus its target arg (e.g. `> /dev/null`).
                if matches!(iter.peek().map(|n| &n.kind), Some(TokenKind::Arg)) {
                    iter.next();
                }
            }
            TokenKind::Shellism => {
                // Drop shellisms; never useful in a sanitized pattern.
            }
            TokenKind::Arg => out.push(t),
        }
    }
    out
}

/// Build a sanitized command pattern from a raw shell command line.
///
/// Pipeline (see `docs/privacy-hardening-plan.md`):
/// 1. Trim whitespace.
/// 2. Strip `sudo` / `env VAR=val` / `VAR=val` prefixes.
/// 3. Tokenize the leftmost segment (ignore everything past the first `|`/`&&`/`||`/`;`).
/// 4. Drop redirects and shellisms.
/// 5. Normalize the command name: strip absolute path, lowercase.
/// 6. Look up command metadata.
/// 7. Walk tokens to capture up to `max_depth` non-flag subcommand tokens.
/// 8. Reject captured tokens that look like paths, IDs, or long fingerprints.
/// 9. Cap at 3 tokens total.
/// 10. Join with spaces.
/// 11. On any error path, return `"unknown"`.
pub fn build_cmd_pattern(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return FALLBACK.to_string();
    }

    let stripped = strip_env_prefix(trimmed);
    let cleaned = stripped.trim();
    if cleaned.is_empty() {
        return FALLBACK.to_string();
    }

    let tokens = leftmost_segment(tokenize(cleaned));
    if tokens.is_empty() {
        return FALLBACK.to_string();
    }

    let cmd_name = match normalize_cmd_name(&tokens[0].value) {
        Some(n) => n,
        None => return FALLBACK.to_string(),
    };

    let mut out: Vec<String> = vec![cmd_name.clone()];
    let meta = lookup_meta(&cmd_name);
    let max_depth = meta.map(|m| m.max_depth).unwrap_or(0);

    if max_depth == 0 && meta.is_none_or(|m| !m.module_dash_m && !m.compose_subcmd) {
        return out.join(" ");
    }

    let mut captured = 0usize;
    let mut i = 1usize;
    while i < tokens.len() && captured < max_depth + module_or_compose_extra(meta) {
        let val = &tokens[i].value;

        if let Some(m) = meta {
            // Handle `python -m pkg` virtual subcommand.
            if m.module_dash_m && val == "-m" {
                if let Some(next) = tokens.get(i + 1) {
                    if token_passes_guard(&next.value) {
                        out.push(next.value.to_ascii_lowercase());
                        captured += 1;
                        i += 2;
                        continue;
                    }
                }
                break;
            }

            // Skip flags. If the flag consumes an argument, skip the next token too.
            if val.starts_with('-') {
                if m.flags_consume_arg.iter().any(|f| f == val) {
                    i += 2;
                } else {
                    i += 1;
                }
                continue;
            }
        } else if val.starts_with('-') {
            i += 1;
            continue;
        }

        // Compose handling: `docker compose <subcmd>` captures both tokens.
        if let Some(m) = meta {
            if m.compose_subcmd && captured == 0 && val == "compose" {
                out.push("compose".to_string());
                i += 1;
                // Consume any compose flags before the subcommand (e.g. `-f file`).
                while i < tokens.len() && tokens[i].value.starts_with('-') {
                    if matches!(tokens[i].value.as_str(), "-f" | "--file") {
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                if let Some(sub) = tokens.get(i) {
                    if token_passes_guard(&sub.value) {
                        out.push(sub.value.to_ascii_lowercase());
                    }
                }
                break;
            }
        }

        if !token_passes_guard(val) {
            break;
        }
        out.push(val.to_ascii_lowercase());
        captured += 1;
        i += 1;
    }

    if out.len() > MAX_PATTERN_TOKENS {
        out.truncate(MAX_PATTERN_TOKENS);
    }

    out.join(" ")
}

/// `python -m pytest` and `docker compose up` need one extra capture slot
/// beyond `max_depth` because the `-m`/`compose` token itself is not a flag
/// and counts toward the captured subcommands.
fn module_or_compose_extra(meta: Option<&CmdMeta>) -> usize {
    match meta {
        Some(m) if m.module_dash_m || m.compose_subcmd => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> String {
        build_cmd_pattern(s)
    }

    #[test]
    fn worked_examples_from_plan() {
        assert_eq!(p("git status"), "git status");
        assert_eq!(p("git -C /home/x status"), "git status");
        assert_eq!(p("AWS_SECRET=abc aws s3 ls s3://b/k"), "aws s3 ls");
        assert_eq!(p("cargo test foo::bar::baz"), "cargo test");
        // Hard cap is 3 tokens (cmd + 2 captured), so any further token is dropped
        // even if it would pass the guard. `gh pr view <n>` always collapses to
        // `gh pr view` regardless of `n`.
        assert_eq!(p("gh pr view 1234"), "gh pr view");
        assert_eq!(p("gh pr view 99"), "gh pr view");
        assert_eq!(p("kubectl -n prod get pods"), "kubectl get pods");
        assert_eq!(p("cat /etc/passwd"), "cat");
        assert_eq!(p("npm run build:prod"), "npm run");
        assert_eq!(p("docker compose up -d"), "docker compose up");
        assert_eq!(p("docker compose -f /tmp/x.yml up"), "docker compose up");
        assert_eq!(p("python -m pytest tests/"), "python pytest");
        assert_eq!(p("uv pip install requests"), "uv pip install");
        assert_eq!(p("/usr/local/bin/git status"), "git status");
        assert_eq!(p("source ./scripts/env.sh"), "source");
        assert_eq!(p("bash -c \"rm -rf /\""), "bash");
        assert_eq!(
            p("FOO=1 BAR=\"x y\" sudo env BAZ=2 git status"),
            "git status"
        );
        assert_eq!(p("git log | head -20"), "git log");
        assert_eq!(p("cargo test && git status"), "cargo test");
    }

    #[test]
    fn empty_and_whitespace() {
        assert_eq!(p(""), "unknown");
        assert_eq!(p("   "), "unknown");
        assert_eq!(p("\t\n  \t"), "unknown");
    }

    #[test]
    fn long_garbage_does_not_panic() {
        let garbage: String = "x".repeat(1000);
        let _ = p(&garbage);
        let with_ops: String = format!("{} && {}", "a".repeat(500), "b".repeat(500));
        let _ = p(&with_ops);
    }

    #[test]
    fn unknown_command_keeps_only_name() {
        assert_eq!(p("frobnicate --xyzzy"), "frobnicate");
        assert_eq!(p("totally-made-up sub /etc/passwd"), "totally-made-up");
    }

    #[test]
    fn redirects_dropped() {
        assert_eq!(p("git log > /tmp/out.txt"), "git log");
        assert_eq!(p("cargo build 2>&1"), "cargo build");
        assert_eq!(p("git status >> log.txt"), "git status");
    }

    #[test]
    fn absolute_path_normalization() {
        assert_eq!(p("/usr/bin/grep foo bar"), "grep");
        assert_eq!(p("/opt/homebrew/bin/cargo test"), "cargo test");
    }

    #[test]
    fn case_normalization() {
        assert_eq!(p("Git Status"), "git status");
        assert_eq!(p("CARGO TEST"), "cargo test");
    }

    #[test]
    fn token_guard_rejects_paths() {
        assert!(!token_passes_guard("/etc/passwd"));
        assert!(!token_passes_guard("./file"));
        assert!(!token_passes_guard("../parent"));
        assert!(!token_passes_guard("~/home"));
        assert!(!token_passes_guard("path/with/slash"));
        assert!(!token_passes_guard("key=value"));
        assert!(!token_passes_guard("ns:resource"));
    }

    #[test]
    fn token_guard_rejects_long_tokens() {
        assert!(!token_passes_guard(&"x".repeat(25)));
        assert!(token_passes_guard(&"x".repeat(24)));
    }

    #[test]
    fn token_guard_rejects_hex_hashes() {
        assert!(!token_passes_guard("abc1234"));
        assert!(!token_passes_guard("deadbeef"));
        assert!(token_passes_guard("abc")); // too short
    }

    #[test]
    fn token_guard_rejects_digit_runs() {
        assert!(!token_passes_guard("issue1234"));
        assert!(!token_passes_guard("1234"));
        assert!(token_passes_guard("issue12"));
        assert!(token_passes_guard("v1"));
    }

    #[test]
    fn token_guard_accepts_short_words() {
        assert!(token_passes_guard("status"));
        assert!(token_passes_guard("test"));
        assert!(token_passes_guard("pr"));
        assert!(token_passes_guard("install"));
    }

    #[test]
    fn flag_consume_arg() {
        assert_eq!(p("git -C /tmp status"), "git status");
        assert_eq!(p("kubectl --namespace prod get pods"), "kubectl get pods");
        assert_eq!(p("aws --region us-east-1 s3 ls"), "aws s3 ls");
        assert_eq!(
            p("cargo --manifest-path /path/Cargo.toml test"),
            "cargo test"
        );
    }

    #[test]
    fn pipe_drops_rest() {
        assert_eq!(p("ls | wc -l"), "ls");
        assert_eq!(p("cat /etc/passwd | grep root"), "cat");
    }

    #[test]
    fn operators_drop_rest() {
        assert_eq!(p("git pull && cargo build"), "git pull");
        assert_eq!(p("test || echo fail"), "test");
        assert_eq!(p("cd /tmp ; ls"), "cd");
    }

    #[test]
    fn module_dash_m_pytest() {
        assert_eq!(p("python -m pytest tests/"), "python pytest");
        assert_eq!(p("python3 -m mypy ./src"), "python3 mypy");
        assert_eq!(p("python -m"), "python"); // no module follows
    }

    #[test]
    fn docker_compose_capture() {
        assert_eq!(p("docker compose up"), "docker compose up");
        assert_eq!(p("docker compose down"), "docker compose down");
        assert_eq!(p("docker compose -f /tmp/x.yml up"), "docker compose up");
        // Without 'compose', normal docker behavior applies.
        assert_eq!(p("docker ps -a"), "docker ps");
    }

    #[test]
    fn unicode_does_not_panic() {
        let _ = p("git status héllo");
        let _ = p("café noir");
        let _ = p("日本語");
    }

    #[test]
    fn fuzz_no_panic_random_bytes() {
        // Hand-rolled deterministic LCG so the test is reproducible without proptest.
        let mut state: u64 = 0xdead_beef_cafe_babe;
        for _ in 0..1000 {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let len = (state >> 56) as usize % 200;
            let mut bytes = Vec::with_capacity(len);
            for _ in 0..len {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                // Bias toward ASCII shell metachars to stress the lexer and guard.
                let pool = b" \t&|;<>'\"\\$()`*?abcdefghij0123456789-_=/\n";
                bytes.push(pool[(state >> 50) as usize % pool.len()]);
            }
            let s = String::from_utf8_lossy(&bytes);
            let result = build_cmd_pattern(&s);
            assert!(!result.is_empty(), "pattern must never be empty");
        }
    }

    #[test]
    fn always_returns_non_empty() {
        for input in &[
            "",
            "   ",
            "\0",
            "\n",
            "&&",
            "||",
            "|",
            ";",
            ">",
            "<",
            "a b c d e f g h i j k l m n",
            "VAR=value",
            "sudo",
            "env",
        ] {
            let r = build_cmd_pattern(input);
            assert!(!r.is_empty(), "empty result for {:?}", input);
        }
    }

    #[test]
    fn cap_at_three_tokens() {
        // `git log show diff` would parse to 4 tokens, but max_depth=2 limits to 3.
        let r = p("git log oneline extra-token");
        let count = r.split_whitespace().count();
        assert!(
            count <= MAX_PATTERN_TOKENS,
            "expected ≤3 tokens, got: {}",
            r
        );
    }

    #[test]
    fn npm_run_script_collapses() {
        assert_eq!(p("npm run test:unit"), "npm run");
        assert_eq!(p("pnpm run build"), "pnpm run build");
        assert_eq!(p("pnpm install"), "pnpm install");
    }

    #[test]
    fn gh_pr_view_caps_at_three_tokens() {
        // The 3-token cap means PR numbers never make it into the pattern,
        // regardless of length. This is intentional: a stable cap is easier
        // to reason about than per-command exceptions.
        assert_eq!(p("gh pr view 12"), "gh pr view");
        assert_eq!(p("gh pr view 9999"), "gh pr view");
    }

    #[test]
    fn aws_with_secret_env() {
        assert_eq!(
            p("AWS_ACCESS_KEY_ID=AKIA1234 AWS_SECRET_ACCESS_KEY=verysecret aws s3 ls"),
            "aws s3 ls"
        );
    }

    #[test]
    fn drift_prevention_every_rule_prefix_is_classified() {
        // Every command name appearing as a `rewrite_prefixes` entry in
        // `src/discover/rules.rs` must either be in `CMD_META` or be in the
        // explicit `INTENTIONALLY_UNCLASSIFIED` list. New rewrite rules without
        // a metadata decision will fail this test — that is intentional.
        use crate::discover::rules::RULES;

        let mut missing = Vec::new();
        for rule in RULES {
            for prefix in rule.rewrite_prefixes {
                let first = prefix.split_whitespace().next().unwrap_or("");
                if first.is_empty() {
                    continue;
                }
                // `bin/rake` etc. — Path::file_name strips the bin/ prefix when it
                // appears as an absolute path; here we look at the leading word.
                let name = first.rsplit('/').next().unwrap_or(first);
                let known = CMD_META.iter().any(|m| m.name == name)
                    || INTENTIONALLY_UNCLASSIFIED.contains(&name);
                if !known {
                    missing.push(name.to_string());
                }
            }
        }
        missing.sort();
        missing.dedup();
        assert!(
            missing.is_empty(),
            "These rule prefixes need a CMD_META entry or INTENTIONALLY_UNCLASSIFIED listing: {:?}",
            missing
        );
    }
}
