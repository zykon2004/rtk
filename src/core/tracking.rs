//! Token savings tracking and analytics system.
//!
//! This module provides comprehensive tracking of RTK command executions,
//! recording token savings, execution times, and providing aggregation APIs
//! for daily/weekly/monthly statistics.
//!
//! # Architecture
//!
//! - Storage: SQLite database (~/.local/share/rtk/tracking.db)
//! - Retention: 90-day automatic cleanup
//! - Metrics: Input/output tokens, savings %, execution time
//!
//! # Quick Start
//!
//! ```no_run
//! use rtk::tracking::{TimedExecution, Tracker};
//!
//! // Track a command execution
//! let timer = TimedExecution::start();
//! let input = "raw output";
//! let output = "filtered output";
//! timer.track("ls -la", "rtk ls", input, output);
//!
//! // Query statistics
//! let tracker = Tracker::new().unwrap();
//! let summary = tracker.get_summary().unwrap();
//! println!("Saved {} tokens", summary.total_saved);
//! ```
//!
//! # Privacy
//!
//! The raw command line is **never** persisted. `Tracker::record` and
//! `record_parse_failure` both pass their input through `build_cmd_pattern`
//! before storage; only an aggregate, paths-and-identifiers-stripped
//! `cmd_pattern` (e.g. `git status`, `npm run`, `aws s3 ls`) reaches disk.
//!
//! See [docs/tracking.md](../docs/tracking.md) for full documentation.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OpenFlags};
use serde::Serialize;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Instant;

use super::cmd_pattern::build_cmd_pattern;

/// Schema version — bumped when persisted columns change in a privacy-relevant way.
/// `Tracker::new()` rebuilds the DB from scratch when `PRAGMA user_version` is below this.
const SCHEMA_VERSION: i32 = 1;

// ── Project path helpers ── // added: project-scoped tracking support

/// Get the canonical project path string for the current working directory.
fn current_project_path_string() -> String {
    std::env::current_dir()
        .ok()
        .and_then(|p| p.canonicalize().ok())
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default()
}

/// Build SQL filter params for project-scoped queries.
/// Returns (exact_match, glob_prefix) for WHERE clause.
/// Uses GLOB instead of LIKE to avoid `_` and `%` in paths acting as wildcards. // changed: GLOB
fn project_filter_params(project_path: Option<&str>) -> (Option<String>, Option<String>) {
    match project_path {
        Some(p) => (
            Some(p.to_string()),
            Some(format!("{}{}*", p, std::path::MAIN_SEPARATOR)), // changed: GLOB pattern with * wildcard
        ),
        None => (None, None),
    }
}

use super::constants::{DEFAULT_HISTORY_DAYS, HISTORY_DB, RTK_DATA_DIR};

/// Main tracking interface for recording and querying command history.
///
/// Manages SQLite database connection and provides methods for:
/// - Recording command executions with token counts and timing
/// - Querying aggregated statistics (summary, daily, weekly, monthly)
/// - Retrieving recent command history
///
/// # Database Location
///
/// - Linux: `~/.local/share/rtk/tracking.db`
/// - macOS: `~/Library/Application Support/rtk/tracking.db`
/// - Windows: `%APPDATA%\rtk\tracking.db`
///
/// # Examples
///
/// ```no_run
/// use rtk::tracking::Tracker;
///
/// let tracker = Tracker::new()?;
/// tracker.record("ls -la", false, 1000, 200, 50)?;
///
/// let summary = tracker.get_summary()?;
/// println!("Total saved: {} tokens", summary.total_saved);
/// # Ok::<(), anyhow::Error>(())
/// ```
pub struct Tracker {
    conn: Connection,
}

/// Individual command record from tracking history.
///
/// Contains timestamp, sanitized command pattern, and savings metrics for a
/// single execution. The pattern is derived from the raw command line by
/// `build_cmd_pattern` and never contains file paths, identifiers, or secrets.
#[derive(Debug)]
pub struct CommandRecord {
    /// UTC timestamp when command was executed
    pub timestamp: DateTime<Utc>,
    /// Sanitized command pattern (e.g., "git status", "npm run", "aws s3 ls")
    pub cmd_pattern: String,
    /// `true` if the command went through the passthrough fallback path.
    /// Currently used in tests; reserved for future renderer use (e.g. tagging
    /// passthrough rows in `rtk gain --history`).
    #[allow(dead_code)]
    pub is_passthrough: bool,
    /// Number of tokens saved (input - output)
    pub saved_tokens: usize,
    /// Savings percentage ((saved / input) * 100)
    pub savings_pct: f64,
}

/// Aggregated statistics across all recorded commands.
///
/// Provides overall metrics and breakdowns by command and by day.
/// Returned by [`Tracker::get_summary`].
#[derive(Debug)]
pub struct GainSummary {
    /// Total number of commands recorded
    pub total_commands: usize,
    /// Total input tokens across all commands
    pub total_input: usize,
    /// Total output tokens across all commands
    pub total_output: usize,
    /// Total tokens saved (input - output)
    pub total_saved: usize,
    /// Average savings percentage across all commands
    pub avg_savings_pct: f64,
    /// Total execution time across all commands (milliseconds)
    pub total_time_ms: u64,
    /// Average execution time per command (milliseconds)
    pub avg_time_ms: u64,
    /// Top 10 commands by tokens saved: (cmd, count, saved, avg_pct, avg_time_ms)
    pub by_command: Vec<(String, usize, usize, f64, u64)>,
    /// Last 30 days of activity: (date, saved_tokens)
    pub by_day: Vec<(String, usize)>,
}

/// Daily statistics for token savings and execution metrics.
///
/// Serializable to JSON for export via `rtk gain --daily --format json`.
///
/// # JSON Schema
///
/// ```json
/// {
///   "date": "2026-02-03",
///   "commands": 42,
///   "input_tokens": 15420,
///   "output_tokens": 3842,
///   "saved_tokens": 11578,
///   "savings_pct": 75.08,
///   "total_time_ms": 8450,
///   "avg_time_ms": 201
/// }
/// ```
#[derive(Debug, Serialize)]
pub struct DayStats {
    /// ISO date (YYYY-MM-DD)
    pub date: String,
    /// Number of commands executed this day
    pub commands: usize,
    /// Total input tokens for this day
    pub input_tokens: usize,
    /// Total output tokens for this day
    pub output_tokens: usize,
    /// Total tokens saved this day
    pub saved_tokens: usize,
    /// Savings percentage for this day
    pub savings_pct: f64,
    /// Total execution time for this day (milliseconds)
    pub total_time_ms: u64,
    /// Average execution time per command (milliseconds)
    pub avg_time_ms: u64,
}

/// Weekly statistics for token savings and execution metrics.
///
/// Serializable to JSON for export via `rtk gain --weekly --format json`.
/// Weeks start on Sunday (SQLite default).
#[derive(Debug, Serialize)]
pub struct WeekStats {
    /// Week start date (YYYY-MM-DD)
    pub week_start: String,
    /// Week end date (YYYY-MM-DD)
    pub week_end: String,
    /// Number of commands executed this week
    pub commands: usize,
    /// Total input tokens for this week
    pub input_tokens: usize,
    /// Total output tokens for this week
    pub output_tokens: usize,
    /// Total tokens saved this week
    pub saved_tokens: usize,
    /// Savings percentage for this week
    pub savings_pct: f64,
    /// Total execution time for this week (milliseconds)
    pub total_time_ms: u64,
    /// Average execution time per command (milliseconds)
    pub avg_time_ms: u64,
}

/// Monthly statistics for token savings and execution metrics.
///
/// Serializable to JSON for export via `rtk gain --monthly --format json`.
#[derive(Debug, Serialize)]
pub struct MonthStats {
    /// Month identifier (YYYY-MM)
    pub month: String,
    /// Number of commands executed this month
    pub commands: usize,
    /// Total input tokens for this month
    pub input_tokens: usize,
    /// Total output tokens for this month
    pub output_tokens: usize,
    /// Total tokens saved this month
    pub saved_tokens: usize,
    /// Savings percentage for this month
    pub savings_pct: f64,
    /// Total execution time for this month (milliseconds)
    pub total_time_ms: u64,
    /// Average execution time per command (milliseconds)
    pub avg_time_ms: u64,
}

/// Type alias for command statistics tuple: (command, count, saved_tokens, avg_savings_pct, avg_time_ms)
type CommandStats = (String, usize, usize, f64, u64);

impl Tracker {
    /// Create a new tracker instance.
    ///
    /// Opens or creates the SQLite database at the platform-specific location.
    /// Automatically creates the `commands` table if it doesn't exist and runs
    /// any necessary schema migrations.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Cannot determine database path
    /// - Cannot create parent directories
    /// - Cannot open/create SQLite database
    /// - Schema creation/migration fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rtk::tracking::Tracker;
    ///
    /// let tracker = Tracker::new()?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn new() -> Result<Self> {
        let db_path = get_db_path()?;
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Privacy migration: if the existing DB predates the cmd_pattern schema,
        // rebuild it from scratch. The legacy DB contained raw command lines;
        // we explicitly forfeit that history rather than try to redact it
        // (legacy plaintext can also linger in WAL/SHM sidecar files).
        if db_path.exists() {
            let current = read_user_version(&db_path).unwrap_or(0);
            if current < SCHEMA_VERSION {
                migrate_to_v1(&db_path).context("Privacy migration of tracking DB failed")?;
            }
        }

        let conn = Connection::open(&db_path)?;
        // WAL mode + busy_timeout for concurrent access (multiple Claude Code instances).
        // Non-fatal: NFS/read-only filesystems may not support WAL.
        let _ = conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA busy_timeout=5000;",
        );

        create_tables_v1(&conn)?;

        // Stamp the schema version. Idempotent.
        let v: i32 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap_or(0);
        if v < SCHEMA_VERSION {
            conn.execute_batch(&format!("PRAGMA user_version = {};", SCHEMA_VERSION))?;
        }

        Ok(Self { conn })
    }

    /// Record a command execution with token counts and timing.
    ///
    /// Calculates savings metrics and stores the record in the database.
    /// Automatically cleans up records older than 90 days after insertion.
    ///
    /// # Arguments
    ///
    /// - `raw_command`: The original command line (sanitized before storage)
    /// - `is_passthrough`: `true` if the command went through the fallback path
    /// - `input_tokens`: Estimated tokens from standard command output
    /// - `output_tokens`: Actual tokens from RTK output
    /// - `exec_time_ms`: Execution time in milliseconds
    ///
    /// `raw_command` is sanitized via `build_cmd_pattern` before storage — the
    /// raw text never reaches disk.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rtk::tracking::Tracker;
    ///
    /// let tracker = Tracker::new()?;
    /// tracker.record("ls -la", false, 1000, 200, 50)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn record(
        &self,
        raw_command: &str,
        is_passthrough: bool,
        input_tokens: usize,
        output_tokens: usize,
        exec_time_ms: u64,
    ) -> Result<()> {
        let saved = input_tokens.saturating_sub(output_tokens);
        let pct = if input_tokens > 0 {
            (saved as f64 / input_tokens as f64) * 100.0
        } else {
            0.0
        };

        let project_path = current_project_path_string();
        let cmd_pattern = build_cmd_pattern(raw_command);

        self.conn.execute(
            "INSERT INTO commands (timestamp, cmd_pattern, is_passthrough, project_path, input_tokens, output_tokens, saved_tokens, savings_pct, exec_time_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                Utc::now().to_rfc3339(),
                cmd_pattern,
                is_passthrough as i32,
                project_path,
                input_tokens as i64,
                output_tokens as i64,
                saved as i64,
                pct,
                exec_time_ms as i64
            ],
        )?;

        self.cleanup_old()?;
        Ok(())
    }

    fn cleanup_old(&self) -> Result<()> {
        let cutoff = Utc::now() - chrono::Duration::days(DEFAULT_HISTORY_DAYS);
        self.conn.execute(
            "DELETE FROM commands WHERE timestamp < ?1",
            params![cutoff.to_rfc3339()],
        )?;
        self.conn.execute(
            "DELETE FROM parse_failures WHERE timestamp < ?1",
            params![cutoff.to_rfc3339()],
        )?;
        Ok(())
    }

    /// Record a parse failure for analytics.
    ///
    /// `raw_command` is sanitized via `build_cmd_pattern` before storage.
    pub fn record_parse_failure(
        &self,
        raw_command: &str,
        error_message: &str,
        fallback_succeeded: bool,
    ) -> Result<()> {
        let cmd_pattern = build_cmd_pattern(raw_command);
        self.conn.execute(
            "INSERT INTO parse_failures (timestamp, cmd_pattern, error_message, fallback_succeeded)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                Utc::now().to_rfc3339(),
                cmd_pattern,
                error_message,
                fallback_succeeded as i32,
            ],
        )?;
        self.cleanup_old()?;
        Ok(())
    }

    /// Get parse failure summary for `rtk gain --failures`.
    pub fn get_parse_failure_summary(&self) -> Result<ParseFailureSummary> {
        let total: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM parse_failures", [], |row| row.get(0))?;

        let succeeded: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM parse_failures WHERE fallback_succeeded = 1",
            [],
            |row| row.get(0),
        )?;

        let recovery_rate = if total > 0 {
            (succeeded as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        // Top commands by frequency
        let mut stmt = self.conn.prepare(
            "SELECT cmd_pattern, COUNT(*) as cnt
             FROM parse_failures
             GROUP BY cmd_pattern
             ORDER BY cnt DESC
             LIMIT 10",
        )?;
        let top_commands = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as usize))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        // Recent 10
        let mut stmt = self.conn.prepare(
            "SELECT timestamp, cmd_pattern, error_message, fallback_succeeded
             FROM parse_failures
             ORDER BY timestamp DESC
             LIMIT 10",
        )?;
        let recent = stmt
            .query_map([], |row| {
                Ok(ParseFailureRecord {
                    timestamp: row.get(0)?,
                    cmd_pattern: row.get(1)?,
                    error_message: row.get(2)?,
                    fallback_succeeded: row.get::<_, i32>(3)? != 0,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(ParseFailureSummary {
            total: total as usize,
            recovery_rate,
            top_commands,
            recent,
        })
    }

    /// Get overall summary statistics across all recorded commands.
    ///
    /// Returns aggregated metrics including:
    /// - Total commands, tokens (input/output/saved)
    /// - Average savings percentage and execution time
    /// - Top 10 commands by tokens saved
    /// - Last 30 days of activity
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rtk::tracking::Tracker;
    ///
    /// let tracker = Tracker::new()?;
    /// let summary = tracker.get_summary()?;
    /// println!("Saved {} tokens ({:.1}%)",
    ///     summary.total_saved, summary.avg_savings_pct);
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    #[allow(dead_code)]
    pub fn get_summary(&self) -> Result<GainSummary> {
        self.get_summary_filtered(None) // delegate to filtered variant
    }

    /// Get summary statistics filtered by project path. // added
    ///
    /// When `project_path` is `Some`, matches the exact working directory
    /// or any subdirectory (prefix match with path separator).
    pub fn get_summary_filtered(&self, project_path: Option<&str>) -> Result<GainSummary> {
        let (project_exact, project_glob) = project_filter_params(project_path); // added
        let mut total_commands = 0usize;
        let mut total_input = 0usize;
        let mut total_output = 0usize;
        let mut total_saved = 0usize;
        let mut total_time_ms = 0u64;

        let mut stmt = self.conn.prepare(
            "SELECT input_tokens, output_tokens, saved_tokens, exec_time_ms
             FROM commands
             WHERE (?1 IS NULL OR project_path = ?1 OR project_path GLOB ?2)", // added: project filter
        )?;

        let rows = stmt.query_map(params![project_exact, project_glob], |row| {
            // added: params
            Ok((
                row.get::<_, i64>(0)? as usize,
                row.get::<_, i64>(1)? as usize,
                row.get::<_, i64>(2)? as usize,
                row.get::<_, i64>(3)? as u64,
            ))
        })?;

        for row in rows {
            let (input, output, saved, time_ms) = row?;
            total_commands += 1;
            total_input += input;
            total_output += output;
            total_saved += saved;
            total_time_ms += time_ms;
        }

        let avg_savings_pct = if total_input > 0 {
            (total_saved as f64 / total_input as f64) * 100.0
        } else {
            0.0
        };

        let avg_time_ms = if total_commands > 0 {
            total_time_ms / total_commands as u64
        } else {
            0
        };

        let by_command = self.get_by_command(project_path)?; // added: pass project filter
        let by_day = self.get_by_day(project_path)?; // added: pass project filter

        Ok(GainSummary {
            total_commands,
            total_input,
            total_output,
            total_saved,
            avg_savings_pct,
            total_time_ms,
            avg_time_ms,
            by_command,
            by_day,
        })
    }

    fn get_by_command(
        &self,
        project_path: Option<&str>, // added
    ) -> Result<Vec<CommandStats>> {
        let (project_exact, project_glob) = project_filter_params(project_path); // added
        let mut stmt = self.conn.prepare(
            "SELECT cmd_pattern, COUNT(*), SUM(saved_tokens), AVG(savings_pct), AVG(exec_time_ms)
             FROM commands
             WHERE (?1 IS NULL OR project_path = ?1 OR project_path GLOB ?2)
             GROUP BY cmd_pattern
             ORDER BY SUM(saved_tokens) DESC
             LIMIT 10", // added: project filter in WHERE
        )?;

        let rows = stmt.query_map(params![project_exact, project_glob], |row| {
            // added: params
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)? as usize,
                row.get::<_, i64>(2)? as usize,
                row.get::<_, f64>(3)?,
                row.get::<_, f64>(4)? as u64,
            ))
        })?;

        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    fn get_by_day(
        &self,
        project_path: Option<&str>, // added
    ) -> Result<Vec<(String, usize)>> {
        let (project_exact, project_glob) = project_filter_params(project_path); // added
        let mut stmt = self.conn.prepare(
            "SELECT DATE(timestamp), SUM(saved_tokens)
             FROM commands
             WHERE (?1 IS NULL OR project_path = ?1 OR project_path GLOB ?2)
             GROUP BY DATE(timestamp)
             ORDER BY DATE(timestamp) DESC
             LIMIT 30", // added: project filter in WHERE
        )?;

        let rows = stmt.query_map(params![project_exact, project_glob], |row| {
            // added: params
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as usize))
        })?;

        let mut result: Vec<_> = rows.collect::<Result<Vec<_>, _>>()?;
        result.reverse();
        Ok(result)
    }

    /// Get daily statistics for all recorded days.
    ///
    /// Returns one [`DayStats`] per day with commands executed, tokens saved,
    /// and execution time metrics. Results are ordered chronologically (oldest first).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rtk::tracking::Tracker;
    ///
    /// let tracker = Tracker::new()?;
    /// let days = tracker.get_all_days()?;
    /// for day in days.iter().take(7) {
    ///     println!("{}: {} commands, {} tokens saved",
    ///         day.date, day.commands, day.saved_tokens);
    /// }
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn get_all_days(&self) -> Result<Vec<DayStats>> {
        self.get_all_days_filtered(None) // delegate to filtered variant
    }

    /// Get daily statistics filtered by project path. // added
    pub fn get_all_days_filtered(&self, project_path: Option<&str>) -> Result<Vec<DayStats>> {
        let (project_exact, project_glob) = project_filter_params(project_path); // added
        let mut stmt = self.conn.prepare(
            "SELECT
                DATE(timestamp) as date,
                COUNT(*) as commands,
                SUM(input_tokens) as input,
                SUM(output_tokens) as output,
                SUM(saved_tokens) as saved,
                SUM(exec_time_ms) as total_time
             FROM commands
             WHERE (?1 IS NULL OR project_path = ?1 OR project_path GLOB ?2)
             GROUP BY DATE(timestamp)
             ORDER BY DATE(timestamp) DESC", // added: project filter
        )?;

        let rows = stmt.query_map(params![project_exact, project_glob], |row| {
            // added: params
            let input = row.get::<_, i64>(2)? as usize;
            let saved = row.get::<_, i64>(4)? as usize;
            let commands = row.get::<_, i64>(1)? as usize;
            let total_time = row.get::<_, i64>(5)? as u64;
            let savings_pct = if input > 0 {
                (saved as f64 / input as f64) * 100.0
            } else {
                0.0
            };
            let avg_time_ms = if commands > 0 {
                total_time / commands as u64
            } else {
                0
            };

            Ok(DayStats {
                date: row.get(0)?,
                commands,
                input_tokens: input,
                output_tokens: row.get::<_, i64>(3)? as usize,
                saved_tokens: saved,
                savings_pct,
                total_time_ms: total_time,
                avg_time_ms,
            })
        })?;

        let mut result: Vec<_> = rows.collect::<Result<Vec<_>, _>>()?;
        result.reverse();
        Ok(result)
    }

    /// Get weekly statistics grouped by week.
    ///
    /// Returns one [`WeekStats`] per week with aggregated metrics.
    /// Weeks start on Sunday (SQLite default). Results ordered chronologically.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rtk::tracking::Tracker;
    ///
    /// let tracker = Tracker::new()?;
    /// let weeks = tracker.get_by_week()?;
    /// for week in weeks {
    ///     println!("{} to {}: {} tokens saved",
    ///         week.week_start, week.week_end, week.saved_tokens);
    /// }
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn get_by_week(&self) -> Result<Vec<WeekStats>> {
        self.get_by_week_filtered(None) // delegate to filtered variant
    }

    /// Get weekly statistics filtered by project path. // added
    pub fn get_by_week_filtered(&self, project_path: Option<&str>) -> Result<Vec<WeekStats>> {
        let (project_exact, project_glob) = project_filter_params(project_path); // added
        let mut stmt = self.conn.prepare(
            "SELECT
                DATE(timestamp, 'weekday 0', '-6 days') as week_start,
                DATE(timestamp, 'weekday 0') as week_end,
                COUNT(*) as commands,
                SUM(input_tokens) as input,
                SUM(output_tokens) as output,
                SUM(saved_tokens) as saved,
                SUM(exec_time_ms) as total_time
             FROM commands
             WHERE (?1 IS NULL OR project_path = ?1 OR project_path GLOB ?2)
             GROUP BY week_start
             ORDER BY week_start DESC", // added: project filter
        )?;

        let rows = stmt.query_map(params![project_exact, project_glob], |row| {
            // added: params
            let input = row.get::<_, i64>(3)? as usize;
            let saved = row.get::<_, i64>(5)? as usize;
            let commands = row.get::<_, i64>(2)? as usize;
            let total_time = row.get::<_, i64>(6)? as u64;
            let savings_pct = if input > 0 {
                (saved as f64 / input as f64) * 100.0
            } else {
                0.0
            };
            let avg_time_ms = if commands > 0 {
                total_time / commands as u64
            } else {
                0
            };

            Ok(WeekStats {
                week_start: row.get(0)?,
                week_end: row.get(1)?,
                commands,
                input_tokens: input,
                output_tokens: row.get::<_, i64>(4)? as usize,
                saved_tokens: saved,
                savings_pct,
                total_time_ms: total_time,
                avg_time_ms,
            })
        })?;

        let mut result: Vec<_> = rows.collect::<Result<Vec<_>, _>>()?;
        result.reverse();
        Ok(result)
    }

    /// Get monthly statistics grouped by month.
    ///
    /// Returns one [`MonthStats`] per month (YYYY-MM format) with aggregated metrics.
    /// Results ordered chronologically.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rtk::tracking::Tracker;
    ///
    /// let tracker = Tracker::new()?;
    /// let months = tracker.get_by_month()?;
    /// for month in months {
    ///     println!("{}: {} tokens saved ({:.1}%)",
    ///         month.month, month.saved_tokens, month.savings_pct);
    /// }
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn get_by_month(&self) -> Result<Vec<MonthStats>> {
        self.get_by_month_filtered(None) // delegate to filtered variant
    }

    /// Get monthly statistics filtered by project path. // added
    pub fn get_by_month_filtered(&self, project_path: Option<&str>) -> Result<Vec<MonthStats>> {
        let (project_exact, project_glob) = project_filter_params(project_path); // added
        let mut stmt = self.conn.prepare(
            "SELECT
                strftime('%Y-%m', timestamp) as month,
                COUNT(*) as commands,
                SUM(input_tokens) as input,
                SUM(output_tokens) as output,
                SUM(saved_tokens) as saved,
                SUM(exec_time_ms) as total_time
             FROM commands
             WHERE (?1 IS NULL OR project_path = ?1 OR project_path GLOB ?2)
             GROUP BY month
             ORDER BY month DESC", // added: project filter
        )?;

        let rows = stmt.query_map(params![project_exact, project_glob], |row| {
            // added: params
            let input = row.get::<_, i64>(2)? as usize;
            let saved = row.get::<_, i64>(4)? as usize;
            let commands = row.get::<_, i64>(1)? as usize;
            let total_time = row.get::<_, i64>(5)? as u64;
            let savings_pct = if input > 0 {
                (saved as f64 / input as f64) * 100.0
            } else {
                0.0
            };
            let avg_time_ms = if commands > 0 {
                total_time / commands as u64
            } else {
                0
            };

            Ok(MonthStats {
                month: row.get(0)?,
                commands,
                input_tokens: input,
                output_tokens: row.get::<_, i64>(3)? as usize,
                saved_tokens: saved,
                savings_pct,
                total_time_ms: total_time,
                avg_time_ms,
            })
        })?;

        let mut result: Vec<_> = rows.collect::<Result<Vec<_>, _>>()?;
        result.reverse();
        Ok(result)
    }

    /// Get recent command history.
    ///
    /// Returns up to `limit` most recent command records, ordered by timestamp (newest first).
    ///
    /// # Arguments
    ///
    /// - `limit`: Maximum number of records to return
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rtk::tracking::Tracker;
    ///
    /// let tracker = Tracker::new()?;
    /// let recent = tracker.get_recent(10)?;
    /// for cmd in recent {
    ///     println!("{}: {} saved {:.1}%",
    ///         cmd.timestamp, cmd.cmd_pattern, cmd.savings_pct);
    /// }
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    #[allow(dead_code)]
    pub fn get_recent(&self, limit: usize) -> Result<Vec<CommandRecord>> {
        self.get_recent_filtered(limit, None) // delegate to filtered variant
    }

    /// Get recent command history filtered by project path. // added
    pub fn get_recent_filtered(
        &self,
        limit: usize,
        project_path: Option<&str>,
    ) -> Result<Vec<CommandRecord>> {
        let (project_exact, project_glob) = project_filter_params(project_path); // added
        let mut stmt = self.conn.prepare(
            "SELECT timestamp, cmd_pattern, is_passthrough, saved_tokens, savings_pct
             FROM commands
             WHERE (?1 IS NULL OR project_path = ?1 OR project_path GLOB ?2)
             ORDER BY timestamp DESC
             LIMIT ?3", // added: project filter
        )?;

        let rows = stmt.query_map(
            params![project_exact, project_glob, limit as i64], // added: project params
            |row| {
                Ok(CommandRecord {
                    timestamp: DateTime::parse_from_rfc3339(&row.get::<_, String>(0)?)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                    cmd_pattern: row.get(1)?,
                    is_passthrough: row.get::<_, i32>(2)? != 0,
                    saved_tokens: row.get::<_, i64>(3)? as usize,
                    savings_pct: row.get(4)?,
                })
            },
        )?;

        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Count commands since a given timestamp.
    pub fn count_commands_since(&self, since: chrono::DateTime<chrono::Utc>) -> Result<i64> {
        let ts = since.format("%Y-%m-%dT%H:%M:%S").to_string();
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM commands WHERE timestamp >= ?1",
            params![ts],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    /// Get top N commands by frequency.
    pub fn top_commands(&self, limit: usize) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT cmd_pattern, COUNT(*) as cnt FROM commands
             GROUP BY cmd_pattern ORDER BY cnt DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            let cmd: String = row.get(0)?;
            // Extract just the command name (e.g. "git status" → "git")
            Ok(cmd.split_whitespace().next().unwrap_or(&cmd).to_string())
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    /// Get overall savings percentage.
    pub fn overall_savings_pct(&self) -> Result<f64> {
        let (total_input, total_saved): (i64, i64) = self.conn.query_row(
            "SELECT COALESCE(SUM(input_tokens), 0), COALESCE(SUM(saved_tokens), 0) FROM commands",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if total_input > 0 {
            Ok((total_saved as f64 / total_input as f64) * 100.0)
        } else {
            Ok(0.0)
        }
    }

    /// Get total tokens saved across all tracked commands.
    pub fn total_tokens_saved(&self) -> Result<i64> {
        let saved: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(saved_tokens), 0) FROM commands",
            [],
            |row| row.get(0),
        )?;
        Ok(saved)
    }

    /// Get tokens saved in the last 24 hours.
    pub fn tokens_saved_24h(&self, since: chrono::DateTime<chrono::Utc>) -> Result<i64> {
        let ts = since.format("%Y-%m-%dT%H:%M:%S").to_string();
        let saved: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(saved_tokens), 0) FROM commands WHERE timestamp >= ?1",
            params![ts],
            |row| row.get(0),
        )?;
        Ok(saved)
    }

    /// Top N passthrough commands — commands routed through the fallback path.
    /// Groups by first token of the sanitized command pattern.
    pub fn top_passthrough(&self, limit: usize) -> Result<Vec<(String, i64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT TRIM(SUBSTR(cmd_pattern, 1, INSTR(cmd_pattern || ' ', ' ') - 1)) as tool,
             COUNT(*) as cnt FROM commands
             WHERE is_passthrough = 1
             GROUP BY tool ORDER BY cnt DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            let cmd: String = row.get(0)?;
            let count: i64 = row.get(1)?;
            Ok((cmd, count))
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    /// Count parse failures in the last 24 hours.
    pub fn parse_failures_since(&self, since: chrono::DateTime<chrono::Utc>) -> Result<i64> {
        let ts = since.format("%Y-%m-%dT%H:%M:%S").to_string();
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM parse_failures WHERE timestamp >= ?1",
            params![ts],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    /// Count commands with low savings (<30%) — filters that need improvement.
    pub fn low_savings_commands(&self, limit: usize) -> Result<Vec<(String, f64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT cmd_pattern, AVG(savings_pct) as avg_sav FROM commands
             WHERE input_tokens > 0
             GROUP BY cmd_pattern
             HAVING avg_sav < 30.0 AND avg_sav > 0.0
             ORDER BY COUNT(*) DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            let cmd: String = row.get(0)?;
            let sav: f64 = row.get(1)?;
            Ok((cmd, sav))
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    /// Average savings percentage per command (unweighted — each command name counts once).
    pub fn avg_savings_per_command(&self) -> Result<f64> {
        let avg: f64 = self.conn.query_row(
            "SELECT COALESCE(AVG(avg_sav), 0.0) FROM (
                SELECT cmd_pattern, AVG(savings_pct) as avg_sav
                FROM commands WHERE input_tokens > 0
                GROUP BY cmd_pattern
            )",
            [],
            |row| row.get(0),
        )?;
        Ok(avg)
    }

    /// Count invocations of a specific meta-command (e.g. "gain", "discover").
    /// Matches rows whose `cmd_pattern` starts with the literal `rtk <name>`.
    pub fn count_meta_command(&self, name: &str) -> Result<i64> {
        // cmd_pattern's first token is the binary name. RTK records its own meta
        // commands as `rtk <subcmd>`; we filter by that prefix.
        let exact = format!("rtk {}", name);
        let prefix = format!("rtk {} ", name);
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM commands WHERE cmd_pattern = ?1 OR cmd_pattern LIKE ?2 || '%'",
            params![exact, prefix],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    /// Days since first recorded command (installation age).
    pub fn first_seen_days(&self) -> Result<i64> {
        let oldest: Option<String> =
            match self
                .conn
                .query_row("SELECT MIN(timestamp) FROM commands", [], |row| row.get(0))
            {
                Ok(v) => v,
                Err(rusqlite::Error::QueryReturnedNoRows) => None,
                Err(e) => return Err(anyhow::anyhow!("Failed to query first seen timestamp: {e}")),
            };
        match oldest {
            Some(ts) => {
                let first = chrono::NaiveDateTime::parse_from_str(&ts, "%Y-%m-%dT%H:%M:%S")
                    .or_else(|_| chrono::NaiveDateTime::parse_from_str(&ts, "%Y-%m-%d %H:%M:%S"))
                    .map(|dt| dt.and_utc())
                    .unwrap_or_else(|_| chrono::Utc::now());
                let days = (chrono::Utc::now() - first).num_days();
                Ok(days.max(0))
            }
            None => Ok(0),
        }
    }

    /// Number of distinct active days in the last 30 days.
    pub fn active_days_30d(&self) -> Result<i64> {
        let since = (chrono::Utc::now() - chrono::Duration::days(30))
            .format("%Y-%m-%dT%H:%M:%S")
            .to_string();
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(DISTINCT DATE(timestamp)) FROM commands WHERE timestamp >= ?1",
            params![since],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    /// Total number of recorded commands.
    pub fn commands_total(&self) -> Result<i64> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM commands", [], |row| row.get(0))?;
        Ok(count)
    }

    /// Ecosystem distribution as percentages (top categories by command prefix).
    pub fn ecosystem_mix(&self) -> Result<Vec<(String, f64)>> {
        let total: f64 = self.conn.query_row(
            "SELECT COUNT(*) FROM commands WHERE input_tokens > 0 AND timestamp >= datetime('now', '-90 days')",
            [],
            |row| row.get(0),
        )?;
        if total == 0.0 {
            return Ok(vec![]);
        }
        let mut stmt = self.conn.prepare(
            "SELECT cmd_pattern, COUNT(*) as cnt FROM commands
             WHERE input_tokens > 0 AND timestamp >= datetime('now', '-90 days')
             GROUP BY cmd_pattern ORDER BY cnt DESC",
        )?;
        let mut categories: std::collections::HashMap<String, f64> =
            std::collections::HashMap::new();
        let rows = stmt.query_map([], |row| {
            let cmd: String = row.get(0)?;
            let cnt: f64 = row.get(1)?;
            Ok((cmd, cnt))
        })?;
        for row in rows.flatten() {
            let cat = categorize_command(&row.0);
            *categories.entry(cat).or_default() += row.1;
        }
        let mut result: Vec<(String, f64)> = categories
            .into_iter()
            .map(|(cat, cnt)| (cat, (cnt / total * 100.0).round()))
            .collect();
        result.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        result.truncate(8);
        Ok(result)
    }

    /// Tokens saved in the last 30 days.
    pub fn tokens_saved_30d(&self) -> Result<i64> {
        let since = (chrono::Utc::now() - chrono::Duration::days(30))
            .format("%Y-%m-%dT%H:%M:%S")
            .to_string();
        let saved: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(saved_tokens), 0) FROM commands WHERE timestamp >= ?1",
            params![since],
            |row| row.get(0),
        )?;
        Ok(saved)
    }

    /// Number of distinct project paths.
    pub fn projects_count(&self) -> Result<i64> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(DISTINCT project_path) FROM commands WHERE project_path != ''",
            [],
            |row| row.get(0),
        )?;
        Ok(count)
    }
}

/// Map a sanitized cmd_pattern to an ecosystem category.
fn categorize_command(cmd_pattern: &str) -> String {
    // cmd_pattern always starts with the tool name (e.g. "git status", "npm run").
    let tool = cmd_pattern.split_whitespace().next().unwrap_or("other");
    match tool {
        "git" | "gh" | "gt" => "git",
        "cargo" => "cargo",
        "npm" | "npx" | "pnpm" | "vitest" | "tsc" | "lint" | "prettier" | "next" | "playwright"
        | "prisma" => "js",
        "pytest" | "ruff" | "mypy" | "pip" => "python",
        "go" | "golangci-lint" => "go",
        "docker" | "kubectl" => "cloud",
        "rspec" | "rubocop" | "rake" => "ruby",
        "dotnet" => "dotnet",
        "ls" | "tree" | "grep" | "find" | "wc" | "read" | "env" | "json" | "log" | "smart"
        | "diff" | "deps" | "summary" | "format" => "system",
        _ => "other",
    }
    .to_string()
}

/// Read `PRAGMA user_version` without taking a write lock or modifying the file.
fn read_user_version(path: &Path) -> Result<i32> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("Failed to open DB read-only: {}", path.display()))?;
    Ok(conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap_or(0))
}

/// Create the v1 schema in an open connection if not already present. Idempotent.
fn create_tables_v1(conn: &Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS commands (
            id INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
            cmd_pattern TEXT NOT NULL,
            is_passthrough INTEGER NOT NULL DEFAULT 0,
            input_tokens INTEGER NOT NULL,
            output_tokens INTEGER NOT NULL,
            saved_tokens INTEGER NOT NULL,
            savings_pct REAL NOT NULL,
            exec_time_ms INTEGER NOT NULL DEFAULT 0,
            project_path TEXT NOT NULL DEFAULT ''
        )",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_timestamp ON commands(timestamp)",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_project_path_timestamp ON commands(project_path, timestamp)",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_cmd_pattern ON commands(cmd_pattern)",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS parse_failures (
            id INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
            cmd_pattern TEXT NOT NULL,
            error_message TEXT NOT NULL,
            fallback_succeeded INTEGER NOT NULL DEFAULT 0
        )",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_pf_timestamp ON parse_failures(timestamp)",
        [],
    )?;
    Ok(())
}

/// Replace a legacy DB with a fresh v1 DB. The old contents — including raw
/// command lines that lingered in WAL/SHM sidecars — are forfeited, not migrated.
///
/// Strategy: build a fresh DB at a temp path, then atomically rename over the
/// existing one. On Unix this is fully atomic; on Windows we fall back to a
/// best-effort remove-and-rename if `MOVEFILE_REPLACE_EXISTING` is refused.
fn migrate_to_v1(db_path: &Path) -> Result<()> {
    let parent = db_path
        .parent()
        .context("DB path has no parent directory")?;

    let tmp_path = parent.join(format!("history.db.migrating-{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp_path);

    {
        let conn = Connection::open(&tmp_path)
            .with_context(|| format!("Failed to open temp DB: {}", tmp_path.display()))?;
        // DELETE journal mode for the migration step so we never leave a WAL
        // sidecar behind that could outlive the rename.
        conn.execute_batch("PRAGMA journal_mode=DELETE;")?;
        create_tables_v1(&conn)?;
        conn.execute_batch(&format!("PRAGMA user_version = {};", SCHEMA_VERSION))?;
    }

    if let Err(e) = std::fs::rename(&tmp_path, db_path) {
        #[cfg(windows)]
        {
            // Windows can refuse atomic replace under specific ACL/lock conditions.
            // Best-effort fallback: remove the destination and retry.
            let _ = std::fs::remove_file(db_path);
            std::fs::rename(&tmp_path, db_path).with_context(|| {
                format!("Windows fallback rename failed (after first error: {e})")
            })?;
        }
        #[cfg(not(windows))]
        {
            return Err(
                anyhow::Error::new(e).context("Atomic rename failed during privacy migration")
            );
        }
    }

    // Drop legacy WAL/SHM sidecars so plaintext from the old DB does not linger.
    let _ = std::fs::remove_file(parent.join("history.db-wal"));
    let _ = std::fs::remove_file(parent.join("history.db-shm"));

    Ok(())
}

/// Filename of the one-time announce sidecar (sits next to the tracking DB).
const ANNOUNCE_SIDECAR: &str = ".privacy_migration_announced_v1";

/// One-time user-facing migration notice.
///
/// Call this from `rtk gain`, `rtk init`, and `rtk verify` (user-facing entry
/// points only — never from the silent Bash-hook rewrite path). Prints once
/// per DB, recording acknowledgement via a sibling sidecar file.
///
/// Errors are swallowed: the notice is best-effort.
pub fn print_privacy_migration_notice_if_needed() {
    let db_path = match get_db_path() {
        Ok(p) => p,
        Err(_) => return,
    };
    let parent = match db_path.parent() {
        Some(p) => p,
        None => return,
    };
    if !db_path.exists() {
        return; // No DB yet -> nothing to announce.
    }
    let sidecar = parent.join(ANNOUNCE_SIDECAR);
    if sidecar.exists() {
        return;
    }
    // Only announce if the schema is at the privacy version (i.e. migration
    // either ran on this DB or it was created fresh under v1).
    let version = read_user_version(&db_path).unwrap_or(0);
    if version < SCHEMA_VERSION {
        return;
    }
    eprintln!(
        "rtk: privacy migration v1 applied — pre-existing tracking data was wiped (history.db rebuilt with sanitized command patterns)."
    );
    let _ = std::fs::write(&sidecar, b"v1\n");
}

fn get_db_path() -> Result<PathBuf> {
    // Priority 1: Environment variable RTK_DB_PATH
    if let Ok(custom_path) = std::env::var("RTK_DB_PATH") {
        return Ok(PathBuf::from(custom_path));
    }

    // Priority 2: Configuration file
    if let Ok(config) = crate::core::config::Config::load() {
        if let Some(db_path) = config.tracking.database_path {
            return Ok(db_path);
        }
    }

    // Priority 3: Default platform-specific location
    let data_dir = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
    Ok(data_dir.join(RTK_DATA_DIR).join(HISTORY_DB))
}

/// Individual parse failure record.
#[derive(Debug)]
pub struct ParseFailureRecord {
    pub timestamp: String,
    /// Sanitized command pattern (built from the raw command via `build_cmd_pattern`).
    pub cmd_pattern: String,
    #[allow(dead_code)]
    pub error_message: String,
    pub fallback_succeeded: bool,
}

/// Aggregated parse failure summary.
#[derive(Debug)]
pub struct ParseFailureSummary {
    pub total: usize,
    pub recovery_rate: f64,
    pub top_commands: Vec<(String, usize)>,
    pub recent: Vec<ParseFailureRecord>,
}

/// Record a parse failure without ever crashing.
/// Silently ignores all errors — used in the fallback path.
pub fn record_parse_failure_silent(raw_command: &str, error_message: &str, succeeded: bool) {
    if let Ok(tracker) = Tracker::new() {
        let _ = tracker.record_parse_failure(raw_command, error_message, succeeded);
    }
}

/// Estimate token count from text using ~4 chars = 1 token heuristic.
///
/// This is a fast approximation suitable for tracking purposes.
/// For precise counts, integrate with your LLM's tokenizer API.
///
/// # Formula
///
/// `tokens = ceil(chars / 4)`
///
/// # Examples
///
/// ```
/// use rtk::tracking::estimate_tokens;
///
/// assert_eq!(estimate_tokens(""), 0);
/// assert_eq!(estimate_tokens("abcd"), 1);  // 4 chars = 1 token
/// assert_eq!(estimate_tokens("abcde"), 2); // 5 chars = ceil(1.25) = 2
/// assert_eq!(estimate_tokens("hello world"), 3); // 11 chars = ceil(2.75) = 3
/// ```
pub fn estimate_tokens(text: &str) -> usize {
    // ~4 chars per token on average
    (text.len() as f64 / 4.0).ceil() as usize
}

/// Helper struct for timing command execution
/// Helper for timing command execution and tracking results.
///
/// Preferred API for tracking commands. Automatically measures execution time
/// and records token savings. Use instead of the deprecated [`track`] function.
///
/// # Examples
///
/// ```no_run
/// use rtk::tracking::TimedExecution;
///
/// let timer = TimedExecution::start();
/// let input = execute_standard_command()?;
/// let output = execute_rtk_command()?;
/// timer.track("ls -la", "rtk ls", &input, &output);
/// # Ok::<(), anyhow::Error>(())
/// ```
pub struct TimedExecution {
    start: Instant,
}

impl TimedExecution {
    /// Start timing a command execution.
    ///
    /// Creates a new timer that starts measuring elapsed time immediately.
    /// Call [`track`](Self::track) or [`track_passthrough`](Self::track_passthrough)
    /// when the command completes.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rtk::tracking::TimedExecution;
    ///
    /// let timer = TimedExecution::start();
    /// // ... execute command ...
    /// timer.track("cmd", "rtk cmd", "input", "output");
    /// ```
    pub fn start() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    /// Track the command with elapsed time and token counts.
    ///
    /// Records the command execution with:
    /// - Elapsed time since [`start`](Self::start)
    /// - Token counts estimated from input/output strings
    /// - Calculated savings metrics
    ///
    /// # Arguments
    ///
    /// - `original_cmd`: Standard command (e.g., "ls -la")
    /// - `rtk_cmd`: RTK command used (e.g., "rtk ls")
    /// - `input`: Standard command output (for token estimation)
    /// - `output`: RTK command output (for token estimation)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rtk::tracking::TimedExecution;
    ///
    /// let timer = TimedExecution::start();
    /// let input = "long output...";
    /// let output = "short output";
    /// timer.track("ls -la", "rtk ls", input, output);
    /// ```
    pub fn track(&self, original_cmd: &str, _rtk_cmd: &str, input: &str, output: &str) {
        // _rtk_cmd is intentionally unused: the storage layer atomizes
        // `original_cmd` into a privacy-safe `cmd_pattern` and persists nothing
        // else from the caller. Kept in the signature to avoid touching ~80
        // call sites until a future refactor.
        let elapsed_ms = self.start.elapsed().as_millis() as u64;
        let input_tokens = estimate_tokens(input);
        let output_tokens = estimate_tokens(output);

        if let Ok(tracker) = Tracker::new() {
            let _ = tracker.record(original_cmd, false, input_tokens, output_tokens, elapsed_ms);
        }
    }

    /// Track passthrough commands (timing-only, no token counting).
    ///
    /// For commands that stream output or run interactively where output
    /// cannot be captured. Records execution time but sets tokens to 0
    /// (does not dilute savings statistics).
    ///
    /// # Arguments
    ///
    /// - `original_cmd`: Standard command (e.g., "git tag --list")
    /// - `rtk_cmd`: RTK command used (e.g., "rtk git tag --list")
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rtk::tracking::TimedExecution;
    ///
    /// let timer = TimedExecution::start();
    /// // ... execute streaming command ...
    /// timer.track_passthrough("git tag", "rtk git tag");
    /// ```
    pub fn track_passthrough(&self, original_cmd: &str, _rtk_cmd: &str) {
        // _rtk_cmd is intentionally unused — see `track` above for the
        // explanation. The is_passthrough flag is the structured replacement
        // for the legacy `"rtk fallback: ..."` prefix encoding.
        let elapsed_ms = self.start.elapsed().as_millis() as u64;
        if let Ok(tracker) = Tracker::new() {
            let _ = tracker.record(original_cmd, true, 0, 0, elapsed_ms);
        }
    }
}

/// Format OsString args for tracking display.
///
/// Joins arguments with spaces, converting each to UTF-8 (lossy).
/// Useful for displaying command arguments in tracking records.
///
/// # Examples
///
/// ```
/// use std::ffi::OsString;
/// use rtk::tracking::args_display;
///
/// let args = vec![OsString::from("status"), OsString::from("--short")];
/// assert_eq!(args_display(&args), "status --short");
/// ```
pub fn args_display(args: &[OsString]) -> String {
    args.iter()
        .map(|a| a.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    // 1. estimate_tokens — verify ~4 chars/token ratio
    #[test]
    fn test_estimate_tokens() {
        assert_eq!(estimate_tokens(""), 0);
        assert_eq!(estimate_tokens("abcd"), 1); // 4 chars = 1 token
        assert_eq!(estimate_tokens("abcde"), 2); // 5 chars = ceil(1.25) = 2
        assert_eq!(estimate_tokens("a"), 1); // 1 char = ceil(0.25) = 1
        assert_eq!(estimate_tokens("12345678"), 2); // 8 chars = 2 tokens
    }

    // 2. args_display — format OsString vec
    #[test]
    fn test_args_display() {
        let args = vec![OsString::from("status"), OsString::from("--short")];
        assert_eq!(args_display(&args), "status --short");
        assert_eq!(args_display(&[]), "");

        let single = vec![OsString::from("log")];
        assert_eq!(args_display(&single), "log");
    }

    // 3. Tracker::record + get_recent — round-trip DB
    #[test]
    fn test_tracker_record_and_recent() {
        let tracker = Tracker::new().expect("Failed to create tracker");

        // Use a unique-ish raw command. After atomization the cmd_pattern
        // collapses to "git status", so we assert on aggregate fields instead
        // of trying to match a per-test marker.
        tracker
            .record("git status --short", false, 100, 20, 50)
            .expect("Failed to record");

        let recent = tracker.get_recent(10).expect("Failed to get recent");

        let test_record = recent
            .iter()
            .find(|r| r.cmd_pattern == "git status" && r.saved_tokens == 80)
            .expect("Test record not found in recent commands");

        assert_eq!(test_record.savings_pct, 80.0);
        assert!(!test_record.is_passthrough);
    }

    // 4. is_passthrough flag persists round-trip
    #[test]
    fn test_track_passthrough_flag_persists() {
        let tracker = Tracker::new().expect("Failed to create tracker");

        // Tests share a DB, so we anchor assertions on the unique cmd_pattern
        // that this test produces, not generic "first match" logic.
        tracker
            .record("git log -10", false, 1000, 200, 10)
            .expect("Failed to record git log");

        tracker
            .record("git tag --list v1.*", true, 0, 0, 5)
            .expect("Failed to record passthrough");

        let recent = tracker.get_recent(50).expect("Failed to get recent");

        // Non-passthrough "git log" record with 80% savings
        let filtered = recent
            .iter()
            .find(|r| !r.is_passthrough && r.cmd_pattern == "git log" && r.saved_tokens == 800)
            .expect("filtered git log record not found");
        assert_eq!(filtered.savings_pct, 80.0);

        // Passthrough "git tag" record with 0 tokens
        let passthrough = recent
            .iter()
            .find(|r| r.is_passthrough && r.cmd_pattern == "git tag")
            .expect("passthrough git tag record not found");
        assert_eq!(passthrough.savings_pct, 0.0);
        assert_eq!(passthrough.saved_tokens, 0);
    }

    // 5. TimedExecution::track records with exec_time > 0
    #[test]
    fn test_timed_execution_records_time() {
        let timer = TimedExecution::start();
        std::thread::sleep(std::time::Duration::from_millis(10));
        // The second arg is unused at the storage layer, but kept in the
        // public signature for back-compat with ~80 call sites.
        timer.track("git status", "rtk git status", "raw input data", "filtered");

        let tracker = Tracker::new().expect("Failed to create tracker");
        let recent = tracker.get_recent(5).expect("Failed to get recent");
        assert!(recent
            .iter()
            .any(|r| r.cmd_pattern == "git status" && !r.is_passthrough));
    }

    // 6. TimedExecution::track_passthrough records with passthrough flag set
    #[test]
    fn test_timed_execution_passthrough() {
        let timer = TimedExecution::start();
        timer.track_passthrough("git tag --list", "rtk git tag");

        let tracker = Tracker::new().expect("Failed to create tracker");
        let recent = tracker.get_recent(5).expect("Failed to get recent");

        let pt = recent
            .iter()
            .find(|r| r.is_passthrough && r.cmd_pattern == "git tag")
            .expect("Passthrough record not found");

        assert_eq!(pt.savings_pct, 0.0);
        assert_eq!(pt.saved_tokens, 0);
    }

    // 7. get_db_path respects environment variable RTK_DB_PATH
    #[test]
    fn test_custom_db_path_env() {
        use std::env;

        let custom_path = env::temp_dir().join("rtk_test_custom.db");
        env::set_var("RTK_DB_PATH", &custom_path);

        let db_path = get_db_path().expect("Failed to get db path");
        assert_eq!(db_path, custom_path);

        env::remove_var("RTK_DB_PATH");
    }

    // 8. get_db_path falls back to default when no custom config
    #[test]
    fn test_default_db_path() {
        use std::env;

        // Ensure no env var is set
        env::remove_var("RTK_DB_PATH");

        let db_path = get_db_path().expect("Failed to get db path");
        assert!(db_path.ends_with("rtk/history.db"));
    }

    // 9. project_filter_params uses GLOB pattern with * wildcard // added
    #[test]
    fn test_project_filter_params_glob_pattern() {
        let (exact, glob) = project_filter_params(Some("/home/user/project"));
        assert_eq!(exact.unwrap(), "/home/user/project");
        // Must use * (GLOB) not % (LIKE) for subdirectory prefix matching
        let glob_val = glob.unwrap();
        assert!(glob_val.ends_with('*'), "GLOB pattern must end with *");
        assert!(!glob_val.contains('%'), "Must not contain LIKE wildcard %");
        assert_eq!(
            glob_val,
            format!("/home/user/project{}*", std::path::MAIN_SEPARATOR)
        );
    }

    // 10. project_filter_params returns None for None input // added
    #[test]
    fn test_project_filter_params_none() {
        let (exact, glob) = project_filter_params(None);
        assert!(exact.is_none());
        assert!(glob.is_none());
    }

    // 11. GLOB pattern safe with underscores in path names // added
    #[test]
    fn test_project_filter_params_underscore_safe() {
        // In LIKE, _ matches any single char; in GLOB, _ is literal
        let (exact, glob) = project_filter_params(Some("/home/user/my_project"));
        assert_eq!(exact.unwrap(), "/home/user/my_project");
        let glob_val = glob.unwrap();
        // _ must be preserved literally (GLOB treats _ as literal, LIKE does not)
        assert!(glob_val.contains("my_project"));
        assert_eq!(
            glob_val,
            format!("/home/user/my_project{}*", std::path::MAIN_SEPARATOR)
        );
    }

    // 12. record_parse_failure + get_parse_failure_summary roundtrip
    #[test]
    fn test_parse_failure_roundtrip() {
        let tracker = Tracker::new().expect("Failed to create tracker");

        // Raw command contains an absolute path; we assert that storage holds
        // only the sanitized cmd_pattern, never the path.
        let raw = format!("git -C /home/u/proj-{} status", std::process::id());
        tracker
            .record_parse_failure(&raw, "unrecognized subcommand", true)
            .expect("Failed to record parse failure");

        let summary = tracker
            .get_parse_failure_summary()
            .expect("Failed to get summary");

        assert!(summary.total >= 1);
        // Sanitization must have stripped the absolute path entirely.
        for rec in &summary.recent {
            assert!(
                !rec.cmd_pattern.contains('/'),
                "cmd_pattern leaked path: {}",
                rec.cmd_pattern
            );
        }
        assert!(summary
            .recent
            .iter()
            .any(|r| r.cmd_pattern.starts_with("git")));
    }

    // 13. recovery_rate calculation
    #[test]
    fn test_parse_failure_recovery_rate() {
        let tracker = Tracker::new().expect("Failed to create tracker");
        let pid = std::process::id();

        // 2 successes, 1 failure
        tracker
            .record_parse_failure(&format!("cmd_ok1_{}", pid), "err", true)
            .unwrap();
        tracker
            .record_parse_failure(&format!("cmd_ok2_{}", pid), "err", true)
            .unwrap();
        tracker
            .record_parse_failure(&format!("cmd_fail_{}", pid), "err", false)
            .unwrap();

        let summary = tracker.get_parse_failure_summary().unwrap();
        // We can't assert exact rate because other tests may have added records,
        // but we can verify recovery_rate is between 0 and 100
        assert!(summary.recovery_rate >= 0.0 && summary.recovery_rate <= 100.0);
    }
}
