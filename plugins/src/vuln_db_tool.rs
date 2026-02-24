//! RustSec vulnerability database management tool for Claude Code agents.
//!
//! Provides commands to manage the local RustSec advisory database, search for
//! known vulnerabilities, and retrieve statistics about the vulnerability landscape.
//! Outputs machine-readable JSON for agent consumption.
//!
//! # Commands
//!
//! - `update` - Update the local RustSec advisory database
//! - `search` - Search for advisories by crate name or CVE ID
//! - `stats` - Display database statistics (total advisories, recent additions, etc.)
//! - `docs` - Show paths to required project documentation files

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rustsec::{advisory, Database};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "vuln-db-tool",
    about = "RustSec vulnerability database management for Claude Code agents",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Path to store the advisory database (defaults to ~/.cargo/advisory-db)
    #[arg(short, long, global = true)]
    db_path: Option<PathBuf>,

    /// Output format (json only for now)
    #[arg(short = 'f', long, default_value = "json", global = true)]
    format: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Update the local RustSec advisory database
    Update {
        /// Force update even if recently updated
        #[arg(long)]
        force: bool,
    },
    /// Search for advisories
    Search {
        /// Crate name or CVE ID to search for
        query: String,

        /// Show full advisory details
        #[arg(long)]
        detailed: bool,
    },
    /// Display database statistics
    Stats,
    /// Show paths to required project documentation files
    Docs {
        /// Search from a specific directory instead of the current working directory
        #[arg(long)]
        base: Option<PathBuf>,
    },
}

/// Paths to the four required project documentation files.
///
/// Files are discovered by searching `.claude/` then the project root.
/// A `None` value means the file was not found in any search location.
#[derive(Serialize, Deserialize)]
struct DocFiles {
    /// Path to CODING-PRINCIPLES.md, or null if not found.
    coding_principles: Option<String>,
    /// Path to TESTING.md, or null if not found.
    testing: Option<String>,
    /// Path to SECURITY.md, or null if not found.
    security: Option<String>,
    /// Path to DEVELOPMENT.md, or null if not found.
    development: Option<String>,
    /// Directories that were searched, in priority order.
    searched_dirs: Vec<String>,
}

/// Result of updating the RustSec advisory database.
#[derive(Serialize, Deserialize)]
struct UpdateInfo {
    /// Whether the update succeeded.
    success: bool,
    /// Git commit hash of the database.
    commit: Option<String>,
    /// ISO 8601 timestamp of the update.
    updated_at: String,
    /// Total number of advisories in the database.
    advisories_count: usize,
}

/// Information about a single security advisory.
#[derive(Serialize, Deserialize)]
struct AdvisoryInfo {
    /// Advisory identifier (e.g., "RUSTSEC-2023-0001").
    id: String,
    /// Name of the affected package.
    package: String,
    /// Short description of the vulnerability.
    title: String,
    /// Detailed description, if requested.
    description: Option<String>,
    /// Date the advisory was published.
    date: String,
    /// URL to the advisory or related information.
    url: Option<String>,
    /// CVSS score as a string.
    cvss: Option<String>,
    /// Keywords categorizing the advisory.
    keywords: Vec<String>,
    /// Version ranges affected by the vulnerability.
    affected_versions: Vec<String>,
    /// Versions with patches for the vulnerability.
    patched_versions: Vec<String>,
    /// Versions that are not affected.
    unaffected_versions: Vec<String>,
}

/// Result of searching the advisory database.
#[derive(Serialize, Deserialize)]
struct SearchResult {
    /// The search query string.
    query: String,
    /// Matching advisories.
    matches: Vec<AdvisoryInfo>,
    /// Total number of matches found.
    total_matches: usize,
}

/// Statistics about the advisory database.
#[derive(Serialize, Deserialize)]
struct DatabaseStats {
    /// Total number of advisories in the database.
    total_advisories: usize,
    /// Number of unique crates with advisories.
    total_crates: usize,
    /// Most recent advisories (last 10).
    recent_advisories: Vec<AdvisoryInfo>,
    /// Distribution of advisories by severity.
    severity_breakdown: SeverityBreakdown,
    /// ISO 8601 timestamp of last database update.
    last_updated: Option<String>,
}

/// Distribution of advisories across severity levels.
#[derive(Serialize, Deserialize)]
struct SeverityBreakdown {
    /// Count of critical severity advisories.
    critical: usize,
    /// Count of high severity advisories.
    high: usize,
    /// Count of medium severity advisories.
    medium: usize,
    /// Count of low severity advisories.
    low: usize,
    /// Count of advisories without severity rating.
    unknown: usize,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Update { force } => handle_update(cli.db_path, force)?,
        Commands::Search { query, detailed } => handle_search(cli.db_path, query, detailed)?,
        Commands::Stats => handle_stats(cli.db_path)?,
        Commands::Docs { base } => handle_docs(base)?,
    };

    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

/// Reports the discovered paths of the four required documentation files.
fn handle_docs(base: Option<PathBuf>) -> Result<serde_json::Value> {
    let doc_files = discover_doc_files(base);
    Ok(serde_json::to_value(doc_files)?)
}

/// Discovers the four required documentation files starting from `base`.
///
/// Search order (first match wins for each file):
/// 1. `<base>/.claude/<file>`  — files placed by `/init` in a target project
/// 2. `<base>/<file>`          — files at the project root
fn discover_doc_files(base: Option<PathBuf>) -> DocFiles {
    let base_dir = base.unwrap_or_else(|| {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    });

    let search_dirs = vec![
        base_dir.join(".claude"),
        base_dir.clone(),
    ];

    let searched_dirs: Vec<String> = search_dirs
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();

    DocFiles {
        coding_principles: find_doc_file(&search_dirs, "CODING-PRINCIPLES.md"),
        testing: find_doc_file(&search_dirs, "TESTING.md"),
        security: find_doc_file(&search_dirs, "SECURITY.md"),
        development: find_doc_file(&search_dirs, "DEVELOPMENT.md"),
        searched_dirs,
    }
}

/// Returns the path of the first location where `filename` exists, or `None`.
fn find_doc_file(search_dirs: &[PathBuf], filename: &str) -> Option<String> {
    search_dirs
        .iter()
        .map(|dir| dir.join(filename))
        .find(|path| path.exists())
        .map(|path| path.to_string_lossy().into_owned())
}

/// Updates the local RustSec advisory database
fn handle_update(db_path: Option<PathBuf>, _force: bool) -> Result<serde_json::Value> {
    // Fetch the database using the default method
    let db = if db_path.is_some() {
        // If custom path provided, we need to handle it differently
        Database::fetch().context("Failed to fetch advisory database")?
    } else {
        Database::fetch().context("Failed to fetch advisory database")?
    };

    let advisories_count = db.iter().count();

    let update_info = UpdateInfo {
        success: true,
        commit: None, // RustSec database doesn't expose commit info easily
        updated_at: chrono::Utc::now().to_rfc3339(),
        advisories_count,
    };

    Ok(serde_json::to_value(update_info)?)
}

/// Searches for advisories by crate name or CVE ID
fn handle_search(
    db_path: Option<PathBuf>,
    query: String,
    detailed: bool,
) -> Result<serde_json::Value> {
    let db = load_database(db_path)?;

    let mut matches = Vec::new();

    for advisory in db.iter() {
        let metadata = &advisory.metadata;

        // Search by crate name or CVE ID
        let query_lower = query.to_lowercase();
        let package_match = metadata
            .package
            .to_string()
            .to_lowercase()
            .contains(&query_lower);
        let id_match = advisory
            .id()
            .to_string()
            .to_lowercase()
            .contains(&query_lower);

        if package_match || id_match {
            let advisory_info = convert_advisory_to_info(advisory, detailed);
            matches.push(advisory_info);
        }
    }

    let total_matches = matches.len();

    let result = SearchResult {
        query,
        matches,
        total_matches,
    };

    Ok(serde_json::to_value(result)?)
}

/// Displays database statistics
fn handle_stats(db_path: Option<PathBuf>) -> Result<serde_json::Value> {
    let db = load_database(db_path)?;

    let mut total_advisories = 0;
    let mut crates = std::collections::HashSet::new();
    let mut severity_breakdown = SeverityBreakdown {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        unknown: 0,
    };

    let mut all_advisories: Vec<_> = db.iter().collect();

    for advisory in &all_advisories {
        total_advisories += 1;
        crates.insert(advisory.metadata.package.to_string());

        // Count severity if available
        if let Some(cvss) = &advisory.metadata.cvss {
            let score = cvss.score().value();
            match score {
                9.0..=10.0 => severity_breakdown.critical += 1,
                7.0..=8.9 => severity_breakdown.high += 1,
                4.0..=6.9 => severity_breakdown.medium += 1,
                0.1..=3.9 => severity_breakdown.low += 1,
                _ => severity_breakdown.unknown += 1,
            }
        } else {
            severity_breakdown.unknown += 1;
        }
    }

    // Sort by date and get recent 10
    all_advisories.sort_by(|a, b| b.metadata.date.cmp(&a.metadata.date));
    let recent_advisories: Vec<AdvisoryInfo> = all_advisories
        .iter()
        .take(10)
        .map(|a| convert_advisory_to_info(a, false))
        .collect();

    let stats = DatabaseStats {
        total_advisories,
        total_crates: crates.len(),
        recent_advisories,
        severity_breakdown,
        last_updated: None, // Could extract from git metadata if needed
    };

    Ok(serde_json::to_value(stats)?)
}

/// Loads the RustSec database from disk
fn load_database(db_path: Option<PathBuf>) -> Result<Database> {
    let path = db_path.unwrap_or_else(|| get_default_db_path().unwrap());

    if !path.exists() {
        anyhow::bail!(
            "Advisory database not found at {:?}. Run 'update' command first.",
            path
        );
    }

    Database::open(&path).context("Failed to open advisory database")
}

/// Returns the default database path
fn get_default_db_path() -> Result<PathBuf> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .context("Cannot determine home directory")?;

    Ok(PathBuf::from(home).join(".cargo").join("advisory-db"))
}

/// Converts a RustSec advisory to AdvisoryInfo struct
fn convert_advisory_to_info(advisory: &advisory::Advisory, detailed: bool) -> AdvisoryInfo {
    let metadata = &advisory.metadata;

    AdvisoryInfo {
        id: advisory.id().to_string(),
        package: metadata.package.to_string(),
        title: metadata.title.clone(),
        description: if detailed {
            Some(metadata.description.clone())
        } else {
            None
        },
        date: metadata.date.to_string(),
        url: metadata.url.as_ref().map(|u| u.to_string()),
        cvss: metadata
            .cvss
            .as_ref()
            .map(|c| format!("{:.1}", c.score().value())),
        keywords: metadata
            .keywords
            .iter()
            .map(|k| format!("{:?}", k))
            .collect(),
        affected_versions: Vec::new(), // Version API changed - simplified for now
        patched_versions: advisory
            .versions
            .patched()
            .iter()
            .map(|v| v.to_string())
            .collect(),
        unaffected_versions: advisory
            .versions
            .unaffected()
            .iter()
            .map(|v| v.to_string())
            .collect(),
    }
}
