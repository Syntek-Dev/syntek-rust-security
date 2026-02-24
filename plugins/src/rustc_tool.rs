//! Rust toolchain detection and version information tool for Claude Code agents.
//!
//! Provides commands to detect and report information about the installed Rust
//! toolchain, including compiler version, release channel (stable/beta/nightly),
//! target triple, and sysroot location. Outputs machine-readable JSON for agent
//! consumption.
//!
//! # Commands
//!
//! - `version` - Display rustc version and commit information
//! - `target` - Show default target triple and available targets
//! - `channel` - Detect release channel (stable, beta, nightly)
//! - `sysroot` - Display sysroot path and library locations
//! - `docs` - Show paths to required project documentation files

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Parser)]
#[command(
    name = "rustc-tool",
    about = "Rust toolchain detection for Claude Code agents",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output format (json only for now)
    #[arg(short, long, default_value = "json", global = true)]
    format: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Display rustc version and commit information
    Version {
        /// Show verbose version information
        #[arg(long)]
        verbose: bool,
    },
    /// Show target triple information
    Target {
        /// List all installed targets
        #[arg(long)]
        list: bool,
    },
    /// Detect release channel
    Channel,
    /// Display sysroot path
    Sysroot {
        /// Show library paths
        #[arg(long)]
        libs: bool,
    },
    /// Show paths to required project documentation files
    Docs {
        /// Search from a specific directory instead of the current working directory
        #[arg(long)]
        base: Option<std::path::PathBuf>,
    },
}

/// Rust compiler version information.
#[derive(Serialize, Deserialize)]
struct VersionInfo {
    /// Semantic version string (e.g., "1.92.0").
    version: String,
    /// Git commit hash of the compiler build.
    commit_hash: Option<String>,
    /// Date of the compiler build commit.
    commit_date: Option<String>,
    /// Host target triple (e.g., "x86_64-unknown-linux-gnu").
    host: String,
    /// Release version string.
    release: String,
    /// LLVM version used by the compiler.
    llvm_version: Option<String>,
}

/// Target triple information.
#[derive(Serialize, Deserialize)]
struct TargetInfo {
    /// Default compilation target for this host.
    default_target: String,
    /// List of installed cross-compilation targets.
    installed_targets: Vec<String>,
}

/// Release channel information.
#[derive(Serialize, Deserialize)]
struct ChannelInfo {
    /// Release channel name: "stable", "beta", or "nightly".
    channel: String,
    /// Full version string including channel suffix.
    version: String,
    /// Whether this is a nightly toolchain.
    is_nightly: bool,
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

/// Sysroot path information.
#[derive(Serialize, Deserialize)]
struct SysrootInfo {
    /// Path to the Rust sysroot directory.
    sysroot: String,
    /// Path to the Rust libraries.
    lib_path: Option<String>,
    /// Path to the Rust standard library source.
    src_path: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Version { verbose } => handle_version(verbose)?,
        Commands::Target { list } => handle_target(list)?,
        Commands::Channel => handle_channel()?,
        Commands::Sysroot { libs } => handle_sysroot(libs)?,
        Commands::Docs { base } => handle_docs(base)?,
    };

    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

/// Reports the discovered paths of the four required documentation files.
fn handle_docs(base: Option<std::path::PathBuf>) -> Result<serde_json::Value> {
    let doc_files = discover_doc_files(base);
    Ok(serde_json::to_value(doc_files)?)
}

/// Discovers the four required documentation files starting from `base`.
///
/// Search order (first match wins for each file):
/// 1. `<base>/.claude/<file>`  — files placed by `/init` in a target project
/// 2. `<base>/<file>`          — files at the project root
fn discover_doc_files(base: Option<std::path::PathBuf>) -> DocFiles {
    let base_dir = base.unwrap_or_else(|| {
        std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))
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
fn find_doc_file(search_dirs: &[std::path::PathBuf], filename: &str) -> Option<String> {
    search_dirs
        .iter()
        .map(|dir| dir.join(filename))
        .find(|path| path.exists())
        .map(|path| path.to_string_lossy().into_owned())
}

/// Extracts rustc version and commit information
fn handle_version(_verbose: bool) -> Result<serde_json::Value> {
    let output = Command::new("rustc")
        .arg("--version")
        .arg("--verbose")
        .output()
        .context("Failed to execute rustc. Is Rust installed?")?;

    if !output.status.success() {
        anyhow::bail!("rustc command failed");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse version info
    let mut version = String::new();
    let mut commit_hash = None;
    let mut commit_date = None;
    let mut host = String::new();
    let mut release = String::new();
    let mut llvm_version = None;

    // Pre-compile regex outside the loop
    let commit_re = Regex::new(r"\(([a-f0-9]+) (\d{4}-\d{2}-\d{2})\)").unwrap();

    for line in stdout.lines() {
        if line.starts_with("rustc ") {
            // Extract version from "rustc 1.70.0 (hash date)"
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                version = parts[1].to_string();
            }
            if parts.len() >= 3 {
                let hash_date = parts[2..].join(" ");
                if let Some(caps) = commit_re.captures(&hash_date) {
                    commit_hash = Some(caps[1].to_string());
                    commit_date = Some(caps[2].to_string());
                }
            }
        } else if line.starts_with("host: ") {
            host = line.strip_prefix("host: ").unwrap_or("").to_string();
        } else if line.starts_with("release: ") {
            release = line.strip_prefix("release: ").unwrap_or("").to_string();
        } else if line.starts_with("LLVM version: ") {
            llvm_version = Some(
                line.strip_prefix("LLVM version: ")
                    .unwrap_or("")
                    .to_string(),
            );
        }
    }

    let version_info = VersionInfo {
        version,
        commit_hash,
        commit_date,
        host,
        release,
        llvm_version,
    };

    Ok(serde_json::to_value(version_info)?)
}

/// Retrieves target triple information
fn handle_target(list_all: bool) -> Result<serde_json::Value> {
    // Get default target
    let default_output = Command::new("rustc")
        .arg("--version")
        .arg("--verbose")
        .output()
        .context("Failed to execute rustc")?;

    if !default_output.status.success() {
        anyhow::bail!("rustc command failed");
    }

    let stdout = String::from_utf8_lossy(&default_output.stdout);
    let mut default_target = String::new();

    for line in stdout.lines() {
        if line.starts_with("host: ") {
            default_target = line.strip_prefix("host: ").unwrap_or("").to_string();
            break;
        }
    }

    // Get installed targets if requested
    let mut installed_targets = Vec::new();

    if list_all {
        let targets_output = Command::new("rustup")
            .args(["target", "list", "--installed"])
            .output();

        if let Ok(output) = targets_output {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                installed_targets = stdout.lines().map(|s| s.to_string()).collect();
            }
        }
    }

    let target_info = TargetInfo {
        default_target,
        installed_targets,
    };

    Ok(serde_json::to_value(target_info)?)
}

/// Detects the Rust release channel (stable, beta, nightly)
fn handle_channel() -> Result<serde_json::Value> {
    let output = Command::new("rustc")
        .arg("--version")
        .output()
        .context("Failed to execute rustc")?;

    if !output.status.success() {
        anyhow::bail!("rustc command failed");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let version_line = stdout.lines().next().unwrap_or("");

    // Detect channel from version string
    let (channel, is_nightly) = if version_line.contains("-nightly") {
        ("nightly".to_string(), true)
    } else if version_line.contains("-beta") {
        ("beta".to_string(), false)
    } else {
        ("stable".to_string(), false)
    };

    // Extract full version
    let version = version_line
        .strip_prefix("rustc ")
        .unwrap_or("")
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_string();

    let channel_info = ChannelInfo {
        channel,
        version,
        is_nightly,
    };

    Ok(serde_json::to_value(channel_info)?)
}

/// Retrieves sysroot path and library locations
fn handle_sysroot(show_libs: bool) -> Result<serde_json::Value> {
    let output = Command::new("rustc")
        .arg("--print")
        .arg("sysroot")
        .output()
        .context("Failed to execute rustc")?;

    if !output.status.success() {
        anyhow::bail!("rustc command failed");
    }

    let sysroot = String::from_utf8_lossy(&output.stdout).trim().to_string();

    let mut lib_path = None;
    let mut src_path = None;

    if show_libs {
        // Detect lib path
        let lib_candidate = format!("{}/lib", sysroot);
        if std::path::Path::new(&lib_candidate).exists() {
            lib_path = Some(lib_candidate);
        }

        // Detect src path
        let src_candidate = format!("{}/lib/rustlib/src/rust/library", sysroot);
        if std::path::Path::new(&src_candidate).exists() {
            src_path = Some(src_candidate);
        }
    }

    let sysroot_info = SysrootInfo {
        sysroot,
        lib_path,
        src_path,
    };

    Ok(serde_json::to_value(sysroot_info)?)
}
