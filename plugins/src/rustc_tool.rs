/**
 * rustc_tool.rs
 *
 * Rust toolchain detection and version information tool for Claude Code agents.
 *
 * Provides commands to detect and report information about the installed Rust
 * toolchain, including compiler version, release channel (stable/beta/nightly),
 * target triple, and sysroot location. Outputs machine-readable JSON for agent
 * consumption.
 *
 * Commands:
 * - version: Display rustc version and commit information
 * - target: Show default target triple and available targets
 * - channel: Detect release channel (stable, beta, nightly)
 * - sysroot: Display sysroot path and library locations
 */

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
}

#[derive(Serialize, Deserialize)]
struct VersionInfo {
    version: String,
    commit_hash: Option<String>,
    commit_date: Option<String>,
    host: String,
    release: String,
    llvm_version: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct TargetInfo {
    default_target: String,
    installed_targets: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct ChannelInfo {
    channel: String, // "stable", "beta", "nightly"
    version: String,
    is_nightly: bool,
}

#[derive(Serialize, Deserialize)]
struct SysrootInfo {
    sysroot: String,
    lib_path: Option<String>,
    src_path: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Version { verbose } => handle_version(verbose)?,
        Commands::Target { list } => handle_target(list)?,
        Commands::Channel => handle_channel()?,
        Commands::Sysroot { libs } => handle_sysroot(libs)?,
    };

    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

/// Extracts rustc version and commit information
fn handle_version(verbose: bool) -> Result<serde_json::Value> {
    let output = Command::new("rustc")
        .arg(if verbose { "--version" } else { "--version" })
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

    for line in stdout.lines() {
        if line.starts_with("rustc ") {
            // Extract version from "rustc 1.70.0 (hash date)"
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                version = parts[1].to_string();
            }
            if parts.len() >= 3 {
                let hash_date = parts[2..].join(" ");
                let re = Regex::new(r"\(([a-f0-9]+) (\d{4}-\d{2}-\d{2})\)").unwrap();
                if let Some(caps) = re.captures(&hash_date) {
                    commit_hash = Some(caps[1].to_string());
                    commit_date = Some(caps[2].to_string());
                }
            }
        } else if line.starts_with("host: ") {
            host = line.strip_prefix("host: ").unwrap_or("").to_string();
        } else if line.starts_with("release: ") {
            release = line.strip_prefix("release: ").unwrap_or("").to_string();
        } else if line.starts_with("LLVM version: ") {
            llvm_version = Some(line.strip_prefix("LLVM version: ").unwrap_or("").to_string());
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
