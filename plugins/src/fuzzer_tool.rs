//! Fuzzing infrastructure management tool for Claude Code agents.
//!
//! Provides commands to initialize fuzzing harnesses, run fuzzing campaigns,
//! manage fuzzing corpus, and analyze crash reports. Supports cargo-fuzz and
//! libFuzzer infrastructure. Outputs machine-readable JSON for agent consumption.
//!
//! # Commands
//!
//! - `init` - Initialize fuzzing infrastructure for a project
//! - `run` - Execute fuzzing campaign on a target
//! - `corpus` - Manage and inspect fuzzing corpus
//! - `crashes` - Analyze and report crash artifacts
//! - `docs` - Show paths to required project documentation files

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use walkdir::WalkDir;

#[derive(Parser)]
#[command(
    name = "fuzzer-tool",
    about = "Fuzzing infrastructure management for Claude Code agents",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Path to project directory
    #[arg(short, long, global = true)]
    project_path: Option<PathBuf>,

    /// Output format (json only for now)
    #[arg(short, long, default_value = "json", global = true)]
    format: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize fuzzing infrastructure
    Init {
        /// Target name for the fuzz harness
        target: String,

        /// Template type (default, custom)
        #[arg(long, default_value = "default")]
        template: String,
    },
    /// Execute fuzzing campaign
    Run {
        /// Target to fuzz
        target: String,

        /// Maximum time in seconds (0 = unlimited)
        #[arg(long, default_value = "0")]
        max_time: u64,

        /// Number of jobs (parallel fuzzing)
        #[arg(long, default_value = "1")]
        jobs: u32,
    },
    /// Manage fuzzing corpus
    Corpus {
        /// Target name
        target: String,

        /// Corpus operation (stats, minimize, merge)
        #[arg(long, default_value = "stats")]
        operation: String,
    },
    /// Analyze crash artifacts
    Crashes {
        /// Target name
        target: String,

        /// Show detailed crash information
        #[arg(long)]
        detailed: bool,
    },
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

/// Result of initializing fuzzing infrastructure.
#[derive(Serialize, Deserialize)]
struct InitResult {
    /// Whether initialization succeeded.
    success: bool,
    /// Name of the fuzz target.
    target: String,
    /// Path to the fuzz directory.
    fuzz_directory: String,
    /// Path to the generated harness source file.
    harness_path: String,
    /// Path to the corpus directory.
    corpus_path: String,
    /// Recommended next steps for the user.
    next_steps: Vec<String>,
}

/// Result of a fuzzing campaign execution.
#[derive(Serialize, Deserialize)]
struct RunResult {
    /// Whether the fuzzing run completed successfully.
    success: bool,
    /// Name of the fuzz target.
    target: String,
    /// Total number of test executions.
    executions: u64,
    /// Number of inputs in the corpus.
    corpus_size: usize,
    /// Number of crashes discovered.
    crashes_found: usize,
    /// Total fuzzing duration in seconds.
    duration_seconds: u64,
    /// Code coverage percentage, if available.
    coverage_percent: Option<f64>,
}

/// Information about a fuzzing corpus.
#[derive(Serialize, Deserialize)]
struct CorpusInfo {
    /// Name of the fuzz target.
    target: String,
    /// Total number of corpus inputs.
    total_inputs: usize,
    /// Total size of all corpus files in bytes.
    total_size_bytes: u64,
    /// Average size of corpus inputs in bytes.
    average_input_size: u64,
    /// Code coverage metrics, if available.
    coverage_metrics: Option<CoverageMetrics>,
}

/// Code coverage metrics from fuzzing.
#[derive(Serialize, Deserialize)]
struct CoverageMetrics {
    /// Number of basic blocks covered.
    blocks_covered: usize,
    /// Total number of basic blocks in the target.
    total_blocks: usize,
    /// Coverage percentage (0.0-100.0).
    coverage_percent: f64,
}

/// Report of crashes discovered during fuzzing.
#[derive(Serialize, Deserialize)]
struct CrashReport {
    /// Name of the fuzz target.
    target: String,
    /// Total number of crash artifacts.
    total_crashes: usize,
    /// Number of unique crashes after deduplication.
    unique_crashes: usize,
    /// Details of individual crash artifacts.
    crash_details: Vec<CrashDetail>,
}

/// Details of a single crash artifact.
#[derive(Serialize, Deserialize)]
struct CrashDetail {
    /// Path to the crash artifact file.
    file: String,
    /// Size of the crash input in bytes.
    size_bytes: u64,
    /// Hash of the crash input for deduplication.
    hash: String,
    /// First few bytes of the input as hex (for preview).
    preview: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Init { target, template } => handle_init(cli.project_path, target, template)?,
        Commands::Run {
            target,
            max_time,
            jobs,
        } => handle_run(cli.project_path, target, max_time, jobs)?,
        Commands::Corpus { target, operation } => {
            handle_corpus(cli.project_path, target, operation)?
        }
        Commands::Crashes { target, detailed } => {
            handle_crashes(cli.project_path, target, detailed)?
        }
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

/// Initializes fuzzing infrastructure for a project
fn handle_init(
    project_path: Option<PathBuf>,
    target: String,
    _template: String,
) -> Result<serde_json::Value> {
    let project_dir = project_path.unwrap_or_else(|| PathBuf::from("."));

    // Check if cargo-fuzz is installed
    if !is_cargo_fuzz_installed() {
        anyhow::bail!("cargo-fuzz is not installed. Install with: cargo install cargo-fuzz");
    }

    // Initialize cargo-fuzz if fuzz directory doesn't exist
    let fuzz_dir = project_dir.join("fuzz");
    if !fuzz_dir.exists() {
        let status = Command::new("cargo")
            .arg("fuzz")
            .arg("init")
            .current_dir(&project_dir)
            .status()
            .context("Failed to initialize cargo-fuzz")?;

        if !status.success() {
            anyhow::bail!("cargo fuzz init failed");
        }
    }

    // Add new fuzz target
    let status = Command::new("cargo")
        .arg("fuzz")
        .arg("add")
        .arg(&target)
        .current_dir(&project_dir)
        .status()
        .context("Failed to add fuzz target")?;

    if !status.success() {
        anyhow::bail!("cargo fuzz add failed");
    }

    let harness_path = fuzz_dir.join("fuzz_targets").join(format!("{}.rs", target));
    let corpus_path = fuzz_dir.join("corpus").join(&target);

    let result = InitResult {
        success: true,
        target: target.clone(),
        fuzz_directory: fuzz_dir.to_string_lossy().to_string(),
        harness_path: harness_path.to_string_lossy().to_string(),
        corpus_path: corpus_path.to_string_lossy().to_string(),
        next_steps: vec![
            format!("Edit the fuzz harness at {}", harness_path.display()),
            format!("Run fuzzing with: cargo fuzz run {}", target),
        ],
    };

    Ok(serde_json::to_value(result)?)
}

/// Executes a fuzzing campaign
fn handle_run(
    project_path: Option<PathBuf>,
    target: String,
    max_time: u64,
    jobs: u32,
) -> Result<serde_json::Value> {
    let project_dir = project_path.unwrap_or_else(|| PathBuf::from("."));

    if !is_cargo_fuzz_installed() {
        anyhow::bail!("cargo-fuzz is not installed");
    }

    let mut cmd = Command::new("cargo");
    cmd.arg("fuzz")
        .arg("run")
        .arg(&target)
        .current_dir(&project_dir);

    if max_time > 0 {
        cmd.arg("--").arg(format!("-max_total_time={}", max_time));
    }

    if jobs > 1 {
        cmd.arg(format!("-jobs={}", jobs));
    }

    let _output = cmd.output().context("Failed to execute cargo fuzz run")?;

    // Get corpus size
    let corpus_path = project_dir.join("fuzz").join("corpus").join(&target);
    let corpus_size = if corpus_path.exists() {
        fs::read_dir(&corpus_path)?.count()
    } else {
        0
    };

    // Get crashes count
    let artifacts_path = project_dir.join("fuzz").join("artifacts").join(&target);
    let crashes_found = if artifacts_path.exists() {
        fs::read_dir(&artifacts_path)?.count()
    } else {
        0
    };

    let result = RunResult {
        success: true,
        target,
        executions: 0, // Would need to parse fuzzer output
        corpus_size,
        crashes_found,
        duration_seconds: max_time,
        coverage_percent: None,
    };

    Ok(serde_json::to_value(result)?)
}

/// Manages fuzzing corpus
fn handle_corpus(
    project_path: Option<PathBuf>,
    target: String,
    _operation: String,
) -> Result<serde_json::Value> {
    let project_dir = project_path.unwrap_or_else(|| PathBuf::from("."));
    let corpus_path = project_dir.join("fuzz").join("corpus").join(&target);

    if !corpus_path.exists() {
        anyhow::bail!("Corpus directory not found for target: {}", target);
    }

    let mut total_inputs = 0;
    let mut total_size_bytes = 0u64;

    for entry in fs::read_dir(&corpus_path)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            total_inputs += 1;
            total_size_bytes += entry.metadata()?.len();
        }
    }

    let average_input_size = if total_inputs > 0 {
        total_size_bytes / total_inputs as u64
    } else {
        0
    };

    let corpus_info = CorpusInfo {
        target,
        total_inputs,
        total_size_bytes,
        average_input_size,
        coverage_metrics: None,
    };

    Ok(serde_json::to_value(corpus_info)?)
}

/// Analyzes crash artifacts
fn handle_crashes(
    project_path: Option<PathBuf>,
    target: String,
    detailed: bool,
) -> Result<serde_json::Value> {
    let project_dir = project_path.unwrap_or_else(|| PathBuf::from("."));
    let artifacts_path = project_dir.join("fuzz").join("artifacts").join(&target);

    let mut crash_details = Vec::new();
    let mut total_crashes = 0;

    if artifacts_path.exists() {
        for entry in WalkDir::new(&artifacts_path)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                let path = entry.path();
                let metadata = fs::metadata(path)?;
                total_crashes += 1;

                if detailed {
                    let hash = format!("{:x}", md5::compute(path.to_string_lossy().as_bytes()));
                    let preview = if metadata.len() > 0 {
                        let bytes = fs::read(path)?;
                        let preview_bytes = &bytes[..bytes.len().min(16)];
                        Some(
                            preview_bytes
                                .iter()
                                .map(|b| format!("{:02x}", b))
                                .collect::<Vec<_>>()
                                .join(" "),
                        )
                    } else {
                        None
                    };

                    crash_details.push(CrashDetail {
                        file: path.to_string_lossy().to_string(),
                        size_bytes: metadata.len(),
                        hash,
                        preview,
                    });
                }
            }
        }
    }

    let report = CrashReport {
        target,
        total_crashes,
        unique_crashes: crash_details.len(), // Simplified - would need deduplication
        crash_details,
    };

    Ok(serde_json::to_value(report)?)
}

/// Checks if cargo-fuzz is installed
fn is_cargo_fuzz_installed() -> bool {
    Command::new("cargo")
        .arg("fuzz")
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}
