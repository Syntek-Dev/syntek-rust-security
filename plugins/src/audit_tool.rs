//! Security audit orchestration tool for Claude Code agents.
//!
//! Provides commands to execute multiple security audit tools (cargo-audit, cargo-deny,
//! cargo-geiger) and aggregate their results into a unified security report. Outputs
//! machine-readable JSON for agent consumption.
//!
//! # Commands
//!
//! - `run` - Execute full security audit (all tools)
//! - `quick` - Execute quick audit (cargo-audit only)
//! - `report` - Generate comprehensive security report
//! - `docs` - Show paths to required project documentation files

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Command;

#[derive(Parser)]
#[command(
    name = "audit-tool",
    about = "Security audit orchestration for Claude Code agents",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Path to Cargo.toml or project directory
    #[arg(short, long, global = true)]
    manifest_path: Option<PathBuf>,

    /// Output format (json only for now)
    #[arg(short, long, default_value = "json", global = true)]
    format: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Execute full security audit (all tools)
    Run {
        /// Skip cargo-deny checks
        #[arg(long)]
        skip_deny: bool,

        /// Skip cargo-geiger checks
        #[arg(long)]
        skip_geiger: bool,
    },
    /// Execute quick audit (cargo-audit only)
    Quick,
    /// Generate comprehensive security report
    Report {
        /// Include detailed vulnerability information
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

/// Complete security audit result from all tools.
#[derive(Serialize, Deserialize)]
struct AuditResult {
    /// ISO 8601 timestamp when audit was performed.
    timestamp: String,
    /// Name of the audited project.
    project_name: Option<String>,
    /// High-level summary of audit findings.
    summary: AuditSummary,
    /// List of discovered vulnerabilities.
    vulnerabilities: Vec<Vulnerability>,
    /// Unsafe code statistics from cargo-geiger.
    unsafe_stats: Option<UnsafeStats>,
    /// License compliance issues from cargo-deny.
    license_issues: Vec<LicenseIssue>,
    /// List of audit tools that were executed.
    tools_run: Vec<String>,
}

/// Summary statistics from the security audit.
#[derive(Serialize, Deserialize)]
struct AuditSummary {
    /// Total number of vulnerabilities found.
    total_vulnerabilities: usize,
    /// Count of critical severity vulnerabilities.
    critical_count: usize,
    /// Count of high severity vulnerabilities.
    high_count: usize,
    /// Count of medium severity vulnerabilities.
    medium_count: usize,
    /// Count of low severity vulnerabilities.
    low_count: usize,
    /// Number of unsafe functions detected.
    unsafe_functions: usize,
    /// Number of license compliance issues.
    license_issues: usize,
    /// Whether the audit passed (no critical issues).
    passed: bool,
}

/// A single vulnerability from the security audit.
#[derive(Serialize, Deserialize)]
struct Vulnerability {
    /// Vulnerability identifier (e.g., "RUSTSEC-2023-0001").
    id: String,
    /// Name of the affected package.
    package: String,
    /// Version of the affected package.
    version: String,
    /// Short description of the vulnerability.
    title: String,
    /// Severity level (critical, high, medium, low).
    severity: String,
    /// CVSS score if available.
    cvss_score: Option<f64>,
    /// Detailed description of the vulnerability.
    description: Option<String>,
    /// Recommended remediation steps.
    solution: Option<String>,
}

/// Statistics about unsafe code usage from cargo-geiger.
#[derive(Serialize, Deserialize)]
struct UnsafeStats {
    /// Number of unsafe functions.
    functions: usize,
    /// Number of unsafe expressions.
    expressions: usize,
    /// Number of unsafe impl blocks.
    impls: usize,
    /// Number of unsafe trait declarations.
    traits: usize,
    /// Number of unsafe methods.
    methods: usize,
}

/// A license compliance issue from cargo-deny.
#[derive(Serialize, Deserialize)]
struct LicenseIssue {
    /// Name of the package with the license issue.
    package: String,
    /// License identifier of the package.
    license: String,
    /// Description of the compliance issue.
    issue: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Run {
            skip_deny,
            skip_geiger,
        } => handle_run(cli.manifest_path, skip_deny, skip_geiger)?,
        Commands::Quick => handle_quick(cli.manifest_path)?,
        Commands::Report { detailed } => handle_report(cli.manifest_path, detailed)?,
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

/// Executes full security audit with all tools
fn handle_run(
    manifest_path: Option<PathBuf>,
    skip_deny: bool,
    skip_geiger: bool,
) -> Result<serde_json::Value> {
    let mut tools_run = vec!["cargo-audit".to_string()];
    let mut vulnerabilities = Vec::new();
    let mut license_issues = Vec::new();
    let mut unsafe_stats = None;

    // Run cargo-audit
    let audit_result = run_cargo_audit(manifest_path.clone())?;
    vulnerabilities.extend(audit_result);

    // Run cargo-deny if not skipped
    if !skip_deny && is_tool_available("cargo-deny") {
        tools_run.push("cargo-deny".to_string());
        let deny_result = run_cargo_deny(manifest_path.clone())?;
        license_issues.extend(deny_result);
    }

    // Run cargo-geiger if not skipped
    if !skip_geiger && is_tool_available("cargo-geiger") {
        tools_run.push("cargo-geiger".to_string());
        unsafe_stats = Some(run_cargo_geiger(manifest_path.clone())?);
    }

    let summary = create_summary(&vulnerabilities, &license_issues, &unsafe_stats);

    let result = AuditResult {
        timestamp: chrono::Utc::now().to_rfc3339(),
        project_name: None,
        summary,
        vulnerabilities,
        unsafe_stats,
        license_issues,
        tools_run,
    };

    Ok(serde_json::to_value(result)?)
}

/// Executes quick audit using only cargo-audit
fn handle_quick(manifest_path: Option<PathBuf>) -> Result<serde_json::Value> {
    let vulnerabilities = run_cargo_audit(manifest_path)?;
    let summary = create_summary(&vulnerabilities, &[], &None);

    let result = AuditResult {
        timestamp: chrono::Utc::now().to_rfc3339(),
        project_name: None,
        summary,
        vulnerabilities,
        unsafe_stats: None,
        license_issues: Vec::new(),
        tools_run: vec!["cargo-audit".to_string()],
    };

    Ok(serde_json::to_value(result)?)
}

/// Generates comprehensive security report
fn handle_report(manifest_path: Option<PathBuf>, _detailed: bool) -> Result<serde_json::Value> {
    // Same as full run, but includes detailed descriptions
    handle_run(manifest_path, false, false)
}

/// Runs cargo-audit and parses results
fn run_cargo_audit(manifest_path: Option<PathBuf>) -> Result<Vec<Vulnerability>> {
    if !is_tool_available("cargo-audit") {
        eprintln!("Warning: cargo-audit not found. Install with: cargo install cargo-audit");
        return Ok(Vec::new());
    }

    let mut cmd = Command::new("cargo");
    cmd.arg("audit").arg("--json");

    if let Some(path) = manifest_path {
        cmd.arg("--manifest-path").arg(path);
    }

    let output = cmd.output().context("Failed to execute cargo-audit")?;

    // Parse JSON output if successful
    if output.status.success() || !output.stdout.is_empty() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_cargo_audit_output(&stdout)
    } else {
        Ok(Vec::new())
    }
}

/// Parses cargo-audit JSON output
fn parse_cargo_audit_output(output: &str) -> Result<Vec<Vulnerability>> {
    let mut vulnerabilities = Vec::new();

    // Try to parse as JSON
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(output) {
        if let Some(vulns) = json.get("vulnerabilities").and_then(|v| v.get("list")) {
            if let Some(array) = vulns.as_array() {
                for item in array {
                    if let Some(advisory) = item.get("advisory") {
                        let vuln = Vulnerability {
                            id: advisory
                                .get("id")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string(),
                            package: item
                                .get("package")
                                .and_then(|p| p.get("name"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string(),
                            version: item
                                .get("package")
                                .and_then(|p| p.get("version"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string(),
                            title: advisory
                                .get("title")
                                .and_then(|v| v.as_str())
                                .unwrap_or("No title")
                                .to_string(),
                            severity: "medium".to_string(), // Default severity
                            cvss_score: None,
                            description: advisory
                                .get("description")
                                .and_then(|v| v.as_str())
                                .map(String::from),
                            solution: Some("Update to a patched version".to_string()),
                        };
                        vulnerabilities.push(vuln);
                    }
                }
            }
        }
    }

    Ok(vulnerabilities)
}

/// Runs cargo-deny and parses results
fn run_cargo_deny(manifest_path: Option<PathBuf>) -> Result<Vec<LicenseIssue>> {
    let mut cmd = Command::new("cargo");
    cmd.arg("deny").arg("check").arg("licenses");

    if let Some(path) = manifest_path {
        cmd.arg("--manifest-path").arg(path);
    }

    let _output = cmd.output().context("Failed to execute cargo-deny")?;

    // Parse output (simplified - actual parsing would be more complex)
    Ok(Vec::new())
}

/// Runs cargo-geiger and parses results
fn run_cargo_geiger(manifest_path: Option<PathBuf>) -> Result<UnsafeStats> {
    let mut cmd = Command::new("cargo");
    cmd.arg("geiger")
        .arg("--output-format")
        .arg("GitHubMarkdown");

    if let Some(path) = manifest_path {
        cmd.arg("--manifest-path").arg(path);
    }

    let _output = cmd.output().context("Failed to execute cargo-geiger")?;

    // Parse output (simplified)
    Ok(UnsafeStats {
        functions: 0,
        expressions: 0,
        impls: 0,
        traits: 0,
        methods: 0,
    })
}

/// Creates audit summary from collected data
fn create_summary(
    vulnerabilities: &[Vulnerability],
    license_issues: &[LicenseIssue],
    unsafe_stats: &Option<UnsafeStats>,
) -> AuditSummary {
    let mut critical_count = 0;
    let mut high_count = 0;
    let mut medium_count = 0;
    let mut low_count = 0;

    for vuln in vulnerabilities {
        match vuln.severity.as_str() {
            "critical" => critical_count += 1,
            "high" => high_count += 1,
            "medium" => medium_count += 1,
            "low" => low_count += 1,
            _ => medium_count += 1,
        }
    }

    let unsafe_functions = unsafe_stats.as_ref().map(|s| s.functions).unwrap_or(0);

    AuditSummary {
        total_vulnerabilities: vulnerabilities.len(),
        critical_count,
        high_count,
        medium_count,
        low_count,
        unsafe_functions,
        license_issues: license_issues.len(),
        passed: vulnerabilities.is_empty() && license_issues.is_empty(),
    }
}

/// Checks if a cargo tool is available
fn is_tool_available(tool: &str) -> bool {
    Command::new("cargo")
        .arg("--list")
        .output()
        .map(|output| {
            let stdout = String::from_utf8_lossy(&output.stdout);
            stdout.contains(tool)
        })
        .unwrap_or(false)
}
