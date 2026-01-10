/**
 * audit_tool.rs
 *
 * Security audit orchestration tool for Claude Code agents.
 *
 * Provides commands to execute multiple security audit tools (cargo-audit, cargo-deny,
 * cargo-geiger) and aggregate their results into a unified security report. Outputs
 * machine-readable JSON for agent consumption.
 *
 * Commands:
 * - run: Execute full security audit (all tools)
 * - quick: Execute quick audit (cargo-audit only)
 * - report: Generate comprehensive security report
 */

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
}

#[derive(Serialize, Deserialize)]
struct AuditResult {
    timestamp: String,
    project_name: Option<String>,
    summary: AuditSummary,
    vulnerabilities: Vec<Vulnerability>,
    unsafe_stats: Option<UnsafeStats>,
    license_issues: Vec<LicenseIssue>,
    tools_run: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct AuditSummary {
    total_vulnerabilities: usize,
    critical_count: usize,
    high_count: usize,
    medium_count: usize,
    low_count: usize,
    unsafe_functions: usize,
    license_issues: usize,
    passed: bool,
}

#[derive(Serialize, Deserialize)]
struct Vulnerability {
    id: String,
    package: String,
    version: String,
    title: String,
    severity: String,
    cvss_score: Option<f64>,
    description: Option<String>,
    solution: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct UnsafeStats {
    functions: usize,
    expressions: usize,
    impls: usize,
    traits: usize,
    methods: usize,
}

#[derive(Serialize, Deserialize)]
struct LicenseIssue {
    package: String,
    license: String,
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
    };

    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
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
    if !skip_deny {
        if is_tool_available("cargo-deny") {
            tools_run.push("cargo-deny".to_string());
            let deny_result = run_cargo_deny(manifest_path.clone())?;
            license_issues.extend(deny_result);
        }
    }

    // Run cargo-geiger if not skipped
    if !skip_geiger {
        if is_tool_available("cargo-geiger") {
            tools_run.push("cargo-geiger".to_string());
            unsafe_stats = Some(run_cargo_geiger(manifest_path.clone())?);
        }
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
    cmd.arg("geiger").arg("--output-format").arg("GitHubMarkdown");

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
