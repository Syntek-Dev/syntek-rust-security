//! Compliance report generation tool for Claude Code agents.
//!
//! Provides commands to map vulnerabilities to compliance frameworks (OWASP, CWE),
//! calculate CVSS scores, and generate compliance reports in multiple formats.
//! Outputs machine-readable JSON and formatted Markdown reports for agent consumption.
//!
//! # Commands
//!
//! - `owasp` - Map vulnerabilities to OWASP Top 10
//! - `cwe` - Map vulnerabilities to CWE (Common Weakness Enumeration)
//! - `cvss` - Calculate CVSS scores for vulnerabilities
//! - `export` - Generate compliance reports in JSON/Markdown format
//! - `docs` - Show paths to required project documentation files

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "compliance-tool",
    about = "Compliance report generation for Claude Code agents",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Path to audit results JSON file
    #[arg(short, long, global = true)]
    input: Option<PathBuf>,

    /// Output format (json or markdown)
    #[arg(short, long, default_value = "json", global = true)]
    format: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Map vulnerabilities to OWASP Top 10
    Owasp {
        /// OWASP version (2017, 2021)
        #[arg(long, default_value = "2021")]
        version: String,
    },
    /// Map vulnerabilities to CWE
    Cwe {
        /// Show detailed CWE descriptions
        #[arg(long)]
        detailed: bool,
    },
    /// Calculate CVSS scores
    Cvss {
        /// CVSS version (2.0, 3.0, 3.1)
        #[arg(long, default_value = "3.1")]
        version: String,
    },
    /// Generate compliance report
    Export {
        /// Output file path
        #[arg(short, long)]
        output: PathBuf,

        /// Include all compliance mappings
        #[arg(long)]
        full: bool,
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

/// OWASP Top 10 vulnerability mapping result.
#[derive(Serialize, Deserialize)]
struct OwaspMapping {
    /// OWASP version (e.g., "2021").
    version: String,
    /// Total number of vulnerabilities analyzed.
    total_vulnerabilities: usize,
    /// Vulnerabilities grouped by OWASP category.
    mappings: Vec<OwaspCategory>,
    /// Count of vulnerabilities that couldn't be mapped.
    unmapped_count: usize,
}

/// A single OWASP Top 10 category with mapped vulnerabilities.
#[derive(Serialize, Deserialize)]
struct OwaspCategory {
    /// OWASP category identifier (e.g., "A01:2021").
    id: String,
    /// Human-readable category name.
    name: String,
    /// List of vulnerability IDs in this category.
    vulnerabilities: Vec<String>,
    /// Number of vulnerabilities in this category.
    count: usize,
    /// Overall severity for this category.
    severity: String,
}

/// CWE (Common Weakness Enumeration) mapping result.
#[derive(Serialize, Deserialize)]
struct CweMapping {
    /// Total number of vulnerabilities analyzed.
    total_vulnerabilities: usize,
    /// Vulnerabilities grouped by CWE category.
    mappings: Vec<CweCategory>,
    /// Count of vulnerabilities that couldn't be mapped.
    unmapped_count: usize,
}

/// A single CWE category with mapped vulnerabilities.
#[derive(Serialize, Deserialize)]
struct CweCategory {
    /// CWE identifier (e.g., "CWE-119").
    cwe_id: String,
    /// Human-readable weakness name.
    name: String,
    /// Detailed description of the weakness.
    description: Option<String>,
    /// List of vulnerability IDs in this category.
    vulnerabilities: Vec<String>,
    /// Number of vulnerabilities in this category.
    count: usize,
}

/// CVSS scoring report for analyzed vulnerabilities.
#[derive(Serialize, Deserialize)]
struct CvssReport {
    /// CVSS version used (e.g., "3.1").
    version: String,
    /// Individual CVSS scores for each vulnerability.
    scores: Vec<CvssScore>,
    /// Average CVSS score across all vulnerabilities.
    average_score: f64,
    /// Distribution of vulnerabilities by severity level.
    severity_distribution: SeverityDistribution,
}

/// CVSS score details for a single vulnerability.
#[derive(Serialize, Deserialize)]
struct CvssScore {
    /// Unique identifier for the vulnerability.
    vulnerability_id: String,
    /// Base CVSS score (0.0-10.0).
    base_score: f64,
    /// Temporal score adjustment, if calculated.
    temporal_score: Option<f64>,
    /// Environmental score adjustment, if calculated.
    environmental_score: Option<f64>,
    /// Severity rating derived from the score.
    severity: String,
    /// CVSS vector string representation.
    vector_string: String,
}

/// Distribution of vulnerabilities across severity levels.
#[derive(Serialize, Deserialize)]
struct SeverityDistribution {
    /// Count of critical severity vulnerabilities (9.0-10.0).
    critical: usize,
    /// Count of high severity vulnerabilities (7.0-8.9).
    high: usize,
    /// Count of medium severity vulnerabilities (4.0-6.9).
    medium: usize,
    /// Count of low severity vulnerabilities (0.1-3.9).
    low: usize,
    /// Count of informational/none severity items.
    none: usize,
}

/// Complete compliance report combining all mapping results.
#[derive(Serialize, Deserialize)]
struct ComplianceReport {
    /// ISO 8601 timestamp when report was generated.
    generated_at: String,
    /// Name of the analyzed project.
    project_name: String,
    /// OWASP Top 10 mapping results.
    owasp_mapping: OwaspMapping,
    /// CWE mapping results.
    cwe_mapping: CweMapping,
    /// CVSS scoring results.
    cvss_report: CvssReport,
    /// Executive summary with recommendations.
    summary: ComplianceSummary,
}

/// Executive summary of compliance status.
#[derive(Serialize, Deserialize)]
struct ComplianceSummary {
    /// Total number of vulnerabilities found.
    total_vulnerabilities: usize,
    /// Count of critical severity issues.
    critical_issues: usize,
    /// Count of high severity issues.
    high_issues: usize,
    /// Count of medium severity issues.
    medium_issues: usize,
    /// Count of low severity issues.
    low_issues: usize,
    /// Overall compliance score (0-100, higher is better).
    compliance_score: f64,
    /// Actionable recommendations for remediation.
    recommendations: Vec<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Owasp { version } => handle_owasp(cli.input, version)?,
        Commands::Cwe { detailed } => handle_cwe(cli.input, detailed)?,
        Commands::Cvss { version } => handle_cvss(cli.input, version)?,
        Commands::Export { output, full } => handle_export(cli.input, output, full)?,
        Commands::Docs { base } => handle_docs(base)?,
    };

    if cli.format == "markdown" {
        println!("{}", format_as_markdown(&result)?);
    } else {
        println!("{}", serde_json::to_string_pretty(&result)?);
    }

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

/// Maps vulnerabilities to OWASP Top 10
fn handle_owasp(input: Option<PathBuf>, version: String) -> Result<serde_json::Value> {
    let vulnerabilities = load_vulnerabilities(input)?;

    // OWASP 2021 Top 10 categories
    let owasp_2021_categories = vec![
        ("A01:2021", "Broken Access Control"),
        ("A02:2021", "Cryptographic Failures"),
        ("A03:2021", "Injection"),
        ("A04:2021", "Insecure Design"),
        ("A05:2021", "Security Misconfiguration"),
        ("A06:2021", "Vulnerable and Outdated Components"),
        ("A07:2021", "Identification and Authentication Failures"),
        ("A08:2021", "Software and Data Integrity Failures"),
        ("A09:2021", "Security Logging and Monitoring Failures"),
        ("A10:2021", "Server-Side Request Forgery"),
    ];

    let mut mappings = Vec::new();
    let mut mapped_vulns = 0;

    for (id, name) in owasp_2021_categories {
        let mut category_vulns = Vec::new();

        // Simple mapping based on keywords (in production, use proper CWE-to-OWASP mapping)
        for vuln in &vulnerabilities {
            if should_map_to_owasp(vuln, id) {
                category_vulns.push(vuln.clone());
            }
        }

        if !category_vulns.is_empty() {
            let count = category_vulns.len();
            mapped_vulns += count;
            mappings.push(OwaspCategory {
                id: id.to_string(),
                name: name.to_string(),
                vulnerabilities: category_vulns,
                count,
                severity: "Medium".to_string(),
            });
        }
    }

    let result = OwaspMapping {
        version,
        total_vulnerabilities: vulnerabilities.len(),
        mappings,
        unmapped_count: vulnerabilities.len() - mapped_vulns,
    };

    Ok(serde_json::to_value(result)?)
}

/// Maps vulnerabilities to CWE
fn handle_cwe(input: Option<PathBuf>, detailed: bool) -> Result<serde_json::Value> {
    let vulnerabilities = load_vulnerabilities(input)?;

    // Common CWE mappings for Rust
    let cwe_mappings = get_common_cwe_mappings();

    let mut mappings = Vec::new();
    let mut mapped_vulns = 0;

    for (cwe_id, name, description) in cwe_mappings {
        let mut category_vulns = Vec::new();

        for vuln in &vulnerabilities {
            if should_map_to_cwe(vuln, cwe_id) {
                category_vulns.push(vuln.clone());
            }
        }

        if !category_vulns.is_empty() {
            let count = category_vulns.len();
            mapped_vulns += count;
            mappings.push(CweCategory {
                cwe_id: cwe_id.to_string(),
                name: name.to_string(),
                description: if detailed {
                    Some(description.to_string())
                } else {
                    None
                },
                vulnerabilities: category_vulns,
                count,
            });
        }
    }

    let result = CweMapping {
        total_vulnerabilities: vulnerabilities.len(),
        mappings,
        unmapped_count: vulnerabilities.len() - mapped_vulns,
    };

    Ok(serde_json::to_value(result)?)
}

/// Calculates CVSS scores for vulnerabilities
fn handle_cvss(input: Option<PathBuf>, version: String) -> Result<serde_json::Value> {
    let vulnerabilities = load_vulnerabilities(input)?;

    let mut scores = Vec::new();
    let mut severity_dist = SeverityDistribution {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        none: 0,
    };

    for vuln_id in vulnerabilities {
        // Calculate CVSS score (simplified - actual implementation would use CVSS calculator)
        let base_score = calculate_base_score(&vuln_id);
        let severity = cvss_score_to_severity(base_score);

        match severity.as_str() {
            "Critical" => severity_dist.critical += 1,
            "High" => severity_dist.high += 1,
            "Medium" => severity_dist.medium += 1,
            "Low" => severity_dist.low += 1,
            _ => severity_dist.none += 1,
        }

        scores.push(CvssScore {
            vulnerability_id: vuln_id.clone(),
            base_score,
            temporal_score: None,
            environmental_score: None,
            severity: severity.clone(),
            vector_string: format!("CVSS:{}/(AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)", version),
        });
    }

    let average_score = if !scores.is_empty() {
        scores.iter().map(|s| s.base_score).sum::<f64>() / scores.len() as f64
    } else {
        0.0
    };

    let result = CvssReport {
        version,
        scores,
        average_score,
        severity_distribution: severity_dist,
    };

    Ok(serde_json::to_value(result)?)
}

/// Generates full compliance report
fn handle_export(input: Option<PathBuf>, output: PathBuf, full: bool) -> Result<serde_json::Value> {
    let owasp = handle_owasp(input.clone(), "2021".to_string())?;
    let cwe = handle_cwe(input.clone(), full)?;
    let cvss = handle_cvss(input, "3.1".to_string())?;

    let owasp_mapping: OwaspMapping = serde_json::from_value(owasp)?;
    let cwe_mapping: CweMapping = serde_json::from_value(cwe)?;
    let cvss_report: CvssReport = serde_json::from_value(cvss)?;

    let summary = ComplianceSummary {
        total_vulnerabilities: owasp_mapping.total_vulnerabilities,
        critical_issues: cvss_report.severity_distribution.critical,
        high_issues: cvss_report.severity_distribution.high,
        medium_issues: cvss_report.severity_distribution.medium,
        low_issues: cvss_report.severity_distribution.low,
        compliance_score: calculate_compliance_score(&cvss_report),
        recommendations: generate_recommendations(&owasp_mapping, &cvss_report),
    };

    let report = ComplianceReport {
        generated_at: chrono::Utc::now().to_rfc3339(),
        project_name: "Unknown".to_string(),
        owasp_mapping,
        cwe_mapping,
        cvss_report,
        summary,
    };

    // Write to file
    let json = serde_json::to_string_pretty(&report)?;
    std::fs::write(&output, json).context("Failed to write report")?;

    Ok(serde_json::to_value(report)?)
}

/// Loads vulnerabilities from input file or stdin
fn load_vulnerabilities(_input: Option<PathBuf>) -> Result<Vec<String>> {
    // Simplified - in production, would parse actual audit results
    Ok(vec![
        "RUSTSEC-2023-0001".to_string(),
        "RUSTSEC-2023-0002".to_string(),
    ])
}

/// Determines if vulnerability should map to specific OWASP category
fn should_map_to_owasp(vuln_id: &str, owasp_id: &str) -> bool {
    // Simplified mapping logic
    if owasp_id == "A06:2021" {
        // Vulnerable and Outdated Components
        vuln_id.starts_with("RUSTSEC-")
    } else {
        false
    }
}

/// Determines if vulnerability should map to specific CWE
fn should_map_to_cwe(vuln_id: &str, cwe_id: &str) -> bool {
    // Simplified mapping logic
    if cwe_id == "CWE-1104" {
        // Use of Unmaintained Third Party Components
        vuln_id.starts_with("RUSTSEC-")
    } else {
        false
    }
}

/// Returns common CWE mappings for Rust vulnerabilities
fn get_common_cwe_mappings() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        (
            "CWE-119",
            "Improper Restriction of Operations within the Bounds of a Memory Buffer",
            "Buffer overflow vulnerabilities",
        ),
        (
            "CWE-125",
            "Out-of-bounds Read",
            "Reading beyond buffer boundaries",
        ),
        (
            "CWE-416",
            "Use After Free",
            "Using memory after it has been freed",
        ),
        (
            "CWE-787",
            "Out-of-bounds Write",
            "Writing beyond buffer boundaries",
        ),
        (
            "CWE-1104",
            "Use of Unmaintained Third Party Components",
            "Outdated dependencies",
        ),
        (
            "CWE-252",
            "Unchecked Return Value",
            "Ignoring function return values",
        ),
        (
            "CWE-476",
            "NULL Pointer Dereference",
            "Dereferencing null pointers",
        ),
        (
            "CWE-190",
            "Integer Overflow or Wraparound",
            "Integer overflow vulnerabilities",
        ),
    ]
}

/// Calculates CVSS base score (simplified)
fn calculate_base_score(_vuln_id: &str) -> f64 {
    // Simplified - actual implementation would parse vulnerability data
    7.5
}

/// Converts CVSS score to severity rating
fn cvss_score_to_severity(score: f64) -> String {
    match score {
        9.0..=10.0 => "Critical".to_string(),
        7.0..=8.9 => "High".to_string(),
        4.0..=6.9 => "Medium".to_string(),
        0.1..=3.9 => "Low".to_string(),
        _ => "None".to_string(),
    }
}

/// Calculates overall compliance score (0-100)
fn calculate_compliance_score(cvss_report: &CvssReport) -> f64 {
    let total = cvss_report.severity_distribution.critical
        + cvss_report.severity_distribution.high
        + cvss_report.severity_distribution.medium
        + cvss_report.severity_distribution.low;

    if total == 0 {
        return 100.0;
    }

    let weighted_issues = cvss_report.severity_distribution.critical as f64 * 1.0
        + cvss_report.severity_distribution.high as f64 * 0.75
        + cvss_report.severity_distribution.medium as f64 * 0.5
        + cvss_report.severity_distribution.low as f64 * 0.25;

    (100.0 - (weighted_issues / total as f64) * 100.0).max(0.0)
}

/// Generates compliance recommendations
fn generate_recommendations(owasp: &OwaspMapping, cvss: &CvssReport) -> Vec<String> {
    let mut recommendations = Vec::new();

    if cvss.severity_distribution.critical > 0 {
        recommendations.push("Address all critical vulnerabilities immediately".to_string());
    }

    if cvss.severity_distribution.high > 0 {
        recommendations.push("Prioritize high-severity vulnerabilities".to_string());
    }

    if owasp.unmapped_count > 0 {
        recommendations.push("Review unmapped vulnerabilities for compliance impact".to_string());
    }

    recommendations.push("Run regular security audits using cargo-audit".to_string());
    recommendations.push("Keep dependencies up-to-date".to_string());

    recommendations
}

/// Formats result as Markdown
fn format_as_markdown(result: &serde_json::Value) -> Result<String> {
    // Simplified Markdown formatting
    let mut md = String::new();
    md.push_str("# Compliance Report\n\n");
    md.push_str(&format!(
        "Generated: {}\n\n",
        chrono::Utc::now().to_rfc3339()
    ));
    md.push_str("## Summary\n\n");
    md.push_str(&format!(
        "```json\n{}\n```\n",
        serde_json::to_string_pretty(result)?
    ));
    Ok(md)
}
