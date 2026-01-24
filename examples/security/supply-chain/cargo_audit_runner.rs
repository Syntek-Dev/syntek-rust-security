//! Cargo Audit Integration Example
//!
//! Demonstrates programmatic usage of cargo-audit for vulnerability scanning
//! in Rust projects. This provides automated security auditing of dependencies.

use std::collections::HashMap;
use std::process::Command;

/// Vulnerability severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn from_cvss(score: f32) -> Self {
        match score {
            s if s >= 9.0 => Severity::Critical,
            s if s >= 7.0 => Severity::High,
            s if s >= 4.0 => Severity::Medium,
            s if s > 0.0 => Severity::Low,
            _ => Severity::None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::None => "none",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// Represents a security advisory
#[derive(Debug, Clone)]
pub struct Advisory {
    pub id: String,
    pub package: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub cvss_score: Option<f32>,
    pub affected_versions: String,
    pub patched_versions: Option<String>,
    pub url: Option<String>,
}

/// Audit result for a project
#[derive(Debug, Clone)]
pub struct AuditResult {
    pub advisories: Vec<Advisory>,
    pub warnings: Vec<String>,
    pub scan_time_ms: u64,
}

impl AuditResult {
    pub fn is_clean(&self) -> bool {
        self.advisories.is_empty()
    }

    pub fn critical_count(&self) -> usize {
        self.advisories
            .iter()
            .filter(|a| a.severity == Severity::Critical)
            .count()
    }

    pub fn high_count(&self) -> usize {
        self.advisories
            .iter()
            .filter(|a| a.severity == Severity::High)
            .count()
    }

    pub fn by_severity(&self) -> HashMap<Severity, Vec<&Advisory>> {
        let mut map: HashMap<Severity, Vec<&Advisory>> = HashMap::new();
        for advisory in &self.advisories {
            map.entry(advisory.severity).or_default().push(advisory);
        }
        map
    }
}

/// Cargo audit runner
pub struct CargoAudit {
    database_path: Option<String>,
    deny_warnings: bool,
    ignore_advisories: Vec<String>,
}

impl Default for CargoAudit {
    fn default() -> Self {
        Self::new()
    }
}

impl CargoAudit {
    pub fn new() -> Self {
        Self {
            database_path: None,
            deny_warnings: false,
            ignore_advisories: Vec::new(),
        }
    }

    pub fn with_database(mut self, path: &str) -> Self {
        self.database_path = Some(path.to_string());
        self
    }

    pub fn deny_warnings(mut self) -> Self {
        self.deny_warnings = true;
        self
    }

    pub fn ignore(mut self, advisory_id: &str) -> Self {
        self.ignore_advisories.push(advisory_id.to_string());
        self
    }

    /// Run cargo audit and parse results
    pub fn run(&self, project_path: &str) -> Result<AuditResult, AuditError> {
        let start = std::time::Instant::now();

        let mut cmd = Command::new("cargo");
        cmd.arg("audit").arg("--json").current_dir(project_path);

        if let Some(ref db_path) = self.database_path {
            cmd.arg("--db").arg(db_path);
        }

        if self.deny_warnings {
            cmd.arg("--deny").arg("warnings");
        }

        for id in &self.ignore_advisories {
            cmd.arg("--ignore").arg(id);
        }

        let output = cmd
            .output()
            .map_err(|e| AuditError::CommandFailed(e.to_string()))?;

        let scan_time_ms = start.elapsed().as_millis() as u64;

        // Parse JSON output (simplified)
        let stdout = String::from_utf8_lossy(&output.stdout);
        let advisories = self.parse_json_output(&stdout)?;

        let warnings = if !output.status.success() && advisories.is_empty() {
            vec!["Audit completed with warnings".to_string()]
        } else {
            Vec::new()
        };

        Ok(AuditResult {
            advisories,
            warnings,
            scan_time_ms,
        })
    }

    fn parse_json_output(&self, _json: &str) -> Result<Vec<Advisory>, AuditError> {
        // Simplified parsing - in real implementation would use serde_json
        // This is a demonstration of the structure
        Ok(Vec::new())
    }

    /// Generate audit report in markdown format
    pub fn generate_report(&self, result: &AuditResult) -> String {
        let mut report = String::new();

        report.push_str("# Security Audit Report\n\n");
        report.push_str(&format!("Scan completed in {}ms\n\n", result.scan_time_ms));

        if result.is_clean() {
            report.push_str("## Status: CLEAN\n\n");
            report.push_str("No vulnerabilities found.\n");
            return report;
        }

        report.push_str("## Summary\n\n");
        report.push_str(&format!("- Critical: {}\n", result.critical_count()));
        report.push_str(&format!("- High: {}\n", result.high_count()));
        report.push_str(&format!("- Total: {}\n\n", result.advisories.len()));

        report.push_str("## Vulnerabilities\n\n");

        for advisory in &result.advisories {
            report.push_str(&format!("### {} - {}\n\n", advisory.id, advisory.package));
            report.push_str(&format!("**Severity**: {}\n\n", advisory.severity.as_str()));
            report.push_str(&format!("**Title**: {}\n\n", advisory.title));
            report.push_str(&format!("{}\n\n", advisory.description));
            report.push_str(&format!("**Affected**: {}\n", advisory.affected_versions));

            if let Some(ref patched) = advisory.patched_versions {
                report.push_str(&format!("**Patched**: {}\n", patched));
            }

            if let Some(ref url) = advisory.url {
                report.push_str(&format!("**More info**: {}\n", url));
            }

            report.push_str("\n---\n\n");
        }

        report
    }
}

#[derive(Debug)]
pub enum AuditError {
    CommandFailed(String),
    ParseError(String),
    DatabaseError(String),
}

/// Helper to create test advisories
pub fn create_test_advisory(id: &str, package: &str, severity: Severity) -> Advisory {
    Advisory {
        id: id.to_string(),
        package: package.to_string(),
        title: format!("Test vulnerability in {}", package),
        description: "This is a test advisory for demonstration purposes.".to_string(),
        severity,
        cvss_score: match severity {
            Severity::Critical => Some(9.5),
            Severity::High => Some(7.5),
            Severity::Medium => Some(5.0),
            Severity::Low => Some(2.0),
            Severity::None => None,
        },
        affected_versions: "< 1.0.0".to_string(),
        patched_versions: Some(">= 1.0.0".to_string()),
        url: Some(format!("https://rustsec.org/advisories/{}", id)),
    }
}

fn main() {
    println!("Cargo Audit Integration Example");
    println!("================================\n");

    // Create audit runner
    let audit = CargoAudit::new()
        .deny_warnings()
        .ignore("RUSTSEC-0000-0000"); // Example ignored advisory

    println!("Audit Configuration:");
    println!("  Deny warnings: true");
    println!("  Ignored: RUSTSEC-0000-0000\n");

    // Create sample result for demonstration
    let result = AuditResult {
        advisories: vec![
            create_test_advisory("RUSTSEC-2024-0001", "vulnerable-crate", Severity::Critical),
            create_test_advisory("RUSTSEC-2024-0002", "another-crate", Severity::High),
            create_test_advisory("RUSTSEC-2024-0003", "third-crate", Severity::Medium),
        ],
        warnings: vec![],
        scan_time_ms: 1234,
    };

    println!("Audit Results:");
    println!("  Clean: {}", result.is_clean());
    println!("  Critical: {}", result.critical_count());
    println!("  High: {}", result.high_count());
    println!("  Total: {}\n", result.advisories.len());

    // Generate and print report
    println!("Generated Report:");
    println!("==================");
    println!("{}", audit.generate_report(&result));

    // Show severity breakdown
    println!("\nAdvisories by Severity:");
    for (severity, advisories) in result.by_severity() {
        println!(
            "  {}: {} advisory(ies)",
            severity.as_str(),
            advisories.len()
        );
        for adv in advisories {
            println!("    - {} ({})", adv.id, adv.package);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_from_cvss() {
        assert_eq!(Severity::from_cvss(9.5), Severity::Critical);
        assert_eq!(Severity::from_cvss(8.0), Severity::High);
        assert_eq!(Severity::from_cvss(5.5), Severity::Medium);
        assert_eq!(Severity::from_cvss(2.0), Severity::Low);
        assert_eq!(Severity::from_cvss(0.0), Severity::None);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::None);
    }

    #[test]
    fn test_audit_result_clean() {
        let result = AuditResult {
            advisories: vec![],
            warnings: vec![],
            scan_time_ms: 100,
        };

        assert!(result.is_clean());
        assert_eq!(result.critical_count(), 0);
        assert_eq!(result.high_count(), 0);
    }

    #[test]
    fn test_audit_result_with_vulnerabilities() {
        let result = AuditResult {
            advisories: vec![
                create_test_advisory("RUSTSEC-0001", "crate1", Severity::Critical),
                create_test_advisory("RUSTSEC-0002", "crate2", Severity::Critical),
                create_test_advisory("RUSTSEC-0003", "crate3", Severity::High),
            ],
            warnings: vec![],
            scan_time_ms: 500,
        };

        assert!(!result.is_clean());
        assert_eq!(result.critical_count(), 2);
        assert_eq!(result.high_count(), 1);
    }

    #[test]
    fn test_by_severity() {
        let result = AuditResult {
            advisories: vec![
                create_test_advisory("RUSTSEC-0001", "crate1", Severity::High),
                create_test_advisory("RUSTSEC-0002", "crate2", Severity::High),
                create_test_advisory("RUSTSEC-0003", "crate3", Severity::Low),
            ],
            warnings: vec![],
            scan_time_ms: 100,
        };

        let by_sev = result.by_severity();
        assert_eq!(by_sev.get(&Severity::High).map(|v| v.len()), Some(2));
        assert_eq!(by_sev.get(&Severity::Low).map(|v| v.len()), Some(1));
    }

    #[test]
    fn test_cargo_audit_builder() {
        let audit = CargoAudit::new()
            .with_database("/path/to/db")
            .deny_warnings()
            .ignore("RUSTSEC-0000-0000");

        assert!(audit.database_path.is_some());
        assert!(audit.deny_warnings);
        assert_eq!(audit.ignore_advisories.len(), 1);
    }

    #[test]
    fn test_report_generation_clean() {
        let audit = CargoAudit::new();
        let result = AuditResult {
            advisories: vec![],
            warnings: vec![],
            scan_time_ms: 100,
        };

        let report = audit.generate_report(&result);
        assert!(report.contains("CLEAN"));
        assert!(report.contains("No vulnerabilities found"));
    }

    #[test]
    fn test_report_generation_with_vulns() {
        let audit = CargoAudit::new();
        let result = AuditResult {
            advisories: vec![create_test_advisory(
                "RUSTSEC-2024-0001",
                "test-crate",
                Severity::Critical,
            )],
            warnings: vec![],
            scan_time_ms: 200,
        };

        let report = audit.generate_report(&result);
        assert!(report.contains("RUSTSEC-2024-0001"));
        assert!(report.contains("test-crate"));
        assert!(report.contains("critical"));
    }

    #[test]
    fn test_advisory_creation() {
        let advisory = create_test_advisory("TEST-001", "my-crate", Severity::High);

        assert_eq!(advisory.id, "TEST-001");
        assert_eq!(advisory.package, "my-crate");
        assert_eq!(advisory.severity, Severity::High);
        assert_eq!(advisory.cvss_score, Some(7.5));
    }
}
