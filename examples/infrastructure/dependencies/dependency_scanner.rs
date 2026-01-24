//! Dependency Scanner - Supply Chain Security Analysis
//!
//! This example demonstrates building a dependency analysis tool for
//! vulnerability scanning, license compliance, and supply chain security.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Dependency information
#[derive(Debug, Clone)]
pub struct Dependency {
    pub name: String,
    pub version: String,
    pub source: DependencySource,
    pub license: Option<String>,
    pub authors: Vec<String>,
    pub repository: Option<String>,
    pub description: Option<String>,
    pub dependencies: Vec<String>,
    pub features: Vec<String>,
    pub build_script: bool,
    pub proc_macro: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DependencySource {
    CratesIo,
    Git { url: String, rev: Option<String> },
    Path { path: PathBuf },
    Registry { name: String },
}

/// Vulnerability information
#[derive(Debug, Clone)]
pub struct Vulnerability {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: VulnerabilitySeverity,
    pub cvss_score: Option<f32>,
    pub affected_package: String,
    pub affected_versions: String,
    pub patched_versions: Option<String>,
    pub advisory_url: Option<String>,
    pub cve: Option<String>,
    pub published: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub enum VulnerabilitySeverity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl VulnerabilitySeverity {
    pub fn from_cvss(score: f32) -> Self {
        match score {
            s if s >= 9.0 => Self::Critical,
            s if s >= 7.0 => Self::High,
            s if s >= 4.0 => Self::Medium,
            s if s > 0.0 => Self::Low,
            _ => Self::None,
        }
    }
}

/// License information
#[derive(Debug, Clone)]
pub struct License {
    pub id: String,
    pub name: String,
    pub category: LicenseCategory,
    pub osi_approved: bool,
    pub copyleft: bool,
    pub patent_grant: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseCategory {
    Permissive,
    WeakCopyleft,
    StrongCopyleft,
    Proprietary,
    Unknown,
}

impl License {
    pub fn from_id(id: &str) -> Self {
        match id.to_uppercase().as_str() {
            "MIT" => Self {
                id: "MIT".to_string(),
                name: "MIT License".to_string(),
                category: LicenseCategory::Permissive,
                osi_approved: true,
                copyleft: false,
                patent_grant: false,
            },
            "APACHE-2.0" => Self {
                id: "Apache-2.0".to_string(),
                name: "Apache License 2.0".to_string(),
                category: LicenseCategory::Permissive,
                osi_approved: true,
                copyleft: false,
                patent_grant: true,
            },
            "GPL-3.0" | "GPL-3.0-ONLY" | "GPL-3.0-OR-LATER" => Self {
                id: "GPL-3.0".to_string(),
                name: "GNU General Public License v3.0".to_string(),
                category: LicenseCategory::StrongCopyleft,
                osi_approved: true,
                copyleft: true,
                patent_grant: true,
            },
            "LGPL-3.0" | "LGPL-3.0-ONLY" | "LGPL-3.0-OR-LATER" => Self {
                id: "LGPL-3.0".to_string(),
                name: "GNU Lesser General Public License v3.0".to_string(),
                category: LicenseCategory::WeakCopyleft,
                osi_approved: true,
                copyleft: true,
                patent_grant: true,
            },
            "MPL-2.0" => Self {
                id: "MPL-2.0".to_string(),
                name: "Mozilla Public License 2.0".to_string(),
                category: LicenseCategory::WeakCopyleft,
                osi_approved: true,
                copyleft: true,
                patent_grant: true,
            },
            "BSD-3-CLAUSE" => Self {
                id: "BSD-3-Clause".to_string(),
                name: "BSD 3-Clause License".to_string(),
                category: LicenseCategory::Permissive,
                osi_approved: true,
                copyleft: false,
                patent_grant: false,
            },
            "UNLICENSE" => Self {
                id: "Unlicense".to_string(),
                name: "The Unlicense".to_string(),
                category: LicenseCategory::Permissive,
                osi_approved: true,
                copyleft: false,
                patent_grant: false,
            },
            _ => Self {
                id: id.to_string(),
                name: format!("Unknown ({})", id),
                category: LicenseCategory::Unknown,
                osi_approved: false,
                copyleft: false,
                patent_grant: false,
            },
        }
    }
}

/// Scan result
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub scanned_at: u64,
    pub dependencies: Vec<Dependency>,
    pub vulnerabilities: Vec<VulnerabilityMatch>,
    pub license_issues: Vec<LicenseIssue>,
    pub unmaintained: Vec<UnmaintainedWarning>,
    pub yanked: Vec<YankedWarning>,
    pub stats: ScanStats,
}

#[derive(Debug, Clone)]
pub struct VulnerabilityMatch {
    pub dependency: String,
    pub version: String,
    pub vulnerability: Vulnerability,
}

#[derive(Debug, Clone)]
pub struct LicenseIssue {
    pub dependency: String,
    pub license: String,
    pub issue_type: LicenseIssueType,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseIssueType {
    Incompatible,
    Copyleft,
    Unknown,
    Multiple,
    Missing,
}

#[derive(Debug, Clone)]
pub struct UnmaintainedWarning {
    pub dependency: String,
    pub last_update: Option<u64>,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct YankedWarning {
    pub dependency: String,
    pub version: String,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ScanStats {
    pub total_dependencies: u32,
    pub direct_dependencies: u32,
    pub transitive_dependencies: u32,
    pub vulnerabilities_found: u32,
    pub critical_vulnerabilities: u32,
    pub high_vulnerabilities: u32,
    pub license_issues: u32,
    pub unmaintained_count: u32,
    pub yanked_count: u32,
}

/// Scanner configuration
#[derive(Debug, Clone)]
pub struct ScannerConfig {
    /// Check RustSec advisory database
    pub check_advisories: bool,
    /// Check license compatibility
    pub check_licenses: bool,
    /// Project license for compatibility check
    pub project_license: Option<String>,
    /// Denied licenses
    pub denied_licenses: HashSet<String>,
    /// Allowed licenses
    pub allowed_licenses: HashSet<String>,
    /// Check for unmaintained crates
    pub check_unmaintained: bool,
    /// Months without update to consider unmaintained
    pub unmaintained_threshold_months: u32,
    /// Check for yanked versions
    pub check_yanked: bool,
    /// Fail on severity level
    pub fail_on_severity: VulnerabilitySeverity,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        let mut allowed = HashSet::new();
        allowed.insert("MIT".to_string());
        allowed.insert("Apache-2.0".to_string());
        allowed.insert("BSD-3-Clause".to_string());
        allowed.insert("BSD-2-Clause".to_string());
        allowed.insert("ISC".to_string());
        allowed.insert("Unlicense".to_string());
        allowed.insert("CC0-1.0".to_string());
        allowed.insert("Zlib".to_string());

        Self {
            check_advisories: true,
            check_licenses: true,
            project_license: Some("MIT".to_string()),
            denied_licenses: HashSet::new(),
            allowed_licenses: allowed,
            check_unmaintained: true,
            unmaintained_threshold_months: 24,
            check_yanked: true,
            fail_on_severity: VulnerabilitySeverity::High,
        }
    }
}

/// Advisory database (simplified)
pub struct AdvisoryDatabase {
    advisories: Vec<Vulnerability>,
    last_updated: u64,
}

impl AdvisoryDatabase {
    pub fn new() -> Self {
        Self {
            advisories: Self::load_sample_advisories(),
            last_updated: current_timestamp(),
        }
    }

    fn load_sample_advisories() -> Vec<Vulnerability> {
        vec![
            Vulnerability {
                id: "RUSTSEC-2024-0001".to_string(),
                title: "Memory corruption in unsafe code".to_string(),
                description: "A buffer overflow exists in the parsing logic".to_string(),
                severity: VulnerabilitySeverity::Critical,
                cvss_score: Some(9.8),
                affected_package: "vulnerable-crate".to_string(),
                affected_versions: "< 2.0.0".to_string(),
                patched_versions: Some(">= 2.0.0".to_string()),
                advisory_url: Some("https://rustsec.org/advisories/RUSTSEC-2024-0001".to_string()),
                cve: Some("CVE-2024-12345".to_string()),
                published: current_timestamp() - 86400 * 30,
            },
            Vulnerability {
                id: "RUSTSEC-2024-0002".to_string(),
                title: "Denial of service via regex".to_string(),
                description: "Specially crafted regex can cause exponential backtracking"
                    .to_string(),
                severity: VulnerabilitySeverity::Medium,
                cvss_score: Some(5.3),
                affected_package: "regex-vulnerable".to_string(),
                affected_versions: "< 1.5.0".to_string(),
                patched_versions: Some(">= 1.5.0".to_string()),
                advisory_url: None,
                cve: None,
                published: current_timestamp() - 86400 * 60,
            },
        ]
    }

    pub fn query(&self, package: &str, version: &str) -> Vec<&Vulnerability> {
        self.advisories
            .iter()
            .filter(|v| v.affected_package == package)
            .filter(|v| self.version_affected(&v.affected_versions, version))
            .collect()
    }

    fn version_affected(&self, constraint: &str, version: &str) -> bool {
        // Simplified version matching
        if constraint.starts_with("< ") {
            let target = &constraint[2..];
            version < target
        } else if constraint.starts_with("<= ") {
            let target = &constraint[3..];
            version <= target
        } else if constraint.contains(',') {
            // Range like ">= 1.0, < 2.0"
            true // Simplified
        } else {
            constraint == version
        }
    }
}

impl Default for AdvisoryDatabase {
    fn default() -> Self {
        Self::new()
    }
}

/// Main dependency scanner
pub struct DependencyScanner {
    config: ScannerConfig,
    advisory_db: AdvisoryDatabase,
}

impl DependencyScanner {
    pub fn new(config: ScannerConfig) -> Self {
        Self {
            config,
            advisory_db: AdvisoryDatabase::new(),
        }
    }

    /// Scan a Cargo.toml file
    pub fn scan(&self, cargo_toml_path: &Path) -> ScanResult {
        // Parse dependencies (simulated)
        let dependencies = self.parse_dependencies(cargo_toml_path);
        let direct_count = dependencies.len() as u32;

        // Build dependency tree (simulated - would resolve transitive deps)
        let all_deps = self.resolve_transitive(&dependencies);
        let transitive_count = all_deps.len() as u32 - direct_count;

        let mut vulnerabilities = Vec::new();
        let mut license_issues = Vec::new();
        let mut unmaintained = Vec::new();
        let mut yanked = Vec::new();

        for dep in &all_deps {
            // Check vulnerabilities
            if self.config.check_advisories {
                let vulns = self.advisory_db.query(&dep.name, &dep.version);
                for vuln in vulns {
                    vulnerabilities.push(VulnerabilityMatch {
                        dependency: dep.name.clone(),
                        version: dep.version.clone(),
                        vulnerability: vuln.clone(),
                    });
                }
            }

            // Check licenses
            if self.config.check_licenses {
                if let Some(issue) = self.check_license(dep) {
                    license_issues.push(issue);
                }
            }

            // Check unmaintained
            if self.config.check_unmaintained {
                if let Some(warning) = self.check_unmaintained(dep) {
                    unmaintained.push(warning);
                }
            }

            // Check yanked
            if self.config.check_yanked {
                if let Some(warning) = self.check_yanked(dep) {
                    yanked.push(warning);
                }
            }
        }

        let stats = ScanStats {
            total_dependencies: all_deps.len() as u32,
            direct_dependencies: direct_count,
            transitive_dependencies: transitive_count,
            vulnerabilities_found: vulnerabilities.len() as u32,
            critical_vulnerabilities: vulnerabilities
                .iter()
                .filter(|v| v.vulnerability.severity == VulnerabilitySeverity::Critical)
                .count() as u32,
            high_vulnerabilities: vulnerabilities
                .iter()
                .filter(|v| v.vulnerability.severity == VulnerabilitySeverity::High)
                .count() as u32,
            license_issues: license_issues.len() as u32,
            unmaintained_count: unmaintained.len() as u32,
            yanked_count: yanked.len() as u32,
        };

        ScanResult {
            scanned_at: current_timestamp(),
            dependencies: all_deps,
            vulnerabilities,
            license_issues,
            unmaintained,
            yanked,
            stats,
        }
    }

    fn parse_dependencies(&self, _path: &Path) -> Vec<Dependency> {
        // Simulated - would parse Cargo.toml
        vec![
            Dependency {
                name: "serde".to_string(),
                version: "1.0.200".to_string(),
                source: DependencySource::CratesIo,
                license: Some("MIT OR Apache-2.0".to_string()),
                authors: vec!["Erick Tryzelaar".to_string(), "David Tolnay".to_string()],
                repository: Some("https://github.com/serde-rs/serde".to_string()),
                description: Some("A generic serialization/deserialization framework".to_string()),
                dependencies: vec!["serde_derive".to_string()],
                features: vec!["derive".to_string(), "std".to_string()],
                build_script: false,
                proc_macro: false,
            },
            Dependency {
                name: "tokio".to_string(),
                version: "1.37.0".to_string(),
                source: DependencySource::CratesIo,
                license: Some("MIT".to_string()),
                authors: vec!["Tokio Contributors".to_string()],
                repository: Some("https://github.com/tokio-rs/tokio".to_string()),
                description: Some("An asynchronous runtime for Rust".to_string()),
                dependencies: vec!["mio".to_string(), "parking_lot".to_string()],
                features: vec!["full".to_string(), "rt-multi-thread".to_string()],
                build_script: false,
                proc_macro: false,
            },
            Dependency {
                name: "vulnerable-crate".to_string(),
                version: "1.0.0".to_string(),
                source: DependencySource::CratesIo,
                license: Some("MIT".to_string()),
                authors: vec![],
                repository: None,
                description: None,
                dependencies: vec![],
                features: vec![],
                build_script: false,
                proc_macro: false,
            },
        ]
    }

    fn resolve_transitive(&self, direct: &[Dependency]) -> Vec<Dependency> {
        // Simulated - would actually resolve the full dependency tree
        let mut all = direct.to_vec();

        // Add some simulated transitive dependencies
        all.push(Dependency {
            name: "syn".to_string(),
            version: "2.0.60".to_string(),
            source: DependencySource::CratesIo,
            license: Some("MIT OR Apache-2.0".to_string()),
            authors: vec!["David Tolnay".to_string()],
            repository: Some("https://github.com/dtolnay/syn".to_string()),
            description: Some("Parser for Rust source code".to_string()),
            dependencies: vec![],
            features: vec![],
            build_script: false,
            proc_macro: false,
        });

        all
    }

    fn check_license(&self, dep: &Dependency) -> Option<LicenseIssue> {
        let license_str = dep.license.as_deref()?;

        // Parse license expression (simplified)
        let licenses: Vec<&str> = license_str.split(" OR ").collect();

        // Check if any license is allowed
        let has_allowed = licenses.iter().any(|l| {
            let normalized = l.trim().to_uppercase();
            self.config
                .allowed_licenses
                .iter()
                .any(|a| a.to_uppercase() == normalized)
        });

        // Check for denied licenses
        let has_denied = licenses.iter().any(|l| {
            let normalized = l.trim().to_uppercase();
            self.config
                .denied_licenses
                .iter()
                .any(|d| d.to_uppercase() == normalized)
        });

        if has_denied {
            return Some(LicenseIssue {
                dependency: dep.name.clone(),
                license: license_str.to_string(),
                issue_type: LicenseIssueType::Incompatible,
                message: "Uses a denied license".to_string(),
            });
        }

        if !has_allowed && !self.config.allowed_licenses.is_empty() {
            // Check for copyleft
            for l in &licenses {
                let license = License::from_id(l.trim());
                if license.copyleft {
                    return Some(LicenseIssue {
                        dependency: dep.name.clone(),
                        license: license_str.to_string(),
                        issue_type: LicenseIssueType::Copyleft,
                        message: format!("{} is a copyleft license", l),
                    });
                }
            }

            return Some(LicenseIssue {
                dependency: dep.name.clone(),
                license: license_str.to_string(),
                issue_type: LicenseIssueType::Unknown,
                message: "License not in allowed list".to_string(),
            });
        }

        None
    }

    fn check_unmaintained(&self, _dep: &Dependency) -> Option<UnmaintainedWarning> {
        // Simulated - would check crates.io API for last update
        None
    }

    fn check_yanked(&self, _dep: &Dependency) -> Option<YankedWarning> {
        // Simulated - would check crates.io API for yanked status
        None
    }

    /// Generate SBOM (Software Bill of Materials)
    pub fn generate_sbom(&self, result: &ScanResult) -> Sbom {
        Sbom {
            format: SbomFormat::CycloneDx,
            version: "1.4".to_string(),
            generated_at: current_timestamp(),
            components: result
                .dependencies
                .iter()
                .map(|d| SbomComponent {
                    name: d.name.clone(),
                    version: d.version.clone(),
                    purl: format!("pkg:cargo/{}@{}", d.name, d.version),
                    license: d.license.clone(),
                    hashes: Vec::new(),
                })
                .collect(),
        }
    }
}

/// Software Bill of Materials
#[derive(Debug, Clone)]
pub struct Sbom {
    pub format: SbomFormat,
    pub version: String,
    pub generated_at: u64,
    pub components: Vec<SbomComponent>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SbomFormat {
    CycloneDx,
    Spdx,
}

#[derive(Debug, Clone)]
pub struct SbomComponent {
    pub name: String,
    pub version: String,
    pub purl: String,
    pub license: Option<String>,
    pub hashes: Vec<(String, String)>,
}

impl Sbom {
    pub fn to_json(&self) -> String {
        let mut json = String::from("{\n");
        json.push_str(&format!("  \"format\": \"{:?}\",\n", self.format));
        json.push_str(&format!("  \"version\": \"{}\",\n", self.version));
        json.push_str("  \"components\": [\n");

        for (i, comp) in self.components.iter().enumerate() {
            json.push_str("    {\n");
            json.push_str(&format!("      \"name\": \"{}\",\n", comp.name));
            json.push_str(&format!("      \"version\": \"{}\",\n", comp.version));
            json.push_str(&format!("      \"purl\": \"{}\"\n", comp.purl));
            json.push_str("    }");
            if i < self.components.len() - 1 {
                json.push(',');
            }
            json.push('\n');
        }

        json.push_str("  ]\n");
        json.push_str("}\n");
        json
    }
}

// Helper functions

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn main() {
    println!("=== Dependency Scanner ===\n");

    // Create scanner
    let config = ScannerConfig::default();
    let scanner = DependencyScanner::new(config);

    // Scan project
    println!("--- Scanning Dependencies ---");
    let result = scanner.scan(Path::new("Cargo.toml"));

    // Print statistics
    println!("\n--- Statistics ---");
    println!("Total dependencies: {}", result.stats.total_dependencies);
    println!("Direct dependencies: {}", result.stats.direct_dependencies);
    println!(
        "Transitive dependencies: {}",
        result.stats.transitive_dependencies
    );

    // Print vulnerabilities
    println!("\n--- Vulnerabilities ---");
    if result.vulnerabilities.is_empty() {
        println!("No vulnerabilities found!");
    } else {
        for vuln in &result.vulnerabilities {
            let icon = match vuln.vulnerability.severity {
                VulnerabilitySeverity::Critical => "🔴",
                VulnerabilitySeverity::High => "🟠",
                VulnerabilitySeverity::Medium => "🟡",
                VulnerabilitySeverity::Low => "🟢",
                VulnerabilitySeverity::None => "⚪",
            };
            println!(
                "{} {} {} @ {} - {}",
                icon,
                vuln.vulnerability.id,
                vuln.dependency,
                vuln.version,
                vuln.vulnerability.title
            );
            if let Some(patched) = &vuln.vulnerability.patched_versions {
                println!("   Fix: upgrade to {}", patched);
            }
        }
    }

    // Print license issues
    println!("\n--- License Issues ---");
    if result.license_issues.is_empty() {
        println!("No license issues found!");
    } else {
        for issue in &result.license_issues {
            println!(
                "[{:?}] {} ({}): {}",
                issue.issue_type, issue.dependency, issue.license, issue.message
            );
        }
    }

    // Print dependencies
    println!("\n--- Dependencies ---");
    for dep in &result.dependencies {
        println!(
            "  {} {} ({:?})",
            dep.name,
            dep.version,
            dep.license.as_deref().unwrap_or("Unknown")
        );
    }

    // Generate SBOM
    println!("\n--- SBOM Generation ---");
    let sbom = scanner.generate_sbom(&result);
    println!("Generated SBOM with {} components", sbom.components.len());
    println!("Format: {:?}", sbom.format);

    // Print first part of SBOM JSON
    let sbom_json = sbom.to_json();
    println!(
        "\nSBOM preview:\n{}",
        &sbom_json[..sbom_json.len().min(500)]
    );

    println!("\n=== Dependency Scanner Complete ===");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_from_cvss() {
        assert_eq!(
            VulnerabilitySeverity::from_cvss(10.0),
            VulnerabilitySeverity::Critical
        );
        assert_eq!(
            VulnerabilitySeverity::from_cvss(8.0),
            VulnerabilitySeverity::High
        );
        assert_eq!(
            VulnerabilitySeverity::from_cvss(5.0),
            VulnerabilitySeverity::Medium
        );
        assert_eq!(
            VulnerabilitySeverity::from_cvss(2.0),
            VulnerabilitySeverity::Low
        );
        assert_eq!(
            VulnerabilitySeverity::from_cvss(0.0),
            VulnerabilitySeverity::None
        );
    }

    #[test]
    fn test_license_from_id() {
        let mit = License::from_id("MIT");
        assert_eq!(mit.category, LicenseCategory::Permissive);
        assert!(mit.osi_approved);
        assert!(!mit.copyleft);

        let gpl = License::from_id("GPL-3.0");
        assert_eq!(gpl.category, LicenseCategory::StrongCopyleft);
        assert!(gpl.copyleft);
    }

    #[test]
    fn test_advisory_database() {
        let db = AdvisoryDatabase::new();
        let vulns = db.query("vulnerable-crate", "1.0.0");
        assert!(!vulns.is_empty());

        let no_vulns = db.query("safe-crate", "1.0.0");
        assert!(no_vulns.is_empty());
    }

    #[test]
    fn test_scanner_config_defaults() {
        let config = ScannerConfig::default();
        assert!(config.check_advisories);
        assert!(config.check_licenses);
        assert!(config.allowed_licenses.contains("MIT"));
    }

    #[test]
    fn test_scan() {
        let scanner = DependencyScanner::new(ScannerConfig::default());
        let result = scanner.scan(Path::new("Cargo.toml"));

        assert!(result.stats.total_dependencies > 0);
        assert!(result
            .vulnerabilities
            .iter()
            .any(|v| v.dependency == "vulnerable-crate"));
    }

    #[test]
    fn test_sbom_generation() {
        let scanner = DependencyScanner::new(ScannerConfig::default());
        let result = scanner.scan(Path::new("Cargo.toml"));
        let sbom = scanner.generate_sbom(&result);

        assert!(!sbom.components.is_empty());
        assert!(sbom
            .components
            .iter()
            .all(|c| c.purl.starts_with("pkg:cargo/")));
    }

    #[test]
    fn test_sbom_json() {
        let sbom = Sbom {
            format: SbomFormat::CycloneDx,
            version: "1.4".to_string(),
            generated_at: 0,
            components: vec![SbomComponent {
                name: "test".to_string(),
                version: "1.0.0".to_string(),
                purl: "pkg:cargo/test@1.0.0".to_string(),
                license: Some("MIT".to_string()),
                hashes: Vec::new(),
            }],
        };

        let json = sbom.to_json();
        assert!(json.contains("\"name\": \"test\""));
        assert!(json.contains("CycloneDx"));
    }

    #[test]
    fn test_dependency_source() {
        let crates_io = DependencySource::CratesIo;
        let git = DependencySource::Git {
            url: "https://github.com/example/repo".to_string(),
            rev: Some("abc123".to_string()),
        };
        let path = DependencySource::Path {
            path: PathBuf::from("../local"),
        };

        assert_eq!(crates_io, DependencySource::CratesIo);
        assert!(matches!(git, DependencySource::Git { .. }));
        assert!(matches!(path, DependencySource::Path { .. }));
    }
}
