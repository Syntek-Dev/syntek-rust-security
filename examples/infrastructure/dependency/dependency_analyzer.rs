//! Dependency Analyzer
//!
//! Security-focused dependency analysis with vulnerability scanning,
//! license compliance, and dependency tree visualization.

use std::collections::{HashMap, HashSet};

/// Dependency information
#[derive(Debug, Clone)]
pub struct Dependency {
    pub name: String,
    pub version: String,
    pub source: DependencySource,
    pub features: Vec<String>,
    pub optional: bool,
    pub dependencies: Vec<String>,
}

/// Dependency source
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DependencySource {
    CratesIo,
    Git { url: String, rev: Option<String> },
    Path { path: String },
    Registry { registry: String },
}

/// Vulnerability information
#[derive(Debug, Clone)]
pub struct Vulnerability {
    pub id: String,
    pub package: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub cvss_score: Option<f32>,
    pub affected_versions: String,
    pub patched_versions: Option<String>,
    pub references: Vec<String>,
}

/// Severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }

    pub fn from_cvss(score: f32) -> Self {
        match score {
            s if s >= 9.0 => Severity::Critical,
            s if s >= 7.0 => Severity::High,
            s if s >= 4.0 => Severity::Medium,
            _ => Severity::Low,
        }
    }
}

/// License information
#[derive(Debug, Clone)]
pub struct License {
    pub name: String,
    pub spdx_id: Option<String>,
    pub category: LicenseCategory,
    pub is_osi_approved: bool,
}

/// License categories
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseCategory {
    Permissive,
    Copyleft,
    WeakCopyleft,
    Proprietary,
    PublicDomain,
    Unknown,
}

impl LicenseCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            LicenseCategory::Permissive => "Permissive",
            LicenseCategory::Copyleft => "Copyleft",
            LicenseCategory::WeakCopyleft => "Weak Copyleft",
            LicenseCategory::Proprietary => "Proprietary",
            LicenseCategory::PublicDomain => "Public Domain",
            LicenseCategory::Unknown => "Unknown",
        }
    }
}

/// Dependency analyzer
#[derive(Debug)]
pub struct DependencyAnalyzer {
    dependencies: HashMap<String, Dependency>,
    vulnerabilities: Vec<Vulnerability>,
    licenses: HashMap<String, License>,
    config: AnalyzerConfig,
}

/// Analyzer configuration
#[derive(Debug, Clone)]
pub struct AnalyzerConfig {
    /// Check for vulnerabilities
    pub check_vulnerabilities: bool,
    /// Check license compliance
    pub check_licenses: bool,
    /// Allowed licenses
    pub allowed_licenses: HashSet<String>,
    /// Blocked licenses
    pub blocked_licenses: HashSet<String>,
    /// Maximum dependency depth
    pub max_depth: usize,
    /// Check for yanked crates
    pub check_yanked: bool,
    /// Minimum required MSRV
    pub required_msrv: Option<String>,
}

impl Default for AnalyzerConfig {
    fn default() -> Self {
        let mut allowed = HashSet::new();
        for license in &[
            "MIT",
            "Apache-2.0",
            "BSD-2-Clause",
            "BSD-3-Clause",
            "ISC",
            "Zlib",
            "Unlicense",
            "CC0-1.0",
        ] {
            allowed.insert(license.to_string());
        }

        let mut blocked = HashSet::new();
        for license in &["GPL-3.0", "AGPL-3.0", "SSPL-1.0"] {
            blocked.insert(license.to_string());
        }

        Self {
            check_vulnerabilities: true,
            check_licenses: true,
            allowed_licenses: allowed,
            blocked_licenses: blocked,
            max_depth: 10,
            check_yanked: true,
            required_msrv: None,
        }
    }
}

/// Analysis result
#[derive(Debug)]
pub struct AnalysisResult {
    pub total_dependencies: usize,
    pub direct_dependencies: usize,
    pub transitive_dependencies: usize,
    pub vulnerabilities: Vec<Vulnerability>,
    pub license_issues: Vec<LicenseIssue>,
    pub outdated_dependencies: Vec<OutdatedDependency>,
    pub duplicate_dependencies: Vec<DuplicateDependency>,
    pub unused_dependencies: Vec<String>,
    pub security_score: u8,
}

/// License issue
#[derive(Debug)]
pub struct LicenseIssue {
    pub package: String,
    pub license: String,
    pub issue_type: LicenseIssueType,
    pub message: String,
}

/// License issue type
#[derive(Debug, Clone, Copy)]
pub enum LicenseIssueType {
    Blocked,
    Unknown,
    Incompatible,
    NotOsiApproved,
}

/// Outdated dependency
#[derive(Debug)]
pub struct OutdatedDependency {
    pub name: String,
    pub current_version: String,
    pub latest_version: String,
    pub is_major_update: bool,
}

/// Duplicate dependency
#[derive(Debug)]
pub struct DuplicateDependency {
    pub name: String,
    pub versions: Vec<String>,
}

impl DependencyAnalyzer {
    pub fn new(config: AnalyzerConfig) -> Self {
        Self {
            dependencies: HashMap::new(),
            vulnerabilities: Vec::new(),
            licenses: HashMap::new(),
            config,
        }
    }

    /// Add a dependency
    pub fn add_dependency(&mut self, dep: Dependency) {
        self.dependencies.insert(dep.name.clone(), dep);
    }

    /// Add vulnerability database entries
    pub fn add_vulnerability(&mut self, vuln: Vulnerability) {
        self.vulnerabilities.push(vuln);
    }

    /// Add license information
    pub fn add_license(&mut self, package: &str, license: License) {
        self.licenses.insert(package.to_string(), license);
    }

    /// Analyze all dependencies
    pub fn analyze(&self) -> AnalysisResult {
        let total = self.dependencies.len();
        let direct = self
            .dependencies
            .values()
            .filter(|d| d.dependencies.is_empty())
            .count();

        let vulns = self.check_vulnerabilities();
        let license_issues = self.check_licenses();
        let duplicates = self.find_duplicates();
        let outdated = self.find_outdated();

        let security_score = self.calculate_security_score(&vulns, &license_issues);

        AnalysisResult {
            total_dependencies: total,
            direct_dependencies: direct,
            transitive_dependencies: total - direct,
            vulnerabilities: vulns,
            license_issues,
            outdated_dependencies: outdated,
            duplicate_dependencies: duplicates,
            unused_dependencies: Vec::new(), // Would require build graph analysis
            security_score,
        }
    }

    /// Check for vulnerabilities
    fn check_vulnerabilities(&self) -> Vec<Vulnerability> {
        if !self.config.check_vulnerabilities {
            return Vec::new();
        }

        let mut found = Vec::new();

        for vuln in &self.vulnerabilities {
            if self.dependencies.contains_key(&vuln.package) {
                // In a real implementation, we'd check version ranges
                found.push(vuln.clone());
            }
        }

        found
    }

    /// Check license compliance
    fn check_licenses(&self) -> Vec<LicenseIssue> {
        if !self.config.check_licenses {
            return Vec::new();
        }

        let mut issues = Vec::new();

        for (package, license) in &self.licenses {
            // Check if license is blocked
            if let Some(ref spdx) = license.spdx_id {
                if self.config.blocked_licenses.contains(spdx) {
                    issues.push(LicenseIssue {
                        package: package.clone(),
                        license: spdx.clone(),
                        issue_type: LicenseIssueType::Blocked,
                        message: format!("License '{}' is in the blocked list", spdx),
                    });
                    continue;
                }

                // Check if license is allowed
                if !self.config.allowed_licenses.contains(spdx) {
                    issues.push(LicenseIssue {
                        package: package.clone(),
                        license: spdx.clone(),
                        issue_type: LicenseIssueType::Unknown,
                        message: format!("License '{}' is not in the allowed list", spdx),
                    });
                }
            } else {
                issues.push(LicenseIssue {
                    package: package.clone(),
                    license: license.name.clone(),
                    issue_type: LicenseIssueType::Unknown,
                    message: "Unable to determine SPDX license identifier".to_string(),
                });
            }

            // Check OSI approval
            if !license.is_osi_approved {
                issues.push(LicenseIssue {
                    package: package.clone(),
                    license: license.name.clone(),
                    issue_type: LicenseIssueType::NotOsiApproved,
                    message: "License is not OSI approved".to_string(),
                });
            }
        }

        issues
    }

    /// Find duplicate dependencies
    fn find_duplicates(&self) -> Vec<DuplicateDependency> {
        let mut by_name: HashMap<String, Vec<String>> = HashMap::new();

        for (name, dep) in &self.dependencies {
            // Extract base name (without version)
            let base_name = name.split('@').next().unwrap_or(name).to_string();
            by_name
                .entry(base_name)
                .or_default()
                .push(dep.version.clone());
        }

        by_name
            .into_iter()
            .filter(|(_, versions)| versions.len() > 1)
            .map(|(name, versions)| DuplicateDependency { name, versions })
            .collect()
    }

    /// Find outdated dependencies
    fn find_outdated(&self) -> Vec<OutdatedDependency> {
        // In a real implementation, this would query crates.io
        // For demo, return empty
        Vec::new()
    }

    /// Calculate security score
    fn calculate_security_score(
        &self,
        vulns: &[Vulnerability],
        license_issues: &[LicenseIssue],
    ) -> u8 {
        let mut score: i32 = 100;

        // Deduct for vulnerabilities
        for vuln in vulns {
            match vuln.severity {
                Severity::Critical => score -= 25,
                Severity::High => score -= 15,
                Severity::Medium => score -= 10,
                Severity::Low => score -= 5,
            }
        }

        // Deduct for license issues
        for issue in license_issues {
            match issue.issue_type {
                LicenseIssueType::Blocked => score -= 20,
                LicenseIssueType::Incompatible => score -= 15,
                LicenseIssueType::Unknown => score -= 5,
                LicenseIssueType::NotOsiApproved => score -= 2,
            }
        }

        score.max(0).min(100) as u8
    }

    /// Generate dependency tree
    pub fn dependency_tree(&self, root: &str, depth: usize) -> String {
        let mut output = String::new();
        let mut visited = HashSet::new();
        self.build_tree(&mut output, root, 0, depth, &mut visited);
        output
    }

    fn build_tree(
        &self,
        output: &mut String,
        name: &str,
        current_depth: usize,
        max_depth: usize,
        visited: &mut HashSet<String>,
    ) {
        if current_depth > max_depth || visited.contains(name) {
            return;
        }

        visited.insert(name.to_string());

        let indent = "  ".repeat(current_depth);
        let prefix = if current_depth == 0 { "" } else { "├── " };

        if let Some(dep) = self.dependencies.get(name) {
            output.push_str(&format!(
                "{}{}{} v{}\n",
                indent, prefix, dep.name, dep.version
            ));

            for child in &dep.dependencies {
                self.build_tree(output, child, current_depth + 1, max_depth, visited);
            }
        } else {
            output.push_str(&format!("{}{}{} (not found)\n", indent, prefix, name));
        }
    }

    /// Generate SBOM (Software Bill of Materials)
    pub fn generate_sbom(&self) -> Sbom {
        let components: Vec<SbomComponent> = self
            .dependencies
            .values()
            .map(|dep| {
                let license = self.licenses.get(&dep.name);
                SbomComponent {
                    name: dep.name.clone(),
                    version: dep.version.clone(),
                    purl: format!("pkg:cargo/{}@{}", dep.name, dep.version),
                    license: license.map(|l| l.name.clone()),
                    source: match &dep.source {
                        DependencySource::CratesIo => "crates.io".to_string(),
                        DependencySource::Git { url, .. } => url.clone(),
                        DependencySource::Path { path } => path.clone(),
                        DependencySource::Registry { registry } => registry.clone(),
                    },
                }
            })
            .collect();

        Sbom {
            bom_format: "CycloneDX".to_string(),
            spec_version: "1.4".to_string(),
            components,
        }
    }

    /// Generate report
    pub fn generate_report(&self, result: &AnalysisResult) -> String {
        let mut report = String::new();

        report.push_str("=== Dependency Analysis Report ===\n\n");

        // Summary
        report.push_str("## Summary\n\n");
        report.push_str(&format!(
            "Total Dependencies: {}\n",
            result.total_dependencies
        ));
        report.push_str(&format!("  Direct: {}\n", result.direct_dependencies));
        report.push_str(&format!(
            "  Transitive: {}\n",
            result.transitive_dependencies
        ));
        report.push_str(&format!(
            "Security Score: {}/100\n\n",
            result.security_score
        ));

        // Vulnerabilities
        if !result.vulnerabilities.is_empty() {
            report.push_str("## Vulnerabilities\n\n");
            for vuln in &result.vulnerabilities {
                report.push_str(&format!(
                    "- [{}] {} in {} ({})\n  {}\n",
                    vuln.severity.as_str(),
                    vuln.id,
                    vuln.package,
                    vuln.affected_versions,
                    vuln.title
                ));
                if let Some(ref patched) = vuln.patched_versions {
                    report.push_str(&format!("  Patched in: {}\n", patched));
                }
                report.push('\n');
            }
        }

        // License Issues
        if !result.license_issues.is_empty() {
            report.push_str("## License Issues\n\n");
            for issue in &result.license_issues {
                report.push_str(&format!(
                    "- {}: {} ({})\n  {}\n\n",
                    issue.package,
                    issue.license,
                    match issue.issue_type {
                        LicenseIssueType::Blocked => "BLOCKED",
                        LicenseIssueType::Unknown => "UNKNOWN",
                        LicenseIssueType::Incompatible => "INCOMPATIBLE",
                        LicenseIssueType::NotOsiApproved => "NOT OSI APPROVED",
                    },
                    issue.message
                ));
            }
        }

        // Duplicates
        if !result.duplicate_dependencies.is_empty() {
            report.push_str("## Duplicate Dependencies\n\n");
            for dup in &result.duplicate_dependencies {
                report.push_str(&format!(
                    "- {}: versions {}\n",
                    dup.name,
                    dup.versions.join(", ")
                ));
            }
            report.push('\n');
        }

        // Outdated
        if !result.outdated_dependencies.is_empty() {
            report.push_str("## Outdated Dependencies\n\n");
            for outdated in &result.outdated_dependencies {
                let update_type = if outdated.is_major_update {
                    "MAJOR"
                } else {
                    "minor"
                };
                report.push_str(&format!(
                    "- {}: {} -> {} ({})\n",
                    outdated.name, outdated.current_version, outdated.latest_version, update_type
                ));
            }
        }

        report
    }
}

/// SBOM (Software Bill of Materials)
#[derive(Debug)]
pub struct Sbom {
    pub bom_format: String,
    pub spec_version: String,
    pub components: Vec<SbomComponent>,
}

/// SBOM component
#[derive(Debug)]
pub struct SbomComponent {
    pub name: String,
    pub version: String,
    pub purl: String,
    pub license: Option<String>,
    pub source: String,
}

impl Sbom {
    /// Export to JSON format
    pub fn to_json(&self) -> String {
        let mut output = String::new();
        output.push_str("{\n");
        output.push_str(&format!("  \"bomFormat\": \"{}\",\n", self.bom_format));
        output.push_str(&format!("  \"specVersion\": \"{}\",\n", self.spec_version));
        output.push_str("  \"components\": [\n");

        for (i, comp) in self.components.iter().enumerate() {
            output.push_str("    {\n");
            output.push_str(&format!("      \"name\": \"{}\",\n", comp.name));
            output.push_str(&format!("      \"version\": \"{}\",\n", comp.version));
            output.push_str(&format!("      \"purl\": \"{}\",\n", comp.purl));
            if let Some(ref license) = comp.license {
                output.push_str(&format!("      \"license\": \"{}\",\n", license));
            }
            output.push_str(&format!("      \"source\": \"{}\"\n", comp.source));
            output.push_str("    }");
            if i < self.components.len() - 1 {
                output.push(',');
            }
            output.push('\n');
        }

        output.push_str("  ]\n");
        output.push_str("}\n");
        output
    }
}

fn main() {
    println!("=== Dependency Analyzer Demo ===\n");

    let config = AnalyzerConfig::default();
    let mut analyzer = DependencyAnalyzer::new(config);

    // Add sample dependencies
    analyzer.add_dependency(Dependency {
        name: "serde".to_string(),
        version: "1.0.193".to_string(),
        source: DependencySource::CratesIo,
        features: vec!["derive".to_string()],
        optional: false,
        dependencies: vec!["serde_derive".to_string()],
    });

    analyzer.add_dependency(Dependency {
        name: "serde_derive".to_string(),
        version: "1.0.193".to_string(),
        source: DependencySource::CratesIo,
        features: vec![],
        optional: false,
        dependencies: vec![
            "proc-macro2".to_string(),
            "quote".to_string(),
            "syn".to_string(),
        ],
    });

    analyzer.add_dependency(Dependency {
        name: "tokio".to_string(),
        version: "1.35.1".to_string(),
        source: DependencySource::CratesIo,
        features: vec!["full".to_string()],
        optional: false,
        dependencies: vec![],
    });

    analyzer.add_dependency(Dependency {
        name: "vulnerable-crate".to_string(),
        version: "0.1.0".to_string(),
        source: DependencySource::CratesIo,
        features: vec![],
        optional: false,
        dependencies: vec![],
    });

    // Add vulnerability
    analyzer.add_vulnerability(Vulnerability {
        id: "RUSTSEC-2024-0001".to_string(),
        package: "vulnerable-crate".to_string(),
        title: "Memory safety issue in vulnerable-crate".to_string(),
        description: "A memory safety issue was discovered that could lead to undefined behavior."
            .to_string(),
        severity: Severity::High,
        cvss_score: Some(7.5),
        affected_versions: "< 0.2.0".to_string(),
        patched_versions: Some(">= 0.2.0".to_string()),
        references: vec!["https://rustsec.org/advisories/RUSTSEC-2024-0001".to_string()],
    });

    // Add licenses
    analyzer.add_license(
        "serde",
        License {
            name: "MIT OR Apache-2.0".to_string(),
            spdx_id: Some("MIT".to_string()),
            category: LicenseCategory::Permissive,
            is_osi_approved: true,
        },
    );

    analyzer.add_license(
        "tokio",
        License {
            name: "MIT".to_string(),
            spdx_id: Some("MIT".to_string()),
            category: LicenseCategory::Permissive,
            is_osi_approved: true,
        },
    );

    analyzer.add_license(
        "vulnerable-crate",
        License {
            name: "GPL-3.0".to_string(),
            spdx_id: Some("GPL-3.0".to_string()),
            category: LicenseCategory::Copyleft,
            is_osi_approved: true,
        },
    );

    // Run analysis
    let result = analyzer.analyze();

    // Print report
    println!("{}", analyzer.generate_report(&result));

    // Print dependency tree
    println!("\n=== Dependency Tree ===\n");
    println!("{}", analyzer.dependency_tree("serde", 3));

    // Generate SBOM
    println!("\n=== SBOM (JSON) ===\n");
    let sbom = analyzer.generate_sbom();
    println!("{}", sbom.to_json());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_analyzer() -> DependencyAnalyzer {
        DependencyAnalyzer::new(AnalyzerConfig::default())
    }

    #[test]
    fn test_add_dependency() {
        let mut analyzer = create_analyzer();

        analyzer.add_dependency(Dependency {
            name: "test-crate".to_string(),
            version: "1.0.0".to_string(),
            source: DependencySource::CratesIo,
            features: vec![],
            optional: false,
            dependencies: vec![],
        });

        let result = analyzer.analyze();
        assert_eq!(result.total_dependencies, 1);
    }

    #[test]
    fn test_vulnerability_detection() {
        let mut analyzer = create_analyzer();

        analyzer.add_dependency(Dependency {
            name: "vuln-crate".to_string(),
            version: "1.0.0".to_string(),
            source: DependencySource::CratesIo,
            features: vec![],
            optional: false,
            dependencies: vec![],
        });

        analyzer.add_vulnerability(Vulnerability {
            id: "TEST-001".to_string(),
            package: "vuln-crate".to_string(),
            title: "Test vulnerability".to_string(),
            description: "Test".to_string(),
            severity: Severity::High,
            cvss_score: Some(7.5),
            affected_versions: "< 2.0.0".to_string(),
            patched_versions: Some(">= 2.0.0".to_string()),
            references: vec![],
        });

        let result = analyzer.analyze();
        assert!(!result.vulnerabilities.is_empty());
    }

    #[test]
    fn test_license_blocking() {
        let mut analyzer = create_analyzer();

        analyzer.add_dependency(Dependency {
            name: "gpl-crate".to_string(),
            version: "1.0.0".to_string(),
            source: DependencySource::CratesIo,
            features: vec![],
            optional: false,
            dependencies: vec![],
        });

        analyzer.add_license(
            "gpl-crate",
            License {
                name: "GPL-3.0".to_string(),
                spdx_id: Some("GPL-3.0".to_string()),
                category: LicenseCategory::Copyleft,
                is_osi_approved: true,
            },
        );

        let result = analyzer.analyze();
        assert!(result
            .license_issues
            .iter()
            .any(|i| matches!(i.issue_type, LicenseIssueType::Blocked)));
    }

    #[test]
    fn test_security_score_calculation() {
        let mut analyzer = create_analyzer();

        // Clean dependency
        analyzer.add_dependency(Dependency {
            name: "clean-crate".to_string(),
            version: "1.0.0".to_string(),
            source: DependencySource::CratesIo,
            features: vec![],
            optional: false,
            dependencies: vec![],
        });

        analyzer.add_license(
            "clean-crate",
            License {
                name: "MIT".to_string(),
                spdx_id: Some("MIT".to_string()),
                category: LicenseCategory::Permissive,
                is_osi_approved: true,
            },
        );

        let result = analyzer.analyze();
        assert_eq!(result.security_score, 100);
    }

    #[test]
    fn test_severity_from_cvss() {
        assert_eq!(Severity::from_cvss(9.5), Severity::Critical);
        assert_eq!(Severity::from_cvss(8.0), Severity::High);
        assert_eq!(Severity::from_cvss(5.0), Severity::Medium);
        assert_eq!(Severity::from_cvss(2.0), Severity::Low);
    }

    #[test]
    fn test_dependency_tree() {
        let mut analyzer = create_analyzer();

        analyzer.add_dependency(Dependency {
            name: "parent".to_string(),
            version: "1.0.0".to_string(),
            source: DependencySource::CratesIo,
            features: vec![],
            optional: false,
            dependencies: vec!["child".to_string()],
        });

        analyzer.add_dependency(Dependency {
            name: "child".to_string(),
            version: "1.0.0".to_string(),
            source: DependencySource::CratesIo,
            features: vec![],
            optional: false,
            dependencies: vec![],
        });

        let tree = analyzer.dependency_tree("parent", 2);
        assert!(tree.contains("parent"));
        assert!(tree.contains("child"));
    }

    #[test]
    fn test_sbom_generation() {
        let mut analyzer = create_analyzer();

        analyzer.add_dependency(Dependency {
            name: "test-crate".to_string(),
            version: "1.0.0".to_string(),
            source: DependencySource::CratesIo,
            features: vec![],
            optional: false,
            dependencies: vec![],
        });

        let sbom = analyzer.generate_sbom();
        assert_eq!(sbom.components.len(), 1);
        assert!(sbom.components[0]
            .purl
            .contains("pkg:cargo/test-crate@1.0.0"));
    }

    #[test]
    fn test_sbom_json_export() {
        let sbom = Sbom {
            bom_format: "CycloneDX".to_string(),
            spec_version: "1.4".to_string(),
            components: vec![SbomComponent {
                name: "test".to_string(),
                version: "1.0.0".to_string(),
                purl: "pkg:cargo/test@1.0.0".to_string(),
                license: Some("MIT".to_string()),
                source: "crates.io".to_string(),
            }],
        };

        let json = sbom.to_json();
        assert!(json.contains("CycloneDX"));
        assert!(json.contains("test"));
        assert!(json.contains("1.0.0"));
    }

    #[test]
    fn test_report_generation() {
        let mut analyzer = create_analyzer();

        analyzer.add_dependency(Dependency {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            source: DependencySource::CratesIo,
            features: vec![],
            optional: false,
            dependencies: vec![],
        });

        let result = analyzer.analyze();
        let report = analyzer.generate_report(&result);

        assert!(report.contains("Dependency Analysis Report"));
        assert!(report.contains("Total Dependencies"));
    }

    #[test]
    fn test_duplicate_detection() {
        let mut analyzer = create_analyzer();

        analyzer.add_dependency(Dependency {
            name: "crate@1.0.0".to_string(),
            version: "1.0.0".to_string(),
            source: DependencySource::CratesIo,
            features: vec![],
            optional: false,
            dependencies: vec![],
        });

        analyzer.add_dependency(Dependency {
            name: "crate@2.0.0".to_string(),
            version: "2.0.0".to_string(),
            source: DependencySource::CratesIo,
            features: vec![],
            optional: false,
            dependencies: vec![],
        });

        let result = analyzer.analyze();
        assert!(!result.duplicate_dependencies.is_empty());
    }

    #[test]
    fn test_config_defaults() {
        let config = AnalyzerConfig::default();

        assert!(config.check_vulnerabilities);
        assert!(config.check_licenses);
        assert!(config.allowed_licenses.contains("MIT"));
        assert!(config.blocked_licenses.contains("GPL-3.0"));
    }
}
