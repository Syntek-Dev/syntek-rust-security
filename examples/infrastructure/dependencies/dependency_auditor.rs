//! Dependency Auditor for Rust Projects
//!
//! This example demonstrates a comprehensive dependency auditing system that
//! checks for security vulnerabilities, license compliance, outdated packages,
//! and supply chain risks in Cargo.toml dependencies.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ============================================================================
// Dependency Representation
// ============================================================================

/// A Cargo dependency
#[derive(Clone, Debug)]
pub struct Dependency {
    pub name: String,
    pub version: Version,
    pub source: DependencySource,
    pub features: Vec<String>,
    pub optional: bool,
    pub default_features: bool,
    pub dependencies: Vec<String>,
}

/// Semantic version
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub pre: Option<String>,
}

impl Version {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
            pre: None,
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split('-').collect();
        let version_part = parts[0];
        let pre = parts.get(1).map(|s| s.to_string());

        let nums: Vec<u32> = version_part
            .split('.')
            .filter_map(|p| p.parse().ok())
            .collect();

        if nums.len() >= 3 {
            Some(Self {
                major: nums[0],
                minor: nums[1],
                patch: nums[2],
                pre,
            })
        } else {
            None
        }
    }

    pub fn is_major_bump(&self, other: &Version) -> bool {
        self.major != other.major
    }

    pub fn is_minor_bump(&self, other: &Version) -> bool {
        self.major == other.major && self.minor != other.minor
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if let Some(ref pre) = self.pre {
            write!(f, "-{}", pre)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub enum DependencySource {
    CratesIo,
    Git {
        url: String,
        branch: Option<String>,
        rev: Option<String>,
    },
    Path {
        path: String,
    },
    Registry {
        name: String,
    },
}

// ============================================================================
// Vulnerability Database
// ============================================================================

/// Security vulnerability
#[derive(Clone, Debug)]
pub struct Vulnerability {
    pub id: String,
    pub crate_name: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub cvss_score: Option<f32>,
    pub affected_versions: VersionRange,
    pub patched_versions: Vec<Version>,
    pub references: Vec<String>,
    pub categories: Vec<VulnCategory>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
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
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::None => write!(f, "None"),
            Severity::Low => write!(f, "Low"),
            Severity::Medium => write!(f, "Medium"),
            Severity::High => write!(f, "High"),
            Severity::Critical => write!(f, "Critical"),
        }
    }
}

#[derive(Clone, Debug)]
pub enum VulnCategory {
    MemorySafety,
    CodeExecution,
    DenialOfService,
    InformationDisclosure,
    PrivilegeEscalation,
    Cryptography,
    InputValidation,
    Configuration,
}

#[derive(Clone, Debug)]
pub struct VersionRange {
    pub min: Option<Version>,
    pub max: Option<Version>,
    pub min_inclusive: bool,
    pub max_inclusive: bool,
}

impl VersionRange {
    pub fn all() -> Self {
        Self {
            min: None,
            max: None,
            min_inclusive: true,
            max_inclusive: true,
        }
    }

    pub fn contains(&self, version: &Version) -> bool {
        let min_ok = match &self.min {
            None => true,
            Some(min) => {
                if self.min_inclusive {
                    version >= min
                } else {
                    version > min
                }
            }
        };

        let max_ok = match &self.max {
            None => true,
            Some(max) => {
                if self.max_inclusive {
                    version <= max
                } else {
                    version < max
                }
            }
        };

        min_ok && max_ok
    }
}

/// Vulnerability database (simulated RustSec)
pub struct VulnDatabase {
    vulnerabilities: HashMap<String, Vec<Vulnerability>>,
    last_updated: SystemTime,
}

impl VulnDatabase {
    pub fn new() -> Self {
        let mut db = Self {
            vulnerabilities: HashMap::new(),
            last_updated: SystemTime::now(),
        };

        // Add sample vulnerabilities
        db.add_sample_vulnerabilities();
        db
    }

    fn add_sample_vulnerabilities(&mut self) {
        // Simulated vulnerabilities for common crates
        self.add_vulnerability(Vulnerability {
            id: "RUSTSEC-2024-0001".to_string(),
            crate_name: "hyper".to_string(),
            title: "Request smuggling via content-length header".to_string(),
            description: "Improper parsing of Content-Length header allows request smuggling"
                .to_string(),
            severity: Severity::High,
            cvss_score: Some(7.5),
            affected_versions: VersionRange {
                min: Some(Version::new(0, 14, 0)),
                max: Some(Version::new(0, 14, 27)),
                min_inclusive: true,
                max_inclusive: true,
            },
            patched_versions: vec![Version::new(0, 14, 28), Version::new(1, 0, 0)],
            references: vec!["https://rustsec.org/advisories/RUSTSEC-2024-0001.html".to_string()],
            categories: vec![VulnCategory::InputValidation],
        });

        self.add_vulnerability(Vulnerability {
            id: "RUSTSEC-2024-0002".to_string(),
            crate_name: "regex".to_string(),
            title: "Exponential backtracking in regex matching".to_string(),
            description: "Certain patterns cause exponential time complexity".to_string(),
            severity: Severity::Medium,
            cvss_score: Some(5.3),
            affected_versions: VersionRange {
                min: Some(Version::new(1, 0, 0)),
                max: Some(Version::new(1, 9, 5)),
                min_inclusive: true,
                max_inclusive: true,
            },
            patched_versions: vec![Version::new(1, 9, 6)],
            references: vec![],
            categories: vec![VulnCategory::DenialOfService],
        });

        self.add_vulnerability(Vulnerability {
            id: "RUSTSEC-2024-0003".to_string(),
            crate_name: "chrono".to_string(),
            title: "Potential overflow in timestamp calculation".to_string(),
            description: "Integer overflow when parsing extreme date values".to_string(),
            severity: Severity::Low,
            cvss_score: Some(3.7),
            affected_versions: VersionRange {
                min: None,
                max: Some(Version::new(0, 4, 34)),
                min_inclusive: true,
                max_inclusive: true,
            },
            patched_versions: vec![Version::new(0, 4, 35)],
            references: vec![],
            categories: vec![VulnCategory::MemorySafety],
        });

        self.add_vulnerability(Vulnerability {
            id: "RUSTSEC-2024-0004".to_string(),
            crate_name: "openssl".to_string(),
            title: "Buffer overflow in certificate parsing".to_string(),
            description: "Malformed X.509 certificates can trigger buffer overflow".to_string(),
            severity: Severity::Critical,
            cvss_score: Some(9.8),
            affected_versions: VersionRange {
                min: Some(Version::new(0, 10, 0)),
                max: Some(Version::new(0, 10, 60)),
                min_inclusive: true,
                max_inclusive: true,
            },
            patched_versions: vec![Version::new(0, 10, 61)],
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2024-XXXX".to_string()],
            categories: vec![VulnCategory::MemorySafety, VulnCategory::CodeExecution],
        });
    }

    fn add_vulnerability(&mut self, vuln: Vulnerability) {
        self.vulnerabilities
            .entry(vuln.crate_name.clone())
            .or_insert_with(Vec::new)
            .push(vuln);
    }

    pub fn check(&self, name: &str, version: &Version) -> Vec<&Vulnerability> {
        self.vulnerabilities
            .get(name)
            .map(|vulns| {
                vulns
                    .iter()
                    .filter(|v| v.affected_versions.contains(version))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn age(&self) -> Duration {
        self.last_updated.elapsed().unwrap_or_default()
    }
}

// ============================================================================
// License Compliance
// ============================================================================

/// Software license
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum License {
    MIT,
    Apache2,
    BSD2,
    BSD3,
    GPL2,
    GPL3,
    LGPL2,
    LGPL3,
    MPL2,
    ISC,
    Unlicense,
    CC0,
    WTFPL,
    Proprietary,
    Unknown(String),
}

impl License {
    pub fn parse(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "MIT" => License::MIT,
            "APACHE-2.0" | "APACHE" | "APACHE2" => License::Apache2,
            "BSD-2-CLAUSE" | "BSD2" => License::BSD2,
            "BSD-3-CLAUSE" | "BSD3" => License::BSD3,
            "GPL-2.0" | "GPL2" => License::GPL2,
            "GPL-3.0" | "GPL3" => License::GPL3,
            "LGPL-2.1" | "LGPL2" => License::LGPL2,
            "LGPL-3.0" | "LGPL3" => License::LGPL3,
            "MPL-2.0" | "MPL2" => License::MPL2,
            "ISC" => License::ISC,
            "UNLICENSE" => License::Unlicense,
            "CC0-1.0" | "CC0" => License::CC0,
            "WTFPL" => License::WTFPL,
            _ => License::Unknown(s.to_string()),
        }
    }

    pub fn is_copyleft(&self) -> bool {
        matches!(
            self,
            License::GPL2 | License::GPL3 | License::LGPL2 | License::LGPL3
        )
    }

    pub fn is_permissive(&self) -> bool {
        matches!(
            self,
            License::MIT
                | License::Apache2
                | License::BSD2
                | License::BSD3
                | License::ISC
                | License::Unlicense
                | License::CC0
        )
    }
}

impl fmt::Display for License {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            License::MIT => write!(f, "MIT"),
            License::Apache2 => write!(f, "Apache-2.0"),
            License::BSD2 => write!(f, "BSD-2-Clause"),
            License::BSD3 => write!(f, "BSD-3-Clause"),
            License::GPL2 => write!(f, "GPL-2.0"),
            License::GPL3 => write!(f, "GPL-3.0"),
            License::LGPL2 => write!(f, "LGPL-2.1"),
            License::LGPL3 => write!(f, "LGPL-3.0"),
            License::MPL2 => write!(f, "MPL-2.0"),
            License::ISC => write!(f, "ISC"),
            License::Unlicense => write!(f, "Unlicense"),
            License::CC0 => write!(f, "CC0-1.0"),
            License::WTFPL => write!(f, "WTFPL"),
            License::Proprietary => write!(f, "Proprietary"),
            License::Unknown(s) => write!(f, "Unknown({})", s),
        }
    }
}

/// License policy configuration
#[derive(Clone, Debug)]
pub struct LicensePolicy {
    pub allowed: HashSet<License>,
    pub denied: HashSet<License>,
    pub allow_copyleft: bool,
    pub require_attribution: bool,
}

impl Default for LicensePolicy {
    fn default() -> Self {
        let mut allowed = HashSet::new();
        allowed.insert(License::MIT);
        allowed.insert(License::Apache2);
        allowed.insert(License::BSD2);
        allowed.insert(License::BSD3);
        allowed.insert(License::ISC);
        allowed.insert(License::Unlicense);
        allowed.insert(License::CC0);

        let mut denied = HashSet::new();
        denied.insert(License::GPL3);
        denied.insert(License::Proprietary);

        Self {
            allowed,
            denied,
            allow_copyleft: false,
            require_attribution: true,
        }
    }
}

impl LicensePolicy {
    pub fn permissive_only() -> Self {
        Self::default()
    }

    pub fn allow_copyleft() -> Self {
        let mut policy = Self::default();
        policy.allow_copyleft = true;
        policy.denied.remove(&License::GPL3);
        policy.allowed.insert(License::GPL2);
        policy.allowed.insert(License::GPL3);
        policy.allowed.insert(License::LGPL2);
        policy.allowed.insert(License::LGPL3);
        policy.allowed.insert(License::MPL2);
        policy
    }

    pub fn check(&self, license: &License) -> LicenseCheckResult {
        if self.denied.contains(license) {
            return LicenseCheckResult::Denied;
        }

        if self.allowed.contains(license) {
            return LicenseCheckResult::Allowed;
        }

        if license.is_copyleft() && !self.allow_copyleft {
            return LicenseCheckResult::CopyleftNotAllowed;
        }

        LicenseCheckResult::Unknown
    }
}

#[derive(Debug, PartialEq)]
pub enum LicenseCheckResult {
    Allowed,
    Denied,
    CopyleftNotAllowed,
    Unknown,
}

// ============================================================================
// Supply Chain Analysis
// ============================================================================

/// Supply chain risk assessment
#[derive(Clone, Debug)]
pub struct SupplyChainRisk {
    pub crate_name: String,
    pub risk_level: RiskLevel,
    pub factors: Vec<RiskFactor>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug)]
pub enum RiskFactor {
    Unmaintained { last_update_days: u64 },
    LowDownloads { count: u64 },
    SingleMaintainer,
    NoRepository,
    GitDependency { url: String },
    PathDependency { path: String },
    YankHistory { count: usize },
    TooManyDependencies { count: usize },
    UnsafeCode { unsafe_blocks: usize },
    BuildScript,
    ProcMacro,
    NativeCode,
    PreReleaseVersion,
}

impl RiskFactor {
    pub fn severity(&self) -> RiskLevel {
        match self {
            RiskFactor::Unmaintained { last_update_days } => {
                if *last_update_days > 730 {
                    RiskLevel::High
                } else if *last_update_days > 365 {
                    RiskLevel::Medium
                } else {
                    RiskLevel::Low
                }
            }
            RiskFactor::LowDownloads { count } => {
                if *count < 100 {
                    RiskLevel::High
                } else if *count < 1000 {
                    RiskLevel::Medium
                } else {
                    RiskLevel::Low
                }
            }
            RiskFactor::SingleMaintainer => RiskLevel::Medium,
            RiskFactor::NoRepository => RiskLevel::High,
            RiskFactor::GitDependency { .. } => RiskLevel::High,
            RiskFactor::PathDependency { .. } => RiskLevel::Medium,
            RiskFactor::YankHistory { count } => {
                if *count > 3 {
                    RiskLevel::High
                } else {
                    RiskLevel::Medium
                }
            }
            RiskFactor::TooManyDependencies { count } => {
                if *count > 50 {
                    RiskLevel::High
                } else if *count > 20 {
                    RiskLevel::Medium
                } else {
                    RiskLevel::Low
                }
            }
            RiskFactor::UnsafeCode { unsafe_blocks } => {
                if *unsafe_blocks > 10 {
                    RiskLevel::High
                } else if *unsafe_blocks > 0 {
                    RiskLevel::Medium
                } else {
                    RiskLevel::Low
                }
            }
            RiskFactor::BuildScript => RiskLevel::Medium,
            RiskFactor::ProcMacro => RiskLevel::Medium,
            RiskFactor::NativeCode => RiskLevel::Medium,
            RiskFactor::PreReleaseVersion => RiskLevel::Low,
        }
    }

    pub fn description(&self) -> String {
        match self {
            RiskFactor::Unmaintained { last_update_days } => {
                format!("Last updated {} days ago", last_update_days)
            }
            RiskFactor::LowDownloads { count } => {
                format!("Only {} downloads", count)
            }
            RiskFactor::SingleMaintainer => "Single maintainer".to_string(),
            RiskFactor::NoRepository => "No source repository linked".to_string(),
            RiskFactor::GitDependency { url } => {
                format!("Git dependency: {}", url)
            }
            RiskFactor::PathDependency { path } => {
                format!("Path dependency: {}", path)
            }
            RiskFactor::YankHistory { count } => {
                format!("{} yanked versions", count)
            }
            RiskFactor::TooManyDependencies { count } => {
                format!("{} transitive dependencies", count)
            }
            RiskFactor::UnsafeCode { unsafe_blocks } => {
                format!("{} unsafe blocks", unsafe_blocks)
            }
            RiskFactor::BuildScript => "Has build.rs script".to_string(),
            RiskFactor::ProcMacro => "Procedural macro crate".to_string(),
            RiskFactor::NativeCode => "Contains native (C/C++) code".to_string(),
            RiskFactor::PreReleaseVersion => "Pre-release version (0.x.y)".to_string(),
        }
    }
}

/// Supply chain analyzer
pub struct SupplyChainAnalyzer {
    min_downloads_threshold: u64,
    max_age_days: u64,
    max_dependencies: usize,
}

impl Default for SupplyChainAnalyzer {
    fn default() -> Self {
        Self {
            min_downloads_threshold: 1000,
            max_age_days: 365,
            max_dependencies: 50,
        }
    }
}

impl SupplyChainAnalyzer {
    pub fn analyze(&self, dep: &Dependency, metadata: &CrateMetadata) -> SupplyChainRisk {
        let mut factors = Vec::new();

        // Check update freshness
        let age_days = metadata
            .last_updated
            .elapsed()
            .unwrap_or_default()
            .as_secs()
            / 86400;
        if age_days > self.max_age_days {
            factors.push(RiskFactor::Unmaintained {
                last_update_days: age_days,
            });
        }

        // Check download count
        if metadata.downloads < self.min_downloads_threshold {
            factors.push(RiskFactor::LowDownloads {
                count: metadata.downloads,
            });
        }

        // Check maintainer count
        if metadata.maintainers == 1 {
            factors.push(RiskFactor::SingleMaintainer);
        }

        // Check repository
        if metadata.repository.is_none() {
            factors.push(RiskFactor::NoRepository);
        }

        // Check source type
        match &dep.source {
            DependencySource::Git { url, .. } => {
                factors.push(RiskFactor::GitDependency { url: url.clone() });
            }
            DependencySource::Path { path } => {
                factors.push(RiskFactor::PathDependency { path: path.clone() });
            }
            _ => {}
        }

        // Check yank history
        if metadata.yanked_versions > 0 {
            factors.push(RiskFactor::YankHistory {
                count: metadata.yanked_versions,
            });
        }

        // Check dependency count
        if dep.dependencies.len() > self.max_dependencies {
            factors.push(RiskFactor::TooManyDependencies {
                count: dep.dependencies.len(),
            });
        }

        // Check for unsafe code
        if metadata.unsafe_blocks > 0 {
            factors.push(RiskFactor::UnsafeCode {
                unsafe_blocks: metadata.unsafe_blocks,
            });
        }

        // Check for build script
        if metadata.has_build_script {
            factors.push(RiskFactor::BuildScript);
        }

        // Check for proc-macro
        if metadata.is_proc_macro {
            factors.push(RiskFactor::ProcMacro);
        }

        // Check for native code
        if metadata.has_native_code {
            factors.push(RiskFactor::NativeCode);
        }

        // Check version
        if dep.version.major == 0 {
            factors.push(RiskFactor::PreReleaseVersion);
        }

        // Calculate overall risk level
        let risk_level = factors
            .iter()
            .map(|f| f.severity())
            .max()
            .unwrap_or(RiskLevel::Low);

        SupplyChainRisk {
            crate_name: dep.name.clone(),
            risk_level,
            factors,
        }
    }
}

/// Crate metadata from registry
#[derive(Clone, Debug)]
pub struct CrateMetadata {
    pub downloads: u64,
    pub maintainers: usize,
    pub repository: Option<String>,
    pub last_updated: SystemTime,
    pub yanked_versions: usize,
    pub unsafe_blocks: usize,
    pub has_build_script: bool,
    pub is_proc_macro: bool,
    pub has_native_code: bool,
    pub license: Option<License>,
    pub latest_version: Version,
}

impl Default for CrateMetadata {
    fn default() -> Self {
        Self {
            downloads: 10000,
            maintainers: 2,
            repository: Some("https://github.com/example/crate".to_string()),
            last_updated: SystemTime::now() - Duration::from_secs(86400 * 30),
            yanked_versions: 0,
            unsafe_blocks: 0,
            has_build_script: false,
            is_proc_macro: false,
            has_native_code: false,
            license: Some(License::MIT),
            latest_version: Version::new(1, 0, 0),
        }
    }
}

// ============================================================================
// Dependency Auditor
// ============================================================================

/// Audit result for a single dependency
#[derive(Clone, Debug)]
pub struct AuditResult {
    pub dependency: Dependency,
    pub vulnerabilities: Vec<Vulnerability>,
    pub license_status: LicenseCheckResult,
    pub license: Option<License>,
    pub supply_chain_risk: SupplyChainRisk,
    pub update_available: Option<Version>,
}

impl AuditResult {
    pub fn is_ok(&self) -> bool {
        self.vulnerabilities.is_empty()
            && self.license_status == LicenseCheckResult::Allowed
            && self.supply_chain_risk.risk_level <= RiskLevel::Low
    }

    pub fn max_severity(&self) -> Severity {
        self.vulnerabilities
            .iter()
            .map(|v| v.severity.clone())
            .max()
            .unwrap_or(Severity::None)
    }
}

/// Complete audit report
#[derive(Clone, Debug)]
pub struct AuditReport {
    pub project_name: String,
    pub timestamp: String,
    pub total_dependencies: usize,
    pub results: Vec<AuditResult>,
}

impl AuditReport {
    pub fn vulnerabilities(&self) -> Vec<(&Dependency, &Vulnerability)> {
        self.results
            .iter()
            .flat_map(|r| r.vulnerabilities.iter().map(move |v| (&r.dependency, v)))
            .collect()
    }

    pub fn license_issues(&self) -> Vec<&AuditResult> {
        self.results
            .iter()
            .filter(|r| r.license_status != LicenseCheckResult::Allowed)
            .collect()
    }

    pub fn high_risk_dependencies(&self) -> Vec<&AuditResult> {
        self.results
            .iter()
            .filter(|r| r.supply_chain_risk.risk_level >= RiskLevel::High)
            .collect()
    }

    pub fn outdated_dependencies(&self) -> Vec<&AuditResult> {
        self.results
            .iter()
            .filter(|r| r.update_available.is_some())
            .collect()
    }

    pub fn summary(&self) -> AuditSummary {
        let critical = self
            .results
            .iter()
            .filter(|r| r.max_severity() == Severity::Critical)
            .count();
        let high = self
            .results
            .iter()
            .filter(|r| r.max_severity() == Severity::High)
            .count();
        let medium = self
            .results
            .iter()
            .filter(|r| r.max_severity() == Severity::Medium)
            .count();
        let low = self
            .results
            .iter()
            .filter(|r| r.max_severity() == Severity::Low)
            .count();

        AuditSummary {
            total: self.total_dependencies,
            clean: self.results.iter().filter(|r| r.is_ok()).count(),
            vulnerable: self
                .results
                .iter()
                .filter(|r| !r.vulnerabilities.is_empty())
                .count(),
            license_issues: self.license_issues().len(),
            high_risk: self.high_risk_dependencies().len(),
            outdated: self.outdated_dependencies().len(),
            severity_critical: critical,
            severity_high: high,
            severity_medium: medium,
            severity_low: low,
        }
    }
}

#[derive(Debug)]
pub struct AuditSummary {
    pub total: usize,
    pub clean: usize,
    pub vulnerable: usize,
    pub license_issues: usize,
    pub high_risk: usize,
    pub outdated: usize,
    pub severity_critical: usize,
    pub severity_high: usize,
    pub severity_medium: usize,
    pub severity_low: usize,
}

/// Main dependency auditor
pub struct DependencyAuditor {
    vuln_db: VulnDatabase,
    license_policy: LicensePolicy,
    supply_chain_analyzer: SupplyChainAnalyzer,
    metadata_cache: HashMap<String, CrateMetadata>,
}

impl DependencyAuditor {
    pub fn new() -> Self {
        Self {
            vuln_db: VulnDatabase::new(),
            license_policy: LicensePolicy::default(),
            supply_chain_analyzer: SupplyChainAnalyzer::default(),
            metadata_cache: HashMap::new(),
        }
    }

    pub fn with_license_policy(mut self, policy: LicensePolicy) -> Self {
        self.license_policy = policy;
        self
    }

    pub fn add_metadata(&mut self, name: &str, metadata: CrateMetadata) {
        self.metadata_cache.insert(name.to_string(), metadata);
    }

    pub fn audit(&self, dependencies: &[Dependency]) -> AuditReport {
        let results: Vec<AuditResult> = dependencies
            .iter()
            .map(|dep| self.audit_dependency(dep))
            .collect();

        AuditReport {
            project_name: "project".to_string(),
            timestamp: format!(
                "{}",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            ),
            total_dependencies: dependencies.len(),
            results,
        }
    }

    fn audit_dependency(&self, dep: &Dependency) -> AuditResult {
        // Check vulnerabilities
        let vulnerabilities: Vec<Vulnerability> = self
            .vuln_db
            .check(&dep.name, &dep.version)
            .into_iter()
            .cloned()
            .collect();

        // Get metadata
        let metadata = self
            .metadata_cache
            .get(&dep.name)
            .cloned()
            .unwrap_or_default();

        // Check license
        let license = metadata.license.clone();
        let license_status = license
            .as_ref()
            .map(|l| self.license_policy.check(l))
            .unwrap_or(LicenseCheckResult::Unknown);

        // Analyze supply chain
        let supply_chain_risk = self.supply_chain_analyzer.analyze(dep, &metadata);

        // Check for updates
        let update_available = if metadata.latest_version > dep.version {
            Some(metadata.latest_version.clone())
        } else {
            None
        };

        AuditResult {
            dependency: dep.clone(),
            vulnerabilities,
            license_status,
            license,
            supply_chain_risk,
            update_available,
        }
    }
}

// ============================================================================
// Report Generation
// ============================================================================

pub fn generate_text_report(report: &AuditReport) -> String {
    let mut output = String::new();

    output.push_str("╔════════════════════════════════════════════════════════════════════╗\n");
    output.push_str("║                    DEPENDENCY AUDIT REPORT                         ║\n");
    output.push_str("╚════════════════════════════════════════════════════════════════════╝\n\n");

    let summary = report.summary();

    output.push_str(&format!("Project: {}\n", report.project_name));
    output.push_str(&format!("Total Dependencies: {}\n\n", summary.total));

    // Summary
    output.push_str("═══════════════════════════════════════════════════════════════════════\n");
    output.push_str("                              SUMMARY\n");
    output.push_str("═══════════════════════════════════════════════════════════════════════\n\n");

    output.push_str(&format!("  Clean:           {:3}\n", summary.clean));
    output.push_str(&format!("  Vulnerable:      {:3}\n", summary.vulnerable));
    output.push_str(&format!(
        "  License Issues:  {:3}\n",
        summary.license_issues
    ));
    output.push_str(&format!("  High Risk:       {:3}\n", summary.high_risk));
    output.push_str(&format!("  Outdated:        {:3}\n\n", summary.outdated));

    if summary.vulnerable > 0 {
        output.push_str("  Vulnerabilities by Severity:\n");
        output.push_str(&format!("    Critical: {}\n", summary.severity_critical));
        output.push_str(&format!("    High:     {}\n", summary.severity_high));
        output.push_str(&format!("    Medium:   {}\n", summary.severity_medium));
        output.push_str(&format!("    Low:      {}\n", summary.severity_low));
    }
    output.push('\n');

    // Vulnerabilities
    let vulns = report.vulnerabilities();
    if !vulns.is_empty() {
        output
            .push_str("═══════════════════════════════════════════════════════════════════════\n");
        output.push_str("                         VULNERABILITIES\n");
        output.push_str(
            "═══════════════════════════════════════════════════════════════════════\n\n",
        );

        for (dep, vuln) in vulns {
            output.push_str(&format!(
                "  [{:8}] {} @ {} - {}\n",
                vuln.severity, dep.name, dep.version, vuln.id
            ));
            output.push_str(&format!("            {}\n", vuln.title));
            if !vuln.patched_versions.is_empty() {
                output.push_str(&format!(
                    "            Patched in: {}\n",
                    vuln.patched_versions
                        .iter()
                        .map(|v| v.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            output.push('\n');
        }
    }

    // License issues
    let license_issues = report.license_issues();
    if !license_issues.is_empty() {
        output
            .push_str("═══════════════════════════════════════════════════════════════════════\n");
        output.push_str("                         LICENSE ISSUES\n");
        output.push_str(
            "═══════════════════════════════════════════════════════════════════════\n\n",
        );

        for result in license_issues {
            let license_str = result
                .license
                .as_ref()
                .map(|l| l.to_string())
                .unwrap_or_else(|| "Unknown".to_string());

            output.push_str(&format!(
                "  {} @ {} - {} ({:?})\n",
                result.dependency.name,
                result.dependency.version,
                license_str,
                result.license_status
            ));
        }
        output.push('\n');
    }

    // High risk dependencies
    let high_risk = report.high_risk_dependencies();
    if !high_risk.is_empty() {
        output
            .push_str("═══════════════════════════════════════════════════════════════════════\n");
        output.push_str("                      HIGH RISK DEPENDENCIES\n");
        output.push_str(
            "═══════════════════════════════════════════════════════════════════════\n\n",
        );

        for result in high_risk {
            output.push_str(&format!(
                "  {} @ {} [{:?}]\n",
                result.dependency.name,
                result.dependency.version,
                result.supply_chain_risk.risk_level
            ));
            for factor in &result.supply_chain_risk.factors {
                output.push_str(&format!("    - {}\n", factor.description()));
            }
            output.push('\n');
        }
    }

    output
}

// ============================================================================
// Main Demonstration
// ============================================================================

fn main() {
    println!("=== Dependency Auditor for Rust Projects ===\n");

    // Create auditor
    let mut auditor =
        DependencyAuditor::new().with_license_policy(LicensePolicy::permissive_only());

    // Add sample metadata
    auditor.add_metadata(
        "hyper",
        CrateMetadata {
            downloads: 50_000_000,
            maintainers: 5,
            repository: Some("https://github.com/hyperium/hyper".to_string()),
            last_updated: SystemTime::now() - Duration::from_secs(86400 * 7),
            yanked_versions: 2,
            unsafe_blocks: 15,
            has_build_script: false,
            is_proc_macro: false,
            has_native_code: false,
            license: Some(License::MIT),
            latest_version: Version::new(1, 0, 0),
        },
    );

    auditor.add_metadata(
        "regex",
        CrateMetadata {
            downloads: 100_000_000,
            maintainers: 3,
            repository: Some("https://github.com/rust-lang/regex".to_string()),
            last_updated: SystemTime::now() - Duration::from_secs(86400 * 14),
            yanked_versions: 0,
            unsafe_blocks: 5,
            has_build_script: false,
            is_proc_macro: false,
            has_native_code: false,
            license: Some(License::Apache2),
            latest_version: Version::new(1, 10, 0),
        },
    );

    auditor.add_metadata(
        "openssl",
        CrateMetadata {
            downloads: 30_000_000,
            maintainers: 4,
            repository: Some("https://github.com/sfackler/rust-openssl".to_string()),
            last_updated: SystemTime::now() - Duration::from_secs(86400 * 60),
            yanked_versions: 5,
            unsafe_blocks: 100,
            has_build_script: true,
            is_proc_macro: false,
            has_native_code: true,
            license: Some(License::Apache2),
            latest_version: Version::new(0, 10, 61),
        },
    );

    auditor.add_metadata(
        "sketchy-crate",
        CrateMetadata {
            downloads: 50,
            maintainers: 1,
            repository: None,
            last_updated: SystemTime::now() - Duration::from_secs(86400 * 800),
            yanked_versions: 3,
            unsafe_blocks: 20,
            has_build_script: true,
            is_proc_macro: false,
            has_native_code: true,
            license: Some(License::GPL3),
            latest_version: Version::new(0, 1, 0),
        },
    );

    // Create sample dependencies
    let dependencies = vec![
        Dependency {
            name: "hyper".to_string(),
            version: Version::new(0, 14, 25),
            source: DependencySource::CratesIo,
            features: vec!["http1".to_string(), "client".to_string()],
            optional: false,
            default_features: true,
            dependencies: vec!["bytes".to_string(), "tokio".to_string()],
        },
        Dependency {
            name: "regex".to_string(),
            version: Version::new(1, 9, 0),
            source: DependencySource::CratesIo,
            features: vec![],
            optional: false,
            default_features: true,
            dependencies: vec!["regex-syntax".to_string()],
        },
        Dependency {
            name: "openssl".to_string(),
            version: Version::new(0, 10, 55),
            source: DependencySource::CratesIo,
            features: vec![],
            optional: false,
            default_features: true,
            dependencies: vec!["openssl-sys".to_string(), "libc".to_string()],
        },
        Dependency {
            name: "serde".to_string(),
            version: Version::new(1, 0, 195),
            source: DependencySource::CratesIo,
            features: vec!["derive".to_string()],
            optional: false,
            default_features: true,
            dependencies: vec!["serde_derive".to_string()],
        },
        Dependency {
            name: "sketchy-crate".to_string(),
            version: Version::new(0, 1, 0),
            source: DependencySource::Git {
                url: "https://github.com/unknown/sketchy".to_string(),
                branch: Some("main".to_string()),
                rev: None,
            },
            features: vec![],
            optional: true,
            default_features: true,
            dependencies: (0..60).map(|i| format!("dep-{}", i)).collect(),
        },
    ];

    println!("Auditing {} dependencies...\n", dependencies.len());

    // Run audit
    let report = auditor.audit(&dependencies);

    // Generate and print report
    println!("{}", generate_text_report(&report));

    // Print recommendation
    let summary = report.summary();
    println!("═══════════════════════════════════════════════════════════════════════");
    println!("                          RECOMMENDATIONS");
    println!("═══════════════════════════════════════════════════════════════════════\n");

    if summary.severity_critical > 0 {
        println!(
            "  ❌ CRITICAL: {} critical vulnerabilities found. Update immediately!",
            summary.severity_critical
        );
    }
    if summary.severity_high > 0 {
        println!(
            "  ⚠️  HIGH: {} high severity vulnerabilities. Prioritize updates.",
            summary.severity_high
        );
    }
    if summary.license_issues > 0 {
        println!(
            "  📜 LICENSE: {} dependencies have license issues.",
            summary.license_issues
        );
    }
    if summary.high_risk > 0 {
        println!(
            "  🔒 SUPPLY CHAIN: {} high-risk dependencies identified.",
            summary.high_risk
        );
    }
    if summary.clean == summary.total {
        println!("  ✅ All dependencies pass security checks!");
    }

    println!("\n=== Audit Complete ===");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_parse() {
        let v = Version::parse("1.2.3").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 3);

        let v = Version::parse("0.10.5-beta").unwrap();
        assert_eq!(v.major, 0);
        assert_eq!(v.minor, 10);
        assert_eq!(v.patch, 5);
        assert_eq!(v.pre, Some("beta".to_string()));
    }

    #[test]
    fn test_version_comparison() {
        let v1 = Version::new(1, 0, 0);
        let v2 = Version::new(1, 1, 0);
        let v3 = Version::new(2, 0, 0);

        assert!(v1 < v2);
        assert!(v2 < v3);
        assert!(v1 < v3);
    }

    #[test]
    fn test_version_range() {
        let range = VersionRange {
            min: Some(Version::new(1, 0, 0)),
            max: Some(Version::new(2, 0, 0)),
            min_inclusive: true,
            max_inclusive: false,
        };

        assert!(range.contains(&Version::new(1, 0, 0)));
        assert!(range.contains(&Version::new(1, 5, 0)));
        assert!(!range.contains(&Version::new(2, 0, 0)));
        assert!(!range.contains(&Version::new(0, 9, 0)));
    }

    #[test]
    fn test_severity_from_cvss() {
        assert_eq!(Severity::from_cvss(9.5), Severity::Critical);
        assert_eq!(Severity::from_cvss(7.5), Severity::High);
        assert_eq!(Severity::from_cvss(5.0), Severity::Medium);
        assert_eq!(Severity::from_cvss(2.0), Severity::Low);
        assert_eq!(Severity::from_cvss(0.0), Severity::None);
    }

    #[test]
    fn test_license_parse() {
        assert_eq!(License::parse("MIT"), License::MIT);
        assert_eq!(License::parse("Apache-2.0"), License::Apache2);
        assert_eq!(License::parse("GPL-3.0"), License::GPL3);
    }

    #[test]
    fn test_license_policy() {
        let policy = LicensePolicy::permissive_only();

        assert_eq!(policy.check(&License::MIT), LicenseCheckResult::Allowed);
        assert_eq!(policy.check(&License::Apache2), LicenseCheckResult::Allowed);
        assert_eq!(policy.check(&License::GPL3), LicenseCheckResult::Denied);
    }

    #[test]
    fn test_vuln_database() {
        let db = VulnDatabase::new();

        let vulns = db.check("hyper", &Version::new(0, 14, 25));
        assert!(!vulns.is_empty());

        let vulns = db.check("hyper", &Version::new(1, 0, 0));
        assert!(vulns.is_empty());
    }

    #[test]
    fn test_supply_chain_analyzer() {
        let analyzer = SupplyChainAnalyzer::default();

        let dep = Dependency {
            name: "test".to_string(),
            version: Version::new(0, 1, 0),
            source: DependencySource::Git {
                url: "https://example.com/test".to_string(),
                branch: None,
                rev: None,
            },
            features: vec![],
            optional: false,
            default_features: true,
            dependencies: vec![],
        };

        let metadata = CrateMetadata {
            downloads: 10,
            maintainers: 1,
            repository: None,
            last_updated: SystemTime::now() - Duration::from_secs(86400 * 1000),
            yanked_versions: 5,
            unsafe_blocks: 20,
            has_build_script: true,
            is_proc_macro: false,
            has_native_code: true,
            license: None,
            latest_version: Version::new(0, 1, 0),
        };

        let risk = analyzer.analyze(&dep, &metadata);
        assert!(risk.risk_level >= RiskLevel::High);
        assert!(risk.factors.len() > 5);
    }

    #[test]
    fn test_auditor() {
        let auditor = DependencyAuditor::new();

        let dependencies = vec![Dependency {
            name: "safe-crate".to_string(),
            version: Version::new(1, 0, 0),
            source: DependencySource::CratesIo,
            features: vec![],
            optional: false,
            default_features: true,
            dependencies: vec![],
        }];

        let report = auditor.audit(&dependencies);
        assert_eq!(report.total_dependencies, 1);
    }

    #[test]
    fn test_audit_report_summary() {
        let report = AuditReport {
            project_name: "test".to_string(),
            timestamp: "123".to_string(),
            total_dependencies: 5,
            results: vec![],
        };

        let summary = report.summary();
        assert_eq!(summary.total, 5);
        assert_eq!(summary.clean, 0);
    }
}
