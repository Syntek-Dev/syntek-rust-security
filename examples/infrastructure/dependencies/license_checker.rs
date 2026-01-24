//! License Checker
//!
//! Automated license compliance checking for Rust dependencies.

use std::collections::{HashMap, HashSet};
use std::fmt;

/// SPDX license identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum License {
    // Permissive licenses
    MIT,
    Apache2,
    BSD2,
    BSD3,
    ISC,
    Zlib,
    Unlicense,
    CC0,
    WTFPL,

    // Copyleft licenses
    GPL2,
    GPL3,
    LGPL2,
    LGPL3,
    AGPL3,
    MPL2,
    EPL2,

    // Creative Commons
    CCBY,
    CCBYSA,
    CCBYNC,

    // Other
    Proprietary,
    Unknown(String),
    Custom(String),
}

impl License {
    pub fn from_spdx(spdx: &str) -> Self {
        match spdx.to_uppercase().as_str() {
            "MIT" => Self::MIT,
            "APACHE-2.0" | "APACHE2" => Self::Apache2,
            "BSD-2-CLAUSE" | "BSD2" => Self::BSD2,
            "BSD-3-CLAUSE" | "BSD3" => Self::BSD3,
            "ISC" => Self::ISC,
            "ZLIB" => Self::Zlib,
            "UNLICENSE" => Self::Unlicense,
            "CC0-1.0" | "CC0" => Self::CC0,
            "WTFPL" => Self::WTFPL,
            "GPL-2.0" | "GPL-2.0-ONLY" | "GPL2" => Self::GPL2,
            "GPL-3.0" | "GPL-3.0-ONLY" | "GPL3" => Self::GPL3,
            "LGPL-2.1" | "LGPL-2.1-ONLY" | "LGPL2" => Self::LGPL2,
            "LGPL-3.0" | "LGPL-3.0-ONLY" | "LGPL3" => Self::LGPL3,
            "AGPL-3.0" | "AGPL-3.0-ONLY" | "AGPL3" => Self::AGPL3,
            "MPL-2.0" | "MPL2" => Self::MPL2,
            "EPL-2.0" | "EPL2" => Self::EPL2,
            "CC-BY-4.0" | "CCBY" => Self::CCBY,
            "CC-BY-SA-4.0" | "CCBYSA" => Self::CCBYSA,
            "CC-BY-NC-4.0" | "CCBYNC" => Self::CCBYNC,
            _ => Self::Unknown(spdx.to_string()),
        }
    }

    pub fn spdx_id(&self) -> &str {
        match self {
            Self::MIT => "MIT",
            Self::Apache2 => "Apache-2.0",
            Self::BSD2 => "BSD-2-Clause",
            Self::BSD3 => "BSD-3-Clause",
            Self::ISC => "ISC",
            Self::Zlib => "Zlib",
            Self::Unlicense => "Unlicense",
            Self::CC0 => "CC0-1.0",
            Self::WTFPL => "WTFPL",
            Self::GPL2 => "GPL-2.0-only",
            Self::GPL3 => "GPL-3.0-only",
            Self::LGPL2 => "LGPL-2.1-only",
            Self::LGPL3 => "LGPL-3.0-only",
            Self::AGPL3 => "AGPL-3.0-only",
            Self::MPL2 => "MPL-2.0",
            Self::EPL2 => "EPL-2.0",
            Self::CCBY => "CC-BY-4.0",
            Self::CCBYSA => "CC-BY-SA-4.0",
            Self::CCBYNC => "CC-BY-NC-4.0",
            Self::Proprietary => "Proprietary",
            Self::Unknown(s) | Self::Custom(s) => s,
        }
    }

    pub fn category(&self) -> LicenseCategory {
        match self {
            Self::MIT | Self::Apache2 | Self::BSD2 | Self::BSD3 | Self::ISC | Self::Zlib => {
                LicenseCategory::Permissive
            }
            Self::Unlicense | Self::CC0 | Self::WTFPL => LicenseCategory::PublicDomain,
            Self::GPL2 | Self::GPL3 | Self::AGPL3 => LicenseCategory::StrongCopyleft,
            Self::LGPL2 | Self::LGPL3 | Self::MPL2 | Self::EPL2 => LicenseCategory::WeakCopyleft,
            Self::CCBY | Self::CCBYSA => LicenseCategory::Creative,
            Self::CCBYNC => LicenseCategory::NonCommercial,
            Self::Proprietary => LicenseCategory::Proprietary,
            Self::Unknown(_) | Self::Custom(_) => LicenseCategory::Unknown,
        }
    }

    pub fn is_osi_approved(&self) -> bool {
        matches!(
            self,
            Self::MIT
                | Self::Apache2
                | Self::BSD2
                | Self::BSD3
                | Self::ISC
                | Self::Zlib
                | Self::GPL2
                | Self::GPL3
                | Self::LGPL2
                | Self::LGPL3
                | Self::AGPL3
                | Self::MPL2
                | Self::EPL2
        )
    }

    pub fn is_copyleft(&self) -> bool {
        matches!(
            self.category(),
            LicenseCategory::StrongCopyleft | LicenseCategory::WeakCopyleft
        )
    }

    pub fn requires_attribution(&self) -> bool {
        !matches!(self, Self::Unlicense | Self::CC0 | Self::WTFPL)
    }

    pub fn allows_commercial(&self) -> bool {
        !matches!(self, Self::CCBYNC)
    }

    pub fn compatible_with(&self, other: &License) -> bool {
        // Simplified compatibility check
        match (self.category(), other.category()) {
            (LicenseCategory::PublicDomain, _) => true,
            (LicenseCategory::Permissive, LicenseCategory::Permissive) => true,
            (LicenseCategory::Permissive, LicenseCategory::PublicDomain) => true,
            (LicenseCategory::WeakCopyleft, LicenseCategory::Permissive) => true,
            (LicenseCategory::WeakCopyleft, LicenseCategory::PublicDomain) => true,
            (LicenseCategory::StrongCopyleft, LicenseCategory::StrongCopyleft) => {
                // GPL versions must match
                self == other
            }
            _ => false,
        }
    }
}

impl fmt::Display for License {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.spdx_id())
    }
}

/// License category
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LicenseCategory {
    Permissive,
    PublicDomain,
    WeakCopyleft,
    StrongCopyleft,
    Creative,
    NonCommercial,
    Proprietary,
    Unknown,
}

impl fmt::Display for LicenseCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Permissive => write!(f, "Permissive"),
            Self::PublicDomain => write!(f, "Public Domain"),
            Self::WeakCopyleft => write!(f, "Weak Copyleft"),
            Self::StrongCopyleft => write!(f, "Strong Copyleft"),
            Self::Creative => write!(f, "Creative Commons"),
            Self::NonCommercial => write!(f, "Non-Commercial"),
            Self::Proprietary => write!(f, "Proprietary"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Dependency with license information
#[derive(Debug, Clone)]
pub struct Dependency {
    pub name: String,
    pub version: String,
    pub license: License,
    pub license_file: Option<String>,
    pub authors: Vec<String>,
    pub repository: Option<String>,
    pub is_direct: bool,
}

impl Dependency {
    pub fn new(name: impl Into<String>, version: impl Into<String>, license: License) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            license,
            license_file: None,
            authors: Vec::new(),
            repository: None,
            is_direct: true,
        }
    }

    pub fn with_authors(mut self, authors: Vec<String>) -> Self {
        self.authors = authors;
        self
    }

    pub fn with_repository(mut self, repo: impl Into<String>) -> Self {
        self.repository = Some(repo.into());
        self
    }

    pub fn with_license_file(mut self, file: impl Into<String>) -> Self {
        self.license_file = Some(file.into());
        self
    }

    pub fn as_transitive(mut self) -> Self {
        self.is_direct = false;
        self
    }
}

/// License policy for compliance checking
#[derive(Debug, Clone)]
pub struct LicensePolicy {
    pub name: String,
    pub allowed_licenses: HashSet<License>,
    pub denied_licenses: HashSet<License>,
    pub allowed_categories: HashSet<LicenseCategory>,
    pub denied_categories: HashSet<LicenseCategory>,
    pub require_osi_approved: bool,
    pub allow_copyleft: bool,
    pub allow_unknown: bool,
    pub exceptions: HashMap<String, Vec<License>>,
}

impl LicensePolicy {
    pub fn permissive() -> Self {
        let mut allowed = HashSet::new();
        allowed.insert(License::MIT);
        allowed.insert(License::Apache2);
        allowed.insert(License::BSD2);
        allowed.insert(License::BSD3);
        allowed.insert(License::ISC);
        allowed.insert(License::Zlib);
        allowed.insert(License::Unlicense);
        allowed.insert(License::CC0);

        let mut allowed_categories = HashSet::new();
        allowed_categories.insert(LicenseCategory::Permissive);
        allowed_categories.insert(LicenseCategory::PublicDomain);

        Self {
            name: "Permissive Only".to_string(),
            allowed_licenses: allowed,
            denied_licenses: HashSet::new(),
            allowed_categories,
            denied_categories: HashSet::new(),
            require_osi_approved: false,
            allow_copyleft: false,
            allow_unknown: false,
            exceptions: HashMap::new(),
        }
    }

    pub fn osi_approved() -> Self {
        Self {
            name: "OSI Approved".to_string(),
            allowed_licenses: HashSet::new(),
            denied_licenses: HashSet::new(),
            allowed_categories: HashSet::new(),
            denied_categories: HashSet::new(),
            require_osi_approved: true,
            allow_copyleft: true,
            allow_unknown: false,
            exceptions: HashMap::new(),
        }
    }

    pub fn corporate() -> Self {
        let mut denied = HashSet::new();
        denied.insert(License::GPL2);
        denied.insert(License::GPL3);
        denied.insert(License::AGPL3);

        let mut denied_categories = HashSet::new();
        denied_categories.insert(LicenseCategory::StrongCopyleft);
        denied_categories.insert(LicenseCategory::NonCommercial);

        Self {
            name: "Corporate".to_string(),
            allowed_licenses: HashSet::new(),
            denied_licenses: denied,
            allowed_categories: HashSet::new(),
            denied_categories,
            require_osi_approved: false,
            allow_copyleft: false,
            allow_unknown: false,
            exceptions: HashMap::new(),
        }
    }

    pub fn add_exception(&mut self, package: impl Into<String>, licenses: Vec<License>) {
        self.exceptions.insert(package.into(), licenses);
    }

    pub fn check(&self, dep: &Dependency) -> LicenseCheckResult {
        // Check exceptions first
        if let Some(allowed) = self.exceptions.get(&dep.name) {
            if allowed.contains(&dep.license) {
                return LicenseCheckResult::Allowed(AllowedReason::Exception);
            }
        }

        // Check denied licenses
        if self.denied_licenses.contains(&dep.license) {
            return LicenseCheckResult::Denied(DeniedReason::ExplicitlyDenied);
        }

        // Check denied categories
        if self.denied_categories.contains(&dep.license.category()) {
            return LicenseCheckResult::Denied(DeniedReason::CategoryDenied);
        }

        // Check OSI requirement
        if self.require_osi_approved && !dep.license.is_osi_approved() {
            return LicenseCheckResult::Denied(DeniedReason::NotOsiApproved);
        }

        // Check copyleft restriction
        if !self.allow_copyleft && dep.license.is_copyleft() {
            return LicenseCheckResult::Denied(DeniedReason::CopyleftNotAllowed);
        }

        // Check unknown licenses
        if !self.allow_unknown && matches!(dep.license, License::Unknown(_)) {
            return LicenseCheckResult::Warning(WarningReason::UnknownLicense);
        }

        // Check explicitly allowed
        if !self.allowed_licenses.is_empty() && self.allowed_licenses.contains(&dep.license) {
            return LicenseCheckResult::Allowed(AllowedReason::ExplicitlyAllowed);
        }

        // Check allowed categories
        if !self.allowed_categories.is_empty()
            && self.allowed_categories.contains(&dep.license.category())
        {
            return LicenseCheckResult::Allowed(AllowedReason::CategoryAllowed);
        }

        // If no explicit allow list, permit by default
        if self.allowed_licenses.is_empty() && self.allowed_categories.is_empty() {
            LicenseCheckResult::Allowed(AllowedReason::DefaultAllow)
        } else {
            LicenseCheckResult::Denied(DeniedReason::NotInAllowList)
        }
    }
}

/// License check result
#[derive(Debug, Clone)]
pub enum LicenseCheckResult {
    Allowed(AllowedReason),
    Denied(DeniedReason),
    Warning(WarningReason),
}

impl LicenseCheckResult {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed(_))
    }

    pub fn is_denied(&self) -> bool {
        matches!(self, Self::Denied(_))
    }

    pub fn is_warning(&self) -> bool {
        matches!(self, Self::Warning(_))
    }
}

/// Reason for allowing a license
#[derive(Debug, Clone)]
pub enum AllowedReason {
    ExplicitlyAllowed,
    CategoryAllowed,
    Exception,
    DefaultAllow,
}

/// Reason for denying a license
#[derive(Debug, Clone)]
pub enum DeniedReason {
    ExplicitlyDenied,
    CategoryDenied,
    NotOsiApproved,
    CopyleftNotAllowed,
    NotInAllowList,
}

impl fmt::Display for DeniedReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExplicitlyDenied => write!(f, "License is explicitly denied"),
            Self::CategoryDenied => write!(f, "License category is denied"),
            Self::NotOsiApproved => write!(f, "License is not OSI approved"),
            Self::CopyleftNotAllowed => write!(f, "Copyleft licenses not allowed"),
            Self::NotInAllowList => write!(f, "License not in allow list"),
        }
    }
}

/// Reason for warning
#[derive(Debug, Clone)]
pub enum WarningReason {
    UnknownLicense,
    MissingLicenseFile,
    MultipleAuthors,
}

/// License checker
pub struct LicenseChecker {
    policy: LicensePolicy,
    dependencies: Vec<Dependency>,
}

impl LicenseChecker {
    pub fn new(policy: LicensePolicy) -> Self {
        Self {
            policy,
            dependencies: Vec::new(),
        }
    }

    pub fn add_dependency(&mut self, dep: Dependency) {
        self.dependencies.push(dep);
    }

    pub fn check_all(&self) -> LicenseReport {
        let mut report = LicenseReport::new(&self.policy.name);

        for dep in &self.dependencies {
            let result = self.policy.check(dep);
            report.add_result(dep.clone(), result);
        }

        report
    }

    pub fn get_license_summary(&self) -> HashMap<License, Vec<&Dependency>> {
        let mut summary: HashMap<License, Vec<&Dependency>> = HashMap::new();

        for dep in &self.dependencies {
            summary.entry(dep.license.clone()).or_default().push(dep);
        }

        summary
    }

    pub fn get_category_summary(&self) -> HashMap<LicenseCategory, Vec<&Dependency>> {
        let mut summary: HashMap<LicenseCategory, Vec<&Dependency>> = HashMap::new();

        for dep in &self.dependencies {
            summary.entry(dep.license.category()).or_default().push(dep);
        }

        summary
    }
}

/// License compliance report
#[derive(Debug)]
pub struct LicenseReport {
    pub policy_name: String,
    pub results: Vec<(Dependency, LicenseCheckResult)>,
    pub allowed_count: usize,
    pub denied_count: usize,
    pub warning_count: usize,
}

impl LicenseReport {
    pub fn new(policy_name: &str) -> Self {
        Self {
            policy_name: policy_name.to_string(),
            results: Vec::new(),
            allowed_count: 0,
            denied_count: 0,
            warning_count: 0,
        }
    }

    pub fn add_result(&mut self, dep: Dependency, result: LicenseCheckResult) {
        match &result {
            LicenseCheckResult::Allowed(_) => self.allowed_count += 1,
            LicenseCheckResult::Denied(_) => self.denied_count += 1,
            LicenseCheckResult::Warning(_) => self.warning_count += 1,
        }
        self.results.push((dep, result));
    }

    pub fn is_compliant(&self) -> bool {
        self.denied_count == 0
    }

    pub fn get_denied(&self) -> Vec<&(Dependency, LicenseCheckResult)> {
        self.results.iter().filter(|(_, r)| r.is_denied()).collect()
    }

    pub fn get_warnings(&self) -> Vec<&(Dependency, LicenseCheckResult)> {
        self.results
            .iter()
            .filter(|(_, r)| r.is_warning())
            .collect()
    }

    pub fn to_text(&self) -> String {
        let mut output = String::new();

        output.push_str(&format!("=== License Compliance Report ===\n"));
        output.push_str(&format!("Policy: {}\n\n", self.policy_name));

        output.push_str(&format!("Summary:\n"));
        output.push_str(&format!("  Total dependencies: {}\n", self.results.len()));
        output.push_str(&format!("  Allowed: {}\n", self.allowed_count));
        output.push_str(&format!("  Denied: {}\n", self.denied_count));
        output.push_str(&format!("  Warnings: {}\n\n", self.warning_count));

        if self.denied_count > 0 {
            output.push_str("Denied Dependencies:\n");
            for (dep, result) in self.get_denied() {
                if let LicenseCheckResult::Denied(reason) = result {
                    output.push_str(&format!(
                        "  ✗ {} {} ({}): {}\n",
                        dep.name, dep.version, dep.license, reason
                    ));
                }
            }
            output.push('\n');
        }

        if self.warning_count > 0 {
            output.push_str("Warnings:\n");
            for (dep, result) in self.get_warnings() {
                if let LicenseCheckResult::Warning(reason) = result {
                    output.push_str(&format!(
                        "  ⚠ {} {} ({}): {:?}\n",
                        dep.name, dep.version, dep.license, reason
                    ));
                }
            }
            output.push('\n');
        }

        output.push_str("All Dependencies:\n");
        for (dep, result) in &self.results {
            let status = match result {
                LicenseCheckResult::Allowed(_) => "✓",
                LicenseCheckResult::Denied(_) => "✗",
                LicenseCheckResult::Warning(_) => "⚠",
            };
            output.push_str(&format!(
                "  {} {} {} ({})\n",
                status, dep.name, dep.version, dep.license
            ));
        }

        output.push_str(&format!(
            "\nCompliance Status: {}\n",
            if self.is_compliant() { "PASS" } else { "FAIL" }
        ));

        output
    }

    pub fn to_json(&self) -> String {
        let results: Vec<String> = self
            .results
            .iter()
            .map(|(dep, result)| {
                let (status, reason) = match result {
                    LicenseCheckResult::Allowed(r) => ("allowed", format!("{:?}", r)),
                    LicenseCheckResult::Denied(r) => ("denied", format!("{}", r)),
                    LicenseCheckResult::Warning(r) => ("warning", format!("{:?}", r)),
                };
                format!(
                    r#"    {{
      "name": "{}",
      "version": "{}",
      "license": "{}",
      "status": "{}",
      "reason": "{}"
    }}"#,
                    dep.name, dep.version, dep.license, status, reason
                )
            })
            .collect();

        format!(
            r#"{{
  "policy": "{}",
  "summary": {{
    "total": {},
    "allowed": {},
    "denied": {},
    "warnings": {}
  }},
  "compliant": {},
  "dependencies": [
{}
  ]
}}"#,
            self.policy_name,
            self.results.len(),
            self.allowed_count,
            self.denied_count,
            self.warning_count,
            self.is_compliant(),
            results.join(",\n")
        )
    }
}

/// Attribution generator for license compliance
pub struct AttributionGenerator;

impl AttributionGenerator {
    pub fn generate(dependencies: &[Dependency]) -> String {
        let mut output = String::new();

        output.push_str("# Third-Party Licenses\n\n");
        output.push_str("This project uses the following third-party dependencies:\n\n");

        for dep in dependencies {
            if dep.license.requires_attribution() {
                output.push_str(&format!("## {} {}\n\n", dep.name, dep.version));
                output.push_str(&format!("- **License**: {}\n", dep.license));

                if !dep.authors.is_empty() {
                    output.push_str(&format!("- **Authors**: {}\n", dep.authors.join(", ")));
                }

                if let Some(repo) = &dep.repository {
                    output.push_str(&format!("- **Repository**: {}\n", repo));
                }

                output.push('\n');
            }
        }

        output
    }

    pub fn generate_notice(dependencies: &[Dependency]) -> String {
        let mut output = String::new();

        output.push_str("NOTICES AND INFORMATION\n");
        output.push_str("=======================\n\n");
        output.push_str("This software includes the following third-party components:\n\n");

        // Group by license
        let mut by_license: HashMap<&License, Vec<&Dependency>> = HashMap::new();
        for dep in dependencies {
            by_license.entry(&dep.license).or_default().push(dep);
        }

        for (license, deps) in by_license {
            output.push_str(&format!("--- {} ---\n", license));
            for dep in deps {
                output.push_str(&format!("  - {} {}\n", dep.name, dep.version));
            }
            output.push('\n');
        }

        output
    }
}

fn main() {
    println!("=== License Checker Demo ===\n");

    // Create a corporate policy
    let mut policy = LicensePolicy::corporate();
    policy.add_exception("special-crate".to_string(), vec![License::GPL2]);

    // Create checker
    let mut checker = LicenseChecker::new(policy);

    // Add dependencies
    checker.add_dependency(
        Dependency::new("serde", "1.0.0", License::Apache2)
            .with_authors(vec!["David Tolnay".to_string()])
            .with_repository("https://github.com/serde-rs/serde"),
    );

    checker.add_dependency(
        Dependency::new("tokio", "1.0.0", License::MIT)
            .with_authors(vec!["Tokio Contributors".to_string()])
            .with_repository("https://github.com/tokio-rs/tokio"),
    );

    checker.add_dependency(
        Dependency::new("ring", "0.16.0", License::ISC)
            .with_authors(vec!["Brian Smith".to_string()]),
    );

    checker.add_dependency(
        Dependency::new("gpl-lib", "1.0.0", License::GPL3)
            .with_authors(vec!["GPL Author".to_string()]),
    );

    checker.add_dependency(
        Dependency::new("special-crate", "1.0.0", License::GPL2)
            .with_authors(vec!["Special Author".to_string()]),
    );

    checker.add_dependency(
        Dependency::new(
            "unknown-lib",
            "0.1.0",
            License::Unknown("CUSTOM-1.0".to_string()),
        )
        .as_transitive(),
    );

    // Run check
    let report = checker.check_all();

    // Print text report
    println!("{}", report.to_text());

    // Print JSON report
    println!("\n--- JSON Report ---");
    println!("{}", report.to_json());

    // License summary
    println!("\n--- License Summary ---");
    let summary = checker.get_license_summary();
    for (license, deps) in &summary {
        println!("{}: {} dependencies", license, deps.len());
        for dep in deps {
            println!("  - {} {}", dep.name, dep.version);
        }
    }

    // Category summary
    println!("\n--- Category Summary ---");
    let cat_summary = checker.get_category_summary();
    for (category, deps) in &cat_summary {
        println!("{}: {} dependencies", category, deps.len());
    }

    // Generate attribution
    println!("\n--- Attribution ---");
    let deps: Vec<Dependency> = checker.dependencies.iter().cloned().collect();
    println!("{}", AttributionGenerator::generate(&deps));

    // Generate notice file
    println!("\n--- NOTICE File ---");
    println!("{}", AttributionGenerator::generate_notice(&deps));

    // License compatibility check
    println!("\n--- License Compatibility ---");
    let mit = License::MIT;
    let apache = License::Apache2;
    let gpl = License::GPL3;

    println!(
        "MIT compatible with Apache-2.0: {}",
        mit.compatible_with(&apache)
    );
    println!("MIT compatible with GPL-3.0: {}", mit.compatible_with(&gpl));
    println!("GPL-3.0 compatible with MIT: {}", gpl.compatible_with(&mit));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_license_from_spdx() {
        assert_eq!(License::from_spdx("MIT"), License::MIT);
        assert_eq!(License::from_spdx("Apache-2.0"), License::Apache2);
        assert_eq!(License::from_spdx("GPL-3.0"), License::GPL3);
        assert!(matches!(
            License::from_spdx("UNKNOWN-LICENSE"),
            License::Unknown(_)
        ));
    }

    #[test]
    fn test_license_category() {
        assert_eq!(License::MIT.category(), LicenseCategory::Permissive);
        assert_eq!(License::GPL3.category(), LicenseCategory::StrongCopyleft);
        assert_eq!(License::LGPL3.category(), LicenseCategory::WeakCopyleft);
        assert_eq!(License::CC0.category(), LicenseCategory::PublicDomain);
    }

    #[test]
    fn test_license_is_osi_approved() {
        assert!(License::MIT.is_osi_approved());
        assert!(License::Apache2.is_osi_approved());
        assert!(License::GPL3.is_osi_approved());
        assert!(!License::CC0.is_osi_approved());
        assert!(!License::Proprietary.is_osi_approved());
    }

    #[test]
    fn test_license_is_copyleft() {
        assert!(!License::MIT.is_copyleft());
        assert!(License::GPL3.is_copyleft());
        assert!(License::LGPL3.is_copyleft());
    }

    #[test]
    fn test_license_requires_attribution() {
        assert!(License::MIT.requires_attribution());
        assert!(License::Apache2.requires_attribution());
        assert!(!License::Unlicense.requires_attribution());
        assert!(!License::CC0.requires_attribution());
    }

    #[test]
    fn test_license_compatibility() {
        assert!(License::MIT.compatible_with(&License::Apache2));
        assert!(License::CC0.compatible_with(&License::MIT));
        assert!(!License::GPL3.compatible_with(&License::MIT));
    }

    #[test]
    fn test_dependency_creation() {
        let dep = Dependency::new("test", "1.0.0", License::MIT)
            .with_authors(vec!["Author".to_string()])
            .with_repository("https://example.com");

        assert_eq!(dep.name, "test");
        assert_eq!(dep.version, "1.0.0");
        assert_eq!(dep.license, License::MIT);
        assert!(dep.is_direct);
    }

    #[test]
    fn test_dependency_transitive() {
        let dep = Dependency::new("test", "1.0.0", License::MIT).as_transitive();

        assert!(!dep.is_direct);
    }

    #[test]
    fn test_permissive_policy() {
        let policy = LicensePolicy::permissive();

        let mit_dep = Dependency::new("test", "1.0.0", License::MIT);
        let gpl_dep = Dependency::new("test", "1.0.0", License::GPL3);

        assert!(policy.check(&mit_dep).is_allowed());
        assert!(policy.check(&gpl_dep).is_denied());
    }

    #[test]
    fn test_corporate_policy() {
        let policy = LicensePolicy::corporate();

        let mit_dep = Dependency::new("test", "1.0.0", License::MIT);
        let gpl_dep = Dependency::new("test", "1.0.0", License::GPL3);
        let agpl_dep = Dependency::new("test", "1.0.0", License::AGPL3);

        assert!(policy.check(&mit_dep).is_allowed());
        assert!(policy.check(&gpl_dep).is_denied());
        assert!(policy.check(&agpl_dep).is_denied());
    }

    #[test]
    fn test_policy_exception() {
        let mut policy = LicensePolicy::corporate();
        policy.add_exception("special".to_string(), vec![License::GPL3]);

        let special_dep = Dependency::new("special", "1.0.0", License::GPL3);
        let other_dep = Dependency::new("other", "1.0.0", License::GPL3);

        assert!(policy.check(&special_dep).is_allowed());
        assert!(policy.check(&other_dep).is_denied());
    }

    #[test]
    fn test_license_checker() {
        let policy = LicensePolicy::permissive();
        let mut checker = LicenseChecker::new(policy);

        checker.add_dependency(Dependency::new("a", "1.0.0", License::MIT));
        checker.add_dependency(Dependency::new("b", "1.0.0", License::Apache2));

        let report = checker.check_all();

        assert!(report.is_compliant());
        assert_eq!(report.allowed_count, 2);
        assert_eq!(report.denied_count, 0);
    }

    #[test]
    fn test_license_report() {
        let policy = LicensePolicy::permissive();
        let mut checker = LicenseChecker::new(policy);

        checker.add_dependency(Dependency::new("good", "1.0.0", License::MIT));
        checker.add_dependency(Dependency::new("bad", "1.0.0", License::GPL3));

        let report = checker.check_all();

        assert!(!report.is_compliant());
        assert_eq!(report.allowed_count, 1);
        assert_eq!(report.denied_count, 1);
    }

    #[test]
    fn test_license_summary() {
        let policy = LicensePolicy::permissive();
        let mut checker = LicenseChecker::new(policy);

        checker.add_dependency(Dependency::new("a", "1.0.0", License::MIT));
        checker.add_dependency(Dependency::new("b", "1.0.0", License::MIT));
        checker.add_dependency(Dependency::new("c", "1.0.0", License::Apache2));

        let summary = checker.get_license_summary();

        assert_eq!(summary.get(&License::MIT).map(|v| v.len()), Some(2));
        assert_eq!(summary.get(&License::Apache2).map(|v| v.len()), Some(1));
    }

    #[test]
    fn test_attribution_generator() {
        let deps =
            vec![Dependency::new("test", "1.0.0", License::MIT)
                .with_authors(vec!["Author".to_string()])];

        let attribution = AttributionGenerator::generate(&deps);

        assert!(attribution.contains("test"));
        assert!(attribution.contains("MIT"));
        assert!(attribution.contains("Author"));
    }

    #[test]
    fn test_unknown_license_warning() {
        let policy = LicensePolicy::permissive();
        let dep = Dependency::new("test", "1.0.0", License::Unknown("CUSTOM".to_string()));

        let result = policy.check(&dep);

        assert!(result.is_warning());
    }
}
