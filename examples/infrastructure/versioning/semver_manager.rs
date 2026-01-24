//! Semantic Versioning Manager
//!
//! Comprehensive semantic versioning implementation with:
//! - Version parsing and validation
//! - Version comparison and ordering
//! - Pre-release and build metadata
//! - Version bumping with rules
//! - Changelog integration

use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

/// Semantic version following SemVer 2.0.0
#[derive(Clone, Debug, Eq)]
pub struct SemVer {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub pre_release: Option<PreRelease>,
    pub build_metadata: Option<String>,
}

/// Pre-release version identifier
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreRelease {
    pub identifiers: Vec<PreReleaseId>,
}

/// Individual pre-release identifier
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PreReleaseId {
    Numeric(u64),
    AlphaNumeric(String),
}

/// Version bump type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BumpType {
    Major,
    Minor,
    Patch,
    PreRelease,
}

/// Version constraint for dependency resolution
#[derive(Clone, Debug)]
pub enum VersionConstraint {
    Exact(SemVer),
    Caret(SemVer), // ^1.2.3 - compatible updates
    Tilde(SemVer), // ~1.2.3 - patch updates only
    GreaterThan(SemVer),
    GreaterThanOrEqual(SemVer),
    LessThan(SemVer),
    LessThanOrEqual(SemVer),
    Range(Box<VersionConstraint>, Box<VersionConstraint>),
    Or(Vec<VersionConstraint>),
    Wildcard,
}

/// Changelog entry
#[derive(Clone, Debug)]
pub struct ChangelogEntry {
    pub version: SemVer,
    pub date: String,
    pub changes: Vec<Change>,
}

/// Individual change in changelog
#[derive(Clone, Debug)]
pub struct Change {
    pub change_type: ChangeType,
    pub description: String,
    pub breaking: bool,
    pub issue_refs: Vec<String>,
}

/// Type of change
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeType {
    Added,
    Changed,
    Deprecated,
    Removed,
    Fixed,
    Security,
}

/// Version manager for project versioning
pub struct VersionManager {
    current_version: SemVer,
    changelog: Vec<ChangelogEntry>,
    pending_changes: Vec<Change>,
    version_history: Vec<SemVer>,
}

/// Parse error for versions
#[derive(Debug)]
pub struct ParseError {
    pub message: String,
    pub input: String,
}

impl SemVer {
    /// Create a new semantic version
    pub fn new(major: u64, minor: u64, patch: u64) -> Self {
        Self {
            major,
            minor,
            patch,
            pre_release: None,
            build_metadata: None,
        }
    }

    /// Create version with pre-release
    pub fn with_pre_release(mut self, pre: PreRelease) -> Self {
        self.pre_release = Some(pre);
        self
    }

    /// Create version with build metadata
    pub fn with_build(mut self, build: impl Into<String>) -> Self {
        self.build_metadata = Some(build.into());
        self
    }

    /// Bump version by type
    pub fn bump(&self, bump_type: BumpType) -> Self {
        match bump_type {
            BumpType::Major => Self::new(self.major + 1, 0, 0),
            BumpType::Minor => Self::new(self.major, self.minor + 1, 0),
            BumpType::Patch => Self::new(self.major, self.minor, self.patch + 1),
            BumpType::PreRelease => {
                let pre = match &self.pre_release {
                    Some(pr) => pr.increment(),
                    None => PreRelease::alpha(1),
                };
                Self::new(self.major, self.minor, self.patch).with_pre_release(pre)
            }
        }
    }

    /// Check if this is a stable version (no pre-release)
    pub fn is_stable(&self) -> bool {
        self.pre_release.is_none()
    }

    /// Check if this is version 0.x.x (initial development)
    pub fn is_initial_development(&self) -> bool {
        self.major == 0
    }

    /// Check if version satisfies constraint
    pub fn satisfies(&self, constraint: &VersionConstraint) -> bool {
        match constraint {
            VersionConstraint::Exact(v) => self == v,
            VersionConstraint::Caret(v) => self.satisfies_caret(v),
            VersionConstraint::Tilde(v) => self.satisfies_tilde(v),
            VersionConstraint::GreaterThan(v) => self > v,
            VersionConstraint::GreaterThanOrEqual(v) => self >= v,
            VersionConstraint::LessThan(v) => self < v,
            VersionConstraint::LessThanOrEqual(v) => self <= v,
            VersionConstraint::Range(min, max) => self.satisfies(min) && self.satisfies(max),
            VersionConstraint::Or(constraints) => constraints.iter().any(|c| self.satisfies(c)),
            VersionConstraint::Wildcard => true,
        }
    }

    /// Caret constraint: ^1.2.3 allows >=1.2.3 <2.0.0
    fn satisfies_caret(&self, base: &SemVer) -> bool {
        if self < base {
            return false;
        }

        if base.major == 0 {
            if base.minor == 0 {
                // ^0.0.x only allows patch changes
                self.major == 0 && self.minor == 0 && self.patch >= base.patch
            } else {
                // ^0.x.y allows minor and patch changes within 0.x
                self.major == 0 && self.minor == base.minor
            }
        } else {
            // ^x.y.z allows changes that don't modify major version
            self.major == base.major
        }
    }

    /// Tilde constraint: ~1.2.3 allows >=1.2.3 <1.3.0
    fn satisfies_tilde(&self, base: &SemVer) -> bool {
        self >= base && self.major == base.major && self.minor == base.minor
    }

    /// Calculate the difference between versions
    pub fn diff(&self, other: &SemVer) -> BumpType {
        if self.major != other.major {
            BumpType::Major
        } else if self.minor != other.minor {
            BumpType::Minor
        } else if self.patch != other.patch {
            BumpType::Patch
        } else {
            BumpType::PreRelease
        }
    }
}

impl FromStr for SemVer {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim().trim_start_matches('v');

        // Split off build metadata
        let (version_pre, build) = match s.split_once('+') {
            Some((v, b)) => (v, Some(b.to_string())),
            None => (s, None),
        };

        // Split off pre-release
        let (version, pre) = match version_pre.split_once('-') {
            Some((v, p)) => (v, Some(PreRelease::from_str(p)?)),
            None => (version_pre, None),
        };

        // Parse major.minor.patch
        let parts: Vec<&str> = version.split('.').collect();
        if parts.len() != 3 {
            return Err(ParseError {
                message: "Version must have exactly three components".to_string(),
                input: s.to_string(),
            });
        }

        let major = parts[0].parse().map_err(|_| ParseError {
            message: "Invalid major version".to_string(),
            input: s.to_string(),
        })?;

        let minor = parts[1].parse().map_err(|_| ParseError {
            message: "Invalid minor version".to_string(),
            input: s.to_string(),
        })?;

        let patch = parts[2].parse().map_err(|_| ParseError {
            message: "Invalid patch version".to_string(),
            input: s.to_string(),
        })?;

        Ok(Self {
            major,
            minor,
            patch,
            pre_release: pre,
            build_metadata: build,
        })
    }
}

impl fmt::Display for SemVer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if let Some(pre) = &self.pre_release {
            write!(f, "-{}", pre)?;
        }
        if let Some(build) = &self.build_metadata {
            write!(f, "+{}", build)?;
        }
        Ok(())
    }
}

impl PartialEq for SemVer {
    fn eq(&self, other: &Self) -> bool {
        // Build metadata is ignored in comparison
        self.major == other.major
            && self.minor == other.minor
            && self.patch == other.patch
            && self.pre_release == other.pre_release
    }
}

impl PartialOrd for SemVer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SemVer {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.major.cmp(&other.major) {
            Ordering::Equal => {}
            ord => return ord,
        }
        match self.minor.cmp(&other.minor) {
            Ordering::Equal => {}
            ord => return ord,
        }
        match self.patch.cmp(&other.patch) {
            Ordering::Equal => {}
            ord => return ord,
        }

        // Pre-release versions have lower precedence
        match (&self.pre_release, &other.pre_release) {
            (None, None) => Ordering::Equal,
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (Some(a), Some(b)) => a.cmp(b),
        }
    }
}

impl PreRelease {
    /// Create alpha pre-release
    pub fn alpha(n: u64) -> Self {
        Self {
            identifiers: vec![
                PreReleaseId::AlphaNumeric("alpha".to_string()),
                PreReleaseId::Numeric(n),
            ],
        }
    }

    /// Create beta pre-release
    pub fn beta(n: u64) -> Self {
        Self {
            identifiers: vec![
                PreReleaseId::AlphaNumeric("beta".to_string()),
                PreReleaseId::Numeric(n),
            ],
        }
    }

    /// Create release candidate
    pub fn rc(n: u64) -> Self {
        Self {
            identifiers: vec![
                PreReleaseId::AlphaNumeric("rc".to_string()),
                PreReleaseId::Numeric(n),
            ],
        }
    }

    /// Increment the pre-release version
    pub fn increment(&self) -> Self {
        let mut ids = self.identifiers.clone();
        if let Some(last) = ids.last_mut() {
            if let PreReleaseId::Numeric(n) = last {
                *n += 1;
            }
        }
        Self { identifiers: ids }
    }
}

impl FromStr for PreRelease {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let identifiers = s
            .split('.')
            .map(|part| {
                if let Ok(n) = part.parse::<u64>() {
                    PreReleaseId::Numeric(n)
                } else {
                    PreReleaseId::AlphaNumeric(part.to_string())
                }
            })
            .collect();

        Ok(Self { identifiers })
    }
}

impl fmt::Display for PreRelease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let parts: Vec<String> = self
            .identifiers
            .iter()
            .map(|id| match id {
                PreReleaseId::Numeric(n) => n.to_string(),
                PreReleaseId::AlphaNumeric(s) => s.clone(),
            })
            .collect();
        write!(f, "{}", parts.join("."))
    }
}

impl Ord for PreRelease {
    fn cmp(&self, other: &Self) -> Ordering {
        for (a, b) in self.identifiers.iter().zip(other.identifiers.iter()) {
            let ord = match (a, b) {
                (PreReleaseId::Numeric(x), PreReleaseId::Numeric(y)) => x.cmp(y),
                (PreReleaseId::AlphaNumeric(x), PreReleaseId::AlphaNumeric(y)) => x.cmp(y),
                (PreReleaseId::Numeric(_), PreReleaseId::AlphaNumeric(_)) => Ordering::Less,
                (PreReleaseId::AlphaNumeric(_), PreReleaseId::Numeric(_)) => Ordering::Greater,
            };
            if ord != Ordering::Equal {
                return ord;
            }
        }
        self.identifiers.len().cmp(&other.identifiers.len())
    }
}

impl PartialOrd for PreRelease {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl VersionManager {
    /// Create new version manager
    pub fn new(initial_version: SemVer) -> Self {
        Self {
            current_version: initial_version.clone(),
            changelog: Vec::new(),
            pending_changes: Vec::new(),
            version_history: vec![initial_version],
        }
    }

    /// Get current version
    pub fn current(&self) -> &SemVer {
        &self.current_version
    }

    /// Add a pending change
    pub fn add_change(&mut self, change: Change) {
        self.pending_changes.push(change);
    }

    /// Calculate recommended bump based on pending changes
    pub fn recommended_bump(&self) -> BumpType {
        let has_breaking = self.pending_changes.iter().any(|c| c.breaking);
        let has_features = self
            .pending_changes
            .iter()
            .any(|c| c.change_type == ChangeType::Added);

        if has_breaking {
            if self.current_version.is_initial_development() {
                BumpType::Minor
            } else {
                BumpType::Major
            }
        } else if has_features {
            BumpType::Minor
        } else {
            BumpType::Patch
        }
    }

    /// Release a new version
    pub fn release(&mut self, bump_type: BumpType, date: &str) -> SemVer {
        let new_version = self.current_version.bump(bump_type);

        let entry = ChangelogEntry {
            version: new_version.clone(),
            date: date.to_string(),
            changes: std::mem::take(&mut self.pending_changes),
        };

        self.changelog.push(entry);
        self.version_history.push(new_version.clone());
        self.current_version = new_version.clone();

        new_version
    }

    /// Generate changelog markdown
    pub fn generate_changelog(&self) -> String {
        let mut output = String::new();
        output.push_str("# Changelog\n\n");
        output.push_str("All notable changes to this project will be documented in this file.\n\n");
        output.push_str(
            "The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),\n",
        );
        output.push_str("and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).\n\n");

        for entry in self.changelog.iter().rev() {
            output.push_str(&format!("## [{}] - {}\n\n", entry.version, entry.date));

            let mut by_type: HashMap<ChangeType, Vec<&Change>> = HashMap::new();
            for change in &entry.changes {
                by_type.entry(change.change_type).or_default().push(change);
            }

            for (change_type, changes) in by_type {
                let header = match change_type {
                    ChangeType::Added => "### Added",
                    ChangeType::Changed => "### Changed",
                    ChangeType::Deprecated => "### Deprecated",
                    ChangeType::Removed => "### Removed",
                    ChangeType::Fixed => "### Fixed",
                    ChangeType::Security => "### Security",
                };
                output.push_str(&format!("{}\n\n", header));

                for change in changes {
                    let breaking_marker = if change.breaking { "**BREAKING** " } else { "" };
                    let refs = if change.issue_refs.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", change.issue_refs.join(", "))
                    };
                    output.push_str(&format!(
                        "- {}{}{}\n",
                        breaking_marker, change.description, refs
                    ));
                }
                output.push('\n');
            }
        }

        output
    }

    /// Get version history
    pub fn history(&self) -> &[SemVer] {
        &self.version_history
    }
}

impl fmt::Display for ChangeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChangeType::Added => write!(f, "Added"),
            ChangeType::Changed => write!(f, "Changed"),
            ChangeType::Deprecated => write!(f, "Deprecated"),
            ChangeType::Removed => write!(f, "Removed"),
            ChangeType::Fixed => write!(f, "Fixed"),
            ChangeType::Security => write!(f, "Security"),
        }
    }
}

fn main() {
    println!("=== Semantic Versioning Manager Demo ===\n");

    // Parse versions
    let v1 = SemVer::from_str("1.2.3").unwrap();
    let v2 = SemVer::from_str("1.2.4-alpha.1").unwrap();
    let v3 = SemVer::from_str("2.0.0-rc.1+build.123").unwrap();

    println!("Parsed versions:");
    println!("  v1: {}", v1);
    println!("  v2: {}", v2);
    println!("  v3: {}", v3);

    // Version comparison
    println!("\nVersion comparison:");
    println!("  {} < {} : {}", v1, v2, v1 < v2);
    println!("  {} < {} : {}", v2, v3, v2 < v3);
    println!("  {} is stable: {}", v1, v1.is_stable());
    println!("  {} is stable: {}", v2, v2.is_stable());

    // Version bumping
    println!("\nVersion bumping from {}:", v1);
    println!("  Patch bump: {}", v1.bump(BumpType::Patch));
    println!("  Minor bump: {}", v1.bump(BumpType::Minor));
    println!("  Major bump: {}", v1.bump(BumpType::Major));

    // Constraint checking
    let constraint = VersionConstraint::Caret(SemVer::new(1, 2, 0));
    println!("\nCaret constraint ^1.2.0:");
    println!(
        "  1.2.3 satisfies: {}",
        SemVer::new(1, 2, 3).satisfies(&constraint)
    );
    println!(
        "  1.9.0 satisfies: {}",
        SemVer::new(1, 9, 0).satisfies(&constraint)
    );
    println!(
        "  2.0.0 satisfies: {}",
        SemVer::new(2, 0, 0).satisfies(&constraint)
    );

    // Version manager with changelog
    println!("\n=== Version Manager Demo ===\n");

    let mut manager = VersionManager::new(SemVer::new(0, 1, 0));

    // Add changes
    manager.add_change(Change {
        change_type: ChangeType::Added,
        description: "Initial API implementation".to_string(),
        breaking: false,
        issue_refs: vec!["#1".to_string()],
    });
    manager.add_change(Change {
        change_type: ChangeType::Added,
        description: "Authentication support".to_string(),
        breaking: false,
        issue_refs: vec!["#2".to_string()],
    });

    // Release
    let v1 = manager.release(BumpType::Minor, "2025-01-15");
    println!("Released version: {}", v1);

    // More changes
    manager.add_change(Change {
        change_type: ChangeType::Fixed,
        description: "Fixed memory leak in connection pool".to_string(),
        breaking: false,
        issue_refs: vec!["#5".to_string()],
    });
    manager.add_change(Change {
        change_type: ChangeType::Security,
        description: "Updated crypto dependencies".to_string(),
        breaking: false,
        issue_refs: vec!["CVE-2025-0001".to_string()],
    });

    let v2 = manager.release(BumpType::Patch, "2025-01-20");
    println!("Released version: {}", v2);

    // Breaking change
    manager.add_change(Change {
        change_type: ChangeType::Changed,
        description: "Renamed Config to Configuration".to_string(),
        breaking: true,
        issue_refs: vec!["#10".to_string()],
    });

    println!("\nRecommended bump: {:?}", manager.recommended_bump());

    let v3 = manager.release(manager.recommended_bump(), "2025-01-23");
    println!("Released version: {}", v3);

    // Generate changelog
    println!("\n{}", manager.generate_changelog());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_parsing() {
        let v = SemVer::from_str("1.2.3").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 3);
        assert!(v.pre_release.is_none());
        assert!(v.build_metadata.is_none());
    }

    #[test]
    fn test_version_with_prerelease() {
        let v = SemVer::from_str("1.0.0-alpha.1").unwrap();
        assert!(v.pre_release.is_some());
        assert_eq!(v.to_string(), "1.0.0-alpha.1");
    }

    #[test]
    fn test_version_with_build() {
        let v = SemVer::from_str("1.0.0+build.123").unwrap();
        assert_eq!(v.build_metadata, Some("build.123".to_string()));
    }

    #[test]
    fn test_version_comparison() {
        let v1 = SemVer::new(1, 0, 0);
        let v2 = SemVer::new(1, 0, 1);
        let v3 = SemVer::new(1, 1, 0);
        let v4 = SemVer::new(2, 0, 0);

        assert!(v1 < v2);
        assert!(v2 < v3);
        assert!(v3 < v4);
    }

    #[test]
    fn test_prerelease_precedence() {
        let stable = SemVer::new(1, 0, 0);
        let alpha = SemVer::new(1, 0, 0).with_pre_release(PreRelease::alpha(1));
        let beta = SemVer::new(1, 0, 0).with_pre_release(PreRelease::beta(1));
        let rc = SemVer::new(1, 0, 0).with_pre_release(PreRelease::rc(1));

        assert!(alpha < beta);
        assert!(beta < rc);
        assert!(rc < stable);
    }

    #[test]
    fn test_version_bumping() {
        let v = SemVer::new(1, 2, 3);

        assert_eq!(v.bump(BumpType::Patch), SemVer::new(1, 2, 4));
        assert_eq!(v.bump(BumpType::Minor), SemVer::new(1, 3, 0));
        assert_eq!(v.bump(BumpType::Major), SemVer::new(2, 0, 0));
    }

    #[test]
    fn test_caret_constraint() {
        let constraint = VersionConstraint::Caret(SemVer::new(1, 2, 0));

        assert!(SemVer::new(1, 2, 0).satisfies(&constraint));
        assert!(SemVer::new(1, 9, 9).satisfies(&constraint));
        assert!(!SemVer::new(2, 0, 0).satisfies(&constraint));
        assert!(!SemVer::new(1, 1, 0).satisfies(&constraint));
    }

    #[test]
    fn test_tilde_constraint() {
        let constraint = VersionConstraint::Tilde(SemVer::new(1, 2, 0));

        assert!(SemVer::new(1, 2, 0).satisfies(&constraint));
        assert!(SemVer::new(1, 2, 9).satisfies(&constraint));
        assert!(!SemVer::new(1, 3, 0).satisfies(&constraint));
    }

    #[test]
    fn test_caret_zero_version() {
        // ^0.2.3 should only allow 0.2.x
        let constraint = VersionConstraint::Caret(SemVer::new(0, 2, 3));

        assert!(SemVer::new(0, 2, 3).satisfies(&constraint));
        assert!(SemVer::new(0, 2, 9).satisfies(&constraint));
        assert!(!SemVer::new(0, 3, 0).satisfies(&constraint));
    }

    #[test]
    fn test_version_manager() {
        let mut manager = VersionManager::new(SemVer::new(1, 0, 0));

        manager.add_change(Change {
            change_type: ChangeType::Added,
            description: "New feature".to_string(),
            breaking: false,
            issue_refs: vec![],
        });

        assert_eq!(manager.recommended_bump(), BumpType::Minor);

        let new_version = manager.release(BumpType::Minor, "2025-01-01");
        assert_eq!(new_version, SemVer::new(1, 1, 0));
    }

    #[test]
    fn test_breaking_change_bump() {
        let mut manager = VersionManager::new(SemVer::new(1, 0, 0));

        manager.add_change(Change {
            change_type: ChangeType::Changed,
            description: "Breaking API change".to_string(),
            breaking: true,
            issue_refs: vec![],
        });

        assert_eq!(manager.recommended_bump(), BumpType::Major);
    }

    #[test]
    fn test_changelog_generation() {
        let mut manager = VersionManager::new(SemVer::new(0, 1, 0));

        manager.add_change(Change {
            change_type: ChangeType::Added,
            description: "Initial release".to_string(),
            breaking: false,
            issue_refs: vec!["#1".to_string()],
        });

        manager.release(BumpType::Minor, "2025-01-01");

        let changelog = manager.generate_changelog();
        assert!(changelog.contains("## [0.2.0] - 2025-01-01"));
        assert!(changelog.contains("### Added"));
        assert!(changelog.contains("Initial release"));
        assert!(changelog.contains("#1"));
    }
}
