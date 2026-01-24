//! Semantic Versioning Management
//!
//! Tools for managing semantic versioning:
//! - Version parsing and comparison
//! - Version bumping logic
//! - Changelog generation
//! - VERSION-HISTORY.md maintenance
//! - Pre-release and build metadata

use std::cmp::Ordering;
use std::fmt;

// ============================================================================
// Semantic Version
// ============================================================================

/// Semantic version (SemVer 2.0.0 compliant)
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct SemanticVersion {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub pre_release: Option<PreRelease>,
    pub build_metadata: Option<String>,
}

/// Pre-release version
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct PreRelease {
    pub identifiers: Vec<PreReleaseId>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum PreReleaseId {
    Numeric(u64),
    AlphaNumeric(String),
}

impl SemanticVersion {
    /// Create a new version
    pub fn new(major: u64, minor: u64, patch: u64) -> Self {
        Self {
            major,
            minor,
            patch,
            pre_release: None,
            build_metadata: None,
        }
    }

    /// Parse version from string
    pub fn parse(s: &str) -> Result<Self, VersionError> {
        let s = s.trim().trim_start_matches('v').trim_start_matches('V');

        // Split build metadata
        let (version_pre, build) = if let Some(pos) = s.find('+') {
            (&s[..pos], Some(s[pos + 1..].to_string()))
        } else {
            (s, None)
        };

        // Split pre-release
        let (version, pre) = if let Some(pos) = version_pre.find('-') {
            (&version_pre[..pos], Some(&version_pre[pos + 1..]))
        } else {
            (version_pre, None)
        };

        // Parse core version
        let parts: Vec<&str> = version.split('.').collect();
        if parts.len() < 3 {
            return Err(VersionError::InvalidFormat(s.to_string()));
        }

        let major = parts[0]
            .parse()
            .map_err(|_| VersionError::InvalidNumber(parts[0].to_string()))?;
        let minor = parts[1]
            .parse()
            .map_err(|_| VersionError::InvalidNumber(parts[1].to_string()))?;
        let patch = parts[2]
            .parse()
            .map_err(|_| VersionError::InvalidNumber(parts[2].to_string()))?;

        // Parse pre-release
        let pre_release = if let Some(pre_str) = pre {
            Some(PreRelease::parse(pre_str)?)
        } else {
            None
        };

        Ok(Self {
            major,
            minor,
            patch,
            pre_release,
            build_metadata: build,
        })
    }

    /// Bump major version
    pub fn bump_major(&self) -> Self {
        Self::new(self.major + 1, 0, 0)
    }

    /// Bump minor version
    pub fn bump_minor(&self) -> Self {
        Self::new(self.major, self.minor + 1, 0)
    }

    /// Bump patch version
    pub fn bump_patch(&self) -> Self {
        Self::new(self.major, self.minor, self.patch + 1)
    }

    /// Add pre-release tag
    pub fn with_pre_release(mut self, pre: &str) -> Result<Self, VersionError> {
        self.pre_release = Some(PreRelease::parse(pre)?);
        Ok(self)
    }

    /// Add build metadata
    pub fn with_build(mut self, build: &str) -> Self {
        self.build_metadata = Some(build.to_string());
        self
    }

    /// Check if this is a pre-release version
    pub fn is_pre_release(&self) -> bool {
        self.pre_release.is_some()
    }

    /// Check if this is a stable release (>= 1.0.0)
    pub fn is_stable(&self) -> bool {
        self.major >= 1 && !self.is_pre_release()
    }

    /// Check compatibility (same major version for stable, any for 0.x)
    pub fn is_compatible_with(&self, other: &Self) -> bool {
        if self.major == 0 && other.major == 0 {
            self.minor == other.minor
        } else {
            self.major == other.major
        }
    }
}

impl PreRelease {
    pub fn parse(s: &str) -> Result<Self, VersionError> {
        let identifiers = s
            .split('.')
            .map(|part| {
                if let Ok(num) = part.parse::<u64>() {
                    Ok(PreReleaseId::Numeric(num))
                } else if part.chars().all(|c| c.is_alphanumeric() || c == '-') {
                    Ok(PreReleaseId::AlphaNumeric(part.to_string()))
                } else {
                    Err(VersionError::InvalidPreRelease(part.to_string()))
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self { identifiers })
    }
}

impl Ord for SemanticVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare major.minor.patch
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

impl PartialOrd for SemanticVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PreRelease {
    fn cmp(&self, other: &Self) -> Ordering {
        for (a, b) in self.identifiers.iter().zip(other.identifiers.iter()) {
            match a.cmp(b) {
                Ordering::Equal => continue,
                ord => return ord,
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

impl Ord for PreReleaseId {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (PreReleaseId::Numeric(a), PreReleaseId::Numeric(b)) => a.cmp(b),
            (PreReleaseId::Numeric(_), PreReleaseId::AlphaNumeric(_)) => Ordering::Less,
            (PreReleaseId::AlphaNumeric(_), PreReleaseId::Numeric(_)) => Ordering::Greater,
            (PreReleaseId::AlphaNumeric(a), PreReleaseId::AlphaNumeric(b)) => a.cmp(b),
        }
    }
}

impl PartialOrd for PreReleaseId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for SemanticVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if let Some(ref pre) = self.pre_release {
            write!(f, "-{}", pre)?;
        }
        if let Some(ref build) = self.build_metadata {
            write!(f, "+{}", build)?;
        }
        Ok(())
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

#[derive(Debug)]
pub enum VersionError {
    InvalidFormat(String),
    InvalidNumber(String),
    InvalidPreRelease(String),
}

impl fmt::Display for VersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat(s) => write!(f, "Invalid version format: {}", s),
            Self::InvalidNumber(s) => write!(f, "Invalid version number: {}", s),
            Self::InvalidPreRelease(s) => write!(f, "Invalid pre-release identifier: {}", s),
        }
    }
}

// ============================================================================
// Changelog
// ============================================================================

/// Changelog entry type
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ChangeType {
    Added,
    Changed,
    Deprecated,
    Removed,
    Fixed,
    Security,
}

impl ChangeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Added => "Added",
            Self::Changed => "Changed",
            Self::Deprecated => "Deprecated",
            Self::Removed => "Removed",
            Self::Fixed => "Fixed",
            Self::Security => "Security",
        }
    }

    /// Determine version bump type
    pub fn bump_type(&self) -> BumpType {
        match self {
            Self::Security | Self::Fixed => BumpType::Patch,
            Self::Added | Self::Changed | Self::Deprecated => BumpType::Minor,
            Self::Removed => BumpType::Major,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BumpType {
    Patch,
    Minor,
    Major,
}

/// A single changelog entry
#[derive(Debug, Clone)]
pub struct ChangelogEntry {
    pub change_type: ChangeType,
    pub description: String,
    pub issue: Option<String>,
    pub author: Option<String>,
    pub breaking: bool,
}

impl ChangelogEntry {
    pub fn new(change_type: ChangeType, description: &str) -> Self {
        Self {
            change_type,
            description: description.to_string(),
            issue: None,
            author: None,
            breaking: false,
        }
    }

    pub fn with_issue(mut self, issue: &str) -> Self {
        self.issue = Some(issue.to_string());
        self
    }

    pub fn with_author(mut self, author: &str) -> Self {
        self.author = Some(author.to_string());
        self
    }

    pub fn breaking(mut self) -> Self {
        self.breaking = true;
        self
    }

    pub fn to_markdown(&self) -> String {
        let mut line = format!("- {}", self.description);
        if self.breaking {
            line = format!("- **BREAKING:** {}", self.description);
        }
        if let Some(ref issue) = self.issue {
            line.push_str(&format!(" ({})", issue));
        }
        if let Some(ref author) = self.author {
            line.push_str(&format!(" - @{}", author));
        }
        line
    }
}

/// A release in the changelog
#[derive(Debug, Clone)]
pub struct Release {
    pub version: SemanticVersion,
    pub date: String,
    pub entries: Vec<ChangelogEntry>,
    pub yanked: bool,
}

impl Release {
    pub fn new(version: SemanticVersion, date: &str) -> Self {
        Self {
            version,
            date: date.to_string(),
            entries: Vec::new(),
            yanked: false,
        }
    }

    pub fn add_entry(&mut self, entry: ChangelogEntry) {
        self.entries.push(entry);
    }

    pub fn has_breaking_changes(&self) -> bool {
        self.entries
            .iter()
            .any(|e| e.breaking || e.change_type == ChangeType::Removed)
    }

    pub fn to_markdown(&self) -> String {
        let mut md = String::new();

        // Header
        let yanked = if self.yanked { " [YANKED]" } else { "" };
        md.push_str(&format!(
            "## [{}] - {}{}\n\n",
            self.version, self.date, yanked
        ));

        // Group entries by type
        let types = [
            ChangeType::Security,
            ChangeType::Added,
            ChangeType::Changed,
            ChangeType::Deprecated,
            ChangeType::Removed,
            ChangeType::Fixed,
        ];

        for change_type in types {
            let entries: Vec<_> = self
                .entries
                .iter()
                .filter(|e| e.change_type == change_type)
                .collect();

            if !entries.is_empty() {
                md.push_str(&format!("### {}\n\n", change_type.as_str()));
                for entry in entries {
                    md.push_str(&entry.to_markdown());
                    md.push('\n');
                }
                md.push('\n');
            }
        }

        md
    }
}

/// Complete changelog
#[derive(Debug, Clone)]
pub struct Changelog {
    pub title: String,
    pub description: Option<String>,
    pub releases: Vec<Release>,
    pub unreleased: Vec<ChangelogEntry>,
}

impl Changelog {
    pub fn new(title: &str) -> Self {
        Self {
            title: title.to_string(),
            description: None,
            releases: Vec::new(),
            unreleased: Vec::new(),
        }
    }

    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = Some(desc.to_string());
        self
    }

    pub fn add_unreleased(&mut self, entry: ChangelogEntry) {
        self.unreleased.push(entry);
    }

    pub fn create_release(&mut self, version: SemanticVersion, date: &str) {
        let mut release = Release::new(version, date);
        release.entries = std::mem::take(&mut self.unreleased);
        self.releases.insert(0, release);
    }

    pub fn latest_version(&self) -> Option<&SemanticVersion> {
        self.releases.first().map(|r| &r.version)
    }

    pub fn suggest_next_version(&self) -> SemanticVersion {
        let current = self
            .latest_version()
            .cloned()
            .unwrap_or_else(|| SemanticVersion::new(0, 1, 0));

        // Determine bump type from unreleased changes
        let bump = self
            .unreleased
            .iter()
            .map(|e| {
                if e.breaking {
                    BumpType::Major
                } else {
                    e.change_type.bump_type()
                }
            })
            .max()
            .unwrap_or(BumpType::Patch);

        match bump {
            BumpType::Major => current.bump_major(),
            BumpType::Minor => current.bump_minor(),
            BumpType::Patch => current.bump_patch(),
        }
    }

    pub fn to_markdown(&self) -> String {
        let mut md = String::new();

        // Header
        md.push_str(&format!("# {}\n\n", self.title));

        // Description
        if let Some(ref desc) = self.description {
            md.push_str(desc);
            md.push_str("\n\n");
        }

        // Standard link
        md.push_str("All notable changes to this project will be documented in this file.\n\n");
        md.push_str(
            "The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),\n",
        );
        md.push_str("and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).\n\n");

        // Unreleased
        if !self.unreleased.is_empty() {
            md.push_str("## [Unreleased]\n\n");

            let types = [
                ChangeType::Security,
                ChangeType::Added,
                ChangeType::Changed,
                ChangeType::Deprecated,
                ChangeType::Removed,
                ChangeType::Fixed,
            ];

            for change_type in types {
                let entries: Vec<_> = self
                    .unreleased
                    .iter()
                    .filter(|e| e.change_type == change_type)
                    .collect();

                if !entries.is_empty() {
                    md.push_str(&format!("### {}\n\n", change_type.as_str()));
                    for entry in entries {
                        md.push_str(&entry.to_markdown());
                        md.push('\n');
                    }
                    md.push('\n');
                }
            }
        }

        // Releases
        for release in &self.releases {
            md.push_str(&release.to_markdown());
        }

        md
    }
}

// ============================================================================
// Version History
// ============================================================================

/// Version history entry with detailed metadata
#[derive(Debug, Clone)]
pub struct VersionHistoryEntry {
    pub version: SemanticVersion,
    pub date: String,
    pub author: String,
    pub summary: String,
    pub migration_notes: Option<String>,
    pub breaking_changes: Vec<String>,
    pub highlights: Vec<String>,
}

/// VERSION-HISTORY.md generator
pub struct VersionHistory {
    pub project_name: String,
    pub entries: Vec<VersionHistoryEntry>,
}

impl VersionHistory {
    pub fn new(project_name: &str) -> Self {
        Self {
            project_name: project_name.to_string(),
            entries: Vec::new(),
        }
    }

    pub fn add_entry(&mut self, entry: VersionHistoryEntry) {
        self.entries.insert(0, entry);
    }

    pub fn to_markdown(&self) -> String {
        let mut md = String::new();

        md.push_str(&format!("# {} Version History\n\n", self.project_name));
        md.push_str("This document provides detailed version history including migration notes and breaking changes.\n\n");

        for entry in &self.entries {
            md.push_str(&format!(
                "## Version {} ({})\n\n",
                entry.version, entry.date
            ));
            md.push_str(&format!("**Released by:** {}\n\n", entry.author));
            md.push_str(&format!("{}\n\n", entry.summary));

            if !entry.highlights.is_empty() {
                md.push_str("### Highlights\n\n");
                for highlight in &entry.highlights {
                    md.push_str(&format!("- {}\n", highlight));
                }
                md.push('\n');
            }

            if !entry.breaking_changes.is_empty() {
                md.push_str("### Breaking Changes\n\n");
                for change in &entry.breaking_changes {
                    md.push_str(&format!("- ⚠️ {}\n", change));
                }
                md.push('\n');
            }

            if let Some(ref notes) = entry.migration_notes {
                md.push_str("### Migration Guide\n\n");
                md.push_str(notes);
                md.push_str("\n\n");
            }

            md.push_str("---\n\n");
        }

        md
    }
}

// ============================================================================
// Main and Tests
// ============================================================================

fn main() {
    println!("Semantic Versioning Management Example\n");

    // Parse and compare versions
    println!("=== Version Parsing ===\n");

    let versions = [
        "1.0.0",
        "2.1.3",
        "1.0.0-alpha",
        "1.0.0-alpha.1",
        "1.0.0-beta.2",
        "1.0.0-rc.1",
        "0.9.0",
        "v1.2.3+build.123",
    ];

    for v in versions {
        match SemanticVersion::parse(v) {
            Ok(ver) => {
                println!(
                    "  {} -> {} (stable: {}, pre-release: {})",
                    v,
                    ver,
                    ver.is_stable(),
                    ver.is_pre_release()
                );
            }
            Err(e) => {
                println!("  {} -> Error: {}", v, e);
            }
        }
    }

    // Version comparison
    println!("\n=== Version Comparison ===\n");

    let v1 = SemanticVersion::parse("1.0.0").unwrap();
    let v2 = SemanticVersion::parse("1.0.0-alpha").unwrap();
    let v3 = SemanticVersion::parse("1.0.1").unwrap();

    println!("  {} > {} = {}", v1, v2, v1 > v2);
    println!("  {} < {} = {}", v1, v3, v1 < v3);
    println!(
        "  {} compatible with {} = {}",
        v1,
        v3,
        v1.is_compatible_with(&v3)
    );

    // Version bumping
    println!("\n=== Version Bumping ===\n");

    let current = SemanticVersion::parse("1.2.3").unwrap();
    println!("  Current: {}", current);
    println!("  Bump patch: {}", current.bump_patch());
    println!("  Bump minor: {}", current.bump_minor());
    println!("  Bump major: {}", current.bump_major());
    println!(
        "  With pre-release: {}",
        current.bump_minor().with_pre_release("beta.1").unwrap()
    );

    // Changelog generation
    println!("\n=== Changelog Generation ===\n");

    let mut changelog = Changelog::new("Changelog")
        .with_description("All notable changes to the Syntek Rust Security project.");

    // Add a release
    let mut release1 = Release::new(SemanticVersion::parse("1.0.0").unwrap(), "2024-01-15");
    release1.add_entry(ChangelogEntry::new(ChangeType::Added, "Initial release"));
    release1.add_entry(ChangelogEntry::new(
        ChangeType::Added,
        "Threat modelling support",
    ));
    release1.add_entry(
        ChangelogEntry::new(ChangeType::Security, "Fixed CVE-2024-0001").with_issue("#123"),
    );
    changelog.releases.push(release1);

    // Add unreleased changes
    changelog.add_unreleased(ChangelogEntry::new(ChangeType::Added, "AI Gateway support"));
    changelog.add_unreleased(ChangelogEntry::new(
        ChangeType::Fixed,
        "Memory leak in scanner",
    ));
    changelog.add_unreleased(
        ChangelogEntry::new(ChangeType::Removed, "Deprecated crypto API").breaking(),
    );

    println!("{}", changelog.to_markdown());

    // Suggest next version
    println!("=== Suggested Next Version ===\n");
    println!(
        "  Based on unreleased changes: {}",
        changelog.suggest_next_version()
    );

    // Version history
    println!("\n=== Version History ===\n");

    let mut history = VersionHistory::new("syntek-rust-security");

    history.add_entry(VersionHistoryEntry {
        version: SemanticVersion::parse("1.0.0").unwrap(),
        date: "2024-01-15".to_string(),
        author: "Security Team".to_string(),
        summary: "First stable release with comprehensive security analysis tools.".to_string(),
        migration_notes: Some("No migration required - initial release.".to_string()),
        breaking_changes: vec![],
        highlights: vec![
            "STRIDE threat modelling".to_string(),
            "Vulnerability scanning".to_string(),
            "Cryptographic review".to_string(),
        ],
    });

    println!("{}", history.to_markdown());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_parse() {
        let v = SemanticVersion::parse("1.2.3").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 3);
    }

    #[test]
    fn test_version_parse_with_v() {
        let v = SemanticVersion::parse("v1.2.3").unwrap();
        assert_eq!(v.major, 1);
    }

    #[test]
    fn test_version_parse_pre_release() {
        let v = SemanticVersion::parse("1.0.0-alpha.1").unwrap();
        assert!(v.is_pre_release());
        assert!(!v.is_stable());
    }

    #[test]
    fn test_version_parse_build() {
        let v = SemanticVersion::parse("1.0.0+build.123").unwrap();
        assert_eq!(v.build_metadata, Some("build.123".to_string()));
    }

    #[test]
    fn test_version_comparison() {
        let v1 = SemanticVersion::parse("1.0.0").unwrap();
        let v2 = SemanticVersion::parse("2.0.0").unwrap();
        assert!(v1 < v2);
    }

    #[test]
    fn test_pre_release_lower() {
        let stable = SemanticVersion::parse("1.0.0").unwrap();
        let pre = SemanticVersion::parse("1.0.0-alpha").unwrap();
        assert!(pre < stable);
    }

    #[test]
    fn test_bump_major() {
        let v = SemanticVersion::new(1, 2, 3);
        let bumped = v.bump_major();
        assert_eq!(bumped, SemanticVersion::new(2, 0, 0));
    }

    #[test]
    fn test_bump_minor() {
        let v = SemanticVersion::new(1, 2, 3);
        let bumped = v.bump_minor();
        assert_eq!(bumped, SemanticVersion::new(1, 3, 0));
    }

    #[test]
    fn test_bump_patch() {
        let v = SemanticVersion::new(1, 2, 3);
        let bumped = v.bump_patch();
        assert_eq!(bumped, SemanticVersion::new(1, 2, 4));
    }

    #[test]
    fn test_version_display() {
        let v = SemanticVersion::parse("1.2.3-beta.1+build.456").unwrap();
        assert_eq!(v.to_string(), "1.2.3-beta.1+build.456");
    }

    #[test]
    fn test_is_stable() {
        assert!(SemanticVersion::new(1, 0, 0).is_stable());
        assert!(!SemanticVersion::new(0, 1, 0).is_stable());
        assert!(!SemanticVersion::parse("1.0.0-alpha").unwrap().is_stable());
    }

    #[test]
    fn test_compatibility() {
        let v1 = SemanticVersion::new(1, 0, 0);
        let v2 = SemanticVersion::new(1, 5, 0);
        let v3 = SemanticVersion::new(2, 0, 0);

        assert!(v1.is_compatible_with(&v2));
        assert!(!v1.is_compatible_with(&v3));
    }

    #[test]
    fn test_changelog_entry() {
        let entry = ChangelogEntry::new(ChangeType::Added, "New feature")
            .with_issue("#123")
            .with_author("dev");

        let md = entry.to_markdown();
        assert!(md.contains("New feature"));
        assert!(md.contains("#123"));
        assert!(md.contains("@dev"));
    }

    #[test]
    fn test_changelog_suggest_version() {
        let mut changelog = Changelog::new("Test");
        changelog
            .releases
            .push(Release::new(SemanticVersion::new(1, 0, 0), "2024-01-01"));

        changelog.add_unreleased(ChangelogEntry::new(ChangeType::Fixed, "Bug fix"));
        assert_eq!(
            changelog.suggest_next_version(),
            SemanticVersion::new(1, 0, 1)
        );

        changelog.add_unreleased(ChangelogEntry::new(ChangeType::Added, "Feature"));
        assert_eq!(
            changelog.suggest_next_version(),
            SemanticVersion::new(1, 1, 0)
        );

        changelog.add_unreleased(ChangelogEntry::new(ChangeType::Removed, "API").breaking());
        assert_eq!(
            changelog.suggest_next_version(),
            SemanticVersion::new(2, 0, 0)
        );
    }

    #[test]
    fn test_change_type_bump() {
        assert_eq!(ChangeType::Fixed.bump_type(), BumpType::Patch);
        assert_eq!(ChangeType::Added.bump_type(), BumpType::Minor);
        assert_eq!(ChangeType::Removed.bump_type(), BumpType::Major);
    }
}
