//! Semantic Versioning and Changelog Management
//!
//! Automated version bumping, changelog generation, and release management
//! following Semantic Versioning 2.0.0 specification.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Semantic version following semver 2.0.0
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub prerelease: Option<String>,
    pub build_metadata: Option<String>,
}

impl SemanticVersion {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
            prerelease: None,
            build_metadata: None,
        }
    }

    pub fn with_prerelease(mut self, prerelease: &str) -> Self {
        self.prerelease = Some(prerelease.into());
        self
    }

    pub fn with_build(mut self, build: &str) -> Self {
        self.build_metadata = Some(build.into());
        self
    }

    /// Bump major version (breaking changes)
    pub fn bump_major(&self) -> Self {
        Self {
            major: self.major + 1,
            minor: 0,
            patch: 0,
            prerelease: None,
            build_metadata: None,
        }
    }

    /// Bump minor version (new features, backward compatible)
    pub fn bump_minor(&self) -> Self {
        Self {
            major: self.major,
            minor: self.minor + 1,
            patch: 0,
            prerelease: None,
            build_metadata: None,
        }
    }

    /// Bump patch version (bug fixes)
    pub fn bump_patch(&self) -> Self {
        Self {
            major: self.major,
            minor: self.minor,
            patch: self.patch + 1,
            prerelease: None,
            build_metadata: None,
        }
    }

    /// Check if this is a prerelease version
    pub fn is_prerelease(&self) -> bool {
        self.prerelease.is_some()
    }

    /// Check if this is the initial development version (0.x.x)
    pub fn is_initial_development(&self) -> bool {
        self.major == 0
    }

    /// Parse from Cargo.toml version string
    pub fn from_cargo_version(version: &str) -> Option<Self> {
        Self::from_str(version).ok()
    }
}

impl fmt::Display for SemanticVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;

        if let Some(pre) = &self.prerelease {
            write!(f, "-{}", pre)?;
        }

        if let Some(build) = &self.build_metadata {
            write!(f, "+{}", build)?;
        }

        Ok(())
    }
}

impl FromStr for SemanticVersion {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim().trim_start_matches('v').trim_start_matches('V');

        // Split off build metadata
        let (version_pre, build) = if let Some(pos) = s.find('+') {
            (&s[..pos], Some(s[pos + 1..].to_string()))
        } else {
            (s, None)
        };

        // Split off prerelease
        let (version, prerelease) = if let Some(pos) = version_pre.find('-') {
            (
                &version_pre[..pos],
                Some(version_pre[pos + 1..].to_string()),
            )
        } else {
            (version_pre, None)
        };

        // Parse major.minor.patch
        let parts: Vec<&str> = version.split('.').collect();
        if parts.len() < 2 || parts.len() > 3 {
            return Err(format!("Invalid version format: {}", s));
        }

        let major = parts[0]
            .parse()
            .map_err(|_| format!("Invalid major version: {}", parts[0]))?;
        let minor = parts[1]
            .parse()
            .map_err(|_| format!("Invalid minor version: {}", parts[1]))?;
        let patch = if parts.len() == 3 {
            parts[2]
                .parse()
                .map_err(|_| format!("Invalid patch version: {}", parts[2]))?
        } else {
            0
        };

        Ok(Self {
            major,
            minor,
            patch,
            prerelease,
            build_metadata: build,
        })
    }
}

impl PartialOrd for SemanticVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SemanticVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare major.minor.patch first
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

        // Prerelease versions have lower precedence
        match (&self.prerelease, &other.prerelease) {
            (None, None) => Ordering::Equal,
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (Some(a), Some(b)) => a.cmp(b),
        }
    }
}

/// Types of changes for changelog
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
            ChangeType::Added => "Added",
            ChangeType::Changed => "Changed",
            ChangeType::Deprecated => "Deprecated",
            ChangeType::Removed => "Removed",
            ChangeType::Fixed => "Fixed",
            ChangeType::Security => "Security",
        }
    }

    /// Determine version bump type based on change type
    pub fn suggested_bump(&self) -> BumpType {
        match self {
            ChangeType::Removed | ChangeType::Changed => BumpType::Major,
            ChangeType::Added | ChangeType::Deprecated => BumpType::Minor,
            ChangeType::Fixed | ChangeType::Security => BumpType::Patch,
        }
    }
}

impl FromStr for ChangeType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "added" | "add" | "feat" | "feature" => Ok(ChangeType::Added),
            "changed" | "change" => Ok(ChangeType::Changed),
            "deprecated" | "deprecate" => Ok(ChangeType::Deprecated),
            "removed" | "remove" => Ok(ChangeType::Removed),
            "fixed" | "fix" | "bugfix" => Ok(ChangeType::Fixed),
            "security" | "sec" => Ok(ChangeType::Security),
            _ => Err(format!("Unknown change type: {}", s)),
        }
    }
}

/// Version bump type
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
    pub issue_refs: Vec<String>,
    pub breaking: bool,
}

impl ChangelogEntry {
    pub fn new(change_type: ChangeType, description: &str) -> Self {
        Self {
            change_type,
            description: description.into(),
            issue_refs: vec![],
            breaking: false,
        }
    }

    pub fn with_issue(mut self, issue: &str) -> Self {
        self.issue_refs.push(issue.into());
        self
    }

    pub fn breaking(mut self) -> Self {
        self.breaking = true;
        self
    }

    pub fn to_markdown(&self) -> String {
        let mut line = format!("- {}", self.description);

        if !self.issue_refs.is_empty() {
            line.push_str(&format!(" ({})", self.issue_refs.join(", ")));
        }

        if self.breaking {
            line.push_str(" **BREAKING**");
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
            date: date.into(),
            entries: vec![],
            yanked: false,
        }
    }

    pub fn unreleased() -> Self {
        Self {
            version: SemanticVersion::new(0, 0, 0),
            date: "Unreleased".into(),
            entries: vec![],
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

    pub fn suggested_bump(&self, current: &SemanticVersion) -> BumpType {
        let mut max_bump = BumpType::Patch;

        for entry in &self.entries {
            let bump = if entry.breaking {
                BumpType::Major
            } else {
                entry.change_type.suggested_bump()
            };

            if bump > max_bump {
                max_bump = bump;
            }
        }

        // In initial development (0.x.x), breaking changes bump minor
        if current.is_initial_development() && max_bump == BumpType::Major {
            max_bump = BumpType::Minor;
        }

        max_bump
    }

    pub fn to_markdown(&self) -> String {
        let mut md = String::new();

        // Version header
        if self.date == "Unreleased" {
            md.push_str("## [Unreleased]\n\n");
        } else {
            let yanked = if self.yanked { " [YANKED]" } else { "" };
            md.push_str(&format!(
                "## [{}] - {}{}\n\n",
                self.version, self.date, yanked
            ));
        }

        // Group entries by type
        let mut by_type: HashMap<ChangeType, Vec<&ChangelogEntry>> = HashMap::new();
        for entry in &self.entries {
            by_type.entry(entry.change_type).or_default().push(entry);
        }

        // Output in standard order
        let order = [
            ChangeType::Added,
            ChangeType::Changed,
            ChangeType::Deprecated,
            ChangeType::Removed,
            ChangeType::Fixed,
            ChangeType::Security,
        ];

        for change_type in &order {
            if let Some(entries) = by_type.get(change_type) {
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
    pub description: String,
    pub releases: Vec<Release>,
    pub repository_url: Option<String>,
}

impl Changelog {
    pub fn new() -> Self {
        Self {
            title: "Changelog".into(),
            description: "All notable changes to this project will be documented in this file.\n\nThe format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),\nand this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).".into(),
            releases: vec![],
            repository_url: None,
        }
    }

    pub fn with_repo_url(mut self, url: &str) -> Self {
        self.repository_url = Some(url.into());
        self
    }

    pub fn add_release(&mut self, release: Release) {
        // Insert maintaining reverse chronological order
        if release.date == "Unreleased" {
            self.releases.insert(0, release);
        } else {
            let pos = self
                .releases
                .iter()
                .position(|r| r.date != "Unreleased" && r.version < release.version)
                .unwrap_or(self.releases.len());
            self.releases.insert(pos, release);
        }
    }

    pub fn latest_release(&self) -> Option<&Release> {
        self.releases.iter().find(|r| r.date != "Unreleased")
    }

    pub fn unreleased(&self) -> Option<&Release> {
        self.releases.iter().find(|r| r.date == "Unreleased")
    }

    pub fn unreleased_mut(&mut self) -> Option<&mut Release> {
        self.releases.iter_mut().find(|r| r.date == "Unreleased")
    }

    pub fn to_markdown(&self) -> String {
        let mut md = String::new();

        // Header
        md.push_str(&format!("# {}\n\n", self.title));
        md.push_str(&self.description);
        md.push_str("\n\n");

        // Releases
        for release in &self.releases {
            md.push_str(&release.to_markdown());
        }

        // Version links
        if let Some(repo_url) = &self.repository_url {
            md.push_str("\n");

            let mut prev_version: Option<&SemanticVersion> = None;

            for release in self.releases.iter().rev() {
                if release.date == "Unreleased" {
                    if let Some(latest) = self.latest_release() {
                        md.push_str(&format!(
                            "[Unreleased]: {}/compare/v{}...HEAD\n",
                            repo_url, latest.version
                        ));
                    }
                } else if let Some(prev) = prev_version {
                    md.push_str(&format!(
                        "[{}]: {}/compare/v{}...v{}\n",
                        release.version, repo_url, prev, release.version
                    ));
                } else {
                    md.push_str(&format!(
                        "[{}]: {}/releases/tag/v{}\n",
                        release.version, repo_url, release.version
                    ));
                }
                prev_version = Some(&release.version);
            }
        }

        md
    }

    /// Parse from existing CHANGELOG.md
    pub fn from_markdown(_content: &str) -> Result<Self, String> {
        // Simplified parser - real implementation would be more robust
        Ok(Self::new())
    }

    /// Write to file
    pub fn write_to_file<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        let md = self.to_markdown();
        fs::write(path, md)?;
        Ok(())
    }
}

/// Version manager for project files
#[derive(Debug)]
pub struct VersionManager {
    pub project_root: PathBuf,
    pub current_version: SemanticVersion,
    pub changelog: Changelog,
}

impl VersionManager {
    pub fn new<P: AsRef<Path>>(project_root: P) -> Result<Self, String> {
        let project_root = project_root.as_ref().to_path_buf();

        // Try to read version from Cargo.toml
        let cargo_toml_path = project_root.join("Cargo.toml");
        let current_version = if cargo_toml_path.exists() {
            Self::read_cargo_version(&cargo_toml_path)?
        } else {
            SemanticVersion::new(0, 1, 0)
        };

        // Try to read existing changelog
        let changelog_path = project_root.join("CHANGELOG.md");
        let changelog = if changelog_path.exists() {
            let content = fs::read_to_string(&changelog_path)
                .map_err(|e| format!("Failed to read CHANGELOG.md: {}", e))?;
            Changelog::from_markdown(&content)?
        } else {
            Changelog::new()
        };

        Ok(Self {
            project_root,
            current_version,
            changelog,
        })
    }

    fn read_cargo_version(path: &Path) -> Result<SemanticVersion, String> {
        let content =
            fs::read_to_string(path).map_err(|e| format!("Failed to read Cargo.toml: {}", e))?;

        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("version") {
                if let Some(version_str) = line.split('=').nth(1) {
                    let version_str = version_str.trim().trim_matches('"');
                    return SemanticVersion::from_str(version_str);
                }
            }
        }

        Err("No version found in Cargo.toml".into())
    }

    /// Bump version based on change type
    pub fn bump(&mut self, bump_type: BumpType) -> SemanticVersion {
        let new_version = match bump_type {
            BumpType::Major => self.current_version.bump_major(),
            BumpType::Minor => self.current_version.bump_minor(),
            BumpType::Patch => self.current_version.bump_patch(),
        };

        self.current_version = new_version.clone();
        new_version
    }

    /// Auto-bump based on unreleased changes
    pub fn auto_bump(&mut self) -> Option<SemanticVersion> {
        if let Some(unreleased) = self.changelog.unreleased() {
            if unreleased.entries.is_empty() {
                return None;
            }

            let bump_type = unreleased.suggested_bump(&self.current_version);
            Some(self.bump(bump_type))
        } else {
            None
        }
    }

    /// Add a changelog entry
    pub fn add_change(&mut self, entry: ChangelogEntry) {
        if self.changelog.unreleased().is_none() {
            self.changelog.add_release(Release::unreleased());
        }

        if let Some(unreleased) = self.changelog.unreleased_mut() {
            unreleased.add_entry(entry);
        }
    }

    /// Create a new release from unreleased changes
    pub fn create_release(&mut self, date: &str) -> Option<Release> {
        let unreleased = self.changelog.unreleased()?.clone();

        if unreleased.entries.is_empty() {
            return None;
        }

        // Auto-bump version
        let bump_type = unreleased.suggested_bump(&self.current_version);
        let new_version = self.bump(bump_type);

        // Create release
        let mut release = Release::new(new_version, date);
        release.entries = unreleased.entries;

        // Replace unreleased with empty one
        if let Some(ur) = self.changelog.unreleased_mut() {
            ur.entries.clear();
        }

        // Add release
        self.changelog.add_release(release.clone());

        Some(release)
    }

    /// Update version in Cargo.toml
    pub fn update_cargo_toml(&self) -> io::Result<()> {
        let cargo_toml_path = self.project_root.join("Cargo.toml");

        if !cargo_toml_path.exists() {
            return Ok(());
        }

        let content = fs::read_to_string(&cargo_toml_path)?;
        let mut new_content = String::new();
        let mut in_package = false;
        let mut version_updated = false;

        for line in content.lines() {
            let trimmed = line.trim();

            if trimmed == "[package]" {
                in_package = true;
            } else if trimmed.starts_with('[') && trimmed != "[package]" {
                in_package = false;
            }

            if in_package && trimmed.starts_with("version") && !version_updated {
                new_content.push_str(&format!("version = \"{}\"\n", self.current_version));
                version_updated = true;
            } else {
                new_content.push_str(line);
                new_content.push('\n');
            }
        }

        fs::write(&cargo_toml_path, new_content)?;
        Ok(())
    }

    /// Update CHANGELOG.md
    pub fn update_changelog(&self) -> io::Result<()> {
        let changelog_path = self.project_root.join("CHANGELOG.md");
        self.changelog.write_to_file(&changelog_path)
    }

    /// Get a summary of pending changes
    pub fn pending_changes_summary(&self) -> String {
        if let Some(unreleased) = self.changelog.unreleased() {
            if unreleased.entries.is_empty() {
                return "No pending changes".into();
            }

            let bump = unreleased.suggested_bump(&self.current_version);
            let new_version = match bump {
                BumpType::Major => self.current_version.bump_major(),
                BumpType::Minor => self.current_version.bump_minor(),
                BumpType::Patch => self.current_version.bump_patch(),
            };

            format!(
                "{} pending changes -> {} {} ({})",
                unreleased.entries.len(),
                new_version,
                match bump {
                    BumpType::Major => "MAJOR",
                    BumpType::Minor => "MINOR",
                    BumpType::Patch => "PATCH",
                },
                if unreleased.has_breaking_changes() {
                    "BREAKING"
                } else {
                    "compatible"
                }
            )
        } else {
            "No pending changes".into()
        }
    }
}

/// Parse conventional commit message
pub fn parse_conventional_commit(message: &str) -> Option<ChangelogEntry> {
    let message = message.trim();

    // Format: type(scope): description
    // or: type: description
    let (type_part, description) = if let Some(colon_pos) = message.find(':') {
        (&message[..colon_pos], message[colon_pos + 1..].trim())
    } else {
        return None;
    };

    let change_type = type_part.split('(').next()?;
    let change_type = ChangeType::from_str(change_type).ok()?;

    let breaking = type_part.ends_with('!') || description.to_lowercase().starts_with("breaking");

    let mut entry = ChangelogEntry::new(change_type, description);
    if breaking {
        entry = entry.breaking();
    }

    Some(entry)
}

fn main() {
    println!("Semantic Version Manager\n");

    // Version parsing examples
    println!("=== Version Parsing ===");
    let versions = vec!["1.0.0", "2.3.4-alpha.1", "1.0.0-beta+build.123", "v3.2.1"];

    for v in versions {
        match SemanticVersion::from_str(v) {
            Ok(version) => println!("  {} -> {}", v, version),
            Err(e) => println!("  {} -> Error: {}", v, e),
        }
    }

    // Version comparison
    println!("\n=== Version Comparison ===");
    let v1 = SemanticVersion::new(1, 0, 0);
    let v2 = SemanticVersion::new(1, 0, 1);
    let v3 = SemanticVersion::new(1, 0, 0).with_prerelease("alpha");

    println!("  {} < {} = {}", v1, v2, v1 < v2);
    println!("  {} > {} = {}", v1, v3, v1 > v3); // Release > prerelease

    // Create a changelog
    println!("\n=== Changelog Generation ===");
    let mut changelog = Changelog::new().with_repo_url("https://github.com/example/project");

    // Add unreleased changes
    let mut unreleased = Release::unreleased();
    unreleased.add_entry(
        ChangelogEntry::new(ChangeType::Added, "New authentication system").with_issue("#123"),
    );
    unreleased.add_entry(
        ChangelogEntry::new(ChangeType::Fixed, "Memory leak in connection pool").with_issue("#456"),
    );
    unreleased.add_entry(ChangelogEntry::new(
        ChangeType::Security,
        "Updated dependencies for CVE-2024-1234",
    ));
    changelog.add_release(unreleased);

    // Add a past release
    let mut v1_release = Release::new(SemanticVersion::new(1, 0, 0), "2024-01-15");
    v1_release.add_entry(ChangelogEntry::new(ChangeType::Added, "Initial release"));
    changelog.add_release(v1_release);

    println!("{}", changelog.to_markdown());

    // Conventional commit parsing
    println!("=== Conventional Commits ===");
    let commits = vec![
        "feat: add user authentication",
        "fix(api): resolve null pointer issue",
        "feat!: change API response format",
        "docs: update README",
        "security: patch XSS vulnerability",
    ];

    for commit in commits {
        if let Some(entry) = parse_conventional_commit(commit) {
            println!(
                "  {} -> {:?} (breaking: {})",
                commit, entry.change_type, entry.breaking
            );
        }
    }

    // Version bumping
    println!("\n=== Version Bumping ===");
    let current = SemanticVersion::new(1, 2, 3);
    println!("  Current: {}", current);
    println!("  Patch bump: {}", current.bump_patch());
    println!("  Minor bump: {}", current.bump_minor());
    println!("  Major bump: {}", current.bump_major());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_parsing() {
        let v = SemanticVersion::from_str("1.2.3").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 3);
    }

    #[test]
    fn test_version_with_prerelease() {
        let v = SemanticVersion::from_str("1.0.0-alpha.1").unwrap();
        assert_eq!(v.prerelease, Some("alpha.1".into()));
    }

    #[test]
    fn test_version_with_build() {
        let v = SemanticVersion::from_str("1.0.0+build.123").unwrap();
        assert_eq!(v.build_metadata, Some("build.123".into()));
    }

    #[test]
    fn test_version_with_both() {
        let v = SemanticVersion::from_str("1.0.0-beta+build").unwrap();
        assert_eq!(v.prerelease, Some("beta".into()));
        assert_eq!(v.build_metadata, Some("build".into()));
    }

    #[test]
    fn test_version_display() {
        let v = SemanticVersion::new(1, 2, 3)
            .with_prerelease("alpha")
            .with_build("123");
        assert_eq!(v.to_string(), "1.2.3-alpha+123");
    }

    #[test]
    fn test_version_bump_major() {
        let v = SemanticVersion::new(1, 2, 3);
        let bumped = v.bump_major();
        assert_eq!(bumped.major, 2);
        assert_eq!(bumped.minor, 0);
        assert_eq!(bumped.patch, 0);
    }

    #[test]
    fn test_version_bump_minor() {
        let v = SemanticVersion::new(1, 2, 3);
        let bumped = v.bump_minor();
        assert_eq!(bumped.major, 1);
        assert_eq!(bumped.minor, 3);
        assert_eq!(bumped.patch, 0);
    }

    #[test]
    fn test_version_bump_patch() {
        let v = SemanticVersion::new(1, 2, 3);
        let bumped = v.bump_patch();
        assert_eq!(bumped.major, 1);
        assert_eq!(bumped.minor, 2);
        assert_eq!(bumped.patch, 4);
    }

    #[test]
    fn test_version_comparison() {
        let v1 = SemanticVersion::new(1, 0, 0);
        let v2 = SemanticVersion::new(2, 0, 0);
        let v3 = SemanticVersion::new(1, 1, 0);
        let v4 = SemanticVersion::new(1, 0, 1);

        assert!(v1 < v2);
        assert!(v1 < v3);
        assert!(v1 < v4);
        assert!(v3 < v2);
    }

    #[test]
    fn test_prerelease_comparison() {
        let release = SemanticVersion::new(1, 0, 0);
        let prerelease = SemanticVersion::new(1, 0, 0).with_prerelease("alpha");

        assert!(prerelease < release);
    }

    #[test]
    fn test_change_type_from_str() {
        assert_eq!(ChangeType::from_str("feat").unwrap(), ChangeType::Added);
        assert_eq!(ChangeType::from_str("fix").unwrap(), ChangeType::Fixed);
        assert_eq!(
            ChangeType::from_str("security").unwrap(),
            ChangeType::Security
        );
    }

    #[test]
    fn test_changelog_entry_to_markdown() {
        let entry = ChangelogEntry::new(ChangeType::Added, "New feature")
            .with_issue("#123")
            .breaking();

        let md = entry.to_markdown();
        assert!(md.contains("New feature"));
        assert!(md.contains("#123"));
        assert!(md.contains("BREAKING"));
    }

    #[test]
    fn test_release_suggested_bump() {
        let version = SemanticVersion::new(1, 0, 0);
        let mut release = Release::unreleased();

        release.add_entry(ChangelogEntry::new(ChangeType::Fixed, "Bug fix"));
        assert_eq!(release.suggested_bump(&version), BumpType::Patch);

        release.add_entry(ChangelogEntry::new(ChangeType::Added, "New feature"));
        assert_eq!(release.suggested_bump(&version), BumpType::Minor);

        release.add_entry(ChangelogEntry::new(ChangeType::Changed, "Breaking change").breaking());
        assert_eq!(release.suggested_bump(&version), BumpType::Major);
    }

    #[test]
    fn test_initial_development_bump() {
        let version = SemanticVersion::new(0, 1, 0);
        let mut release = Release::unreleased();
        release.add_entry(ChangelogEntry::new(ChangeType::Changed, "Breaking").breaking());

        // In 0.x.x, breaking changes bump minor, not major
        assert_eq!(release.suggested_bump(&version), BumpType::Minor);
    }

    #[test]
    fn test_parse_conventional_commit() {
        let entry = parse_conventional_commit("feat: add new feature").unwrap();
        assert_eq!(entry.change_type, ChangeType::Added);
        assert!(!entry.breaking);

        let entry = parse_conventional_commit("fix(api): resolve bug").unwrap();
        assert_eq!(entry.change_type, ChangeType::Fixed);

        let entry = parse_conventional_commit("feat!: breaking change").unwrap();
        assert!(entry.breaking);
    }

    #[test]
    fn test_changelog_new() {
        let changelog = Changelog::new();
        assert_eq!(changelog.title, "Changelog");
        assert!(changelog.releases.is_empty());
    }

    #[test]
    fn test_changelog_add_release() {
        let mut changelog = Changelog::new();

        changelog.add_release(Release::unreleased());
        changelog.add_release(Release::new(SemanticVersion::new(1, 0, 0), "2024-01-01"));

        assert_eq!(changelog.releases.len(), 2);
        assert!(changelog.unreleased().is_some());
    }

    #[test]
    fn test_is_prerelease() {
        let release = SemanticVersion::new(1, 0, 0);
        let prerelease = SemanticVersion::new(1, 0, 0).with_prerelease("alpha");

        assert!(!release.is_prerelease());
        assert!(prerelease.is_prerelease());
    }

    #[test]
    fn test_is_initial_development() {
        let v0 = SemanticVersion::new(0, 1, 0);
        let v1 = SemanticVersion::new(1, 0, 0);

        assert!(v0.is_initial_development());
        assert!(!v1.is_initial_development());
    }
}
