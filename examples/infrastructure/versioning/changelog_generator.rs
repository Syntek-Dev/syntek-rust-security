//! Changelog Generator for Rust Projects
//!
//! This example demonstrates automated changelog generation from git commits
//! following Conventional Commits specification, with support for semantic
//! versioning, release notes, and multiple output formats.

use std::collections::HashMap;
use std::fmt;

// ============================================================================
// Conventional Commits Parser
// ============================================================================

/// A conventional commit message
#[derive(Clone, Debug)]
pub struct ConventionalCommit {
    pub hash: String,
    pub commit_type: CommitType,
    pub scope: Option<String>,
    pub description: String,
    pub body: Option<String>,
    pub footers: Vec<Footer>,
    pub breaking: bool,
    pub author: Author,
    pub date: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CommitType {
    Feat,
    Fix,
    Docs,
    Style,
    Refactor,
    Perf,
    Test,
    Build,
    Ci,
    Chore,
    Revert,
    Security,
    Deps,
    Custom(String),
}

impl CommitType {
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "feat" | "feature" => CommitType::Feat,
            "fix" | "bugfix" => CommitType::Fix,
            "docs" | "documentation" => CommitType::Docs,
            "style" => CommitType::Style,
            "refactor" => CommitType::Refactor,
            "perf" | "performance" => CommitType::Perf,
            "test" | "tests" => CommitType::Test,
            "build" => CommitType::Build,
            "ci" => CommitType::Ci,
            "chore" => CommitType::Chore,
            "revert" => CommitType::Revert,
            "security" | "sec" => CommitType::Security,
            "deps" | "dependencies" => CommitType::Deps,
            other => CommitType::Custom(other.to_string()),
        }
    }

    pub fn section_title(&self) -> &str {
        match self {
            CommitType::Feat => "Features",
            CommitType::Fix => "Bug Fixes",
            CommitType::Docs => "Documentation",
            CommitType::Style => "Styles",
            CommitType::Refactor => "Code Refactoring",
            CommitType::Perf => "Performance Improvements",
            CommitType::Test => "Tests",
            CommitType::Build => "Build System",
            CommitType::Ci => "Continuous Integration",
            CommitType::Chore => "Chores",
            CommitType::Revert => "Reverts",
            CommitType::Security => "Security",
            CommitType::Deps => "Dependencies",
            CommitType::Custom(s) => s.as_str(),
        }
    }

    pub fn emoji(&self) -> &str {
        match self {
            CommitType::Feat => "✨",
            CommitType::Fix => "🐛",
            CommitType::Docs => "📚",
            CommitType::Style => "💄",
            CommitType::Refactor => "♻️",
            CommitType::Perf => "⚡",
            CommitType::Test => "✅",
            CommitType::Build => "📦",
            CommitType::Ci => "👷",
            CommitType::Chore => "🔧",
            CommitType::Revert => "⏪",
            CommitType::Security => "🔒",
            CommitType::Deps => "📌",
            CommitType::Custom(_) => "📝",
        }
    }

    pub fn priority(&self) -> u32 {
        match self {
            CommitType::Security => 0,
            CommitType::Feat => 1,
            CommitType::Fix => 2,
            CommitType::Perf => 3,
            CommitType::Refactor => 4,
            CommitType::Deps => 5,
            CommitType::Docs => 6,
            CommitType::Test => 7,
            CommitType::Build => 8,
            CommitType::Ci => 9,
            CommitType::Style => 10,
            CommitType::Chore => 11,
            CommitType::Revert => 12,
            CommitType::Custom(_) => 13,
        }
    }

    pub fn bump_type(&self) -> VersionBump {
        match self {
            CommitType::Feat => VersionBump::Minor,
            CommitType::Fix | CommitType::Security | CommitType::Perf => VersionBump::Patch,
            _ => VersionBump::None,
        }
    }
}

impl fmt::Display for CommitType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommitType::Custom(s) => write!(f, "{}", s),
            _ => write!(f, "{}", format!("{:?}", self).to_lowercase()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Footer {
    pub key: String,
    pub value: String,
}

#[derive(Clone, Debug)]
pub struct Author {
    pub name: String,
    pub email: String,
}

/// Parser for conventional commit messages
pub struct CommitParser;

impl CommitParser {
    pub fn parse(
        raw: &str,
        hash: &str,
        author_name: &str,
        author_email: &str,
        date: &str,
    ) -> Option<ConventionalCommit> {
        let lines: Vec<&str> = raw.lines().collect();
        if lines.is_empty() {
            return None;
        }

        let first_line = lines[0];

        // Parse type, scope, and description
        // Format: type(scope)!: description
        let (commit_type, scope, description, breaking_indicator) = Self::parse_header(first_line)?;

        // Parse body and footers
        let mut body_lines = Vec::new();
        let mut footers = Vec::new();
        let mut in_body = true;

        for line in lines.iter().skip(1) {
            if line.is_empty() {
                if in_body && !body_lines.is_empty() {
                    body_lines.push("");
                }
                continue;
            }

            // Check if it's a footer
            if let Some(footer) = Self::parse_footer(line) {
                in_body = false;
                footers.push(footer);
            } else if in_body {
                body_lines.push(*line);
            }
        }

        let body = if body_lines.is_empty() {
            None
        } else {
            Some(body_lines.join("\n").trim().to_string())
        };

        // Check for breaking change
        let breaking = breaking_indicator
            || footers.iter().any(|f| {
                f.key.to_uppercase() == "BREAKING CHANGE"
                    || f.key.to_uppercase() == "BREAKING-CHANGE"
            });

        Some(ConventionalCommit {
            hash: hash.to_string(),
            commit_type,
            scope,
            description,
            body,
            footers,
            breaking,
            author: Author {
                name: author_name.to_string(),
                email: author_email.to_string(),
            },
            date: date.to_string(),
        })
    }

    fn parse_header(line: &str) -> Option<(CommitType, Option<String>, String, bool)> {
        // Match: type(scope)!: description
        let mut chars = line.chars().peekable();
        let mut type_str = String::new();

        // Parse type
        while let Some(&c) = chars.peek() {
            if c == '(' || c == '!' || c == ':' {
                break;
            }
            type_str.push(chars.next()?);
        }

        if type_str.is_empty() {
            return None;
        }

        let commit_type = CommitType::parse(&type_str);

        // Parse optional scope
        let scope = if chars.peek() == Some(&'(') {
            chars.next(); // consume '('
            let mut scope_str = String::new();
            while let Some(&c) = chars.peek() {
                if c == ')' {
                    chars.next(); // consume ')'
                    break;
                }
                scope_str.push(chars.next()?);
            }
            if scope_str.is_empty() {
                None
            } else {
                Some(scope_str)
            }
        } else {
            None
        };

        // Check for breaking change indicator
        let breaking = if chars.peek() == Some(&'!') {
            chars.next(); // consume '!'
            true
        } else {
            false
        };

        // Expect colon and space
        if chars.next() != Some(':') {
            return None;
        }

        // Skip optional space
        if chars.peek() == Some(&' ') {
            chars.next();
        }

        // Rest is description
        let description: String = chars.collect();
        if description.is_empty() {
            return None;
        }

        Some((commit_type, scope, description, breaking))
    }

    fn parse_footer(line: &str) -> Option<Footer> {
        // Format: Key: Value or Key #Value
        if let Some(colon_pos) = line.find(':') {
            let key = line[..colon_pos].trim();
            let value = line[colon_pos + 1..].trim();

            if !key.is_empty() && !key.contains(' ') {
                return Some(Footer {
                    key: key.to_string(),
                    value: value.to_string(),
                });
            }
        }

        if let Some(hash_pos) = line.find(" #") {
            let key = line[..hash_pos].trim();
            let value = line[hash_pos + 2..].trim();

            if !key.is_empty() && !key.contains(' ') {
                return Some(Footer {
                    key: key.to_string(),
                    value: format!("#{}", value),
                });
            }
        }

        None
    }
}

// ============================================================================
// Version Management
// ============================================================================

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
        let s = s.trim_start_matches('v');
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
        } else if nums.len() == 2 {
            Some(Self {
                major: nums[0],
                minor: nums[1],
                patch: 0,
                pre,
            })
        } else {
            None
        }
    }

    pub fn bump(&self, bump_type: VersionBump) -> Self {
        match bump_type {
            VersionBump::Major => Self::new(self.major + 1, 0, 0),
            VersionBump::Minor => Self::new(self.major, self.minor + 1, 0),
            VersionBump::Patch => Self::new(self.major, self.minor, self.patch + 1),
            VersionBump::None => self.clone(),
        }
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

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum VersionBump {
    None,
    Patch,
    Minor,
    Major,
}

// ============================================================================
// Changelog Generation
// ============================================================================

/// A release in the changelog
#[derive(Clone, Debug)]
pub struct Release {
    pub version: Version,
    pub date: String,
    pub commits: Vec<ConventionalCommit>,
    pub compare_url: Option<String>,
}

impl Release {
    pub fn new(version: Version, date: String) -> Self {
        Self {
            version,
            date,
            commits: Vec::new(),
            compare_url: None,
        }
    }

    pub fn add_commit(&mut self, commit: ConventionalCommit) {
        self.commits.push(commit);
    }

    pub fn breaking_changes(&self) -> Vec<&ConventionalCommit> {
        self.commits.iter().filter(|c| c.breaking).collect()
    }

    pub fn commits_by_type(&self) -> HashMap<CommitType, Vec<&ConventionalCommit>> {
        let mut by_type: HashMap<CommitType, Vec<&ConventionalCommit>> = HashMap::new();
        for commit in &self.commits {
            by_type
                .entry(commit.commit_type.clone())
                .or_insert_with(Vec::new)
                .push(commit);
        }
        by_type
    }

    pub fn suggested_bump(&self) -> VersionBump {
        if self.commits.iter().any(|c| c.breaking) {
            return VersionBump::Major;
        }

        self.commits
            .iter()
            .map(|c| c.commit_type.bump_type())
            .max()
            .unwrap_or(VersionBump::None)
    }
}

/// Configuration for changelog generation
#[derive(Clone, Debug)]
pub struct ChangelogConfig {
    pub title: String,
    pub repo_url: Option<String>,
    pub include_types: Vec<CommitType>,
    pub show_author: bool,
    pub show_hash: bool,
    pub show_date: bool,
    pub use_emoji: bool,
    pub group_by_scope: bool,
    pub unreleased_title: String,
}

impl Default for ChangelogConfig {
    fn default() -> Self {
        Self {
            title: "Changelog".to_string(),
            repo_url: None,
            include_types: vec![
                CommitType::Feat,
                CommitType::Fix,
                CommitType::Perf,
                CommitType::Refactor,
                CommitType::Security,
                CommitType::Deps,
            ],
            show_author: false,
            show_hash: true,
            show_date: true,
            use_emoji: true,
            group_by_scope: false,
            unreleased_title: "Unreleased".to_string(),
        }
    }
}

impl ChangelogConfig {
    pub fn minimal() -> Self {
        Self {
            include_types: vec![CommitType::Feat, CommitType::Fix],
            show_author: false,
            show_hash: false,
            show_date: false,
            use_emoji: false,
            ..Default::default()
        }
    }

    pub fn full() -> Self {
        Self {
            include_types: CommitType::all_standard(),
            show_author: true,
            show_hash: true,
            show_date: true,
            use_emoji: true,
            ..Default::default()
        }
    }

    pub fn with_repo_url(mut self, url: &str) -> Self {
        self.repo_url = Some(url.to_string());
        self
    }
}

impl CommitType {
    fn all_standard() -> Vec<CommitType> {
        vec![
            CommitType::Feat,
            CommitType::Fix,
            CommitType::Docs,
            CommitType::Style,
            CommitType::Refactor,
            CommitType::Perf,
            CommitType::Test,
            CommitType::Build,
            CommitType::Ci,
            CommitType::Chore,
            CommitType::Security,
            CommitType::Deps,
        ]
    }
}

/// Changelog generator
pub struct ChangelogGenerator {
    config: ChangelogConfig,
    releases: Vec<Release>,
}

impl ChangelogGenerator {
    pub fn new(config: ChangelogConfig) -> Self {
        Self {
            config,
            releases: Vec::new(),
        }
    }

    pub fn add_release(&mut self, release: Release) {
        self.releases.push(release);
    }

    pub fn generate_markdown(&self) -> String {
        let mut output = String::new();

        // Title
        output.push_str(&format!("# {}\n\n", self.config.title));

        // Description
        output.push_str("All notable changes to this project will be documented in this file.\n\n");
        output.push_str(
            "The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),\n",
        );
        output.push_str("and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).\n\n");

        // Releases
        for release in &self.releases {
            output.push_str(&self.format_release(release));
        }

        output
    }

    fn format_release(&self, release: &Release) -> String {
        let mut output = String::new();

        // Release header
        let version_str = if release.version == Version::new(0, 0, 0) {
            self.config.unreleased_title.clone()
        } else {
            format!("[{}]", release.version)
        };

        if self.config.show_date {
            output.push_str(&format!("## {} - {}\n\n", version_str, release.date));
        } else {
            output.push_str(&format!("## {}\n\n", version_str));
        }

        // Compare URL
        if let Some(ref url) = release.compare_url {
            output.push_str(&format!("[Compare changes]({})\n\n", url));
        }

        // Breaking changes section
        let breaking = release.breaking_changes();
        if !breaking.is_empty() {
            output.push_str("### ⚠️ BREAKING CHANGES\n\n");
            for commit in breaking {
                output.push_str(&self.format_commit(commit, true));
            }
            output.push('\n');
        }

        // Group commits by type
        let by_type = release.commits_by_type();
        let mut sorted_types: Vec<_> = by_type.keys().collect();
        sorted_types.sort_by_key(|t| t.priority());

        for commit_type in sorted_types {
            if !self.config.include_types.contains(commit_type) {
                continue;
            }

            let commits = by_type.get(commit_type).unwrap();
            if commits.is_empty() {
                continue;
            }

            // Section header
            let emoji = if self.config.use_emoji {
                format!("{} ", commit_type.emoji())
            } else {
                String::new()
            };
            output.push_str(&format!("### {}{}\n\n", emoji, commit_type.section_title()));

            if self.config.group_by_scope {
                // Group by scope
                let mut by_scope: HashMap<Option<String>, Vec<&&ConventionalCommit>> =
                    HashMap::new();
                for commit in commits {
                    by_scope
                        .entry(commit.scope.clone())
                        .or_insert_with(Vec::new)
                        .push(commit);
                }

                for (scope, scope_commits) in by_scope {
                    if let Some(ref s) = scope {
                        output.push_str(&format!("#### {}\n\n", s));
                    }
                    for commit in scope_commits {
                        output.push_str(&self.format_commit(commit, false));
                    }
                    output.push('\n');
                }
            } else {
                for commit in commits {
                    output.push_str(&self.format_commit(commit, false));
                }
                output.push('\n');
            }
        }

        output
    }

    fn format_commit(&self, commit: &ConventionalCommit, is_breaking: bool) -> String {
        let mut line = String::from("- ");

        // Scope
        if let Some(ref scope) = commit.scope {
            line.push_str(&format!("**{}:** ", scope));
        }

        // Description
        line.push_str(&commit.description);

        // Breaking indicator
        if is_breaking && !line.contains("BREAKING") {
            line.push_str(" **[BREAKING]**");
        }

        // Hash link
        if self.config.show_hash {
            if let Some(ref repo_url) = self.config.repo_url {
                let short_hash = &commit.hash[..7.min(commit.hash.len())];
                line.push_str(&format!(
                    " ([{}]({}/commit/{}))",
                    short_hash, repo_url, commit.hash
                ));
            } else {
                let short_hash = &commit.hash[..7.min(commit.hash.len())];
                line.push_str(&format!(" ({})", short_hash));
            }
        }

        // Author
        if self.config.show_author {
            line.push_str(&format!(" by @{}", commit.author.name));
        }

        line.push('\n');

        // Body (indented)
        if let Some(ref body) = commit.body {
            for body_line in body.lines() {
                line.push_str(&format!("  {}\n", body_line));
            }
        }

        line
    }

    pub fn generate_json(&self) -> String {
        let mut json = String::from("{\n");
        json.push_str(&format!("  \"title\": \"{}\",\n", self.config.title));
        json.push_str("  \"releases\": [\n");

        for (i, release) in self.releases.iter().enumerate() {
            json.push_str("    {\n");
            json.push_str(&format!("      \"version\": \"{}\",\n", release.version));
            json.push_str(&format!("      \"date\": \"{}\",\n", release.date));
            json.push_str(&format!("      \"commits\": {},\n", release.commits.len()));
            json.push_str(&format!(
                "      \"breaking_changes\": {},\n",
                release.breaking_changes().len()
            ));
            json.push_str(&format!(
                "      \"suggested_bump\": \"{:?}\"\n",
                release.suggested_bump()
            ));
            json.push_str("    }");
            if i < self.releases.len() - 1 {
                json.push(',');
            }
            json.push('\n');
        }

        json.push_str("  ]\n");
        json.push_str("}\n");
        json
    }

    pub fn generate_release_notes(&self) -> String {
        if self.releases.is_empty() {
            return String::new();
        }

        let release = &self.releases[0];
        let mut output = String::new();

        output.push_str(&format!("# Release v{}\n\n", release.version));
        output.push_str(&format!("📅 Released on {}\n\n", release.date));

        // Summary
        let by_type = release.commits_by_type();
        output.push_str("## Summary\n\n");
        for commit_type in &self.config.include_types {
            if let Some(commits) = by_type.get(commit_type) {
                output.push_str(&format!(
                    "- {} {}: {}\n",
                    commit_type.emoji(),
                    commit_type.section_title(),
                    commits.len()
                ));
            }
        }
        output.push('\n');

        // Breaking changes
        let breaking = release.breaking_changes();
        if !breaking.is_empty() {
            output.push_str("## ⚠️ Breaking Changes\n\n");
            output.push_str(
                "This release contains breaking changes. Please review before upgrading.\n\n",
            );
            for commit in breaking {
                output.push_str(&format!("- {}\n", commit.description));
            }
            output.push('\n');
        }

        // Highlights (first 5 features)
        if let Some(features) = by_type.get(&CommitType::Feat) {
            if !features.is_empty() {
                output.push_str("## ✨ Highlights\n\n");
                for commit in features.iter().take(5) {
                    output.push_str(&format!("### {}\n\n", commit.description));
                    if let Some(ref body) = commit.body {
                        output.push_str(&format!("{}\n\n", body));
                    }
                }
            }
        }

        // Bug fixes
        if let Some(fixes) = by_type.get(&CommitType::Fix) {
            if !fixes.is_empty() {
                output.push_str("## 🐛 Bug Fixes\n\n");
                for commit in fixes {
                    output.push_str(&format!("- {}\n", commit.description));
                }
                output.push('\n');
            }
        }

        // Security
        if let Some(security) = by_type.get(&CommitType::Security) {
            if !security.is_empty() {
                output.push_str("## 🔒 Security\n\n");
                for commit in security {
                    output.push_str(&format!("- {}\n", commit.description));
                }
                output.push('\n');
            }
        }

        // Upgrade instructions
        output.push_str("## 📦 Upgrade\n\n");
        output.push_str("```toml\n");
        output.push_str(&format!("[dependencies]\n"));
        output.push_str(&format!("your-crate = \"{}\"\n", release.version));
        output.push_str("```\n");

        output
    }
}

// ============================================================================
// Version History Tracker
// ============================================================================

/// Tracks version history
pub struct VersionHistory {
    versions: Vec<(Version, String, String)>, // version, date, tag
}

impl VersionHistory {
    pub fn new() -> Self {
        Self {
            versions: Vec::new(),
        }
    }

    pub fn add_version(&mut self, version: Version, date: &str, tag: &str) {
        self.versions
            .push((version, date.to_string(), tag.to_string()));
    }

    pub fn latest(&self) -> Option<&Version> {
        self.versions.last().map(|(v, _, _)| v)
    }

    pub fn next_version(&self, bump: VersionBump) -> Version {
        self.latest()
            .map(|v| v.bump(bump))
            .unwrap_or_else(|| Version::new(0, 1, 0))
    }

    pub fn generate_version_file(&self) -> String {
        let mut output = String::from("# Version History\n\n");
        output.push_str("| Version | Date | Tag |\n");
        output.push_str("|---------|------|-----|\n");

        for (version, date, tag) in self.versions.iter().rev() {
            output.push_str(&format!("| {} | {} | {} |\n", version, date, tag));
        }

        output
    }
}

// ============================================================================
// Main Demonstration
// ============================================================================

fn main() {
    println!("=== Changelog Generator for Rust Projects ===\n");

    // Sample commits
    let sample_commits = vec![
        ("feat(auth): add OAuth2 support for GitHub and GitLab\n\nThis adds full OAuth2 integration with support for:\n- GitHub OAuth\n- GitLab OAuth\n- Custom OAuth providers\n\nCloses #123",
         "abc1234", "Alice", "alice@example.com", "2024-01-15"),
        ("fix(security): patch XSS vulnerability in user input\n\nBREAKING CHANGE: User input is now sanitized by default",
         "def5678", "Bob", "bob@example.com", "2024-01-14"),
        ("feat(api)!: redesign REST API with OpenAPI 3.0\n\nThe API has been completely redesigned.",
         "ghi9012", "Charlie", "charlie@example.com", "2024-01-13"),
        ("perf(db): optimize database queries for large datasets",
         "jkl3456", "Alice", "alice@example.com", "2024-01-12"),
        ("fix(auth): correct token expiration handling",
         "mno7890", "Bob", "bob@example.com", "2024-01-11"),
        ("docs: update README with installation instructions",
         "pqr1234", "Dave", "dave@example.com", "2024-01-10"),
        ("security: update dependencies to fix CVE-2024-0001",
         "stu5678", "Alice", "alice@example.com", "2024-01-09"),
        ("refactor(core): simplify error handling",
         "vwx9012", "Charlie", "charlie@example.com", "2024-01-08"),
        ("test: add integration tests for OAuth flow",
         "yza3456", "Bob", "bob@example.com", "2024-01-07"),
        ("chore: update CI configuration",
         "bcd7890", "Dave", "dave@example.com", "2024-01-06"),
        ("deps: update tokio to 1.35",
         "efg1234", "Alice", "alice@example.com", "2024-01-05"),
    ];

    // Parse commits
    println!("Parsing {} commits...\n", sample_commits.len());

    let mut commits = Vec::new();
    for (raw, hash, author, email, date) in sample_commits {
        if let Some(commit) = CommitParser::parse(raw, hash, author, email, date) {
            println!(
                "  {} {} - {}",
                commit.commit_type.emoji(),
                commit.commit_type,
                commit.description
            );
            if commit.breaking {
                println!("    ⚠️  BREAKING CHANGE");
            }
            commits.push(commit);
        }
    }
    println!();

    // Create release
    let mut release = Release::new(Version::new(2, 0, 0), "2024-01-15".to_string());
    release.compare_url =
        Some("https://github.com/example/project/compare/v1.5.0...v2.0.0".to_string());
    for commit in commits {
        release.add_commit(commit);
    }

    // Analyze release
    println!("Release Analysis:");
    println!("  Version: {}", release.version);
    println!("  Total commits: {}", release.commits.len());
    println!("  Breaking changes: {}", release.breaking_changes().len());
    println!("  Suggested bump: {:?}", release.suggested_bump());
    println!();

    // Generate changelog
    let config = ChangelogConfig::default().with_repo_url("https://github.com/example/project");

    let mut generator = ChangelogGenerator::new(config);
    generator.add_release(release);

    // Output markdown
    println!("═══════════════════════════════════════════════════════════════════════");
    println!("                         CHANGELOG.md");
    println!("═══════════════════════════════════════════════════════════════════════\n");
    println!("{}", generator.generate_markdown());

    // Output release notes
    println!("═══════════════════════════════════════════════════════════════════════");
    println!("                       RELEASE NOTES");
    println!("═══════════════════════════════════════════════════════════════════════\n");
    println!("{}", generator.generate_release_notes());

    // Version history
    println!("═══════════════════════════════════════════════════════════════════════");
    println!("                      VERSION HISTORY");
    println!("═══════════════════════════════════════════════════════════════════════\n");

    let mut history = VersionHistory::new();
    history.add_version(Version::new(1, 0, 0), "2023-06-01", "v1.0.0");
    history.add_version(Version::new(1, 1, 0), "2023-08-15", "v1.1.0");
    history.add_version(Version::new(1, 5, 0), "2023-12-01", "v1.5.0");
    history.add_version(Version::new(2, 0, 0), "2024-01-15", "v2.0.0");

    println!("{}", history.generate_version_file());

    println!("=== Changelog Generation Complete ===");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commit_type_parse() {
        assert_eq!(CommitType::parse("feat"), CommitType::Feat);
        assert_eq!(CommitType::parse("FEAT"), CommitType::Feat);
        assert_eq!(CommitType::parse("fix"), CommitType::Fix);
        assert_eq!(CommitType::parse("docs"), CommitType::Docs);
        assert_eq!(CommitType::parse("security"), CommitType::Security);
    }

    #[test]
    fn test_commit_parser_simple() {
        let raw = "feat: add new feature";
        let commit =
            CommitParser::parse(raw, "abc123", "Alice", "alice@test.com", "2024-01-01").unwrap();

        assert_eq!(commit.commit_type, CommitType::Feat);
        assert_eq!(commit.scope, None);
        assert_eq!(commit.description, "add new feature");
        assert!(!commit.breaking);
    }

    #[test]
    fn test_commit_parser_with_scope() {
        let raw = "fix(auth): correct login bug";
        let commit =
            CommitParser::parse(raw, "abc123", "Bob", "bob@test.com", "2024-01-01").unwrap();

        assert_eq!(commit.commit_type, CommitType::Fix);
        assert_eq!(commit.scope, Some("auth".to_string()));
        assert_eq!(commit.description, "correct login bug");
    }

    #[test]
    fn test_commit_parser_breaking() {
        let raw = "feat(api)!: breaking change";
        let commit =
            CommitParser::parse(raw, "abc123", "Charlie", "c@test.com", "2024-01-01").unwrap();

        assert!(commit.breaking);
    }

    #[test]
    fn test_commit_parser_breaking_footer() {
        let raw = "feat: add feature\n\nBREAKING CHANGE: this breaks stuff";
        let commit =
            CommitParser::parse(raw, "abc123", "Dave", "d@test.com", "2024-01-01").unwrap();

        assert!(commit.breaking);
    }

    #[test]
    fn test_commit_parser_with_body() {
        let raw = "feat: add feature\n\nThis is the body\nwith multiple lines";
        let commit = CommitParser::parse(raw, "abc123", "Eve", "e@test.com", "2024-01-01").unwrap();

        assert!(commit.body.is_some());
        assert!(commit.body.unwrap().contains("multiple lines"));
    }

    #[test]
    fn test_version_parse() {
        let v = Version::parse("1.2.3").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 3);

        let v = Version::parse("v2.0.0-beta").unwrap();
        assert_eq!(v.major, 2);
        assert_eq!(v.pre, Some("beta".to_string()));
    }

    #[test]
    fn test_version_bump() {
        let v = Version::new(1, 2, 3);

        assert_eq!(v.bump(VersionBump::Patch), Version::new(1, 2, 4));
        assert_eq!(v.bump(VersionBump::Minor), Version::new(1, 3, 0));
        assert_eq!(v.bump(VersionBump::Major), Version::new(2, 0, 0));
    }

    #[test]
    fn test_release_suggested_bump() {
        let mut release = Release::new(Version::new(1, 0, 0), "2024-01-01".to_string());

        // Only fixes -> patch
        release.add_commit(ConventionalCommit {
            hash: "abc".to_string(),
            commit_type: CommitType::Fix,
            scope: None,
            description: "fix bug".to_string(),
            body: None,
            footers: vec![],
            breaking: false,
            author: Author {
                name: "Test".to_string(),
                email: "test@test.com".to_string(),
            },
            date: "2024-01-01".to_string(),
        });
        assert_eq!(release.suggested_bump(), VersionBump::Patch);

        // Add feature -> minor
        release.add_commit(ConventionalCommit {
            hash: "def".to_string(),
            commit_type: CommitType::Feat,
            scope: None,
            description: "add feature".to_string(),
            body: None,
            footers: vec![],
            breaking: false,
            author: Author {
                name: "Test".to_string(),
                email: "test@test.com".to_string(),
            },
            date: "2024-01-01".to_string(),
        });
        assert_eq!(release.suggested_bump(), VersionBump::Minor);

        // Add breaking -> major
        release.add_commit(ConventionalCommit {
            hash: "ghi".to_string(),
            commit_type: CommitType::Feat,
            scope: None,
            description: "breaking".to_string(),
            body: None,
            footers: vec![],
            breaking: true,
            author: Author {
                name: "Test".to_string(),
                email: "test@test.com".to_string(),
            },
            date: "2024-01-01".to_string(),
        });
        assert_eq!(release.suggested_bump(), VersionBump::Major);
    }

    #[test]
    fn test_changelog_generator() {
        let config = ChangelogConfig::default();
        let generator = ChangelogGenerator::new(config);

        let markdown = generator.generate_markdown();
        assert!(markdown.contains("# Changelog"));
        assert!(markdown.contains("Keep a Changelog"));
    }

    #[test]
    fn test_version_history() {
        let mut history = VersionHistory::new();
        history.add_version(Version::new(1, 0, 0), "2024-01-01", "v1.0.0");
        history.add_version(Version::new(1, 1, 0), "2024-02-01", "v1.1.0");

        assert_eq!(history.latest(), Some(&Version::new(1, 1, 0)));
        assert_eq!(
            history.next_version(VersionBump::Patch),
            Version::new(1, 1, 1)
        );
        assert_eq!(
            history.next_version(VersionBump::Minor),
            Version::new(1, 2, 0)
        );
    }

    #[test]
    fn test_commit_type_bump() {
        assert_eq!(CommitType::Feat.bump_type(), VersionBump::Minor);
        assert_eq!(CommitType::Fix.bump_type(), VersionBump::Patch);
        assert_eq!(CommitType::Docs.bump_type(), VersionBump::None);
        assert_eq!(CommitType::Security.bump_type(), VersionBump::Patch);
    }

    #[test]
    fn test_footer_parsing() {
        let raw = "feat: add feature\n\nCloses: #123\nReviewed-by: Alice";
        let commit =
            CommitParser::parse(raw, "abc", "Test", "test@test.com", "2024-01-01").unwrap();

        assert_eq!(commit.footers.len(), 2);
        assert_eq!(commit.footers[0].key, "Closes");
        assert_eq!(commit.footers[0].value, "#123");
    }
}
