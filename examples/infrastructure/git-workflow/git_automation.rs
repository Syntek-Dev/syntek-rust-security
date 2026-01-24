//! Git Workflow Automation
//!
//! Implements git workflow patterns including branch management,
//! commit conventions, and pull request automation.

use std::collections::HashMap;
use std::process::Command;
use std::time::SystemTime;

/// Git configuration
#[derive(Debug, Clone)]
pub struct GitConfig {
    /// Repository path
    pub repo_path: String,
    /// Main branch name
    pub main_branch: String,
    /// Development branch name
    pub dev_branch: Option<String>,
    /// Branch prefix patterns
    pub branch_prefixes: BranchPrefixes,
    /// Commit message format
    pub commit_format: CommitFormat,
    /// Enable GPG signing
    pub gpg_signing: bool,
    /// Protected branches
    pub protected_branches: Vec<String>,
}

impl Default for GitConfig {
    fn default() -> Self {
        Self {
            repo_path: ".".to_string(),
            main_branch: "main".to_string(),
            dev_branch: Some("develop".to_string()),
            branch_prefixes: BranchPrefixes::default(),
            commit_format: CommitFormat::Conventional,
            gpg_signing: false,
            protected_branches: vec!["main".to_string(), "develop".to_string()],
        }
    }
}

#[derive(Debug, Clone)]
pub struct BranchPrefixes {
    pub feature: String,
    pub bugfix: String,
    pub hotfix: String,
    pub release: String,
    pub chore: String,
}

impl Default for BranchPrefixes {
    fn default() -> Self {
        Self {
            feature: "feature/".to_string(),
            bugfix: "bugfix/".to_string(),
            hotfix: "hotfix/".to_string(),
            release: "release/".to_string(),
            chore: "chore/".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum CommitFormat {
    Conventional,
    Gitmoji,
    Angular,
    Custom(String),
}

/// Conventional commit structure
#[derive(Debug, Clone)]
pub struct ConventionalCommit {
    /// Commit type
    pub commit_type: CommitType,
    /// Scope (optional)
    pub scope: Option<String>,
    /// Description
    pub description: String,
    /// Body (optional)
    pub body: Option<String>,
    /// Footer (optional)
    pub footer: Option<String>,
    /// Breaking change
    pub breaking: bool,
}

#[derive(Debug, Clone, PartialEq)]
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
}

impl CommitType {
    pub fn as_str(&self) -> &str {
        match self {
            CommitType::Feat => "feat",
            CommitType::Fix => "fix",
            CommitType::Docs => "docs",
            CommitType::Style => "style",
            CommitType::Refactor => "refactor",
            CommitType::Perf => "perf",
            CommitType::Test => "test",
            CommitType::Build => "build",
            CommitType::Ci => "ci",
            CommitType::Chore => "chore",
            CommitType::Revert => "revert",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "feat" | "feature" => Some(CommitType::Feat),
            "fix" | "bugfix" => Some(CommitType::Fix),
            "docs" | "documentation" => Some(CommitType::Docs),
            "style" => Some(CommitType::Style),
            "refactor" => Some(CommitType::Refactor),
            "perf" | "performance" => Some(CommitType::Perf),
            "test" | "tests" => Some(CommitType::Test),
            "build" => Some(CommitType::Build),
            "ci" => Some(CommitType::Ci),
            "chore" => Some(CommitType::Chore),
            "revert" => Some(CommitType::Revert),
            _ => None,
        }
    }
}

impl ConventionalCommit {
    /// Create new conventional commit
    pub fn new(commit_type: CommitType, description: &str) -> Self {
        Self {
            commit_type,
            scope: None,
            description: description.to_string(),
            body: None,
            footer: None,
            breaking: false,
        }
    }

    /// Add scope
    pub fn with_scope(mut self, scope: &str) -> Self {
        self.scope = Some(scope.to_string());
        self
    }

    /// Add body
    pub fn with_body(mut self, body: &str) -> Self {
        self.body = Some(body.to_string());
        self
    }

    /// Add footer
    pub fn with_footer(mut self, footer: &str) -> Self {
        self.footer = Some(footer.to_string());
        self
    }

    /// Mark as breaking change
    pub fn breaking(mut self) -> Self {
        self.breaking = true;
        self
    }

    /// Format as commit message
    pub fn format(&self) -> String {
        let mut message = String::new();

        // Type
        message.push_str(self.commit_type.as_str());

        // Scope
        if let Some(ref scope) = self.scope {
            message.push_str(&format!("({})", scope));
        }

        // Breaking indicator
        if self.breaking {
            message.push('!');
        }

        // Description
        message.push_str(&format!(": {}", self.description));

        // Body
        if let Some(ref body) = self.body {
            message.push_str("\n\n");
            message.push_str(body);
        }

        // Footer
        if let Some(ref footer) = self.footer {
            message.push_str("\n\n");
            message.push_str(footer);
        }

        // Breaking change footer
        if self.breaking && self.footer.is_none() {
            message.push_str("\n\nBREAKING CHANGE: This commit introduces breaking changes");
        }

        message
    }

    /// Parse from commit message
    pub fn parse(message: &str) -> Result<Self, String> {
        let first_line = message.lines().next().ok_or("Empty commit message")?;

        // Parse type
        let colon_pos = first_line.find(':').ok_or("Missing colon")?;
        let type_part = &first_line[..colon_pos];
        let description = first_line[colon_pos + 1..].trim();

        // Check for breaking indicator
        let breaking = type_part.contains('!');
        let type_part = type_part.trim_end_matches('!');

        // Parse scope
        let (commit_type_str, scope) = if let Some(paren_start) = type_part.find('(') {
            let paren_end = type_part.find(')').ok_or("Unclosed parenthesis")?;
            (
                &type_part[..paren_start],
                Some(type_part[paren_start + 1..paren_end].to_string()),
            )
        } else {
            (type_part, None)
        };

        let commit_type = CommitType::from_str(commit_type_str)
            .ok_or_else(|| format!("Unknown commit type: {}", commit_type_str))?;

        // Parse body and footer
        let mut lines = message.lines();
        lines.next(); // Skip first line

        let remaining: Vec<&str> = lines.collect();
        let body = if remaining.len() > 1 {
            Some(remaining[1..].join("\n").trim().to_string())
        } else {
            None
        };

        Ok(Self {
            commit_type,
            scope,
            description: description.to_string(),
            body,
            footer: None,
            breaking,
        })
    }
}

/// Git operations
pub struct GitOperations {
    config: GitConfig,
}

impl GitOperations {
    pub fn new(config: GitConfig) -> Self {
        Self { config }
    }

    /// Get current branch
    pub fn current_branch(&self) -> Result<String, String> {
        self.run_git(&["rev-parse", "--abbrev-ref", "HEAD"])
    }

    /// Get list of branches
    pub fn list_branches(&self) -> Result<Vec<String>, String> {
        let output = self.run_git(&["branch", "--list", "--format=%(refname:short)"])?;
        Ok(output.lines().map(|s| s.trim().to_string()).collect())
    }

    /// Create branch
    pub fn create_branch(&self, branch_type: BranchType, name: &str) -> Result<String, String> {
        let prefix = match branch_type {
            BranchType::Feature => &self.config.branch_prefixes.feature,
            BranchType::Bugfix => &self.config.branch_prefixes.bugfix,
            BranchType::Hotfix => &self.config.branch_prefixes.hotfix,
            BranchType::Release => &self.config.branch_prefixes.release,
            BranchType::Chore => &self.config.branch_prefixes.chore,
        };

        let branch_name = format!("{}{}", prefix, name);

        // Determine base branch
        let base = match branch_type {
            BranchType::Hotfix => &self.config.main_branch,
            _ => self
                .config
                .dev_branch
                .as_ref()
                .unwrap_or(&self.config.main_branch),
        };

        self.run_git(&["checkout", "-b", &branch_name, base])?;

        Ok(branch_name)
    }

    /// Switch branch
    pub fn checkout(&self, branch: &str) -> Result<(), String> {
        self.run_git(&["checkout", branch])?;
        Ok(())
    }

    /// Commit with conventional commit
    pub fn commit(&self, commit: &ConventionalCommit) -> Result<String, String> {
        let message = commit.format();

        let mut args = vec!["commit", "-m", &message];

        if self.config.gpg_signing {
            args.push("-S");
        }

        self.run_git(&args)
    }

    /// Get commit history
    pub fn log(&self, count: usize) -> Result<Vec<CommitInfo>, String> {
        let format = "--format=%H|%an|%ae|%at|%s";
        let output = self.run_git(&["log", format, &format!("-{}", count)])?;

        let mut commits = Vec::new();
        for line in output.lines() {
            let parts: Vec<&str> = line.split('|').collect();
            if parts.len() >= 5 {
                commits.push(CommitInfo {
                    hash: parts[0].to_string(),
                    author_name: parts[1].to_string(),
                    author_email: parts[2].to_string(),
                    timestamp: parts[3].parse().unwrap_or(0),
                    subject: parts[4..].join("|"),
                });
            }
        }

        Ok(commits)
    }

    /// Get status
    pub fn status(&self) -> Result<GitStatus, String> {
        let output = self.run_git(&["status", "--porcelain"])?;

        let mut status = GitStatus::default();

        for line in output.lines() {
            if line.len() < 3 {
                continue;
            }

            let status_code = &line[0..2];
            let file = line[3..].to_string();

            match status_code {
                "M " | " M" | "MM" => status.modified.push(file),
                "A " => status.staged.push(file),
                "D " | " D" => status.deleted.push(file),
                "??" => status.untracked.push(file),
                "R " => status.renamed.push(file),
                _ => {}
            }
        }

        Ok(status)
    }

    /// Stage files
    pub fn add(&self, files: &[&str]) -> Result<(), String> {
        let mut args = vec!["add"];
        args.extend(files);
        self.run_git(&args)?;
        Ok(())
    }

    /// Stage all changes
    pub fn add_all(&self) -> Result<(), String> {
        self.run_git(&["add", "-A"])?;
        Ok(())
    }

    /// Merge branch
    pub fn merge(&self, branch: &str, no_ff: bool) -> Result<(), String> {
        let mut args = vec!["merge"];
        if no_ff {
            args.push("--no-ff");
        }
        args.push(branch);
        self.run_git(&args)?;
        Ok(())
    }

    /// Rebase
    pub fn rebase(&self, branch: &str) -> Result<(), String> {
        self.run_git(&["rebase", branch])?;
        Ok(())
    }

    /// Create tag
    pub fn tag(&self, name: &str, message: Option<&str>) -> Result<(), String> {
        if let Some(msg) = message {
            self.run_git(&["tag", "-a", name, "-m", msg])?;
        } else {
            self.run_git(&["tag", name])?;
        }
        Ok(())
    }

    /// Push
    pub fn push(&self, remote: &str, branch: &str) -> Result<(), String> {
        self.run_git(&["push", remote, branch])?;
        Ok(())
    }

    /// Pull
    pub fn pull(&self, remote: &str, branch: &str) -> Result<(), String> {
        self.run_git(&["pull", remote, branch])?;
        Ok(())
    }

    /// Fetch
    pub fn fetch(&self, remote: &str) -> Result<(), String> {
        self.run_git(&["fetch", remote])?;
        Ok(())
    }

    /// Stash changes
    pub fn stash(&self, message: Option<&str>) -> Result<(), String> {
        if let Some(msg) = message {
            self.run_git(&["stash", "push", "-m", msg])?;
        } else {
            self.run_git(&["stash"])?;
        }
        Ok(())
    }

    /// Pop stash
    pub fn stash_pop(&self) -> Result<(), String> {
        self.run_git(&["stash", "pop"])?;
        Ok(())
    }

    /// Check if branch is protected
    pub fn is_protected(&self, branch: &str) -> bool {
        self.config.protected_branches.contains(&branch.to_string())
    }

    fn run_git(&self, args: &[&str]) -> Result<String, String> {
        let output = Command::new("git")
            .args(&["-C", &self.config.repo_path])
            .args(args)
            .output()
            .map_err(|e| format!("Failed to run git: {}", e))?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
        }
    }
}

#[derive(Debug, Clone)]
pub enum BranchType {
    Feature,
    Bugfix,
    Hotfix,
    Release,
    Chore,
}

#[derive(Debug, Clone)]
pub struct CommitInfo {
    pub hash: String,
    pub author_name: String,
    pub author_email: String,
    pub timestamp: i64,
    pub subject: String,
}

#[derive(Debug, Default, Clone)]
pub struct GitStatus {
    pub staged: Vec<String>,
    pub modified: Vec<String>,
    pub deleted: Vec<String>,
    pub untracked: Vec<String>,
    pub renamed: Vec<String>,
}

impl GitStatus {
    pub fn is_clean(&self) -> bool {
        self.staged.is_empty()
            && self.modified.is_empty()
            && self.deleted.is_empty()
            && self.untracked.is_empty()
            && self.renamed.is_empty()
    }

    pub fn has_staged(&self) -> bool {
        !self.staged.is_empty()
    }
}

/// Changelog generator
pub struct ChangelogGenerator {
    commits: Vec<ConventionalCommit>,
    version: String,
}

impl ChangelogGenerator {
    pub fn new(version: &str) -> Self {
        Self {
            commits: Vec::new(),
            version: version.to_string(),
        }
    }

    pub fn add_commit(&mut self, commit: ConventionalCommit) {
        self.commits.push(commit);
    }

    pub fn generate(&self) -> String {
        let mut changelog = String::new();

        changelog.push_str(&format!(
            "## [{}] - {}\n\n",
            self.version,
            chrono_format_date()
        ));

        // Group by type
        let mut features = Vec::new();
        let mut fixes = Vec::new();
        let mut breaking = Vec::new();
        let mut other = Vec::new();

        for commit in &self.commits {
            if commit.breaking {
                breaking.push(commit);
            } else {
                match commit.commit_type {
                    CommitType::Feat => features.push(commit),
                    CommitType::Fix => fixes.push(commit),
                    _ => other.push(commit),
                }
            }
        }

        if !breaking.is_empty() {
            changelog.push_str("### ⚠️ BREAKING CHANGES\n\n");
            for commit in breaking {
                changelog.push_str(&format!("- {}\n", commit.description));
            }
            changelog.push('\n');
        }

        if !features.is_empty() {
            changelog.push_str("### ✨ Features\n\n");
            for commit in features {
                let scope = commit
                    .scope
                    .as_ref()
                    .map(|s| format!("**{}:** ", s))
                    .unwrap_or_default();
                changelog.push_str(&format!("- {}{}\n", scope, commit.description));
            }
            changelog.push('\n');
        }

        if !fixes.is_empty() {
            changelog.push_str("### 🐛 Bug Fixes\n\n");
            for commit in fixes {
                let scope = commit
                    .scope
                    .as_ref()
                    .map(|s| format!("**{}:** ", s))
                    .unwrap_or_default();
                changelog.push_str(&format!("- {}{}\n", scope, commit.description));
            }
            changelog.push('\n');
        }

        if !other.is_empty() {
            changelog.push_str("### 🔧 Other Changes\n\n");
            for commit in other {
                let scope = commit
                    .scope
                    .as_ref()
                    .map(|s| format!("**{}:** ", s))
                    .unwrap_or_default();
                changelog.push_str(&format!("- {}{}\n", scope, commit.description));
            }
        }

        changelog
    }
}

fn chrono_format_date() -> String {
    // Simplified date formatting
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let days = now / 86400;
    let years = 1970 + days / 365;
    let remaining_days = days % 365;
    let months = remaining_days / 30 + 1;
    let day = remaining_days % 30 + 1;

    format!("{:04}-{:02}-{:02}", years, months, day)
}

fn main() {
    println!("=== Git Workflow Automation Demo ===\n");

    // Create configuration
    let config = GitConfig::default();
    let _git = GitOperations::new(config);

    // Demonstrate conventional commits
    println!("Conventional Commits:\n");

    let commits = vec![
        ConventionalCommit::new(CommitType::Feat, "add user authentication").with_scope("auth"),
        ConventionalCommit::new(CommitType::Fix, "resolve memory leak in cache")
            .with_scope("cache")
            .with_body("The cache was not properly cleaning up expired entries."),
        ConventionalCommit::new(CommitType::Feat, "change API response format")
            .with_scope("api")
            .breaking(),
        ConventionalCommit::new(CommitType::Docs, "update README"),
        ConventionalCommit::new(CommitType::Refactor, "simplify error handling").with_scope("core"),
    ];

    for commit in &commits {
        println!("---");
        println!("{}", commit.format());
    }

    // Parse a commit message
    println!("\n=== Commit Parsing ===\n");
    let message = "feat(auth): add OAuth2 support";
    match ConventionalCommit::parse(message) {
        Ok(parsed) => {
            println!("Parsed: {:?}", parsed.commit_type);
            println!("Scope: {:?}", parsed.scope);
            println!("Description: {}", parsed.description);
            println!("Breaking: {}", parsed.breaking);
        }
        Err(e) => println!("Parse error: {}", e),
    }

    // Generate changelog
    println!("\n=== Generated Changelog ===\n");
    let mut changelog = ChangelogGenerator::new("1.2.0");
    for commit in commits {
        changelog.add_commit(commit);
    }
    println!("{}", changelog.generate());

    // Branch naming
    println!("=== Branch Naming ===\n");
    let prefixes = BranchPrefixes::default();
    println!("Feature: {}user-auth", prefixes.feature);
    println!("Bugfix: {}memory-leak", prefixes.bugfix);
    println!("Hotfix: {}security-patch", prefixes.hotfix);
    println!("Release: {}1.2.0", prefixes.release);

    // Simulate status
    println!("\n=== Git Status (simulated) ===\n");
    let status = GitStatus {
        staged: vec!["src/lib.rs".to_string()],
        modified: vec!["Cargo.toml".to_string()],
        deleted: vec![],
        untracked: vec!["temp.txt".to_string()],
        renamed: vec![],
    };

    println!("Staged: {:?}", status.staged);
    println!("Modified: {:?}", status.modified);
    println!("Untracked: {:?}", status.untracked);
    println!("Is clean: {}", status.is_clean());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conventional_commit_format() {
        let commit = ConventionalCommit::new(CommitType::Feat, "add feature").with_scope("module");

        assert_eq!(commit.format(), "feat(module): add feature");
    }

    #[test]
    fn test_breaking_commit() {
        let commit = ConventionalCommit::new(CommitType::Feat, "change API").breaking();

        let formatted = commit.format();
        assert!(formatted.starts_with("feat!:"));
        assert!(formatted.contains("BREAKING CHANGE"));
    }

    #[test]
    fn test_commit_with_body() {
        let commit =
            ConventionalCommit::new(CommitType::Fix, "fix bug").with_body("Detailed explanation");

        let formatted = commit.format();
        assert!(formatted.contains("Detailed explanation"));
    }

    #[test]
    fn test_parse_simple_commit() {
        let parsed = ConventionalCommit::parse("feat: add feature").unwrap();

        assert_eq!(parsed.commit_type, CommitType::Feat);
        assert_eq!(parsed.description, "add feature");
        assert!(parsed.scope.is_none());
    }

    #[test]
    fn test_parse_commit_with_scope() {
        let parsed = ConventionalCommit::parse("fix(auth): resolve issue").unwrap();

        assert_eq!(parsed.commit_type, CommitType::Fix);
        assert_eq!(parsed.scope, Some("auth".to_string()));
        assert_eq!(parsed.description, "resolve issue");
    }

    #[test]
    fn test_parse_breaking_commit() {
        let parsed = ConventionalCommit::parse("feat!: breaking change").unwrap();

        assert!(parsed.breaking);
    }

    #[test]
    fn test_commit_type_from_str() {
        assert_eq!(CommitType::from_str("feat"), Some(CommitType::Feat));
        assert_eq!(CommitType::from_str("fix"), Some(CommitType::Fix));
        assert_eq!(CommitType::from_str("docs"), Some(CommitType::Docs));
        assert_eq!(CommitType::from_str("unknown"), None);
    }

    #[test]
    fn test_git_status_clean() {
        let status = GitStatus::default();
        assert!(status.is_clean());

        let dirty_status = GitStatus {
            modified: vec!["file.rs".to_string()],
            ..Default::default()
        };
        assert!(!dirty_status.is_clean());
    }

    #[test]
    fn test_branch_prefixes() {
        let prefixes = BranchPrefixes::default();

        assert_eq!(prefixes.feature, "feature/");
        assert_eq!(prefixes.bugfix, "bugfix/");
        assert_eq!(prefixes.hotfix, "hotfix/");
    }

    #[test]
    fn test_changelog_generation() {
        let mut changelog = ChangelogGenerator::new("1.0.0");

        changelog.add_commit(ConventionalCommit::new(CommitType::Feat, "new feature"));
        changelog.add_commit(ConventionalCommit::new(CommitType::Fix, "bug fix"));

        let output = changelog.generate();

        assert!(output.contains("[1.0.0]"));
        assert!(output.contains("Features"));
        assert!(output.contains("Bug Fixes"));
        assert!(output.contains("new feature"));
        assert!(output.contains("bug fix"));
    }
}
