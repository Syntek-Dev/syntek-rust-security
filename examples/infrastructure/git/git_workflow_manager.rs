//! Git Workflow Manager for Rust Projects
//!
//! This example demonstrates automated git workflow management including
//! branch strategies, commit validation, pull request handling, and
//! release management for Rust projects.

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ============================================================================
// Git Objects
// ============================================================================

/// Git commit representation
#[derive(Clone, Debug)]
pub struct Commit {
    pub hash: String,
    pub short_hash: String,
    pub author: Author,
    pub message: String,
    pub timestamp: SystemTime,
    pub parent_hashes: Vec<String>,
    pub tree_hash: String,
    pub signature: Option<GpgSignature>,
}

#[derive(Clone, Debug)]
pub struct Author {
    pub name: String,
    pub email: String,
}

#[derive(Clone, Debug)]
pub struct GpgSignature {
    pub key_id: String,
    pub status: SignatureStatus,
    pub signer: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum SignatureStatus {
    Valid,
    Invalid,
    Unknown,
    Expired,
    Revoked,
}

/// Git branch
#[derive(Clone, Debug)]
pub struct Branch {
    pub name: String,
    pub branch_type: BranchType,
    pub head: String,
    pub upstream: Option<String>,
    pub created_at: SystemTime,
    pub last_commit_at: SystemTime,
    pub is_protected: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub enum BranchType {
    Main,
    Develop,
    Feature,
    Bugfix,
    Hotfix,
    Release,
    Support,
    Custom(String),
}

impl BranchType {
    pub fn from_name(name: &str) -> Self {
        if name == "main" || name == "master" {
            BranchType::Main
        } else if name == "develop" || name == "dev" {
            BranchType::Develop
        } else if name.starts_with("feature/") {
            BranchType::Feature
        } else if name.starts_with("bugfix/") || name.starts_with("fix/") {
            BranchType::Bugfix
        } else if name.starts_with("hotfix/") {
            BranchType::Hotfix
        } else if name.starts_with("release/") {
            BranchType::Release
        } else if name.starts_with("support/") {
            BranchType::Support
        } else {
            BranchType::Custom(name.to_string())
        }
    }

    pub fn prefix(&self) -> &str {
        match self {
            BranchType::Main => "",
            BranchType::Develop => "",
            BranchType::Feature => "feature/",
            BranchType::Bugfix => "bugfix/",
            BranchType::Hotfix => "hotfix/",
            BranchType::Release => "release/",
            BranchType::Support => "support/",
            BranchType::Custom(_) => "",
        }
    }
}

/// Git tag
#[derive(Clone, Debug)]
pub struct Tag {
    pub name: String,
    pub target: String,
    pub tagger: Option<Author>,
    pub message: Option<String>,
    pub created_at: SystemTime,
    pub is_annotated: bool,
}

// ============================================================================
// Branch Strategy
// ============================================================================

/// Git branching strategy
#[derive(Clone, Debug)]
pub enum BranchStrategy {
    GitFlow,
    GitHubFlow,
    GitLabFlow,
    TrunkBased,
    Custom(CustomStrategy),
}

#[derive(Clone, Debug)]
pub struct CustomStrategy {
    pub name: String,
    pub main_branch: String,
    pub develop_branch: Option<String>,
    pub feature_prefix: String,
    pub release_prefix: String,
    pub hotfix_prefix: String,
}

impl BranchStrategy {
    pub fn main_branch(&self) -> &str {
        match self {
            BranchStrategy::GitFlow => "main",
            BranchStrategy::GitHubFlow => "main",
            BranchStrategy::GitLabFlow => "main",
            BranchStrategy::TrunkBased => "main",
            BranchStrategy::Custom(c) => &c.main_branch,
        }
    }

    pub fn develop_branch(&self) -> Option<&str> {
        match self {
            BranchStrategy::GitFlow => Some("develop"),
            BranchStrategy::GitHubFlow => None,
            BranchStrategy::GitLabFlow => None,
            BranchStrategy::TrunkBased => None,
            BranchStrategy::Custom(c) => c.develop_branch.as_deref(),
        }
    }

    pub fn feature_base(&self) -> &str {
        match self {
            BranchStrategy::GitFlow => "develop",
            BranchStrategy::GitHubFlow => "main",
            BranchStrategy::GitLabFlow => "main",
            BranchStrategy::TrunkBased => "main",
            BranchStrategy::Custom(c) => c.develop_branch.as_deref().unwrap_or(&c.main_branch),
        }
    }

    pub fn supports_release_branches(&self) -> bool {
        matches!(self, BranchStrategy::GitFlow | BranchStrategy::GitLabFlow)
    }
}

impl fmt::Display for BranchStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BranchStrategy::GitFlow => write!(f, "Git Flow"),
            BranchStrategy::GitHubFlow => write!(f, "GitHub Flow"),
            BranchStrategy::GitLabFlow => write!(f, "GitLab Flow"),
            BranchStrategy::TrunkBased => write!(f, "Trunk-Based Development"),
            BranchStrategy::Custom(c) => write!(f, "Custom: {}", c.name),
        }
    }
}

// ============================================================================
// Commit Validation
// ============================================================================

/// Commit validation rules
#[derive(Clone, Debug)]
pub struct CommitPolicy {
    pub require_conventional: bool,
    pub require_signed: bool,
    pub require_linked_issue: bool,
    pub max_subject_length: usize,
    pub max_body_line_length: usize,
    pub allowed_types: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub forbidden_patterns: Vec<String>,
}

impl Default for CommitPolicy {
    fn default() -> Self {
        Self {
            require_conventional: true,
            require_signed: false,
            require_linked_issue: false,
            max_subject_length: 72,
            max_body_line_length: 100,
            allowed_types: vec![
                "feat".to_string(),
                "fix".to_string(),
                "docs".to_string(),
                "style".to_string(),
                "refactor".to_string(),
                "perf".to_string(),
                "test".to_string(),
                "build".to_string(),
                "ci".to_string(),
                "chore".to_string(),
                "revert".to_string(),
            ],
            allowed_scopes: vec![],
            forbidden_patterns: vec![
                "WIP".to_string(),
                "fixup!".to_string(),
                "squash!".to_string(),
            ],
        }
    }
}

/// Commit validation result
#[derive(Clone, Debug)]
pub struct CommitValidation {
    pub commit_hash: String,
    pub is_valid: bool,
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct ValidationError {
    pub code: String,
    pub message: String,
    pub severity: ErrorSeverity,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ErrorSeverity {
    Error,
    Warning,
    Info,
}

/// Commit validator
pub struct CommitValidator {
    policy: CommitPolicy,
}

impl CommitValidator {
    pub fn new(policy: CommitPolicy) -> Self {
        Self { policy }
    }

    pub fn validate(&self, commit: &Commit) -> CommitValidation {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        let lines: Vec<&str> = commit.message.lines().collect();
        let subject = lines.first().unwrap_or(&"");

        // Check subject length
        if subject.len() > self.policy.max_subject_length {
            errors.push(ValidationError {
                code: "E001".to_string(),
                message: format!(
                    "Subject line too long: {} chars (max: {})",
                    subject.len(),
                    self.policy.max_subject_length
                ),
                severity: ErrorSeverity::Error,
            });
        }

        // Check conventional commit format
        if self.policy.require_conventional {
            if let Some(err) = self.validate_conventional(subject) {
                errors.push(err);
            }
        }

        // Check for forbidden patterns
        for pattern in &self.policy.forbidden_patterns {
            if commit.message.contains(pattern) {
                errors.push(ValidationError {
                    code: "E003".to_string(),
                    message: format!("Commit contains forbidden pattern: {}", pattern),
                    severity: ErrorSeverity::Error,
                });
            }
        }

        // Check signature
        if self.policy.require_signed {
            match &commit.signature {
                None => {
                    errors.push(ValidationError {
                        code: "E004".to_string(),
                        message: "Commit is not signed".to_string(),
                        severity: ErrorSeverity::Error,
                    });
                }
                Some(sig) if sig.status != SignatureStatus::Valid => {
                    errors.push(ValidationError {
                        code: "E005".to_string(),
                        message: format!("Invalid signature: {:?}", sig.status),
                        severity: ErrorSeverity::Error,
                    });
                }
                _ => {}
            }
        }

        // Check linked issue
        if self.policy.require_linked_issue {
            let has_issue = commit.message.contains('#')
                || commit.message.to_lowercase().contains("closes")
                || commit.message.to_lowercase().contains("fixes")
                || commit.message.to_lowercase().contains("resolves");

            if !has_issue {
                warnings.push("No linked issue found in commit message".to_string());
            }
        }

        // Check body line length
        for (i, line) in lines.iter().enumerate().skip(2) {
            if line.len() > self.policy.max_body_line_length {
                warnings.push(format!(
                    "Body line {} too long: {} chars",
                    i + 1,
                    line.len()
                ));
            }
        }

        CommitValidation {
            commit_hash: commit.hash.clone(),
            is_valid: errors.is_empty(),
            errors,
            warnings,
        }
    }

    fn validate_conventional(&self, subject: &str) -> Option<ValidationError> {
        // Parse: type(scope)!: description
        let re_pattern = r"^([a-z]+)(\([a-z0-9-]+\))?!?:\s.+$";

        // Simplified check without regex
        if let Some(colon_pos) = subject.find(':') {
            let prefix = &subject[..colon_pos];
            let type_part = if let Some(paren) = prefix.find('(') {
                &prefix[..paren]
            } else {
                prefix.trim_end_matches('!')
            };

            if !self.policy.allowed_types.iter().any(|t| t == type_part) {
                return Some(ValidationError {
                    code: "E002".to_string(),
                    message: format!("Invalid commit type: {}", type_part),
                    severity: ErrorSeverity::Error,
                });
            }

            // Check scope if specified
            if !self.policy.allowed_scopes.is_empty() {
                if let Some(start) = prefix.find('(') {
                    if let Some(end) = prefix.find(')') {
                        let scope = &prefix[start + 1..end];
                        if !self.policy.allowed_scopes.contains(&scope.to_string()) {
                            return Some(ValidationError {
                                code: "E006".to_string(),
                                message: format!("Invalid scope: {}", scope),
                                severity: ErrorSeverity::Error,
                            });
                        }
                    }
                }
            }

            None
        } else {
            Some(ValidationError {
                code: "E002".to_string(),
                message: "Not a conventional commit format (missing type: prefix)".to_string(),
                severity: ErrorSeverity::Error,
            })
        }
    }
}

// ============================================================================
// Pull Request Management
// ============================================================================

/// Pull request
#[derive(Clone, Debug)]
pub struct PullRequest {
    pub id: u64,
    pub title: String,
    pub description: String,
    pub author: Author,
    pub source_branch: String,
    pub target_branch: String,
    pub commits: Vec<String>,
    pub status: PrStatus,
    pub reviews: Vec<Review>,
    pub checks: Vec<CiCheck>,
    pub labels: Vec<String>,
    pub created_at: SystemTime,
    pub updated_at: SystemTime,
    pub merged_at: Option<SystemTime>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum PrStatus {
    Draft,
    Open,
    Approved,
    ChangesRequested,
    Merged,
    Closed,
}

#[derive(Clone, Debug)]
pub struct Review {
    pub reviewer: Author,
    pub status: ReviewStatus,
    pub comments: Vec<ReviewComment>,
    pub submitted_at: SystemTime,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ReviewStatus {
    Pending,
    Approved,
    ChangesRequested,
    Commented,
    Dismissed,
}

#[derive(Clone, Debug)]
pub struct ReviewComment {
    pub file: String,
    pub line: usize,
    pub body: String,
    pub resolved: bool,
}

#[derive(Clone, Debug)]
pub struct CiCheck {
    pub name: String,
    pub status: CheckStatus,
    pub details_url: Option<String>,
    pub started_at: SystemTime,
    pub completed_at: Option<SystemTime>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum CheckStatus {
    Pending,
    Running,
    Success,
    Failure,
    Cancelled,
    Skipped,
}

/// PR merge requirements
#[derive(Clone, Debug)]
pub struct MergeRequirements {
    pub min_approvals: usize,
    pub require_ci_pass: bool,
    pub require_no_conflicts: bool,
    pub require_signed_commits: bool,
    pub require_linear_history: bool,
    pub allowed_merge_methods: Vec<MergeMethod>,
    pub required_reviewers: Vec<String>,
    pub required_checks: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum MergeMethod {
    Merge,
    Squash,
    Rebase,
    FastForward,
}

impl Default for MergeRequirements {
    fn default() -> Self {
        Self {
            min_approvals: 1,
            require_ci_pass: true,
            require_no_conflicts: true,
            require_signed_commits: false,
            require_linear_history: false,
            allowed_merge_methods: vec![MergeMethod::Squash, MergeMethod::Merge],
            required_reviewers: vec![],
            required_checks: vec!["ci/build".to_string(), "ci/test".to_string()],
        }
    }
}

/// PR manager
pub struct PullRequestManager {
    requirements: MergeRequirements,
}

impl PullRequestManager {
    pub fn new(requirements: MergeRequirements) -> Self {
        Self { requirements }
    }

    pub fn can_merge(&self, pr: &PullRequest) -> MergeCheck {
        let mut blockers = Vec::new();
        let mut warnings = Vec::new();

        // Check approvals
        let approvals = pr
            .reviews
            .iter()
            .filter(|r| r.status == ReviewStatus::Approved)
            .count();

        if approvals < self.requirements.min_approvals {
            blockers.push(format!(
                "Need {} approvals, have {}",
                self.requirements.min_approvals, approvals
            ));
        }

        // Check for changes requested
        if pr
            .reviews
            .iter()
            .any(|r| r.status == ReviewStatus::ChangesRequested)
        {
            blockers.push("Changes requested by reviewer".to_string());
        }

        // Check CI
        if self.requirements.require_ci_pass {
            let failed_checks: Vec<_> = pr
                .checks
                .iter()
                .filter(|c| c.status == CheckStatus::Failure)
                .map(|c| c.name.clone())
                .collect();

            if !failed_checks.is_empty() {
                blockers.push(format!("Failed checks: {}", failed_checks.join(", ")));
            }

            let pending_checks: Vec<_> = pr
                .checks
                .iter()
                .filter(|c| c.status == CheckStatus::Pending || c.status == CheckStatus::Running)
                .map(|c| c.name.clone())
                .collect();

            if !pending_checks.is_empty() {
                warnings.push(format!("Pending checks: {}", pending_checks.join(", ")));
            }
        }

        // Check required checks
        for required in &self.requirements.required_checks {
            if !pr
                .checks
                .iter()
                .any(|c| &c.name == required && c.status == CheckStatus::Success)
            {
                blockers.push(format!("Required check not passing: {}", required));
            }
        }

        // Check required reviewers
        for required in &self.requirements.required_reviewers {
            if !pr
                .reviews
                .iter()
                .any(|r| &r.reviewer.email == required && r.status == ReviewStatus::Approved)
            {
                blockers.push(format!("Required reviewer not approved: {}", required));
            }
        }

        // Check unresolved comments
        let unresolved = pr
            .reviews
            .iter()
            .flat_map(|r| &r.comments)
            .filter(|c| !c.resolved)
            .count();

        if unresolved > 0 {
            warnings.push(format!("{} unresolved comments", unresolved));
        }

        MergeCheck {
            can_merge: blockers.is_empty(),
            blockers,
            warnings,
            suggested_method: self.suggest_merge_method(pr),
        }
    }

    fn suggest_merge_method(&self, pr: &PullRequest) -> MergeMethod {
        // Suggest squash for single-commit or small PRs
        if pr.commits.len() <= 3 {
            if self
                .requirements
                .allowed_merge_methods
                .contains(&MergeMethod::Squash)
            {
                return MergeMethod::Squash;
            }
        }

        // Suggest rebase for linear history
        if self.requirements.require_linear_history {
            if self
                .requirements
                .allowed_merge_methods
                .contains(&MergeMethod::Rebase)
            {
                return MergeMethod::Rebase;
            }
        }

        // Default to merge
        self.requirements
            .allowed_merge_methods
            .first()
            .cloned()
            .unwrap_or(MergeMethod::Merge)
    }
}

#[derive(Debug)]
pub struct MergeCheck {
    pub can_merge: bool,
    pub blockers: Vec<String>,
    pub warnings: Vec<String>,
    pub suggested_method: MergeMethod,
}

// ============================================================================
// Release Management
// ============================================================================

/// Release
#[derive(Clone, Debug)]
pub struct Release {
    pub version: String,
    pub tag_name: String,
    pub name: String,
    pub description: String,
    pub target_commit: String,
    pub assets: Vec<ReleaseAsset>,
    pub is_prerelease: bool,
    pub is_draft: bool,
    pub created_at: SystemTime,
    pub published_at: Option<SystemTime>,
}

#[derive(Clone, Debug)]
pub struct ReleaseAsset {
    pub name: String,
    pub content_type: String,
    pub size: u64,
    pub download_url: String,
}

/// Release manager
pub struct ReleaseManager {
    strategy: BranchStrategy,
}

impl ReleaseManager {
    pub fn new(strategy: BranchStrategy) -> Self {
        Self { strategy }
    }

    pub fn create_release_branch(&self, version: &str) -> Result<Branch, String> {
        if !self.strategy.supports_release_branches() {
            return Err(format!("{} doesn't use release branches", self.strategy));
        }

        let branch_name = format!("release/{}", version);

        Ok(Branch {
            name: branch_name,
            branch_type: BranchType::Release,
            head: String::new(), // Would be set by git
            upstream: None,
            created_at: SystemTime::now(),
            last_commit_at: SystemTime::now(),
            is_protected: true,
        })
    }

    pub fn generate_release_notes(&self, commits: &[Commit]) -> ReleaseNotes {
        let mut features = Vec::new();
        let mut fixes = Vec::new();
        let mut breaking = Vec::new();
        let mut other = Vec::new();

        for commit in commits {
            let first_line = commit.message.lines().next().unwrap_or("");

            // Check for breaking change
            if first_line.contains('!') || commit.message.contains("BREAKING CHANGE") {
                breaking.push(ReleaseNote {
                    commit_hash: commit.short_hash.clone(),
                    message: first_line.to_string(),
                    author: commit.author.name.clone(),
                });
                continue;
            }

            // Categorize by type
            if first_line.starts_with("feat") {
                features.push(ReleaseNote {
                    commit_hash: commit.short_hash.clone(),
                    message: first_line.to_string(),
                    author: commit.author.name.clone(),
                });
            } else if first_line.starts_with("fix") {
                fixes.push(ReleaseNote {
                    commit_hash: commit.short_hash.clone(),
                    message: first_line.to_string(),
                    author: commit.author.name.clone(),
                });
            } else if !first_line.starts_with("chore") && !first_line.starts_with("docs") {
                other.push(ReleaseNote {
                    commit_hash: commit.short_hash.clone(),
                    message: first_line.to_string(),
                    author: commit.author.name.clone(),
                });
            }
        }

        ReleaseNotes {
            features,
            fixes,
            breaking,
            other,
        }
    }

    pub fn suggest_next_version(&self, current: &str, commits: &[Commit]) -> String {
        let parts: Vec<u32> = current
            .trim_start_matches('v')
            .split('.')
            .filter_map(|p| p.parse().ok())
            .collect();

        let (major, minor, patch) = match parts.as_slice() {
            [a, b, c, ..] => (*a, *b, *c),
            [a, b] => (*a, *b, 0),
            [a] => (*a, 0, 0),
            [] => (0, 0, 0),
        };

        // Check for breaking changes
        let has_breaking = commits.iter().any(|c| {
            let msg = &c.message;
            msg.contains("BREAKING CHANGE")
                || msg.lines().next().map(|l| l.contains('!')).unwrap_or(false)
        });

        // Check for features
        let has_features = commits.iter().any(|c| {
            c.message
                .lines()
                .next()
                .map(|l| l.starts_with("feat"))
                .unwrap_or(false)
        });

        if has_breaking && major > 0 {
            format!("{}.0.0", major + 1)
        } else if has_features {
            format!("{}.{}.0", major, minor + 1)
        } else {
            format!("{}.{}.{}", major, minor, patch + 1)
        }
    }
}

#[derive(Debug)]
pub struct ReleaseNotes {
    pub features: Vec<ReleaseNote>,
    pub fixes: Vec<ReleaseNote>,
    pub breaking: Vec<ReleaseNote>,
    pub other: Vec<ReleaseNote>,
}

impl ReleaseNotes {
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();

        if !self.breaking.is_empty() {
            md.push_str("## ⚠️ Breaking Changes\n\n");
            for note in &self.breaking {
                md.push_str(&format!("- {} ({})\n", note.message, note.commit_hash));
            }
            md.push('\n');
        }

        if !self.features.is_empty() {
            md.push_str("## ✨ Features\n\n");
            for note in &self.features {
                md.push_str(&format!("- {} ({})\n", note.message, note.commit_hash));
            }
            md.push('\n');
        }

        if !self.fixes.is_empty() {
            md.push_str("## 🐛 Bug Fixes\n\n");
            for note in &self.fixes {
                md.push_str(&format!("- {} ({})\n", note.message, note.commit_hash));
            }
            md.push('\n');
        }

        if !self.other.is_empty() {
            md.push_str("## 📝 Other Changes\n\n");
            for note in &self.other {
                md.push_str(&format!("- {} ({})\n", note.message, note.commit_hash));
            }
            md.push('\n');
        }

        md
    }
}

#[derive(Debug)]
pub struct ReleaseNote {
    pub commit_hash: String,
    pub message: String,
    pub author: String,
}

// ============================================================================
// Git Hooks
// ============================================================================

/// Git hook types
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum HookType {
    PreCommit,
    CommitMsg,
    PrepareCommitMsg,
    PostCommit,
    PrePush,
    PostCheckout,
    PreRebase,
    PostMerge,
    PreReceive,
    Update,
    PostReceive,
}

impl fmt::Display for HookType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HookType::PreCommit => write!(f, "pre-commit"),
            HookType::CommitMsg => write!(f, "commit-msg"),
            HookType::PrepareCommitMsg => write!(f, "prepare-commit-msg"),
            HookType::PostCommit => write!(f, "post-commit"),
            HookType::PrePush => write!(f, "pre-push"),
            HookType::PostCheckout => write!(f, "post-checkout"),
            HookType::PreRebase => write!(f, "pre-rebase"),
            HookType::PostMerge => write!(f, "post-merge"),
            HookType::PreReceive => write!(f, "pre-receive"),
            HookType::Update => write!(f, "update"),
            HookType::PostReceive => write!(f, "post-receive"),
        }
    }
}

/// Git hook generator
pub struct HookGenerator;

impl HookGenerator {
    pub fn generate_pre_commit() -> String {
        r#"#!/bin/sh
# Pre-commit hook for Rust projects

set -e

echo "Running pre-commit checks..."

# Format check
echo "Checking formatting..."
cargo fmt -- --check

# Lint check
echo "Running clippy..."
cargo clippy -- -D warnings

# Security audit
if command -v cargo-audit &> /dev/null; then
    echo "Running security audit..."
    cargo audit
fi

# Run tests
echo "Running tests..."
cargo test --lib

echo "Pre-commit checks passed!"
"#
        .to_string()
    }

    pub fn generate_commit_msg() -> String {
        r#"#!/bin/sh
# Commit message hook

COMMIT_MSG_FILE=$1
COMMIT_MSG=$(cat "$COMMIT_MSG_FILE")

# Check conventional commit format
if ! echo "$COMMIT_MSG" | grep -qE "^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\(.+\))?(!)?: .+"; then
    echo "ERROR: Commit message doesn't follow conventional commit format."
    echo ""
    echo "Expected format: type(scope): description"
    echo ""
    echo "Types: feat, fix, docs, style, refactor, perf, test, build, ci, chore, revert"
    echo ""
    exit 1
fi

# Check subject line length
SUBJECT=$(echo "$COMMIT_MSG" | head -n1)
if [ ${#SUBJECT} -gt 72 ]; then
    echo "ERROR: Subject line too long (${#SUBJECT} > 72 characters)"
    exit 1
fi

echo "Commit message validated!"
"#.to_string()
    }

    pub fn generate_pre_push() -> String {
        r#"#!/bin/sh
# Pre-push hook

set -e

echo "Running pre-push checks..."

# Full test suite
echo "Running full test suite..."
cargo test

# Build in release mode
echo "Building release..."
cargo build --release

# Check documentation
echo "Checking documentation..."
cargo doc --no-deps

echo "Pre-push checks passed!"
"#
        .to_string()
    }
}

// ============================================================================
// Main Demonstration
// ============================================================================

fn main() {
    println!("=== Git Workflow Manager for Rust Projects ===\n");

    // Branch strategy
    println!("1. Branch Strategy Configuration");
    println!("─────────────────────────────────────────────────────────────────────────");

    let strategies = [
        BranchStrategy::GitFlow,
        BranchStrategy::GitHubFlow,
        BranchStrategy::TrunkBased,
    ];

    for strategy in &strategies {
        println!("  {}:", strategy);
        println!("    Main branch: {}", strategy.main_branch());
        if let Some(dev) = strategy.develop_branch() {
            println!("    Develop branch: {}", dev);
        }
        println!("    Feature base: {}", strategy.feature_base());
        println!(
            "    Release branches: {}",
            strategy.supports_release_branches()
        );
        println!();
    }

    // Commit validation
    println!("2. Commit Validation");
    println!("─────────────────────────────────────────────────────────────────────────");

    let policy = CommitPolicy::default();
    let validator = CommitValidator::new(policy);

    let test_commits = vec![
        Commit {
            hash: "abc123def456".to_string(),
            short_hash: "abc123d".to_string(),
            author: Author {
                name: "Alice".to_string(),
                email: "alice@example.com".to_string(),
            },
            message: "feat(auth): add OAuth2 support\n\nImplements GitHub and GitLab OAuth."
                .to_string(),
            timestamp: SystemTime::now(),
            parent_hashes: vec!["def789".to_string()],
            tree_hash: "tree123".to_string(),
            signature: None,
        },
        Commit {
            hash: "def456abc789".to_string(),
            short_hash: "def456a".to_string(),
            author: Author {
                name: "Bob".to_string(),
                email: "bob@example.com".to_string(),
            },
            message: "Updated the code".to_string(),
            timestamp: SystemTime::now(),
            parent_hashes: vec!["abc123".to_string()],
            tree_hash: "tree456".to_string(),
            signature: None,
        },
        Commit {
            hash: "ghi789jkl012".to_string(),
            short_hash: "ghi789j".to_string(),
            author: Author {
                name: "Charlie".to_string(),
                email: "charlie@example.com".to_string(),
            },
            message: "WIP: working on feature".to_string(),
            timestamp: SystemTime::now(),
            parent_hashes: vec![],
            tree_hash: "tree789".to_string(),
            signature: None,
        },
    ];

    for commit in &test_commits {
        let validation = validator.validate(commit);
        let status = if validation.is_valid { "✓" } else { "✗" };
        println!(
            "  {} {}: {}",
            status,
            commit.short_hash,
            commit.message.lines().next().unwrap_or("")
        );

        for error in &validation.errors {
            println!("    ❌ [{}] {}", error.code, error.message);
        }
        for warning in &validation.warnings {
            println!("    ⚠️  {}", warning);
        }
    }
    println!();

    // Pull request management
    println!("3. Pull Request Management");
    println!("─────────────────────────────────────────────────────────────────────────");

    let requirements = MergeRequirements {
        min_approvals: 2,
        require_ci_pass: true,
        ..Default::default()
    };

    let pr_manager = PullRequestManager::new(requirements);

    let pr = PullRequest {
        id: 42,
        title: "feat(api): add new endpoints".to_string(),
        description: "This PR adds new API endpoints.".to_string(),
        author: Author {
            name: "Alice".to_string(),
            email: "alice@example.com".to_string(),
        },
        source_branch: "feature/new-endpoints".to_string(),
        target_branch: "main".to_string(),
        commits: vec!["abc123".to_string(), "def456".to_string()],
        status: PrStatus::Open,
        reviews: vec![Review {
            reviewer: Author {
                name: "Bob".to_string(),
                email: "bob@example.com".to_string(),
            },
            status: ReviewStatus::Approved,
            comments: vec![],
            submitted_at: SystemTime::now(),
        }],
        checks: vec![
            CiCheck {
                name: "ci/build".to_string(),
                status: CheckStatus::Success,
                details_url: None,
                started_at: SystemTime::now(),
                completed_at: Some(SystemTime::now()),
            },
            CiCheck {
                name: "ci/test".to_string(),
                status: CheckStatus::Success,
                details_url: None,
                started_at: SystemTime::now(),
                completed_at: Some(SystemTime::now()),
            },
        ],
        labels: vec!["enhancement".to_string()],
        created_at: SystemTime::now(),
        updated_at: SystemTime::now(),
        merged_at: None,
    };

    let merge_check = pr_manager.can_merge(&pr);

    println!("  PR #{}: {}", pr.id, pr.title);
    println!(
        "  Can merge: {}",
        if merge_check.can_merge {
            "✓ Yes"
        } else {
            "✗ No"
        }
    );

    if !merge_check.blockers.is_empty() {
        println!("  Blockers:");
        for blocker in &merge_check.blockers {
            println!("    ❌ {}", blocker);
        }
    }

    if !merge_check.warnings.is_empty() {
        println!("  Warnings:");
        for warning in &merge_check.warnings {
            println!("    ⚠️  {}", warning);
        }
    }

    println!(
        "  Suggested merge method: {:?}",
        merge_check.suggested_method
    );
    println!();

    // Release management
    println!("4. Release Management");
    println!("─────────────────────────────────────────────────────────────────────────");

    let release_manager = ReleaseManager::new(BranchStrategy::GitFlow);

    let release_commits = vec![
        Commit {
            hash: "aaa111".to_string(),
            short_hash: "aaa111".to_string(),
            author: Author {
                name: "Alice".to_string(),
                email: "alice@example.com".to_string(),
            },
            message: "feat(api): add new endpoint".to_string(),
            timestamp: SystemTime::now(),
            parent_hashes: vec![],
            tree_hash: "".to_string(),
            signature: None,
        },
        Commit {
            hash: "bbb222".to_string(),
            short_hash: "bbb222".to_string(),
            author: Author {
                name: "Bob".to_string(),
                email: "bob@example.com".to_string(),
            },
            message: "fix(auth): correct token validation".to_string(),
            timestamp: SystemTime::now(),
            parent_hashes: vec![],
            tree_hash: "".to_string(),
            signature: None,
        },
        Commit {
            hash: "ccc333".to_string(),
            short_hash: "ccc333".to_string(),
            author: Author {
                name: "Charlie".to_string(),
                email: "c@example.com".to_string(),
            },
            message:
                "feat(db)!: change database schema\n\nBREAKING CHANGE: Schema migration required"
                    .to_string(),
            timestamp: SystemTime::now(),
            parent_hashes: vec![],
            tree_hash: "".to_string(),
            signature: None,
        },
    ];

    let next_version = release_manager.suggest_next_version("1.2.3", &release_commits);
    println!("  Current version: 1.2.3");
    println!("  Suggested next version: {}", next_version);
    println!();

    let notes = release_manager.generate_release_notes(&release_commits);
    println!("  Release Notes:");
    println!("  ───────────────────────────────────────────────────────────────────");
    print!("{}", notes.to_markdown());
    println!();

    // Git hooks
    println!("5. Git Hooks");
    println!("─────────────────────────────────────────────────────────────────────────");

    println!("  Available hooks:");
    println!("    - pre-commit: Format, lint, and test checks");
    println!("    - commit-msg: Conventional commit validation");
    println!("    - pre-push: Full test suite and release build");
    println!();

    println!("  Sample pre-commit hook:");
    println!("  ───────────────────────────────────────────────────────────────────");
    for line in HookGenerator::generate_pre_commit().lines().take(10) {
        println!("  {}", line);
    }
    println!("  ...");

    println!("\n=== Git Workflow Manager Demo Complete ===");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_branch_type_from_name() {
        assert_eq!(BranchType::from_name("main"), BranchType::Main);
        assert_eq!(BranchType::from_name("master"), BranchType::Main);
        assert_eq!(BranchType::from_name("develop"), BranchType::Develop);
        assert_eq!(
            BranchType::from_name("feature/new-feature"),
            BranchType::Feature
        );
        assert_eq!(BranchType::from_name("bugfix/fix-bug"), BranchType::Bugfix);
        assert_eq!(BranchType::from_name("hotfix/urgent"), BranchType::Hotfix);
        assert_eq!(BranchType::from_name("release/1.0"), BranchType::Release);
    }

    #[test]
    fn test_branch_strategy() {
        let git_flow = BranchStrategy::GitFlow;
        assert_eq!(git_flow.main_branch(), "main");
        assert_eq!(git_flow.develop_branch(), Some("develop"));
        assert!(git_flow.supports_release_branches());

        let github_flow = BranchStrategy::GitHubFlow;
        assert_eq!(github_flow.main_branch(), "main");
        assert_eq!(github_flow.develop_branch(), None);
        assert!(!github_flow.supports_release_branches());
    }

    #[test]
    fn test_commit_validation_valid() {
        let policy = CommitPolicy::default();
        let validator = CommitValidator::new(policy);

        let commit = Commit {
            hash: "abc123".to_string(),
            short_hash: "abc123".to_string(),
            author: Author {
                name: "Test".to_string(),
                email: "test@test.com".to_string(),
            },
            message: "feat(scope): add new feature".to_string(),
            timestamp: SystemTime::now(),
            parent_hashes: vec![],
            tree_hash: "".to_string(),
            signature: None,
        };

        let result = validator.validate(&commit);
        assert!(result.is_valid);
    }

    #[test]
    fn test_commit_validation_invalid() {
        let policy = CommitPolicy::default();
        let validator = CommitValidator::new(policy);

        let commit = Commit {
            hash: "abc123".to_string(),
            short_hash: "abc123".to_string(),
            author: Author {
                name: "Test".to_string(),
                email: "test@test.com".to_string(),
            },
            message: "not a conventional commit".to_string(),
            timestamp: SystemTime::now(),
            parent_hashes: vec![],
            tree_hash: "".to_string(),
            signature: None,
        };

        let result = validator.validate(&commit);
        assert!(!result.is_valid);
    }

    #[test]
    fn test_commit_validation_forbidden_pattern() {
        let policy = CommitPolicy::default();
        let validator = CommitValidator::new(policy);

        let commit = Commit {
            hash: "abc123".to_string(),
            short_hash: "abc123".to_string(),
            author: Author {
                name: "Test".to_string(),
                email: "test@test.com".to_string(),
            },
            message: "WIP: feat(scope): work in progress".to_string(),
            timestamp: SystemTime::now(),
            parent_hashes: vec![],
            tree_hash: "".to_string(),
            signature: None,
        };

        let result = validator.validate(&commit);
        assert!(!result.is_valid);
        assert!(result
            .errors
            .iter()
            .any(|e| e.message.contains("forbidden")));
    }

    #[test]
    fn test_pr_merge_check() {
        let requirements = MergeRequirements {
            min_approvals: 1,
            require_ci_pass: true,
            ..Default::default()
        };

        let manager = PullRequestManager::new(requirements);

        let pr = PullRequest {
            id: 1,
            title: "Test PR".to_string(),
            description: "".to_string(),
            author: Author {
                name: "Test".to_string(),
                email: "test@test.com".to_string(),
            },
            source_branch: "feature/test".to_string(),
            target_branch: "main".to_string(),
            commits: vec!["abc".to_string()],
            status: PrStatus::Open,
            reviews: vec![Review {
                reviewer: Author {
                    name: "Reviewer".to_string(),
                    email: "reviewer@test.com".to_string(),
                },
                status: ReviewStatus::Approved,
                comments: vec![],
                submitted_at: SystemTime::now(),
            }],
            checks: vec![
                CiCheck {
                    name: "ci/build".to_string(),
                    status: CheckStatus::Success,
                    details_url: None,
                    started_at: SystemTime::now(),
                    completed_at: Some(SystemTime::now()),
                },
                CiCheck {
                    name: "ci/test".to_string(),
                    status: CheckStatus::Success,
                    details_url: None,
                    started_at: SystemTime::now(),
                    completed_at: Some(SystemTime::now()),
                },
            ],
            labels: vec![],
            created_at: SystemTime::now(),
            updated_at: SystemTime::now(),
            merged_at: None,
        };

        let check = manager.can_merge(&pr);
        assert!(check.can_merge);
    }

    #[test]
    fn test_version_suggestion() {
        let manager = ReleaseManager::new(BranchStrategy::GitFlow);

        // Feature -> minor bump
        let commits = vec![Commit {
            hash: "abc".to_string(),
            short_hash: "abc".to_string(),
            author: Author {
                name: "Test".to_string(),
                email: "test@test.com".to_string(),
            },
            message: "feat: new feature".to_string(),
            timestamp: SystemTime::now(),
            parent_hashes: vec![],
            tree_hash: "".to_string(),
            signature: None,
        }];

        assert_eq!(manager.suggest_next_version("1.2.3", &commits), "1.3.0");

        // Fix only -> patch bump
        let fix_commits = vec![Commit {
            hash: "def".to_string(),
            short_hash: "def".to_string(),
            author: Author {
                name: "Test".to_string(),
                email: "test@test.com".to_string(),
            },
            message: "fix: bug fix".to_string(),
            timestamp: SystemTime::now(),
            parent_hashes: vec![],
            tree_hash: "".to_string(),
            signature: None,
        }];

        assert_eq!(manager.suggest_next_version("1.2.3", &fix_commits), "1.2.4");
    }

    #[test]
    fn test_release_notes() {
        let manager = ReleaseManager::new(BranchStrategy::GitFlow);

        let commits = vec![
            Commit {
                hash: "abc".to_string(),
                short_hash: "abc".to_string(),
                author: Author {
                    name: "Test".to_string(),
                    email: "test@test.com".to_string(),
                },
                message: "feat: new feature".to_string(),
                timestamp: SystemTime::now(),
                parent_hashes: vec![],
                tree_hash: "".to_string(),
                signature: None,
            },
            Commit {
                hash: "def".to_string(),
                short_hash: "def".to_string(),
                author: Author {
                    name: "Test".to_string(),
                    email: "test@test.com".to_string(),
                },
                message: "fix: bug fix".to_string(),
                timestamp: SystemTime::now(),
                parent_hashes: vec![],
                tree_hash: "".to_string(),
                signature: None,
            },
        ];

        let notes = manager.generate_release_notes(&commits);
        assert_eq!(notes.features.len(), 1);
        assert_eq!(notes.fixes.len(), 1);
    }

    #[test]
    fn test_hook_generation() {
        let pre_commit = HookGenerator::generate_pre_commit();
        assert!(pre_commit.contains("#!/bin/sh"));
        assert!(pre_commit.contains("cargo fmt"));
        assert!(pre_commit.contains("cargo clippy"));

        let commit_msg = HookGenerator::generate_commit_msg();
        assert!(commit_msg.contains("conventional commit"));
    }
}
