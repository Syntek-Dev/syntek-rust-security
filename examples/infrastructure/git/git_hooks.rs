//! Git Hooks and Security Automation
//!
//! Pre-commit hooks, commit message validation, branch protection,
//! and automated security checks for Git workflows.

use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

/// Hook types supported by Git
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HookType {
    PreCommit,
    PrepareCommitMsg,
    CommitMsg,
    PostCommit,
    PreRebase,
    PostRewrite,
    PostCheckout,
    PostMerge,
    PrePush,
    PreAutoGc,
    PostUpdate,
    PreReceive,
    Update,
    PostReceive,
}

impl HookType {
    pub fn as_str(&self) -> &'static str {
        match self {
            HookType::PreCommit => "pre-commit",
            HookType::PrepareCommitMsg => "prepare-commit-msg",
            HookType::CommitMsg => "commit-msg",
            HookType::PostCommit => "post-commit",
            HookType::PreRebase => "pre-rebase",
            HookType::PostRewrite => "post-rewrite",
            HookType::PostCheckout => "post-checkout",
            HookType::PostMerge => "post-merge",
            HookType::PrePush => "pre-push",
            HookType::PreAutoGc => "pre-auto-gc",
            HookType::PostUpdate => "post-update",
            HookType::PreReceive => "pre-receive",
            HookType::Update => "update",
            HookType::PostReceive => "post-receive",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "pre-commit" => Some(HookType::PreCommit),
            "prepare-commit-msg" => Some(HookType::PrepareCommitMsg),
            "commit-msg" => Some(HookType::CommitMsg),
            "post-commit" => Some(HookType::PostCommit),
            "pre-rebase" => Some(HookType::PreRebase),
            "post-rewrite" => Some(HookType::PostRewrite),
            "post-checkout" => Some(HookType::PostCheckout),
            "post-merge" => Some(HookType::PostMerge),
            "pre-push" => Some(HookType::PrePush),
            "pre-auto-gc" => Some(HookType::PreAutoGc),
            "post-update" => Some(HookType::PostUpdate),
            "pre-receive" => Some(HookType::PreReceive),
            "update" => Some(HookType::Update),
            "post-receive" => Some(HookType::PostReceive),
            _ => None,
        }
    }
}

/// Result of running a hook check
#[derive(Debug, Clone)]
pub struct CheckResult {
    pub name: String,
    pub passed: bool,
    pub message: String,
    pub suggestions: Vec<String>,
    pub files_affected: Vec<PathBuf>,
}

impl CheckResult {
    pub fn pass(name: &str, message: &str) -> Self {
        Self {
            name: name.into(),
            passed: true,
            message: message.into(),
            suggestions: vec![],
            files_affected: vec![],
        }
    }

    pub fn fail(name: &str, message: &str) -> Self {
        Self {
            name: name.into(),
            passed: false,
            message: message.into(),
            suggestions: vec![],
            files_affected: vec![],
        }
    }

    pub fn with_suggestion(mut self, suggestion: &str) -> Self {
        self.suggestions.push(suggestion.into());
        self
    }

    pub fn with_files(mut self, files: Vec<PathBuf>) -> Self {
        self.files_affected = files;
        self
    }
}

/// Pre-commit check trait
pub trait PreCommitCheck {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn run(&self, staged_files: &[PathBuf]) -> CheckResult;
}

/// Secret detection check
pub struct SecretDetector {
    patterns: Vec<SecretPattern>,
    allowlist: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SecretPattern {
    pub name: String,
    pub pattern: String,
    pub severity: SecretSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl SecretDetector {
    pub fn new() -> Self {
        Self {
            patterns: Self::default_patterns(),
            allowlist: vec![],
        }
    }

    fn default_patterns() -> Vec<SecretPattern> {
        vec![
            SecretPattern {
                name: "AWS Access Key".into(),
                pattern: r"AKIA[0-9A-Z]{16}".into(),
                severity: SecretSeverity::Critical,
            },
            SecretPattern {
                name: "AWS Secret Key".into(),
                pattern: r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]".into(),
                severity: SecretSeverity::Critical,
            },
            SecretPattern {
                name: "GitHub Token".into(),
                pattern: r"ghp_[0-9a-zA-Z]{36}".into(),
                severity: SecretSeverity::Critical,
            },
            SecretPattern {
                name: "GitHub OAuth".into(),
                pattern: r"gho_[0-9a-zA-Z]{36}".into(),
                severity: SecretSeverity::Critical,
            },
            SecretPattern {
                name: "Slack Token".into(),
                pattern: r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*".into(),
                severity: SecretSeverity::High,
            },
            SecretPattern {
                name: "Private Key".into(),
                pattern: r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----".into(),
                severity: SecretSeverity::Critical,
            },
            SecretPattern {
                name: "Generic API Key".into(),
                pattern: r"(?i)(api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"][0-9a-zA-Z]{16,}['\"]".into(),
                severity: SecretSeverity::Medium,
            },
            SecretPattern {
                name: "Generic Secret".into(),
                pattern: r"(?i)(secret|password|passwd|pwd)['\"]?\s*[:=]\s*['\"][^'\"]{8,}['\"]".into(),
                severity: SecretSeverity::Medium,
            },
            SecretPattern {
                name: "JWT Token".into(),
                pattern: r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/]*".into(),
                severity: SecretSeverity::High,
            },
        ]
    }

    pub fn add_allowlist(&mut self, pattern: &str) {
        self.allowlist.push(pattern.into());
    }

    pub fn scan_content(&self, content: &str, file_path: &Path) -> Vec<SecretMatch> {
        let mut matches = vec![];

        for line_num in 1..=content.lines().count() {
            let line = content.lines().nth(line_num - 1).unwrap_or("");

            // Skip allowlisted patterns
            if self.allowlist.iter().any(|a| line.contains(a)) {
                continue;
            }

            for pattern in &self.patterns {
                // Simplified pattern matching (real impl would use regex)
                if self.simple_match(&pattern.pattern, line) {
                    matches.push(SecretMatch {
                        pattern_name: pattern.name.clone(),
                        file_path: file_path.to_path_buf(),
                        line_number: line_num,
                        severity: pattern.severity,
                    });
                }
            }
        }

        matches
    }

    fn simple_match(&self, pattern: &str, text: &str) -> bool {
        // Simplified matching for demonstration
        // Real implementation would use the regex crate
        if pattern.contains("AKIA") && text.contains("AKIA") {
            return true;
        }
        if pattern.contains("ghp_") && text.contains("ghp_") {
            return true;
        }
        if pattern.contains("PRIVATE KEY") && text.contains("PRIVATE KEY") {
            return true;
        }
        false
    }
}

#[derive(Debug, Clone)]
pub struct SecretMatch {
    pub pattern_name: String,
    pub file_path: PathBuf,
    pub line_number: usize,
    pub severity: SecretSeverity,
}

impl PreCommitCheck for SecretDetector {
    fn name(&self) -> &str {
        "Secret Detection"
    }

    fn description(&self) -> &str {
        "Scans for accidentally committed secrets and credentials"
    }

    fn run(&self, staged_files: &[PathBuf]) -> CheckResult {
        let mut all_matches = vec![];
        let mut affected_files = vec![];

        for file_path in staged_files {
            if let Ok(content) = fs::read_to_string(file_path) {
                let matches = self.scan_content(&content, file_path);
                if !matches.is_empty() {
                    affected_files.push(file_path.clone());
                    all_matches.extend(matches);
                }
            }
        }

        if all_matches.is_empty() {
            CheckResult::pass(self.name(), "No secrets detected")
        } else {
            let critical_count = all_matches
                .iter()
                .filter(|m| m.severity == SecretSeverity::Critical)
                .count();

            CheckResult::fail(
                self.name(),
                &format!(
                    "Found {} potential secrets ({} critical)",
                    all_matches.len(),
                    critical_count
                ),
            )
            .with_suggestion("Remove secrets and use environment variables or secret management")
            .with_suggestion("Add false positives to .secretsignore")
            .with_files(affected_files)
        }
    }
}

/// File size limit check
pub struct FileSizeCheck {
    max_size_bytes: u64,
    max_total_bytes: u64,
}

impl FileSizeCheck {
    pub fn new(max_file_mb: u64, max_total_mb: u64) -> Self {
        Self {
            max_size_bytes: max_file_mb * 1024 * 1024,
            max_total_bytes: max_total_mb * 1024 * 1024,
        }
    }
}

impl PreCommitCheck for FileSizeCheck {
    fn name(&self) -> &str {
        "File Size Limit"
    }

    fn description(&self) -> &str {
        "Prevents committing large files"
    }

    fn run(&self, staged_files: &[PathBuf]) -> CheckResult {
        let mut oversized = vec![];
        let mut total_size = 0u64;

        for file_path in staged_files {
            if let Ok(metadata) = fs::metadata(file_path) {
                let size = metadata.len();
                total_size += size;

                if size > self.max_size_bytes {
                    oversized.push(file_path.clone());
                }
            }
        }

        if !oversized.is_empty() {
            CheckResult::fail(
                self.name(),
                &format!(
                    "{} files exceed {} MB limit",
                    oversized.len(),
                    self.max_size_bytes / (1024 * 1024)
                ),
            )
            .with_suggestion("Use Git LFS for large files")
            .with_files(oversized)
        } else if total_size > self.max_total_bytes {
            CheckResult::fail(
                self.name(),
                &format!(
                    "Total staged size ({} MB) exceeds {} MB limit",
                    total_size / (1024 * 1024),
                    self.max_total_bytes / (1024 * 1024)
                ),
            )
            .with_suggestion("Split into smaller commits")
        } else {
            CheckResult::pass(self.name(), "All files within size limits")
        }
    }
}

/// Conventional commit message validator
pub struct ConventionalCommitValidator {
    allowed_types: Vec<String>,
    require_scope: bool,
    max_subject_length: usize,
    require_body: bool,
}

impl ConventionalCommitValidator {
    pub fn new() -> Self {
        Self {
            allowed_types: vec![
                "feat".into(),
                "fix".into(),
                "docs".into(),
                "style".into(),
                "refactor".into(),
                "perf".into(),
                "test".into(),
                "build".into(),
                "ci".into(),
                "chore".into(),
                "revert".into(),
            ],
            require_scope: false,
            max_subject_length: 72,
            require_body: false,
        }
    }

    pub fn with_scope_required(mut self) -> Self {
        self.require_scope = true;
        self
    }

    pub fn with_body_required(mut self) -> Self {
        self.require_body = true;
        self
    }

    pub fn validate(&self, message: &str) -> Result<CommitInfo, Vec<String>> {
        let mut errors = vec![];
        let lines: Vec<&str> = message.lines().collect();

        if lines.is_empty() {
            errors.push("Commit message is empty".into());
            return Err(errors);
        }

        let subject = lines[0];

        // Parse conventional commit format: type(scope): description
        let parsed = self.parse_subject(subject);

        match parsed {
            Ok(info) => {
                // Validate type
                if !self.allowed_types.contains(&info.commit_type) {
                    errors.push(format!(
                        "Invalid commit type '{}'. Allowed: {}",
                        info.commit_type,
                        self.allowed_types.join(", ")
                    ));
                }

                // Validate scope requirement
                if self.require_scope && info.scope.is_none() {
                    errors.push("Scope is required".into());
                }

                // Validate subject length
                if subject.len() > self.max_subject_length {
                    errors.push(format!(
                        "Subject line too long ({} > {} chars)",
                        subject.len(),
                        self.max_subject_length
                    ));
                }

                // Check for body
                if self.require_body {
                    let has_body = lines.len() > 2 && lines[1].is_empty() && !lines[2].is_empty();
                    if !has_body {
                        errors.push("Commit body is required".into());
                    }
                }

                if errors.is_empty() {
                    Ok(info)
                } else {
                    Err(errors)
                }
            }
            Err(e) => {
                errors.push(e);
                Err(errors)
            }
        }
    }

    fn parse_subject(&self, subject: &str) -> Result<CommitInfo, String> {
        // Format: type(scope)!: description
        // or: type!: description
        // or: type(scope): description
        // or: type: description

        let colon_pos = subject.find(':').ok_or("Missing ':' in commit message")?;
        let type_part = &subject[..colon_pos];
        let description = subject[colon_pos + 1..].trim();

        if description.is_empty() {
            return Err("Missing description after ':'".into());
        }

        let breaking = type_part.contains('!');
        let type_part = type_part.replace('!', "");

        let (commit_type, scope) = if let Some(paren_start) = type_part.find('(') {
            let paren_end = type_part.find(')').ok_or("Missing ')' in scope")?;
            let commit_type = type_part[..paren_start].to_string();
            let scope = type_part[paren_start + 1..paren_end].to_string();
            (commit_type, Some(scope))
        } else {
            (type_part.to_string(), None)
        };

        Ok(CommitInfo {
            commit_type,
            scope,
            description: description.into(),
            breaking,
        })
    }
}

#[derive(Debug, Clone)]
pub struct CommitInfo {
    pub commit_type: String,
    pub scope: Option<String>,
    pub description: String,
    pub breaking: bool,
}

/// Branch naming convention validator
pub struct BranchNameValidator {
    patterns: Vec<BranchPattern>,
    protected_branches: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct BranchPattern {
    pub prefix: String,
    pub description: String,
    pub requires_issue: bool,
}

impl BranchNameValidator {
    pub fn new() -> Self {
        Self {
            patterns: vec![
                BranchPattern {
                    prefix: "feature/".into(),
                    description: "New features".into(),
                    requires_issue: true,
                },
                BranchPattern {
                    prefix: "bugfix/".into(),
                    description: "Bug fixes".into(),
                    requires_issue: true,
                },
                BranchPattern {
                    prefix: "hotfix/".into(),
                    description: "Production hotfixes".into(),
                    requires_issue: false,
                },
                BranchPattern {
                    prefix: "release/".into(),
                    description: "Release branches".into(),
                    requires_issue: false,
                },
                BranchPattern {
                    prefix: "chore/".into(),
                    description: "Maintenance tasks".into(),
                    requires_issue: false,
                },
            ],
            protected_branches: vec!["main".into(), "master".into(), "develop".into()],
        }
    }

    pub fn validate(&self, branch_name: &str) -> Result<(), Vec<String>> {
        let mut errors = vec![];

        // Check if protected
        if self.protected_branches.contains(&branch_name.to_string()) {
            errors.push(format!("Cannot push directly to protected branch '{}'", branch_name));
            return Err(errors);
        }

        // Check naming convention
        let matches_pattern = self.patterns.iter().any(|p| branch_name.starts_with(&p.prefix));

        if !matches_pattern {
            errors.push(format!(
                "Branch name '{}' doesn't follow naming conventions",
                branch_name
            ));
            errors.push(format!(
                "Valid prefixes: {}",
                self.patterns.iter().map(|p| &p.prefix).cloned().collect::<Vec<_>>().join(", ")
            ));
        }

        // Check for issue reference if required
        for pattern in &self.patterns {
            if branch_name.starts_with(&pattern.prefix) && pattern.requires_issue {
                // Check for issue number like feature/123-description or feature/JIRA-123-description
                let suffix = &branch_name[pattern.prefix.len()..];
                let has_issue = suffix.chars().next().map(|c| c.is_numeric()).unwrap_or(false)
                    || suffix.contains('-') && suffix.split('-').next().map(|s| s.chars().all(|c| c.is_alphanumeric())).unwrap_or(false);

                if !has_issue {
                    errors.push(format!(
                        "Branch '{}' should include an issue reference (e.g., {}<issue-number>-description)",
                        branch_name, pattern.prefix
                    ));
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// Git hooks manager
pub struct GitHooksManager {
    repo_path: PathBuf,
    hooks_dir: PathBuf,
    pre_commit_checks: Vec<Box<dyn PreCommitCheck>>,
}

impl GitHooksManager {
    pub fn new<P: AsRef<Path>>(repo_path: P) -> Self {
        let repo_path = repo_path.as_ref().to_path_buf();
        let hooks_dir = repo_path.join(".git").join("hooks");

        Self {
            repo_path,
            hooks_dir,
            pre_commit_checks: vec![],
        }
    }

    pub fn add_check(&mut self, check: Box<dyn PreCommitCheck>) {
        self.pre_commit_checks.push(check);
    }

    /// Run all pre-commit checks
    pub fn run_pre_commit(&self, staged_files: &[PathBuf]) -> Vec<CheckResult> {
        self.pre_commit_checks
            .iter()
            .map(|check| check.run(staged_files))
            .collect()
    }

    /// Install hook script
    pub fn install_hook(&self, hook_type: HookType, script: &str) -> io::Result<()> {
        fs::create_dir_all(&self.hooks_dir)?;

        let hook_path = self.hooks_dir.join(hook_type.as_str());
        let mut file = fs::File::create(&hook_path)?;
        file.write_all(script.as_bytes())?;

        // Make executable on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&hook_path)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&hook_path, perms)?;
        }

        Ok(())
    }

    /// Generate pre-commit hook script
    pub fn generate_pre_commit_script(&self) -> String {
        r#"#!/bin/sh
# Pre-commit hook generated by Syntek Rust Security
# Runs security checks before allowing commits

set -e

echo "Running pre-commit checks..."

# Get list of staged files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)

if [ -z "$STAGED_FILES" ]; then
    echo "No files staged for commit"
    exit 0
fi

# Run cargo fmt check
if command -v cargo &> /dev/null; then
    echo "Checking formatting..."
    cargo fmt -- --check || {
        echo "Error: Code is not formatted. Run 'cargo fmt' to fix."
        exit 1
    }
fi

# Run cargo clippy
if command -v cargo &> /dev/null; then
    echo "Running clippy..."
    cargo clippy -- -D warnings || {
        echo "Error: Clippy found issues."
        exit 1
    }
fi

# Run secret detection
echo "Scanning for secrets..."
for file in $STAGED_FILES; do
    if [ -f "$file" ]; then
        # Check for common secret patterns
        if grep -E "(AKIA[0-9A-Z]{16}|ghp_[0-9a-zA-Z]{36}|-----BEGIN.*PRIVATE KEY-----)" "$file" > /dev/null 2>&1; then
            echo "Error: Potential secret found in $file"
            exit 1
        fi
    fi
done

# Run cargo test
if command -v cargo &> /dev/null; then
    echo "Running tests..."
    cargo test --quiet || {
        echo "Error: Tests failed."
        exit 1
    }
fi

echo "All pre-commit checks passed!"
exit 0
"#.to_string()
    }

    /// Generate commit-msg hook script
    pub fn generate_commit_msg_script(&self) -> String {
        r#"#!/bin/sh
# Commit message hook generated by Syntek Rust Security
# Validates commit message format

COMMIT_MSG_FILE=$1
COMMIT_MSG=$(cat "$COMMIT_MSG_FILE")

# Skip merge commits
if echo "$COMMIT_MSG" | grep -q "^Merge"; then
    exit 0
fi

# Validate conventional commit format
if ! echo "$COMMIT_MSG" | grep -qE "^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\(.+\))?!?:"; then
    echo "Error: Commit message doesn't follow Conventional Commits format"
    echo ""
    echo "Format: <type>(<scope>): <description>"
    echo ""
    echo "Types: feat, fix, docs, style, refactor, perf, test, build, ci, chore, revert"
    echo ""
    echo "Examples:"
    echo "  feat(auth): add OAuth2 support"
    echo "  fix: resolve memory leak in connection pool"
    echo "  docs(readme): update installation instructions"
    exit 1
fi

# Check subject line length
SUBJECT=$(echo "$COMMIT_MSG" | head -n 1)
if [ ${#SUBJECT} -gt 72 ]; then
    echo "Error: Subject line too long (${#SUBJECT} > 72 characters)"
    exit 1
fi

exit 0
"#.to_string()
    }

    /// Generate pre-push hook script
    pub fn generate_pre_push_script(&self) -> String {
        r#"#!/bin/sh
# Pre-push hook generated by Syntek Rust Security
# Prevents pushing to protected branches

PROTECTED_BRANCHES="main master develop"
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)

for branch in $PROTECTED_BRANCHES; do
    if [ "$CURRENT_BRANCH" = "$branch" ]; then
        echo "Error: Cannot push directly to protected branch '$branch'"
        echo "Please create a pull request instead."
        exit 1
    fi
done

# Run full test suite before pushing
if command -v cargo &> /dev/null; then
    echo "Running tests before push..."
    cargo test || {
        echo "Error: Tests failed. Push aborted."
        exit 1
    }
fi

exit 0
"#.to_string()
    }
}

fn main() {
    println!("Git Hooks and Security Automation\n");

    // Secret detection
    println!("=== Secret Detection ===\n");

    let detector = SecretDetector::new();

    let test_content = r#"
# Configuration file
API_KEY = "ghp_1234567890abcdef1234567890abcdef1234"
DATABASE_URL = "postgres://user:pass@localhost/db"
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
"#;

    let matches = detector.scan_content(test_content, Path::new("config.txt"));
    if matches.is_empty() {
        println!("No secrets detected");
    } else {
        for m in &matches {
            println!(
                "Found {} at line {} ({:?})",
                m.pattern_name, m.line_number, m.severity
            );
        }
    }

    // Conventional commit validation
    println!("\n=== Commit Message Validation ===\n");

    let validator = ConventionalCommitValidator::new();

    let test_commits = vec![
        "feat(auth): add OAuth2 support",
        "fix: resolve memory leak",
        "invalid commit message",
        "feat!: breaking change in API",
    ];

    for msg in test_commits {
        match validator.validate(msg) {
            Ok(info) => {
                println!("✓ Valid: {}", msg);
                println!("  Type: {}, Breaking: {}", info.commit_type, info.breaking);
            }
            Err(errors) => {
                println!("✗ Invalid: {}", msg);
                for err in errors {
                    println!("  - {}", err);
                }
            }
        }
    }

    // Branch name validation
    println!("\n=== Branch Name Validation ===\n");

    let branch_validator = BranchNameValidator::new();

    let test_branches = vec![
        "feature/123-add-login",
        "bugfix/456-fix-crash",
        "random-branch-name",
        "main",
    ];

    for branch in test_branches {
        match branch_validator.validate(branch) {
            Ok(_) => println!("✓ Valid branch: {}", branch),
            Err(errors) => {
                println!("✗ Invalid branch: {}", branch);
                for err in errors {
                    println!("  - {}", err);
                }
            }
        }
    }

    // Hook script generation
    println!("\n=== Generated Hook Scripts ===\n");

    let manager = GitHooksManager::new(".");

    println!("Pre-commit script (first 20 lines):");
    for line in manager.generate_pre_commit_script().lines().take(20) {
        println!("{}", line);
    }
    println!("...\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hook_type_from_str() {
        assert_eq!(HookType::from_str("pre-commit"), Some(HookType::PreCommit));
        assert_eq!(HookType::from_str("commit-msg"), Some(HookType::CommitMsg));
        assert_eq!(HookType::from_str("invalid"), None);
    }

    #[test]
    fn test_hook_type_as_str() {
        assert_eq!(HookType::PreCommit.as_str(), "pre-commit");
        assert_eq!(HookType::PrePush.as_str(), "pre-push");
    }

    #[test]
    fn test_check_result_pass() {
        let result = CheckResult::pass("Test", "All good");
        assert!(result.passed);
        assert_eq!(result.name, "Test");
    }

    #[test]
    fn test_check_result_fail() {
        let result = CheckResult::fail("Test", "Something wrong")
            .with_suggestion("Fix it");
        assert!(!result.passed);
        assert_eq!(result.suggestions.len(), 1);
    }

    #[test]
    fn test_secret_detector_creation() {
        let detector = SecretDetector::new();
        assert!(!detector.patterns.is_empty());
    }

    #[test]
    fn test_conventional_commit_valid() {
        let validator = ConventionalCommitValidator::new();

        let result = validator.validate("feat(auth): add login");
        assert!(result.is_ok());

        let info = result.unwrap();
        assert_eq!(info.commit_type, "feat");
        assert_eq!(info.scope, Some("auth".into()));
        assert!(!info.breaking);
    }

    #[test]
    fn test_conventional_commit_breaking() {
        let validator = ConventionalCommitValidator::new();

        let result = validator.validate("feat!: breaking change");
        assert!(result.is_ok());
        assert!(result.unwrap().breaking);
    }

    #[test]
    fn test_conventional_commit_invalid() {
        let validator = ConventionalCommitValidator::new();

        let result = validator.validate("invalid message");
        assert!(result.is_err());
    }

    #[test]
    fn test_conventional_commit_invalid_type() {
        let validator = ConventionalCommitValidator::new();

        let result = validator.validate("invalid: some message");
        assert!(result.is_err());
    }

    #[test]
    fn test_branch_name_valid() {
        let validator = BranchNameValidator::new();

        assert!(validator.validate("feature/123-new-feature").is_ok());
        assert!(validator.validate("bugfix/456-fix-issue").is_ok());
        assert!(validator.validate("hotfix/urgent-fix").is_ok());
    }

    #[test]
    fn test_branch_name_invalid() {
        let validator = BranchNameValidator::new();

        assert!(validator.validate("random-branch").is_err());
        assert!(validator.validate("my-feature").is_err());
    }

    #[test]
    fn test_branch_name_protected() {
        let validator = BranchNameValidator::new();

        assert!(validator.validate("main").is_err());
        assert!(validator.validate("master").is_err());
        assert!(validator.validate("develop").is_err());
    }

    #[test]
    fn test_file_size_check_pass() {
        let check = FileSizeCheck::new(10, 100);
        let result = check.run(&[]);
        assert!(result.passed);
    }

    #[test]
    fn test_git_hooks_manager_creation() {
        let manager = GitHooksManager::new("/tmp/test-repo");
        assert_eq!(manager.repo_path, PathBuf::from("/tmp/test-repo"));
    }

    #[test]
    fn test_generate_pre_commit_script() {
        let manager = GitHooksManager::new(".");
        let script = manager.generate_pre_commit_script();
        assert!(script.contains("#!/bin/sh"));
        assert!(script.contains("pre-commit"));
    }

    #[test]
    fn test_generate_commit_msg_script() {
        let manager = GitHooksManager::new(".");
        let script = manager.generate_commit_msg_script();
        assert!(script.contains("Conventional Commits"));
    }

    #[test]
    fn test_generate_pre_push_script() {
        let manager = GitHooksManager::new(".");
        let script = manager.generate_pre_push_script();
        assert!(script.contains("protected branch"));
    }

    #[test]
    fn test_commit_info() {
        let info = CommitInfo {
            commit_type: "feat".into(),
            scope: Some("api".into()),
            description: "add endpoint".into(),
            breaking: false,
        };

        assert_eq!(info.commit_type, "feat");
        assert_eq!(info.scope, Some("api".into()));
    }

    #[test]
    fn test_secret_severity() {
        assert!(matches!(
            SecretSeverity::Critical,
            SecretSeverity::Critical
        ));
    }
}
