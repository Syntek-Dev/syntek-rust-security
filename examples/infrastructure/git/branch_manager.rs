//! Git Branch Manager
//!
//! Automated git branch management with protection rules and workflows.

use std::collections::{HashMap, HashSet};
use std::fmt;

/// Branch type classification
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BranchType {
    Main,
    Development,
    Feature,
    Bugfix,
    Hotfix,
    Release,
    Support,
    Experiment,
    Custom(String),
}

impl BranchType {
    pub fn from_name(name: &str) -> Self {
        let lower = name.to_lowercase();
        if lower == "main" || lower == "master" {
            Self::Main
        } else if lower == "develop" || lower == "development" || lower == "dev" {
            Self::Development
        } else if lower.starts_with("feature/") || lower.starts_with("feat/") {
            Self::Feature
        } else if lower.starts_with("bugfix/") || lower.starts_with("bug/") {
            Self::Bugfix
        } else if lower.starts_with("hotfix/") || lower.starts_with("hot/") {
            Self::Hotfix
        } else if lower.starts_with("release/") || lower.starts_with("rel/") {
            Self::Release
        } else if lower.starts_with("support/") {
            Self::Support
        } else if lower.starts_with("experiment/") || lower.starts_with("exp/") {
            Self::Experiment
        } else {
            Self::Custom(name.to_string())
        }
    }

    pub fn prefix(&self) -> &str {
        match self {
            Self::Main => "",
            Self::Development => "",
            Self::Feature => "feature/",
            Self::Bugfix => "bugfix/",
            Self::Hotfix => "hotfix/",
            Self::Release => "release/",
            Self::Support => "support/",
            Self::Experiment => "experiment/",
            Self::Custom(_) => "",
        }
    }

    pub fn is_protected(&self) -> bool {
        matches!(self, Self::Main | Self::Development | Self::Release)
    }

    pub fn default_base(&self) -> &str {
        match self {
            Self::Feature | Self::Bugfix | Self::Experiment => "develop",
            Self::Hotfix => "main",
            Self::Release => "develop",
            Self::Support => "main",
            _ => "main",
        }
    }
}

impl fmt::Display for BranchType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Main => write!(f, "main"),
            Self::Development => write!(f, "develop"),
            Self::Feature => write!(f, "feature"),
            Self::Bugfix => write!(f, "bugfix"),
            Self::Hotfix => write!(f, "hotfix"),
            Self::Release => write!(f, "release"),
            Self::Support => write!(f, "support"),
            Self::Experiment => write!(f, "experiment"),
            Self::Custom(name) => write!(f, "{}", name),
        }
    }
}

/// Branch information
#[derive(Debug, Clone)]
pub struct Branch {
    pub name: String,
    pub branch_type: BranchType,
    pub upstream: Option<String>,
    pub last_commit: String,
    pub last_commit_date: String,
    pub author: String,
    pub ahead: usize,
    pub behind: usize,
    pub is_merged: bool,
    pub is_current: bool,
    pub tracking_remote: Option<String>,
}

impl Branch {
    pub fn new(name: impl Into<String>) -> Self {
        let name = name.into();
        let branch_type = BranchType::from_name(&name);

        Self {
            name,
            branch_type,
            upstream: None,
            last_commit: String::new(),
            last_commit_date: String::new(),
            author: String::new(),
            ahead: 0,
            behind: 0,
            is_merged: false,
            is_current: false,
            tracking_remote: None,
        }
    }

    pub fn with_upstream(mut self, upstream: impl Into<String>) -> Self {
        self.upstream = Some(upstream.into());
        self
    }

    pub fn with_commit(mut self, hash: impl Into<String>, date: impl Into<String>) -> Self {
        self.last_commit = hash.into();
        self.last_commit_date = date.into();
        self
    }

    pub fn with_author(mut self, author: impl Into<String>) -> Self {
        self.author = author.into();
        self
    }

    pub fn with_tracking(mut self, ahead: usize, behind: usize) -> Self {
        self.ahead = ahead;
        self.behind = behind;
        self
    }

    pub fn set_merged(mut self, merged: bool) -> Self {
        self.is_merged = merged;
        self
    }

    pub fn set_current(mut self, current: bool) -> Self {
        self.is_current = current;
        self
    }

    pub fn is_stale(&self, days: u64) -> bool {
        // Check if branch is stale based on last commit date
        // Simplified: in real implementation, parse date and compare
        self.behind > 50 || self.last_commit_date.is_empty()
    }

    pub fn needs_rebase(&self) -> bool {
        self.behind > 0
    }

    pub fn is_ready_to_merge(&self) -> bool {
        !self.is_merged && self.behind == 0 && !self.name.is_empty()
    }
}

/// Branch protection rules
#[derive(Debug, Clone)]
pub struct ProtectionRules {
    pub require_pull_request: bool,
    pub required_approvals: u32,
    pub require_status_checks: bool,
    pub required_checks: Vec<String>,
    pub require_signed_commits: bool,
    pub require_linear_history: bool,
    pub allow_force_push: bool,
    pub allow_deletion: bool,
    pub restrict_pushes: bool,
    pub allowed_push_users: HashSet<String>,
    pub allowed_push_teams: HashSet<String>,
    pub dismiss_stale_reviews: bool,
    pub require_code_owners: bool,
    pub include_administrators: bool,
}

impl Default for ProtectionRules {
    fn default() -> Self {
        Self {
            require_pull_request: true,
            required_approvals: 1,
            require_status_checks: true,
            required_checks: vec!["ci".to_string(), "tests".to_string()],
            require_signed_commits: false,
            require_linear_history: false,
            allow_force_push: false,
            allow_deletion: false,
            restrict_pushes: false,
            allowed_push_users: HashSet::new(),
            allowed_push_teams: HashSet::new(),
            dismiss_stale_reviews: true,
            require_code_owners: false,
            include_administrators: true,
        }
    }
}

impl ProtectionRules {
    pub fn strict() -> Self {
        Self {
            require_pull_request: true,
            required_approvals: 2,
            require_status_checks: true,
            required_checks: vec![
                "ci".to_string(),
                "tests".to_string(),
                "security-scan".to_string(),
                "lint".to_string(),
            ],
            require_signed_commits: true,
            require_linear_history: true,
            allow_force_push: false,
            allow_deletion: false,
            restrict_pushes: true,
            allowed_push_users: HashSet::new(),
            allowed_push_teams: HashSet::new(),
            dismiss_stale_reviews: true,
            require_code_owners: true,
            include_administrators: true,
        }
    }

    pub fn minimal() -> Self {
        Self {
            require_pull_request: false,
            required_approvals: 0,
            require_status_checks: false,
            required_checks: Vec::new(),
            require_signed_commits: false,
            require_linear_history: false,
            allow_force_push: false,
            allow_deletion: false,
            restrict_pushes: false,
            allowed_push_users: HashSet::new(),
            allowed_push_teams: HashSet::new(),
            dismiss_stale_reviews: false,
            require_code_owners: false,
            include_administrators: false,
        }
    }
}

/// Branch protection rule builder
pub struct ProtectionRulesBuilder {
    rules: ProtectionRules,
}

impl ProtectionRulesBuilder {
    pub fn new() -> Self {
        Self {
            rules: ProtectionRules::default(),
        }
    }

    pub fn require_pull_request(mut self, require: bool) -> Self {
        self.rules.require_pull_request = require;
        self
    }

    pub fn required_approvals(mut self, count: u32) -> Self {
        self.rules.required_approvals = count;
        self
    }

    pub fn require_status_checks(mut self, checks: Vec<String>) -> Self {
        self.rules.require_status_checks = !checks.is_empty();
        self.rules.required_checks = checks;
        self
    }

    pub fn require_signed_commits(mut self, require: bool) -> Self {
        self.rules.require_signed_commits = require;
        self
    }

    pub fn require_linear_history(mut self, require: bool) -> Self {
        self.rules.require_linear_history = require;
        self
    }

    pub fn allow_force_push(mut self, allow: bool) -> Self {
        self.rules.allow_force_push = allow;
        self
    }

    pub fn allow_deletion(mut self, allow: bool) -> Self {
        self.rules.allow_deletion = allow;
        self
    }

    pub fn restrict_pushes_to_users(mut self, users: Vec<String>) -> Self {
        self.rules.restrict_pushes = true;
        self.rules.allowed_push_users = users.into_iter().collect();
        self
    }

    pub fn restrict_pushes_to_teams(mut self, teams: Vec<String>) -> Self {
        self.rules.restrict_pushes = true;
        self.rules.allowed_push_teams = teams.into_iter().collect();
        self
    }

    pub fn dismiss_stale_reviews(mut self, dismiss: bool) -> Self {
        self.rules.dismiss_stale_reviews = dismiss;
        self
    }

    pub fn require_code_owners(mut self, require: bool) -> Self {
        self.rules.require_code_owners = require;
        self
    }

    pub fn build(self) -> ProtectionRules {
        self.rules
    }
}

impl Default for ProtectionRulesBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Git workflow type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitWorkflow {
    GitFlow,
    GitHubFlow,
    GitLabFlow,
    TrunkBased,
    Custom,
}

impl GitWorkflow {
    pub fn protected_branches(&self) -> Vec<&str> {
        match self {
            Self::GitFlow => vec!["main", "develop"],
            Self::GitHubFlow => vec!["main"],
            Self::GitLabFlow => vec!["main", "staging", "production"],
            Self::TrunkBased => vec!["main"],
            Self::Custom => vec![],
        }
    }

    pub fn allowed_branch_types(&self) -> Vec<BranchType> {
        match self {
            Self::GitFlow => vec![
                BranchType::Main,
                BranchType::Development,
                BranchType::Feature,
                BranchType::Bugfix,
                BranchType::Hotfix,
                BranchType::Release,
            ],
            Self::GitHubFlow => vec![BranchType::Main, BranchType::Feature],
            Self::GitLabFlow => vec![BranchType::Main, BranchType::Feature, BranchType::Bugfix],
            Self::TrunkBased => vec![BranchType::Main, BranchType::Feature],
            Self::Custom => vec![],
        }
    }
}

/// Branch manager for automated branch operations
pub struct BranchManager {
    workflow: GitWorkflow,
    branches: HashMap<String, Branch>,
    protection_rules: HashMap<String, ProtectionRules>,
    default_branch: String,
    remote: String,
}

impl BranchManager {
    pub fn new(workflow: GitWorkflow) -> Self {
        let default_branch = match workflow {
            GitWorkflow::GitFlow => "develop".to_string(),
            _ => "main".to_string(),
        };

        Self {
            workflow,
            branches: HashMap::new(),
            protection_rules: HashMap::new(),
            default_branch,
            remote: "origin".to_string(),
        }
    }

    pub fn with_remote(mut self, remote: impl Into<String>) -> Self {
        self.remote = remote.into();
        self
    }

    pub fn add_branch(&mut self, branch: Branch) {
        self.branches.insert(branch.name.clone(), branch);
    }

    pub fn set_protection(&mut self, branch_pattern: impl Into<String>, rules: ProtectionRules) {
        self.protection_rules.insert(branch_pattern.into(), rules);
    }

    pub fn get_branch(&self, name: &str) -> Option<&Branch> {
        self.branches.get(name)
    }

    pub fn list_branches(&self) -> Vec<&Branch> {
        self.branches.values().collect()
    }

    pub fn list_by_type(&self, branch_type: &BranchType) -> Vec<&Branch> {
        self.branches
            .values()
            .filter(|b| &b.branch_type == branch_type)
            .collect()
    }

    pub fn get_stale_branches(&self, days: u64) -> Vec<&Branch> {
        self.branches
            .values()
            .filter(|b| b.is_stale(days) && !b.branch_type.is_protected())
            .collect()
    }

    pub fn get_merged_branches(&self) -> Vec<&Branch> {
        self.branches
            .values()
            .filter(|b| b.is_merged && !b.branch_type.is_protected())
            .collect()
    }

    pub fn validate_branch_name(&self, name: &str) -> Result<(), BranchValidationError> {
        // Check for valid characters
        if name.contains(' ') || name.contains("..") || name.starts_with('-') {
            return Err(BranchValidationError::InvalidCharacters(name.to_string()));
        }

        // Check length
        if name.len() > 255 {
            return Err(BranchValidationError::TooLong(name.len()));
        }

        // Check workflow compliance
        let branch_type = BranchType::from_name(name);
        let allowed = self.workflow.allowed_branch_types();

        if !allowed.is_empty() && !allowed.contains(&branch_type) {
            if let BranchType::Custom(_) = branch_type {
                return Err(BranchValidationError::WorkflowViolation(format!(
                    "Custom branch naming not allowed in {:?} workflow",
                    self.workflow
                )));
            }
        }

        Ok(())
    }

    pub fn suggest_branch_name(&self, branch_type: &BranchType, description: &str) -> String {
        let sanitized = description
            .to_lowercase()
            .replace(' ', "-")
            .replace('_', "-")
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '/')
            .collect::<String>();

        format!("{}{}", branch_type.prefix(), sanitized)
    }

    pub fn get_merge_target(&self, branch: &Branch) -> String {
        match &branch.branch_type {
            BranchType::Feature | BranchType::Bugfix => self.default_branch.clone(),
            BranchType::Hotfix => "main".to_string(),
            BranchType::Release => "main".to_string(),
            _ => self.default_branch.clone(),
        }
    }

    pub fn generate_create_command(&self, branch_type: &BranchType, name: &str) -> Vec<String> {
        let branch_name = format!("{}{}", branch_type.prefix(), name);
        let base = branch_type.default_base();

        vec![
            format!("git fetch {} {}", self.remote, base),
            format!("git checkout -b {} {}/{}", branch_name, self.remote, base),
            format!("git push -u {} {}", self.remote, branch_name),
        ]
    }

    pub fn generate_cleanup_commands(&self) -> Vec<String> {
        let mut commands = Vec::new();

        // Fetch and prune
        commands.push(format!("git fetch {} --prune", self.remote));

        // Delete merged branches
        for branch in self.get_merged_branches() {
            if !branch.is_current {
                commands.push(format!("git branch -d {}", branch.name));
                commands.push(format!("git push {} --delete {}", self.remote, branch.name));
            }
        }

        commands
    }

    pub fn generate_protection_config(&self, branch: &str) -> String {
        let rules = self
            .protection_rules
            .get(branch)
            .cloned()
            .unwrap_or_default();

        let mut config = String::new();
        config.push_str(&format!("# Branch protection for: {}\n", branch));
        config.push_str(&format!(
            "require_pull_request: {}\n",
            rules.require_pull_request
        ));
        config.push_str(&format!(
            "required_approvals: {}\n",
            rules.required_approvals
        ));
        config.push_str(&format!(
            "require_status_checks: {}\n",
            rules.require_status_checks
        ));
        config.push_str(&format!("required_checks: {:?}\n", rules.required_checks));
        config.push_str(&format!(
            "require_signed_commits: {}\n",
            rules.require_signed_commits
        ));
        config.push_str(&format!(
            "require_linear_history: {}\n",
            rules.require_linear_history
        ));
        config.push_str(&format!("allow_force_push: {}\n", rules.allow_force_push));
        config.push_str(&format!("allow_deletion: {}\n", rules.allow_deletion));

        config
    }

    pub fn analyze(&self) -> BranchAnalysis {
        let mut analysis = BranchAnalysis::default();

        for branch in self.branches.values() {
            analysis.total += 1;

            match &branch.branch_type {
                BranchType::Feature => analysis.features += 1,
                BranchType::Bugfix => analysis.bugfixes += 1,
                BranchType::Hotfix => analysis.hotfixes += 1,
                BranchType::Release => analysis.releases += 1,
                _ => analysis.other += 1,
            }

            if branch.is_merged {
                analysis.merged += 1;
            }

            if branch.is_stale(30) {
                analysis.stale += 1;
            }

            if branch.needs_rebase() {
                analysis.needs_rebase += 1;
            }
        }

        analysis
    }
}

/// Branch validation errors
#[derive(Debug)]
pub enum BranchValidationError {
    InvalidCharacters(String),
    TooLong(usize),
    WorkflowViolation(String),
    AlreadyExists(String),
    ProtectedBranch(String),
}

impl fmt::Display for BranchValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCharacters(name) => {
                write!(f, "Branch name contains invalid characters: {}", name)
            }
            Self::TooLong(len) => {
                write!(f, "Branch name too long: {} characters (max 255)", len)
            }
            Self::WorkflowViolation(msg) => write!(f, "Workflow violation: {}", msg),
            Self::AlreadyExists(name) => write!(f, "Branch already exists: {}", name),
            Self::ProtectedBranch(name) => write!(f, "Cannot modify protected branch: {}", name),
        }
    }
}

/// Branch analysis results
#[derive(Debug, Default)]
pub struct BranchAnalysis {
    pub total: usize,
    pub features: usize,
    pub bugfixes: usize,
    pub hotfixes: usize,
    pub releases: usize,
    pub other: usize,
    pub merged: usize,
    pub stale: usize,
    pub needs_rebase: usize,
}

impl BranchAnalysis {
    pub fn health_score(&self) -> f64 {
        if self.total == 0 {
            return 100.0;
        }

        let stale_penalty = (self.stale as f64 / self.total as f64) * 30.0;
        let merged_penalty = (self.merged as f64 / self.total as f64) * 20.0;
        let rebase_penalty = (self.needs_rebase as f64 / self.total as f64) * 10.0;

        (100.0 - stale_penalty - merged_penalty - rebase_penalty).max(0.0)
    }
}

/// GitHub Actions workflow for branch protection
pub fn generate_github_branch_rules(manager: &BranchManager) -> String {
    let mut yaml = String::new();
    yaml.push_str("# GitHub Branch Protection Rules\n");
    yaml.push_str("# Apply via GitHub API or Settings\n\n");

    for (pattern, rules) in &manager.protection_rules {
        yaml.push_str(&format!("{}:\n", pattern));
        yaml.push_str(&format!("  required_pull_request_reviews:\n"));
        yaml.push_str(&format!(
            "    required_approving_review_count: {}\n",
            rules.required_approvals
        ));
        yaml.push_str(&format!(
            "    dismiss_stale_reviews: {}\n",
            rules.dismiss_stale_reviews
        ));
        yaml.push_str(&format!(
            "    require_code_owner_reviews: {}\n",
            rules.require_code_owners
        ));

        if rules.require_status_checks {
            yaml.push_str("  required_status_checks:\n");
            yaml.push_str("    strict: true\n");
            yaml.push_str("    contexts:\n");
            for check in &rules.required_checks {
                yaml.push_str(&format!("      - {}\n", check));
            }
        }

        yaml.push_str(&format!(
            "  require_signed_commits: {}\n",
            rules.require_signed_commits
        ));
        yaml.push_str(&format!(
            "  require_linear_history: {}\n",
            rules.require_linear_history
        ));
        yaml.push_str(&format!(
            "  allow_force_pushes: {}\n",
            rules.allow_force_push
        ));
        yaml.push_str(&format!("  allow_deletions: {}\n", rules.allow_deletion));
        yaml.push_str("\n");
    }

    yaml
}

fn main() {
    println!("=== Git Branch Manager Demo ===\n");

    // Create branch manager with GitFlow workflow
    let mut manager = BranchManager::new(GitWorkflow::GitFlow);

    // Add protection rules
    manager.set_protection("main", ProtectionRules::strict());
    manager.set_protection(
        "develop",
        ProtectionRulesBuilder::new()
            .required_approvals(1)
            .require_status_checks(vec!["ci".to_string(), "tests".to_string()])
            .build(),
    );

    // Add sample branches
    manager.add_branch(
        Branch::new("main")
            .with_commit("abc123", "2025-01-15")
            .set_current(false),
    );

    manager.add_branch(
        Branch::new("develop")
            .with_commit("def456", "2025-01-14")
            .with_tracking(0, 0)
            .set_current(true),
    );

    manager.add_branch(
        Branch::new("feature/user-auth")
            .with_commit("ghi789", "2025-01-13")
            .with_author("alice")
            .with_tracking(5, 2),
    );

    manager.add_branch(
        Branch::new("feature/api-v2")
            .with_commit("jkl012", "2024-12-01")
            .with_author("bob")
            .with_tracking(10, 50)
            .set_merged(true),
    );

    manager.add_branch(
        Branch::new("hotfix/security-patch")
            .with_commit("mno345", "2025-01-15")
            .with_author("charlie")
            .with_tracking(1, 0),
    );

    // List all branches
    println!("All branches:");
    for branch in manager.list_branches() {
        println!(
            "  {} ({}) - ahead: {}, behind: {}{}{}",
            branch.name,
            branch.branch_type,
            branch.ahead,
            branch.behind,
            if branch.is_merged { " [merged]" } else { "" },
            if branch.is_current { " *" } else { "" }
        );
    }

    // List by type
    println!("\nFeature branches:");
    for branch in manager.list_by_type(&BranchType::Feature) {
        println!("  {}", branch.name);
    }

    // Stale branches
    println!("\nStale branches (>30 days):");
    for branch in manager.get_stale_branches(30) {
        println!("  {}", branch.name);
    }

    // Merged branches
    println!("\nMerged branches (can be deleted):");
    for branch in manager.get_merged_branches() {
        println!("  {}", branch.name);
    }

    // Validate branch name
    println!("\nBranch name validation:");
    let test_names = ["feature/new-login", "my branch", "hotfix/urgent-fix"];
    for name in test_names {
        match manager.validate_branch_name(name) {
            Ok(_) => println!("  '{}' - valid", name),
            Err(e) => println!("  '{}' - invalid: {}", name, e),
        }
    }

    // Suggest branch name
    println!("\nSuggested branch names:");
    println!(
        "  Feature 'User Authentication': {}",
        manager.suggest_branch_name(&BranchType::Feature, "User Authentication")
    );
    println!(
        "  Bugfix 'Fix null pointer': {}",
        manager.suggest_branch_name(&BranchType::Bugfix, "Fix null pointer")
    );

    // Generate create commands
    println!("\nCommands to create new feature branch:");
    for cmd in manager.generate_create_command(&BranchType::Feature, "new-dashboard") {
        println!("  {}", cmd);
    }

    // Generate cleanup commands
    println!("\nCleanup commands:");
    for cmd in manager.generate_cleanup_commands() {
        println!("  {}", cmd);
    }

    // Protection configuration
    println!("\nProtection configuration for 'main':");
    println!("{}", manager.generate_protection_config("main"));

    // Analysis
    println!("Branch analysis:");
    let analysis = manager.analyze();
    println!("  Total branches: {}", analysis.total);
    println!("  Features: {}", analysis.features);
    println!("  Bugfixes: {}", analysis.bugfixes);
    println!("  Hotfixes: {}", analysis.hotfixes);
    println!("  Merged: {}", analysis.merged);
    println!("  Stale: {}", analysis.stale);
    println!("  Needs rebase: {}", analysis.needs_rebase);
    println!("  Health score: {:.1}%", analysis.health_score());

    // GitHub rules
    println!("\n--- GitHub Branch Protection Rules ---");
    println!("{}", generate_github_branch_rules(&manager));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_branch_type_from_name() {
        assert_eq!(BranchType::from_name("main"), BranchType::Main);
        assert_eq!(BranchType::from_name("master"), BranchType::Main);
        assert_eq!(BranchType::from_name("develop"), BranchType::Development);
        assert_eq!(BranchType::from_name("feature/login"), BranchType::Feature);
        assert_eq!(BranchType::from_name("bugfix/null-ptr"), BranchType::Bugfix);
        assert_eq!(BranchType::from_name("hotfix/urgent"), BranchType::Hotfix);
        assert_eq!(BranchType::from_name("release/1.0"), BranchType::Release);
    }

    #[test]
    fn test_branch_is_protected() {
        assert!(BranchType::Main.is_protected());
        assert!(BranchType::Development.is_protected());
        assert!(BranchType::Release.is_protected());
        assert!(!BranchType::Feature.is_protected());
        assert!(!BranchType::Bugfix.is_protected());
    }

    #[test]
    fn test_branch_creation() {
        let branch = Branch::new("feature/test")
            .with_commit("abc123", "2025-01-15")
            .with_author("alice")
            .with_tracking(5, 2);

        assert_eq!(branch.name, "feature/test");
        assert_eq!(branch.branch_type, BranchType::Feature);
        assert_eq!(branch.last_commit, "abc123");
        assert_eq!(branch.author, "alice");
        assert_eq!(branch.ahead, 5);
        assert_eq!(branch.behind, 2);
    }

    #[test]
    fn test_branch_needs_rebase() {
        let branch = Branch::new("feature/test").with_tracking(5, 10);
        assert!(branch.needs_rebase());

        let branch2 = Branch::new("feature/test2").with_tracking(5, 0);
        assert!(!branch2.needs_rebase());
    }

    #[test]
    fn test_protection_rules_builder() {
        let rules = ProtectionRulesBuilder::new()
            .required_approvals(2)
            .require_signed_commits(true)
            .require_linear_history(true)
            .build();

        assert_eq!(rules.required_approvals, 2);
        assert!(rules.require_signed_commits);
        assert!(rules.require_linear_history);
    }

    #[test]
    fn test_strict_protection() {
        let rules = ProtectionRules::strict();

        assert!(rules.require_pull_request);
        assert_eq!(rules.required_approvals, 2);
        assert!(rules.require_signed_commits);
        assert!(rules.require_linear_history);
        assert!(rules.require_code_owners);
    }

    #[test]
    fn test_branch_manager_workflow() {
        let manager = BranchManager::new(GitWorkflow::GitFlow);

        assert_eq!(manager.default_branch, "develop");
        assert_eq!(manager.workflow, GitWorkflow::GitFlow);
    }

    #[test]
    fn test_validate_branch_name() {
        let manager = BranchManager::new(GitWorkflow::GitFlow);

        assert!(manager.validate_branch_name("feature/test").is_ok());
        assert!(manager.validate_branch_name("my branch").is_err());
        assert!(manager.validate_branch_name("-invalid").is_err());
        assert!(manager.validate_branch_name("branch..test").is_err());
    }

    #[test]
    fn test_suggest_branch_name() {
        let manager = BranchManager::new(GitWorkflow::GitFlow);

        assert_eq!(
            manager.suggest_branch_name(&BranchType::Feature, "User Login"),
            "feature/user-login"
        );
        assert_eq!(
            manager.suggest_branch_name(&BranchType::Bugfix, "Fix Bug"),
            "bugfix/fix-bug"
        );
    }

    #[test]
    fn test_branch_analysis() {
        let mut manager = BranchManager::new(GitWorkflow::GitFlow);

        manager.add_branch(Branch::new("main"));
        manager.add_branch(Branch::new("feature/a"));
        manager.add_branch(Branch::new("feature/b").set_merged(true));
        manager.add_branch(Branch::new("bugfix/c"));

        let analysis = manager.analyze();

        assert_eq!(analysis.total, 4);
        assert_eq!(analysis.features, 2);
        assert_eq!(analysis.bugfixes, 1);
        assert_eq!(analysis.merged, 1);
    }

    #[test]
    fn test_get_merge_target() {
        let manager = BranchManager::new(GitWorkflow::GitFlow);

        let feature = Branch::new("feature/test");
        assert_eq!(manager.get_merge_target(&feature), "develop");

        let hotfix = Branch::new("hotfix/urgent");
        assert_eq!(manager.get_merge_target(&hotfix), "main");
    }

    #[test]
    fn test_generate_create_command() {
        let manager = BranchManager::new(GitWorkflow::GitFlow);

        let commands = manager.generate_create_command(&BranchType::Feature, "new-feature");

        assert_eq!(commands.len(), 3);
        assert!(commands[0].contains("git fetch"));
        assert!(commands[1].contains("git checkout -b feature/new-feature"));
        assert!(commands[2].contains("git push -u"));
    }

    #[test]
    fn test_workflow_protected_branches() {
        assert_eq!(
            GitWorkflow::GitFlow.protected_branches(),
            vec!["main", "develop"]
        );
        assert_eq!(GitWorkflow::GitHubFlow.protected_branches(), vec!["main"]);
        assert_eq!(
            GitWorkflow::GitLabFlow.protected_branches(),
            vec!["main", "staging", "production"]
        );
    }

    #[test]
    fn test_health_score() {
        let analysis = BranchAnalysis {
            total: 10,
            stale: 0,
            merged: 0,
            needs_rebase: 0,
            ..Default::default()
        };
        assert_eq!(analysis.health_score(), 100.0);

        let analysis2 = BranchAnalysis {
            total: 10,
            stale: 5,
            merged: 2,
            needs_rebase: 3,
            ..Default::default()
        };
        assert!(analysis2.health_score() < 100.0);
    }
}
