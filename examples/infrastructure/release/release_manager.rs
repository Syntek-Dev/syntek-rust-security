//! Release Manager
//!
//! Comprehensive release management with:
//! - Release notes generation
//! - Asset building and signing
//! - Distribution channel management
//! - Rollback capabilities

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Release channel
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReleaseChannel {
    Stable,
    Beta,
    Nightly,
    LTS,
}

/// Release status
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleaseStatus {
    Draft,
    Pending,
    Published,
    Deprecated,
    Yanked,
}

/// A release
#[derive(Clone, Debug)]
pub struct Release {
    pub version: String,
    pub channel: ReleaseChannel,
    pub status: ReleaseStatus,
    pub title: String,
    pub notes: ReleaseNotes,
    pub assets: Vec<ReleaseAsset>,
    pub created_at: u64,
    pub published_at: Option<u64>,
    pub signatures: HashMap<String, String>,
    pub metadata: ReleaseMetadata,
}

/// Release notes
#[derive(Clone, Debug, Default)]
pub struct ReleaseNotes {
    pub summary: String,
    pub breaking_changes: Vec<String>,
    pub features: Vec<String>,
    pub fixes: Vec<String>,
    pub security: Vec<String>,
    pub deprecations: Vec<String>,
    pub contributors: Vec<String>,
    pub migration_guide: Option<String>,
}

/// Release asset (binary, archive, etc.)
#[derive(Clone, Debug)]
pub struct ReleaseAsset {
    pub name: String,
    pub path: PathBuf,
    pub size: u64,
    pub content_type: String,
    pub checksum_sha256: String,
    pub signature: Option<String>,
    pub target: Option<String>,
}

/// Release metadata
#[derive(Clone, Debug, Default)]
pub struct ReleaseMetadata {
    pub commit_sha: String,
    pub branch: String,
    pub rust_version: String,
    pub build_host: String,
    pub reproducible: bool,
}

/// Release configuration
#[derive(Clone, Debug)]
pub struct ReleaseConfig {
    pub project_name: String,
    pub repository_url: String,
    pub signing_key: Option<String>,
    pub channels: Vec<ReleaseChannel>,
    pub asset_patterns: Vec<String>,
    pub pre_release_hooks: Vec<String>,
    pub post_release_hooks: Vec<String>,
}

/// Release manager
pub struct ReleaseManager {
    config: ReleaseConfig,
    releases: Vec<Release>,
    current_draft: Option<Release>,
}

/// Release builder
pub struct ReleaseBuilder {
    version: String,
    channel: ReleaseChannel,
    title: Option<String>,
    notes: ReleaseNotes,
    assets: Vec<ReleaseAsset>,
    metadata: ReleaseMetadata,
}

impl ReleaseManager {
    /// Create new release manager
    pub fn new(config: ReleaseConfig) -> Self {
        Self {
            config,
            releases: Vec::new(),
            current_draft: None,
        }
    }

    /// Start a new release
    pub fn start_release(&mut self, version: &str, channel: ReleaseChannel) -> ReleaseBuilder {
        ReleaseBuilder::new(version, channel)
    }

    /// Create draft release
    pub fn create_draft(&mut self, builder: ReleaseBuilder) -> &Release {
        let release = builder.build();
        self.current_draft = Some(release);
        self.current_draft.as_ref().unwrap()
    }

    /// Publish the current draft
    pub fn publish(&mut self) -> Result<&Release, ReleaseError> {
        let mut draft = self.current_draft.take().ok_or(ReleaseError::NoDraft)?;

        // Validate release
        self.validate_release(&draft)?;

        // Set published timestamp
        draft.published_at = Some(current_timestamp());
        draft.status = ReleaseStatus::Published;

        self.releases.push(draft);
        Ok(self.releases.last().unwrap())
    }

    /// Validate release before publishing
    fn validate_release(&self, release: &Release) -> Result<(), ReleaseError> {
        if release.version.is_empty() {
            return Err(ReleaseError::InvalidVersion);
        }

        if release.assets.is_empty() {
            return Err(ReleaseError::NoAssets);
        }

        // Check for duplicate version
        if self.releases.iter().any(|r| r.version == release.version) {
            return Err(ReleaseError::DuplicateVersion);
        }

        // Verify all assets have checksums
        for asset in &release.assets {
            if asset.checksum_sha256.is_empty() {
                return Err(ReleaseError::MissingChecksum(asset.name.clone()));
            }
        }

        Ok(())
    }

    /// Yank a release (mark as unusable)
    pub fn yank(&mut self, version: &str) -> Result<(), ReleaseError> {
        let release = self
            .releases
            .iter_mut()
            .find(|r| r.version == version)
            .ok_or(ReleaseError::NotFound)?;

        release.status = ReleaseStatus::Yanked;
        Ok(())
    }

    /// Deprecate a release
    pub fn deprecate(&mut self, version: &str, successor: &str) -> Result<(), ReleaseError> {
        let release = self
            .releases
            .iter_mut()
            .find(|r| r.version == version)
            .ok_or(ReleaseError::NotFound)?;

        release.status = ReleaseStatus::Deprecated;
        release.notes.migration_guide = Some(format!(
            "This version is deprecated. Please upgrade to {}",
            successor
        ));
        Ok(())
    }

    /// Get latest release for channel
    pub fn latest(&self, channel: ReleaseChannel) -> Option<&Release> {
        self.releases
            .iter()
            .filter(|r| r.channel == channel && r.status == ReleaseStatus::Published)
            .last()
    }

    /// Get all releases
    pub fn all_releases(&self) -> &[Release] {
        &self.releases
    }

    /// Generate release notes from commits
    pub fn generate_notes_from_commits(commits: &[CommitInfo]) -> ReleaseNotes {
        let mut notes = ReleaseNotes::default();
        let mut contributors = std::collections::HashSet::new();

        for commit in commits {
            contributors.insert(commit.author.clone());

            let message = commit.message.to_lowercase();

            if message.starts_with("feat") || message.contains("[feature]") {
                notes.features.push(commit.message.clone());
            } else if message.starts_with("fix") || message.contains("[fix]") {
                notes.fixes.push(commit.message.clone());
            } else if message.starts_with("security") || message.contains("[security]") {
                notes.security.push(commit.message.clone());
            } else if message.contains("breaking") || message.contains("!:") {
                notes.breaking_changes.push(commit.message.clone());
            } else if message.starts_with("deprecate") {
                notes.deprecations.push(commit.message.clone());
            }
        }

        notes.contributors = contributors.into_iter().collect();
        notes
    }

    /// Generate markdown release notes
    pub fn generate_markdown(&self, release: &Release) -> String {
        let mut output = String::new();

        output.push_str(&format!("# {} - {}\n\n", release.title, release.version));

        if let Some(published) = release.published_at {
            output.push_str(&format!("Released: {}\n\n", format_timestamp(published)));
        }

        output.push_str(&format!("{}\n\n", release.notes.summary));

        if !release.notes.breaking_changes.is_empty() {
            output.push_str("## Breaking Changes\n\n");
            for change in &release.notes.breaking_changes {
                output.push_str(&format!("- {}\n", change));
            }
            output.push('\n');
        }

        if !release.notes.security.is_empty() {
            output.push_str("## Security\n\n");
            for fix in &release.notes.security {
                output.push_str(&format!("- {}\n", fix));
            }
            output.push('\n');
        }

        if !release.notes.features.is_empty() {
            output.push_str("## New Features\n\n");
            for feature in &release.notes.features {
                output.push_str(&format!("- {}\n", feature));
            }
            output.push('\n');
        }

        if !release.notes.fixes.is_empty() {
            output.push_str("## Bug Fixes\n\n");
            for fix in &release.notes.fixes {
                output.push_str(&format!("- {}\n", fix));
            }
            output.push('\n');
        }

        if !release.notes.deprecations.is_empty() {
            output.push_str("## Deprecations\n\n");
            for dep in &release.notes.deprecations {
                output.push_str(&format!("- {}\n", dep));
            }
            output.push('\n');
        }

        if let Some(guide) = &release.notes.migration_guide {
            output.push_str("## Migration Guide\n\n");
            output.push_str(guide);
            output.push_str("\n\n");
        }

        if !release.assets.is_empty() {
            output.push_str("## Downloads\n\n");
            output.push_str("| Asset | Size | SHA256 |\n");
            output.push_str("|-------|------|--------|\n");
            for asset in &release.assets {
                let size = format_size(asset.size);
                let checksum = &asset.checksum_sha256[..16];
                output.push_str(&format!(
                    "| {} | {} | `{}...` |\n",
                    asset.name, size, checksum
                ));
            }
            output.push('\n');
        }

        if !release.notes.contributors.is_empty() {
            output.push_str("## Contributors\n\n");
            for contributor in &release.notes.contributors {
                output.push_str(&format!("- @{}\n", contributor));
            }
        }

        output
    }
}

impl ReleaseBuilder {
    /// Create new release builder
    pub fn new(version: &str, channel: ReleaseChannel) -> Self {
        Self {
            version: version.to_string(),
            channel,
            title: None,
            notes: ReleaseNotes::default(),
            assets: Vec::new(),
            metadata: ReleaseMetadata::default(),
        }
    }

    /// Set release title
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Set release summary
    pub fn summary(mut self, summary: impl Into<String>) -> Self {
        self.notes.summary = summary.into();
        self
    }

    /// Add a feature
    pub fn feature(mut self, feature: impl Into<String>) -> Self {
        self.notes.features.push(feature.into());
        self
    }

    /// Add a bug fix
    pub fn fix(mut self, fix: impl Into<String>) -> Self {
        self.notes.fixes.push(fix.into());
        self
    }

    /// Add a security fix
    pub fn security_fix(mut self, fix: impl Into<String>) -> Self {
        self.notes.security.push(fix.into());
        self
    }

    /// Add a breaking change
    pub fn breaking_change(mut self, change: impl Into<String>) -> Self {
        self.notes.breaking_changes.push(change.into());
        self
    }

    /// Add migration guide
    pub fn migration_guide(mut self, guide: impl Into<String>) -> Self {
        self.notes.migration_guide = Some(guide.into());
        self
    }

    /// Add an asset
    pub fn asset(mut self, asset: ReleaseAsset) -> Self {
        self.assets.push(asset);
        self
    }

    /// Set metadata
    pub fn metadata(mut self, metadata: ReleaseMetadata) -> Self {
        self.metadata = metadata;
        self
    }

    /// Build the release
    pub fn build(self) -> Release {
        Release {
            version: self.version.clone(),
            channel: self.channel,
            status: ReleaseStatus::Draft,
            title: self
                .title
                .unwrap_or_else(|| format!("Release {}", self.version)),
            notes: self.notes,
            assets: self.assets,
            created_at: current_timestamp(),
            published_at: None,
            signatures: HashMap::new(),
            metadata: self.metadata,
        }
    }
}

impl ReleaseAsset {
    /// Create new asset
    pub fn new(name: impl Into<String>, path: PathBuf) -> Self {
        Self {
            name: name.into(),
            path,
            size: 0,
            content_type: "application/octet-stream".to_string(),
            checksum_sha256: String::new(),
            signature: None,
            target: None,
        }
    }

    /// Set size
    pub fn with_size(mut self, size: u64) -> Self {
        self.size = size;
        self
    }

    /// Set content type
    pub fn with_content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = content_type.into();
        self
    }

    /// Set checksum
    pub fn with_checksum(mut self, checksum: impl Into<String>) -> Self {
        self.checksum_sha256 = checksum.into();
        self
    }

    /// Set target platform
    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }
}

/// Commit information for release notes generation
#[derive(Clone, Debug)]
pub struct CommitInfo {
    pub sha: String,
    pub message: String,
    pub author: String,
    pub timestamp: u64,
}

/// Release error
#[derive(Debug)]
pub enum ReleaseError {
    NoDraft,
    InvalidVersion,
    NoAssets,
    DuplicateVersion,
    MissingChecksum(String),
    NotFound,
    SigningFailed,
}

impl fmt::Display for ReleaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReleaseError::NoDraft => write!(f, "No draft release to publish"),
            ReleaseError::InvalidVersion => write!(f, "Invalid version format"),
            ReleaseError::NoAssets => write!(f, "Release has no assets"),
            ReleaseError::DuplicateVersion => write!(f, "Version already exists"),
            ReleaseError::MissingChecksum(name) => {
                write!(f, "Asset '{}' missing checksum", name)
            }
            ReleaseError::NotFound => write!(f, "Release not found"),
            ReleaseError::SigningFailed => write!(f, "Failed to sign release"),
        }
    }
}

impl std::error::Error for ReleaseError {}

impl fmt::Display for ReleaseChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReleaseChannel::Stable => write!(f, "stable"),
            ReleaseChannel::Beta => write!(f, "beta"),
            ReleaseChannel::Nightly => write!(f, "nightly"),
            ReleaseChannel::LTS => write!(f, "lts"),
        }
    }
}

impl fmt::Display for ReleaseStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReleaseStatus::Draft => write!(f, "draft"),
            ReleaseStatus::Pending => write!(f, "pending"),
            ReleaseStatus::Published => write!(f, "published"),
            ReleaseStatus::Deprecated => write!(f, "deprecated"),
            ReleaseStatus::Yanked => write!(f, "yanked"),
        }
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn format_timestamp(ts: u64) -> String {
    // Simple date formatting
    let days = ts / 86400;
    let years = 1970 + days / 365;
    let remaining_days = days % 365;
    let months = remaining_days / 30 + 1;
    let day = remaining_days % 30 + 1;
    format!("{:04}-{:02}-{:02}", years, months, day)
}

fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} bytes", bytes)
    }
}

fn main() {
    println!("=== Release Manager Demo ===\n");

    let config = ReleaseConfig {
        project_name: "my-security-tool".to_string(),
        repository_url: "https://github.com/example/my-security-tool".to_string(),
        signing_key: Some("signing-key-id".to_string()),
        channels: vec![ReleaseChannel::Stable, ReleaseChannel::Beta],
        asset_patterns: vec!["target/release/*".to_string()],
        pre_release_hooks: vec!["cargo test".to_string()],
        post_release_hooks: vec!["notify-discord".to_string()],
    };

    let mut manager = ReleaseManager::new(config);

    // Create a release
    let builder = manager
        .start_release("1.0.0", ReleaseChannel::Stable)
        .title("First Stable Release")
        .summary(
            "The first stable release of my-security-tool with comprehensive security features.",
        )
        .feature("Add encryption module with AES-256-GCM support")
        .feature("Add secure key storage using OS keyring")
        .feature("Add audit logging with tamper detection")
        .fix("Fix memory leak in connection pool")
        .fix("Fix race condition in concurrent encryption")
        .security_fix("CVE-2025-0001: Fix timing attack in password verification")
        .security_fix("Upgrade openssl dependency to fix vulnerability")
        .asset(
            ReleaseAsset::new(
                "my-security-tool-linux-x64",
                PathBuf::from("target/release/my-security-tool"),
            )
            .with_size(15_000_000)
            .with_content_type("application/x-executable")
            .with_checksum("a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456")
            .with_target("x86_64-unknown-linux-gnu"),
        )
        .asset(
            ReleaseAsset::new(
                "my-security-tool-macos-x64",
                PathBuf::from("target/release/my-security-tool"),
            )
            .with_size(14_500_000)
            .with_content_type("application/x-mach-binary")
            .with_checksum("b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef1234567a")
            .with_target("x86_64-apple-darwin"),
        )
        .metadata(ReleaseMetadata {
            commit_sha: "abc123def456".to_string(),
            branch: "main".to_string(),
            rust_version: "1.92.0".to_string(),
            build_host: "ubuntu-22.04".to_string(),
            reproducible: true,
        });

    // Create draft
    manager.create_draft(builder);
    println!("Created draft release\n");

    // Publish
    match manager.publish() {
        Ok(release) => {
            println!(
                "Published release: {} ({})",
                release.version, release.status
            );
            println!("\n{}", manager.generate_markdown(release));
        }
        Err(e) => println!("Failed to publish: {}", e),
    }

    // Create beta release
    let beta = manager.start_release("1.1.0-beta.1", ReleaseChannel::Beta)
        .title("1.1.0 Beta 1")
        .summary("Beta release with new HSM support.")
        .feature("Add HSM integration for key storage")
        .breaking_change("Changed Config struct - migration required")
        .migration_guide("Update your Config initialization:\n\n```rust\n// Old\nlet config = Config::new();\n\n// New\nlet config = Config::builder().build();\n```")
        .asset(
            ReleaseAsset::new("my-security-tool-beta-linux", PathBuf::from("target/release/my-security-tool"))
                .with_size(16_000_000)
                .with_checksum("c3d4e5f6789012345678901234567890abcdef1234567890abcdef1234567ab2")
        );

    manager.create_draft(beta);
    manager.publish().unwrap();

    // Test notes generation from commits
    println!("\n=== Auto-generated Notes from Commits ===\n");

    let commits = vec![
        CommitInfo {
            sha: "abc123".to_string(),
            message: "feat: Add new encryption algorithm".to_string(),
            author: "alice".to_string(),
            timestamp: current_timestamp(),
        },
        CommitInfo {
            sha: "def456".to_string(),
            message: "fix: Memory leak in key derivation".to_string(),
            author: "bob".to_string(),
            timestamp: current_timestamp(),
        },
        CommitInfo {
            sha: "ghi789".to_string(),
            message: "security: Patch timing vulnerability".to_string(),
            author: "alice".to_string(),
            timestamp: current_timestamp(),
        },
        CommitInfo {
            sha: "jkl012".to_string(),
            message: "feat!: Breaking API change for Config".to_string(),
            author: "charlie".to_string(),
            timestamp: current_timestamp(),
        },
    ];

    let notes = ReleaseManager::generate_notes_from_commits(&commits);
    println!("Features: {:?}", notes.features);
    println!("Fixes: {:?}", notes.fixes);
    println!("Security: {:?}", notes.security);
    println!("Contributors: {:?}", notes.contributors);

    // Show all releases
    println!("\n=== All Releases ===\n");
    for release in manager.all_releases() {
        println!(
            "  {} ({}) - {} - {}",
            release.version, release.channel, release.status, release.title
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> ReleaseConfig {
        ReleaseConfig {
            project_name: "test".to_string(),
            repository_url: "https://example.com".to_string(),
            signing_key: None,
            channels: vec![ReleaseChannel::Stable],
            asset_patterns: vec![],
            pre_release_hooks: vec![],
            post_release_hooks: vec![],
        }
    }

    #[test]
    fn test_create_release() {
        let mut manager = ReleaseManager::new(test_config());

        let builder = manager
            .start_release("1.0.0", ReleaseChannel::Stable)
            .title("Test Release")
            .feature("New feature");

        let draft = manager.create_draft(builder);
        assert_eq!(draft.version, "1.0.0");
        assert_eq!(draft.status, ReleaseStatus::Draft);
    }

    #[test]
    fn test_publish_release() {
        let mut manager = ReleaseManager::new(test_config());

        let builder = manager
            .start_release("1.0.0", ReleaseChannel::Stable)
            .asset(ReleaseAsset::new("binary", PathBuf::from("test")).with_checksum("abc123"));

        manager.create_draft(builder);
        let result = manager.publish();

        assert!(result.is_ok());
        let release = result.unwrap();
        assert_eq!(release.status, ReleaseStatus::Published);
        assert!(release.published_at.is_some());
    }

    #[test]
    fn test_publish_without_assets_fails() {
        let mut manager = ReleaseManager::new(test_config());

        let builder = manager.start_release("1.0.0", ReleaseChannel::Stable);
        manager.create_draft(builder);

        let result = manager.publish();
        assert!(matches!(result, Err(ReleaseError::NoAssets)));
    }

    #[test]
    fn test_publish_without_checksum_fails() {
        let mut manager = ReleaseManager::new(test_config());

        let builder = manager
            .start_release("1.0.0", ReleaseChannel::Stable)
            .asset(ReleaseAsset::new("binary", PathBuf::from("test")));

        manager.create_draft(builder);
        let result = manager.publish();

        assert!(matches!(result, Err(ReleaseError::MissingChecksum(_))));
    }

    #[test]
    fn test_duplicate_version_fails() {
        let mut manager = ReleaseManager::new(test_config());

        // First release
        let builder = manager
            .start_release("1.0.0", ReleaseChannel::Stable)
            .asset(ReleaseAsset::new("b", PathBuf::from("t")).with_checksum("c"));
        manager.create_draft(builder);
        manager.publish().unwrap();

        // Duplicate
        let builder = manager
            .start_release("1.0.0", ReleaseChannel::Stable)
            .asset(ReleaseAsset::new("b", PathBuf::from("t")).with_checksum("c"));
        manager.create_draft(builder);

        let result = manager.publish();
        assert!(matches!(result, Err(ReleaseError::DuplicateVersion)));
    }

    #[test]
    fn test_yank_release() {
        let mut manager = ReleaseManager::new(test_config());

        let builder = manager
            .start_release("1.0.0", ReleaseChannel::Stable)
            .asset(ReleaseAsset::new("b", PathBuf::from("t")).with_checksum("c"));
        manager.create_draft(builder);
        manager.publish().unwrap();

        let result = manager.yank("1.0.0");
        assert!(result.is_ok());

        let release = manager.all_releases().first().unwrap();
        assert_eq!(release.status, ReleaseStatus::Yanked);
    }

    #[test]
    fn test_latest_release() {
        let mut manager = ReleaseManager::new(test_config());

        for version in ["1.0.0", "1.1.0", "1.2.0"] {
            let builder = manager
                .start_release(version, ReleaseChannel::Stable)
                .asset(ReleaseAsset::new("b", PathBuf::from("t")).with_checksum("c"));
            manager.create_draft(builder);
            manager.publish().unwrap();
        }

        let latest = manager.latest(ReleaseChannel::Stable).unwrap();
        assert_eq!(latest.version, "1.2.0");
    }

    #[test]
    fn test_generate_notes_from_commits() {
        let commits = vec![
            CommitInfo {
                sha: "1".to_string(),
                message: "feat: Add feature".to_string(),
                author: "alice".to_string(),
                timestamp: 0,
            },
            CommitInfo {
                sha: "2".to_string(),
                message: "fix: Fix bug".to_string(),
                author: "bob".to_string(),
                timestamp: 0,
            },
        ];

        let notes = ReleaseManager::generate_notes_from_commits(&commits);

        assert_eq!(notes.features.len(), 1);
        assert_eq!(notes.fixes.len(), 1);
        assert_eq!(notes.contributors.len(), 2);
    }

    #[test]
    fn test_release_builder() {
        let release = ReleaseBuilder::new("1.0.0", ReleaseChannel::Stable)
            .title("Test")
            .summary("Summary")
            .feature("Feature 1")
            .fix("Fix 1")
            .security_fix("Security 1")
            .build();

        assert_eq!(release.version, "1.0.0");
        assert_eq!(release.title, "Test");
        assert_eq!(release.notes.features.len(), 1);
        assert_eq!(release.notes.fixes.len(), 1);
        assert_eq!(release.notes.security.len(), 1);
    }

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(500), "500 bytes");
        assert_eq!(format_size(1024), "1.00 KB");
        assert_eq!(format_size(1024 * 1024), "1.00 MB");
        assert_eq!(format_size(1024 * 1024 * 1024), "1.00 GB");
    }
}
