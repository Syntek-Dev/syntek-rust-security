//! Cargo project metadata extraction tool for Claude Code agents.
//!
//! Provides commands to extract project information, dependencies, build targets,
//! feature flags, and unsafe code analysis from Cargo projects. Outputs machine-readable
//! JSON for agent consumption.
//!
//! # Commands
//!
//! - `info` - Extract basic project metadata (name, version, authors, etc.)
//! - `deps` - List all dependencies with versions and features
//! - `targets` - List compilation targets (bins, libs, examples, tests, benches)
//! - `features` - List available feature flags and their dependencies
//! - `unsafe` - Scan for unsafe code blocks across the project

use anyhow::{Context, Result};
use cargo_metadata::{CargoOpt, Metadata, MetadataCommand, Package};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use walkdir::WalkDir;

#[derive(Parser)]
#[command(
    name = "cargo-tool",
    about = "Cargo project metadata extraction for Claude Code agents",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Path to Cargo.toml or project directory
    #[arg(short, long, global = true)]
    manifest_path: Option<PathBuf>,

    /// Output format (json only for now)
    #[arg(short, long, default_value = "json", global = true)]
    format: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Extract basic project metadata
    Info,
    /// List all dependencies with versions and features
    Deps {
        /// Include dev dependencies
        #[arg(long)]
        dev: bool,
        /// Include build dependencies
        #[arg(long)]
        build: bool,
    },
    /// List compilation targets
    Targets,
    /// List available feature flags
    Features,
    /// Scan for unsafe code blocks
    Unsafe {
        /// Show detailed locations
        #[arg(long)]
        detailed: bool,
    },
}

/// Project metadata extracted from Cargo.toml.
#[derive(Serialize, Deserialize)]
struct ProjectInfo {
    /// Package name.
    name: String,
    /// Package version.
    version: String,
    /// List of package authors.
    authors: Vec<String>,
    /// Rust edition (e.g., "2021").
    edition: String,
    /// Minimum supported Rust version (MSRV).
    rust_version: Option<String>,
    /// Package description.
    description: Option<String>,
    /// SPDX license identifier.
    license: Option<String>,
    /// Repository URL.
    repository: Option<String>,
    /// Homepage URL.
    homepage: Option<String>,
    /// Path to workspace root, if in a workspace.
    workspace_root: Option<String>,
    /// Path to Cargo.toml.
    manifest_path: String,
}

/// Information about a single dependency.
#[derive(Serialize, Deserialize)]
struct DependencyInfo {
    /// Dependency name.
    name: String,
    /// Version requirement string.
    version: String,
    /// Source (registry, git, path).
    source: String,
    /// Enabled features for this dependency.
    features: Vec<String>,
    /// Whether this is an optional dependency.
    optional: bool,
    /// Dependency kind: "Normal", "Development", or "Build".
    kind: String,
}

/// Information about a compilation target.
#[derive(Serialize, Deserialize)]
struct TargetInfo {
    /// Target name.
    name: String,
    /// Target kinds: "bin", "lib", "test", "bench", "example".
    kind: Vec<String>,
    /// Path to the target source file.
    src_path: String,
    /// Rust edition for this target.
    edition: String,
    /// Features required to build this target.
    required_features: Vec<String>,
}

/// Information about a feature flag.
#[derive(Serialize, Deserialize)]
struct FeatureInfo {
    /// Feature name.
    name: String,
    /// Dependencies activated by this feature.
    dependencies: Vec<String>,
    /// Whether this feature is enabled by default.
    enabled_by_default: bool,
}

/// Summary of unsafe code usage in the project.
#[derive(Serialize, Deserialize)]
struct UnsafeInfo {
    /// Total number of unsafe blocks found.
    total_unsafe_blocks: usize,
    /// Number of files containing unsafe code.
    files_with_unsafe: usize,
    /// Detailed locations of unsafe blocks.
    locations: Vec<UnsafeLocation>,
}

/// Location of an unsafe code block.
#[derive(Serialize, Deserialize)]
struct UnsafeLocation {
    /// Path to the source file.
    file: String,
    /// Line number of the unsafe block.
    line: usize,
    /// Code context around the unsafe block.
    context: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Info => handle_info(cli.manifest_path)?,
        Commands::Deps { dev, build } => handle_deps(cli.manifest_path, dev, build)?,
        Commands::Targets => handle_targets(cli.manifest_path)?,
        Commands::Features => handle_features(cli.manifest_path)?,
        Commands::Unsafe { detailed } => handle_unsafe(cli.manifest_path, detailed)?,
    };

    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

/// Extracts basic project metadata from Cargo.toml
fn handle_info(manifest_path: Option<PathBuf>) -> Result<serde_json::Value> {
    let metadata = get_metadata(manifest_path)?;
    let root_package = get_root_package(&metadata)?;

    let info = ProjectInfo {
        name: root_package.name.clone(),
        version: root_package.version.to_string(),
        authors: root_package.authors.clone(),
        edition: root_package.edition.to_string(),
        rust_version: root_package.rust_version.as_ref().map(|v| v.to_string()),
        description: root_package.description.clone(),
        license: root_package.license.clone(),
        repository: root_package.repository.clone(),
        homepage: root_package.homepage.clone(),
        workspace_root: Some(metadata.workspace_root.to_string()),
        manifest_path: root_package.manifest_path.to_string(),
    };

    Ok(serde_json::to_value(info)?)
}

/// Lists all dependencies with versions and features
fn handle_deps(
    manifest_path: Option<PathBuf>,
    include_dev: bool,
    include_build: bool,
) -> Result<serde_json::Value> {
    let metadata = get_metadata(manifest_path)?;
    let root_package = get_root_package(&metadata)?;

    let mut dependencies = Vec::new();

    for dep in &root_package.dependencies {
        // Filter based on dependency kind
        let kind = format!("{:?}", dep.kind);
        let should_include = match dep.kind {
            cargo_metadata::DependencyKind::Normal => true,
            cargo_metadata::DependencyKind::Development => include_dev,
            cargo_metadata::DependencyKind::Build => include_build,
            _ => false,
        };

        if !should_include {
            continue;
        }

        let dep_info = DependencyInfo {
            name: dep.name.clone(),
            version: dep.req.to_string(),
            source: dep
                .source
                .as_ref()
                .map(|s| s.to_string())
                .unwrap_or_else(|| "registry".to_string()),
            features: dep.features.clone(),
            optional: dep.optional,
            kind,
        };

        dependencies.push(dep_info);
    }

    Ok(serde_json::to_value(dependencies)?)
}

/// Lists all compilation targets (bins, libs, tests, etc.)
fn handle_targets(manifest_path: Option<PathBuf>) -> Result<serde_json::Value> {
    let metadata = get_metadata(manifest_path)?;
    let root_package = get_root_package(&metadata)?;

    let mut targets = Vec::new();

    for target in &root_package.targets {
        let target_info = TargetInfo {
            name: target.name.clone(),
            kind: target.kind.clone(),
            src_path: target.src_path.to_string(),
            edition: target.edition.to_string(),
            required_features: target.required_features.clone(),
        };

        targets.push(target_info);
    }

    Ok(serde_json::to_value(targets)?)
}

/// Lists available feature flags and their dependencies
fn handle_features(manifest_path: Option<PathBuf>) -> Result<serde_json::Value> {
    let metadata = get_metadata(manifest_path)?;
    let root_package = get_root_package(&metadata)?;

    let mut features = Vec::new();

    for (name, deps) in &root_package.features {
        let enabled_by_default = root_package
            .features
            .get("default")
            .map(|default_features| default_features.contains(name))
            .unwrap_or(false);

        let feature_info = FeatureInfo {
            name: name.clone(),
            dependencies: deps.clone(),
            enabled_by_default,
        };

        features.push(feature_info);
    }

    Ok(serde_json::to_value(features)?)
}

/// Scans for unsafe code blocks across the project
fn handle_unsafe(manifest_path: Option<PathBuf>, detailed: bool) -> Result<serde_json::Value> {
    let metadata = get_metadata(manifest_path)?;
    let root_package = get_root_package(&metadata)?;

    let package_dir = root_package
        .manifest_path
        .parent()
        .context("Failed to get package directory")?;

    let mut locations = Vec::new();
    let mut files_with_unsafe = std::collections::HashSet::new();
    let mut total_unsafe_blocks = 0;

    // Walk through all .rs files in src/
    for entry in WalkDir::new(package_dir.join("src"))
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }

        let content = std::fs::read_to_string(path)?;
        let relative_path = path.strip_prefix(package_dir).unwrap_or(path);

        for (line_num, line) in content.lines().enumerate() {
            if line.contains("unsafe") {
                total_unsafe_blocks += 1;
                files_with_unsafe.insert(relative_path.to_string_lossy().to_string());

                if detailed {
                    locations.push(UnsafeLocation {
                        file: relative_path.to_string_lossy().to_string(),
                        line: line_num + 1,
                        context: line.trim().to_string(),
                    });
                }
            }
        }
    }

    let unsafe_info = UnsafeInfo {
        total_unsafe_blocks,
        files_with_unsafe: files_with_unsafe.len(),
        locations: if detailed { locations } else { Vec::new() },
    };

    Ok(serde_json::to_value(unsafe_info)?)
}

/// Retrieves cargo metadata for the project
fn get_metadata(manifest_path: Option<PathBuf>) -> Result<Metadata> {
    let mut cmd = MetadataCommand::new();

    if let Some(path) = manifest_path {
        cmd.manifest_path(path);
    }

    cmd.features(CargoOpt::AllFeatures)
        .exec()
        .context("Failed to execute cargo metadata")
}

/// Gets the root package from metadata
fn get_root_package(metadata: &Metadata) -> Result<&Package> {
    metadata
        .root_package()
        .context("No root package found. Are you in a Cargo workspace?")
}
