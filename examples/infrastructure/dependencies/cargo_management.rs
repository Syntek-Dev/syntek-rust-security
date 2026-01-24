//! Cargo Dependency Management
//!
//! Implements dependency management patterns including version resolution,
//! feature flag optimization, and dependency auditing.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

/// Cargo.toml dependency
#[derive(Debug, Clone)]
pub struct Dependency {
    /// Crate name
    pub name: String,
    /// Version requirement
    pub version: VersionReq,
    /// Optional dependency
    pub optional: bool,
    /// Default features enabled
    pub default_features: bool,
    /// Enabled features
    pub features: Vec<String>,
    /// Git source
    pub git: Option<GitSource>,
    /// Path source
    pub path: Option<PathBuf>,
    /// Target platform
    pub target: Option<String>,
}

#[derive(Debug, Clone)]
pub struct VersionReq {
    /// Original requirement string
    pub original: String,
    /// Comparator
    pub comparator: Comparator,
    /// Major version
    pub major: u32,
    /// Minor version
    pub minor: Option<u32>,
    /// Patch version
    pub patch: Option<u32>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Comparator {
    Exact,     // =
    Caret,     // ^
    Tilde,     // ~
    GreaterEq, // >=
    Greater,   // >
    LessEq,    // <=
    Less,      // <
    Wildcard,  // *
}

#[derive(Debug, Clone)]
pub struct GitSource {
    pub url: String,
    pub branch: Option<String>,
    pub tag: Option<String>,
    pub rev: Option<String>,
}

/// Resolved dependency version
#[derive(Debug, Clone)]
pub struct ResolvedDependency {
    pub name: String,
    pub version: Version,
    pub features: Vec<String>,
    pub dependencies: Vec<String>,
    pub checksum: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub pre: Option<String>,
}

impl Version {
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let (version_part, pre) = if let Some(idx) = s.find('-') {
            (&s[..idx], Some(s[idx + 1..].to_string()))
        } else {
            (s, None)
        };

        let parts: Vec<&str> = version_part.split('.').collect();
        if parts.is_empty() {
            return Err("Empty version string".to_string());
        }

        let major = parts[0].parse().map_err(|_| "Invalid major version")?;
        let minor = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let patch = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);

        Ok(Self {
            major,
            minor,
            patch,
            pre,
        })
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if let Some(ref pre) = self.pre {
            write!(f, "-{}", pre)?;
        }
        Ok(())
    }
}

/// Dependency manager
pub struct DependencyManager {
    /// Project root
    project_root: PathBuf,
    /// Parsed dependencies
    dependencies: HashMap<String, Dependency>,
    /// Dev dependencies
    dev_dependencies: HashMap<String, Dependency>,
    /// Build dependencies
    build_dependencies: HashMap<String, Dependency>,
    /// Available crate versions (from registry)
    available_versions: HashMap<String, Vec<Version>>,
}

impl DependencyManager {
    /// Create new dependency manager
    pub fn new(project_root: PathBuf) -> Self {
        Self {
            project_root,
            dependencies: HashMap::new(),
            dev_dependencies: HashMap::new(),
            build_dependencies: HashMap::new(),
            available_versions: HashMap::new(),
        }
    }

    /// Parse Cargo.toml
    pub fn parse_cargo_toml(&mut self) -> Result<(), String> {
        let cargo_path = self.project_root.join("Cargo.toml");
        let content = fs::read_to_string(&cargo_path)
            .map_err(|e| format!("Failed to read Cargo.toml: {}", e))?;

        self.parse_toml_content(&content)
    }

    fn parse_toml_content(&mut self, content: &str) -> Result<(), String> {
        let mut current_section = "";
        let mut current_dep_name = String::new();
        let mut in_dep_table = false;

        for line in content.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Section headers
            if line.starts_with('[') && line.ends_with(']') {
                current_section = match &line[1..line.len() - 1] {
                    "dependencies" => "deps",
                    "dev-dependencies" => "dev-deps",
                    "build-dependencies" => "build-deps",
                    _ => {
                        in_dep_table = false;
                        ""
                    }
                };
                in_dep_table = false;
                continue;
            }

            // Inline table dependency (e.g., foo.version = "1.0")
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim().trim_matches('"');

                if key.contains('.') {
                    // Complex dependency (foo.version, foo.features, etc.)
                    let parts: Vec<&str> = key.split('.').collect();
                    if parts.len() >= 2 {
                        let dep_name = parts[0];
                        let field = parts[1];

                        let deps = match current_section {
                            "deps" => &mut self.dependencies,
                            "dev-deps" => &mut self.dev_dependencies,
                            "build-deps" => &mut self.build_dependencies,
                            _ => continue,
                        };

                        let dep = deps
                            .entry(dep_name.to_string())
                            .or_insert_with(|| Dependency {
                                name: dep_name.to_string(),
                                version: VersionReq {
                                    original: String::new(),
                                    comparator: Comparator::Caret,
                                    major: 0,
                                    minor: None,
                                    patch: None,
                                },
                                optional: false,
                                default_features: true,
                                features: Vec::new(),
                                git: None,
                                path: None,
                                target: None,
                            });

                        match field {
                            "version" => dep.version = self.parse_version_req(value)?,
                            "optional" => dep.optional = value == "true",
                            "default-features" => dep.default_features = value == "true",
                            "git" => {
                                dep.git = Some(GitSource {
                                    url: value.to_string(),
                                    branch: None,
                                    tag: None,
                                    rev: None,
                                })
                            }
                            "path" => dep.path = Some(PathBuf::from(value)),
                            _ => {}
                        }
                    }
                } else {
                    // Simple dependency (foo = "1.0")
                    let deps = match current_section {
                        "deps" => &mut self.dependencies,
                        "dev-deps" => &mut self.dev_dependencies,
                        "build-deps" => &mut self.build_dependencies,
                        _ => continue,
                    };

                    deps.insert(
                        key.to_string(),
                        Dependency {
                            name: key.to_string(),
                            version: self.parse_version_req(value)?,
                            optional: false,
                            default_features: true,
                            features: Vec::new(),
                            git: None,
                            path: None,
                            target: None,
                        },
                    );
                }
            }
        }

        Ok(())
    }

    fn parse_version_req(&self, s: &str) -> Result<VersionReq, String> {
        let s = s.trim();

        let (comparator, version_str) = if s.starts_with(">=") {
            (Comparator::GreaterEq, &s[2..])
        } else if s.starts_with("<=") {
            (Comparator::LessEq, &s[2..])
        } else if s.starts_with('>') {
            (Comparator::Greater, &s[1..])
        } else if s.starts_with('<') {
            (Comparator::Less, &s[1..])
        } else if s.starts_with('=') {
            (Comparator::Exact, &s[1..])
        } else if s.starts_with('~') {
            (Comparator::Tilde, &s[1..])
        } else if s.starts_with('^') {
            (Comparator::Caret, &s[1..])
        } else if s == "*" {
            (Comparator::Wildcard, s)
        } else {
            (Comparator::Caret, s) // Default is caret
        };

        let version_str = version_str.trim();

        if comparator == Comparator::Wildcard {
            return Ok(VersionReq {
                original: s.to_string(),
                comparator,
                major: 0,
                minor: None,
                patch: None,
            });
        }

        let parts: Vec<&str> = version_str.split('.').collect();
        let major = parts
            .first()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| format!("Invalid version: {}", s))?;
        let minor = parts.get(1).and_then(|s| s.parse().ok());
        let patch = parts.get(2).and_then(|s| s.parse().ok());

        Ok(VersionReq {
            original: s.to_string(),
            comparator,
            major,
            minor,
            patch,
        })
    }

    /// Add available version for a crate
    pub fn add_available_version(&mut self, crate_name: &str, version: Version) {
        self.available_versions
            .entry(crate_name.to_string())
            .or_default()
            .push(version);
    }

    /// Check if a version satisfies a requirement
    pub fn version_satisfies(&self, version: &Version, req: &VersionReq) -> bool {
        match req.comparator {
            Comparator::Exact => {
                version.major == req.major
                    && req.minor.map_or(true, |m| version.minor == m)
                    && req.patch.map_or(true, |p| version.patch == p)
            }
            Comparator::Caret => {
                if req.major == 0 {
                    if let Some(minor) = req.minor {
                        if minor == 0 {
                            // ^0.0.x only matches 0.0.x
                            version.major == 0
                                && version.minor == 0
                                && req.patch.map_or(true, |p| version.patch >= p)
                        } else {
                            // ^0.x matches 0.x.y
                            version.major == 0
                                && version.minor == minor
                                && req.patch.map_or(true, |p| version.patch >= p)
                        }
                    } else {
                        version.major == 0
                    }
                } else {
                    version.major == req.major
                        && (version.minor > req.minor.unwrap_or(0)
                            || (version.minor == req.minor.unwrap_or(0)
                                && version.patch >= req.patch.unwrap_or(0)))
                }
            }
            Comparator::Tilde => {
                version.major == req.major
                    && version.minor == req.minor.unwrap_or(0)
                    && version.patch >= req.patch.unwrap_or(0)
            }
            Comparator::GreaterEq => {
                version.major > req.major
                    || (version.major == req.major && version.minor > req.minor.unwrap_or(0))
                    || (version.major == req.major
                        && version.minor == req.minor.unwrap_or(0)
                        && version.patch >= req.patch.unwrap_or(0))
            }
            Comparator::Greater => {
                version.major > req.major
                    || (version.major == req.major && version.minor > req.minor.unwrap_or(0))
                    || (version.major == req.major
                        && version.minor == req.minor.unwrap_or(0)
                        && version.patch > req.patch.unwrap_or(0))
            }
            Comparator::LessEq => {
                version.major < req.major
                    || (version.major == req.major && version.minor < req.minor.unwrap_or(u32::MAX))
                    || (version.major == req.major
                        && version.minor == req.minor.unwrap_or(u32::MAX)
                        && version.patch <= req.patch.unwrap_or(u32::MAX))
            }
            Comparator::Less => {
                version.major < req.major
                    || (version.major == req.major && version.minor < req.minor.unwrap_or(u32::MAX))
                    || (version.major == req.major
                        && version.minor == req.minor.unwrap_or(u32::MAX)
                        && version.patch < req.patch.unwrap_or(u32::MAX))
            }
            Comparator::Wildcard => true,
        }
    }

    /// Find best matching version
    pub fn find_best_version(&self, crate_name: &str, req: &VersionReq) -> Option<&Version> {
        self.available_versions
            .get(crate_name)?
            .iter()
            .filter(|v| self.version_satisfies(v, req))
            .max()
    }

    /// Check for outdated dependencies
    pub fn check_outdated(&self) -> Vec<OutdatedDependency> {
        let mut outdated = Vec::new();

        for (name, dep) in &self.dependencies {
            if let Some(versions) = self.available_versions.get(name) {
                if let Some(latest) = versions.iter().max() {
                    if let Some(current) = self.find_best_version(name, &dep.version) {
                        if latest > current {
                            outdated.push(OutdatedDependency {
                                name: name.clone(),
                                current_version: current.clone(),
                                latest_version: latest.clone(),
                                required: dep.version.original.clone(),
                            });
                        }
                    }
                }
            }
        }

        outdated
    }

    /// Analyze feature usage
    pub fn analyze_features(&self) -> FeatureAnalysis {
        let mut analysis = FeatureAnalysis::default();

        for (name, dep) in &self.dependencies {
            analysis.total_dependencies += 1;

            if dep.optional {
                analysis.optional_dependencies += 1;
            }

            if !dep.default_features {
                analysis.default_features_disabled += 1;
            }

            analysis.total_features += dep.features.len();

            for feature in &dep.features {
                *analysis
                    .feature_usage
                    .entry(format!("{}/{}", name, feature))
                    .or_insert(0) += 1;
            }
        }

        analysis
    }

    /// Get all dependencies
    pub fn get_dependencies(&self) -> &HashMap<String, Dependency> {
        &self.dependencies
    }

    /// Get dev dependencies
    pub fn get_dev_dependencies(&self) -> &HashMap<String, Dependency> {
        &self.dev_dependencies
    }

    /// Get build dependencies
    pub fn get_build_dependencies(&self) -> &HashMap<String, Dependency> {
        &self.build_dependencies
    }

    /// Generate Cargo.toml content
    pub fn generate_cargo_toml(&self) -> String {
        let mut toml = String::new();

        toml.push_str("[package]\n");
        toml.push_str("name = \"example\"\n");
        toml.push_str("version = \"0.1.0\"\n");
        toml.push_str("edition = \"2021\"\n\n");

        if !self.dependencies.is_empty() {
            toml.push_str("[dependencies]\n");
            for (name, dep) in &self.dependencies {
                toml.push_str(&self.format_dependency(name, dep));
            }
            toml.push('\n');
        }

        if !self.dev_dependencies.is_empty() {
            toml.push_str("[dev-dependencies]\n");
            for (name, dep) in &self.dev_dependencies {
                toml.push_str(&self.format_dependency(name, dep));
            }
            toml.push('\n');
        }

        if !self.build_dependencies.is_empty() {
            toml.push_str("[build-dependencies]\n");
            for (name, dep) in &self.build_dependencies {
                toml.push_str(&self.format_dependency(name, dep));
            }
        }

        toml
    }

    fn format_dependency(&self, name: &str, dep: &Dependency) -> String {
        if dep.features.is_empty()
            && dep.default_features
            && dep.git.is_none()
            && dep.path.is_none()
            && !dep.optional
        {
            // Simple format
            format!("{} = \"{}\"\n", name, dep.version.original)
        } else {
            // Complex format
            let mut parts = vec![format!("version = \"{}\"", dep.version.original)];

            if !dep.default_features {
                parts.push("default-features = false".to_string());
            }

            if !dep.features.is_empty() {
                parts.push(format!(
                    "features = [{}]",
                    dep.features
                        .iter()
                        .map(|f| format!("\"{}\"", f))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }

            if dep.optional {
                parts.push("optional = true".to_string());
            }

            if let Some(ref git) = dep.git {
                parts.push(format!("git = \"{}\"", git.url));
            }

            if let Some(ref path) = dep.path {
                parts.push(format!("path = \"{}\"", path.display()));
            }

            format!("{} = {{ {} }}\n", name, parts.join(", "))
        }
    }
}

#[derive(Debug, Clone)]
pub struct OutdatedDependency {
    pub name: String,
    pub current_version: Version,
    pub latest_version: Version,
    pub required: String,
}

#[derive(Debug, Default, Clone)]
pub struct FeatureAnalysis {
    pub total_dependencies: usize,
    pub optional_dependencies: usize,
    pub default_features_disabled: usize,
    pub total_features: usize,
    pub feature_usage: HashMap<String, usize>,
}

fn main() {
    println!("=== Cargo Dependency Management Demo ===\n");

    // Create dependency manager
    let mut manager = DependencyManager::new(PathBuf::from("."));

    // Parse sample Cargo.toml content
    let sample_toml = r#"
[package]
name = "example"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = { version = "1.0", features = ["derive"] }
tokio = { version = "1.0", features = ["full"], default-features = false }
anyhow = "1.0"
clap = { version = "4.0", optional = true }

[dev-dependencies]
criterion = "0.5"

[build-dependencies]
cc = "1.0"
"#;

    if let Err(e) = manager.parse_toml_content(sample_toml) {
        println!("Parse error: {}", e);
        return;
    }

    // Display parsed dependencies
    println!("Dependencies:");
    for (name, dep) in manager.get_dependencies() {
        println!("  {} = \"{}\"", name, dep.version.original);
        if !dep.features.is_empty() {
            println!("    features: {:?}", dep.features);
        }
        if !dep.default_features {
            println!("    default-features: false");
        }
        if dep.optional {
            println!("    optional: true");
        }
    }

    println!("\nDev Dependencies:");
    for (name, dep) in manager.get_dev_dependencies() {
        println!("  {} = \"{}\"", name, dep.version.original);
    }

    println!("\nBuild Dependencies:");
    for (name, dep) in manager.get_build_dependencies() {
        println!("  {} = \"{}\"", name, dep.version.original);
    }

    // Add available versions for testing
    manager.add_available_version("serde", Version::parse("1.0.100").unwrap());
    manager.add_available_version("serde", Version::parse("1.0.150").unwrap());
    manager.add_available_version("serde", Version::parse("1.0.200").unwrap());
    manager.add_available_version("tokio", Version::parse("1.0.0").unwrap());
    manager.add_available_version("tokio", Version::parse("1.35.0").unwrap());

    // Test version matching
    println!("\n=== Version Matching ===");

    let v1 = Version::parse("1.5.0").unwrap();
    let req1 = manager.parse_version_req("^1.0").unwrap();
    println!(
        "1.5.0 satisfies ^1.0: {}",
        manager.version_satisfies(&v1, &req1)
    );

    let v2 = Version::parse("2.0.0").unwrap();
    println!(
        "2.0.0 satisfies ^1.0: {}",
        manager.version_satisfies(&v2, &req1)
    );

    let req2 = manager.parse_version_req(">=1.0, <2.0").unwrap();
    println!(
        "1.5.0 satisfies >=1.0: {}",
        manager.version_satisfies(&v1, &req2)
    );

    // Find best version
    println!("\n=== Best Version Resolution ===");
    if let Some(serde_req) = manager.get_dependencies().get("serde") {
        if let Some(best) = manager.find_best_version("serde", &serde_req.version) {
            println!(
                "Best serde version for {}: {}",
                serde_req.version.original, best
            );
        }
    }

    // Check outdated
    println!("\n=== Outdated Dependencies ===");
    let outdated = manager.check_outdated();
    if outdated.is_empty() {
        println!("All dependencies are up to date!");
    } else {
        for dep in &outdated {
            println!(
                "  {} {} -> {} (requires {})",
                dep.name, dep.current_version, dep.latest_version, dep.required
            );
        }
    }

    // Feature analysis
    println!("\n=== Feature Analysis ===");
    let analysis = manager.analyze_features();
    println!("Total dependencies: {}", analysis.total_dependencies);
    println!("Optional dependencies: {}", analysis.optional_dependencies);
    println!(
        "Default features disabled: {}",
        analysis.default_features_disabled
    );
    println!("Total features enabled: {}", analysis.total_features);

    // Generate Cargo.toml
    println!("\n=== Generated Cargo.toml ===");
    println!("{}", manager.generate_cargo_toml());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_parsing() {
        let v = Version::parse("1.2.3").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 3);

        let v_pre = Version::parse("1.0.0-alpha").unwrap();
        assert_eq!(v_pre.pre, Some("alpha".to_string()));
    }

    #[test]
    fn test_version_comparison() {
        let v1 = Version::parse("1.0.0").unwrap();
        let v2 = Version::parse("1.0.1").unwrap();
        let v3 = Version::parse("1.1.0").unwrap();
        let v4 = Version::parse("2.0.0").unwrap();

        assert!(v1 < v2);
        assert!(v2 < v3);
        assert!(v3 < v4);
    }

    #[test]
    fn test_caret_requirement() {
        let manager = DependencyManager::new(PathBuf::from("."));

        let req = manager.parse_version_req("^1.2.3").unwrap();
        assert_eq!(req.comparator, Comparator::Caret);

        let v1 = Version::parse("1.2.3").unwrap();
        let v2 = Version::parse("1.3.0").unwrap();
        let v3 = Version::parse("2.0.0").unwrap();

        assert!(manager.version_satisfies(&v1, &req));
        assert!(manager.version_satisfies(&v2, &req));
        assert!(!manager.version_satisfies(&v3, &req));
    }

    #[test]
    fn test_tilde_requirement() {
        let manager = DependencyManager::new(PathBuf::from("."));

        let req = manager.parse_version_req("~1.2.3").unwrap();
        assert_eq!(req.comparator, Comparator::Tilde);

        let v1 = Version::parse("1.2.5").unwrap();
        let v2 = Version::parse("1.3.0").unwrap();

        assert!(manager.version_satisfies(&v1, &req));
        assert!(!manager.version_satisfies(&v2, &req));
    }

    #[test]
    fn test_exact_requirement() {
        let manager = DependencyManager::new(PathBuf::from("."));

        let req = manager.parse_version_req("=1.2.3").unwrap();

        let v1 = Version::parse("1.2.3").unwrap();
        let v2 = Version::parse("1.2.4").unwrap();

        assert!(manager.version_satisfies(&v1, &req));
        assert!(!manager.version_satisfies(&v2, &req));
    }

    #[test]
    fn test_toml_parsing() {
        let mut manager = DependencyManager::new(PathBuf::from("."));

        let toml = r#"
[dependencies]
serde = "1.0"
tokio = { version = "1.0", features = ["full"] }
"#;

        manager.parse_toml_content(toml).unwrap();

        assert!(manager.dependencies.contains_key("serde"));
        assert!(manager.dependencies.contains_key("tokio"));

        let tokio = &manager.dependencies["tokio"];
        assert!(tokio.features.contains(&"full".to_string()));
    }

    #[test]
    fn test_version_display() {
        let v = Version::parse("1.2.3").unwrap();
        assert_eq!(v.to_string(), "1.2.3");

        let v_pre = Version::parse("1.0.0-beta.1").unwrap();
        assert_eq!(v_pre.to_string(), "1.0.0-beta.1");
    }
}
