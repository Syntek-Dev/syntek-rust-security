//! Cargo Deny Configuration Example
//!
//! Demonstrates programmatic generation and management of cargo-deny
//! configuration for supply chain security.

use std::collections::{HashMap, HashSet};

/// License categories for cargo-deny
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LicenseCategory {
    Allow,
    Deny,
    Copyleft,
    Permissive,
}

/// Cargo-deny configuration generator
#[derive(Debug, Clone)]
pub struct DenyConfig {
    pub advisories: AdvisoriesConfig,
    pub licenses: LicensesConfig,
    pub bans: BansConfig,
    pub sources: SourcesConfig,
}

#[derive(Debug, Clone, Default)]
pub struct AdvisoriesConfig {
    pub db_path: Option<String>,
    pub db_urls: Vec<String>,
    pub vulnerability: String,
    pub unmaintained: String,
    pub yanked: String,
    pub notice: String,
    pub ignore: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct LicensesConfig {
    pub unlicensed: String,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub copyleft: String,
    pub allow_osi_fsf_free: String,
    pub default: String,
    pub confidence_threshold: f32,
    pub exceptions: HashMap<String, Vec<String>>,
    pub clarify: HashMap<String, LicenseClarification>,
}

#[derive(Debug, Clone)]
pub struct LicenseClarification {
    pub license: String,
    pub override_git_url: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct BansConfig {
    pub multiple_versions: String,
    pub wildcards: String,
    pub highlight: String,
    pub deny: Vec<CrateBan>,
    pub skip: Vec<CrateSkip>,
    pub skip_tree: Vec<CrateSkip>,
}

#[derive(Debug, Clone)]
pub struct CrateBan {
    pub name: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CrateSkip {
    pub name: String,
    pub version: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct SourcesConfig {
    pub unknown_registry: String,
    pub unknown_git: String,
    pub allow_registry: Vec<String>,
    pub allow_git: Vec<String>,
}

impl Default for DenyConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl DenyConfig {
    pub fn new() -> Self {
        Self {
            advisories: AdvisoriesConfig {
                db_path: None,
                db_urls: vec!["https://github.com/rustsec/advisory-db".to_string()],
                vulnerability: "deny".to_string(),
                unmaintained: "warn".to_string(),
                yanked: "warn".to_string(),
                notice: "warn".to_string(),
                ignore: Vec::new(),
            },
            licenses: LicensesConfig {
                unlicensed: "deny".to_string(),
                allow: vec![
                    "MIT".to_string(),
                    "Apache-2.0".to_string(),
                    "BSD-2-Clause".to_string(),
                    "BSD-3-Clause".to_string(),
                    "ISC".to_string(),
                    "Zlib".to_string(),
                    "0BSD".to_string(),
                    "CC0-1.0".to_string(),
                    "Unlicense".to_string(),
                ],
                deny: vec!["GPL-3.0".to_string(), "AGPL-3.0".to_string()],
                copyleft: "warn".to_string(),
                allow_osi_fsf_free: "neither".to_string(),
                default: "deny".to_string(),
                confidence_threshold: 0.8,
                exceptions: HashMap::new(),
                clarify: HashMap::new(),
            },
            bans: BansConfig {
                multiple_versions: "warn".to_string(),
                wildcards: "deny".to_string(),
                highlight: "all".to_string(),
                deny: Vec::new(),
                skip: Vec::new(),
                skip_tree: Vec::new(),
            },
            sources: SourcesConfig {
                unknown_registry: "deny".to_string(),
                unknown_git: "warn".to_string(),
                allow_registry: vec!["https://github.com/rust-lang/crates.io-index".to_string()],
                allow_git: Vec::new(),
            },
        }
    }

    /// Create a strict security-focused configuration
    pub fn strict() -> Self {
        let mut config = Self::new();
        config.advisories.unmaintained = "deny".to_string();
        config.advisories.yanked = "deny".to_string();
        config.bans.multiple_versions = "deny".to_string();
        config.sources.unknown_git = "deny".to_string();
        config
    }

    /// Add a banned crate
    pub fn ban_crate(&mut self, name: &str, reason: Option<&str>) -> &mut Self {
        self.bans.deny.push(CrateBan {
            name: name.to_string(),
            reason: reason.map(|s| s.to_string()),
        });
        self
    }

    /// Add a license exception
    pub fn add_license_exception(&mut self, crate_name: &str, licenses: Vec<&str>) -> &mut Self {
        self.licenses.exceptions.insert(
            crate_name.to_string(),
            licenses.iter().map(|s| s.to_string()).collect(),
        );
        self
    }

    /// Add an advisory to ignore
    pub fn ignore_advisory(&mut self, advisory_id: &str) -> &mut Self {
        self.advisories.ignore.push(advisory_id.to_string());
        self
    }

    /// Add an allowed git source
    pub fn allow_git_source(&mut self, url: &str) -> &mut Self {
        self.sources.allow_git.push(url.to_string());
        self
    }

    /// Generate TOML configuration
    pub fn to_toml(&self) -> String {
        let mut toml = String::new();

        // Advisories section
        toml.push_str("[advisories]\n");
        toml.push_str(&format!(
            "vulnerability = \"{}\"\n",
            self.advisories.vulnerability
        ));
        toml.push_str(&format!(
            "unmaintained = \"{}\"\n",
            self.advisories.unmaintained
        ));
        toml.push_str(&format!("yanked = \"{}\"\n", self.advisories.yanked));
        toml.push_str(&format!("notice = \"{}\"\n", self.advisories.notice));

        if !self.advisories.ignore.is_empty() {
            toml.push_str("ignore = [\n");
            for id in &self.advisories.ignore {
                toml.push_str(&format!("    \"{}\",\n", id));
            }
            toml.push_str("]\n");
        }
        toml.push('\n');

        // Licenses section
        toml.push_str("[licenses]\n");
        toml.push_str(&format!("unlicensed = \"{}\"\n", self.licenses.unlicensed));
        toml.push_str(&format!("copyleft = \"{}\"\n", self.licenses.copyleft));
        toml.push_str(&format!("default = \"{}\"\n", self.licenses.default));
        toml.push_str(&format!(
            "confidence-threshold = {}\n",
            self.licenses.confidence_threshold
        ));

        if !self.licenses.allow.is_empty() {
            toml.push_str("allow = [\n");
            for license in &self.licenses.allow {
                toml.push_str(&format!("    \"{}\",\n", license));
            }
            toml.push_str("]\n");
        }

        if !self.licenses.deny.is_empty() {
            toml.push_str("deny = [\n");
            for license in &self.licenses.deny {
                toml.push_str(&format!("    \"{}\",\n", license));
            }
            toml.push_str("]\n");
        }

        // License exceptions
        if !self.licenses.exceptions.is_empty() {
            toml.push_str("\n[[licenses.exceptions]]\n");
            for (crate_name, licenses) in &self.licenses.exceptions {
                toml.push_str(&format!("name = \"{}\"\n", crate_name));
                toml.push_str("allow = [\n");
                for license in licenses {
                    toml.push_str(&format!("    \"{}\",\n", license));
                }
                toml.push_str("]\n");
            }
        }
        toml.push('\n');

        // Bans section
        toml.push_str("[bans]\n");
        toml.push_str(&format!(
            "multiple-versions = \"{}\"\n",
            self.bans.multiple_versions
        ));
        toml.push_str(&format!("wildcards = \"{}\"\n", self.bans.wildcards));
        toml.push_str(&format!("highlight = \"{}\"\n", self.bans.highlight));

        for ban in &self.bans.deny {
            toml.push_str("\n[[bans.deny]]\n");
            toml.push_str(&format!("name = \"{}\"\n", ban.name));
            if let Some(ref reason) = ban.reason {
                toml.push_str(&format!("reason = \"{}\"\n", reason));
            }
        }
        toml.push('\n');

        // Sources section
        toml.push_str("[sources]\n");
        toml.push_str(&format!(
            "unknown-registry = \"{}\"\n",
            self.sources.unknown_registry
        ));
        toml.push_str(&format!("unknown-git = \"{}\"\n", self.sources.unknown_git));

        if !self.sources.allow_registry.is_empty() {
            toml.push_str("allow-registry = [\n");
            for url in &self.sources.allow_registry {
                toml.push_str(&format!("    \"{}\",\n", url));
            }
            toml.push_str("]\n");
        }

        if !self.sources.allow_git.is_empty() {
            toml.push_str("allow-git = [\n");
            for url in &self.sources.allow_git {
                toml.push_str(&format!("    \"{}\",\n", url));
            }
            toml.push_str("]\n");
        }

        toml
    }
}

/// Preset configurations for common use cases
pub mod presets {
    use super::*;

    /// Configuration for open source projects
    pub fn open_source() -> DenyConfig {
        let mut config = DenyConfig::new();
        config.licenses.copyleft = "allow".to_string();
        config.licenses.allow.push("MPL-2.0".to_string());
        config.licenses.allow.push("LGPL-3.0".to_string());
        config
    }

    /// Configuration for commercial/proprietary projects
    pub fn commercial() -> DenyConfig {
        let mut config = DenyConfig::strict();
        config.licenses.copyleft = "deny".to_string();
        config.licenses.deny.push("GPL-2.0".to_string());
        config.licenses.deny.push("LGPL-2.1".to_string());
        config.licenses.deny.push("LGPL-3.0".to_string());
        config.licenses.deny.push("MPL-2.0".to_string());
        config
    }

    /// Configuration for embedded/safety-critical systems
    pub fn embedded() -> DenyConfig {
        let mut config = DenyConfig::strict();

        // Ban crates not suitable for embedded
        config.ban_crate("std", Some("no_std only"));
        config.ban_crate("alloc", Some("heap allocation not allowed"));

        config
    }

    /// Configuration for government/compliance requirements
    pub fn government() -> DenyConfig {
        let mut config = DenyConfig::strict();

        // Only allow well-known permissive licenses
        config.licenses.allow = vec![
            "MIT".to_string(),
            "Apache-2.0".to_string(),
            "BSD-2-Clause".to_string(),
            "BSD-3-Clause".to_string(),
        ];

        // Deny all unknown sources
        config.sources.unknown_registry = "deny".to_string();
        config.sources.unknown_git = "deny".to_string();

        config
    }
}

fn main() {
    println!("Cargo Deny Configuration Example");
    println!("=================================\n");

    // Create default configuration
    let mut config = DenyConfig::new();

    // Customize it
    config.ban_crate("openssl", Some("Use rustls instead"));
    config.ban_crate("native-tls", Some("Use rustls instead"));
    config.add_license_exception("ring", vec!["ISC", "MIT", "OpenSSL"]);
    config.ignore_advisory("RUSTSEC-0000-0000");
    config.allow_git_source("https://github.com/my-org/*");

    println!("Generated deny.toml:");
    println!("=====================");
    println!("{}", config.to_toml());

    // Show presets
    println!("\n\nAvailable Presets:");
    println!("==================");
    println!("1. open_source - Allows copyleft licenses");
    println!("2. commercial - Strict copyleft denial");
    println!("3. embedded - no_std, no alloc");
    println!("4. government - Strict compliance");

    // Generate commercial preset
    println!("\n\nCommercial Preset (deny.toml):");
    println!("==============================");
    println!("{}", presets::commercial().to_toml());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = DenyConfig::new();

        assert_eq!(config.advisories.vulnerability, "deny");
        assert!(config.licenses.allow.contains(&"MIT".to_string()));
        assert!(config.licenses.deny.contains(&"GPL-3.0".to_string()));
    }

    #[test]
    fn test_strict_config() {
        let config = DenyConfig::strict();

        assert_eq!(config.advisories.unmaintained, "deny");
        assert_eq!(config.advisories.yanked, "deny");
        assert_eq!(config.bans.multiple_versions, "deny");
    }

    #[test]
    fn test_ban_crate() {
        let mut config = DenyConfig::new();
        config.ban_crate("bad-crate", Some("Security risk"));

        assert_eq!(config.bans.deny.len(), 1);
        assert_eq!(config.bans.deny[0].name, "bad-crate");
        assert_eq!(
            config.bans.deny[0].reason,
            Some("Security risk".to_string())
        );
    }

    #[test]
    fn test_license_exception() {
        let mut config = DenyConfig::new();
        config.add_license_exception("special-crate", vec!["Custom-License"]);

        assert!(config.licenses.exceptions.contains_key("special-crate"));
    }

    #[test]
    fn test_ignore_advisory() {
        let mut config = DenyConfig::new();
        config.ignore_advisory("RUSTSEC-2024-0001");

        assert!(config
            .advisories
            .ignore
            .contains(&"RUSTSEC-2024-0001".to_string()));
    }

    #[test]
    fn test_toml_generation() {
        let config = DenyConfig::new();
        let toml = config.to_toml();

        assert!(toml.contains("[advisories]"));
        assert!(toml.contains("[licenses]"));
        assert!(toml.contains("[bans]"));
        assert!(toml.contains("[sources]"));
        assert!(toml.contains("vulnerability = \"deny\""));
    }

    #[test]
    fn test_open_source_preset() {
        let config = presets::open_source();

        assert_eq!(config.licenses.copyleft, "allow");
        assert!(config.licenses.allow.contains(&"MPL-2.0".to_string()));
    }

    #[test]
    fn test_commercial_preset() {
        let config = presets::commercial();

        assert_eq!(config.licenses.copyleft, "deny");
        assert!(config.licenses.deny.contains(&"GPL-2.0".to_string()));
        assert!(config.licenses.deny.contains(&"LGPL-3.0".to_string()));
    }

    #[test]
    fn test_embedded_preset() {
        let config = presets::embedded();

        let banned_names: Vec<_> = config.bans.deny.iter().map(|b| b.name.as_str()).collect();
        assert!(banned_names.contains(&"std"));
    }

    #[test]
    fn test_government_preset() {
        let config = presets::government();

        assert_eq!(config.sources.unknown_registry, "deny");
        assert_eq!(config.sources.unknown_git, "deny");
        assert_eq!(config.licenses.allow.len(), 4);
    }
}
