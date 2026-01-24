//! Binary Hardening Verification Example
//!
//! Demonstrates checking for RELRO, PIE, stack canaries, and other
//! binary hardening features in compiled Rust binaries.

use std::collections::HashMap;
use std::process::Command;

/// Binary hardening features
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardeningFeature {
    /// Position Independent Executable
    Pie,
    /// Full RELRO (RELocation Read-Only)
    FullRelro,
    /// Partial RELRO
    PartialRelro,
    /// Stack Canaries
    StackCanary,
    /// No Execute (NX) bit
    NxBit,
    /// Fortify Source
    FortifySource,
    /// Control Flow Integrity
    Cfi,
    /// Address Space Layout Randomization (runtime)
    Aslr,
}

impl HardeningFeature {
    pub fn description(&self) -> &'static str {
        match self {
            HardeningFeature::Pie => {
                "Position Independent Executable - enables ASLR for the binary"
            }
            HardeningFeature::FullRelro => {
                "Full RELRO - GOT is read-only, prevents GOT overwrite attacks"
            }
            HardeningFeature::PartialRelro => "Partial RELRO - some GOT entries are read-only",
            HardeningFeature::StackCanary => "Stack Canaries - detects stack buffer overflows",
            HardeningFeature::NxBit => "NX Bit - prevents execution of data pages",
            HardeningFeature::FortifySource => {
                "Fortify Source - compile-time and runtime buffer overflow checks"
            }
            HardeningFeature::Cfi => "Control Flow Integrity - validates indirect call targets",
            HardeningFeature::Aslr => "ASLR - randomizes memory layout at runtime",
        }
    }

    pub fn risk_if_missing(&self) -> RiskLevel {
        match self {
            HardeningFeature::Pie => RiskLevel::High,
            HardeningFeature::FullRelro => RiskLevel::High,
            HardeningFeature::PartialRelro => RiskLevel::Medium,
            HardeningFeature::StackCanary => RiskLevel::Critical,
            HardeningFeature::NxBit => RiskLevel::Critical,
            HardeningFeature::FortifySource => RiskLevel::Medium,
            HardeningFeature::Cfi => RiskLevel::Medium,
            HardeningFeature::Aslr => RiskLevel::High,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Result of checking a single hardening feature
#[derive(Debug, Clone)]
pub struct FeatureCheck {
    pub feature: HardeningFeature,
    pub enabled: bool,
    pub details: Option<String>,
}

/// Complete binary analysis result
#[derive(Debug, Clone)]
pub struct BinaryAnalysis {
    pub path: String,
    pub file_type: String,
    pub architecture: String,
    pub features: Vec<FeatureCheck>,
    pub warnings: Vec<String>,
    pub score: u32, // 0-100
}

impl BinaryAnalysis {
    pub fn is_hardened(&self) -> bool {
        self.score >= 80
    }

    pub fn missing_critical(&self) -> Vec<&FeatureCheck> {
        self.features
            .iter()
            .filter(|f| !f.enabled && f.feature.risk_if_missing() == RiskLevel::Critical)
            .collect()
    }

    pub fn generate_report(&self) -> String {
        let mut report = String::new();

        report.push_str(&format!("Binary Hardening Report: {}\n", self.path));
        report.push_str(&format!("Type: {}\n", self.file_type));
        report.push_str(&format!("Architecture: {}\n", self.architecture));
        report.push_str(&format!("Hardening Score: {}/100\n\n", self.score));

        report.push_str("Feature Analysis:\n");
        report.push_str("-".repeat(60).as_str());
        report.push('\n');

        for check in &self.features {
            let status = if check.enabled { "[✓]" } else { "[✗]" };
            let risk = if !check.enabled {
                format!(" (Risk: {:?})", check.feature.risk_if_missing())
            } else {
                String::new()
            };

            report.push_str(&format!("{} {:?}{}\n", status, check.feature, risk));

            if let Some(ref details) = check.details {
                report.push_str(&format!("    {}\n", details));
            }
        }

        if !self.warnings.is_empty() {
            report.push_str("\nWarnings:\n");
            for warning in &self.warnings {
                report.push_str(&format!("  ! {}\n", warning));
            }
        }

        report.push_str("\nRecommendations:\n");
        for check in &self.features {
            if !check.enabled {
                report.push_str(&format!(
                    "  - Enable {:?}: {}\n",
                    check.feature,
                    check.feature.description()
                ));
            }
        }

        report
    }
}

/// Binary analyzer using readelf/objdump
pub struct BinaryAnalyzer {
    checksec_path: Option<String>,
}

impl Default for BinaryAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryAnalyzer {
    pub fn new() -> Self {
        Self {
            checksec_path: None,
        }
    }

    pub fn with_checksec(mut self, path: &str) -> Self {
        self.checksec_path = Some(path.to_string());
        self
    }

    /// Analyze a binary file
    pub fn analyze(&self, binary_path: &str) -> Result<BinaryAnalysis, AnalysisError> {
        // Get file type
        let file_output = Command::new("file")
            .arg(binary_path)
            .output()
            .map_err(|e| AnalysisError::CommandFailed(e.to_string()))?;

        let file_type = String::from_utf8_lossy(&file_output.stdout).to_string();

        // Get architecture
        let arch = if file_type.contains("x86-64") {
            "x86_64"
        } else if file_type.contains("ARM64") || file_type.contains("aarch64") {
            "aarch64"
        } else if file_type.contains("32-bit") {
            "x86"
        } else {
            "unknown"
        };

        let mut features = Vec::new();
        let mut warnings = Vec::new();

        // Check PIE
        let pie_enabled = file_type.contains("shared object") || file_type.contains("PIE");
        features.push(FeatureCheck {
            feature: HardeningFeature::Pie,
            enabled: pie_enabled,
            details: if pie_enabled {
                Some("Binary is position independent".to_string())
            } else {
                Some("Binary has fixed base address".to_string())
            },
        });

        // Check RELRO using readelf
        let relro = self.check_relro(binary_path);
        features.push(relro);

        // Check NX bit
        let nx = self.check_nx(binary_path);
        features.push(nx);

        // Check stack canary
        let canary = self.check_stack_canary(binary_path);
        features.push(canary);

        // Check Fortify
        let fortify = self.check_fortify(binary_path);
        features.push(fortify);

        // Calculate score
        let enabled_count = features.iter().filter(|f| f.enabled).count();
        let score = (enabled_count as u32 * 100) / features.len() as u32;

        // Add warnings for critical missing features
        for feature in &features {
            if !feature.enabled && feature.feature.risk_if_missing() == RiskLevel::Critical {
                warnings.push(format!(
                    "CRITICAL: {:?} is not enabled - {}",
                    feature.feature,
                    feature.feature.description()
                ));
            }
        }

        Ok(BinaryAnalysis {
            path: binary_path.to_string(),
            file_type: file_type.trim().to_string(),
            architecture: arch.to_string(),
            features,
            warnings,
            score,
        })
    }

    fn check_relro(&self, binary_path: &str) -> FeatureCheck {
        let output = Command::new("readelf").args(["-l", binary_path]).output();

        match output {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let has_relro = stdout.contains("GNU_RELRO");
                let has_bind_now = stdout.contains("BIND_NOW");

                if has_relro && has_bind_now {
                    FeatureCheck {
                        feature: HardeningFeature::FullRelro,
                        enabled: true,
                        details: Some("Full RELRO with BIND_NOW".to_string()),
                    }
                } else if has_relro {
                    FeatureCheck {
                        feature: HardeningFeature::PartialRelro,
                        enabled: true,
                        details: Some("Partial RELRO (no BIND_NOW)".to_string()),
                    }
                } else {
                    FeatureCheck {
                        feature: HardeningFeature::FullRelro,
                        enabled: false,
                        details: Some("No RELRO segment found".to_string()),
                    }
                }
            }
            Err(_) => FeatureCheck {
                feature: HardeningFeature::FullRelro,
                enabled: false,
                details: Some("Could not check (readelf not available)".to_string()),
            },
        }
    }

    fn check_nx(&self, binary_path: &str) -> FeatureCheck {
        let output = Command::new("readelf").args(["-l", binary_path]).output();

        match output {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                // NX is enabled if GNU_STACK is RW (not RWE)
                let has_stack = stdout.contains("GNU_STACK");
                let has_exec_stack = stdout
                    .lines()
                    .any(|line| line.contains("GNU_STACK") && line.contains("RWE"));

                FeatureCheck {
                    feature: HardeningFeature::NxBit,
                    enabled: has_stack && !has_exec_stack,
                    details: if !has_exec_stack {
                        Some("Stack is non-executable".to_string())
                    } else {
                        Some("Stack is executable (vulnerable)".to_string())
                    },
                }
            }
            Err(_) => FeatureCheck {
                feature: HardeningFeature::NxBit,
                enabled: false,
                details: Some("Could not check".to_string()),
            },
        }
    }

    fn check_stack_canary(&self, binary_path: &str) -> FeatureCheck {
        let output = Command::new("readelf").args(["-s", binary_path]).output();

        match output {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let has_canary =
                    stdout.contains("__stack_chk_fail") || stdout.contains("__stack_chk_guard");

                FeatureCheck {
                    feature: HardeningFeature::StackCanary,
                    enabled: has_canary,
                    details: if has_canary {
                        Some("Stack canary symbols found".to_string())
                    } else {
                        Some("No stack canary symbols".to_string())
                    },
                }
            }
            Err(_) => FeatureCheck {
                feature: HardeningFeature::StackCanary,
                enabled: false,
                details: Some("Could not check".to_string()),
            },
        }
    }

    fn check_fortify(&self, binary_path: &str) -> FeatureCheck {
        let output = Command::new("readelf").args(["-s", binary_path]).output();

        match output {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let has_fortify = stdout.contains("__fortify_fail")
                    || stdout.lines().any(|l| l.contains("_chk@"));

                FeatureCheck {
                    feature: HardeningFeature::FortifySource,
                    enabled: has_fortify,
                    details: if has_fortify {
                        Some("Fortified functions detected".to_string())
                    } else {
                        Some("No fortified functions".to_string())
                    },
                }
            }
            Err(_) => FeatureCheck {
                feature: HardeningFeature::FortifySource,
                enabled: false,
                details: Some("Could not check".to_string()),
            },
        }
    }
}

#[derive(Debug)]
pub enum AnalysisError {
    FileNotFound(String),
    CommandFailed(String),
    ParseError(String),
}

/// Generate Cargo profile for hardened builds
pub fn hardened_cargo_profile() -> String {
    r#"[profile.release]
opt-level = 2
lto = true
codegen-units = 1
panic = "abort"
strip = "symbols"
overflow-checks = true

[profile.release.build-override]
opt-level = 2

# For maximum hardening with nightly:
# [unstable]
# build-std = ["std", "panic_abort"]
# build-std-features = ["panic_immediate_abort"]
"#
    .to_string()
}

/// Generate RUSTFLAGS for hardened builds
pub fn hardened_rustflags() -> String {
    let flags = vec![
        "-C link-arg=-z,relro",
        "-C link-arg=-z,now",
        "-C link-arg=-z,noexecstack",
        "-C target-feature=+crt-static",
        "-C overflow-checks=on",
        "-D unsafe_code",
    ];

    flags.join(" ")
}

fn main() {
    println!("Binary Hardening Verification Example");
    println!("======================================\n");

    // Show hardened build configuration
    println!("Hardened Cargo.toml profile:");
    println!("-----------------------------");
    println!("{}", hardened_cargo_profile());

    println!("\nHardened RUSTFLAGS:");
    println!("-------------------");
    println!("RUSTFLAGS=\"{}\"", hardened_rustflags());

    // Create sample analysis for demonstration
    let analysis = BinaryAnalysis {
        path: "/usr/bin/example".to_string(),
        file_type: "ELF 64-bit LSB shared object, x86-64".to_string(),
        architecture: "x86_64".to_string(),
        features: vec![
            FeatureCheck {
                feature: HardeningFeature::Pie,
                enabled: true,
                details: Some("Binary is position independent".to_string()),
            },
            FeatureCheck {
                feature: HardeningFeature::FullRelro,
                enabled: true,
                details: Some("Full RELRO with BIND_NOW".to_string()),
            },
            FeatureCheck {
                feature: HardeningFeature::NxBit,
                enabled: true,
                details: Some("Stack is non-executable".to_string()),
            },
            FeatureCheck {
                feature: HardeningFeature::StackCanary,
                enabled: true,
                details: Some("Stack canary symbols found".to_string()),
            },
            FeatureCheck {
                feature: HardeningFeature::FortifySource,
                enabled: false,
                details: Some("No fortified functions".to_string()),
            },
        ],
        warnings: vec![],
        score: 80,
    };

    println!("\nSample Analysis Report:");
    println!("========================");
    println!("{}", analysis.generate_report());

    // Show feature descriptions
    println!("\nHardening Features Reference:");
    println!("=============================");
    for feature in [
        HardeningFeature::Pie,
        HardeningFeature::FullRelro,
        HardeningFeature::NxBit,
        HardeningFeature::StackCanary,
        HardeningFeature::FortifySource,
        HardeningFeature::Cfi,
    ] {
        println!("  {:?}: {}", feature, feature.description());
        println!("    Risk if missing: {:?}\n", feature.risk_if_missing());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_levels() {
        assert_eq!(
            HardeningFeature::StackCanary.risk_if_missing(),
            RiskLevel::Critical
        );
        assert_eq!(
            HardeningFeature::NxBit.risk_if_missing(),
            RiskLevel::Critical
        );
        assert_eq!(HardeningFeature::Pie.risk_if_missing(), RiskLevel::High);
        assert_eq!(
            HardeningFeature::FortifySource.risk_if_missing(),
            RiskLevel::Medium
        );
    }

    #[test]
    fn test_risk_ordering() {
        assert!(RiskLevel::Critical > RiskLevel::High);
        assert!(RiskLevel::High > RiskLevel::Medium);
        assert!(RiskLevel::Medium > RiskLevel::Low);
    }

    #[test]
    fn test_feature_descriptions() {
        assert!(!HardeningFeature::Pie.description().is_empty());
        assert!(!HardeningFeature::FullRelro.description().is_empty());
        assert!(!HardeningFeature::NxBit.description().is_empty());
    }

    #[test]
    fn test_binary_analysis_score() {
        let analysis = BinaryAnalysis {
            path: "test".to_string(),
            file_type: "ELF".to_string(),
            architecture: "x86_64".to_string(),
            features: vec![
                FeatureCheck {
                    feature: HardeningFeature::Pie,
                    enabled: true,
                    details: None,
                },
                FeatureCheck {
                    feature: HardeningFeature::NxBit,
                    enabled: true,
                    details: None,
                },
            ],
            warnings: vec![],
            score: 100,
        };

        assert!(analysis.is_hardened());
    }

    #[test]
    fn test_missing_critical() {
        let analysis = BinaryAnalysis {
            path: "test".to_string(),
            file_type: "ELF".to_string(),
            architecture: "x86_64".to_string(),
            features: vec![
                FeatureCheck {
                    feature: HardeningFeature::StackCanary,
                    enabled: false,
                    details: None,
                },
                FeatureCheck {
                    feature: HardeningFeature::Pie,
                    enabled: true,
                    details: None,
                },
            ],
            warnings: vec![],
            score: 50,
        };

        let critical = analysis.missing_critical();
        assert_eq!(critical.len(), 1);
        assert_eq!(critical[0].feature, HardeningFeature::StackCanary);
    }

    #[test]
    fn test_report_generation() {
        let analysis = BinaryAnalysis {
            path: "/test/binary".to_string(),
            file_type: "ELF 64-bit".to_string(),
            architecture: "x86_64".to_string(),
            features: vec![FeatureCheck {
                feature: HardeningFeature::Pie,
                enabled: true,
                details: Some("Enabled".to_string()),
            }],
            warnings: vec!["Test warning".to_string()],
            score: 100,
        };

        let report = analysis.generate_report();
        assert!(report.contains("/test/binary"));
        assert!(report.contains("100/100"));
        assert!(report.contains("[✓]"));
        assert!(report.contains("Test warning"));
    }

    #[test]
    fn test_hardened_cargo_profile() {
        let profile = hardened_cargo_profile();
        assert!(profile.contains("[profile.release]"));
        assert!(profile.contains("lto = true"));
        assert!(profile.contains("overflow-checks = true"));
    }

    #[test]
    fn test_hardened_rustflags() {
        let flags = hardened_rustflags();
        assert!(flags.contains("relro"));
        assert!(flags.contains("noexecstack"));
        assert!(flags.contains("overflow-checks"));
    }
}
