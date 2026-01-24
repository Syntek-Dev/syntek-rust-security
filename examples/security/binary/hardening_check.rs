//! Binary Hardening Verification
//!
//! Check binary security features:
//! - RELRO (Relocation Read-Only)
//! - Stack canaries
//! - NX (No-Execute)
//! - PIE (Position Independent Executable)
//! - Fortify source
//! - ASLR compatibility

use std::collections::HashMap;
use std::fmt;
use std::path::Path;

/// Security feature
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SecurityFeature {
    /// Full RELRO
    FullRelro,
    /// Partial RELRO
    PartialRelro,
    /// Stack canaries
    StackCanary,
    /// No-Execute stack
    NxStack,
    /// Position Independent Executable
    Pie,
    /// Position Independent Code
    Pic,
    /// Fortify source
    Fortify,
    /// Stack clash protection
    StackClash,
    /// Control Flow Integrity
    Cfi,
    /// Address Sanitizer
    Asan,
    /// Undefined Behavior Sanitizer
    Ubsan,
    /// Shadow Call Stack
    ShadowCallStack,
    /// SafeStack
    SafeStack,
    /// Stripped debug symbols
    Stripped,
    /// RUNPATH instead of RPATH
    RunPath,
}

/// Feature status
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeatureStatus {
    Enabled,
    Disabled,
    Partial,
    NotApplicable,
    Unknown,
}

/// Binary analysis result
#[derive(Clone, Debug)]
pub struct BinaryAnalysis {
    pub path: String,
    pub binary_type: BinaryType,
    pub architecture: Architecture,
    pub features: HashMap<SecurityFeature, FeatureStatus>,
    pub score: SecurityScore,
    pub recommendations: Vec<Recommendation>,
}

/// Binary type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinaryType {
    Executable,
    SharedLibrary,
    StaticLibrary,
    Object,
    Unknown,
}

/// Architecture
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Architecture {
    X86,
    X86_64,
    Arm,
    Arm64,
    Riscv64,
    Unknown,
}

/// Security score
#[derive(Clone, Debug)]
pub struct SecurityScore {
    pub score: u32,
    pub max_score: u32,
    pub grade: Grade,
}

/// Security grade
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Grade {
    F,
    D,
    C,
    B,
    A,
    APlus,
}

/// Security recommendation
#[derive(Clone, Debug)]
pub struct Recommendation {
    pub feature: SecurityFeature,
    pub severity: Severity,
    pub message: String,
    pub fix: String,
}

/// Recommendation severity
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Binary analyzer
pub struct BinaryAnalyzer {
    strict_mode: bool,
}

/// Compiler flags for hardening
pub struct HardeningFlags;

impl BinaryAnalyzer {
    /// Create new analyzer
    pub fn new() -> Self {
        Self { strict_mode: false }
    }

    /// Enable strict mode (more recommendations)
    pub fn strict(mut self) -> Self {
        self.strict_mode = true;
        self
    }

    /// Analyze binary file
    pub fn analyze(&self, path: impl AsRef<Path>) -> Result<BinaryAnalysis, AnalysisError> {
        let path = path.as_ref();

        if !path.exists() {
            return Err(AnalysisError::FileNotFound(path.display().to_string()));
        }

        // Simulated analysis
        let binary_type = self.detect_binary_type(path);
        let architecture = self.detect_architecture(path);
        let features = self.check_features(path);
        let score = self.calculate_score(&features);
        let recommendations = self.generate_recommendations(&features);

        Ok(BinaryAnalysis {
            path: path.display().to_string(),
            binary_type,
            architecture,
            features,
            score,
            recommendations,
        })
    }

    /// Analyze multiple binaries
    pub fn analyze_batch(&self, paths: &[&Path]) -> Vec<Result<BinaryAnalysis, AnalysisError>> {
        paths.iter().map(|p| self.analyze(p)).collect()
    }

    fn detect_binary_type(&self, _path: &Path) -> BinaryType {
        // Would parse ELF header
        BinaryType::Executable
    }

    fn detect_architecture(&self, _path: &Path) -> Architecture {
        // Would parse ELF header
        Architecture::X86_64
    }

    fn check_features(&self, _path: &Path) -> HashMap<SecurityFeature, FeatureStatus> {
        // Simulated feature detection
        let mut features = HashMap::new();

        // Typically enabled features
        features.insert(SecurityFeature::PartialRelro, FeatureStatus::Enabled);
        features.insert(SecurityFeature::NxStack, FeatureStatus::Enabled);
        features.insert(SecurityFeature::Pie, FeatureStatus::Enabled);
        features.insert(SecurityFeature::StackCanary, FeatureStatus::Enabled);

        // Typically not enabled by default
        features.insert(SecurityFeature::FullRelro, FeatureStatus::Disabled);
        features.insert(SecurityFeature::Fortify, FeatureStatus::Partial);
        features.insert(SecurityFeature::StackClash, FeatureStatus::Disabled);
        features.insert(SecurityFeature::Cfi, FeatureStatus::Disabled);
        features.insert(SecurityFeature::Asan, FeatureStatus::Disabled);
        features.insert(SecurityFeature::SafeStack, FeatureStatus::Disabled);
        features.insert(SecurityFeature::Stripped, FeatureStatus::Enabled);
        features.insert(SecurityFeature::RunPath, FeatureStatus::Enabled);

        features
    }

    fn calculate_score(&self, features: &HashMap<SecurityFeature, FeatureStatus>) -> SecurityScore {
        let mut score = 0u32;
        let max_score = 100u32;

        // Core security features (high weight)
        if features.get(&SecurityFeature::FullRelro) == Some(&FeatureStatus::Enabled) {
            score += 15;
        } else if features.get(&SecurityFeature::PartialRelro) == Some(&FeatureStatus::Enabled) {
            score += 8;
        }

        if features.get(&SecurityFeature::NxStack) == Some(&FeatureStatus::Enabled) {
            score += 15;
        }

        if features.get(&SecurityFeature::Pie) == Some(&FeatureStatus::Enabled) {
            score += 15;
        }

        if features.get(&SecurityFeature::StackCanary) == Some(&FeatureStatus::Enabled) {
            score += 15;
        }

        // Additional features
        if features.get(&SecurityFeature::Fortify) == Some(&FeatureStatus::Enabled) {
            score += 10;
        } else if features.get(&SecurityFeature::Fortify) == Some(&FeatureStatus::Partial) {
            score += 5;
        }

        if features.get(&SecurityFeature::StackClash) == Some(&FeatureStatus::Enabled) {
            score += 5;
        }

        if features.get(&SecurityFeature::Cfi) == Some(&FeatureStatus::Enabled) {
            score += 10;
        }

        if features.get(&SecurityFeature::Stripped) == Some(&FeatureStatus::Enabled) {
            score += 5;
        }

        if features.get(&SecurityFeature::RunPath) == Some(&FeatureStatus::Enabled) {
            score += 5;
        }

        // Advanced features
        if features.get(&SecurityFeature::SafeStack) == Some(&FeatureStatus::Enabled) {
            score += 5;
        }

        let grade = match score {
            90..=100 => Grade::APlus,
            80..=89 => Grade::A,
            70..=79 => Grade::B,
            60..=69 => Grade::C,
            50..=59 => Grade::D,
            _ => Grade::F,
        };

        SecurityScore {
            score,
            max_score,
            grade,
        }
    }

    fn generate_recommendations(
        &self,
        features: &HashMap<SecurityFeature, FeatureStatus>,
    ) -> Vec<Recommendation> {
        let mut recommendations = Vec::new();

        // Check Full RELRO
        if features.get(&SecurityFeature::FullRelro) != Some(&FeatureStatus::Enabled) {
            recommendations.push(Recommendation {
                feature: SecurityFeature::FullRelro,
                severity: Severity::High,
                message: "Full RELRO is not enabled".to_string(),
                fix: "Add -Wl,-z,relro,-z,now to linker flags".to_string(),
            });
        }

        // Check NX Stack
        if features.get(&SecurityFeature::NxStack) != Some(&FeatureStatus::Enabled) {
            recommendations.push(Recommendation {
                feature: SecurityFeature::NxStack,
                severity: Severity::Critical,
                message: "Executable stack detected".to_string(),
                fix: "Remove -z execstack from linker flags".to_string(),
            });
        }

        // Check PIE
        if features.get(&SecurityFeature::Pie) != Some(&FeatureStatus::Enabled) {
            recommendations.push(Recommendation {
                feature: SecurityFeature::Pie,
                severity: Severity::High,
                message: "PIE is not enabled".to_string(),
                fix: "Compile with -fPIE and link with -pie".to_string(),
            });
        }

        // Check Stack Canary
        if features.get(&SecurityFeature::StackCanary) != Some(&FeatureStatus::Enabled) {
            recommendations.push(Recommendation {
                feature: SecurityFeature::StackCanary,
                severity: Severity::High,
                message: "Stack canaries not detected".to_string(),
                fix: "Compile with -fstack-protector-strong or -fstack-protector-all".to_string(),
            });
        }

        // Check Fortify
        if features.get(&SecurityFeature::Fortify) == Some(&FeatureStatus::Disabled) {
            recommendations.push(Recommendation {
                feature: SecurityFeature::Fortify,
                severity: Severity::Medium,
                message: "FORTIFY_SOURCE not enabled".to_string(),
                fix: "Compile with -D_FORTIFY_SOURCE=2".to_string(),
            });
        }

        // Strict mode additions
        if self.strict_mode {
            if features.get(&SecurityFeature::Cfi) != Some(&FeatureStatus::Enabled) {
                recommendations.push(Recommendation {
                    feature: SecurityFeature::Cfi,
                    severity: Severity::Medium,
                    message: "Control Flow Integrity not enabled".to_string(),
                    fix: "Compile with -fsanitize=cfi (requires LTO)".to_string(),
                });
            }

            if features.get(&SecurityFeature::StackClash) != Some(&FeatureStatus::Enabled) {
                recommendations.push(Recommendation {
                    feature: SecurityFeature::StackClash,
                    severity: Severity::Low,
                    message: "Stack clash protection not enabled".to_string(),
                    fix: "Compile with -fstack-clash-protection".to_string(),
                });
            }
        }

        recommendations
    }
}

impl Default for BinaryAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl HardeningFlags {
    /// Get recommended compiler flags for C/C++
    pub fn gcc() -> Vec<&'static str> {
        vec![
            "-fstack-protector-strong",
            "-fstack-clash-protection",
            "-D_FORTIFY_SOURCE=2",
            "-Wformat",
            "-Wformat-security",
            "-Werror=format-security",
            "-fPIE",
            "-fcf-protection",
        ]
    }

    /// Get recommended linker flags
    pub fn linker() -> Vec<&'static str> {
        vec!["-Wl,-z,relro", "-Wl,-z,now", "-Wl,-z,noexecstack", "-pie"]
    }

    /// Get Rust-specific flags
    pub fn rust() -> Vec<&'static str> {
        vec![
            "-C",
            "relocation-model=pic",
            "-C",
            "link-arg=-Wl,-z,relro,-z,now",
            "-C",
            "link-arg=-Wl,-z,noexecstack",
        ]
    }

    /// Get rustflags for Cargo
    pub fn cargo_rustflags() -> String {
        [
            "-C",
            "relocation-model=pic",
            "-C",
            "link-arg=-Wl,-z,relro,-z,now",
            "-C",
            "link-arg=-Wl,-z,noexecstack",
        ]
        .join(" ")
    }

    /// Generate Cargo config TOML
    pub fn cargo_config() -> String {
        r#"[target.x86_64-unknown-linux-gnu]
rustflags = [
    "-C", "relocation-model=pic",
    "-C", "link-arg=-Wl,-z,relro,-z,now",
    "-C", "link-arg=-Wl,-z,noexecstack",
]

[profile.release]
lto = true
codegen-units = 1
panic = "abort"
strip = true
"#
        .to_string()
    }
}

/// Analysis error
#[derive(Debug)]
pub enum AnalysisError {
    FileNotFound(String),
    NotAnElf(String),
    ParseError(String),
    IoError(String),
}

impl fmt::Display for AnalysisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnalysisError::FileNotFound(path) => write!(f, "File not found: {}", path),
            AnalysisError::NotAnElf(path) => write!(f, "Not an ELF file: {}", path),
            AnalysisError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            AnalysisError::IoError(msg) => write!(f, "IO error: {}", msg),
        }
    }
}

impl std::error::Error for AnalysisError {}

impl fmt::Display for Grade {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Grade::APlus => write!(f, "A+"),
            Grade::A => write!(f, "A"),
            Grade::B => write!(f, "B"),
            Grade::C => write!(f, "C"),
            Grade::D => write!(f, "D"),
            Grade::F => write!(f, "F"),
        }
    }
}

impl fmt::Display for SecurityFeature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityFeature::FullRelro => write!(f, "Full RELRO"),
            SecurityFeature::PartialRelro => write!(f, "Partial RELRO"),
            SecurityFeature::StackCanary => write!(f, "Stack Canary"),
            SecurityFeature::NxStack => write!(f, "NX Stack"),
            SecurityFeature::Pie => write!(f, "PIE"),
            SecurityFeature::Pic => write!(f, "PIC"),
            SecurityFeature::Fortify => write!(f, "Fortify Source"),
            SecurityFeature::StackClash => write!(f, "Stack Clash Protection"),
            SecurityFeature::Cfi => write!(f, "CFI"),
            SecurityFeature::Asan => write!(f, "ASan"),
            SecurityFeature::Ubsan => write!(f, "UBSan"),
            SecurityFeature::ShadowCallStack => write!(f, "Shadow Call Stack"),
            SecurityFeature::SafeStack => write!(f, "SafeStack"),
            SecurityFeature::Stripped => write!(f, "Stripped"),
            SecurityFeature::RunPath => write!(f, "RUNPATH"),
        }
    }
}

impl fmt::Display for FeatureStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FeatureStatus::Enabled => write!(f, "Enabled"),
            FeatureStatus::Disabled => write!(f, "Disabled"),
            FeatureStatus::Partial => write!(f, "Partial"),
            FeatureStatus::NotApplicable => write!(f, "N/A"),
            FeatureStatus::Unknown => write!(f, "Unknown"),
        }
    }
}

fn main() {
    println!("=== Binary Hardening Verification Demo ===\n");

    // Analyze binary (using current executable as example)
    let exe_path = std::env::current_exe().unwrap();
    println!("Analyzing: {}\n", exe_path.display());

    let analyzer = BinaryAnalyzer::new().strict();

    // Note: In this demo we simulate the analysis
    // In production, use a real path
    let analysis = BinaryAnalysis {
        path: exe_path.display().to_string(),
        binary_type: BinaryType::Executable,
        architecture: Architecture::X86_64,
        features: {
            let mut f = HashMap::new();
            f.insert(SecurityFeature::FullRelro, FeatureStatus::Disabled);
            f.insert(SecurityFeature::PartialRelro, FeatureStatus::Enabled);
            f.insert(SecurityFeature::NxStack, FeatureStatus::Enabled);
            f.insert(SecurityFeature::Pie, FeatureStatus::Enabled);
            f.insert(SecurityFeature::StackCanary, FeatureStatus::Enabled);
            f.insert(SecurityFeature::Fortify, FeatureStatus::Partial);
            f.insert(SecurityFeature::StackClash, FeatureStatus::Disabled);
            f.insert(SecurityFeature::Cfi, FeatureStatus::Disabled);
            f.insert(SecurityFeature::Stripped, FeatureStatus::Enabled);
            f.insert(SecurityFeature::RunPath, FeatureStatus::Enabled);
            f
        },
        score: SecurityScore {
            score: 68,
            max_score: 100,
            grade: Grade::C,
        },
        recommendations: vec![Recommendation {
            feature: SecurityFeature::FullRelro,
            severity: Severity::High,
            message: "Full RELRO is not enabled".to_string(),
            fix: "Add -Wl,-z,relro,-z,now to linker flags".to_string(),
        }],
    };

    // Display results
    println!("=== Analysis Results ===\n");
    println!("Type: {:?}", analysis.binary_type);
    println!("Architecture: {:?}", analysis.architecture);
    println!();

    println!("Security Features:");
    println!("{:-<50}", "");
    for (feature, status) in &analysis.features {
        let icon = match status {
            FeatureStatus::Enabled => "✓",
            FeatureStatus::Partial => "~",
            FeatureStatus::Disabled => "✗",
            _ => "?",
        };
        println!("  {} {} - {}", icon, feature, status);
    }
    println!();

    println!(
        "Security Score: {}/{} ({})",
        analysis.score.score, analysis.score.max_score, analysis.score.grade
    );
    println!();

    if !analysis.recommendations.is_empty() {
        println!("Recommendations:");
        println!("{:-<50}", "");
        for rec in &analysis.recommendations {
            println!("  [{:?}] {}", rec.severity, rec.message);
            println!("    Fix: {}", rec.fix);
        }
    }

    // Show hardening flags
    println!("\n=== Recommended Hardening Flags ===\n");

    println!("GCC/Clang compiler flags:");
    for flag in HardeningFlags::gcc() {
        println!("  {}", flag);
    }

    println!("\nLinker flags:");
    for flag in HardeningFlags::linker() {
        println!("  {}", flag);
    }

    println!("\nRust flags:");
    for flag in HardeningFlags::rust().chunks(2) {
        println!("  {} {}", flag[0], flag.get(1).unwrap_or(&""));
    }

    println!("\n=== Cargo Configuration ===\n");
    println!("{}", HardeningFlags::cargo_config());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyzer_creation() {
        let analyzer = BinaryAnalyzer::new();
        assert!(!analyzer.strict_mode);

        let strict = BinaryAnalyzer::new().strict();
        assert!(strict.strict_mode);
    }

    #[test]
    fn test_grade_ordering() {
        assert!(Grade::F < Grade::D);
        assert!(Grade::D < Grade::C);
        assert!(Grade::C < Grade::B);
        assert!(Grade::B < Grade::A);
        assert!(Grade::A < Grade::APlus);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn test_score_calculation() {
        let analyzer = BinaryAnalyzer::new();
        let mut features = HashMap::new();

        // Minimal features
        features.insert(SecurityFeature::NxStack, FeatureStatus::Enabled);
        let score = analyzer.calculate_score(&features);
        assert!(score.score < 30);

        // All core features
        features.insert(SecurityFeature::FullRelro, FeatureStatus::Enabled);
        features.insert(SecurityFeature::Pie, FeatureStatus::Enabled);
        features.insert(SecurityFeature::StackCanary, FeatureStatus::Enabled);
        let score = analyzer.calculate_score(&features);
        assert!(score.score >= 60);
    }

    #[test]
    fn test_recommendations() {
        let analyzer = BinaryAnalyzer::new();
        let mut features = HashMap::new();

        features.insert(SecurityFeature::FullRelro, FeatureStatus::Disabled);
        features.insert(SecurityFeature::NxStack, FeatureStatus::Enabled);
        features.insert(SecurityFeature::Pie, FeatureStatus::Enabled);
        features.insert(SecurityFeature::StackCanary, FeatureStatus::Enabled);

        let recommendations = analyzer.generate_recommendations(&features);
        assert!(!recommendations.is_empty());
        assert!(recommendations
            .iter()
            .any(|r| r.feature == SecurityFeature::FullRelro));
    }

    #[test]
    fn test_strict_mode_recommendations() {
        let strict = BinaryAnalyzer::new().strict();
        let mut features = HashMap::new();

        // All basic features enabled
        features.insert(SecurityFeature::FullRelro, FeatureStatus::Enabled);
        features.insert(SecurityFeature::NxStack, FeatureStatus::Enabled);
        features.insert(SecurityFeature::Pie, FeatureStatus::Enabled);
        features.insert(SecurityFeature::StackCanary, FeatureStatus::Enabled);
        features.insert(SecurityFeature::Fortify, FeatureStatus::Enabled);

        // But advanced features disabled
        features.insert(SecurityFeature::Cfi, FeatureStatus::Disabled);
        features.insert(SecurityFeature::StackClash, FeatureStatus::Disabled);

        let recommendations = strict.generate_recommendations(&features);
        assert!(recommendations
            .iter()
            .any(|r| r.feature == SecurityFeature::Cfi));
    }

    #[test]
    fn test_gcc_flags() {
        let flags = HardeningFlags::gcc();
        assert!(flags.contains(&"-fstack-protector-strong"));
        assert!(flags.contains(&"-fPIE"));
    }

    #[test]
    fn test_linker_flags() {
        let flags = HardeningFlags::linker();
        assert!(flags.iter().any(|f| f.contains("relro")));
        assert!(flags.iter().any(|f| f.contains("now")));
    }

    #[test]
    fn test_rust_flags() {
        let flags = HardeningFlags::rust();
        assert!(!flags.is_empty());
    }

    #[test]
    fn test_cargo_config() {
        let config = HardeningFlags::cargo_config();
        assert!(config.contains("relro"));
        assert!(config.contains("[profile.release]"));
    }

    #[test]
    fn test_feature_display() {
        assert_eq!(format!("{}", SecurityFeature::FullRelro), "Full RELRO");
        assert_eq!(format!("{}", SecurityFeature::Pie), "PIE");
    }

    #[test]
    fn test_status_display() {
        assert_eq!(format!("{}", FeatureStatus::Enabled), "Enabled");
        assert_eq!(format!("{}", FeatureStatus::Disabled), "Disabled");
    }

    #[test]
    fn test_grade_display() {
        assert_eq!(format!("{}", Grade::APlus), "A+");
        assert_eq!(format!("{}", Grade::A), "A");
    }
}
