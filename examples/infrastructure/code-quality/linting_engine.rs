//! Code Quality and Linting Engine
//!
//! Comprehensive linting implementation with:
//! - Rule-based code analysis
//! - Security-focused lint rules
//! - Auto-fix suggestions
//! - Custom rule definitions
//! - Report generation

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;

/// Severity level for lint findings
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Allow,
    Warn,
    Deny,
    Forbid,
}

/// Category of lint rule
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LintCategory {
    Security,
    Performance,
    Style,
    Correctness,
    Complexity,
    Documentation,
    Deprecated,
}

/// A lint rule definition
#[derive(Clone, Debug)]
pub struct LintRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: LintCategory,
    pub default_severity: Severity,
    pub explanation: String,
    pub has_auto_fix: bool,
}

/// Source code location
#[derive(Clone, Debug)]
pub struct Location {
    pub file: PathBuf,
    pub line: usize,
    pub column: usize,
    pub end_line: usize,
    pub end_column: usize,
}

/// A lint finding/diagnostic
#[derive(Clone, Debug)]
pub struct LintFinding {
    pub rule: LintRule,
    pub severity: Severity,
    pub location: Location,
    pub message: String,
    pub suggestion: Option<Suggestion>,
    pub related: Vec<RelatedInfo>,
}

/// Suggested fix for a finding
#[derive(Clone, Debug)]
pub struct Suggestion {
    pub description: String,
    pub replacement: String,
    pub applicability: Applicability,
}

/// How safe is the auto-fix
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Applicability {
    MachineApplicable, // Safe to apply automatically
    MaybeIncorrect,    // Might need manual review
    HasPlaceholders,   // Contains placeholders user must fill
    Unspecified,
}

/// Additional information related to a finding
#[derive(Clone, Debug)]
pub struct RelatedInfo {
    pub location: Location,
    pub message: String,
}

/// Lint configuration
#[derive(Clone, Debug)]
pub struct LintConfig {
    pub rules: HashMap<String, Severity>,
    pub ignored_files: Vec<String>,
    pub ignored_rules: Vec<String>,
}

/// The linting engine
pub struct LintEngine {
    rules: Vec<LintRule>,
    config: LintConfig,
    findings: Vec<LintFinding>,
}

/// Lint report
#[derive(Debug)]
pub struct LintReport {
    pub findings: Vec<LintFinding>,
    pub summary: LintSummary,
    pub passed: bool,
}

/// Summary statistics
#[derive(Debug, Default)]
pub struct LintSummary {
    pub total_findings: usize,
    pub by_severity: HashMap<Severity, usize>,
    pub by_category: HashMap<LintCategory, usize>,
    pub files_analyzed: usize,
    pub auto_fixable: usize,
}

impl LintEngine {
    /// Create a new lint engine with default rules
    pub fn new() -> Self {
        Self {
            rules: Self::default_rules(),
            config: LintConfig::default(),
            findings: Vec::new(),
        }
    }

    /// Create engine with custom config
    pub fn with_config(config: LintConfig) -> Self {
        Self {
            rules: Self::default_rules(),
            config,
            findings: Vec::new(),
        }
    }

    /// Get default security-focused lint rules
    fn default_rules() -> Vec<LintRule> {
        vec![
            // Security rules
            LintRule {
                id: "SEC001".to_string(),
                name: "hardcoded_credentials".to_string(),
                description: "Hardcoded passwords or API keys detected".to_string(),
                category: LintCategory::Security,
                default_severity: Severity::Deny,
                explanation: "Credentials should never be hardcoded in source code. Use environment variables or secure vaults.".to_string(),
                has_auto_fix: false,
            },
            LintRule {
                id: "SEC002".to_string(),
                name: "unsafe_unwrap".to_string(),
                description: "Unsafe use of unwrap() that may panic".to_string(),
                category: LintCategory::Security,
                default_severity: Severity::Warn,
                explanation: "Using unwrap() can cause panics. Consider using proper error handling with ? or expect().".to_string(),
                has_auto_fix: true,
            },
            LintRule {
                id: "SEC003".to_string(),
                name: "sql_injection_risk".to_string(),
                description: "Potential SQL injection vulnerability".to_string(),
                category: LintCategory::Security,
                default_severity: Severity::Deny,
                explanation: "String concatenation in SQL queries can lead to injection. Use parameterized queries.".to_string(),
                has_auto_fix: false,
            },
            LintRule {
                id: "SEC004".to_string(),
                name: "insecure_random".to_string(),
                description: "Use of non-cryptographic random number generator".to_string(),
                category: LintCategory::Security,
                default_severity: Severity::Warn,
                explanation: "For security-sensitive operations, use OsRng or ChaCha20Rng instead of thread_rng().".to_string(),
                has_auto_fix: true,
            },
            LintRule {
                id: "SEC005".to_string(),
                name: "unsafe_block".to_string(),
                description: "Unsafe block requires safety documentation".to_string(),
                category: LintCategory::Security,
                default_severity: Severity::Warn,
                explanation: "Unsafe blocks should have SAFETY comments explaining why the code is sound.".to_string(),
                has_auto_fix: false,
            },
            // Performance rules
            LintRule {
                id: "PERF001".to_string(),
                name: "unnecessary_clone".to_string(),
                description: "Unnecessary clone() call".to_string(),
                category: LintCategory::Performance,
                default_severity: Severity::Warn,
                explanation: "Cloning data when a reference would suffice wastes memory and CPU cycles.".to_string(),
                has_auto_fix: true,
            },
            LintRule {
                id: "PERF002".to_string(),
                name: "inefficient_iteration".to_string(),
                description: "Inefficient iteration pattern".to_string(),
                category: LintCategory::Performance,
                default_severity: Severity::Warn,
                explanation: "Consider using iterator methods like map(), filter(), or collect() for better performance.".to_string(),
                has_auto_fix: true,
            },
            // Correctness rules
            LintRule {
                id: "CORR001".to_string(),
                name: "unused_result".to_string(),
                description: "Result type ignored".to_string(),
                category: LintCategory::Correctness,
                default_severity: Severity::Warn,
                explanation: "Ignoring Result types can hide errors. Handle the error or explicitly ignore with let _ =.".to_string(),
                has_auto_fix: true,
            },
            LintRule {
                id: "CORR002".to_string(),
                name: "missing_debug_impl".to_string(),
                description: "Public type missing Debug implementation".to_string(),
                category: LintCategory::Correctness,
                default_severity: Severity::Warn,
                explanation: "Public types should implement Debug for better debugging experience.".to_string(),
                has_auto_fix: true,
            },
            // Complexity rules
            LintRule {
                id: "CMPLX001".to_string(),
                name: "high_cyclomatic_complexity".to_string(),
                description: "Function has high cyclomatic complexity".to_string(),
                category: LintCategory::Complexity,
                default_severity: Severity::Warn,
                explanation: "High complexity makes code harder to test and maintain. Consider breaking into smaller functions.".to_string(),
                has_auto_fix: false,
            },
            LintRule {
                id: "CMPLX002".to_string(),
                name: "deep_nesting".to_string(),
                description: "Deeply nested code blocks".to_string(),
                category: LintCategory::Complexity,
                default_severity: Severity::Warn,
                explanation: "Deep nesting reduces readability. Consider early returns or extracting logic.".to_string(),
                has_auto_fix: false,
            },
            // Documentation rules
            LintRule {
                id: "DOC001".to_string(),
                name: "missing_docs".to_string(),
                description: "Missing documentation for public item".to_string(),
                category: LintCategory::Documentation,
                default_severity: Severity::Warn,
                explanation: "Public items should be documented to help users understand the API.".to_string(),
                has_auto_fix: false,
            },
        ]
    }

    /// Analyze source code
    pub fn analyze(&mut self, file: &PathBuf, source: &str) -> Vec<LintFinding> {
        let mut findings = Vec::new();

        // Check for hardcoded credentials
        findings.extend(self.check_hardcoded_credentials(file, source));

        // Check for unsafe unwrap
        findings.extend(self.check_unsafe_unwrap(file, source));

        // Check for SQL injection risks
        findings.extend(self.check_sql_injection(file, source));

        // Check for insecure random
        findings.extend(self.check_insecure_random(file, source));

        // Check for unsafe blocks
        findings.extend(self.check_unsafe_blocks(file, source));

        // Check for unnecessary clones
        findings.extend(self.check_unnecessary_clone(file, source));

        // Filter by config
        findings.retain(|f| {
            !self.config.ignored_rules.contains(&f.rule.id)
                && !self
                    .config
                    .ignored_files
                    .iter()
                    .any(|p| file.to_string_lossy().contains(p))
        });

        // Apply severity overrides
        for finding in &mut findings {
            if let Some(severity) = self.config.rules.get(&finding.rule.id) {
                finding.severity = *severity;
            }
        }

        self.findings.extend(findings.clone());
        findings
    }

    fn check_hardcoded_credentials(&self, file: &PathBuf, source: &str) -> Vec<LintFinding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"password\s*=\s*["'][^"']+["']"#, "hardcoded password"),
            (r#"api_key\s*=\s*["'][^"']+["']"#, "hardcoded API key"),
            (r#"secret\s*=\s*["'][^"']+["']"#, "hardcoded secret"),
            (
                r#"token\s*=\s*["'][A-Za-z0-9_-]{20,}["']"#,
                "hardcoded token",
            ),
        ];

        for (line_num, line) in source.lines().enumerate() {
            for (pattern, desc) in &patterns {
                if line
                    .to_lowercase()
                    .contains(&pattern.split('\\').next().unwrap().to_lowercase())
                {
                    // Simplified pattern matching for demo
                    if line.contains("password") && line.contains("=") && line.contains('"') {
                        findings.push(LintFinding {
                            rule: self.get_rule("SEC001").unwrap(),
                            severity: Severity::Deny,
                            location: Location {
                                file: file.clone(),
                                line: line_num + 1,
                                column: 1,
                                end_line: line_num + 1,
                                end_column: line.len(),
                            },
                            message: format!("Found {}", desc),
                            suggestion: None,
                            related: vec![],
                        });
                        break;
                    }
                }
            }
        }

        findings
    }

    fn check_unsafe_unwrap(&self, file: &PathBuf, source: &str) -> Vec<LintFinding> {
        let mut findings = Vec::new();

        for (line_num, line) in source.lines().enumerate() {
            if line.contains(".unwrap()") && !line.trim().starts_with("//") {
                // Skip if there's an expect() suggestion comment
                let column = line.find(".unwrap()").unwrap_or(0) + 1;

                findings.push(LintFinding {
                    rule: self.get_rule("SEC002").unwrap(),
                    severity: Severity::Warn,
                    location: Location {
                        file: file.clone(),
                        line: line_num + 1,
                        column,
                        end_line: line_num + 1,
                        end_column: column + 9,
                    },
                    message: "unwrap() can panic on None/Err values".to_string(),
                    suggestion: Some(Suggestion {
                        description: "Consider using ? operator or expect()".to_string(),
                        replacement: ".expect(\"TODO: add context\")".to_string(),
                        applicability: Applicability::MaybeIncorrect,
                    }),
                    related: vec![],
                });
            }
        }

        findings
    }

    fn check_sql_injection(&self, file: &PathBuf, source: &str) -> Vec<LintFinding> {
        let mut findings = Vec::new();

        for (line_num, line) in source.lines().enumerate() {
            // Check for format! or + with SQL keywords
            if (line.contains("format!") || line.contains("+ \""))
                && (line.to_uppercase().contains("SELECT")
                    || line.to_uppercase().contains("INSERT")
                    || line.to_uppercase().contains("UPDATE")
                    || line.to_uppercase().contains("DELETE"))
            {
                findings.push(LintFinding {
                    rule: self.get_rule("SEC003").unwrap(),
                    severity: Severity::Deny,
                    location: Location {
                        file: file.clone(),
                        line: line_num + 1,
                        column: 1,
                        end_line: line_num + 1,
                        end_column: line.len(),
                    },
                    message: "String interpolation in SQL query - potential injection".to_string(),
                    suggestion: Some(Suggestion {
                        description: "Use parameterized queries instead".to_string(),
                        replacement: "sqlx::query!(\"SELECT * FROM users WHERE id = $1\", id)"
                            .to_string(),
                        applicability: Applicability::HasPlaceholders,
                    }),
                    related: vec![],
                });
            }
        }

        findings
    }

    fn check_insecure_random(&self, file: &PathBuf, source: &str) -> Vec<LintFinding> {
        let mut findings = Vec::new();

        for (line_num, line) in source.lines().enumerate() {
            if line.contains("thread_rng()") || line.contains("rand::random") {
                findings.push(LintFinding {
                    rule: self.get_rule("SEC004").unwrap(),
                    severity: Severity::Warn,
                    location: Location {
                        file: file.clone(),
                        line: line_num + 1,
                        column: 1,
                        end_line: line_num + 1,
                        end_column: line.len(),
                    },
                    message: "Using non-cryptographic RNG for potentially sensitive operation"
                        .to_string(),
                    suggestion: Some(Suggestion {
                        description: "Use OsRng for cryptographic operations".to_string(),
                        replacement: "use rand::rngs::OsRng;\nlet mut rng = OsRng;".to_string(),
                        applicability: Applicability::MaybeIncorrect,
                    }),
                    related: vec![],
                });
            }
        }

        findings
    }

    fn check_unsafe_blocks(&self, file: &PathBuf, source: &str) -> Vec<LintFinding> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            if line.contains("unsafe {") || line.contains("unsafe{") {
                // Check if previous line has a SAFETY comment
                let has_safety_comment = line_num > 0 && lines[line_num - 1].contains("// SAFETY:");

                if !has_safety_comment {
                    findings.push(LintFinding {
                        rule: self.get_rule("SEC005").unwrap(),
                        severity: Severity::Warn,
                        location: Location {
                            file: file.clone(),
                            line: line_num + 1,
                            column: 1,
                            end_line: line_num + 1,
                            end_column: line.len(),
                        },
                        message: "Unsafe block without SAFETY comment".to_string(),
                        suggestion: Some(Suggestion {
                            description: "Add a SAFETY comment explaining soundness".to_string(),
                            replacement: "// SAFETY: TODO: explain why this is safe\nunsafe {"
                                .to_string(),
                            applicability: Applicability::HasPlaceholders,
                        }),
                        related: vec![],
                    });
                }
            }
        }

        findings
    }

    fn check_unnecessary_clone(&self, file: &PathBuf, source: &str) -> Vec<LintFinding> {
        let mut findings = Vec::new();

        for (line_num, line) in source.lines().enumerate() {
            // Simple heuristic: .clone() followed by reference
            if line.contains(".clone()") && line.contains("&") {
                findings.push(LintFinding {
                    rule: self.get_rule("PERF001").unwrap(),
                    severity: Severity::Warn,
                    location: Location {
                        file: file.clone(),
                        line: line_num + 1,
                        column: 1,
                        end_line: line_num + 1,
                        end_column: line.len(),
                    },
                    message: "Possibly unnecessary clone - value is borrowed immediately after"
                        .to_string(),
                    suggestion: Some(Suggestion {
                        description: "Consider borrowing directly".to_string(),
                        replacement: "Remove .clone() and borrow".to_string(),
                        applicability: Applicability::MaybeIncorrect,
                    }),
                    related: vec![],
                });
            }
        }

        findings
    }

    fn get_rule(&self, id: &str) -> Option<LintRule> {
        self.rules.iter().find(|r| r.id == id).cloned()
    }

    /// Generate lint report
    pub fn report(&self) -> LintReport {
        let mut summary = LintSummary::default();
        summary.total_findings = self.findings.len();

        for finding in &self.findings {
            *summary.by_severity.entry(finding.severity).or_insert(0) += 1;
            *summary
                .by_category
                .entry(finding.rule.category)
                .or_insert(0) += 1;
            if finding.suggestion.as_ref().map_or(false, |s| {
                s.applicability == Applicability::MachineApplicable
            }) {
                summary.auto_fixable += 1;
            }
        }

        let passed = !self
            .findings
            .iter()
            .any(|f| f.severity == Severity::Deny || f.severity == Severity::Forbid);

        LintReport {
            findings: self.findings.clone(),
            summary,
            passed,
        }
    }

    /// Get all rules
    pub fn rules(&self) -> &[LintRule] {
        &self.rules
    }

    /// Clear findings
    pub fn clear(&mut self) {
        self.findings.clear();
    }
}

impl Default for LintEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for LintConfig {
    fn default() -> Self {
        Self {
            rules: HashMap::new(),
            ignored_files: vec!["target/".to_string(), "vendor/".to_string()],
            ignored_rules: Vec::new(),
        }
    }
}

impl fmt::Display for LintFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} [{}] {}:{}:{}\n  {}",
            self.severity,
            self.rule.name,
            self.rule.id,
            self.location.file.display(),
            self.location.line,
            self.location.column,
            self.message
        )?;

        if let Some(suggestion) = &self.suggestion {
            write!(f, "\n  help: {}", suggestion.description)?;
        }

        Ok(())
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Allow => write!(f, "allow"),
            Severity::Warn => write!(f, "warning"),
            Severity::Deny => write!(f, "error"),
            Severity::Forbid => write!(f, "FORBID"),
        }
    }
}

impl fmt::Display for LintReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for finding in &self.findings {
            writeln!(f, "{}\n", finding)?;
        }

        writeln!(f, "Summary:")?;
        writeln!(f, "  Total findings: {}", self.summary.total_findings)?;

        for (severity, count) in &self.summary.by_severity {
            writeln!(f, "  {}: {}", severity, count)?;
        }

        if self.passed {
            writeln!(f, "\nLint check PASSED")?;
        } else {
            writeln!(f, "\nLint check FAILED")?;
        }

        Ok(())
    }
}

fn main() {
    println!("=== Code Quality Linting Engine Demo ===\n");

    let mut engine = LintEngine::new();

    // Print available rules
    println!("Available lint rules:");
    for rule in engine.rules() {
        println!("  [{}] {} - {:?}", rule.id, rule.name, rule.category);
    }
    println!();

    // Sample code to analyze
    let sample_code = r#"
use std::collections::HashMap;

fn connect_to_database() {
    let password = "super_secret_123";  // Hardcoded credential
    let connection_string = format!("postgres://user:{}@localhost/db", password);

    // SQL injection risk
    let user_input = get_user_input();
    let query = format!("SELECT * FROM users WHERE name = '{}'", user_input);

    // Unsafe unwrap
    let result = some_operation().unwrap();

    // Non-cryptographic random
    let token = thread_rng().gen::<u64>();

    // Unsafe without SAFETY comment
    unsafe {
        do_something_unsafe();
    }
}

fn get_user_input() -> String {
    String::new()
}

fn some_operation() -> Option<i32> {
    Some(42)
}

unsafe fn do_something_unsafe() {}
"#;

    let file = PathBuf::from("src/database.rs");
    let findings = engine.analyze(&file, sample_code);

    println!("Analysis results for {}:\n", file.display());
    for finding in &findings {
        println!("{}\n", finding);
    }

    // Generate report
    let report = engine.report();
    println!("\n{}", report);

    // Demo with custom config
    println!("\n=== Custom Config Demo ===\n");

    let config = LintConfig {
        rules: {
            let mut rules = HashMap::new();
            rules.insert("SEC002".to_string(), Severity::Allow); // Allow unwrap
            rules
        },
        ignored_files: vec!["tests/".to_string()],
        ignored_rules: vec!["PERF001".to_string()],
    };

    let mut custom_engine = LintEngine::with_config(config);
    let findings = custom_engine.analyze(&file, sample_code);

    println!("With custom config (SEC002 allowed, PERF001 ignored):");
    println!("  Findings: {}", findings.len());

    let report = custom_engine.report();
    println!("  Passed: {}", report.passed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_hardcoded_password() {
        let mut engine = LintEngine::new();
        let code = r#"let password = "secret123";"#;
        let file = PathBuf::from("test.rs");

        let findings = engine.analyze(&file, code);

        assert!(findings.iter().any(|f| f.rule.id == "SEC001"));
    }

    #[test]
    fn test_detect_unsafe_unwrap() {
        let mut engine = LintEngine::new();
        let code = "let x = result.unwrap();";
        let file = PathBuf::from("test.rs");

        let findings = engine.analyze(&file, code);

        assert!(findings.iter().any(|f| f.rule.id == "SEC002"));
    }

    #[test]
    fn test_detect_sql_injection() {
        let mut engine = LintEngine::new();
        let code = r#"let q = format!("SELECT * FROM users WHERE id = {}", id);"#;
        let file = PathBuf::from("test.rs");

        let findings = engine.analyze(&file, code);

        assert!(findings.iter().any(|f| f.rule.id == "SEC003"));
    }

    #[test]
    fn test_detect_unsafe_without_safety() {
        let mut engine = LintEngine::new();
        let code = "unsafe { ptr::read(p) }";
        let file = PathBuf::from("test.rs");

        let findings = engine.analyze(&file, code);

        assert!(findings.iter().any(|f| f.rule.id == "SEC005"));
    }

    #[test]
    fn test_safe_unsafe_block() {
        let mut engine = LintEngine::new();
        let code = "// SAFETY: p is valid and aligned\nunsafe { ptr::read(p) }";
        let file = PathBuf::from("test.rs");

        let findings = engine.analyze(&file, code);

        assert!(!findings.iter().any(|f| f.rule.id == "SEC005"));
    }

    #[test]
    fn test_config_severity_override() {
        let config = LintConfig {
            rules: {
                let mut r = HashMap::new();
                r.insert("SEC002".to_string(), Severity::Deny);
                r
            },
            ..Default::default()
        };

        let mut engine = LintEngine::with_config(config);
        let code = "let x = result.unwrap();";
        let file = PathBuf::from("test.rs");

        let findings = engine.analyze(&file, code);
        let finding = findings.iter().find(|f| f.rule.id == "SEC002").unwrap();

        assert_eq!(finding.severity, Severity::Deny);
    }

    #[test]
    fn test_config_ignored_rules() {
        let config = LintConfig {
            ignored_rules: vec!["SEC002".to_string()],
            ..Default::default()
        };

        let mut engine = LintEngine::with_config(config);
        let code = "let x = result.unwrap();";
        let file = PathBuf::from("test.rs");

        let findings = engine.analyze(&file, code);

        assert!(!findings.iter().any(|f| f.rule.id == "SEC002"));
    }

    #[test]
    fn test_report_generation() {
        let mut engine = LintEngine::new();
        let code = r#"
            let password = "secret";
            let x = result.unwrap();
        "#;
        let file = PathBuf::from("test.rs");

        engine.analyze(&file, code);
        let report = engine.report();

        assert!(report.summary.total_findings >= 2);
        assert!(!report.passed); // Has deny-level findings
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Allow < Severity::Warn);
        assert!(Severity::Warn < Severity::Deny);
        assert!(Severity::Deny < Severity::Forbid);
    }

    #[test]
    fn test_suggestion_applicability() {
        let mut engine = LintEngine::new();
        let code = "let x = result.unwrap();";
        let file = PathBuf::from("test.rs");

        let findings = engine.analyze(&file, code);
        let finding = findings.iter().find(|f| f.rule.id == "SEC002").unwrap();

        assert!(finding.suggestion.is_some());
        let suggestion = finding.suggestion.as_ref().unwrap();
        assert!(suggestion.replacement.contains("expect"));
    }
}
