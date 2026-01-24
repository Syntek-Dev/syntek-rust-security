//! Code Modernization and Refactoring Patterns
//!
//! This example demonstrates automated code modernization patterns for Rust,
//! including migration to modern idioms, safety improvements, performance
//! optimizations, and Rust edition upgrades.

use std::collections::{HashMap, HashSet};
use std::fmt;

// ============================================================================
// Code Pattern Detection
// ============================================================================

/// Detected code pattern that could be modernized
#[derive(Clone, Debug)]
pub struct CodePattern {
    pub id: String,
    pub pattern_type: PatternType,
    pub location: CodeLocation,
    pub original: String,
    pub suggestion: String,
    pub severity: Severity,
    pub auto_fixable: bool,
    pub explanation: String,
}

#[derive(Clone, Debug)]
pub struct CodeLocation {
    pub file: String,
    pub start_line: usize,
    pub end_line: usize,
    pub start_col: usize,
    pub end_col: usize,
}

impl CodeLocation {
    pub fn new(file: &str, line: usize, col: usize) -> Self {
        Self {
            file: file.to_string(),
            start_line: line,
            end_line: line,
            start_col: col,
            end_col: col,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PatternType {
    // Rust 2018+ idioms
    TryOperator,  // .unwrap() -> ?
    QuestionMark, // try!() -> ?
    DynTrait,     // Box<Trait> -> Box<dyn Trait>

    // Safety improvements
    UnwrapToExpect, // .unwrap() -> .expect()
    UnwrapToResult, // .unwrap() -> proper error handling
    PanicToResult,  // panic!() -> Result
    IndexToGet,     // array[i] -> array.get(i)

    // Memory safety
    RawPointerToRef, // raw pointers -> references
    UnsafeToSafe,    // unsafe block elimination
    LeakToOwned,     // mem::forget -> proper cleanup

    // Performance
    CloneToRef,   // unnecessary clone
    CollectToFor, // .collect() -> for loop when appropriate
    BoxToStack,   // unnecessary Box allocation
    StringToStr,  // String -> &str in function params
    VecToSlice,   // Vec<T> -> &[T] in function params

    // Modern APIs
    OldApiToNew,        // deprecated API -> new API
    MatchToIfLet,       // match with one arm -> if let
    LoopToIterator,     // manual loop -> iterator
    ManualImplToDerive, // manual impl -> derive

    // Async patterns
    BlockOnToAsync, // block_on -> async/await
    FuturesToAsync, // futures combinators -> async

    // Error handling
    StringErrorToThisError, // String errors -> thiserror
    BoxErrorToAnyhow,       // Box<dyn Error> -> anyhow

    // Code organization
    LongFunctionSplit,  // long function -> smaller functions
    DeepNestingFlatten, // deep nesting -> early returns
    MagicNumberToConst, // magic numbers -> named constants

    // Security
    HardcodedSecret, // hardcoded secrets -> env/config
    WeakCrypto,      // weak crypto -> strong crypto
    SqlInjection,    // string concat SQL -> prepared statements
}

impl PatternType {
    pub fn category(&self) -> &str {
        match self {
            PatternType::TryOperator | PatternType::QuestionMark | PatternType::DynTrait => {
                "Rust Idioms"
            }

            PatternType::UnwrapToExpect
            | PatternType::UnwrapToResult
            | PatternType::PanicToResult
            | PatternType::IndexToGet => "Safety",

            PatternType::RawPointerToRef | PatternType::UnsafeToSafe | PatternType::LeakToOwned => {
                "Memory Safety"
            }

            PatternType::CloneToRef
            | PatternType::CollectToFor
            | PatternType::BoxToStack
            | PatternType::StringToStr
            | PatternType::VecToSlice => "Performance",

            PatternType::OldApiToNew
            | PatternType::MatchToIfLet
            | PatternType::LoopToIterator
            | PatternType::ManualImplToDerive => "Modern APIs",

            PatternType::BlockOnToAsync | PatternType::FuturesToAsync => "Async",

            PatternType::StringErrorToThisError | PatternType::BoxErrorToAnyhow => "Error Handling",

            PatternType::LongFunctionSplit
            | PatternType::DeepNestingFlatten
            | PatternType::MagicNumberToConst => "Code Organization",

            PatternType::HardcodedSecret | PatternType::WeakCrypto | PatternType::SqlInjection => {
                "Security"
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Hint,
    Info,
    Warning,
    Error,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Hint => write!(f, "hint"),
            Severity::Info => write!(f, "info"),
            Severity::Warning => write!(f, "warning"),
            Severity::Error => write!(f, "error"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

// ============================================================================
// Pattern Analyzers
// ============================================================================

/// Trait for pattern analyzers
pub trait PatternAnalyzer {
    fn analyze(&self, code: &str, file: &str) -> Vec<CodePattern>;
    fn name(&self) -> &str;
}

/// Unwrap pattern analyzer
pub struct UnwrapAnalyzer;

impl PatternAnalyzer for UnwrapAnalyzer {
    fn analyze(&self, code: &str, file: &str) -> Vec<CodePattern> {
        let mut patterns = Vec::new();

        for (line_num, line) in code.lines().enumerate() {
            // Find .unwrap() calls
            if let Some(pos) = line.find(".unwrap()") {
                patterns.push(CodePattern {
                    id: format!("UNW-{}-{}", line_num + 1, pos),
                    pattern_type: PatternType::UnwrapToExpect,
                    location: CodeLocation::new(file, line_num + 1, pos),
                    original: ".unwrap()".to_string(),
                    suggestion: ".expect(\"descriptive message\")".to_string(),
                    severity: Severity::Warning,
                    auto_fixable: false,
                    explanation: "Replace .unwrap() with .expect() to provide context on panic"
                        .to_string(),
                });
            }

            // Find array indexing
            let chars: Vec<char> = line.chars().collect();
            for (i, window) in chars.windows(2).enumerate() {
                if window[0] != '.' && window[1] == '[' {
                    // Potential array index
                    if let Some(close) = line[i + 1..].find(']') {
                        let idx = &line[i + 2..i + 1 + close];
                        if !idx.contains("..") && idx.parse::<usize>().is_err() {
                            // Variable index, suggest .get()
                            patterns.push(CodePattern {
                                id: format!("IDX-{}-{}", line_num + 1, i),
                                pattern_type: PatternType::IndexToGet,
                                location: CodeLocation::new(file, line_num + 1, i),
                                original: format!("[{}]", idx),
                                suggestion: format!(".get({})", idx),
                                severity: Severity::Info,
                                auto_fixable: false,
                                explanation: "Consider using .get() for bounds-checked access"
                                    .to_string(),
                            });
                        }
                    }
                }
            }
        }

        patterns
    }

    fn name(&self) -> &str {
        "Unwrap Analyzer"
    }
}

/// Clone pattern analyzer
pub struct CloneAnalyzer;

impl PatternAnalyzer for CloneAnalyzer {
    fn analyze(&self, code: &str, file: &str) -> Vec<CodePattern> {
        let mut patterns = Vec::new();

        for (line_num, line) in code.lines().enumerate() {
            // Find .clone() calls
            if let Some(pos) = line.find(".clone()") {
                // Check if it's likely unnecessary
                if line.contains("let ") && line.contains(" = ") && line.contains(".clone()") {
                    patterns.push(CodePattern {
                        id: format!("CLN-{}-{}", line_num + 1, pos),
                        pattern_type: PatternType::CloneToRef,
                        location: CodeLocation::new(file, line_num + 1, pos),
                        original: ".clone()".to_string(),
                        suggestion: "Consider borrowing instead of cloning".to_string(),
                        severity: Severity::Hint,
                        auto_fixable: false,
                        explanation: "Cloning may be unnecessary. Consider using a reference if the value is only read.".to_string(),
                    });
                }
            }

            // Find to_string() on string literals
            if line.contains("\".to_string()") || line.contains("'.to_string()") {
                if let Some(pos) = line.find(".to_string()") {
                    patterns.push(CodePattern {
                        id: format!("STR-{}-{}", line_num + 1, pos),
                        pattern_type: PatternType::StringToStr,
                        location: CodeLocation::new(file, line_num + 1, pos),
                        original: ".to_string()".to_string(),
                        suggestion: "Consider using &str if allocation isn't needed".to_string(),
                        severity: Severity::Hint,
                        auto_fixable: false,
                        explanation:
                            "String allocation may be unnecessary. Consider using &'static str."
                                .to_string(),
                    });
                }
            }
        }

        patterns
    }

    fn name(&self) -> &str {
        "Clone Analyzer"
    }
}

/// Security pattern analyzer
pub struct SecurityAnalyzer;

impl PatternAnalyzer for SecurityAnalyzer {
    fn analyze(&self, code: &str, file: &str) -> Vec<CodePattern> {
        let mut patterns = Vec::new();

        for (line_num, line) in code.lines().enumerate() {
            // Hardcoded secrets
            let secret_patterns = [
                "password = \"",
                "api_key = \"",
                "secret = \"",
                "token = \"",
                "private_key = \"",
                "AWS_SECRET",
            ];

            for pattern in secret_patterns {
                if line.to_lowercase().contains(&pattern.to_lowercase()) {
                    if let Some(pos) = line.to_lowercase().find(&pattern.to_lowercase()) {
                        patterns.push(CodePattern {
                            id: format!("SEC-{}-{}", line_num + 1, pos),
                            pattern_type: PatternType::HardcodedSecret,
                            location: CodeLocation::new(file, line_num + 1, pos),
                            original: pattern.to_string(),
                            suggestion: "Use environment variable or secure config".to_string(),
                            severity: Severity::Critical,
                            auto_fixable: false,
                            explanation: "Hardcoded secrets should be moved to environment variables or a secure configuration system.".to_string(),
                        });
                    }
                }
            }

            // Weak crypto
            let weak_crypto = ["md5", "sha1", "des", "rc4", "ecb"];
            for crypto in weak_crypto {
                if line.to_lowercase().contains(crypto) {
                    if let Some(pos) = line.to_lowercase().find(crypto) {
                        patterns.push(CodePattern {
                            id: format!("CRY-{}-{}", line_num + 1, pos),
                            pattern_type: PatternType::WeakCrypto,
                            location: CodeLocation::new(file, line_num + 1, pos),
                            original: crypto.to_uppercase(),
                            suggestion: "Use SHA-256, AES-GCM, or ChaCha20-Poly1305".to_string(),
                            severity: Severity::Error,
                            auto_fixable: false,
                            explanation: format!(
                                "{} is cryptographically weak. Use modern algorithms.",
                                crypto.to_uppercase()
                            ),
                        });
                    }
                }
            }

            // SQL injection potential
            if line.contains("format!")
                && (line.contains("SELECT")
                    || line.contains("INSERT")
                    || line.contains("UPDATE")
                    || line.contains("DELETE"))
            {
                patterns.push(CodePattern {
                    id: format!("SQL-{}", line_num + 1),
                    pattern_type: PatternType::SqlInjection,
                    location: CodeLocation::new(file, line_num + 1, 0),
                    original: "format!(...SQL...)".to_string(),
                    suggestion: "Use prepared statements or query builder".to_string(),
                    severity: Severity::Critical,
                    auto_fixable: false,
                    explanation: "String formatting in SQL queries can lead to SQL injection. Use parameterized queries.".to_string(),
                });
            }
        }

        patterns
    }

    fn name(&self) -> &str {
        "Security Analyzer"
    }
}

/// Modern idioms analyzer
pub struct IdiomAnalyzer;

impl PatternAnalyzer for IdiomAnalyzer {
    fn analyze(&self, code: &str, file: &str) -> Vec<CodePattern> {
        let mut patterns = Vec::new();

        for (line_num, line) in code.lines().enumerate() {
            // try!() macro (deprecated)
            if line.contains("try!(") {
                if let Some(pos) = line.find("try!(") {
                    patterns.push(CodePattern {
                        id: format!("TRY-{}-{}", line_num + 1, pos),
                        pattern_type: PatternType::QuestionMark,
                        location: CodeLocation::new(file, line_num + 1, pos),
                        original: "try!(...)".to_string(),
                        suggestion: "expr?".to_string(),
                        severity: Severity::Warning,
                        auto_fixable: true,
                        explanation: "The try!() macro is deprecated. Use the ? operator instead."
                            .to_string(),
                    });
                }
            }

            // Box<Trait> without dyn
            if line.contains("Box<") && !line.contains("Box<dyn") {
                // Check if it's a trait (heuristic: starts with uppercase, no generics)
                if let Some(start) = line.find("Box<") {
                    let after = &line[start + 4..];
                    if let Some(end) = after.find('>') {
                        let inner = &after[..end];
                        if inner
                            .chars()
                            .next()
                            .map(|c| c.is_uppercase())
                            .unwrap_or(false)
                            && !inner.contains('<')
                            && ![
                                "String", "Vec", "HashMap", "HashSet", "BTreeMap", "BTreeSet",
                                "Option", "Result",
                            ]
                            .contains(&inner)
                        {
                            patterns.push(CodePattern {
                                id: format!("DYN-{}-{}", line_num + 1, start),
                                pattern_type: PatternType::DynTrait,
                                location: CodeLocation::new(file, line_num + 1, start),
                                original: format!("Box<{}>", inner),
                                suggestion: format!("Box<dyn {}>", inner),
                                severity: Severity::Warning,
                                auto_fixable: true,
                                explanation: "Trait objects require 'dyn' keyword in Rust 2018+."
                                    .to_string(),
                            });
                        }
                    }
                }
            }

            // Match with single arm
            if line.trim().starts_with("match ") && line.contains("=>") {
                // Simplified detection - in reality would need multi-line analysis
                patterns.push(CodePattern {
                    id: format!("MAT-{}", line_num + 1),
                    pattern_type: PatternType::MatchToIfLet,
                    location: CodeLocation::new(file, line_num + 1, 0),
                    original: "match expr { Pattern => ... }".to_string(),
                    suggestion: "if let Pattern = expr { ... }".to_string(),
                    severity: Severity::Hint,
                    auto_fixable: false,
                    explanation: "Consider using 'if let' for single-arm matches.".to_string(),
                });
            }
        }

        patterns
    }

    fn name(&self) -> &str {
        "Idiom Analyzer"
    }
}

/// Code complexity analyzer
pub struct ComplexityAnalyzer {
    max_function_lines: usize,
    max_nesting_depth: usize,
}

impl Default for ComplexityAnalyzer {
    fn default() -> Self {
        Self {
            max_function_lines: 50,
            max_nesting_depth: 4,
        }
    }
}

impl PatternAnalyzer for ComplexityAnalyzer {
    fn analyze(&self, code: &str, file: &str) -> Vec<CodePattern> {
        let mut patterns = Vec::new();
        let mut current_function_start = 0;
        let mut current_function_name = String::new();
        let mut brace_depth = 0;
        let mut max_depth_in_function = 0;

        for (line_num, line) in code.lines().enumerate() {
            let trimmed = line.trim();

            // Detect function start
            if (trimmed.starts_with("fn ")
                || trimmed.starts_with("pub fn ")
                || trimmed.starts_with("async fn ")
                || trimmed.starts_with("pub async fn "))
                && trimmed.contains('(')
            {
                current_function_start = line_num + 1;
                if let Some(name_start) = trimmed.find("fn ") {
                    let after_fn = &trimmed[name_start + 3..];
                    if let Some(paren) = after_fn.find('(') {
                        current_function_name = after_fn[..paren].trim().to_string();
                    }
                }
                max_depth_in_function = 0;
            }

            // Track nesting depth
            let opens = line.chars().filter(|&c| c == '{').count();
            let closes = line.chars().filter(|&c| c == '}').count();
            brace_depth += opens;
            brace_depth = brace_depth.saturating_sub(closes);

            if brace_depth > max_depth_in_function {
                max_depth_in_function = brace_depth;
            }

            // Check for deep nesting
            if brace_depth > self.max_nesting_depth {
                patterns.push(CodePattern {
                    id: format!("NEST-{}", line_num + 1),
                    pattern_type: PatternType::DeepNestingFlatten,
                    location: CodeLocation::new(file, line_num + 1, 0),
                    original: format!("Nesting depth: {}", brace_depth),
                    suggestion: "Use early returns or extract helper functions".to_string(),
                    severity: Severity::Warning,
                    auto_fixable: false,
                    explanation: format!(
                        "Nesting depth of {} exceeds recommended maximum of {}",
                        brace_depth, self.max_nesting_depth
                    ),
                });
            }

            // Check function length at end
            if closes > 0 && brace_depth == 0 && !current_function_name.is_empty() {
                let function_length = line_num + 1 - current_function_start;
                if function_length > self.max_function_lines {
                    patterns.push(CodePattern {
                        id: format!("LONG-{}", current_function_start),
                        pattern_type: PatternType::LongFunctionSplit,
                        location: CodeLocation::new(file, current_function_start, 0),
                        original: format!(
                            "fn {} ({} lines)",
                            current_function_name, function_length
                        ),
                        suggestion: "Consider splitting into smaller functions".to_string(),
                        severity: Severity::Info,
                        auto_fixable: false,
                        explanation: format!(
                            "Function '{}' is {} lines long, exceeding recommended maximum of {}",
                            current_function_name, function_length, self.max_function_lines
                        ),
                    });
                }
                current_function_name.clear();
            }

            // Magic numbers
            let num_pattern = |s: &str| -> bool {
                s.parse::<i64>().is_ok() && s.len() > 1 && s != "10" && s != "100"
            };

            for word in trimmed.split_whitespace() {
                if num_pattern(word)
                    && !trimmed.starts_with("const ")
                    && !trimmed.starts_with("static ")
                {
                    patterns.push(CodePattern {
                        id: format!("MAGIC-{}", line_num + 1),
                        pattern_type: PatternType::MagicNumberToConst,
                        location: CodeLocation::new(file, line_num + 1, 0),
                        original: word.to_string(),
                        suggestion: "const MEANINGFUL_NAME: i64 = ...".to_string(),
                        severity: Severity::Hint,
                        auto_fixable: false,
                        explanation: "Magic numbers should be named constants for clarity"
                            .to_string(),
                    });
                    break;
                }
            }
        }

        patterns
    }

    fn name(&self) -> &str {
        "Complexity Analyzer"
    }
}

// ============================================================================
// Modernization Engine
// ============================================================================

/// Configuration for the modernization engine
#[derive(Clone, Debug)]
pub struct ModernizationConfig {
    pub enabled_analyzers: HashSet<String>,
    pub min_severity: Severity,
    pub auto_fix: bool,
    pub target_edition: RustEdition,
}

#[derive(Clone, Debug, PartialEq)]
pub enum RustEdition {
    Rust2015,
    Rust2018,
    Rust2021,
    Rust2024,
}

impl Default for ModernizationConfig {
    fn default() -> Self {
        let mut analyzers = HashSet::new();
        analyzers.insert("unwrap".to_string());
        analyzers.insert("clone".to_string());
        analyzers.insert("security".to_string());
        analyzers.insert("idiom".to_string());
        analyzers.insert("complexity".to_string());

        Self {
            enabled_analyzers: analyzers,
            min_severity: Severity::Hint,
            auto_fix: false,
            target_edition: RustEdition::Rust2021,
        }
    }
}

/// Modernization engine
pub struct ModernizationEngine {
    config: ModernizationConfig,
    analyzers: Vec<Box<dyn PatternAnalyzer>>,
}

impl ModernizationEngine {
    pub fn new(config: ModernizationConfig) -> Self {
        let mut analyzers: Vec<Box<dyn PatternAnalyzer>> = Vec::new();

        if config.enabled_analyzers.contains("unwrap") {
            analyzers.push(Box::new(UnwrapAnalyzer));
        }
        if config.enabled_analyzers.contains("clone") {
            analyzers.push(Box::new(CloneAnalyzer));
        }
        if config.enabled_analyzers.contains("security") {
            analyzers.push(Box::new(SecurityAnalyzer));
        }
        if config.enabled_analyzers.contains("idiom") {
            analyzers.push(Box::new(IdiomAnalyzer));
        }
        if config.enabled_analyzers.contains("complexity") {
            analyzers.push(Box::new(ComplexityAnalyzer::default()));
        }

        Self { config, analyzers }
    }

    pub fn analyze_file(&self, code: &str, file: &str) -> Vec<CodePattern> {
        let mut all_patterns = Vec::new();

        for analyzer in &self.analyzers {
            let patterns = analyzer.analyze(code, file);
            all_patterns.extend(patterns);
        }

        // Filter by severity
        all_patterns.retain(|p| p.severity >= self.config.min_severity);

        // Sort by line number
        all_patterns.sort_by(|a, b| a.location.start_line.cmp(&b.location.start_line));

        all_patterns
    }

    pub fn generate_report(&self, patterns: &[CodePattern]) -> ModernizationReport {
        let mut by_category: HashMap<String, Vec<&CodePattern>> = HashMap::new();
        let mut by_severity: HashMap<Severity, usize> = HashMap::new();

        for pattern in patterns {
            by_category
                .entry(pattern.pattern_type.category().to_string())
                .or_insert_with(Vec::new)
                .push(pattern);

            *by_severity.entry(pattern.severity.clone()).or_insert(0) += 1;
        }

        let auto_fixable = patterns.iter().filter(|p| p.auto_fixable).count();

        ModernizationReport {
            total_patterns: patterns.len(),
            by_category,
            by_severity,
            auto_fixable,
            patterns: patterns.to_vec(),
        }
    }
}

/// Modernization report
#[derive(Debug)]
pub struct ModernizationReport {
    pub total_patterns: usize,
    pub by_category: HashMap<String, Vec<&'static CodePattern>>,
    pub by_severity: HashMap<Severity, usize>,
    pub auto_fixable: usize,
    pub patterns: Vec<CodePattern>,
}

impl ModernizationReport {
    pub fn to_text(&self) -> String {
        let mut output = String::new();

        output.push_str("╔════════════════════════════════════════════════════════════════════╗\n");
        output.push_str("║                   CODE MODERNIZATION REPORT                        ║\n");
        output
            .push_str("╚════════════════════════════════════════════════════════════════════╝\n\n");

        // Summary
        output.push_str("Summary:\n");
        output.push_str(&format!(
            "  Total patterns found: {}\n",
            self.total_patterns
        ));
        output.push_str(&format!("  Auto-fixable: {}\n", self.auto_fixable));
        output.push('\n');

        // By severity
        output.push_str("By Severity:\n");
        for severity in [
            Severity::Critical,
            Severity::Error,
            Severity::Warning,
            Severity::Info,
            Severity::Hint,
        ] {
            if let Some(&count) = self.by_severity.get(&severity) {
                let icon = match severity {
                    Severity::Critical => "🔴",
                    Severity::Error => "🟠",
                    Severity::Warning => "🟡",
                    Severity::Info => "🔵",
                    Severity::Hint => "⚪",
                };
                output.push_str(&format!("  {} {}: {}\n", icon, severity, count));
            }
        }
        output.push('\n');

        // Patterns by category
        let mut categories: HashMap<String, Vec<&CodePattern>> = HashMap::new();
        for pattern in &self.patterns {
            categories
                .entry(pattern.pattern_type.category().to_string())
                .or_insert_with(Vec::new)
                .push(pattern);
        }

        for (category, patterns) in &categories {
            output.push_str(&format!("═══ {} ({}) ═══\n\n", category, patterns.len()));

            for pattern in patterns.iter().take(5) {
                let icon = match pattern.severity {
                    Severity::Critical => "🔴",
                    Severity::Error => "🟠",
                    Severity::Warning => "🟡",
                    Severity::Info => "🔵",
                    Severity::Hint => "⚪",
                };

                output.push_str(&format!(
                    "  {} {}:{}:{}\n",
                    icon,
                    pattern.location.file,
                    pattern.location.start_line,
                    pattern.location.start_col
                ));
                output.push_str(&format!("    Original: {}\n", pattern.original));
                output.push_str(&format!("    Suggestion: {}\n", pattern.suggestion));
                if pattern.auto_fixable {
                    output.push_str("    [Auto-fixable]\n");
                }
                output.push('\n');
            }

            if patterns.len() > 5 {
                output.push_str(&format!("  ... and {} more\n\n", patterns.len() - 5));
            }
        }

        output
    }
}

// ============================================================================
// Auto-Fix Engine
// ============================================================================

/// Auto-fix result
#[derive(Clone, Debug)]
pub struct FixResult {
    pub pattern_id: String,
    pub success: bool,
    pub original: String,
    pub fixed: String,
    pub error: Option<String>,
}

/// Auto-fixer for code patterns
pub struct AutoFixer;

impl AutoFixer {
    pub fn fix_try_macro(code: &str) -> String {
        // Replace try!(expr) with expr?
        let mut result = code.to_string();

        while let Some(start) = result.find("try!(") {
            if let Some(end) = find_matching_paren(&result[start + 4..]) {
                let inner = &result[start + 5..start + 4 + end];
                let replacement = format!("{}?", inner);
                result = format!(
                    "{}{}{}",
                    &result[..start],
                    replacement,
                    &result[start + 5 + end..]
                );
            } else {
                break;
            }
        }

        result
    }

    pub fn fix_dyn_trait(code: &str) -> String {
        // Add dyn keyword to trait objects
        let mut result = code.to_string();

        // Patterns that need dyn
        let patterns = [
            ("Box<Error>", "Box<dyn Error>"),
            ("Box<Iterator", "Box<dyn Iterator"),
            ("Box<Future", "Box<dyn Future"),
            ("Box<Fn(", "Box<dyn Fn("),
            ("Box<FnMut(", "Box<dyn FnMut("),
            ("Box<FnOnce(", "Box<dyn FnOnce("),
            ("&Error", "&dyn Error"),
            ("&Iterator", "&dyn Iterator"),
        ];

        for (old, new) in patterns {
            result = result.replace(old, new);
        }

        result
    }

    pub fn apply_fixes(&self, code: &str, patterns: &[CodePattern]) -> (String, Vec<FixResult>) {
        let mut result = code.to_string();
        let mut fix_results = Vec::new();

        for pattern in patterns.iter().filter(|p| p.auto_fixable) {
            let fixed = match pattern.pattern_type {
                PatternType::QuestionMark => {
                    let fixed = Self::fix_try_macro(&result);
                    if fixed != result {
                        result = fixed.clone();
                        Some(fixed)
                    } else {
                        None
                    }
                }
                PatternType::DynTrait => {
                    let fixed = Self::fix_dyn_trait(&result);
                    if fixed != result {
                        result = fixed.clone();
                        Some(fixed)
                    } else {
                        None
                    }
                }
                _ => None,
            };

            fix_results.push(FixResult {
                pattern_id: pattern.id.clone(),
                success: fixed.is_some(),
                original: pattern.original.clone(),
                fixed: fixed.unwrap_or_else(|| pattern.original.clone()),
                error: if fixed.is_none() {
                    Some("Auto-fix not implemented".to_string())
                } else {
                    None
                },
            });
        }

        (result, fix_results)
    }
}

fn find_matching_paren(s: &str) -> Option<usize> {
    let mut depth = 1;
    for (i, c) in s.chars().enumerate() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

// ============================================================================
// Main Demonstration
// ============================================================================

fn main() {
    println!("=== Code Modernization and Refactoring ===\n");

    // Sample code with various patterns
    let sample_code = r#"
use std::error::Error;

const MAX_SIZE: usize = 100;

fn process_data(data: Vec<String>) -> Result<(), Box<Error>> {
    let value = try!(get_value());

    let items = data.clone();

    for i in 0..items.len() {
        let item = items[i].clone();
        let parsed = item.parse::<i32>().unwrap();

        if parsed > 1000 {
            if parsed > 2000 {
                if parsed > 3000 {
                    if parsed > 4000 {
                        println!("Very large: {}", parsed);
                    }
                }
            }
        }
    }

    let password = "secret123";
    let hash = md5::compute(password);

    let query = format!("SELECT * FROM users WHERE id = {}", user_id);

    Ok(())
}

fn helper_function() {
    // Long function with many lines
    let x = 1;
    let y = 2;
    let z = 3;
    // ... imagine 50+ more lines here
    println!("{} {} {}", x, y, z);
}

fn old_style() -> Box<Iterator<Item = i32>> {
    Box::new(vec![1, 2, 3].into_iter())
}
"#;

    // Create modernization engine
    let config = ModernizationConfig::default();
    let engine = ModernizationEngine::new(config);

    // Analyze code
    println!("Analyzing sample code...\n");
    let patterns = engine.analyze_file(sample_code, "sample.rs");

    // Generate report
    let report = engine.generate_report(&patterns);
    println!("{}", report.to_text());

    // Demonstrate auto-fixing
    println!("═══════════════════════════════════════════════════════════════════════");
    println!("                          AUTO-FIX DEMONSTRATION");
    println!("═══════════════════════════════════════════════════════════════════════\n");

    let test_code = r#"fn example() -> Result<i32, Error> {
    let x = try!(get_value());
    let y = try!(parse_int(x));
    Ok(y)
}

fn old_trait() -> Box<Iterator<Item = i32>> {
    Box::new(vec![1].into_iter())
}
"#;

    println!("Original code:");
    println!("─────────────────────────────────────────────────────────────────────────");
    println!("{}", test_code);

    let fixer = AutoFixer;
    let auto_fixable: Vec<_> = patterns
        .iter()
        .filter(|p| p.auto_fixable)
        .cloned()
        .collect();
    let (fixed_code, results) = fixer.apply_fixes(test_code, &auto_fixable);

    println!("Fixed code:");
    println!("─────────────────────────────────────────────────────────────────────────");
    println!("{}", fixed_code);

    println!("Fix results:");
    for result in &results {
        let status = if result.success { "✓" } else { "✗" };
        println!("  {} {} -> {}", status, result.original, result.fixed);
    }

    println!("\n=== Code Modernization Complete ===");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unwrap_analyzer() {
        let analyzer = UnwrapAnalyzer;
        let code = r#"
let x = something.unwrap();
let y = other.expect("message");
"#;

        let patterns = analyzer.analyze(code, "test.rs");
        assert!(!patterns.is_empty());
        assert!(patterns
            .iter()
            .any(|p| matches!(p.pattern_type, PatternType::UnwrapToExpect)));
    }

    #[test]
    fn test_clone_analyzer() {
        let analyzer = CloneAnalyzer;
        let code = r#"
let x = value.clone();
let s = "hello".to_string();
"#;

        let patterns = analyzer.analyze(code, "test.rs");
        assert!(!patterns.is_empty());
    }

    #[test]
    fn test_security_analyzer() {
        let analyzer = SecurityAnalyzer;
        let code = r#"
let password = "secret123";
let hash = md5::compute(data);
let query = format!("SELECT * FROM users WHERE id = {}", id);
"#;

        let patterns = analyzer.analyze(code, "test.rs");
        assert!(patterns
            .iter()
            .any(|p| matches!(p.pattern_type, PatternType::HardcodedSecret)));
        assert!(patterns
            .iter()
            .any(|p| matches!(p.pattern_type, PatternType::WeakCrypto)));
        assert!(patterns
            .iter()
            .any(|p| matches!(p.pattern_type, PatternType::SqlInjection)));
    }

    #[test]
    fn test_idiom_analyzer() {
        let analyzer = IdiomAnalyzer;
        let code = r#"
let x = try!(something());
fn old() -> Box<Iterator<Item = i32>> { todo!() }
"#;

        let patterns = analyzer.analyze(code, "test.rs");
        assert!(patterns
            .iter()
            .any(|p| matches!(p.pattern_type, PatternType::QuestionMark)));
    }

    #[test]
    fn test_fix_try_macro() {
        let code = "let x = try!(get_value());";
        let fixed = AutoFixer::fix_try_macro(code);
        assert_eq!(fixed, "let x = get_value()?;");
    }

    #[test]
    fn test_fix_dyn_trait() {
        let code = "fn f() -> Box<Error> {}";
        let fixed = AutoFixer::fix_dyn_trait(code);
        assert_eq!(fixed, "fn f() -> Box<dyn Error> {}");
    }

    #[test]
    fn test_pattern_type_category() {
        assert_eq!(PatternType::UnwrapToExpect.category(), "Safety");
        assert_eq!(PatternType::CloneToRef.category(), "Performance");
        assert_eq!(PatternType::HardcodedSecret.category(), "Security");
        assert_eq!(PatternType::DynTrait.category(), "Rust Idioms");
    }

    #[test]
    fn test_modernization_engine() {
        let config = ModernizationConfig::default();
        let engine = ModernizationEngine::new(config);

        let code = "let x = y.unwrap();";
        let patterns = engine.analyze_file(code, "test.rs");

        assert!(!patterns.is_empty());
    }

    #[test]
    fn test_complexity_analyzer() {
        let analyzer = ComplexityAnalyzer::default();
        let code = r#"
fn deep() {
    if a {
        if b {
            if c {
                if d {
                    if e {
                        println!("deep");
                    }
                }
            }
        }
    }
}
"#;

        let patterns = analyzer.analyze(code, "test.rs");
        assert!(patterns
            .iter()
            .any(|p| matches!(p.pattern_type, PatternType::DeepNestingFlatten)));
    }

    #[test]
    fn test_find_matching_paren() {
        assert_eq!(find_matching_paren("foo)"), Some(3));
        assert_eq!(find_matching_paren("(a)b)"), Some(4));
        assert_eq!(find_matching_paren("a(b)c)"), Some(5));
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::Error);
        assert!(Severity::Error > Severity::Warning);
        assert!(Severity::Warning > Severity::Info);
        assert!(Severity::Info > Severity::Hint);
    }
}
