//! Dead Code Eliminator
//!
//! Automated detection and removal of unused code in Rust projects.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

/// Symbol type classification
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SymbolKind {
    Function,
    Method,
    Struct,
    Enum,
    Trait,
    Const,
    Static,
    TypeAlias,
    Macro,
    Module,
    Import,
    Field,
    Variant,
}

impl SymbolKind {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "function" | "fn" => Some(Self::Function),
            "method" => Some(Self::Method),
            "struct" => Some(Self::Struct),
            "enum" => Some(Self::Enum),
            "trait" => Some(Self::Trait),
            "const" => Some(Self::Const),
            "static" => Some(Self::Static),
            "type" | "typealias" => Some(Self::TypeAlias),
            "macro" => Some(Self::Macro),
            "module" | "mod" => Some(Self::Module),
            "import" | "use" => Some(Self::Import),
            "field" => Some(Self::Field),
            "variant" => Some(Self::Variant),
            _ => None,
        }
    }
}

/// Visibility level
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Visibility {
    Private,
    Crate,
    Super,
    Public,
    Restricted(String),
}

impl Visibility {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "pub" | "public" => Self::Public,
            "pub(crate)" | "crate" => Self::Crate,
            "pub(super)" | "super" => Self::Super,
            "" | "private" => Self::Private,
            _ => Self::Restricted(s.to_string()),
        }
    }

    pub fn is_public(&self) -> bool {
        matches!(self, Self::Public)
    }
}

/// A symbol in the codebase
#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub kind: SymbolKind,
    pub visibility: Visibility,
    pub file: PathBuf,
    pub line: usize,
    pub column: usize,
    pub module_path: String,
    pub references: Vec<SymbolReference>,
    pub attributes: Vec<String>,
}

impl Symbol {
    pub fn new(
        name: impl Into<String>,
        kind: SymbolKind,
        file: PathBuf,
        line: usize,
    ) -> Self {
        Self {
            name: name.into(),
            kind,
            visibility: Visibility::Private,
            file,
            line,
            column: 0,
            module_path: String::new(),
            references: Vec::new(),
            attributes: Vec::new(),
        }
    }

    pub fn with_visibility(mut self, visibility: Visibility) -> Self {
        self.visibility = visibility;
        self
    }

    pub fn with_module_path(mut self, path: impl Into<String>) -> Self {
        self.module_path = path.into();
        self
    }

    pub fn with_attributes(mut self, attrs: Vec<String>) -> Self {
        self.attributes = attrs;
        self
    }

    pub fn add_reference(&mut self, reference: SymbolReference) {
        self.references.push(reference);
    }

    pub fn is_unused(&self) -> bool {
        self.references.is_empty()
    }

    pub fn is_test_only(&self) -> bool {
        self.attributes.iter().any(|a| a.contains("test"))
    }

    pub fn is_cfg_conditional(&self) -> bool {
        self.attributes.iter().any(|a| a.starts_with("cfg("))
    }

    pub fn has_allow_dead_code(&self) -> bool {
        self.attributes
            .iter()
            .any(|a| a.contains("allow(dead_code)") || a.contains("allow(unused)"))
    }

    pub fn fully_qualified_name(&self) -> String {
        if self.module_path.is_empty() {
            self.name.clone()
        } else {
            format!("{}::{}", self.module_path, self.name)
        }
    }
}

/// Reference to a symbol
#[derive(Debug, Clone)]
pub struct SymbolReference {
    pub file: PathBuf,
    pub line: usize,
    pub column: usize,
    pub context: ReferenceContext,
}

/// Context of symbol usage
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReferenceContext {
    FunctionCall,
    MethodCall,
    TypeUsage,
    FieldAccess,
    Import,
    Trait Implementation,
    MacroInvocation,
    Derive,
    PatternMatch,
    Other,
}

/// Dead code detection result
#[derive(Debug, Clone)]
pub struct DeadCodeResult {
    pub symbol: Symbol,
    pub reason: DeadCodeReason,
    pub confidence: Confidence,
    pub suggested_action: SuggestedAction,
}

/// Reason for dead code classification
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeadCodeReason {
    NeverUsed,
    OnlyUsedInTests,
    UnreachableCode,
    RedundantImport,
    UnusedParameter,
    UnusedVariable,
    UnusedField,
    UnusedVariant,
    DeprecatedNoCallers,
}

impl std::fmt::Display for DeadCodeReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NeverUsed => write!(f, "Symbol is never used"),
            Self::OnlyUsedInTests => write!(f, "Only used in test code"),
            Self::UnreachableCode => write!(f, "Code is unreachable"),
            Self::RedundantImport => write!(f, "Import is redundant"),
            Self::UnusedParameter => write!(f, "Parameter is unused"),
            Self::UnusedVariable => write!(f, "Variable is unused"),
            Self::UnusedField => write!(f, "Field is unused"),
            Self::UnusedVariant => write!(f, "Enum variant is unused"),
            Self::DeprecatedNoCallers => write!(f, "Deprecated with no callers"),
        }
    }
}

/// Confidence level of detection
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

/// Suggested action for dead code
#[derive(Debug, Clone)]
pub enum SuggestedAction {
    Remove,
    AddAttribute(String),
    MakePrivate,
    RefactorToTest,
    Review,
    Ignore,
}

impl std::fmt::Display for SuggestedAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Remove => write!(f, "Remove the code"),
            Self::AddAttribute(attr) => write!(f, "Add #[{}]", attr),
            Self::MakePrivate => write!(f, "Reduce visibility to private"),
            Self::RefactorToTest => write!(f, "Move to test module"),
            Self::Review => write!(f, "Manual review required"),
            Self::Ignore => write!(f, "Safe to ignore"),
        }
    }
}

/// Dead code analyzer configuration
#[derive(Debug, Clone)]
pub struct AnalyzerConfig {
    pub check_private: bool,
    pub check_public: bool,
    pub check_imports: bool,
    pub check_fields: bool,
    pub check_variants: bool,
    pub check_test_only: bool,
    pub ignore_patterns: Vec<String>,
    pub ignore_attributes: Vec<String>,
    pub ignore_modules: Vec<String>,
}

impl Default for AnalyzerConfig {
    fn default() -> Self {
        Self {
            check_private: true,
            check_public: false, // Public items might be used externally
            check_imports: true,
            check_fields: true,
            check_variants: true,
            check_test_only: false,
            ignore_patterns: vec!["main".to_string(), "new".to_string()],
            ignore_attributes: vec![
                "allow(dead_code)".to_string(),
                "allow(unused)".to_string(),
            ],
            ignore_modules: vec!["tests".to_string(), "benches".to_string()],
        }
    }
}

/// Dead code analyzer
pub struct DeadCodeAnalyzer {
    config: AnalyzerConfig,
    symbols: HashMap<String, Symbol>,
    results: Vec<DeadCodeResult>,
}

impl DeadCodeAnalyzer {
    pub fn new(config: AnalyzerConfig) -> Self {
        Self {
            config,
            symbols: HashMap::new(),
            results: Vec::new(),
        }
    }

    pub fn add_symbol(&mut self, symbol: Symbol) {
        let key = symbol.fully_qualified_name();
        self.symbols.insert(key, symbol);
    }

    pub fn add_reference(&mut self, symbol_name: &str, reference: SymbolReference) {
        if let Some(symbol) = self.symbols.get_mut(symbol_name) {
            symbol.add_reference(reference);
        }
    }

    pub fn analyze(&mut self) -> Vec<DeadCodeResult> {
        self.results.clear();

        for symbol in self.symbols.values() {
            if self.should_skip(symbol) {
                continue;
            }

            if let Some(result) = self.check_symbol(symbol) {
                self.results.push(result);
            }
        }

        // Sort by file and line
        self.results.sort_by(|a, b| {
            a.symbol
                .file
                .cmp(&b.symbol.file)
                .then(a.symbol.line.cmp(&b.symbol.line))
        });

        self.results.clone()
    }

    fn should_skip(&self, symbol: &Symbol) -> bool {
        // Skip if in ignored module
        if self
            .config
            .ignore_modules
            .iter()
            .any(|m| symbol.module_path.contains(m))
        {
            return true;
        }

        // Skip if matches ignore pattern
        if self
            .config
            .ignore_patterns
            .iter()
            .any(|p| symbol.name.contains(p))
        {
            return true;
        }

        // Skip if has ignore attribute
        if symbol.attributes.iter().any(|a| {
            self.config
                .ignore_attributes
                .iter()
                .any(|ia| a.contains(ia))
        }) {
            return true;
        }

        // Skip public items if not configured
        if symbol.visibility.is_public() && !self.config.check_public {
            return true;
        }

        // Skip test-only items if not configured
        if symbol.is_test_only() && !self.config.check_test_only {
            return true;
        }

        false
    }

    fn check_symbol(&self, symbol: &Symbol) -> Option<DeadCodeResult> {
        let reason = self.determine_dead_code_reason(symbol)?;
        let confidence = self.calculate_confidence(symbol, &reason);
        let suggested_action = self.suggest_action(symbol, &reason);

        Some(DeadCodeResult {
            symbol: symbol.clone(),
            reason,
            confidence,
            suggested_action,
        })
    }

    fn determine_dead_code_reason(&self, symbol: &Symbol) -> Option<DeadCodeReason> {
        if symbol.references.is_empty() {
            // Check specific kinds
            match symbol.kind {
                SymbolKind::Import => {
                    if self.config.check_imports {
                        return Some(DeadCodeReason::RedundantImport);
                    }
                }
                SymbolKind::Field => {
                    if self.config.check_fields {
                        return Some(DeadCodeReason::UnusedField);
                    }
                }
                SymbolKind::Variant => {
                    if self.config.check_variants {
                        return Some(DeadCodeReason::UnusedVariant);
                    }
                }
                _ => return Some(DeadCodeReason::NeverUsed),
            }
        }

        // Check if only used in tests
        if !symbol.references.is_empty()
            && symbol.references.iter().all(|r| {
                r.file.to_string_lossy().contains("test")
                    || r.file.to_string_lossy().contains("tests")
            })
        {
            return Some(DeadCodeReason::OnlyUsedInTests);
        }

        None
    }

    fn calculate_confidence(&self, symbol: &Symbol, reason: &DeadCodeReason) -> Confidence {
        match reason {
            DeadCodeReason::RedundantImport => Confidence::High,
            DeadCodeReason::UnusedVariable => Confidence::High,
            DeadCodeReason::NeverUsed => {
                if symbol.visibility.is_public() {
                    Confidence::Low // Might be used externally
                } else if symbol.is_cfg_conditional() {
                    Confidence::Medium // Might be used with different cfg
                } else {
                    Confidence::High
                }
            }
            DeadCodeReason::OnlyUsedInTests => Confidence::Medium,
            DeadCodeReason::UnusedField | DeadCodeReason::UnusedVariant => {
                if symbol.visibility.is_public() {
                    Confidence::Low
                } else {
                    Confidence::High
                }
            }
            _ => Confidence::Medium,
        }
    }

    fn suggest_action(&self, symbol: &Symbol, reason: &DeadCodeReason) -> SuggestedAction {
        match reason {
            DeadCodeReason::RedundantImport => SuggestedAction::Remove,
            DeadCodeReason::UnusedVariable => SuggestedAction::Remove,
            DeadCodeReason::NeverUsed => {
                if symbol.visibility.is_public() {
                    SuggestedAction::Review
                } else {
                    SuggestedAction::Remove
                }
            }
            DeadCodeReason::OnlyUsedInTests => SuggestedAction::RefactorToTest,
            DeadCodeReason::UnusedField => {
                if symbol.visibility.is_public() {
                    SuggestedAction::MakePrivate
                } else {
                    SuggestedAction::Remove
                }
            }
            _ => SuggestedAction::Review,
        }
    }

    pub fn generate_report(&self) -> DeadCodeReport {
        let mut report = DeadCodeReport::default();

        for result in &self.results {
            report.total += 1;

            match result.confidence {
                Confidence::High => report.high_confidence += 1,
                Confidence::Medium => report.medium_confidence += 1,
                Confidence::Low => report.low_confidence += 1,
            }

            match &result.reason {
                DeadCodeReason::NeverUsed => report.never_used += 1,
                DeadCodeReason::RedundantImport => report.redundant_imports += 1,
                DeadCodeReason::UnusedField => report.unused_fields += 1,
                DeadCodeReason::UnusedVariant => report.unused_variants += 1,
                DeadCodeReason::OnlyUsedInTests => report.test_only += 1,
                _ => report.other += 1,
            }

            // Count by file
            let file = result.symbol.file.display().to_string();
            *report.by_file.entry(file).or_insert(0) += 1;
        }

        report.results = self.results.clone();
        report
    }

    pub fn generate_removal_patch(&self) -> Vec<FilePatch> {
        let mut patches: HashMap<PathBuf, FilePatch> = HashMap::new();

        for result in &self.results {
            if matches!(result.suggested_action, SuggestedAction::Remove)
                && result.confidence == Confidence::High
            {
                let patch = patches
                    .entry(result.symbol.file.clone())
                    .or_insert_with(|| FilePatch {
                        file: result.symbol.file.clone(),
                        removals: Vec::new(),
                    });

                patch.removals.push(LineRemoval {
                    line: result.symbol.line,
                    reason: result.reason.to_string(),
                });
            }
        }

        patches.into_values().collect()
    }
}

/// Dead code report
#[derive(Debug, Default)]
pub struct DeadCodeReport {
    pub total: usize,
    pub high_confidence: usize,
    pub medium_confidence: usize,
    pub low_confidence: usize,
    pub never_used: usize,
    pub redundant_imports: usize,
    pub unused_fields: usize,
    pub unused_variants: usize,
    pub test_only: usize,
    pub other: usize,
    pub by_file: HashMap<String, usize>,
    pub results: Vec<DeadCodeResult>,
}

impl DeadCodeReport {
    pub fn to_text(&self) -> String {
        let mut output = String::new();

        output.push_str("=== Dead Code Analysis Report ===\n\n");

        output.push_str(&format!("Total issues: {}\n", self.total));
        output.push_str(&format!("  High confidence: {}\n", self.high_confidence));
        output.push_str(&format!("  Medium confidence: {}\n", self.medium_confidence));
        output.push_str(&format!("  Low confidence: {}\n", self.low_confidence));
        output.push('\n');

        output.push_str("By category:\n");
        output.push_str(&format!("  Never used: {}\n", self.never_used));
        output.push_str(&format!("  Redundant imports: {}\n", self.redundant_imports));
        output.push_str(&format!("  Unused fields: {}\n", self.unused_fields));
        output.push_str(&format!("  Unused variants: {}\n", self.unused_variants));
        output.push_str(&format!("  Test-only: {}\n", self.test_only));
        output.push('\n');

        output.push_str("By file:\n");
        for (file, count) in &self.by_file {
            output.push_str(&format!("  {}: {}\n", file, count));
        }
        output.push('\n');

        output.push_str("Details:\n");
        for result in &self.results {
            output.push_str(&format!(
                "  {}:{} - {} ({})\n",
                result.symbol.file.display(),
                result.symbol.line,
                result.symbol.name,
                result.reason
            ));
            output.push_str(&format!("    Suggested: {}\n", result.suggested_action));
        }

        output
    }

    pub fn to_json(&self) -> String {
        let issues: Vec<String> = self
            .results
            .iter()
            .map(|r| {
                format!(
                    r#"    {{
      "file": "{}",
      "line": {},
      "name": "{}",
      "kind": "{:?}",
      "reason": "{}",
      "confidence": "{:?}",
      "action": "{}"
    }}"#,
                    r.symbol.file.display(),
                    r.symbol.line,
                    r.symbol.name,
                    r.symbol.kind,
                    r.reason,
                    r.confidence,
                    r.suggested_action
                )
            })
            .collect();

        format!(
            r#"{{
  "summary": {{
    "total": {},
    "high_confidence": {},
    "medium_confidence": {},
    "low_confidence": {}
  }},
  "issues": [
{}
  ]
}}"#,
            self.total,
            self.high_confidence,
            self.medium_confidence,
            self.low_confidence,
            issues.join(",\n")
        )
    }
}

/// File patch for removals
#[derive(Debug)]
pub struct FilePatch {
    pub file: PathBuf,
    pub removals: Vec<LineRemoval>,
}

/// Line removal instruction
#[derive(Debug)]
pub struct LineRemoval {
    pub line: usize,
    pub reason: String,
}

/// AST-based symbol extractor (simplified)
pub struct SymbolExtractor {
    current_module: String,
    symbols: Vec<Symbol>,
}

impl SymbolExtractor {
    pub fn new() -> Self {
        Self {
            current_module: String::new(),
            symbols: Vec::new(),
        }
    }

    pub fn extract_from_source(&mut self, source: &str, file: PathBuf) -> Vec<Symbol> {
        self.symbols.clear();

        for (line_num, line) in source.lines().enumerate() {
            let trimmed = line.trim();

            // Extract function definitions
            if trimmed.starts_with("fn ") || trimmed.starts_with("pub fn ") {
                if let Some(name) = self.extract_fn_name(trimmed) {
                    let visibility = if trimmed.starts_with("pub ") {
                        Visibility::Public
                    } else {
                        Visibility::Private
                    };

                    let symbol = Symbol::new(name, SymbolKind::Function, file.clone(), line_num + 1)
                        .with_visibility(visibility)
                        .with_module_path(&self.current_module);

                    self.symbols.push(symbol);
                }
            }

            // Extract struct definitions
            if trimmed.starts_with("struct ") || trimmed.starts_with("pub struct ") {
                if let Some(name) = self.extract_struct_name(trimmed) {
                    let visibility = if trimmed.starts_with("pub ") {
                        Visibility::Public
                    } else {
                        Visibility::Private
                    };

                    let symbol = Symbol::new(name, SymbolKind::Struct, file.clone(), line_num + 1)
                        .with_visibility(visibility)
                        .with_module_path(&self.current_module);

                    self.symbols.push(symbol);
                }
            }

            // Extract use statements
            if trimmed.starts_with("use ") {
                let symbol = Symbol::new(
                    trimmed.to_string(),
                    SymbolKind::Import,
                    file.clone(),
                    line_num + 1,
                );
                self.symbols.push(symbol);
            }

            // Track module context
            if trimmed.starts_with("mod ") {
                if let Some(name) = self.extract_mod_name(trimmed) {
                    self.current_module = if self.current_module.is_empty() {
                        name
                    } else {
                        format!("{}::{}", self.current_module, name)
                    };
                }
            }
        }

        self.symbols.clone()
    }

    fn extract_fn_name(&self, line: &str) -> Option<String> {
        let start = line.find("fn ")? + 3;
        let rest = &line[start..];
        let end = rest.find('(')?;
        Some(rest[..end].trim().to_string())
    }

    fn extract_struct_name(&self, line: &str) -> Option<String> {
        let start = line.find("struct ")? + 7;
        let rest = &line[start..];
        let end = rest
            .find(|c: char| c == '{' || c == '(' || c == '<' || c.is_whitespace())
            .unwrap_or(rest.len());
        Some(rest[..end].trim().to_string())
    }

    fn extract_mod_name(&self, line: &str) -> Option<String> {
        let start = line.find("mod ")? + 4;
        let rest = &line[start..];
        let end = rest.find(|c: char| c == '{' || c == ';' || c.is_whitespace())?;
        Some(rest[..end].trim().to_string())
    }
}

impl Default for SymbolExtractor {
    fn default() -> Self {
        Self::new()
    }
}

fn main() {
    println!("=== Dead Code Eliminator Demo ===\n");

    // Create analyzer with default config
    let config = AnalyzerConfig {
        check_private: true,
        check_public: false,
        check_imports: true,
        check_fields: true,
        ..Default::default()
    };

    let mut analyzer = DeadCodeAnalyzer::new(config);

    // Add sample symbols
    analyzer.add_symbol(
        Symbol::new(
            "used_function",
            SymbolKind::Function,
            PathBuf::from("src/lib.rs"),
            10,
        )
        .with_visibility(Visibility::Public),
    );

    // Add reference to used_function
    analyzer.add_reference(
        "used_function",
        SymbolReference {
            file: PathBuf::from("src/main.rs"),
            line: 25,
            column: 5,
            context: ReferenceContext::FunctionCall,
        },
    );

    analyzer.add_symbol(Symbol::new(
        "unused_function",
        SymbolKind::Function,
        PathBuf::from("src/lib.rs"),
        20,
    ));

    analyzer.add_symbol(Symbol::new(
        "test_helper",
        SymbolKind::Function,
        PathBuf::from("src/lib.rs"),
        30,
    ));

    // Add reference from test file
    analyzer.add_reference(
        "test_helper",
        SymbolReference {
            file: PathBuf::from("tests/integration.rs"),
            line: 10,
            column: 5,
            context: ReferenceContext::FunctionCall,
        },
    );

    analyzer.add_symbol(Symbol::new(
        "std::io::Read",
        SymbolKind::Import,
        PathBuf::from("src/lib.rs"),
        1,
    ));

    analyzer.add_symbol(
        Symbol::new(
            "unused_field",
            SymbolKind::Field,
            PathBuf::from("src/types.rs"),
            15,
        )
        .with_module_path("types::Config"),
    );

    // Run analysis
    println!("Running dead code analysis...\n");
    let results = analyzer.analyze();

    // Generate and print report
    let report = analyzer.generate_report();
    println!("{}", report.to_text());

    // Print JSON report
    println!("\n--- JSON Report ---");
    println!("{}", report.to_json());

    // Generate removal patches
    println!("\n--- Suggested Removals ---");
    let patches = analyzer.generate_removal_patch();
    for patch in &patches {
        println!("\nFile: {}", patch.file.display());
        for removal in &patch.removals {
            println!("  Line {}: {}", removal.line, removal.reason);
        }
    }

    // Demo symbol extraction
    println!("\n--- Symbol Extraction Demo ---");
    let mut extractor = SymbolExtractor::new();
    let source = r#"
use std::io::Read;

pub fn public_function() {
    // ...
}

fn private_function() {
    // ...
}

pub struct MyStruct {
    field: String,
}

mod inner {
    fn inner_fn() {}
}
"#;

    let symbols = extractor.extract_from_source(source, PathBuf::from("example.rs"));
    println!("Extracted symbols:");
    for symbol in &symbols {
        println!(
            "  {} ({:?}) at line {} - {:?}",
            symbol.name, symbol.kind, symbol.line, symbol.visibility
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symbol_kind_from_str() {
        assert_eq!(SymbolKind::from_str("fn"), Some(SymbolKind::Function));
        assert_eq!(SymbolKind::from_str("struct"), Some(SymbolKind::Struct));
        assert_eq!(SymbolKind::from_str("enum"), Some(SymbolKind::Enum));
        assert_eq!(SymbolKind::from_str("unknown"), None);
    }

    #[test]
    fn test_visibility_from_str() {
        assert_eq!(Visibility::from_str("pub"), Visibility::Public);
        assert_eq!(Visibility::from_str("pub(crate)"), Visibility::Crate);
        assert_eq!(Visibility::from_str(""), Visibility::Private);
    }

    #[test]
    fn test_symbol_creation() {
        let symbol = Symbol::new("test_fn", SymbolKind::Function, PathBuf::from("test.rs"), 10)
            .with_visibility(Visibility::Public)
            .with_module_path("module");

        assert_eq!(symbol.name, "test_fn");
        assert_eq!(symbol.kind, SymbolKind::Function);
        assert_eq!(symbol.visibility, Visibility::Public);
        assert_eq!(symbol.fully_qualified_name(), "module::test_fn");
    }

    #[test]
    fn test_symbol_is_unused() {
        let symbol = Symbol::new("test", SymbolKind::Function, PathBuf::from("test.rs"), 1);
        assert!(symbol.is_unused());

        let mut symbol_with_ref = symbol.clone();
        symbol_with_ref.add_reference(SymbolReference {
            file: PathBuf::from("other.rs"),
            line: 5,
            column: 1,
            context: ReferenceContext::FunctionCall,
        });
        assert!(!symbol_with_ref.is_unused());
    }

    #[test]
    fn test_symbol_test_only() {
        let mut symbol = Symbol::new("test", SymbolKind::Function, PathBuf::from("test.rs"), 1);
        assert!(!symbol.is_test_only());

        symbol.attributes.push("test".to_string());
        assert!(symbol.is_test_only());
    }

    #[test]
    fn test_symbol_has_allow_dead_code() {
        let mut symbol = Symbol::new("test", SymbolKind::Function, PathBuf::from("test.rs"), 1);
        assert!(!symbol.has_allow_dead_code());

        symbol.attributes.push("allow(dead_code)".to_string());
        assert!(symbol.has_allow_dead_code());
    }

    #[test]
    fn test_analyzer_creation() {
        let config = AnalyzerConfig::default();
        let analyzer = DeadCodeAnalyzer::new(config);

        assert!(analyzer.symbols.is_empty());
        assert!(analyzer.results.is_empty());
    }

    #[test]
    fn test_analyzer_add_symbol() {
        let config = AnalyzerConfig::default();
        let mut analyzer = DeadCodeAnalyzer::new(config);

        analyzer.add_symbol(Symbol::new(
            "test",
            SymbolKind::Function,
            PathBuf::from("test.rs"),
            1,
        ));

        assert_eq!(analyzer.symbols.len(), 1);
    }

    #[test]
    fn test_analyzer_find_unused() {
        let config = AnalyzerConfig::default();
        let mut analyzer = DeadCodeAnalyzer::new(config);

        analyzer.add_symbol(Symbol::new(
            "unused",
            SymbolKind::Function,
            PathBuf::from("test.rs"),
            1,
        ));

        let results = analyzer.analyze();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].reason, DeadCodeReason::NeverUsed);
    }

    #[test]
    fn test_analyzer_skip_used() {
        let config = AnalyzerConfig::default();
        let mut analyzer = DeadCodeAnalyzer::new(config);

        analyzer.add_symbol(Symbol::new(
            "used",
            SymbolKind::Function,
            PathBuf::from("test.rs"),
            1,
        ));

        analyzer.add_reference(
            "used",
            SymbolReference {
                file: PathBuf::from("other.rs"),
                line: 10,
                column: 1,
                context: ReferenceContext::FunctionCall,
            },
        );

        let results = analyzer.analyze();

        assert!(results.is_empty());
    }

    #[test]
    fn test_analyzer_skip_ignored_pattern() {
        let config = AnalyzerConfig {
            ignore_patterns: vec!["main".to_string()],
            ..Default::default()
        };
        let mut analyzer = DeadCodeAnalyzer::new(config);

        analyzer.add_symbol(Symbol::new(
            "main",
            SymbolKind::Function,
            PathBuf::from("test.rs"),
            1,
        ));

        let results = analyzer.analyze();

        assert!(results.is_empty());
    }

    #[test]
    fn test_confidence_calculation() {
        let config = AnalyzerConfig::default();
        let mut analyzer = DeadCodeAnalyzer::new(config);

        // Private unused - high confidence
        analyzer.add_symbol(Symbol::new(
            "private_unused",
            SymbolKind::Function,
            PathBuf::from("test.rs"),
            1,
        ));

        let results = analyzer.analyze();

        assert_eq!(results[0].confidence, Confidence::High);
    }

    #[test]
    fn test_report_generation() {
        let config = AnalyzerConfig::default();
        let mut analyzer = DeadCodeAnalyzer::new(config);

        analyzer.add_symbol(Symbol::new(
            "unused1",
            SymbolKind::Function,
            PathBuf::from("test.rs"),
            1,
        ));
        analyzer.add_symbol(Symbol::new(
            "unused2",
            SymbolKind::Function,
            PathBuf::from("test.rs"),
            10,
        ));

        analyzer.analyze();
        let report = analyzer.generate_report();

        assert_eq!(report.total, 2);
        assert_eq!(report.never_used, 2);
    }

    #[test]
    fn test_symbol_extractor() {
        let mut extractor = SymbolExtractor::new();
        let source = r#"
fn private_fn() {}
pub fn public_fn() {}
struct MyStruct {}
"#;

        let symbols = extractor.extract_from_source(source, PathBuf::from("test.rs"));

        assert_eq!(symbols.len(), 3);
    }

    #[test]
    fn test_symbol_extractor_fn_name() {
        let mut extractor = SymbolExtractor::new();
        let source = "fn my_function(arg: i32) -> bool {}";

        let symbols = extractor.extract_from_source(source, PathBuf::from("test.rs"));

        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].name, "my_function");
    }

    #[test]
    fn test_removal_patch_generation() {
        let config = AnalyzerConfig::default();
        let mut analyzer = DeadCodeAnalyzer::new(config);

        analyzer.add_symbol(Symbol::new(
            "unused",
            SymbolKind::Function,
            PathBuf::from("test.rs"),
            10,
        ));

        analyzer.analyze();
        let patches = analyzer.generate_removal_patch();

        assert_eq!(patches.len(), 1);
        assert_eq!(patches[0].removals.len(), 1);
        assert_eq!(patches[0].removals[0].line, 10);
    }
}
