//! Code Refactoring Tools
//!
//! Automated code analysis and refactoring suggestions for Rust code,
//! including pattern detection, code smell identification, and safe transformations.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};

/// Types of code smells that can be detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CodeSmell {
    /// Function is too long
    LongFunction,
    /// Too many parameters
    LongParameterList,
    /// Duplicate code blocks
    DuplicateCode,
    /// Dead code (unused functions/variables)
    DeadCode,
    /// Magic numbers without explanation
    MagicNumbers,
    /// Complex boolean expressions
    ComplexConditional,
    /// Deep nesting
    DeepNesting,
    /// God object (struct with too many responsibilities)
    GodObject,
    /// Feature envy (method uses other object's data more than its own)
    FeatureEnvy,
    /// Primitive obsession
    PrimitiveObsession,
    /// Shotgun surgery (changes require modifying many places)
    ShotgunSurgery,
    /// Large match expression
    LargeMatch,
    /// Unnecessary clone
    UnnecessaryClone,
    /// Inefficient string operations
    InefficientString,
    /// Missing error context
    MissingErrorContext,
}

impl CodeSmell {
    pub fn description(&self) -> &'static str {
        match self {
            CodeSmell::LongFunction => "Function exceeds recommended line count",
            CodeSmell::LongParameterList => "Function has too many parameters",
            CodeSmell::DuplicateCode => "Similar code appears in multiple places",
            CodeSmell::DeadCode => "Code that is never executed",
            CodeSmell::MagicNumbers => "Unexplained literal values in code",
            CodeSmell::ComplexConditional => "Boolean expression is hard to understand",
            CodeSmell::DeepNesting => "Code has too many levels of indentation",
            CodeSmell::GodObject => "Struct has too many fields or methods",
            CodeSmell::FeatureEnvy => "Method heavily uses another object's data",
            CodeSmell::PrimitiveObsession => "Using primitives instead of small objects",
            CodeSmell::ShotgunSurgery => "Changes require modifications in many places",
            CodeSmell::LargeMatch => "Match expression has too many arms",
            CodeSmell::UnnecessaryClone => "Clone that could be avoided",
            CodeSmell::InefficientString => "Inefficient string concatenation",
            CodeSmell::MissingErrorContext => "Error without sufficient context",
        }
    }

    pub fn severity(&self) -> SmellSeverity {
        match self {
            CodeSmell::DuplicateCode | CodeSmell::DeadCode => SmellSeverity::High,
            CodeSmell::GodObject | CodeSmell::ShotgunSurgery => SmellSeverity::High,
            CodeSmell::LongFunction | CodeSmell::ComplexConditional => SmellSeverity::Medium,
            CodeSmell::DeepNesting | CodeSmell::LargeMatch => SmellSeverity::Medium,
            CodeSmell::UnnecessaryClone | CodeSmell::InefficientString => SmellSeverity::Medium,
            CodeSmell::MissingErrorContext => SmellSeverity::Medium,
            _ => SmellSeverity::Low,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SmellSeverity {
    Low,
    Medium,
    High,
}

/// Refactoring technique that can be applied
#[derive(Debug, Clone)]
pub enum RefactoringTechnique {
    ExtractFunction {
        original_lines: (usize, usize),
        suggested_name: String,
    },
    ExtractVariable {
        expression: String,
        suggested_name: String,
    },
    InlineFunction {
        function_name: String,
    },
    RenameSymbol {
        old_name: String,
        new_name: String,
    },
    ExtractStruct {
        fields: Vec<String>,
        suggested_name: String,
    },
    IntroduceParameterObject {
        parameters: Vec<String>,
        suggested_name: String,
    },
    ReplaceConditionalWithPolymorphism {
        match_location: usize,
    },
    ConvertToIterator {
        loop_location: usize,
    },
    UseBuilderPattern {
        struct_name: String,
    },
    IntroduceNullObject,
    ReplaceErrorWithResult,
    AddErrorContext {
        error_location: usize,
    },
}

impl RefactoringTechnique {
    pub fn name(&self) -> &'static str {
        match self {
            RefactoringTechnique::ExtractFunction { .. } => "Extract Function",
            RefactoringTechnique::ExtractVariable { .. } => "Extract Variable",
            RefactoringTechnique::InlineFunction { .. } => "Inline Function",
            RefactoringTechnique::RenameSymbol { .. } => "Rename Symbol",
            RefactoringTechnique::ExtractStruct { .. } => "Extract Struct",
            RefactoringTechnique::IntroduceParameterObject { .. } => "Introduce Parameter Object",
            RefactoringTechnique::ReplaceConditionalWithPolymorphism { .. } => {
                "Replace Conditional with Polymorphism"
            }
            RefactoringTechnique::ConvertToIterator { .. } => "Convert to Iterator",
            RefactoringTechnique::UseBuilderPattern { .. } => "Use Builder Pattern",
            RefactoringTechnique::IntroduceNullObject => "Introduce Null Object",
            RefactoringTechnique::ReplaceErrorWithResult => "Replace Error with Result",
            RefactoringTechnique::AddErrorContext { .. } => "Add Error Context",
        }
    }
}

/// A detected issue in the code
#[derive(Debug, Clone)]
pub struct CodeIssue {
    pub smell: CodeSmell,
    pub file_path: PathBuf,
    pub line_start: usize,
    pub line_end: usize,
    pub description: String,
    pub suggested_refactoring: Option<RefactoringTechnique>,
}

impl CodeIssue {
    pub fn new(smell: CodeSmell, file_path: PathBuf, line_start: usize, line_end: usize) -> Self {
        Self {
            smell,
            file_path,
            line_start,
            line_end,
            description: smell.description().into(),
            suggested_refactoring: None,
        }
    }

    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = desc.into();
        self
    }

    pub fn with_refactoring(mut self, technique: RefactoringTechnique) -> Self {
        self.suggested_refactoring = Some(technique);
        self
    }
}

/// Configuration for code analysis
#[derive(Debug, Clone)]
pub struct AnalysisConfig {
    pub max_function_lines: usize,
    pub max_parameters: usize,
    pub max_nesting_depth: usize,
    pub max_match_arms: usize,
    pub max_struct_fields: usize,
    pub max_struct_methods: usize,
    pub max_cyclomatic_complexity: usize,
    pub check_unused: bool,
    pub check_clones: bool,
    pub check_string_ops: bool,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            max_function_lines: 50,
            max_parameters: 5,
            max_nesting_depth: 4,
            max_match_arms: 10,
            max_struct_fields: 10,
            max_struct_methods: 15,
            max_cyclomatic_complexity: 10,
            check_unused: true,
            check_clones: true,
            check_string_ops: true,
        }
    }
}

/// Simplified AST node for demonstration
#[derive(Debug, Clone)]
pub enum AstNode {
    Function {
        name: String,
        params: Vec<String>,
        body_lines: usize,
        complexity: usize,
    },
    Struct {
        name: String,
        fields: Vec<String>,
        methods: Vec<String>,
    },
    Match {
        arms: usize,
        line: usize,
    },
    Loop {
        kind: LoopKind,
        line: usize,
    },
    Conditional {
        depth: usize,
        complexity: usize,
        line: usize,
    },
    Clone {
        line: usize,
        unnecessary: bool,
    },
    StringOp {
        kind: StringOpKind,
        line: usize,
    },
}

#[derive(Debug, Clone, Copy)]
pub enum LoopKind {
    For,
    While,
    Loop,
}

#[derive(Debug, Clone, Copy)]
pub enum StringOpKind {
    Concatenation,
    Format,
    Push,
}

/// Code analyzer
pub struct CodeAnalyzer {
    config: AnalysisConfig,
    issues: Vec<CodeIssue>,
}

impl CodeAnalyzer {
    pub fn new(config: AnalysisConfig) -> Self {
        Self {
            config,
            issues: vec![],
        }
    }

    pub fn analyze_file(&mut self, file_path: &Path, content: &str) {
        let nodes = self.parse_simplified(content);

        for node in nodes {
            self.analyze_node(&node, file_path);
        }
    }

    fn parse_simplified(&self, content: &str) -> Vec<AstNode> {
        // Simplified parsing for demonstration
        // Real implementation would use syn crate
        let mut nodes = vec![];
        let lines: Vec<&str> = content.lines().collect();

        let mut i = 0;
        while i < lines.len() {
            let line = lines[i].trim();

            // Detect function definitions
            if line.starts_with("fn ") || line.starts_with("pub fn ") {
                let name = self.extract_function_name(line);
                let params = self.count_parameters(line);

                // Count body lines
                let body_start = i;
                let mut brace_count = 0;
                let mut body_lines = 0;

                for j in i..lines.len() {
                    brace_count += lines[j].matches('{').count();
                    brace_count -= lines[j].matches('}').count();
                    body_lines += 1;
                    if brace_count == 0 && j > i {
                        break;
                    }
                }

                nodes.push(AstNode::Function {
                    name,
                    params: (0..params).map(|p| format!("param{}", p)).collect(),
                    body_lines,
                    complexity: 1
                        + content[..].matches("if ").count()
                        + content.matches("match ").count(),
                });
            }

            // Detect structs
            if line.starts_with("struct ") || line.starts_with("pub struct ") {
                let name = self.extract_struct_name(line);
                nodes.push(AstNode::Struct {
                    name,
                    fields: vec![],
                    methods: vec![],
                });
            }

            // Detect match expressions
            if line.contains("match ") {
                let arms = self.count_match_arms(&lines[i..]);
                nodes.push(AstNode::Match { arms, line: i + 1 });
            }

            // Detect clones
            if line.contains(".clone()") {
                // Simple heuristic: clone after reference might be unnecessary
                let unnecessary = line.contains("&") && line.contains(".clone()");
                nodes.push(AstNode::Clone {
                    line: i + 1,
                    unnecessary,
                });
            }

            // Detect string operations
            if line.contains("+ \"") || line.contains("\" +") {
                nodes.push(AstNode::StringOp {
                    kind: StringOpKind::Concatenation,
                    line: i + 1,
                });
            }

            i += 1;
        }

        nodes
    }

    fn extract_function_name(&self, line: &str) -> String {
        let parts: Vec<&str> = line.split_whitespace().collect();
        for (i, part) in parts.iter().enumerate() {
            if *part == "fn" && i + 1 < parts.len() {
                let name = parts[i + 1];
                return name.split('(').next().unwrap_or(name).to_string();
            }
        }
        "unknown".into()
    }

    fn extract_struct_name(&self, line: &str) -> String {
        let parts: Vec<&str> = line.split_whitespace().collect();
        for (i, part) in parts.iter().enumerate() {
            if *part == "struct" && i + 1 < parts.len() {
                let name = parts[i + 1];
                return name.trim_matches(|c| c == '{' || c == '<').to_string();
            }
        }
        "unknown".into()
    }

    fn count_parameters(&self, line: &str) -> usize {
        if let Some(start) = line.find('(') {
            if let Some(end) = line.find(')') {
                let params = &line[start + 1..end];
                if params.trim().is_empty() {
                    return 0;
                }
                return params.split(',').count();
            }
        }
        0
    }

    fn count_match_arms(&self, lines: &[&str]) -> usize {
        let mut arms = 0;
        let mut brace_count = 0;

        for line in lines {
            brace_count += line.matches('{').count();
            brace_count -= line.matches('}').count();

            if line.contains("=>") {
                arms += 1;
            }

            if brace_count == 0 && arms > 0 {
                break;
            }
        }

        arms
    }

    fn analyze_node(&mut self, node: &AstNode, file_path: &Path) {
        match node {
            AstNode::Function {
                name,
                params,
                body_lines,
                complexity,
            } => {
                // Check function length
                if *body_lines > self.config.max_function_lines {
                    let mut issue = CodeIssue::new(
                        CodeSmell::LongFunction,
                        file_path.to_path_buf(),
                        1,
                        *body_lines,
                    )
                    .with_description(&format!(
                        "Function '{}' has {} lines (max: {})",
                        name, body_lines, self.config.max_function_lines
                    ));

                    issue = issue.with_refactoring(RefactoringTechnique::ExtractFunction {
                        original_lines: (1, *body_lines),
                        suggested_name: format!("{}_helper", name),
                    });

                    self.issues.push(issue);
                }

                // Check parameter count
                if params.len() > self.config.max_parameters {
                    let mut issue =
                        CodeIssue::new(CodeSmell::LongParameterList, file_path.to_path_buf(), 1, 1)
                            .with_description(&format!(
                                "Function '{}' has {} parameters (max: {})",
                                name,
                                params.len(),
                                self.config.max_parameters
                            ));

                    issue =
                        issue.with_refactoring(RefactoringTechnique::IntroduceParameterObject {
                            parameters: params.clone(),
                            suggested_name: format!("{}Params", name),
                        });

                    self.issues.push(issue);
                }

                // Check cyclomatic complexity
                if *complexity > self.config.max_cyclomatic_complexity {
                    self.issues.push(
                        CodeIssue::new(
                            CodeSmell::ComplexConditional,
                            file_path.to_path_buf(),
                            1,
                            *body_lines,
                        )
                        .with_description(&format!(
                            "Function '{}' has complexity {} (max: {})",
                            name, complexity, self.config.max_cyclomatic_complexity
                        )),
                    );
                }
            }

            AstNode::Struct {
                name,
                fields,
                methods,
            } => {
                if fields.len() > self.config.max_struct_fields {
                    self.issues.push(
                        CodeIssue::new(CodeSmell::GodObject, file_path.to_path_buf(), 1, 1)
                            .with_description(&format!(
                                "Struct '{}' has {} fields (max: {})",
                                name,
                                fields.len(),
                                self.config.max_struct_fields
                            ))
                            .with_refactoring(RefactoringTechnique::ExtractStruct {
                                fields: fields.clone(),
                                suggested_name: format!("{}Data", name),
                            }),
                    );
                }

                if methods.len() > self.config.max_struct_methods {
                    self.issues.push(
                        CodeIssue::new(CodeSmell::GodObject, file_path.to_path_buf(), 1, 1)
                            .with_description(&format!(
                                "Struct '{}' has {} methods (max: {})",
                                name,
                                methods.len(),
                                self.config.max_struct_methods
                            )),
                    );
                }
            }

            AstNode::Match { arms, line } => {
                if *arms > self.config.max_match_arms {
                    self.issues.push(
                        CodeIssue::new(
                            CodeSmell::LargeMatch,
                            file_path.to_path_buf(),
                            *line,
                            *line,
                        )
                        .with_description(&format!(
                            "Match expression has {} arms (max: {})",
                            arms, self.config.max_match_arms
                        ))
                        .with_refactoring(
                            RefactoringTechnique::ReplaceConditionalWithPolymorphism {
                                match_location: *line,
                            },
                        ),
                    );
                }
            }

            AstNode::Clone { line, unnecessary } => {
                if *unnecessary && self.config.check_clones {
                    self.issues.push(
                        CodeIssue::new(
                            CodeSmell::UnnecessaryClone,
                            file_path.to_path_buf(),
                            *line,
                            *line,
                        )
                        .with_description("Potentially unnecessary clone"),
                    );
                }
            }

            AstNode::StringOp { kind, line } => {
                if self.config.check_string_ops {
                    match kind {
                        StringOpKind::Concatenation => {
                            self.issues.push(
                                CodeIssue::new(
                                    CodeSmell::InefficientString,
                                    file_path.to_path_buf(),
                                    *line,
                                    *line,
                                )
                                .with_description("String concatenation with + is inefficient; use format! or push_str"),
                            );
                        }
                        _ => {}
                    }
                }
            }

            _ => {}
        }
    }

    pub fn issues(&self) -> &[CodeIssue] {
        &self.issues
    }

    pub fn summary(&self) -> AnalysisSummary {
        let mut by_smell: HashMap<CodeSmell, usize> = HashMap::new();
        let mut by_severity: HashMap<SmellSeverity, usize> = HashMap::new();

        for issue in &self.issues {
            *by_smell.entry(issue.smell).or_insert(0) += 1;
            *by_severity.entry(issue.smell.severity()).or_insert(0) += 1;
        }

        AnalysisSummary {
            total_issues: self.issues.len(),
            by_smell,
            by_severity,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AnalysisSummary {
    pub total_issues: usize,
    pub by_smell: HashMap<CodeSmell, usize>,
    pub by_severity: HashMap<SmellSeverity, usize>,
}

/// Refactoring suggestion generator
pub struct RefactoringSuggester {
    suggestions: Vec<RefactoringSuggestion>,
}

#[derive(Debug, Clone)]
pub struct RefactoringSuggestion {
    pub issue: CodeIssue,
    pub technique: RefactoringTechnique,
    pub before_example: String,
    pub after_example: String,
    pub impact: RefactoringImpact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefactoringImpact {
    Low,
    Medium,
    High,
}

impl RefactoringSuggester {
    pub fn new() -> Self {
        Self {
            suggestions: vec![],
        }
    }

    pub fn suggest_for_issues(&mut self, issues: &[CodeIssue]) {
        for issue in issues {
            if let Some(suggestion) = self.create_suggestion(issue) {
                self.suggestions.push(suggestion);
            }
        }
    }

    fn create_suggestion(&self, issue: &CodeIssue) -> Option<RefactoringSuggestion> {
        let technique = issue.suggested_refactoring.clone()?;

        let (before, after) = self.generate_examples(&technique);

        Some(RefactoringSuggestion {
            issue: issue.clone(),
            technique,
            before_example: before,
            after_example: after,
            impact: self.estimate_impact(issue),
        })
    }

    fn generate_examples(&self, technique: &RefactoringTechnique) -> (String, String) {
        match technique {
            RefactoringTechnique::ExtractFunction { suggested_name, .. } => {
                let before = r#"fn process_data(data: &[u8]) {
    // 50+ lines of processing
    let result = data.iter().map(|x| x * 2).collect::<Vec<_>>();
    // more processing...
    // validation...
    // transformation...
}"#;
                let after = format!(
                    r#"fn process_data(data: &[u8]) {{
    let transformed = transform_data(data);
    let validated = validate_data(&transformed);
    {}(&validated);
}}

fn {}(data: &[u8]) {{
    // Extracted logic here
}}"#,
                    suggested_name, suggested_name
                );

                (before.into(), after)
            }

            RefactoringTechnique::IntroduceParameterObject { suggested_name, .. } => {
                let before = r#"fn create_user(
    name: &str,
    email: &str,
    age: u32,
    address: &str,
    phone: &str,
    role: &str,
) { ... }"#;
                let after = format!(
                    r#"struct {} {{
    name: String,
    email: String,
    age: u32,
    address: String,
    phone: String,
    role: String,
}}

fn create_user(params: {}) {{ ... }}"#,
                    suggested_name, suggested_name
                );

                (before.into(), after)
            }

            RefactoringTechnique::UseBuilderPattern { struct_name } => {
                let before = format!(
                    r#"let config = {}::new(
    "value1",
    "value2",
    42,
    true,
    Some("optional"),
);"#,
                    struct_name
                );
                let after = format!(
                    r#"let config = {}Builder::new()
    .field1("value1")
    .field2("value2")
    .count(42)
    .enabled(true)
    .optional("optional")
    .build();"#,
                    struct_name
                );

                (before, after)
            }

            RefactoringTechnique::ConvertToIterator { .. } => {
                let before = r#"let mut results = Vec::new();
for item in items {
    if item.is_valid() {
        results.push(item.transform());
    }
}"#;
                let after = r#"let results: Vec<_> = items
    .iter()
    .filter(|item| item.is_valid())
    .map(|item| item.transform())
    .collect();"#;

                (before.into(), after.into())
            }

            RefactoringTechnique::AddErrorContext { .. } => {
                let before = r#"fn read_config(path: &Path) -> Result<Config, Error> {
    let content = fs::read_to_string(path)?;
    let config: Config = serde_json::from_str(&content)?;
    Ok(config)
}"#;
                let after = r#"fn read_config(path: &Path) -> Result<Config, Error> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read config from {:?}", path))?;
    let config: Config = serde_json::from_str(&content)
        .with_context(|| "Failed to parse config JSON")?;
    Ok(config)
}"#;

                (before.into(), after.into())
            }

            _ => ("// Before".into(), "// After".into()),
        }
    }

    fn estimate_impact(&self, issue: &CodeIssue) -> RefactoringImpact {
        match issue.smell.severity() {
            SmellSeverity::High => RefactoringImpact::High,
            SmellSeverity::Medium => RefactoringImpact::Medium,
            SmellSeverity::Low => RefactoringImpact::Low,
        }
    }

    pub fn suggestions(&self) -> &[RefactoringSuggestion] {
        &self.suggestions
    }
}

/// Code metrics calculator
#[derive(Debug, Clone, Default)]
pub struct CodeMetrics {
    pub lines_of_code: usize,
    pub lines_of_comments: usize,
    pub blank_lines: usize,
    pub function_count: usize,
    pub struct_count: usize,
    pub enum_count: usize,
    pub trait_count: usize,
    pub impl_count: usize,
    pub test_count: usize,
    pub unsafe_count: usize,
    pub average_function_length: f64,
    pub max_function_length: usize,
    pub cyclomatic_complexity: usize,
}

impl CodeMetrics {
    pub fn calculate(content: &str) -> Self {
        let lines: Vec<&str> = content.lines().collect();
        let mut metrics = CodeMetrics::default();

        let mut in_comment = false;
        let mut function_lengths: Vec<usize> = vec![];
        let mut current_function_length = 0;
        let mut in_function = false;
        let mut brace_depth = 0;

        for line in &lines {
            let trimmed = line.trim();

            // Count line types
            if trimmed.is_empty() {
                metrics.blank_lines += 1;
            } else if trimmed.starts_with("//") || trimmed.starts_with("/*") || in_comment {
                metrics.lines_of_comments += 1;
                if trimmed.contains("/*") && !trimmed.contains("*/") {
                    in_comment = true;
                }
                if trimmed.contains("*/") {
                    in_comment = false;
                }
            } else {
                metrics.lines_of_code += 1;
            }

            // Count definitions
            if trimmed.starts_with("fn ") || trimmed.starts_with("pub fn ") {
                metrics.function_count += 1;
                in_function = true;
                current_function_length = 0;
            }
            if trimmed.starts_with("struct ") || trimmed.starts_with("pub struct ") {
                metrics.struct_count += 1;
            }
            if trimmed.starts_with("enum ") || trimmed.starts_with("pub enum ") {
                metrics.enum_count += 1;
            }
            if trimmed.starts_with("trait ") || trimmed.starts_with("pub trait ") {
                metrics.trait_count += 1;
            }
            if trimmed.starts_with("impl ") {
                metrics.impl_count += 1;
            }
            if trimmed.contains("#[test]") || trimmed.contains("#[cfg(test)]") {
                metrics.test_count += 1;
            }
            if trimmed.contains("unsafe ") {
                metrics.unsafe_count += 1;
            }

            // Track function length
            if in_function {
                current_function_length += 1;
                brace_depth += line.matches('{').count();
                brace_depth -= line.matches('}').count();

                if brace_depth == 0 {
                    function_lengths.push(current_function_length);
                    in_function = false;
                }
            }

            // Count complexity indicators
            if trimmed.starts_with("if ") || trimmed.starts_with("else if ") {
                metrics.cyclomatic_complexity += 1;
            }
            if trimmed.contains("match ") {
                metrics.cyclomatic_complexity += 1;
            }
            if trimmed.contains("for ") || trimmed.contains("while ") {
                metrics.cyclomatic_complexity += 1;
            }
            if trimmed.contains("&&") || trimmed.contains("||") {
                metrics.cyclomatic_complexity += 1;
            }
        }

        if !function_lengths.is_empty() {
            metrics.average_function_length =
                function_lengths.iter().sum::<usize>() as f64 / function_lengths.len() as f64;
            metrics.max_function_length = *function_lengths.iter().max().unwrap_or(&0);
        }

        metrics
    }

    pub fn health_score(&self) -> f64 {
        let mut score = 100.0;

        // Penalize long functions
        if self.average_function_length > 30.0 {
            score -= (self.average_function_length - 30.0) * 0.5;
        }

        // Penalize high complexity
        if self.cyclomatic_complexity > 50 {
            score -= (self.cyclomatic_complexity - 50) as f64 * 0.2;
        }

        // Penalize too many unsafe blocks
        if self.unsafe_count > 5 {
            score -= (self.unsafe_count - 5) as f64 * 2.0;
        }

        // Bonus for tests
        let test_ratio = if self.function_count > 0 {
            self.test_count as f64 / self.function_count as f64
        } else {
            0.0
        };
        score += test_ratio * 10.0;

        score.max(0.0).min(100.0)
    }
}

fn main() {
    println!("Code Refactoring Tools\n");

    // Sample code for analysis
    let sample_code = r#"
pub fn process_user_data(
    name: &str,
    email: &str,
    age: u32,
    address: &str,
    phone: &str,
    preferences: &HashMap<String, String>,
) -> Result<User, Error> {
    // Validate name
    if name.is_empty() {
        return Err(Error::InvalidName);
    }

    // Validate email
    if !email.contains('@') {
        return Err(Error::InvalidEmail);
    }

    // Validate age
    if age < 18 || age > 120 {
        return Err(Error::InvalidAge);
    }

    // Create user
    let user = User {
        name: name.to_string(),
        email: email.to_string(),
        age,
        address: address.to_string(),
        phone: phone.to_string(),
    };

    // Process preferences
    for (key, value) in preferences {
        match key.as_str() {
            "theme" => user.set_theme(value),
            "language" => user.set_language(value),
            "timezone" => user.set_timezone(value),
            "notifications" => user.set_notifications(value),
            "privacy" => user.set_privacy(value),
            "marketing" => user.set_marketing(value),
            "newsletter" => user.set_newsletter(value),
            "updates" => user.set_updates(value),
            "analytics" => user.set_analytics(value),
            "cookies" => user.set_cookies(value),
            "sharing" => user.set_sharing(value),
            _ => {},
        }
    }

    Ok(user)
}

fn concatenate_names(first: &str, last: &str) -> String {
    first.to_string() + " " + last
}

fn clone_example(data: &Vec<String>) {
    let cloned = data.clone();
    // Use cloned...
}
"#;

    // Run analysis
    let config = AnalysisConfig::default();
    let mut analyzer = CodeAnalyzer::new(config);
    analyzer.analyze_file(Path::new("sample.rs"), sample_code);

    println!("=== Code Analysis Results ===\n");

    let issues = analyzer.issues();
    if issues.is_empty() {
        println!("No issues found!");
    } else {
        for issue in issues {
            println!(
                "[{:?}] {} (lines {}-{})",
                issue.smell.severity(),
                issue.description,
                issue.line_start,
                issue.line_end
            );

            if let Some(ref refactoring) = issue.suggested_refactoring {
                println!("  Suggested: {}", refactoring.name());
            }
        }
    }

    // Summary
    let summary = analyzer.summary();
    println!("\n=== Summary ===");
    println!("Total issues: {}", summary.total_issues);
    println!("By severity:");
    for (severity, count) in &summary.by_severity {
        println!("  {:?}: {}", severity, count);
    }

    // Code metrics
    println!("\n=== Code Metrics ===");
    let metrics = CodeMetrics::calculate(sample_code);
    println!("Lines of code: {}", metrics.lines_of_code);
    println!("Lines of comments: {}", metrics.lines_of_comments);
    println!("Functions: {}", metrics.function_count);
    println!(
        "Avg function length: {:.1}",
        metrics.average_function_length
    );
    println!("Cyclomatic complexity: {}", metrics.cyclomatic_complexity);
    println!("Health score: {:.1}/100", metrics.health_score());

    // Generate refactoring suggestions
    println!("\n=== Refactoring Suggestions ===");
    let mut suggester = RefactoringSuggester::new();
    suggester.suggest_for_issues(issues);

    for suggestion in suggester.suggestions() {
        println!("\n{}:", suggestion.technique.name());
        println!("Impact: {:?}", suggestion.impact);
        println!("\nBefore:\n{}", suggestion.before_example);
        println!("\nAfter:\n{}", suggestion.after_example);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_code_smell_severity() {
        assert_eq!(CodeSmell::DuplicateCode.severity(), SmellSeverity::High);
        assert_eq!(CodeSmell::LongFunction.severity(), SmellSeverity::Medium);
        assert_eq!(CodeSmell::MagicNumbers.severity(), SmellSeverity::Low);
    }

    #[test]
    fn test_code_smell_description() {
        assert!(!CodeSmell::LongFunction.description().is_empty());
        assert!(!CodeSmell::DeadCode.description().is_empty());
    }

    #[test]
    fn test_refactoring_technique_name() {
        let technique = RefactoringTechnique::ExtractFunction {
            original_lines: (1, 10),
            suggested_name: "test".into(),
        };
        assert_eq!(technique.name(), "Extract Function");
    }

    #[test]
    fn test_code_issue_creation() {
        let issue = CodeIssue::new(CodeSmell::LongFunction, PathBuf::from("test.rs"), 1, 100);

        assert_eq!(issue.smell, CodeSmell::LongFunction);
        assert_eq!(issue.line_start, 1);
        assert_eq!(issue.line_end, 100);
    }

    #[test]
    fn test_analysis_config_default() {
        let config = AnalysisConfig::default();
        assert_eq!(config.max_function_lines, 50);
        assert_eq!(config.max_parameters, 5);
    }

    #[test]
    fn test_code_analyzer_creation() {
        let config = AnalysisConfig::default();
        let analyzer = CodeAnalyzer::new(config);
        assert!(analyzer.issues().is_empty());
    }

    #[test]
    fn test_code_metrics_simple() {
        let code = "fn main() {\n    println!(\"Hello\");\n}\n";
        let metrics = CodeMetrics::calculate(code);
        assert_eq!(metrics.function_count, 1);
        assert!(metrics.lines_of_code > 0);
    }

    #[test]
    fn test_code_metrics_with_comments() {
        let code = "// Comment\nfn main() {}\n";
        let metrics = CodeMetrics::calculate(code);
        assert_eq!(metrics.lines_of_comments, 1);
    }

    #[test]
    fn test_code_metrics_health_score() {
        let metrics = CodeMetrics::default();
        let score = metrics.health_score();
        assert!(score >= 0.0 && score <= 100.0);
    }

    #[test]
    fn test_refactoring_suggester() {
        let suggester = RefactoringSuggester::new();
        assert!(suggester.suggestions().is_empty());
    }

    #[test]
    fn test_smell_severity_ordering() {
        assert!(SmellSeverity::Low < SmellSeverity::Medium);
        assert!(SmellSeverity::Medium < SmellSeverity::High);
    }

    #[test]
    fn test_refactoring_impact() {
        assert!(matches!(RefactoringImpact::Low, RefactoringImpact::Low));
        assert!(matches!(RefactoringImpact::High, RefactoringImpact::High));
    }
}
