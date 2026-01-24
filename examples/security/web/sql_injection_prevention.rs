//! SQL Injection Prevention
//!
//! Comprehensive SQL injection prevention with parameterized queries,
//! query builders, input validation, and detection mechanisms.

use std::collections::HashMap;

/// SQL parameter types
#[derive(Debug, Clone)]
pub enum SqlParam {
    String(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    Null,
    Bytes(Vec<u8>),
}

impl SqlParam {
    /// Escape string for SQL (fallback - prefer parameterized queries)
    pub fn escape_string(s: &str) -> String {
        let mut escaped = String::with_capacity(s.len() * 2);
        for ch in s.chars() {
            match ch {
                '\'' => escaped.push_str("''"),
                '\\' => escaped.push_str("\\\\"),
                '\0' => escaped.push_str("\\0"),
                '\n' => escaped.push_str("\\n"),
                '\r' => escaped.push_str("\\r"),
                '\x1a' => escaped.push_str("\\Z"),
                _ => escaped.push(ch),
            }
        }
        escaped
    }
}

/// Parameterized query builder
#[derive(Debug, Clone)]
pub struct ParameterizedQuery {
    sql: String,
    params: Vec<SqlParam>,
    param_count: usize,
}

impl ParameterizedQuery {
    pub fn new(sql: &str) -> Self {
        Self {
            sql: sql.to_string(),
            params: Vec::new(),
            param_count: 0,
        }
    }

    /// Add a string parameter
    pub fn bind_string(mut self, value: &str) -> Self {
        self.params.push(SqlParam::String(value.to_string()));
        self.param_count += 1;
        self
    }

    /// Add an integer parameter
    pub fn bind_int(mut self, value: i64) -> Self {
        self.params.push(SqlParam::Integer(value));
        self.param_count += 1;
        self
    }

    /// Add a float parameter
    pub fn bind_float(mut self, value: f64) -> Self {
        self.params.push(SqlParam::Float(value));
        self.param_count += 1;
        self
    }

    /// Add a boolean parameter
    pub fn bind_bool(mut self, value: bool) -> Self {
        self.params.push(SqlParam::Boolean(value));
        self.param_count += 1;
        self
    }

    /// Add a null parameter
    pub fn bind_null(mut self) -> Self {
        self.params.push(SqlParam::Null);
        self.param_count += 1;
        self
    }

    /// Get the SQL string
    pub fn sql(&self) -> &str {
        &self.sql
    }

    /// Get the parameters
    pub fn params(&self) -> &[SqlParam] {
        &self.params
    }

    /// Validate that parameter count matches placeholders
    pub fn validate(&self) -> Result<(), SqlError> {
        let placeholder_count = self.sql.matches('?').count() + self.sql.matches("$").count();

        if self.param_count != placeholder_count {
            return Err(SqlError::ParameterMismatch {
                expected: placeholder_count,
                got: self.param_count,
            });
        }

        Ok(())
    }
}

/// SQL error types
#[derive(Debug)]
pub enum SqlError {
    ParameterMismatch { expected: usize, got: usize },
    InjectionDetected { pattern: String, input: String },
    InvalidIdentifier(String),
    UnsafeOperation(String),
}

impl std::fmt::Display for SqlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SqlError::ParameterMismatch { expected, got } => {
                write!(
                    f,
                    "Parameter count mismatch: expected {}, got {}",
                    expected, got
                )
            }
            SqlError::InjectionDetected { pattern, input } => {
                write!(
                    f,
                    "SQL injection detected: pattern '{}' in '{}'",
                    pattern, input
                )
            }
            SqlError::InvalidIdentifier(id) => {
                write!(f, "Invalid SQL identifier: {}", id)
            }
            SqlError::UnsafeOperation(op) => {
                write!(f, "Unsafe SQL operation: {}", op)
            }
        }
    }
}

impl std::error::Error for SqlError {}

/// Safe query builder with type-safe operations
#[derive(Debug, Clone)]
pub struct QueryBuilder {
    table: String,
    select_columns: Vec<String>,
    where_clauses: Vec<String>,
    params: Vec<SqlParam>,
    order_by: Option<(String, bool)>,
    limit: Option<usize>,
    offset: Option<usize>,
}

impl QueryBuilder {
    pub fn select(table: &str) -> Result<Self, SqlError> {
        let table = Self::validate_identifier(table)?;
        Ok(Self {
            table,
            select_columns: Vec::new(),
            where_clauses: Vec::new(),
            params: Vec::new(),
            order_by: None,
            limit: None,
            offset: None,
        })
    }

    /// Validate SQL identifier (table/column names)
    fn validate_identifier(name: &str) -> Result<String, SqlError> {
        // Only allow alphanumeric and underscore
        if name.is_empty() {
            return Err(SqlError::InvalidIdentifier("empty identifier".to_string()));
        }

        for ch in name.chars() {
            if !ch.is_alphanumeric() && ch != '_' {
                return Err(SqlError::InvalidIdentifier(name.to_string()));
            }
        }

        // Check for SQL keywords that might be dangerous
        let lower = name.to_lowercase();
        let dangerous_keywords = ["drop", "truncate", "delete", "alter", "create", "exec"];
        for keyword in &dangerous_keywords {
            if lower == *keyword {
                return Err(SqlError::InvalidIdentifier(format!(
                    "'{}' is a reserved keyword",
                    name
                )));
            }
        }

        Ok(name.to_string())
    }

    /// Add columns to select
    pub fn columns(mut self, cols: &[&str]) -> Result<Self, SqlError> {
        for col in cols {
            let validated = Self::validate_identifier(col)?;
            self.select_columns.push(validated);
        }
        Ok(self)
    }

    /// Add WHERE clause with equals condition
    pub fn where_eq(mut self, column: &str, value: SqlParam) -> Result<Self, SqlError> {
        let column = Self::validate_identifier(column)?;
        self.where_clauses.push(format!("{} = ?", column));
        self.params.push(value);
        Ok(self)
    }

    /// Add WHERE clause with LIKE condition
    pub fn where_like(mut self, column: &str, pattern: &str) -> Result<Self, SqlError> {
        let column = Self::validate_identifier(column)?;

        // Escape LIKE special characters
        let safe_pattern = pattern.replace('%', "\\%").replace('_', "\\_");

        self.where_clauses.push(format!("{} LIKE ?", column));
        self.params.push(SqlParam::String(safe_pattern));
        Ok(self)
    }

    /// Add WHERE clause with IN condition
    pub fn where_in(mut self, column: &str, values: Vec<SqlParam>) -> Result<Self, SqlError> {
        let column = Self::validate_identifier(column)?;

        if values.is_empty() {
            return Err(SqlError::UnsafeOperation(
                "IN clause with empty values".to_string(),
            ));
        }

        let placeholders: Vec<&str> = values.iter().map(|_| "?").collect();
        self.where_clauses
            .push(format!("{} IN ({})", column, placeholders.join(", ")));
        self.params.extend(values);
        Ok(self)
    }

    /// Add WHERE clause with comparison
    pub fn where_cmp(
        mut self,
        column: &str,
        op: ComparisonOp,
        value: SqlParam,
    ) -> Result<Self, SqlError> {
        let column = Self::validate_identifier(column)?;
        self.where_clauses
            .push(format!("{} {} ?", column, op.as_str()));
        self.params.push(value);
        Ok(self)
    }

    /// Add ORDER BY clause
    pub fn order_by(mut self, column: &str, ascending: bool) -> Result<Self, SqlError> {
        let column = Self::validate_identifier(column)?;
        self.order_by = Some((column, ascending));
        Ok(self)
    }

    /// Add LIMIT clause
    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Add OFFSET clause
    pub fn offset(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }

    /// Build the query
    pub fn build(self) -> ParameterizedQuery {
        let mut sql = String::new();

        // SELECT clause
        let columns = if self.select_columns.is_empty() {
            "*".to_string()
        } else {
            self.select_columns.join(", ")
        };
        sql.push_str(&format!("SELECT {} FROM {}", columns, self.table));

        // WHERE clause
        if !self.where_clauses.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&self.where_clauses.join(" AND "));
        }

        // ORDER BY clause
        if let Some((column, ascending)) = self.order_by {
            let direction = if ascending { "ASC" } else { "DESC" };
            sql.push_str(&format!(" ORDER BY {} {}", column, direction));
        }

        // LIMIT clause
        if let Some(limit) = self.limit {
            sql.push_str(&format!(" LIMIT {}", limit));
        }

        // OFFSET clause
        if let Some(offset) = self.offset {
            sql.push_str(&format!(" OFFSET {}", offset));
        }

        ParameterizedQuery {
            sql,
            params: self.params,
            param_count: 0,
        }
    }
}

/// Comparison operators
#[derive(Debug, Clone, Copy)]
pub enum ComparisonOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl ComparisonOp {
    pub fn as_str(&self) -> &'static str {
        match self {
            ComparisonOp::Eq => "=",
            ComparisonOp::Ne => "<>",
            ComparisonOp::Lt => "<",
            ComparisonOp::Le => "<=",
            ComparisonOp::Gt => ">",
            ComparisonOp::Ge => ">=",
        }
    }
}

/// SQL injection detector
#[derive(Debug)]
pub struct SqlInjectionDetector {
    patterns: Vec<InjectionPattern>,
}

#[derive(Debug)]
struct InjectionPattern {
    name: &'static str,
    pattern: &'static str,
    severity: Severity,
}

#[derive(Debug, Clone, Copy)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Default for SqlInjectionDetector {
    fn default() -> Self {
        Self {
            patterns: vec![
                InjectionPattern {
                    name: "Union-based injection",
                    pattern: "union.*select",
                    severity: Severity::Critical,
                },
                InjectionPattern {
                    name: "Boolean-based injection",
                    pattern: r"'.*or.*'.*=",
                    severity: Severity::Critical,
                },
                InjectionPattern {
                    name: "Comment injection",
                    pattern: "--",
                    severity: Severity::High,
                },
                InjectionPattern {
                    name: "Multi-statement injection",
                    pattern: ";.*(?:drop|delete|truncate|alter)",
                    severity: Severity::Critical,
                },
                InjectionPattern {
                    name: "Stacked queries",
                    pattern: ";\\s*select",
                    severity: Severity::High,
                },
                InjectionPattern {
                    name: "Time-based injection",
                    pattern: "(?:sleep|waitfor|benchmark|pg_sleep)",
                    severity: Severity::High,
                },
                InjectionPattern {
                    name: "Error-based injection",
                    pattern: "(?:extractvalue|updatexml|xmltype)",
                    severity: Severity::High,
                },
                InjectionPattern {
                    name: "Blind injection - substring",
                    pattern: "(?:substring|substr|mid)\\s*\\(",
                    severity: Severity::Medium,
                },
                InjectionPattern {
                    name: "Information schema access",
                    pattern: "information_schema",
                    severity: Severity::High,
                },
                InjectionPattern {
                    name: "Hex encoding",
                    pattern: "0x[0-9a-fA-F]+",
                    severity: Severity::Medium,
                },
                InjectionPattern {
                    name: "Char encoding",
                    pattern: "char\\s*\\(.*\\d",
                    severity: Severity::Medium,
                },
                InjectionPattern {
                    name: "Quote manipulation",
                    pattern: r"'(\s*|\s+or\s+|\s+and\s+)'",
                    severity: Severity::High,
                },
            ],
        }
    }
}

impl SqlInjectionDetector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Detect SQL injection attempts in input
    pub fn detect(&self, input: &str) -> Vec<Detection> {
        let mut detections = Vec::new();
        let lower_input = input.to_lowercase();

        for pattern in &self.patterns {
            if self.matches_pattern(&lower_input, pattern.pattern) {
                detections.push(Detection {
                    pattern_name: pattern.name.to_string(),
                    matched_input: input.to_string(),
                    severity: pattern.severity,
                });
            }
        }

        detections
    }

    /// Simple pattern matching (in production, use regex crate)
    fn matches_pattern(&self, input: &str, pattern: &str) -> bool {
        // Simplified pattern matching for common cases
        if pattern.contains(".*") {
            let parts: Vec<&str> = pattern.split(".*").collect();
            if parts.len() == 2 {
                if let Some(first_pos) = input.find(parts[0]) {
                    let rest = &input[first_pos + parts[0].len()..];
                    return rest.contains(parts[1]);
                }
                return false;
            }
        }

        // Check for alternative patterns
        if pattern.contains("(?:") {
            let alternatives: Vec<&str> = pattern
                .trim_start_matches("(?:")
                .trim_end_matches(')')
                .split('|')
                .collect();
            return alternatives.iter().any(|alt| input.contains(alt));
        }

        input.contains(pattern)
    }

    /// Check if input is safe
    pub fn is_safe(&self, input: &str) -> bool {
        self.detect(input).is_empty()
    }
}

/// Detection result
#[derive(Debug)]
pub struct Detection {
    pub pattern_name: String,
    pub matched_input: String,
    pub severity: Severity,
}

/// Prepared statement simulator (for demonstration)
#[derive(Debug)]
pub struct PreparedStatement {
    name: String,
    sql: String,
    param_types: Vec<ParamType>,
}

#[derive(Debug, Clone)]
pub enum ParamType {
    Text,
    Integer,
    Real,
    Blob,
}

impl PreparedStatement {
    pub fn prepare(name: &str, sql: &str) -> Result<Self, SqlError> {
        // Count parameter placeholders
        let param_count = sql.matches('?').count();
        let param_types = vec![ParamType::Text; param_count];

        Ok(Self {
            name: name.to_string(),
            sql: sql.to_string(),
            param_types,
        })
    }

    /// Set parameter types for validation
    pub fn with_types(mut self, types: &[ParamType]) -> Result<Self, SqlError> {
        if types.len() != self.param_types.len() {
            return Err(SqlError::ParameterMismatch {
                expected: self.param_types.len(),
                got: types.len(),
            });
        }
        self.param_types = types.to_vec();
        Ok(self)
    }

    /// Execute with parameters
    pub fn execute(&self, params: &[SqlParam]) -> Result<ExecutionPlan, SqlError> {
        if params.len() != self.param_types.len() {
            return Err(SqlError::ParameterMismatch {
                expected: self.param_types.len(),
                got: params.len(),
            });
        }

        // Validate parameter types
        for (i, (param, expected_type)) in params.iter().zip(&self.param_types).enumerate() {
            if !self.type_matches(param, expected_type) {
                return Err(SqlError::UnsafeOperation(format!(
                    "Parameter {} type mismatch",
                    i
                )));
            }
        }

        Ok(ExecutionPlan {
            statement_name: self.name.clone(),
            sql: self.sql.clone(),
            bound_params: params.to_vec(),
        })
    }

    fn type_matches(&self, param: &SqlParam, expected: &ParamType) -> bool {
        match (param, expected) {
            (SqlParam::String(_), ParamType::Text) => true,
            (SqlParam::Integer(_), ParamType::Integer) => true,
            (SqlParam::Float(_), ParamType::Real) => true,
            (SqlParam::Bytes(_), ParamType::Blob) => true,
            (SqlParam::Null, _) => true,
            (SqlParam::Boolean(_), ParamType::Integer) => true,
            _ => false,
        }
    }
}

/// Execution plan (simulated)
#[derive(Debug)]
pub struct ExecutionPlan {
    pub statement_name: String,
    pub sql: String,
    pub bound_params: Vec<SqlParam>,
}

fn main() {
    println!("=== SQL Injection Prevention Demo ===\n");

    // Parameterized Query
    println!("1. Parameterized Queries:");
    let query = ParameterizedQuery::new("SELECT * FROM users WHERE username = ? AND status = ?")
        .bind_string("john_doe")
        .bind_string("active");

    println!("   SQL: {}", query.sql());
    println!("   Params: {:?}", query.params());

    // Query Builder
    println!("\n2. Safe Query Builder:");
    let builder_query = QueryBuilder::select("users")
        .unwrap()
        .columns(&["id", "username", "email"])
        .unwrap()
        .where_eq("status", SqlParam::String("active".to_string()))
        .unwrap()
        .where_cmp(
            "created_at",
            ComparisonOp::Gt,
            SqlParam::String("2024-01-01".to_string()),
        )
        .unwrap()
        .order_by("username", true)
        .unwrap()
        .limit(10)
        .build();

    println!("   SQL: {}", builder_query.sql());

    // Invalid identifier detection
    println!("\n3. Invalid Identifier Detection:");
    let bad_table = QueryBuilder::select("users; DROP TABLE users; --");
    match bad_table {
        Ok(_) => println!("   ERROR: Should have failed!"),
        Err(e) => println!("   Blocked: {}", e),
    }

    // SQL Injection Detection
    println!("\n4. SQL Injection Detection:");
    let detector = SqlInjectionDetector::new();

    let test_inputs = [
        "john_doe",
        "' OR '1'='1",
        "1; DROP TABLE users; --",
        "1 UNION SELECT * FROM passwords",
        "admin'--",
        "1' AND SLEEP(5)--",
        "normal search term",
    ];

    for input in &test_inputs {
        let detections = detector.detect(input);
        if detections.is_empty() {
            println!("   '{}' - SAFE", input);
        } else {
            println!("   '{}' - DANGEROUS:", input);
            for d in &detections {
                println!("      - {:?}: {}", d.severity, d.pattern_name);
            }
        }
    }

    // Prepared Statement
    println!("\n5. Prepared Statements:");
    let stmt = PreparedStatement::prepare(
        "get_user_by_id",
        "SELECT * FROM users WHERE id = ? AND deleted = ?",
    )
    .unwrap()
    .with_types(&[ParamType::Integer, ParamType::Integer])
    .unwrap();

    match stmt.execute(&[SqlParam::Integer(42), SqlParam::Boolean(false)]) {
        Ok(plan) => {
            println!("   Statement: {}", plan.statement_name);
            println!("   SQL: {}", plan.sql);
            println!("   Params: {:?}", plan.bound_params);
        }
        Err(e) => println!("   Error: {}", e),
    }

    // String escaping (fallback)
    println!("\n6. String Escaping (fallback method):");
    let dangerous = "'; DROP TABLE users; --";
    let escaped = SqlParam::escape_string(dangerous);
    println!("   Original: {}", dangerous);
    println!("   Escaped: {}", escaped);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parameterized_query_binding() {
        let query = ParameterizedQuery::new("SELECT * FROM users WHERE id = ?").bind_int(42);

        assert!(query.sql().contains("?"));
        assert_eq!(query.params().len(), 1);
    }

    #[test]
    fn test_parameterized_query_validation() {
        let query =
            ParameterizedQuery::new("SELECT * FROM users WHERE id = ? AND name = ?").bind_int(42);

        assert!(query.validate().is_err());
    }

    #[test]
    fn test_query_builder_basic() {
        let query = QueryBuilder::select("users")
            .unwrap()
            .columns(&["id", "name"])
            .unwrap()
            .build();

        assert!(query.sql().contains("SELECT id, name FROM users"));
    }

    #[test]
    fn test_query_builder_where_clause() {
        let query = QueryBuilder::select("users")
            .unwrap()
            .where_eq("status", SqlParam::String("active".to_string()))
            .unwrap()
            .build();

        assert!(query.sql().contains("WHERE status = ?"));
    }

    #[test]
    fn test_query_builder_rejects_invalid_identifier() {
        let result = QueryBuilder::select("users; DROP TABLE users;");
        assert!(result.is_err());
    }

    #[test]
    fn test_query_builder_rejects_dangerous_keywords() {
        let result = QueryBuilder::select("users").unwrap().columns(&["drop"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_injection_detector_union() {
        let detector = SqlInjectionDetector::new();
        let detections = detector.detect("1 UNION SELECT * FROM users");
        assert!(!detections.is_empty());
    }

    #[test]
    fn test_injection_detector_boolean() {
        let detector = SqlInjectionDetector::new();
        let detections = detector.detect("' OR '1'='1");
        assert!(!detections.is_empty());
    }

    #[test]
    fn test_injection_detector_comment() {
        let detector = SqlInjectionDetector::new();
        let detections = detector.detect("admin'--");
        assert!(!detections.is_empty());
    }

    #[test]
    fn test_injection_detector_safe_input() {
        let detector = SqlInjectionDetector::new();
        assert!(detector.is_safe("normal_username"));
        assert!(detector.is_safe("john.doe@example.com"));
    }

    #[test]
    fn test_injection_detector_time_based() {
        let detector = SqlInjectionDetector::new();
        let detections = detector.detect("1; SLEEP(5)");
        assert!(!detections.is_empty());
    }

    #[test]
    fn test_prepared_statement_execute() {
        let stmt = PreparedStatement::prepare("test", "SELECT * FROM users WHERE id = ?")
            .unwrap()
            .with_types(&[ParamType::Integer])
            .unwrap();

        let result = stmt.execute(&[SqlParam::Integer(42)]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_prepared_statement_type_mismatch() {
        let stmt = PreparedStatement::prepare("test", "SELECT * FROM users WHERE id = ?")
            .unwrap()
            .with_types(&[ParamType::Integer])
            .unwrap();

        let result = stmt.execute(&[SqlParam::String("not_an_int".to_string())]);
        assert!(result.is_err());
    }

    #[test]
    fn test_prepared_statement_param_count_mismatch() {
        let stmt =
            PreparedStatement::prepare("test", "SELECT * FROM users WHERE id = ? AND name = ?")
                .unwrap();

        let result = stmt.execute(&[SqlParam::Integer(42)]);
        assert!(result.is_err());
    }

    #[test]
    fn test_string_escaping() {
        let escaped = SqlParam::escape_string("O'Brien");
        assert_eq!(escaped, "O''Brien");
    }

    #[test]
    fn test_string_escaping_backslash() {
        let escaped = SqlParam::escape_string("path\\to\\file");
        assert_eq!(escaped, "path\\\\to\\\\file");
    }

    #[test]
    fn test_query_builder_like_escaping() {
        let query = QueryBuilder::select("users")
            .unwrap()
            .where_like("name", "100%")
            .unwrap()
            .build();

        // Should escape the % character
        let params = query.params();
        if let SqlParam::String(s) = &params[0] {
            assert!(s.contains("\\%"));
        }
    }

    #[test]
    fn test_query_builder_in_clause() {
        let query = QueryBuilder::select("users")
            .unwrap()
            .where_in(
                "status",
                vec![
                    SqlParam::String("active".to_string()),
                    SqlParam::String("pending".to_string()),
                ],
            )
            .unwrap()
            .build();

        assert!(query.sql().contains("IN (?, ?)"));
    }

    #[test]
    fn test_query_builder_empty_in_clause() {
        let result = QueryBuilder::select("users")
            .unwrap()
            .where_in("status", vec![]);

        assert!(result.is_err());
    }
}
