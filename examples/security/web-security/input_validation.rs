//! Input Validation Patterns
//!
//! Demonstrates secure input validation to prevent injection attacks.

use regex::Regex;
use std::collections::HashSet;
use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum ValidationError {
    #[error("Field '{field}' is required")]
    Required { field: String },
    #[error("Field '{field}' must be at least {min} characters")]
    TooShort { field: String, min: usize },
    #[error("Field '{field}' must be at most {max} characters")]
    TooLong { field: String, max: usize },
    #[error("Field '{field}' contains invalid characters")]
    InvalidCharacters { field: String },
    #[error("Field '{field}' has invalid format")]
    InvalidFormat { field: String },
    #[error("Field '{field}' failed validation: {message}")]
    Custom { field: String, message: String },
}

/// Validation result collecting multiple errors
pub struct ValidationResult {
    errors: Vec<ValidationError>,
}

impl ValidationResult {
    pub fn new() -> Self {
        Self { errors: Vec::new() }
    }

    pub fn add_error(&mut self, error: ValidationError) {
        self.errors.push(error);
    }

    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }

    pub fn errors(&self) -> &[ValidationError] {
        &self.errors
    }

    pub fn into_result<T>(self, value: T) -> Result<T, Vec<ValidationError>> {
        if self.is_valid() {
            Ok(value)
        } else {
            Err(self.errors)
        }
    }
}

impl Default for ValidationResult {
    fn default() -> Self {
        Self::new()
    }
}

/// String validator with builder pattern
pub struct StringValidator<'a> {
    field: &'a str,
    value: &'a str,
    result: &'a mut ValidationResult,
}

impl<'a> StringValidator<'a> {
    pub fn new(field: &'a str, value: &'a str, result: &'a mut ValidationResult) -> Self {
        Self {
            field,
            value,
            result,
        }
    }

    pub fn required(self) -> Self {
        if self.value.is_empty() {
            self.result.add_error(ValidationError::Required {
                field: self.field.to_string(),
            });
        }
        self
    }

    pub fn min_length(self, min: usize) -> Self {
        if self.value.len() < min {
            self.result.add_error(ValidationError::TooShort {
                field: self.field.to_string(),
                min,
            });
        }
        self
    }

    pub fn max_length(self, max: usize) -> Self {
        if self.value.len() > max {
            self.result.add_error(ValidationError::TooLong {
                field: self.field.to_string(),
                max,
            });
        }
        self
    }

    pub fn alphanumeric(self) -> Self {
        if !self.value.chars().all(|c| c.is_alphanumeric()) {
            self.result.add_error(ValidationError::InvalidCharacters {
                field: self.field.to_string(),
            });
        }
        self
    }

    pub fn matches(self, pattern: &Regex) -> Self {
        if !pattern.is_match(self.value) {
            self.result.add_error(ValidationError::InvalidFormat {
                field: self.field.to_string(),
            });
        }
        self
    }

    pub fn no_sql_injection(self) -> Self {
        let dangerous_patterns = [
            "--",
            "/*",
            "*/",
            ";--",
            "';",
            "\";",
            "' OR ",
            "\" OR ",
            "' AND ",
            "\" AND ",
            "UNION SELECT",
            "DROP TABLE",
            "DELETE FROM",
            "INSERT INTO",
            "UPDATE ",
            "EXEC(",
        ];

        let upper = self.value.to_uppercase();
        for pattern in &dangerous_patterns {
            if upper.contains(pattern) {
                self.result.add_error(ValidationError::Custom {
                    field: self.field.to_string(),
                    message: "Potentially dangerous SQL pattern detected".to_string(),
                });
                break;
            }
        }
        self
    }

    pub fn no_xss(self) -> Self {
        let dangerous_patterns = [
            "<script",
            "</script>",
            "javascript:",
            "onerror=",
            "onload=",
            "onclick=",
            "onmouseover=",
            "onfocus=",
            "eval(",
            "document.cookie",
            "document.write",
        ];

        let lower = self.value.to_lowercase();
        for pattern in &dangerous_patterns {
            if lower.contains(pattern) {
                self.result.add_error(ValidationError::Custom {
                    field: self.field.to_string(),
                    message: "Potentially dangerous XSS pattern detected".to_string(),
                });
                break;
            }
        }
        self
    }

    pub fn custom<F>(self, predicate: F, message: &str) -> Self
    where
        F: FnOnce(&str) -> bool,
    {
        if !predicate(self.value) {
            self.result.add_error(ValidationError::Custom {
                field: self.field.to_string(),
                message: message.to_string(),
            });
        }
        self
    }
}

/// Common validation patterns
pub mod patterns {
    use super::*;
    use once_cell::sync::Lazy;

    pub static EMAIL: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap());

    pub static USERNAME: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"^[a-zA-Z][a-zA-Z0-9_-]{2,31}$").unwrap());

    pub static UUID: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$").unwrap()
    });

    pub static SLUG: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-z0-9]+(?:-[a-z0-9]+)*$").unwrap());

    pub static PHONE_US: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"^\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}$").unwrap()
    });
}

/// Sanitize HTML to prevent XSS
pub fn sanitize_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Sanitize for SQL (but prefer parameterized queries!)
pub fn escape_sql_string(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('\'', "\\'")
        .replace('"', "\\\"")
        .replace('\0', "\\0")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

/// Allowlist-based input validation
pub struct AllowlistValidator {
    allowed: HashSet<String>,
}

impl AllowlistValidator {
    pub fn new<I, S>(allowed: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            allowed: allowed.into_iter().map(Into::into).collect(),
        }
    }

    pub fn is_allowed(&self, value: &str) -> bool {
        self.allowed.contains(value)
    }

    pub fn validate(&self, value: &str) -> Result<&str, ValidationError> {
        if self.is_allowed(value) {
            Ok(value)
        } else {
            Err(ValidationError::Custom {
                field: "value".to_string(),
                message: "Value not in allowlist".to_string(),
            })
        }
    }
}

/// Example: User registration validation
pub struct UserRegistration {
    pub username: String,
    pub email: String,
    pub password: String,
}

impl UserRegistration {
    pub fn validate(&self) -> Result<(), Vec<ValidationError>> {
        let mut result = ValidationResult::new();

        StringValidator::new("username", &self.username, &mut result)
            .required()
            .min_length(3)
            .max_length(32)
            .matches(&patterns::USERNAME)
            .no_sql_injection();

        StringValidator::new("email", &self.email, &mut result)
            .required()
            .max_length(254)
            .matches(&patterns::EMAIL);

        StringValidator::new("password", &self.password, &mut result)
            .required()
            .min_length(8)
            .max_length(128)
            .custom(
                |p| p.chars().any(|c| c.is_uppercase()),
                "Must contain uppercase letter",
            )
            .custom(
                |p| p.chars().any(|c| c.is_lowercase()),
                "Must contain lowercase letter",
            )
            .custom(|p| p.chars().any(|c| c.is_numeric()), "Must contain number");

        result.into_result(())
    }
}

fn main() {
    println!("=== Input Validation Demo ===\n");

    // Valid registration
    let valid_user = UserRegistration {
        username: "john_doe".to_string(),
        email: "john@example.com".to_string(),
        password: "SecurePass123".to_string(),
    };

    match valid_user.validate() {
        Ok(()) => println!("Valid user registration!"),
        Err(errors) => {
            for e in errors {
                println!("Error: {}", e);
            }
        }
    }

    // Invalid registration
    println!("\n--- Invalid Registration ---");
    let invalid_user = UserRegistration {
        username: "ab".to_string(), // Too short
        email: "not-an-email".to_string(),
        password: "weak".to_string(),
    };

    match invalid_user.validate() {
        Ok(()) => println!("Should have failed!"),
        Err(errors) => {
            for e in &errors {
                println!("Error: {}", e);
            }
        }
    }

    // SQL injection attempt
    println!("\n--- SQL Injection Detection ---");
    let mut result = ValidationResult::new();
    StringValidator::new("search", "'; DROP TABLE users; --", &mut result).no_sql_injection();

    for e in result.errors() {
        println!("Detected: {}", e);
    }

    // XSS attempt
    println!("\n--- XSS Detection ---");
    let mut result = ValidationResult::new();
    StringValidator::new("comment", "<script>alert('xss')</script>", &mut result).no_xss();

    for e in result.errors() {
        println!("Detected: {}", e);
    }

    // HTML sanitization
    println!("\n--- HTML Sanitization ---");
    let malicious = "<script>alert('xss')</script>";
    let sanitized = sanitize_html(malicious);
    println!("Original: {}", malicious);
    println!("Sanitized: {}", sanitized);

    // Allowlist validation
    println!("\n--- Allowlist Validation ---");
    let roles = AllowlistValidator::new(["admin", "user", "guest"]);
    println!("'user' allowed: {}", roles.is_allowed("user"));
    println!("'superadmin' allowed: {}", roles.is_allowed("superadmin"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_email() {
        assert!(patterns::EMAIL.is_match("test@example.com"));
        assert!(patterns::EMAIL.is_match("user.name+tag@domain.co.uk"));
        assert!(!patterns::EMAIL.is_match("invalid-email"));
    }

    #[test]
    fn test_valid_username() {
        assert!(patterns::USERNAME.is_match("john_doe"));
        assert!(patterns::USERNAME.is_match("user123"));
        assert!(!patterns::USERNAME.is_match("1user")); // Can't start with number
        assert!(!patterns::USERNAME.is_match("ab")); // Too short
    }

    #[test]
    fn test_sql_injection_detection() {
        let mut result = ValidationResult::new();
        StringValidator::new("input", "'; DROP TABLE users; --", &mut result).no_sql_injection();
        assert!(!result.is_valid());
    }

    #[test]
    fn test_xss_detection() {
        let mut result = ValidationResult::new();
        StringValidator::new("input", "<script>alert(1)</script>", &mut result).no_xss();
        assert!(!result.is_valid());
    }

    #[test]
    fn test_html_sanitization() {
        let input = "<script>alert('xss')</script>";
        let output = sanitize_html(input);
        assert!(!output.contains('<'));
        assert!(!output.contains('>'));
    }

    #[test]
    fn test_allowlist() {
        let validator = AllowlistValidator::new(["a", "b", "c"]);
        assert!(validator.is_allowed("a"));
        assert!(!validator.is_allowed("d"));
    }
}
