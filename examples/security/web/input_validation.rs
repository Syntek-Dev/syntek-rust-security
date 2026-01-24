//! Input Validation Framework
//!
//! Comprehensive input validation with type-safe validators, sanitizers,
//! and custom validation rules for secure data handling.

use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;

/// Validation result
pub type ValidationResult<T> = Result<T, ValidationError>;

/// Validation error
#[derive(Debug, Clone)]
pub struct ValidationError {
    pub field: String,
    pub message: String,
    pub code: ErrorCode,
}

/// Error codes for validation failures
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    Required,
    InvalidFormat,
    TooShort,
    TooLong,
    OutOfRange,
    InvalidCharacters,
    Blacklisted,
    Custom,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for ValidationError {}

/// Input validator trait
pub trait Validator<T> {
    fn validate(&self, value: &T) -> ValidationResult<()>;
}

/// String validator with configurable rules
#[derive(Debug, Clone)]
pub struct StringValidator {
    field_name: String,
    min_length: Option<usize>,
    max_length: Option<usize>,
    pattern: Option<String>,
    required: bool,
    allowed_chars: Option<String>,
    blacklist: Vec<String>,
    trim_whitespace: bool,
}

impl StringValidator {
    pub fn new(field_name: &str) -> Self {
        Self {
            field_name: field_name.to_string(),
            min_length: None,
            max_length: None,
            pattern: None,
            required: false,
            allowed_chars: None,
            blacklist: Vec::new(),
            trim_whitespace: true,
        }
    }

    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }

    pub fn min_length(mut self, len: usize) -> Self {
        self.min_length = Some(len);
        self
    }

    pub fn max_length(mut self, len: usize) -> Self {
        self.max_length = Some(len);
        self
    }

    pub fn pattern(mut self, regex: &str) -> Self {
        self.pattern = Some(regex.to_string());
        self
    }

    pub fn allowed_chars(mut self, chars: &str) -> Self {
        self.allowed_chars = Some(chars.to_string());
        self
    }

    pub fn blacklist(mut self, items: &[&str]) -> Self {
        self.blacklist = items.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn no_trim(mut self) -> Self {
        self.trim_whitespace = false;
        self
    }
}

impl Validator<String> for StringValidator {
    fn validate(&self, value: &String) -> ValidationResult<()> {
        let value = if self.trim_whitespace {
            value.trim()
        } else {
            value.as_str()
        };

        // Required check
        if value.is_empty() {
            if self.required {
                return Err(ValidationError {
                    field: self.field_name.clone(),
                    message: "This field is required".to_string(),
                    code: ErrorCode::Required,
                });
            }
            return Ok(());
        }

        // Min length check
        if let Some(min) = self.min_length {
            if value.len() < min {
                return Err(ValidationError {
                    field: self.field_name.clone(),
                    message: format!("Must be at least {} characters", min),
                    code: ErrorCode::TooShort,
                });
            }
        }

        // Max length check
        if let Some(max) = self.max_length {
            if value.len() > max {
                return Err(ValidationError {
                    field: self.field_name.clone(),
                    message: format!("Must be at most {} characters", max),
                    code: ErrorCode::TooLong,
                });
            }
        }

        // Allowed characters check
        if let Some(ref allowed) = self.allowed_chars {
            for ch in value.chars() {
                if !allowed.contains(ch) {
                    return Err(ValidationError {
                        field: self.field_name.clone(),
                        message: format!("Contains invalid character: '{}'", ch),
                        code: ErrorCode::InvalidCharacters,
                    });
                }
            }
        }

        // Blacklist check
        let lower_value = value.to_lowercase();
        for blocked in &self.blacklist {
            if lower_value.contains(&blocked.to_lowercase()) {
                return Err(ValidationError {
                    field: self.field_name.clone(),
                    message: "Contains blocked content".to_string(),
                    code: ErrorCode::Blacklisted,
                });
            }
        }

        Ok(())
    }
}

/// Email validator
#[derive(Debug, Clone)]
pub struct EmailValidator {
    field_name: String,
    allowed_domains: Option<Vec<String>>,
    blocked_domains: Vec<String>,
}

impl EmailValidator {
    pub fn new(field_name: &str) -> Self {
        Self {
            field_name: field_name.to_string(),
            allowed_domains: None,
            blocked_domains: Vec::new(),
        }
    }

    pub fn allowed_domains(mut self, domains: &[&str]) -> Self {
        self.allowed_domains = Some(domains.iter().map(|s| s.to_string()).collect());
        self
    }

    pub fn blocked_domains(mut self, domains: &[&str]) -> Self {
        self.blocked_domains = domains.iter().map(|s| s.to_string()).collect();
        self
    }
}

impl Validator<String> for EmailValidator {
    fn validate(&self, value: &String) -> ValidationResult<()> {
        let value = value.trim().to_lowercase();

        if value.is_empty() {
            return Ok(());
        }

        // Basic email format check
        let parts: Vec<&str> = value.split('@').collect();
        if parts.len() != 2 {
            return Err(ValidationError {
                field: self.field_name.clone(),
                message: "Invalid email format".to_string(),
                code: ErrorCode::InvalidFormat,
            });
        }

        let (local, domain) = (parts[0], parts[1]);

        // Local part validation
        if local.is_empty() || local.len() > 64 {
            return Err(ValidationError {
                field: self.field_name.clone(),
                message: "Invalid email local part".to_string(),
                code: ErrorCode::InvalidFormat,
            });
        }

        // Domain validation
        if domain.is_empty() || !domain.contains('.') {
            return Err(ValidationError {
                field: self.field_name.clone(),
                message: "Invalid email domain".to_string(),
                code: ErrorCode::InvalidFormat,
            });
        }

        // Allowed domains check
        if let Some(ref allowed) = self.allowed_domains {
            if !allowed.iter().any(|d| domain.ends_with(d)) {
                return Err(ValidationError {
                    field: self.field_name.clone(),
                    message: "Email domain not allowed".to_string(),
                    code: ErrorCode::Blacklisted,
                });
            }
        }

        // Blocked domains check
        for blocked in &self.blocked_domains {
            if domain.ends_with(blocked) {
                return Err(ValidationError {
                    field: self.field_name.clone(),
                    message: "Email domain is blocked".to_string(),
                    code: ErrorCode::Blacklisted,
                });
            }
        }

        Ok(())
    }
}

/// Password validator with strength requirements
#[derive(Debug, Clone)]
pub struct PasswordValidator {
    field_name: String,
    min_length: usize,
    require_uppercase: bool,
    require_lowercase: bool,
    require_digit: bool,
    require_special: bool,
    common_passwords: Vec<String>,
}

impl PasswordValidator {
    pub fn new(field_name: &str) -> Self {
        Self {
            field_name: field_name.to_string(),
            min_length: 8,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: true,
            common_passwords: vec![
                "password".to_string(),
                "123456".to_string(),
                "qwerty".to_string(),
                "letmein".to_string(),
                "welcome".to_string(),
            ],
        }
    }

    pub fn min_length(mut self, len: usize) -> Self {
        self.min_length = len;
        self
    }

    pub fn require_uppercase(mut self, require: bool) -> Self {
        self.require_uppercase = require;
        self
    }

    pub fn require_lowercase(mut self, require: bool) -> Self {
        self.require_lowercase = require;
        self
    }

    pub fn require_digit(mut self, require: bool) -> Self {
        self.require_digit = require;
        self
    }

    pub fn require_special(mut self, require: bool) -> Self {
        self.require_special = require;
        self
    }

    pub fn common_passwords(mut self, passwords: &[&str]) -> Self {
        self.common_passwords = passwords.iter().map(|s| s.to_string()).collect();
        self
    }

    /// Calculate password strength (0-100)
    pub fn strength(&self, password: &str) -> u8 {
        let mut score = 0u8;

        // Length bonus
        score += (password.len().min(20) * 3) as u8;

        // Character type bonuses
        if password.chars().any(|c| c.is_uppercase()) {
            score += 10;
        }
        if password.chars().any(|c| c.is_lowercase()) {
            score += 10;
        }
        if password.chars().any(|c| c.is_ascii_digit()) {
            score += 10;
        }
        if password.chars().any(|c| !c.is_alphanumeric()) {
            score += 15;
        }

        // Variety bonus
        let unique_chars: std::collections::HashSet<char> = password.chars().collect();
        score += (unique_chars.len().min(10) * 2) as u8;

        score.min(100)
    }
}

impl Validator<String> for PasswordValidator {
    fn validate(&self, value: &String) -> ValidationResult<()> {
        if value.len() < self.min_length {
            return Err(ValidationError {
                field: self.field_name.clone(),
                message: format!("Password must be at least {} characters", self.min_length),
                code: ErrorCode::TooShort,
            });
        }

        if self.require_uppercase && !value.chars().any(|c| c.is_uppercase()) {
            return Err(ValidationError {
                field: self.field_name.clone(),
                message: "Password must contain at least one uppercase letter".to_string(),
                code: ErrorCode::InvalidFormat,
            });
        }

        if self.require_lowercase && !value.chars().any(|c| c.is_lowercase()) {
            return Err(ValidationError {
                field: self.field_name.clone(),
                message: "Password must contain at least one lowercase letter".to_string(),
                code: ErrorCode::InvalidFormat,
            });
        }

        if self.require_digit && !value.chars().any(|c| c.is_ascii_digit()) {
            return Err(ValidationError {
                field: self.field_name.clone(),
                message: "Password must contain at least one digit".to_string(),
                code: ErrorCode::InvalidFormat,
            });
        }

        if self.require_special && !value.chars().any(|c| !c.is_alphanumeric()) {
            return Err(ValidationError {
                field: self.field_name.clone(),
                message: "Password must contain at least one special character".to_string(),
                code: ErrorCode::InvalidFormat,
            });
        }

        // Common password check
        let lower_value = value.to_lowercase();
        for common in &self.common_passwords {
            if lower_value.contains(common) {
                return Err(ValidationError {
                    field: self.field_name.clone(),
                    message: "Password is too common".to_string(),
                    code: ErrorCode::Blacklisted,
                });
            }
        }

        Ok(())
    }
}

/// IP address validator
#[derive(Debug, Clone)]
pub struct IpValidator {
    field_name: String,
    allow_ipv4: bool,
    allow_ipv6: bool,
    allow_private: bool,
    allow_loopback: bool,
    blocked_ranges: Vec<(IpAddr, u8)>,
}

impl IpValidator {
    pub fn new(field_name: &str) -> Self {
        Self {
            field_name: field_name.to_string(),
            allow_ipv4: true,
            allow_ipv6: true,
            allow_private: true,
            allow_loopback: false,
            blocked_ranges: Vec::new(),
        }
    }

    pub fn ipv4_only(mut self) -> Self {
        self.allow_ipv6 = false;
        self
    }

    pub fn ipv6_only(mut self) -> Self {
        self.allow_ipv4 = false;
        self
    }

    pub fn no_private(mut self) -> Self {
        self.allow_private = false;
        self
    }

    pub fn allow_loopback(mut self) -> Self {
        self.allow_loopback = true;
        self
    }

    fn is_private_ipv4(ip: &std::net::Ipv4Addr) -> bool {
        ip.is_private() || ip.is_link_local()
    }
}

impl Validator<String> for IpValidator {
    fn validate(&self, value: &String) -> ValidationResult<()> {
        let value = value.trim();

        if value.is_empty() {
            return Ok(());
        }

        let ip: IpAddr = IpAddr::from_str(value).map_err(|_| ValidationError {
            field: self.field_name.clone(),
            message: "Invalid IP address format".to_string(),
            code: ErrorCode::InvalidFormat,
        })?;

        match ip {
            IpAddr::V4(ipv4) => {
                if !self.allow_ipv4 {
                    return Err(ValidationError {
                        field: self.field_name.clone(),
                        message: "IPv4 addresses not allowed".to_string(),
                        code: ErrorCode::InvalidFormat,
                    });
                }

                if !self.allow_private && Self::is_private_ipv4(&ipv4) {
                    return Err(ValidationError {
                        field: self.field_name.clone(),
                        message: "Private IP addresses not allowed".to_string(),
                        code: ErrorCode::Blacklisted,
                    });
                }

                if !self.allow_loopback && ipv4.is_loopback() {
                    return Err(ValidationError {
                        field: self.field_name.clone(),
                        message: "Loopback addresses not allowed".to_string(),
                        code: ErrorCode::Blacklisted,
                    });
                }
            }
            IpAddr::V6(ipv6) => {
                if !self.allow_ipv6 {
                    return Err(ValidationError {
                        field: self.field_name.clone(),
                        message: "IPv6 addresses not allowed".to_string(),
                        code: ErrorCode::InvalidFormat,
                    });
                }

                if !self.allow_loopback && ipv6.is_loopback() {
                    return Err(ValidationError {
                        field: self.field_name.clone(),
                        message: "Loopback addresses not allowed".to_string(),
                        code: ErrorCode::Blacklisted,
                    });
                }
            }
        }

        Ok(())
    }
}

/// URL validator
#[derive(Debug, Clone)]
pub struct UrlValidator {
    field_name: String,
    require_https: bool,
    allowed_schemes: Vec<String>,
    allowed_hosts: Option<Vec<String>>,
    blocked_hosts: Vec<String>,
}

impl UrlValidator {
    pub fn new(field_name: &str) -> Self {
        Self {
            field_name: field_name.to_string(),
            require_https: false,
            allowed_schemes: vec!["http".to_string(), "https".to_string()],
            allowed_hosts: None,
            blocked_hosts: Vec::new(),
        }
    }

    pub fn https_only(mut self) -> Self {
        self.require_https = true;
        self.allowed_schemes = vec!["https".to_string()];
        self
    }

    pub fn allowed_hosts(mut self, hosts: &[&str]) -> Self {
        self.allowed_hosts = Some(hosts.iter().map(|s| s.to_string()).collect());
        self
    }

    pub fn blocked_hosts(mut self, hosts: &[&str]) -> Self {
        self.blocked_hosts = hosts.iter().map(|s| s.to_string()).collect();
        self
    }
}

impl Validator<String> for UrlValidator {
    fn validate(&self, value: &String) -> ValidationResult<()> {
        let value = value.trim();

        if value.is_empty() {
            return Ok(());
        }

        // Parse scheme
        let scheme_end = value.find("://").ok_or_else(|| ValidationError {
            field: self.field_name.clone(),
            message: "Invalid URL format: missing scheme".to_string(),
            code: ErrorCode::InvalidFormat,
        })?;

        let scheme = &value[..scheme_end].to_lowercase();

        if !self.allowed_schemes.contains(scheme) {
            return Err(ValidationError {
                field: self.field_name.clone(),
                message: format!("URL scheme '{}' not allowed", scheme),
                code: ErrorCode::InvalidFormat,
            });
        }

        // Parse host
        let rest = &value[scheme_end + 3..];
        let host_end = rest.find('/').unwrap_or(rest.len());
        let host_part = &rest[..host_end];

        // Remove port if present
        let host = if let Some(port_start) = host_part.rfind(':') {
            &host_part[..port_start]
        } else {
            host_part
        };

        let host_lower = host.to_lowercase();

        // Allowed hosts check
        if let Some(ref allowed) = self.allowed_hosts {
            if !allowed
                .iter()
                .any(|h| host_lower == *h || host_lower.ends_with(&format!(".{}", h)))
            {
                return Err(ValidationError {
                    field: self.field_name.clone(),
                    message: "URL host not allowed".to_string(),
                    code: ErrorCode::Blacklisted,
                });
            }
        }

        // Blocked hosts check
        for blocked in &self.blocked_hosts {
            if host_lower == *blocked || host_lower.ends_with(&format!(".{}", blocked)) {
                return Err(ValidationError {
                    field: self.field_name.clone(),
                    message: "URL host is blocked".to_string(),
                    code: ErrorCode::Blacklisted,
                });
            }
        }

        Ok(())
    }
}

/// Form validator for multiple fields
#[derive(Debug, Default)]
pub struct FormValidator {
    errors: Vec<ValidationError>,
}

impl FormValidator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn validate<T, V: Validator<T>>(&mut self, validator: &V, value: &T) -> &mut Self {
        if let Err(e) = validator.validate(value) {
            self.errors.push(e);
        }
        self
    }

    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }

    pub fn errors(&self) -> &[ValidationError] {
        &self.errors
    }

    pub fn into_result(self) -> Result<(), Vec<ValidationError>> {
        if self.errors.is_empty() {
            Ok(())
        } else {
            Err(self.errors)
        }
    }
}

/// Input sanitizer
#[derive(Debug)]
pub struct Sanitizer;

impl Sanitizer {
    /// Remove null bytes
    pub fn remove_null_bytes(input: &str) -> String {
        input.replace('\0', "")
    }

    /// Normalize unicode to ASCII
    pub fn normalize_unicode(input: &str) -> String {
        input.chars().filter(|c| c.is_ascii()).collect()
    }

    /// Remove control characters
    pub fn remove_control_chars(input: &str) -> String {
        input
            .chars()
            .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
            .collect()
    }

    /// Normalize whitespace
    pub fn normalize_whitespace(input: &str) -> String {
        let mut result = String::with_capacity(input.len());
        let mut last_was_space = true;

        for ch in input.chars() {
            if ch.is_whitespace() {
                if !last_was_space {
                    result.push(' ');
                    last_was_space = true;
                }
            } else {
                result.push(ch);
                last_was_space = false;
            }
        }

        result.trim().to_string()
    }

    /// Truncate to max length safely
    pub fn truncate(input: &str, max_len: usize) -> String {
        input.chars().take(max_len).collect()
    }
}

fn main() {
    println!("=== Input Validation Demo ===\n");

    // String validation
    let username_validator = StringValidator::new("username")
        .required()
        .min_length(3)
        .max_length(20)
        .allowed_chars("abcdefghijklmnopqrstuvwxyz0123456789_")
        .blacklist(&["admin", "root", "system"]);

    println!("Username Validation:");
    for username in &["john_doe", "ab", "admin123", "valid_user", "user@name"] {
        let result = username_validator.validate(&username.to_string());
        println!("  '{}': {:?}", username, result);
    }

    // Email validation
    println!("\nEmail Validation:");
    let email_validator =
        EmailValidator::new("email").blocked_domains(&["tempmail.com", "throwaway.com"]);

    for email in &[
        "user@example.com",
        "invalid",
        "user@tempmail.com",
        "test@valid.org",
    ] {
        let result = email_validator.validate(&email.to_string());
        println!("  '{}': {:?}", email, result);
    }

    // Password validation
    println!("\nPassword Validation:");
    let password_validator = PasswordValidator::new("password").min_length(12);

    for password in &[
        "short",
        "nouppercase1!",
        "NOLOWERCASE1!",
        "NoSpecialChar1",
        "Valid@Password123",
    ] {
        let result = password_validator.validate(&password.to_string());
        let strength = password_validator.strength(password);
        println!(
            "  '{}': {:?} (strength: {})",
            password,
            result.is_ok(),
            strength
        );
    }

    // IP validation
    println!("\nIP Validation:");
    let ip_validator = IpValidator::new("ip_address").no_private();

    for ip in &["8.8.8.8", "192.168.1.1", "::1", "invalid", "10.0.0.1"] {
        let result = ip_validator.validate(&ip.to_string());
        println!("  '{}': {:?}", ip, result);
    }

    // URL validation
    println!("\nURL Validation:");
    let url_validator = UrlValidator::new("website")
        .https_only()
        .blocked_hosts(&["evil.com"]);

    for url in &[
        "https://example.com",
        "http://insecure.com",
        "https://evil.com/page",
        "ftp://files.com",
    ] {
        let result = url_validator.validate(&url.to_string());
        println!("  '{}': {:?}", url, result);
    }

    // Form validation
    println!("\n=== Form Validation ===\n");

    let mut form = FormValidator::new();
    form.validate(&username_validator, &"john_doe".to_string())
        .validate(&email_validator, &"john@example.com".to_string())
        .validate(&password_validator, &"Weak".to_string());

    if form.is_valid() {
        println!("Form is valid!");
    } else {
        println!("Form errors:");
        for error in form.errors() {
            println!("  - {}: {} ({:?})", error.field, error.message, error.code);
        }
    }

    // Sanitization
    println!("\n=== Input Sanitization ===\n");

    let dirty_input = "Hello\0World  with   spaces\nand\ttabs";
    println!("Original: {:?}", dirty_input);
    println!(
        "No null bytes: {:?}",
        Sanitizer::remove_null_bytes(dirty_input)
    );
    println!(
        "Normalized whitespace: {:?}",
        Sanitizer::normalize_whitespace(dirty_input)
    );
    println!("Truncated (10): {:?}", Sanitizer::truncate(dirty_input, 10));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_validator_required() {
        let validator = StringValidator::new("test").required();
        assert!(validator.validate(&"".to_string()).is_err());
        assert!(validator.validate(&"value".to_string()).is_ok());
    }

    #[test]
    fn test_string_validator_length() {
        let validator = StringValidator::new("test").min_length(3).max_length(10);

        assert!(validator.validate(&"ab".to_string()).is_err());
        assert!(validator.validate(&"abc".to_string()).is_ok());
        assert!(validator.validate(&"12345678901".to_string()).is_err());
    }

    #[test]
    fn test_string_validator_allowed_chars() {
        let validator = StringValidator::new("test").allowed_chars("abc123");

        assert!(validator.validate(&"abc123".to_string()).is_ok());
        assert!(validator.validate(&"abcXYZ".to_string()).is_err());
    }

    #[test]
    fn test_string_validator_blacklist() {
        let validator = StringValidator::new("test").blacklist(&["admin", "root"]);

        assert!(validator.validate(&"user".to_string()).is_ok());
        assert!(validator.validate(&"admin123".to_string()).is_err());
    }

    #[test]
    fn test_email_validator_format() {
        let validator = EmailValidator::new("email");

        assert!(validator.validate(&"user@example.com".to_string()).is_ok());
        assert!(validator.validate(&"invalid".to_string()).is_err());
        assert!(validator.validate(&"@nodomain".to_string()).is_err());
        assert!(validator.validate(&"noat.com".to_string()).is_err());
    }

    #[test]
    fn test_email_validator_blocked_domains() {
        let validator = EmailValidator::new("email").blocked_domains(&["spam.com"]);

        assert!(validator.validate(&"user@spam.com".to_string()).is_err());
        assert!(validator.validate(&"user@valid.com".to_string()).is_ok());
    }

    #[test]
    fn test_password_validator() {
        let validator = PasswordValidator::new("password");

        assert!(validator.validate(&"short".to_string()).is_err());
        assert!(validator.validate(&"nouppercase1!".to_string()).is_err());
        assert!(validator.validate(&"Valid@Pass123".to_string()).is_ok());
    }

    #[test]
    fn test_password_strength() {
        let validator = PasswordValidator::new("password");

        let weak = validator.strength("123456");
        let medium = validator.strength("Password1");
        let strong = validator.strength("C0mpl3x!P@ssw0rd#");

        assert!(weak < medium);
        assert!(medium < strong);
    }

    #[test]
    fn test_ip_validator() {
        let validator = IpValidator::new("ip");

        assert!(validator.validate(&"8.8.8.8".to_string()).is_ok());
        assert!(validator.validate(&"::1".to_string()).is_ok());
        assert!(validator.validate(&"invalid".to_string()).is_err());
    }

    #[test]
    fn test_ip_validator_no_private() {
        let validator = IpValidator::new("ip").no_private();

        assert!(validator.validate(&"192.168.1.1".to_string()).is_err());
        assert!(validator.validate(&"8.8.8.8".to_string()).is_ok());
    }

    #[test]
    fn test_url_validator_https_only() {
        let validator = UrlValidator::new("url").https_only();

        assert!(validator
            .validate(&"https://example.com".to_string())
            .is_ok());
        assert!(validator
            .validate(&"http://example.com".to_string())
            .is_err());
    }

    #[test]
    fn test_url_validator_blocked_hosts() {
        let validator = UrlValidator::new("url").blocked_hosts(&["evil.com"]);

        assert!(validator.validate(&"https://evil.com".to_string()).is_err());
        assert!(validator.validate(&"https://good.com".to_string()).is_ok());
    }

    #[test]
    fn test_form_validator() {
        let string_validator = StringValidator::new("name").required();
        let mut form = FormValidator::new();

        form.validate(&string_validator, &"".to_string());
        assert!(!form.is_valid());
        assert_eq!(form.errors().len(), 1);
    }

    #[test]
    fn test_sanitizer_null_bytes() {
        let result = Sanitizer::remove_null_bytes("hello\0world");
        assert_eq!(result, "helloworld");
    }

    #[test]
    fn test_sanitizer_whitespace() {
        let result = Sanitizer::normalize_whitespace("  hello   world  ");
        assert_eq!(result, "hello world");
    }

    #[test]
    fn test_sanitizer_truncate() {
        let result = Sanitizer::truncate("hello world", 5);
        assert_eq!(result, "hello");
    }

    #[test]
    fn test_sanitizer_control_chars() {
        let result = Sanitizer::remove_control_chars("hello\x00\x01world\n");
        assert_eq!(result, "helloworld\n");
    }
}
