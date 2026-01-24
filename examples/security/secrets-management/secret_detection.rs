//! Secret Detection Patterns
//!
//! Demonstrates detecting hardcoded secrets in source code and configuration.

use regex::Regex;
use std::collections::HashMap;

/// Types of secrets that can be detected
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SecretType {
    AwsAccessKey,
    AwsSecretKey,
    GitHubToken,
    GitHubOAuth,
    SlackToken,
    SlackWebhook,
    StripeKey,
    GoogleApiKey,
    PrivateKey,
    GenericApiKey,
    GenericSecret,
    JwtToken,
    BasicAuth,
    ConnectionString,
}

impl SecretType {
    pub fn severity(&self) -> Severity {
        match self {
            Self::AwsAccessKey | Self::AwsSecretKey => Severity::Critical,
            Self::PrivateKey => Severity::Critical,
            Self::GitHubToken | Self::GitHubOAuth => Severity::High,
            Self::StripeKey => Severity::High,
            Self::SlackToken | Self::SlackWebhook => Severity::Medium,
            Self::JwtToken => Severity::High,
            Self::ConnectionString => Severity::High,
            Self::BasicAuth => Severity::High,
            Self::GoogleApiKey => Severity::Medium,
            Self::GenericApiKey | Self::GenericSecret => Severity::Medium,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// A detected secret
#[derive(Debug, Clone)]
pub struct SecretFinding {
    pub secret_type: SecretType,
    pub line_number: usize,
    pub column: usize,
    pub matched_text: String,
    pub redacted: String,
    pub severity: Severity,
    pub description: String,
}

impl SecretFinding {
    fn redact(text: &str) -> String {
        if text.len() <= 8 {
            "*".repeat(text.len())
        } else {
            format!("{}...{}", &text[..4], &text[text.len()-4..])
        }
    }
}

/// Secret scanner with configurable patterns
pub struct SecretScanner {
    patterns: Vec<(SecretType, Regex, &'static str)>,
    allowlist: Vec<Regex>,
}

impl SecretScanner {
    pub fn new() -> Self {
        let patterns = vec![
            // AWS
            (SecretType::AwsAccessKey,
             Regex::new(r"(?i)(AKIA[0-9A-Z]{16})").unwrap(),
             "AWS Access Key ID"),
            (SecretType::AwsSecretKey,
             Regex::new(r#"(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?"#).unwrap(),
             "AWS Secret Access Key"),

            // GitHub
            (SecretType::GitHubToken,
             Regex::new(r"(ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|ghu_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|ghr_[A-Za-z0-9]{36})").unwrap(),
             "GitHub Personal Access Token"),
            (SecretType::GitHubOAuth,
             Regex::new(r"github[_\-]?oauth[_\-]?token\s*[=:]\s*['\"]?([a-f0-9]{40})['\"]?").unwrap(),
             "GitHub OAuth Token"),

            // Slack
            (SecretType::SlackToken,
             Regex::new(r"(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)").unwrap(),
             "Slack Token"),
            (SecretType::SlackWebhook,
             Regex::new(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+").unwrap(),
             "Slack Webhook URL"),

            // Stripe
            (SecretType::StripeKey,
             Regex::new(r"(sk_live_[A-Za-z0-9]{24,})").unwrap(),
             "Stripe Live Secret Key"),

            // Google
            (SecretType::GoogleApiKey,
             Regex::new(r"AIza[0-9A-Za-z_-]{35}").unwrap(),
             "Google API Key"),

            // Private Keys
            (SecretType::PrivateKey,
             Regex::new(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----").unwrap(),
             "Private Key"),

            // JWT
            (SecretType::JwtToken,
             Regex::new(r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*").unwrap(),
             "JWT Token"),

            // Connection Strings
            (SecretType::ConnectionString,
             Regex::new(r#"(?i)(postgres|mysql|mongodb|redis)://[^:]+:[^@]+@[^\s"']+"#).unwrap(),
             "Database Connection String"),

            // Basic Auth
            (SecretType::BasicAuth,
             Regex::new(r"(?i)authorization:\s*basic\s+[A-Za-z0-9+/=]+").unwrap(),
             "Basic Auth Header"),

            // Generic patterns (lower confidence)
            (SecretType::GenericApiKey,
             Regex::new(r#"(?i)(api[_-]?key|apikey)\s*[=:]\s*["']?([A-Za-z0-9_-]{20,})["']?"#).unwrap(),
             "Generic API Key"),
            (SecretType::GenericSecret,
             Regex::new(r#"(?i)(secret|password|passwd|pwd)\s*[=:]\s*["']([^"']{8,})["']"#).unwrap(),
             "Generic Secret"),
        ];

        Self {
            patterns,
            allowlist: Vec::new(),
        }
    }

    /// Add patterns to ignore (e.g., example values, test data)
    pub fn add_allowlist(&mut self, pattern: &str) -> Result<(), regex::Error> {
        self.allowlist.push(Regex::new(pattern)?);
        Ok(())
    }

    /// Scan content for secrets
    pub fn scan(&self, content: &str) -> Vec<SecretFinding> {
        let mut findings = Vec::new();

        for (line_number, line) in content.lines().enumerate() {
            // Skip if line matches allowlist
            if self.allowlist.iter().any(|p| p.is_match(line)) {
                continue;
            }

            for (secret_type, pattern, description) in &self.patterns {
                if let Some(m) = pattern.find(line) {
                    let matched_text = m.as_str().to_string();

                    // Skip if matched text is allowlisted
                    if self.allowlist.iter().any(|p| p.is_match(&matched_text)) {
                        continue;
                    }

                    findings.push(SecretFinding {
                        secret_type: secret_type.clone(),
                        line_number: line_number + 1,
                        column: m.start() + 1,
                        redacted: SecretFinding::redact(&matched_text),
                        matched_text,
                        severity: secret_type.severity(),
                        description: description.to_string(),
                    });
                }
            }
        }

        findings
    }

    /// Scan a file
    pub fn scan_file(&self, path: &std::path::Path) -> std::io::Result<Vec<SecretFinding>> {
        let content = std::fs::read_to_string(path)?;
        Ok(self.scan(&content))
    }
}

impl Default for SecretScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate a report from findings
pub fn generate_report(findings: &[SecretFinding]) -> String {
    let mut report = String::new();
    report.push_str("# Secret Detection Report\n\n");

    // Summary by severity
    let mut by_severity: HashMap<Severity, usize> = HashMap::new();
    for f in findings {
        *by_severity.entry(f.severity).or_insert(0) += 1;
    }

    report.push_str("## Summary\n\n");
    report.push_str(&format!("Total findings: {}\n", findings.len()));
    for severity in [Severity::Critical, Severity::High, Severity::Medium, Severity::Low] {
        if let Some(count) = by_severity.get(&severity) {
            report.push_str(&format!("- {:?}: {}\n", severity, count));
        }
    }

    // Detailed findings
    report.push_str("\n## Findings\n\n");
    for finding in findings {
        report.push_str(&format!(
            "### [{:?}] {} (line {})\n",
            finding.severity, finding.description, finding.line_number
        ));
        report.push_str(&format!("- Type: {:?}\n", finding.secret_type));
        report.push_str(&format!("- Value: `{}`\n", finding.redacted));
        report.push_str(&format!("- Column: {}\n\n", finding.column));
    }

    report
}

fn main() {
    let mut scanner = SecretScanner::new();

    // Add allowlist for test/example values
    scanner.add_allowlist(r"(?i)example|test|dummy|fake|placeholder").unwrap();

    // Sample content with various secrets
    let content = r#"
        # Configuration file

        AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
        aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

        GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

        slack_webhook = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXX"

        STRIPE_KEY=sk_live_xxxxxxxxxxxxxxxxxxxxxxxx

        DATABASE_URL=postgres://user:password123@localhost:5432/mydb

        api_key = "sk-1234567890abcdefghij"

        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEA0Z3VS...
        -----END RSA PRIVATE KEY-----

        JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N
    "#;

    let findings = scanner.scan(content);

    println!("=== Secret Detection Demo ===\n");
    println!("Scanned {} lines", content.lines().count());
    println!("Found {} potential secrets\n", findings.len());

    for finding in &findings {
        println!(
            "[{:?}] Line {}: {} - {}",
            finding.severity,
            finding.line_number,
            finding.description,
            finding.redacted
        );
    }

    println!("\n{}", generate_report(&findings));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_key_detection() {
        let scanner = SecretScanner::new();
        let content = "AWS_KEY=AKIAIOSFODNN7EXAMPLE";
        let findings = scanner.scan(content);

        assert!(!findings.is_empty());
        assert_eq!(findings[0].secret_type, SecretType::AwsAccessKey);
    }

    #[test]
    fn test_github_token_detection() {
        let scanner = SecretScanner::new();
        let content = "token = ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let findings = scanner.scan(content);

        assert!(!findings.is_empty());
        assert_eq!(findings[0].secret_type, SecretType::GitHubToken);
    }

    #[test]
    fn test_allowlist() {
        let mut scanner = SecretScanner::new();
        scanner.add_allowlist(r"EXAMPLE").unwrap();

        let content = "AWS_KEY=AKIAIOSFODNN7EXAMPLE";
        let findings = scanner.scan(content);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_private_key_detection() {
        let scanner = SecretScanner::new();
        let content = "-----BEGIN RSA PRIVATE KEY-----\nxxx\n-----END RSA PRIVATE KEY-----";
        let findings = scanner.scan(content);

        assert!(!findings.is_empty());
        assert_eq!(findings[0].secret_type, SecretType::PrivateKey);
        assert_eq!(findings[0].severity, Severity::Critical);
    }
}
