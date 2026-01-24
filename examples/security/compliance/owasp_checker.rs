//! OWASP Compliance Checker
//!
//! Implementation of OWASP Top 10 and ASVS (Application Security Verification Standard)
//! compliance checking for web applications.

use std::collections::HashMap;
use std::fmt;

/// OWASP Top 10 2021 categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OwaspTop10 {
    /// A01:2021 - Broken Access Control
    BrokenAccessControl,
    /// A02:2021 - Cryptographic Failures
    CryptographicFailures,
    /// A03:2021 - Injection
    Injection,
    /// A04:2021 - Insecure Design
    InsecureDesign,
    /// A05:2021 - Security Misconfiguration
    SecurityMisconfiguration,
    /// A06:2021 - Vulnerable and Outdated Components
    VulnerableComponents,
    /// A07:2021 - Identification and Authentication Failures
    AuthenticationFailures,
    /// A08:2021 - Software and Data Integrity Failures
    IntegrityFailures,
    /// A09:2021 - Security Logging and Monitoring Failures
    LoggingFailures,
    /// A10:2021 - Server-Side Request Forgery
    Ssrf,
}

impl OwaspTop10 {
    pub fn code(&self) -> &'static str {
        match self {
            OwaspTop10::BrokenAccessControl => "A01:2021",
            OwaspTop10::CryptographicFailures => "A02:2021",
            OwaspTop10::Injection => "A03:2021",
            OwaspTop10::InsecureDesign => "A04:2021",
            OwaspTop10::SecurityMisconfiguration => "A05:2021",
            OwaspTop10::VulnerableComponents => "A06:2021",
            OwaspTop10::AuthenticationFailures => "A07:2021",
            OwaspTop10::IntegrityFailures => "A08:2021",
            OwaspTop10::LoggingFailures => "A09:2021",
            OwaspTop10::Ssrf => "A10:2021",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            OwaspTop10::BrokenAccessControl => "Broken Access Control",
            OwaspTop10::CryptographicFailures => "Cryptographic Failures",
            OwaspTop10::Injection => "Injection",
            OwaspTop10::InsecureDesign => "Insecure Design",
            OwaspTop10::SecurityMisconfiguration => "Security Misconfiguration",
            OwaspTop10::VulnerableComponents => "Vulnerable and Outdated Components",
            OwaspTop10::AuthenticationFailures => "Identification and Authentication Failures",
            OwaspTop10::IntegrityFailures => "Software and Data Integrity Failures",
            OwaspTop10::LoggingFailures => "Security Logging and Monitoring Failures",
            OwaspTop10::Ssrf => "Server-Side Request Forgery",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            OwaspTop10::BrokenAccessControl => "Access control enforces policy such that users cannot act outside of their intended permissions",
            OwaspTop10::CryptographicFailures => "Failures related to cryptography which often lead to sensitive data exposure",
            OwaspTop10::Injection => "User-supplied data is not validated, filtered, or sanitized by the application",
            OwaspTop10::InsecureDesign => "Missing or ineffective security controls in design, architecture decisions",
            OwaspTop10::SecurityMisconfiguration => "Missing security hardening, improperly configured permissions, unnecessary features enabled",
            OwaspTop10::VulnerableComponents => "Components with known vulnerabilities, outdated or unsupported software",
            OwaspTop10::AuthenticationFailures => "Confirmation of the user's identity, authentication, and session management",
            OwaspTop10::IntegrityFailures => "Code and infrastructure that does not protect against integrity violations",
            OwaspTop10::LoggingFailures => "Insufficient logging, detection, monitoring, and active response",
            OwaspTop10::Ssrf => "Web application fetches remote resource without validating user-supplied URL",
        }
    }

    pub fn all() -> Vec<OwaspTop10> {
        vec![
            OwaspTop10::BrokenAccessControl,
            OwaspTop10::CryptographicFailures,
            OwaspTop10::Injection,
            OwaspTop10::InsecureDesign,
            OwaspTop10::SecurityMisconfiguration,
            OwaspTop10::VulnerableComponents,
            OwaspTop10::AuthenticationFailures,
            OwaspTop10::IntegrityFailures,
            OwaspTop10::LoggingFailures,
            OwaspTop10::Ssrf,
        ]
    }
}

impl fmt::Display for OwaspTop10 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} - {}", self.code(), self.name())
    }
}

/// ASVS verification levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AsvsLevel {
    /// Level 1: Opportunistic - Basic security controls
    Level1,
    /// Level 2: Standard - Most applications should aim for this level
    Level2,
    /// Level 3: Advanced - High value applications requiring significant security
    Level3,
}

impl AsvsLevel {
    pub fn name(&self) -> &'static str {
        match self {
            AsvsLevel::Level1 => "Level 1 - Opportunistic",
            AsvsLevel::Level2 => "Level 2 - Standard",
            AsvsLevel::Level3 => "Level 3 - Advanced",
        }
    }
}

/// ASVS categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AsvsCategory {
    V1Architecture,
    V2Authentication,
    V3SessionManagement,
    V4AccessControl,
    V5Validation,
    V6Cryptography,
    V7ErrorHandling,
    V8DataProtection,
    V9Communications,
    V10Malicious,
    V11BusinessLogic,
    V12Files,
    V13Api,
    V14Configuration,
}

impl AsvsCategory {
    pub fn name(&self) -> &'static str {
        match self {
            AsvsCategory::V1Architecture => "V1 Architecture, Design and Threat Modeling",
            AsvsCategory::V2Authentication => "V2 Authentication",
            AsvsCategory::V3SessionManagement => "V3 Session Management",
            AsvsCategory::V4AccessControl => "V4 Access Control",
            AsvsCategory::V5Validation => "V5 Validation, Sanitization and Encoding",
            AsvsCategory::V6Cryptography => "V6 Stored Cryptography",
            AsvsCategory::V7ErrorHandling => "V7 Error Handling and Logging",
            AsvsCategory::V8DataProtection => "V8 Data Protection",
            AsvsCategory::V9Communications => "V9 Communications",
            AsvsCategory::V10Malicious => "V10 Malicious Code",
            AsvsCategory::V11BusinessLogic => "V11 Business Logic",
            AsvsCategory::V12Files => "V12 Files and Resources",
            AsvsCategory::V13Api => "V13 API and Web Service",
            AsvsCategory::V14Configuration => "V14 Configuration",
        }
    }
}

/// A security requirement/check
#[derive(Debug, Clone)]
pub struct SecurityRequirement {
    pub id: String,
    pub category: AsvsCategory,
    pub owasp_mapping: Vec<OwaspTop10>,
    pub minimum_level: AsvsLevel,
    pub title: String,
    pub description: String,
    pub verification_method: String,
}

impl SecurityRequirement {
    pub fn new(id: &str, category: AsvsCategory, title: &str) -> Self {
        Self {
            id: id.into(),
            category,
            owasp_mapping: vec![],
            minimum_level: AsvsLevel::Level1,
            title: title.into(),
            description: String::new(),
            verification_method: String::new(),
        }
    }

    pub fn with_owasp(mut self, owasp: OwaspTop10) -> Self {
        self.owasp_mapping.push(owasp);
        self
    }

    pub fn with_level(mut self, level: AsvsLevel) -> Self {
        self.minimum_level = level;
        self
    }

    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = desc.into();
        self
    }

    pub fn with_verification(mut self, method: &str) -> Self {
        self.verification_method = method.into();
        self
    }
}

/// Result of a compliance check
#[derive(Debug, Clone)]
pub struct CheckResult {
    pub requirement: SecurityRequirement,
    pub status: ComplianceStatus,
    pub evidence: String,
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComplianceStatus {
    Pass,
    Fail,
    Partial,
    NotApplicable,
    NotTested,
}

impl CheckResult {
    pub fn pass(requirement: SecurityRequirement, evidence: &str) -> Self {
        Self {
            requirement,
            status: ComplianceStatus::Pass,
            evidence: evidence.into(),
            remediation: None,
        }
    }

    pub fn fail(requirement: SecurityRequirement, evidence: &str, remediation: &str) -> Self {
        Self {
            requirement,
            status: ComplianceStatus::Fail,
            evidence: evidence.into(),
            remediation: Some(remediation.into()),
        }
    }

    pub fn partial(requirement: SecurityRequirement, evidence: &str, remediation: &str) -> Self {
        Self {
            requirement,
            status: ComplianceStatus::Partial,
            evidence: evidence.into(),
            remediation: Some(remediation.into()),
        }
    }
}

/// Compliance checker for OWASP standards
pub struct OwaspComplianceChecker {
    requirements: Vec<SecurityRequirement>,
    target_level: AsvsLevel,
    results: Vec<CheckResult>,
}

impl OwaspComplianceChecker {
    pub fn new(target_level: AsvsLevel) -> Self {
        Self {
            requirements: Self::default_requirements(),
            target_level,
            results: vec![],
        }
    }

    fn default_requirements() -> Vec<SecurityRequirement> {
        vec![
            // V2 Authentication
            SecurityRequirement::new("V2.1.1", AsvsCategory::V2Authentication, "Password Length")
                .with_owasp(OwaspTop10::AuthenticationFailures)
                .with_level(AsvsLevel::Level1)
                .with_description("Verify that user set passwords are at least 12 characters in length")
                .with_verification("Review password validation code and configuration"),

            SecurityRequirement::new("V2.1.2", AsvsCategory::V2Authentication, "Password Character Types")
                .with_owasp(OwaspTop10::AuthenticationFailures)
                .with_level(AsvsLevel::Level1)
                .with_description("Verify that passwords can be at least 64 characters and not truncated")
                .with_verification("Test password input with 64+ character passwords"),

            SecurityRequirement::new("V2.1.7", AsvsCategory::V2Authentication, "Breached Password Check")
                .with_owasp(OwaspTop10::AuthenticationFailures)
                .with_level(AsvsLevel::Level2)
                .with_description("Verify that passwords are checked against known breached password databases")
                .with_verification("Review password validation integration with breach database"),

            SecurityRequirement::new("V2.2.1", AsvsCategory::V2Authentication, "Anti-Automation")
                .with_owasp(OwaspTop10::AuthenticationFailures)
                .with_level(AsvsLevel::Level1)
                .with_description("Verify that anti-automation controls are in place to prevent brute force attacks")
                .with_verification("Test rate limiting and account lockout functionality"),

            SecurityRequirement::new("V2.5.1", AsvsCategory::V2Authentication, "MFA Implementation")
                .with_owasp(OwaspTop10::AuthenticationFailures)
                .with_level(AsvsLevel::Level2)
                .with_description("Verify that a second authentication factor is available for user accounts")
                .with_verification("Review MFA implementation and enrollment process"),

            // V3 Session Management
            SecurityRequirement::new("V3.1.1", AsvsCategory::V3SessionManagement, "Secure Session IDs")
                .with_owasp(OwaspTop10::AuthenticationFailures)
                .with_level(AsvsLevel::Level1)
                .with_description("Verify that the application generates a new session token on user authentication")
                .with_verification("Monitor session IDs before and after authentication"),

            SecurityRequirement::new("V3.2.1", AsvsCategory::V3SessionManagement, "Session Timeout")
                .with_owasp(OwaspTop10::AuthenticationFailures)
                .with_level(AsvsLevel::Level1)
                .with_description("Verify that session timeout is implemented")
                .with_verification("Test session expiration after idle period"),

            SecurityRequirement::new("V3.4.1", AsvsCategory::V3SessionManagement, "Cookie Security Attributes")
                .with_owasp(OwaspTop10::AuthenticationFailures)
                .with_level(AsvsLevel::Level1)
                .with_description("Verify that cookie-based session tokens have Secure, HttpOnly, and SameSite attributes")
                .with_verification("Inspect Set-Cookie headers in HTTP responses"),

            // V4 Access Control
            SecurityRequirement::new("V4.1.1", AsvsCategory::V4AccessControl, "Access Control Enforcement")
                .with_owasp(OwaspTop10::BrokenAccessControl)
                .with_level(AsvsLevel::Level1)
                .with_description("Verify that the application enforces access control rules on a trusted service layer")
                .with_verification("Review access control implementation architecture"),

            SecurityRequirement::new("V4.1.2", AsvsCategory::V4AccessControl, "IDOR Prevention")
                .with_owasp(OwaspTop10::BrokenAccessControl)
                .with_level(AsvsLevel::Level1)
                .with_description("Verify that access to sensitive data is protected against IDOR attacks")
                .with_verification("Test direct object reference manipulation"),

            SecurityRequirement::new("V4.2.1", AsvsCategory::V4AccessControl, "Principle of Least Privilege")
                .with_owasp(OwaspTop10::BrokenAccessControl)
                .with_level(AsvsLevel::Level1)
                .with_description("Verify that users can only access functions and data for which they possess authorization")
                .with_verification("Test access to functionality with different user roles"),

            // V5 Validation
            SecurityRequirement::new("V5.1.1", AsvsCategory::V5Validation, "Input Validation Architecture")
                .with_owasp(OwaspTop10::Injection)
                .with_level(AsvsLevel::Level1)
                .with_description("Verify that input validation is enforced on a trusted service layer")
                .with_verification("Review input validation implementation"),

            SecurityRequirement::new("V5.2.1", AsvsCategory::V5Validation, "SQL Injection Prevention")
                .with_owasp(OwaspTop10::Injection)
                .with_level(AsvsLevel::Level1)
                .with_description("Verify that parameterized queries are used for database operations")
                .with_verification("Review database query code for parameterization"),

            SecurityRequirement::new("V5.3.1", AsvsCategory::V5Validation, "Output Encoding")
                .with_owasp(OwaspTop10::Injection)
                .with_level(AsvsLevel::Level1)
                .with_description("Verify that output encoding is relevant for the interpreter being used")
                .with_verification("Review output encoding in templates and responses"),

            // V6 Cryptography
            SecurityRequirement::new("V6.1.1", AsvsCategory::V6Cryptography, "Data Classification")
                .with_owasp(OwaspTop10::CryptographicFailures)
                .with_level(AsvsLevel::Level2)
                .with_description("Verify that regulated data is stored encrypted while at rest")
                .with_verification("Review data storage and encryption implementation"),

            SecurityRequirement::new("V6.2.1", AsvsCategory::V6Cryptography, "Strong Algorithms")
                .with_owasp(OwaspTop10::CryptographicFailures)
                .with_level(AsvsLevel::Level1)
                .with_description("Verify that all cryptographic modules fail securely")
                .with_verification("Review cryptographic implementation and error handling"),

            SecurityRequirement::new("V6.2.5", AsvsCategory::V6Cryptography, "Key Management")
                .with_owasp(OwaspTop10::CryptographicFailures)
                .with_level(AsvsLevel::Level2)
                .with_description("Verify that cryptographic keys are stored securely")
                .with_verification("Review key storage and rotation procedures"),

            // V7 Error Handling
            SecurityRequirement::new("V7.1.1", AsvsCategory::V7ErrorHandling, "Error Message Content")
                .with_owasp(OwaspTop10::LoggingFailures)
                .with_level(AsvsLevel::Level1)
                .with_description("Verify that the application does not log credentials or payment details")
                .with_verification("Review logging configuration and log output"),

            SecurityRequirement::new("V7.2.1", AsvsCategory::V7ErrorHandling, "Security Event Logging")
                .with_owasp(OwaspTop10::LoggingFailures)
                .with_level(AsvsLevel::Level2)
                .with_description("Verify that all authentication events are logged")
                .with_verification("Test authentication logging with various scenarios"),

            // V9 Communications
            SecurityRequirement::new("V9.1.1", AsvsCategory::V9Communications, "TLS for All Connections")
                .with_owasp(OwaspTop10::CryptographicFailures)
                .with_level(AsvsLevel::Level1)
                .with_description("Verify that TLS is used for all client connectivity")
                .with_verification("Test all endpoints for TLS configuration"),

            SecurityRequirement::new("V9.1.2", AsvsCategory::V9Communications, "Strong TLS Configuration")
                .with_owasp(OwaspTop10::CryptographicFailures)
                .with_level(AsvsLevel::Level1)
                .with_description("Verify that only strong cipher suites are enabled")
                .with_verification("Analyze TLS configuration with security scanner"),

            // V13 API Security
            SecurityRequirement::new("V13.1.1", AsvsCategory::V13Api, "API Authentication")
                .with_owasp(OwaspTop10::BrokenAccessControl)
                .with_level(AsvsLevel::Level1)
                .with_description("Verify that all API endpoints require authentication")
                .with_verification("Test all API endpoints without authentication"),

            SecurityRequirement::new("V13.2.1", AsvsCategory::V13Api, "Rate Limiting")
                .with_owasp(OwaspTop10::SecurityMisconfiguration)
                .with_level(AsvsLevel::Level1)
                .with_description("Verify that API rate limiting is implemented")
                .with_verification("Test API endpoints for rate limiting behavior"),

            // V14 Configuration
            SecurityRequirement::new("V14.2.1", AsvsCategory::V14Configuration, "Dependency Security")
                .with_owasp(OwaspTop10::VulnerableComponents)
                .with_level(AsvsLevel::Level1)
                .with_description("Verify that all components are up to date with security patches")
                .with_verification("Run dependency vulnerability scan"),

            SecurityRequirement::new("V14.3.1", AsvsCategory::V14Configuration, "Security Headers")
                .with_owasp(OwaspTop10::SecurityMisconfiguration)
                .with_level(AsvsLevel::Level1)
                .with_description("Verify that security headers are configured")
                .with_verification("Analyze HTTP response headers"),
        ]
    }

    pub fn add_requirement(&mut self, requirement: SecurityRequirement) {
        self.requirements.push(requirement);
    }

    pub fn requirements_for_level(&self) -> Vec<&SecurityRequirement> {
        self.requirements
            .iter()
            .filter(|r| r.minimum_level <= self.target_level)
            .collect()
    }

    pub fn requirements_by_owasp(&self, category: OwaspTop10) -> Vec<&SecurityRequirement> {
        self.requirements
            .iter()
            .filter(|r| r.owasp_mapping.contains(&category))
            .collect()
    }

    pub fn record_result(&mut self, result: CheckResult) {
        self.results.push(result);
    }

    pub fn compliance_score(&self) -> f64 {
        if self.results.is_empty() {
            return 0.0;
        }

        let applicable: Vec<_> = self
            .results
            .iter()
            .filter(|r| {
                r.status != ComplianceStatus::NotApplicable
                    && r.status != ComplianceStatus::NotTested
            })
            .collect();

        if applicable.is_empty() {
            return 100.0;
        }

        let passing = applicable
            .iter()
            .filter(|r| r.status == ComplianceStatus::Pass)
            .count();

        let partial = applicable
            .iter()
            .filter(|r| r.status == ComplianceStatus::Partial)
            .count();

        ((passing as f64 + partial as f64 * 0.5) / applicable.len() as f64) * 100.0
    }

    pub fn failing_requirements(&self) -> Vec<&CheckResult> {
        self.results
            .iter()
            .filter(|r| r.status == ComplianceStatus::Fail)
            .collect()
    }

    pub fn summary(&self) -> ComplianceSummary {
        let mut by_status: HashMap<ComplianceStatus, usize> = HashMap::new();
        let mut by_owasp: HashMap<OwaspTop10, (usize, usize)> = HashMap::new();

        for result in &self.results {
            *by_status.entry(result.status).or_insert(0) += 1;

            for owasp in &result.requirement.owasp_mapping {
                let entry = by_owasp.entry(*owasp).or_insert((0, 0));
                entry.1 += 1; // Total
                if result.status == ComplianceStatus::Pass {
                    entry.0 += 1; // Passing
                }
            }
        }

        ComplianceSummary {
            target_level: self.target_level,
            total_requirements: self.requirements_for_level().len(),
            tested: self.results.len(),
            passing: *by_status.get(&ComplianceStatus::Pass).unwrap_or(&0),
            failing: *by_status.get(&ComplianceStatus::Fail).unwrap_or(&0),
            partial: *by_status.get(&ComplianceStatus::Partial).unwrap_or(&0),
            not_applicable: *by_status
                .get(&ComplianceStatus::NotApplicable)
                .unwrap_or(&0),
            compliance_score: self.compliance_score(),
            by_owasp,
        }
    }

    pub fn generate_report(&self) -> String {
        let summary = self.summary();
        let mut report = String::new();

        report.push_str("# OWASP Compliance Report\n\n");
        report.push_str(&format!(
            "**Target Level:** {}\n\n",
            summary.target_level.name()
        ));
        report.push_str(&format!(
            "**Compliance Score:** {:.1}%\n\n",
            summary.compliance_score
        ));

        report.push_str("## Summary\n\n");
        report.push_str(&format!(
            "- Total Requirements: {}\n",
            summary.total_requirements
        ));
        report.push_str(&format!("- Tested: {}\n", summary.tested));
        report.push_str(&format!("- Passing: {}\n", summary.passing));
        report.push_str(&format!("- Failing: {}\n", summary.failing));
        report.push_str(&format!("- Partial: {}\n", summary.partial));
        report.push_str(&format!("- N/A: {}\n\n", summary.not_applicable));

        report.push_str("## OWASP Top 10 Coverage\n\n");
        for owasp in OwaspTop10::all() {
            if let Some((passing, total)) = summary.by_owasp.get(&owasp) {
                let percentage = if *total > 0 {
                    (*passing as f64 / *total as f64) * 100.0
                } else {
                    0.0
                };
                report.push_str(&format!(
                    "- {}: {}/{} ({:.0}%)\n",
                    owasp, passing, total, percentage
                ));
            }
        }

        report.push_str("\n## Failing Requirements\n\n");
        for result in self.failing_requirements() {
            report.push_str(&format!(
                "### {} - {}\n\n",
                result.requirement.id, result.requirement.title
            ));
            report.push_str(&format!(
                "**Category:** {}\n\n",
                result.requirement.category.name()
            ));
            report.push_str(&format!("**Evidence:** {}\n\n", result.evidence));
            if let Some(remediation) = &result.remediation {
                report.push_str(&format!("**Remediation:** {}\n\n", remediation));
            }
        }

        report
    }
}

#[derive(Debug, Clone)]
pub struct ComplianceSummary {
    pub target_level: AsvsLevel,
    pub total_requirements: usize,
    pub tested: usize,
    pub passing: usize,
    pub failing: usize,
    pub partial: usize,
    pub not_applicable: usize,
    pub compliance_score: f64,
    pub by_owasp: HashMap<OwaspTop10, (usize, usize)>,
}

/// Security header checker
pub struct SecurityHeaderChecker {
    required_headers: Vec<SecurityHeader>,
}

#[derive(Debug, Clone)]
pub struct SecurityHeader {
    pub name: String,
    pub recommended_value: Option<String>,
    pub description: String,
    pub owasp_mapping: OwaspTop10,
}

impl SecurityHeaderChecker {
    pub fn new() -> Self {
        Self {
            required_headers: vec![
                SecurityHeader {
                    name: "Strict-Transport-Security".into(),
                    recommended_value: Some("max-age=31536000; includeSubDomains; preload".into()),
                    description: "Enforces HTTPS connections".into(),
                    owasp_mapping: OwaspTop10::CryptographicFailures,
                },
                SecurityHeader {
                    name: "Content-Security-Policy".into(),
                    recommended_value: None,
                    description: "Prevents XSS and injection attacks".into(),
                    owasp_mapping: OwaspTop10::Injection,
                },
                SecurityHeader {
                    name: "X-Content-Type-Options".into(),
                    recommended_value: Some("nosniff".into()),
                    description: "Prevents MIME type sniffing".into(),
                    owasp_mapping: OwaspTop10::SecurityMisconfiguration,
                },
                SecurityHeader {
                    name: "X-Frame-Options".into(),
                    recommended_value: Some("DENY".into()),
                    description: "Prevents clickjacking attacks".into(),
                    owasp_mapping: OwaspTop10::SecurityMisconfiguration,
                },
                SecurityHeader {
                    name: "Referrer-Policy".into(),
                    recommended_value: Some("strict-origin-when-cross-origin".into()),
                    description: "Controls referrer information".into(),
                    owasp_mapping: OwaspTop10::SecurityMisconfiguration,
                },
                SecurityHeader {
                    name: "Permissions-Policy".into(),
                    recommended_value: None,
                    description: "Controls browser features and APIs".into(),
                    owasp_mapping: OwaspTop10::SecurityMisconfiguration,
                },
            ],
        }
    }

    pub fn check_headers(&self, headers: &HashMap<String, String>) -> Vec<HeaderCheckResult> {
        self.required_headers
            .iter()
            .map(|required| {
                let present = headers.contains_key(&required.name.to_lowercase());
                let value = headers.get(&required.name.to_lowercase());

                let (status, issue) = if present {
                    if let Some(recommended) = &required.recommended_value {
                        if value.map(|v| v == recommended).unwrap_or(false) {
                            (HeaderStatus::Correct, None)
                        } else {
                            (
                                HeaderStatus::Misconfigured,
                                Some(format!(
                                    "Expected '{}', got '{}'",
                                    recommended,
                                    value.unwrap_or(&"(none)".to_string())
                                )),
                            )
                        }
                    } else {
                        (HeaderStatus::Present, None)
                    }
                } else {
                    (HeaderStatus::Missing, Some("Header not present".into()))
                };

                HeaderCheckResult {
                    header: required.clone(),
                    status,
                    issue,
                }
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct HeaderCheckResult {
    pub header: SecurityHeader,
    pub status: HeaderStatus,
    pub issue: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderStatus {
    Correct,
    Present,
    Misconfigured,
    Missing,
}

fn main() {
    println!("OWASP Compliance Checker\n");

    // Create checker targeting ASVS Level 2
    let mut checker = OwaspComplianceChecker::new(AsvsLevel::Level2);

    println!(
        "=== Requirements for ASVS {} ===\n",
        checker.target_level.name()
    );
    println!(
        "Total requirements: {}\n",
        checker.requirements_for_level().len()
    );

    // Simulate some check results
    let requirements = checker.requirements_for_level();

    // Simulate passing checks
    for req in requirements.iter().take(10) {
        let result = CheckResult::pass((*req).clone(), "Verified in code review");
        checker.record_result(result);
    }

    // Simulate some failing checks
    if let Some(req) = requirements.get(10) {
        let result = CheckResult::fail(
            (*req).clone(),
            "Password minimum length is only 8 characters",
            "Update password validation to require minimum 12 characters",
        );
        checker.record_result(result);
    }

    if let Some(req) = requirements.get(11) {
        let result = CheckResult::partial(
            (*req).clone(),
            "Rate limiting implemented but threshold too high",
            "Reduce rate limit threshold to 100 requests per minute",
        );
        checker.record_result(result);
    }

    // Print summary
    let summary = checker.summary();
    println!("=== Compliance Summary ===\n");
    println!("Compliance Score: {:.1}%\n", summary.compliance_score);
    println!("Tested: {}/{}", summary.tested, summary.total_requirements);
    println!("Passing: {}", summary.passing);
    println!("Failing: {}", summary.failing);
    println!("Partial: {}", summary.partial);

    // Print failing requirements
    println!("\n=== Failing Requirements ===\n");
    for result in checker.failing_requirements() {
        println!("{}: {}", result.requirement.id, result.requirement.title);
        println!("  Evidence: {}", result.evidence);
        if let Some(remediation) = &result.remediation {
            println!("  Remediation: {}", remediation);
        }
        println!();
    }

    // Security header check
    println!("=== Security Header Check ===\n");
    let header_checker = SecurityHeaderChecker::new();

    let mut headers = HashMap::new();
    headers.insert(
        "strict-transport-security".into(),
        "max-age=31536000; includeSubDomains; preload".into(),
    );
    headers.insert("x-content-type-options".into(), "nosniff".into());
    headers.insert("x-frame-options".into(), "SAMEORIGIN".into()); // Wrong value

    let header_results = header_checker.check_headers(&headers);
    for result in &header_results {
        let status_icon = match result.status {
            HeaderStatus::Correct => "✓",
            HeaderStatus::Present => "~",
            HeaderStatus::Misconfigured => "⚠",
            HeaderStatus::Missing => "✗",
        };
        println!(
            "{} {}: {:?}",
            status_icon, result.header.name, result.status
        );
        if let Some(issue) = &result.issue {
            println!("  Issue: {}", issue);
        }
    }

    // OWASP Top 10 coverage
    println!("\n=== OWASP Top 10 Categories ===\n");
    for owasp in OwaspTop10::all() {
        let reqs = checker.requirements_by_owasp(owasp);
        println!("{}: {} requirements", owasp, reqs.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_owasp_top10_all() {
        assert_eq!(OwaspTop10::all().len(), 10);
    }

    #[test]
    fn test_owasp_top10_code() {
        assert_eq!(OwaspTop10::BrokenAccessControl.code(), "A01:2021");
        assert_eq!(OwaspTop10::Injection.code(), "A03:2021");
    }

    #[test]
    fn test_asvs_level_ordering() {
        assert!(AsvsLevel::Level1 < AsvsLevel::Level2);
        assert!(AsvsLevel::Level2 < AsvsLevel::Level3);
    }

    #[test]
    fn test_security_requirement_creation() {
        let req = SecurityRequirement::new("V1.1.1", AsvsCategory::V1Architecture, "Test")
            .with_owasp(OwaspTop10::InsecureDesign)
            .with_level(AsvsLevel::Level2);

        assert_eq!(req.id, "V1.1.1");
        assert!(req.owasp_mapping.contains(&OwaspTop10::InsecureDesign));
        assert_eq!(req.minimum_level, AsvsLevel::Level2);
    }

    #[test]
    fn test_check_result_pass() {
        let req = SecurityRequirement::new("V1", AsvsCategory::V1Architecture, "Test");
        let result = CheckResult::pass(req, "Evidence");
        assert_eq!(result.status, ComplianceStatus::Pass);
    }

    #[test]
    fn test_check_result_fail() {
        let req = SecurityRequirement::new("V1", AsvsCategory::V1Architecture, "Test");
        let result = CheckResult::fail(req, "Evidence", "Fix it");
        assert_eq!(result.status, ComplianceStatus::Fail);
        assert!(result.remediation.is_some());
    }

    #[test]
    fn test_compliance_checker_creation() {
        let checker = OwaspComplianceChecker::new(AsvsLevel::Level1);
        assert!(!checker.requirements.is_empty());
    }

    #[test]
    fn test_requirements_for_level() {
        let checker = OwaspComplianceChecker::new(AsvsLevel::Level1);
        let reqs = checker.requirements_for_level();
        assert!(reqs.iter().all(|r| r.minimum_level <= AsvsLevel::Level1));
    }

    #[test]
    fn test_compliance_score_empty() {
        let checker = OwaspComplianceChecker::new(AsvsLevel::Level1);
        assert_eq!(checker.compliance_score(), 0.0);
    }

    #[test]
    fn test_compliance_score_all_pass() {
        let mut checker = OwaspComplianceChecker::new(AsvsLevel::Level1);
        let req = SecurityRequirement::new("V1", AsvsCategory::V1Architecture, "Test");
        checker.record_result(CheckResult::pass(req, "Evidence"));
        assert_eq!(checker.compliance_score(), 100.0);
    }

    #[test]
    fn test_compliance_score_mixed() {
        let mut checker = OwaspComplianceChecker::new(AsvsLevel::Level1);

        let req1 = SecurityRequirement::new("V1", AsvsCategory::V1Architecture, "Test1");
        checker.record_result(CheckResult::pass(req1, "Evidence"));

        let req2 = SecurityRequirement::new("V2", AsvsCategory::V2Authentication, "Test2");
        checker.record_result(CheckResult::fail(req2, "Evidence", "Fix"));

        assert_eq!(checker.compliance_score(), 50.0);
    }

    #[test]
    fn test_security_header_checker() {
        let checker = SecurityHeaderChecker::new();
        assert!(!checker.required_headers.is_empty());
    }

    #[test]
    fn test_header_check_missing() {
        let checker = SecurityHeaderChecker::new();
        let headers = HashMap::new();
        let results = checker.check_headers(&headers);

        assert!(results.iter().all(|r| r.status == HeaderStatus::Missing));
    }

    #[test]
    fn test_header_check_correct() {
        let checker = SecurityHeaderChecker::new();
        let mut headers = HashMap::new();
        headers.insert("x-content-type-options".into(), "nosniff".into());

        let results = checker.check_headers(&headers);
        let xcto = results
            .iter()
            .find(|r| r.header.name == "X-Content-Type-Options")
            .unwrap();

        assert_eq!(xcto.status, HeaderStatus::Correct);
    }

    #[test]
    fn test_header_check_misconfigured() {
        let checker = SecurityHeaderChecker::new();
        let mut headers = HashMap::new();
        headers.insert("x-frame-options".into(), "SAMEORIGIN".into());

        let results = checker.check_headers(&headers);
        let xfo = results
            .iter()
            .find(|r| r.header.name == "X-Frame-Options")
            .unwrap();

        assert_eq!(xfo.status, HeaderStatus::Misconfigured);
    }

    #[test]
    fn test_asvs_category_name() {
        assert!(AsvsCategory::V2Authentication
            .name()
            .contains("Authentication"));
        assert!(AsvsCategory::V5Validation.name().contains("Validation"));
    }
}
