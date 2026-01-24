//! XSS Prevention and Content Security
//!
//! Comprehensive XSS prevention with input sanitization, output encoding,
//! Content Security Policy generation, and DOM-based XSS protection.

use std::collections::{HashMap, HashSet};

/// XSS prevention configuration
#[derive(Debug, Clone)]
pub struct XssConfig {
    /// Enable HTML encoding
    pub encode_html: bool,
    /// Enable JavaScript encoding
    pub encode_js: bool,
    /// Enable URL encoding
    pub encode_url: bool,
    /// Enable CSS encoding
    pub encode_css: bool,
    /// Allowed HTML tags
    pub allowed_tags: HashSet<String>,
    /// Allowed HTML attributes
    pub allowed_attributes: HashSet<String>,
    /// Strip dangerous protocols
    pub strip_protocols: bool,
}

impl Default for XssConfig {
    fn default() -> Self {
        let mut allowed_tags = HashSet::new();
        for tag in &[
            "p", "br", "strong", "em", "ul", "ol", "li", "a", "span", "div",
        ] {
            allowed_tags.insert(tag.to_string());
        }

        let mut allowed_attributes = HashSet::new();
        for attr in &["href", "class", "id", "title"] {
            allowed_attributes.insert(attr.to_string());
        }

        Self {
            encode_html: true,
            encode_js: true,
            encode_url: true,
            encode_css: true,
            allowed_tags,
            allowed_attributes,
            strip_protocols: true,
        }
    }
}

/// XSS sanitizer for user input
#[derive(Debug)]
pub struct XssSanitizer {
    config: XssConfig,
}

impl XssSanitizer {
    pub fn new(config: XssConfig) -> Self {
        Self { config }
    }

    /// Sanitize HTML input
    pub fn sanitize_html(&self, input: &str) -> String {
        let mut result = String::with_capacity(input.len());
        let mut in_tag = false;
        let mut current_tag = String::new();
        let mut chars = input.chars().peekable();

        while let Some(ch) = chars.next() {
            match ch {
                '<' => {
                    in_tag = true;
                    current_tag.clear();
                }
                '>' if in_tag => {
                    in_tag = false;
                    if let Some(sanitized) = self.sanitize_tag(&current_tag) {
                        result.push('<');
                        result.push_str(&sanitized);
                        result.push('>');
                    }
                }
                _ if in_tag => {
                    current_tag.push(ch);
                }
                _ => {
                    if self.config.encode_html {
                        result.push_str(&Self::encode_html_char(ch));
                    } else {
                        result.push(ch);
                    }
                }
            }
        }

        result
    }

    /// Sanitize a single HTML tag
    fn sanitize_tag(&self, tag: &str) -> Option<String> {
        let tag = tag.trim();
        let is_closing = tag.starts_with('/');
        let tag_content = if is_closing { &tag[1..] } else { tag };

        // Extract tag name
        let tag_name = tag_content
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_lowercase();

        if !self.config.allowed_tags.contains(&tag_name) {
            return None;
        }

        // Parse and filter attributes
        let mut result = if is_closing {
            format!("/{}", tag_name)
        } else {
            tag_name.clone()
        };

        if !is_closing {
            let attrs = self.extract_attributes(tag_content);
            for (name, value) in attrs {
                if self.config.allowed_attributes.contains(&name) {
                    let safe_value = self.sanitize_attribute_value(&name, &value);
                    result.push_str(&format!(" {}=\"{}\"", name, safe_value));
                }
            }
        }

        Some(result)
    }

    /// Extract attributes from tag content
    fn extract_attributes(&self, tag_content: &str) -> Vec<(String, String)> {
        let mut attributes = Vec::new();
        let parts: Vec<&str> = tag_content.split_whitespace().collect();

        for part in parts.iter().skip(1) {
            if let Some(eq_pos) = part.find('=') {
                let name = part[..eq_pos].to_lowercase();
                let value = part[eq_pos + 1..]
                    .trim_matches('"')
                    .trim_matches('\'')
                    .to_string();
                attributes.push((name, value));
            }
        }

        attributes
    }

    /// Sanitize attribute value
    fn sanitize_attribute_value(&self, name: &str, value: &str) -> String {
        let mut sanitized = value.to_string();

        // Strip dangerous protocols for href/src attributes
        if self.config.strip_protocols && (name == "href" || name == "src") {
            let dangerous_protocols = ["javascript:", "vbscript:", "data:", "file:"];

            let lower_value = value.to_lowercase();
            for proto in &dangerous_protocols {
                if lower_value.starts_with(proto) {
                    return "#".to_string();
                }
            }
        }

        // Encode special characters
        sanitized = sanitized
            .replace('&', "&amp;")
            .replace('"', "&quot;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");

        sanitized
    }

    /// Encode HTML character
    fn encode_html_char(ch: char) -> String {
        match ch {
            '&' => "&amp;".to_string(),
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&#x27;".to_string(),
            '/' => "&#x2F;".to_string(),
            _ => ch.to_string(),
        }
    }

    /// Encode for JavaScript context
    pub fn encode_js(&self, input: &str) -> String {
        let mut result = String::with_capacity(input.len() * 2);

        for ch in input.chars() {
            match ch {
                '\\' => result.push_str("\\\\"),
                '\'' => result.push_str("\\'"),
                '"' => result.push_str("\\\""),
                '\n' => result.push_str("\\n"),
                '\r' => result.push_str("\\r"),
                '\t' => result.push_str("\\t"),
                '<' => result.push_str("\\u003C"),
                '>' => result.push_str("\\u003E"),
                '&' => result.push_str("\\u0026"),
                '=' => result.push_str("\\u003D"),
                _ if ch.is_ascii_alphanumeric() || ch == ' ' => result.push(ch),
                _ => {
                    let code = ch as u32;
                    if code < 256 {
                        result.push_str(&format!("\\x{:02X}", code));
                    } else {
                        result.push_str(&format!("\\u{:04X}", code));
                    }
                }
            }
        }

        result
    }

    /// Encode for URL context
    pub fn encode_url(&self, input: &str) -> String {
        let mut result = String::with_capacity(input.len() * 3);

        for ch in input.chars() {
            if ch.is_ascii_alphanumeric() || "-_.~".contains(ch) {
                result.push(ch);
            } else {
                for byte in ch.to_string().bytes() {
                    result.push_str(&format!("%{:02X}", byte));
                }
            }
        }

        result
    }

    /// Encode for CSS context
    pub fn encode_css(&self, input: &str) -> String {
        let mut result = String::with_capacity(input.len() * 2);

        for ch in input.chars() {
            if ch.is_ascii_alphanumeric() {
                result.push(ch);
            } else {
                result.push_str(&format!("\\{:06X}", ch as u32));
            }
        }

        result
    }
}

/// Content Security Policy builder
#[derive(Debug, Clone, Default)]
pub struct CspBuilder {
    directives: HashMap<String, Vec<String>>,
    report_uri: Option<String>,
    report_only: bool,
}

impl CspBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set default-src directive
    pub fn default_src(mut self, sources: &[&str]) -> Self {
        self.add_directive("default-src", sources);
        self
    }

    /// Set script-src directive
    pub fn script_src(mut self, sources: &[&str]) -> Self {
        self.add_directive("script-src", sources);
        self
    }

    /// Set style-src directive
    pub fn style_src(mut self, sources: &[&str]) -> Self {
        self.add_directive("style-src", sources);
        self
    }

    /// Set img-src directive
    pub fn img_src(mut self, sources: &[&str]) -> Self {
        self.add_directive("img-src", sources);
        self
    }

    /// Set connect-src directive
    pub fn connect_src(mut self, sources: &[&str]) -> Self {
        self.add_directive("connect-src", sources);
        self
    }

    /// Set font-src directive
    pub fn font_src(mut self, sources: &[&str]) -> Self {
        self.add_directive("font-src", sources);
        self
    }

    /// Set frame-src directive
    pub fn frame_src(mut self, sources: &[&str]) -> Self {
        self.add_directive("frame-src", sources);
        self
    }

    /// Set object-src directive
    pub fn object_src(mut self, sources: &[&str]) -> Self {
        self.add_directive("object-src", sources);
        self
    }

    /// Set media-src directive
    pub fn media_src(mut self, sources: &[&str]) -> Self {
        self.add_directive("media-src", sources);
        self
    }

    /// Set base-uri directive
    pub fn base_uri(mut self, sources: &[&str]) -> Self {
        self.add_directive("base-uri", sources);
        self
    }

    /// Set form-action directive
    pub fn form_action(mut self, sources: &[&str]) -> Self {
        self.add_directive("form-action", sources);
        self
    }

    /// Set frame-ancestors directive
    pub fn frame_ancestors(mut self, sources: &[&str]) -> Self {
        self.add_directive("frame-ancestors", sources);
        self
    }

    /// Block all plugins
    pub fn block_plugins(mut self) -> Self {
        self.add_directive("object-src", &["'none'"]);
        self
    }

    /// Upgrade insecure requests
    pub fn upgrade_insecure(mut self) -> Self {
        self.add_directive("upgrade-insecure-requests", &[]);
        self
    }

    /// Block mixed content
    pub fn block_mixed_content(mut self) -> Self {
        self.add_directive("block-all-mixed-content", &[]);
        self
    }

    /// Set report URI
    pub fn report_uri(mut self, uri: &str) -> Self {
        self.report_uri = Some(uri.to_string());
        self
    }

    /// Set to report-only mode
    pub fn report_only(mut self) -> Self {
        self.report_only = true;
        self
    }

    /// Add a directive
    fn add_directive(&mut self, name: &str, sources: &[&str]) {
        self.directives.insert(
            name.to_string(),
            sources.iter().map(|s| s.to_string()).collect(),
        );
    }

    /// Generate a nonce for inline scripts
    pub fn generate_nonce() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("nonce-{:x}", timestamp)
    }

    /// Build the CSP header value
    pub fn build(&self) -> CspHeader {
        let mut parts = Vec::new();

        for (directive, sources) in &self.directives {
            if sources.is_empty() {
                parts.push(directive.clone());
            } else {
                parts.push(format!("{} {}", directive, sources.join(" ")));
            }
        }

        if let Some(ref uri) = self.report_uri {
            parts.push(format!("report-uri {}", uri));
        }

        let header_name = if self.report_only {
            "Content-Security-Policy-Report-Only"
        } else {
            "Content-Security-Policy"
        };

        CspHeader {
            name: header_name.to_string(),
            value: parts.join("; "),
        }
    }

    /// Create a strict CSP policy
    pub fn strict() -> Self {
        Self::new()
            .default_src(&["'none'"])
            .script_src(&["'self'"])
            .style_src(&["'self'"])
            .img_src(&["'self'", "data:"])
            .font_src(&["'self'"])
            .connect_src(&["'self'"])
            .base_uri(&["'self'"])
            .form_action(&["'self'"])
            .frame_ancestors(&["'none'"])
            .block_plugins()
            .upgrade_insecure()
    }
}

/// CSP header representation
#[derive(Debug, Clone)]
pub struct CspHeader {
    pub name: String,
    pub value: String,
}

/// DOM-based XSS detection patterns
#[derive(Debug)]
pub struct DomXssDetector {
    dangerous_sinks: Vec<&'static str>,
    dangerous_sources: Vec<&'static str>,
}

impl Default for DomXssDetector {
    fn default() -> Self {
        Self {
            dangerous_sinks: vec![
                "innerHTML",
                "outerHTML",
                "document.write",
                "document.writeln",
                "eval(",
                "setTimeout(",
                "setInterval(",
                "Function(",
                "execScript(",
                ".src",
                ".href",
                ".action",
                ".data",
            ],
            dangerous_sources: vec![
                "location.hash",
                "location.search",
                "location.href",
                "document.URL",
                "document.documentURI",
                "document.referrer",
                "window.name",
                "postMessage",
            ],
        }
    }
}

impl DomXssDetector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Analyze JavaScript code for DOM XSS vulnerabilities
    pub fn analyze(&self, js_code: &str) -> Vec<DomXssVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for dangerous patterns
        for (line_num, line) in js_code.lines().enumerate() {
            // Check for dangerous sinks
            for sink in &self.dangerous_sinks {
                if line.contains(sink) {
                    // Check if any dangerous source is used
                    for source in &self.dangerous_sources {
                        if line.contains(source) {
                            vulnerabilities.push(DomXssVulnerability {
                                line: line_num + 1,
                                sink: sink.to_string(),
                                source: source.to_string(),
                                code: line.trim().to_string(),
                                severity: self.calculate_severity(sink, source),
                            });
                        }
                    }
                }
            }
        }

        vulnerabilities
    }

    /// Calculate severity based on sink and source
    fn calculate_severity(&self, sink: &str, _source: &str) -> Severity {
        if sink.contains("eval") || sink.contains("Function") || sink.contains("execScript") {
            Severity::Critical
        } else if sink.contains("innerHTML") || sink.contains("document.write") {
            Severity::High
        } else if sink.contains(".src") || sink.contains(".href") {
            Severity::Medium
        } else {
            Severity::Low
        }
    }
}

/// DOM XSS vulnerability
#[derive(Debug)]
pub struct DomXssVulnerability {
    pub line: usize,
    pub sink: String,
    pub source: String,
    pub code: String,
    pub severity: Severity,
}

/// Severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
        }
    }
}

fn main() {
    println!("=== XSS Prevention Demo ===\n");

    // HTML Sanitization
    let sanitizer = XssSanitizer::new(XssConfig::default());

    let malicious_html = r#"
        <script>alert('XSS')</script>
        <p onclick="evil()">Hello</p>
        <a href="javascript:alert(1)">Click me</a>
        <img src="x" onerror="alert('XSS')">
        <div>Safe content</div>
    "#;

    println!("Original HTML:\n{}", malicious_html);
    println!(
        "\nSanitized HTML:\n{}",
        sanitizer.sanitize_html(malicious_html)
    );

    // JavaScript encoding
    let user_input = "'; alert('XSS'); //";
    println!("\nJS Encoding:");
    println!("  Input: {}", user_input);
    println!("  Encoded: {}", sanitizer.encode_js(user_input));

    // URL encoding
    let url_input = "query=<script>alert(1)</script>";
    println!("\nURL Encoding:");
    println!("  Input: {}", url_input);
    println!("  Encoded: {}", sanitizer.encode_url(url_input));

    // CSS encoding
    let css_input = "expression(alert(1))";
    println!("\nCSS Encoding:");
    println!("  Input: {}", css_input);
    println!("  Encoded: {}", sanitizer.encode_css(css_input));

    // Content Security Policy
    println!("\n=== Content Security Policy ===\n");

    let csp = CspBuilder::strict().report_uri("/csp-report").build();

    println!("Header: {}", csp.name);
    println!("Value: {}", csp.value);

    // Generate nonce
    let nonce = CspBuilder::generate_nonce();
    println!("\nGenerated nonce: {}", nonce);

    // DOM XSS Detection
    println!("\n=== DOM XSS Detection ===\n");

    let vulnerable_js = r#"
        var data = location.hash.substring(1);
        document.getElementById('output').innerHTML = data;

        var param = location.search.split('=')[1];
        eval(param);

        var msg = window.name;
        document.write(msg);
    "#;

    let detector = DomXssDetector::new();
    let vulnerabilities = detector.analyze(vulnerable_js);

    println!("Found {} DOM XSS vulnerabilities:", vulnerabilities.len());
    for vuln in &vulnerabilities {
        println!("\n  Line {}: [{}]", vuln.line, vuln.severity);
        println!("    Sink: {}", vuln.sink);
        println!("    Source: {}", vuln.source);
        println!("    Code: {}", vuln.code);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_html_sanitization_removes_script_tags() {
        let sanitizer = XssSanitizer::new(XssConfig::default());
        let input = "<script>alert('xss')</script>";
        let result = sanitizer.sanitize_html(input);
        assert!(!result.contains("<script>"));
        assert!(!result.contains("alert"));
    }

    #[test]
    fn test_html_sanitization_allows_safe_tags() {
        let sanitizer = XssSanitizer::new(XssConfig::default());
        let input = "<p>Hello</p>";
        let result = sanitizer.sanitize_html(input);
        assert!(result.contains("<p>"));
        assert!(result.contains("</p>"));
    }

    #[test]
    fn test_html_sanitization_strips_event_handlers() {
        let sanitizer = XssSanitizer::new(XssConfig::default());
        let input = "<p onclick=\"evil()\">Hello</p>";
        let result = sanitizer.sanitize_html(input);
        assert!(!result.contains("onclick"));
    }

    #[test]
    fn test_javascript_protocol_stripped() {
        let sanitizer = XssSanitizer::new(XssConfig::default());
        let input = "<a href=\"javascript:alert(1)\">Click</a>";
        let result = sanitizer.sanitize_html(input);
        assert!(!result.contains("javascript:"));
    }

    #[test]
    fn test_js_encoding() {
        let sanitizer = XssSanitizer::new(XssConfig::default());
        let result = sanitizer.encode_js("'; alert('xss'); //");
        assert!(result.contains("\\'"));
        assert!(!result.contains("'"));
    }

    #[test]
    fn test_url_encoding() {
        let sanitizer = XssSanitizer::new(XssConfig::default());
        let result = sanitizer.encode_url("<script>");
        assert!(!result.contains('<'));
        assert!(result.contains("%3C"));
    }

    #[test]
    fn test_css_encoding() {
        let sanitizer = XssSanitizer::new(XssConfig::default());
        let result = sanitizer.encode_css("expression(");
        assert!(!result.contains('('));
    }

    #[test]
    fn test_csp_strict_policy() {
        let csp = CspBuilder::strict().build();
        assert!(csp.value.contains("default-src 'none'"));
        assert!(csp.value.contains("script-src 'self'"));
        assert!(csp.value.contains("object-src 'none'"));
    }

    #[test]
    fn test_csp_report_only() {
        let csp = CspBuilder::new()
            .default_src(&["'self'"])
            .report_only()
            .build();
        assert_eq!(csp.name, "Content-Security-Policy-Report-Only");
    }

    #[test]
    fn test_csp_nonce_generation() {
        let nonce1 = CspBuilder::generate_nonce();
        let nonce2 = CspBuilder::generate_nonce();
        assert!(nonce1.starts_with("nonce-"));
        // Nonces should be different (time-based)
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_dom_xss_detection() {
        let detector = DomXssDetector::new();
        let code = "document.getElementById('x').innerHTML = location.hash;";
        let vulns = detector.analyze(code);
        assert!(!vulns.is_empty());
        assert_eq!(vulns[0].sink, "innerHTML");
        assert_eq!(vulns[0].source, "location.hash");
    }

    #[test]
    fn test_dom_xss_severity() {
        let detector = DomXssDetector::new();
        let code = "eval(location.search);";
        let vulns = detector.analyze(code);
        assert!(!vulns.is_empty());
        assert_eq!(vulns[0].severity, Severity::Critical);
    }

    #[test]
    fn test_safe_code_no_vulnerabilities() {
        let detector = DomXssDetector::new();
        let code = "var x = 5; console.log(x);";
        let vulns = detector.analyze(code);
        assert!(vulns.is_empty());
    }
}
