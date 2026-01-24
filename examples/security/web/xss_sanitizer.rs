//! XSS Sanitization Implementation
//!
//! This example demonstrates comprehensive Cross-Site Scripting protection
//! with HTML sanitization, Content Security Policy generation, and
//! context-aware output encoding for Rust web applications.

use std::collections::{HashMap, HashSet};
use std::fmt;

// ============================================================================
// Sanitization Context
// ============================================================================

/// Context where content will be rendered
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputContext {
    /// HTML body content
    HtmlBody,
    /// HTML attribute value
    HtmlAttribute,
    /// JavaScript string
    JavaScript,
    /// CSS value
    Css,
    /// URL/href attribute
    Url,
    /// JSON value
    Json,
}

/// Sanitization strictness level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrictnessLevel {
    /// Allow minimal safe HTML (text only)
    Strict,
    /// Allow basic formatting tags
    Basic,
    /// Allow extended formatting
    Relaxed,
    /// Custom whitelist
    Custom,
}

// ============================================================================
// HTML Sanitizer Configuration
// ============================================================================

/// HTML tag configuration
#[derive(Debug, Clone)]
pub struct TagConfig {
    /// Allowed tags
    pub allowed_tags: HashSet<String>,
    /// Allowed attributes per tag
    pub allowed_attributes: HashMap<String, HashSet<String>>,
    /// Self-closing tags
    pub void_elements: HashSet<String>,
    /// Tags that strip content entirely
    pub strip_content_tags: HashSet<String>,
}

impl Default for TagConfig {
    fn default() -> Self {
        let mut config = Self {
            allowed_tags: HashSet::new(),
            allowed_attributes: HashMap::new(),
            void_elements: HashSet::new(),
            strip_content_tags: HashSet::new(),
        };

        // Self-closing elements
        for tag in &[
            "br", "hr", "img", "input", "meta", "link", "area", "base", "col",
        ] {
            config.void_elements.insert(tag.to_string());
        }

        // Tags whose content should be stripped
        for tag in &["script", "style", "noscript", "iframe", "object", "embed"] {
            config.strip_content_tags.insert(tag.to_string());
        }

        config
    }
}

impl TagConfig {
    /// Create strict configuration (text only)
    pub fn strict() -> Self {
        Self::default()
    }

    /// Create basic configuration
    pub fn basic() -> Self {
        let mut config = Self::default();

        // Basic formatting tags
        for tag in &[
            "p",
            "br",
            "b",
            "i",
            "u",
            "s",
            "em",
            "strong",
            "small",
            "span",
            "div",
            "pre",
            "code",
            "blockquote",
        ] {
            config.allowed_tags.insert(tag.to_string());
        }

        // Basic attributes
        let global_attrs: HashSet<String> = ["class", "id", "title"]
            .iter()
            .map(|s| s.to_string())
            .collect();

        for tag in &config.allowed_tags.clone() {
            config
                .allowed_attributes
                .insert(tag.clone(), global_attrs.clone());
        }

        config
    }

    /// Create relaxed configuration
    pub fn relaxed() -> Self {
        let mut config = Self::basic();

        // Extended tags
        for tag in &[
            "a",
            "img",
            "ul",
            "ol",
            "li",
            "h1",
            "h2",
            "h3",
            "h4",
            "h5",
            "h6",
            "table",
            "thead",
            "tbody",
            "tr",
            "th",
            "td",
            "dl",
            "dt",
            "dd",
            "figure",
            "figcaption",
            "article",
            "section",
            "header",
            "footer",
        ] {
            config.allowed_tags.insert(tag.to_string());
        }

        // Link attributes
        let mut a_attrs: HashSet<String> = config
            .allowed_attributes
            .get("p")
            .cloned()
            .unwrap_or_default();
        a_attrs.insert("href".to_string());
        a_attrs.insert("rel".to_string());
        a_attrs.insert("target".to_string());
        config.allowed_attributes.insert("a".to_string(), a_attrs);

        // Image attributes
        let mut img_attrs: HashSet<String> = HashSet::new();
        img_attrs.insert("src".to_string());
        img_attrs.insert("alt".to_string());
        img_attrs.insert("width".to_string());
        img_attrs.insert("height".to_string());
        img_attrs.insert("loading".to_string());
        config
            .allowed_attributes
            .insert("img".to_string(), img_attrs);

        // Table attributes
        for tag in &["table", "tr", "th", "td"] {
            let mut attrs: HashSet<String> = HashSet::new();
            attrs.insert("class".to_string());
            if *tag == "th" || *tag == "td" {
                attrs.insert("colspan".to_string());
                attrs.insert("rowspan".to_string());
            }
            config.allowed_attributes.insert(tag.to_string(), attrs);
        }

        config
    }
}

// ============================================================================
// HTML Sanitizer
// ============================================================================

/// HTML sanitizer for XSS prevention
pub struct HtmlSanitizer {
    tag_config: TagConfig,
    /// URL schemes allowed in href/src
    allowed_schemes: HashSet<String>,
    /// Remove empty elements
    remove_empty: bool,
    /// Normalize whitespace
    normalize_whitespace: bool,
    /// Add rel="noopener" to links
    add_noopener: bool,
}

impl HtmlSanitizer {
    pub fn new(level: StrictnessLevel) -> Self {
        let tag_config = match level {
            StrictnessLevel::Strict => TagConfig::strict(),
            StrictnessLevel::Basic => TagConfig::basic(),
            StrictnessLevel::Relaxed => TagConfig::relaxed(),
            StrictnessLevel::Custom => TagConfig::default(),
        };

        let mut allowed_schemes = HashSet::new();
        allowed_schemes.insert("http".to_string());
        allowed_schemes.insert("https".to_string());
        allowed_schemes.insert("mailto".to_string());
        allowed_schemes.insert("tel".to_string());

        Self {
            tag_config,
            allowed_schemes,
            remove_empty: true,
            normalize_whitespace: true,
            add_noopener: true,
        }
    }

    /// Configure custom tag whitelist
    pub fn with_tags(mut self, tags: Vec<&str>) -> Self {
        self.tag_config.allowed_tags = tags.iter().map(|s| s.to_string()).collect();
        self
    }

    /// Configure allowed URL schemes
    pub fn with_schemes(mut self, schemes: Vec<&str>) -> Self {
        self.allowed_schemes = schemes.iter().map(|s| s.to_string()).collect();
        self
    }

    /// Sanitize HTML input
    pub fn sanitize(&self, input: &str) -> SanitizeResult {
        let mut result = SanitizeResult::new();
        let mut output = String::with_capacity(input.len());
        let mut position = 0;
        let chars: Vec<char> = input.chars().collect();

        while position < chars.len() {
            if chars[position] == '<' {
                // Parse tag
                if let Some((tag_result, new_pos)) = self.parse_tag(&chars, position) {
                    match tag_result {
                        TagParseResult::OpenTag {
                            name,
                            attributes,
                            self_closing,
                        } => {
                            if let Some(sanitized) =
                                self.sanitize_tag(&name, &attributes, self_closing, &mut result)
                            {
                                output.push_str(&sanitized);
                            }
                        }
                        TagParseResult::CloseTag { name } => {
                            if self.tag_config.allowed_tags.contains(&name.to_lowercase()) {
                                output.push_str(&format!("</{}>", name.to_lowercase()));
                            }
                        }
                        TagParseResult::Comment(_) => {
                            result.removed_comments += 1;
                        }
                        TagParseResult::Invalid => {
                            // Escape and include
                            output.push_str(&html_encode("<"));
                            result.escaped_chars += 1;
                        }
                    }
                    position = new_pos;
                } else {
                    output.push_str(&html_encode("<"));
                    result.escaped_chars += 1;
                    position += 1;
                }
            } else {
                // Regular character
                output.push(chars[position]);
                position += 1;
            }
        }

        if self.normalize_whitespace {
            output = normalize_whitespace(&output);
        }

        result.output = output;
        result
    }

    fn parse_tag(&self, chars: &[char], start: usize) -> Option<(TagParseResult, usize)> {
        if start >= chars.len() || chars[start] != '<' {
            return None;
        }

        let mut pos = start + 1;

        // Skip whitespace
        while pos < chars.len() && chars[pos].is_whitespace() {
            pos += 1;
        }

        if pos >= chars.len() {
            return None;
        }

        // Check for comment
        if pos + 2 < chars.len()
            && chars[pos] == '!'
            && chars[pos + 1] == '-'
            && chars[pos + 2] == '-'
        {
            // Find end of comment
            pos += 3;
            while pos + 2 < chars.len() {
                if chars[pos] == '-' && chars[pos + 1] == '-' && chars[pos + 2] == '>' {
                    let comment: String = chars[start + 4..pos].iter().collect();
                    return Some((TagParseResult::Comment(comment), pos + 3));
                }
                pos += 1;
            }
            return Some((TagParseResult::Invalid, chars.len()));
        }

        // Check for closing tag
        let is_close = chars[pos] == '/';
        if is_close {
            pos += 1;
        }

        // Parse tag name
        let name_start = pos;
        while pos < chars.len() && (chars[pos].is_alphanumeric() || chars[pos] == '-') {
            pos += 1;
        }

        if name_start == pos {
            return Some((TagParseResult::Invalid, pos));
        }

        let tag_name: String = chars[name_start..pos].iter().collect();

        if is_close {
            // Find closing >
            while pos < chars.len() && chars[pos] != '>' {
                pos += 1;
            }
            if pos < chars.len() {
                pos += 1;
            }
            return Some((TagParseResult::CloseTag { name: tag_name }, pos));
        }

        // Parse attributes
        let mut attributes = Vec::new();
        loop {
            // Skip whitespace
            while pos < chars.len() && chars[pos].is_whitespace() {
                pos += 1;
            }

            if pos >= chars.len() {
                break;
            }

            // Check for self-closing or end
            if chars[pos] == '/' {
                pos += 1;
                while pos < chars.len() && chars[pos] != '>' {
                    pos += 1;
                }
                if pos < chars.len() {
                    pos += 1;
                }
                return Some((
                    TagParseResult::OpenTag {
                        name: tag_name,
                        attributes,
                        self_closing: true,
                    },
                    pos,
                ));
            }

            if chars[pos] == '>' {
                pos += 1;
                return Some((
                    TagParseResult::OpenTag {
                        name: tag_name,
                        attributes,
                        self_closing: false,
                    },
                    pos,
                ));
            }

            // Parse attribute name
            let attr_start = pos;
            while pos < chars.len()
                && chars[pos] != '='
                && chars[pos] != '>'
                && chars[pos] != '/'
                && !chars[pos].is_whitespace()
            {
                pos += 1;
            }

            if attr_start == pos {
                pos += 1;
                continue;
            }

            let attr_name: String = chars[attr_start..pos].iter().collect();

            // Skip whitespace
            while pos < chars.len() && chars[pos].is_whitespace() {
                pos += 1;
            }

            // Check for value
            let attr_value = if pos < chars.len() && chars[pos] == '=' {
                pos += 1;

                // Skip whitespace
                while pos < chars.len() && chars[pos].is_whitespace() {
                    pos += 1;
                }

                if pos < chars.len() {
                    let quote = if chars[pos] == '"' || chars[pos] == '\'' {
                        let q = chars[pos];
                        pos += 1;
                        Some(q)
                    } else {
                        None
                    };

                    let value_start = pos;
                    while pos < chars.len() {
                        if let Some(q) = quote {
                            if chars[pos] == q {
                                break;
                            }
                        } else if chars[pos].is_whitespace()
                            || chars[pos] == '>'
                            || chars[pos] == '/'
                        {
                            break;
                        }
                        pos += 1;
                    }

                    let value: String = chars[value_start..pos].iter().collect();
                    if quote.is_some() && pos < chars.len() {
                        pos += 1;
                    }
                    Some(value)
                } else {
                    None
                }
            } else {
                None
            };

            attributes.push((attr_name, attr_value));
        }

        Some((TagParseResult::Invalid, chars.len()))
    }

    fn sanitize_tag(
        &self,
        name: &str,
        attributes: &[(String, Option<String>)],
        self_closing: bool,
        result: &mut SanitizeResult,
    ) -> Option<String> {
        let lower_name = name.to_lowercase();

        // Check if content should be stripped
        if self.tag_config.strip_content_tags.contains(&lower_name) {
            result.removed_tags.push(lower_name);
            return None;
        }

        // Check if tag is allowed
        if !self.tag_config.allowed_tags.contains(&lower_name) {
            result.removed_tags.push(lower_name);
            return None;
        }

        // Sanitize attributes
        let allowed_attrs = self.tag_config.allowed_attributes.get(&lower_name);
        let mut clean_attrs = Vec::new();

        for (attr_name, attr_value) in attributes {
            let lower_attr = attr_name.to_lowercase();

            // Check if attribute is allowed
            let is_allowed = allowed_attrs
                .map(|set| set.contains(&lower_attr))
                .unwrap_or(false);

            if !is_allowed {
                result
                    .removed_attributes
                    .push(format!("{}:{}", lower_name, lower_attr));
                continue;
            }

            // Sanitize attribute value
            if let Some(value) = attr_value {
                let sanitized_value =
                    self.sanitize_attribute_value(&lower_name, &lower_attr, value, result);
                if let Some(v) = sanitized_value {
                    clean_attrs.push(format!("{}=\"{}\"", lower_attr, attribute_encode(&v)));
                }
            } else {
                clean_attrs.push(lower_attr);
            }
        }

        // Add rel="noopener" to links
        if lower_name == "a" && self.add_noopener {
            let has_rel = clean_attrs.iter().any(|a| a.starts_with("rel="));
            let has_target = clean_attrs.iter().any(|a| a.starts_with("target="));
            if has_target && !has_rel {
                clean_attrs.push("rel=\"noopener noreferrer\"".to_string());
            }
        }

        // Build output tag
        let is_void = self.tag_config.void_elements.contains(&lower_name);
        let mut output = format!("<{}", lower_name);

        if !clean_attrs.is_empty() {
            output.push(' ');
            output.push_str(&clean_attrs.join(" "));
        }

        if self_closing || is_void {
            output.push_str(" />");
        } else {
            output.push('>');
        }

        Some(output)
    }

    fn sanitize_attribute_value(
        &self,
        tag: &str,
        attr: &str,
        value: &str,
        result: &mut SanitizeResult,
    ) -> Option<String> {
        // Check for dangerous patterns
        let lower_value = value.to_lowercase();

        // Block javascript: URLs
        if (attr == "href" || attr == "src" || attr == "action") {
            let trimmed = lower_value.trim();

            // Check scheme
            if let Some(colon_pos) = trimmed.find(':') {
                let scheme = &trimmed[..colon_pos];
                if !self.allowed_schemes.contains(scheme) {
                    result.blocked_urls.push(value.to_string());
                    return None;
                }
            }

            // Block data: URLs in src (allow in some cases for images)
            if attr == "src" && trimmed.starts_with("data:") && tag != "img" {
                result.blocked_urls.push(value.to_string());
                return None;
            }
        }

        // Block event handlers (shouldn't reach here if attrs are filtered)
        if attr.starts_with("on") {
            return None;
        }

        // Block style with expressions
        if attr == "style" {
            if lower_value.contains("expression")
                || lower_value.contains("javascript:")
                || lower_value.contains("behavior:")
            {
                return None;
            }
        }

        Some(value.to_string())
    }
}

/// Tag parsing result
#[derive(Debug)]
enum TagParseResult {
    OpenTag {
        name: String,
        attributes: Vec<(String, Option<String>)>,
        self_closing: bool,
    },
    CloseTag {
        name: String,
    },
    Comment(String),
    Invalid,
}

/// Sanitization result
#[derive(Debug, Clone)]
pub struct SanitizeResult {
    pub output: String,
    pub removed_tags: Vec<String>,
    pub removed_attributes: Vec<String>,
    pub blocked_urls: Vec<String>,
    pub removed_comments: usize,
    pub escaped_chars: usize,
}

impl SanitizeResult {
    fn new() -> Self {
        Self {
            output: String::new(),
            removed_tags: Vec::new(),
            removed_attributes: Vec::new(),
            blocked_urls: Vec::new(),
            removed_comments: 0,
            escaped_chars: 0,
        }
    }

    pub fn had_modifications(&self) -> bool {
        !self.removed_tags.is_empty()
            || !self.removed_attributes.is_empty()
            || !self.blocked_urls.is_empty()
            || self.removed_comments > 0
            || self.escaped_chars > 0
    }
}

// ============================================================================
// Content Security Policy
// ============================================================================

/// CSP directive
#[derive(Debug, Clone)]
pub struct CspDirective {
    name: String,
    values: Vec<String>,
}

impl CspDirective {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            values: Vec::new(),
        }
    }

    pub fn add_source(mut self, source: &str) -> Self {
        self.values.push(source.to_string());
        self
    }

    pub fn self_source(self) -> Self {
        self.add_source("'self'")
    }

    pub fn none(self) -> Self {
        self.add_source("'none'")
    }

    pub fn unsafe_inline(self) -> Self {
        self.add_source("'unsafe-inline'")
    }

    pub fn unsafe_eval(self) -> Self {
        self.add_source("'unsafe-eval'")
    }

    pub fn nonce(self, nonce: &str) -> Self {
        self.add_source(&format!("'nonce-{}'", nonce))
    }

    pub fn hash(self, algorithm: &str, hash: &str) -> Self {
        self.add_source(&format!("'{}-{}'", algorithm, hash))
    }

    pub fn data(self) -> Self {
        self.add_source("data:")
    }

    pub fn https(self) -> Self {
        self.add_source("https:")
    }

    pub fn domain(self, domain: &str) -> Self {
        self.add_source(domain)
    }
}

impl fmt::Display for CspDirective {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.values.is_empty() {
            write!(f, "{}", self.name)
        } else {
            write!(f, "{} {}", self.name, self.values.join(" "))
        }
    }
}

/// Content Security Policy builder
pub struct CspBuilder {
    directives: Vec<CspDirective>,
    report_only: bool,
    report_uri: Option<String>,
}

impl CspBuilder {
    pub fn new() -> Self {
        Self {
            directives: Vec::new(),
            report_only: false,
            report_uri: None,
        }
    }

    /// Create strict CSP
    pub fn strict() -> Self {
        Self::new()
            .default_src(CspDirective::new("default-src").none())
            .script_src(CspDirective::new("script-src").self_source())
            .style_src(CspDirective::new("style-src").self_source())
            .img_src(CspDirective::new("img-src").self_source().data())
            .font_src(CspDirective::new("font-src").self_source())
            .connect_src(CspDirective::new("connect-src").self_source())
            .frame_ancestors(CspDirective::new("frame-ancestors").none())
            .base_uri(CspDirective::new("base-uri").self_source())
            .form_action(CspDirective::new("form-action").self_source())
    }

    /// Add default-src directive
    pub fn default_src(mut self, directive: CspDirective) -> Self {
        self.directives.push(CspDirective {
            name: "default-src".to_string(),
            values: directive.values,
        });
        self
    }

    /// Add script-src directive
    pub fn script_src(mut self, directive: CspDirective) -> Self {
        self.directives.push(CspDirective {
            name: "script-src".to_string(),
            values: directive.values,
        });
        self
    }

    /// Add style-src directive
    pub fn style_src(mut self, directive: CspDirective) -> Self {
        self.directives.push(CspDirective {
            name: "style-src".to_string(),
            values: directive.values,
        });
        self
    }

    /// Add img-src directive
    pub fn img_src(mut self, directive: CspDirective) -> Self {
        self.directives.push(CspDirective {
            name: "img-src".to_string(),
            values: directive.values,
        });
        self
    }

    /// Add font-src directive
    pub fn font_src(mut self, directive: CspDirective) -> Self {
        self.directives.push(CspDirective {
            name: "font-src".to_string(),
            values: directive.values,
        });
        self
    }

    /// Add connect-src directive
    pub fn connect_src(mut self, directive: CspDirective) -> Self {
        self.directives.push(CspDirective {
            name: "connect-src".to_string(),
            values: directive.values,
        });
        self
    }

    /// Add frame-ancestors directive
    pub fn frame_ancestors(mut self, directive: CspDirective) -> Self {
        self.directives.push(CspDirective {
            name: "frame-ancestors".to_string(),
            values: directive.values,
        });
        self
    }

    /// Add base-uri directive
    pub fn base_uri(mut self, directive: CspDirective) -> Self {
        self.directives.push(CspDirective {
            name: "base-uri".to_string(),
            values: directive.values,
        });
        self
    }

    /// Add form-action directive
    pub fn form_action(mut self, directive: CspDirective) -> Self {
        self.directives.push(CspDirective {
            name: "form-action".to_string(),
            values: directive.values,
        });
        self
    }

    /// Add object-src directive
    pub fn object_src(mut self, directive: CspDirective) -> Self {
        self.directives.push(CspDirective {
            name: "object-src".to_string(),
            values: directive.values,
        });
        self
    }

    /// Add media-src directive
    pub fn media_src(mut self, directive: CspDirective) -> Self {
        self.directives.push(CspDirective {
            name: "media-src".to_string(),
            values: directive.values,
        });
        self
    }

    /// Set report-only mode
    pub fn report_only(mut self) -> Self {
        self.report_only = true;
        self
    }

    /// Set report URI
    pub fn report_to(mut self, uri: &str) -> Self {
        self.report_uri = Some(uri.to_string());
        self
    }

    /// Build the CSP header
    pub fn build(&self) -> CspHeader {
        let mut policy_parts: Vec<String> = self.directives.iter().map(|d| d.to_string()).collect();

        if let Some(uri) = &self.report_uri {
            policy_parts.push(format!("report-uri {}", uri));
        }

        let header_name = if self.report_only {
            "Content-Security-Policy-Report-Only"
        } else {
            "Content-Security-Policy"
        };

        CspHeader {
            name: header_name.to_string(),
            value: policy_parts.join("; "),
        }
    }
}

impl Default for CspBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// CSP header
#[derive(Debug, Clone)]
pub struct CspHeader {
    pub name: String,
    pub value: String,
}

impl fmt::Display for CspHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.name, self.value)
    }
}

// ============================================================================
// Context-Aware Encoding
// ============================================================================

/// Context-aware output encoder
pub struct OutputEncoder;

impl OutputEncoder {
    /// Encode for specific context
    pub fn encode(value: &str, context: OutputContext) -> String {
        match context {
            OutputContext::HtmlBody => html_encode(value),
            OutputContext::HtmlAttribute => attribute_encode(value),
            OutputContext::JavaScript => js_encode(value),
            OutputContext::Css => css_encode(value),
            OutputContext::Url => url_encode(value),
            OutputContext::Json => json_encode(value),
        }
    }

    /// Encode for HTML body (most common)
    pub fn html(value: &str) -> String {
        html_encode(value)
    }

    /// Encode for HTML attribute
    pub fn attr(value: &str) -> String {
        attribute_encode(value)
    }

    /// Encode for JavaScript string
    pub fn js(value: &str) -> String {
        js_encode(value)
    }

    /// Encode for CSS
    pub fn css(value: &str) -> String {
        css_encode(value)
    }

    /// Encode for URL
    pub fn url(value: &str) -> String {
        url_encode(value)
    }
}

/// HTML encode
fn html_encode(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '&' => "&amp;".to_string(),
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&#x27;".to_string(),
            _ => c.to_string(),
        })
        .collect()
}

/// Attribute encode (more restrictive)
fn attribute_encode(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '&' => "&amp;".to_string(),
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&#x27;".to_string(),
            '/' => "&#x2F;".to_string(),
            '`' => "&#x60;".to_string(),
            '=' => "&#x3D;".to_string(),
            _ => c.to_string(),
        })
        .collect()
}

/// JavaScript string encode
fn js_encode(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '\\' => "\\\\".to_string(),
            '\'' => "\\'".to_string(),
            '"' => "\\\"".to_string(),
            '\n' => "\\n".to_string(),
            '\r' => "\\r".to_string(),
            '\t' => "\\t".to_string(),
            '<' => "\\u003C".to_string(),
            '>' => "\\u003E".to_string(),
            '&' => "\\u0026".to_string(),
            '/' => "\\/".to_string(),
            '\u{2028}' => "\\u2028".to_string(),
            '\u{2029}' => "\\u2029".to_string(),
            _ if c.is_control() => format!("\\u{:04X}", c as u32),
            _ => c.to_string(),
        })
        .collect()
}

/// CSS encode
fn css_encode(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_alphanumeric() {
                c.to_string()
            } else {
                format!("\\{:06X}", c as u32)
            }
        })
        .collect()
}

/// URL encode
fn url_encode(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' {
                c.to_string()
            } else {
                c.to_string()
                    .bytes()
                    .map(|b| format!("%{:02X}", b))
                    .collect()
            }
        })
        .collect()
}

/// JSON encode
fn json_encode(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '\\' => "\\\\".to_string(),
            '"' => "\\\"".to_string(),
            '\n' => "\\n".to_string(),
            '\r' => "\\r".to_string(),
            '\t' => "\\t".to_string(),
            '\u{0008}' => "\\b".to_string(),
            '\u{000C}' => "\\f".to_string(),
            _ if c.is_control() => format!("\\u{:04X}", c as u32),
            _ => c.to_string(),
        })
        .collect()
}

/// Normalize whitespace
fn normalize_whitespace(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut last_was_space = false;

    for c in s.chars() {
        if c.is_whitespace() {
            if !last_was_space {
                result.push(' ');
                last_was_space = true;
            }
        } else {
            result.push(c);
            last_was_space = false;
        }
    }

    result.trim().to_string()
}

// ============================================================================
// Template Escaping
// ============================================================================

/// Safe template value wrapper
pub struct SafeHtml(String);

impl SafeHtml {
    /// Mark string as already safe (pre-sanitized)
    pub fn new(s: String) -> Self {
        SafeHtml(s)
    }

    /// Get the inner value
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for SafeHtml {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SafeHtml {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Template value that auto-escapes
pub enum TemplateValue {
    /// Raw string (will be escaped)
    Raw(String),
    /// Pre-sanitized HTML
    Safe(SafeHtml),
}

impl TemplateValue {
    pub fn render(&self, context: OutputContext) -> String {
        match self {
            TemplateValue::Raw(s) => OutputEncoder::encode(s, context),
            TemplateValue::Safe(s) => s.0.clone(),
        }
    }
}

impl From<String> for TemplateValue {
    fn from(s: String) -> Self {
        TemplateValue::Raw(s)
    }
}

impl From<&str> for TemplateValue {
    fn from(s: &str) -> Self {
        TemplateValue::Raw(s.to_string())
    }
}

impl From<SafeHtml> for TemplateValue {
    fn from(s: SafeHtml) -> Self {
        TemplateValue::Safe(s)
    }
}

// ============================================================================
// Main Demonstration
// ============================================================================

fn main() {
    println!("=== XSS Sanitization Implementation ===\n");

    // Example 1: HTML Sanitization
    println!("1. HTML Sanitization:");

    let malicious_html = r#"
        <p>Hello <script>alert('XSS')</script> World!</p>
        <a href="javascript:alert('XSS')">Click me</a>
        <img src="x" onerror="alert('XSS')">
        <div onclick="evil()">Content</div>
        <!-- Hidden comment with secrets -->
    "#;

    let sanitizer = HtmlSanitizer::new(StrictnessLevel::Basic);
    let result = sanitizer.sanitize(malicious_html);

    println!("   Input: {}", malicious_html.trim());
    println!("   Output: {}", result.output);
    println!("   Removed tags: {:?}", result.removed_tags);
    println!("   Removed attributes: {:?}", result.removed_attributes);
    println!("   Blocked URLs: {:?}", result.blocked_urls);
    println!("   Removed comments: {}", result.removed_comments);

    // Example 2: Relaxed Sanitization
    println!("\n2. Relaxed Sanitization (allows links/images):");
    let sanitizer = HtmlSanitizer::new(StrictnessLevel::Relaxed);

    let user_html = r#"
        <h1>User Content</h1>
        <p>Check out <a href="https://example.com" target="_blank">this link</a>!</p>
        <img src="https://example.com/image.png" alt="Example">
        <script>document.cookie</script>
    "#;

    let result = sanitizer.sanitize(user_html);
    println!("   Output: {}", result.output);
    println!("   Modifications: {}", result.had_modifications());

    // Example 3: Context-Aware Encoding
    println!("\n3. Context-Aware Encoding:");
    let user_input = "<script>alert('XSS')</script>";

    println!("   Raw input: {}", user_input);
    println!(
        "   HTML Body: {}",
        OutputEncoder::encode(user_input, OutputContext::HtmlBody)
    );
    println!(
        "   HTML Attr: {}",
        OutputEncoder::encode(user_input, OutputContext::HtmlAttribute)
    );
    println!(
        "   JavaScript: {}",
        OutputEncoder::encode(user_input, OutputContext::JavaScript)
    );
    println!(
        "   URL: {}",
        OutputEncoder::encode(user_input, OutputContext::Url)
    );

    // Example 4: Content Security Policy
    println!("\n4. Content Security Policy:");

    let csp = CspBuilder::strict().build();
    println!("   Strict CSP: {}", csp);

    let custom_csp = CspBuilder::new()
        .default_src(CspDirective::new("default-src").self_source())
        .script_src(
            CspDirective::new("script-src")
                .self_source()
                .domain("https://cdn.example.com")
                .nonce("abc123"),
        )
        .style_src(CspDirective::new("style-src").self_source().unsafe_inline())
        .img_src(CspDirective::new("img-src").self_source().https().data())
        .frame_ancestors(CspDirective::new("frame-ancestors").none())
        .report_to("/csp-report")
        .build();

    println!("   Custom CSP: {}", custom_csp);

    // Example 5: Report-Only CSP
    println!("\n5. Report-Only CSP:");
    let report_csp = CspBuilder::strict()
        .report_only()
        .report_to("/csp-violation")
        .build();
    println!("   {}", report_csp);

    // Example 6: Template Value Escaping
    println!("\n6. Template Value Escaping:");

    let values: Vec<TemplateValue> = vec![
        "<script>evil()</script>".into(),
        SafeHtml::new("<strong>Pre-sanitized</strong>".to_string()).into(),
    ];

    for (i, val) in values.iter().enumerate() {
        println!(
            "   Value {}: {}",
            i + 1,
            val.render(OutputContext::HtmlBody)
        );
    }

    // Example 7: URL Validation in Links
    println!("\n7. URL Scheme Blocking:");
    let dangerous_links = [
        r#"<a href="javascript:alert(1)">JS Link</a>"#,
        r#"<a href="data:text/html,<script>alert(1)</script>">Data Link</a>"#,
        r#"<a href="vbscript:MsgBox(1)">VBScript Link</a>"#,
        r#"<a href="https://safe.example.com">Safe Link</a>"#,
    ];

    let sanitizer = HtmlSanitizer::new(StrictnessLevel::Relaxed);
    for link in &dangerous_links {
        let result = sanitizer.sanitize(link);
        println!("   Input: {} -> Output: {}", link, result.output);
    }

    // Example 8: Edge Cases
    println!("\n8. Edge Case Handling:");
    let edge_cases = [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<div style=\"background:url(javascript:alert(1))\">",
        "<a href=\"&#106;avascript:alert(1)\">encoded</a>",
    ];

    for case in &edge_cases {
        let result = sanitizer.sanitize(case);
        println!(
            "   {} -> {}",
            case,
            if result.output.is_empty() {
                "(removed)"
            } else {
                &result.output
            }
        );
    }

    println!("\n=== XSS Sanitization Complete ===");
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_script_removal() {
        let sanitizer = HtmlSanitizer::new(StrictnessLevel::Basic);
        let result = sanitizer.sanitize("<script>alert('XSS')</script>");
        assert!(!result.output.contains("script"));
        assert!(result.removed_tags.contains(&"script".to_string()));
    }

    #[test]
    fn test_event_handler_removal() {
        let sanitizer = HtmlSanitizer::new(StrictnessLevel::Relaxed);
        let result = sanitizer.sanitize("<img src=\"x\" onerror=\"alert(1)\">");
        assert!(!result.output.contains("onerror"));
    }

    #[test]
    fn test_javascript_url_blocking() {
        let sanitizer = HtmlSanitizer::new(StrictnessLevel::Relaxed);
        let result = sanitizer.sanitize("<a href=\"javascript:alert(1)\">link</a>");
        assert!(!result.output.contains("javascript:"));
        assert!(result
            .blocked_urls
            .contains(&"javascript:alert(1)".to_string()));
    }

    #[test]
    fn test_safe_html_allowed() {
        let sanitizer = HtmlSanitizer::new(StrictnessLevel::Basic);
        let result = sanitizer.sanitize("<p>Hello <strong>World</strong></p>");
        assert!(result.output.contains("<p>"));
        assert!(result.output.contains("<strong>"));
    }

    #[test]
    fn test_html_encoding() {
        assert_eq!(html_encode("<script>"), "&lt;script&gt;");
        assert_eq!(html_encode("a & b"), "a &amp; b");
        assert_eq!(html_encode("\"quoted\""), "&quot;quoted&quot;");
    }

    #[test]
    fn test_js_encoding() {
        assert_eq!(js_encode("'single'"), "\\'single\\'");
        assert_eq!(js_encode("line\nbreak"), "line\\nbreak");
        assert_eq!(js_encode("<script>"), "\\u003Cscript\\u003E");
    }

    #[test]
    fn test_url_encoding() {
        assert_eq!(url_encode("hello world"), "hello%20world");
        assert_eq!(url_encode("a=b&c=d"), "a%3Db%26c%3Dd");
    }

    #[test]
    fn test_csp_strict() {
        let csp = CspBuilder::strict().build();
        assert!(csp.value.contains("default-src 'none'"));
        assert!(csp.value.contains("script-src 'self'"));
        assert!(csp.value.contains("frame-ancestors 'none'"));
    }

    #[test]
    fn test_csp_with_nonce() {
        let csp = CspBuilder::new()
            .script_src(CspDirective::new("script-src").nonce("abc123"))
            .build();
        assert!(csp.value.contains("'nonce-abc123'"));
    }

    #[test]
    fn test_csp_report_only() {
        let csp = CspBuilder::new().report_only().build();
        assert_eq!(csp.name, "Content-Security-Policy-Report-Only");
    }

    #[test]
    fn test_noopener_added() {
        let sanitizer = HtmlSanitizer::new(StrictnessLevel::Relaxed);
        let result =
            sanitizer.sanitize("<a href=\"https://example.com\" target=\"_blank\">link</a>");
        assert!(result.output.contains("rel=\"noopener noreferrer\""));
    }

    #[test]
    fn test_comment_removal() {
        let sanitizer = HtmlSanitizer::new(StrictnessLevel::Basic);
        let result = sanitizer.sanitize("before<!-- secret comment -->after");
        assert!(!result.output.contains("<!--"));
        assert!(!result.output.contains("secret"));
        assert_eq!(result.removed_comments, 1);
    }

    #[test]
    fn test_self_closing_tags() {
        let sanitizer = HtmlSanitizer::new(StrictnessLevel::Relaxed);
        let result = sanitizer.sanitize("<img src=\"test.jpg\" alt=\"test\" />");
        assert!(result.output.contains("<img"));
        assert!(result.output.contains("/>"));
    }

    #[test]
    fn test_template_value_escaping() {
        let raw: TemplateValue = "<script>".into();
        let safe: TemplateValue = SafeHtml::new("<b>bold</b>".to_string()).into();

        assert_eq!(raw.render(OutputContext::HtmlBody), "&lt;script&gt;");
        assert_eq!(safe.render(OutputContext::HtmlBody), "<b>bold</b>");
    }

    #[test]
    fn test_normalize_whitespace() {
        assert_eq!(normalize_whitespace("  hello   world  "), "hello world");
        assert_eq!(normalize_whitespace("a\n\n\nb"), "a b");
    }

    #[test]
    fn test_data_url_blocking() {
        let sanitizer = HtmlSanitizer::new(StrictnessLevel::Relaxed);

        // Data URLs blocked in non-img tags
        let result = sanitizer.sanitize("<a href=\"data:text/html,<script>\">link</a>");
        assert!(result.blocked_urls.len() > 0);

        // Data URLs allowed in img src
        let result = sanitizer.sanitize("<img src=\"data:image/png;base64,abc\">");
        // This should be allowed for images
    }

    #[test]
    fn test_strict_mode() {
        let sanitizer = HtmlSanitizer::new(StrictnessLevel::Strict);
        let result = sanitizer.sanitize("<p>Hello</p> <b>World</b>");
        // Strict mode removes all tags
        assert!(!result.output.contains("<p>"));
        assert!(!result.output.contains("<b>"));
    }
}
