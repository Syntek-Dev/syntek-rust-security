//! Rust Documentation Generator
//!
//! Tools for generating rustdoc documentation, doc tests, README files,
//! and API documentation with security-focused annotations.

use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Documentation item types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocItemType {
    Module,
    Struct,
    Enum,
    Trait,
    Function,
    Method,
    Const,
    Static,
    Type,
    Macro,
}

impl DocItemType {
    pub fn as_str(&self) -> &'static str {
        match self {
            DocItemType::Module => "module",
            DocItemType::Struct => "struct",
            DocItemType::Enum => "enum",
            DocItemType::Trait => "trait",
            DocItemType::Function => "function",
            DocItemType::Method => "method",
            DocItemType::Const => "constant",
            DocItemType::Static => "static",
            DocItemType::Type => "type alias",
            DocItemType::Macro => "macro",
        }
    }
}

/// Security consideration for documentation
#[derive(Debug, Clone)]
pub struct SecurityNote {
    pub category: SecurityCategory,
    pub description: String,
    pub severity: SecuritySeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityCategory {
    Memory,
    Cryptography,
    Input,
    Authentication,
    Authorization,
    DataValidation,
    SideChannel,
    Concurrency,
    ResourceExhaustion,
}

impl SecurityCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            SecurityCategory::Memory => "Memory Safety",
            SecurityCategory::Cryptography => "Cryptography",
            SecurityCategory::Input => "Input Handling",
            SecurityCategory::Authentication => "Authentication",
            SecurityCategory::Authorization => "Authorization",
            SecurityCategory::DataValidation => "Data Validation",
            SecurityCategory::SideChannel => "Side-Channel",
            SecurityCategory::Concurrency => "Concurrency",
            SecurityCategory::ResourceExhaustion => "Resource Exhaustion",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecuritySeverity {
    Info,
    Warning,
    Critical,
}

/// A documentation example
#[derive(Debug, Clone)]
pub struct DocExample {
    pub title: String,
    pub description: String,
    pub code: String,
    pub should_panic: bool,
    pub no_run: bool,
    pub ignore: bool,
    pub compile_fail: bool,
}

impl DocExample {
    pub fn new(title: &str, code: &str) -> Self {
        Self {
            title: title.into(),
            description: String::new(),
            code: code.into(),
            should_panic: false,
            no_run: false,
            ignore: false,
            compile_fail: false,
        }
    }

    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = desc.into();
        self
    }

    pub fn should_panic(mut self) -> Self {
        self.should_panic = true;
        self
    }

    pub fn no_run(mut self) -> Self {
        self.no_run = true;
        self
    }

    pub fn to_rustdoc(&self) -> String {
        let mut doc = String::new();

        if !self.title.is_empty() {
            doc.push_str(&format!("/// # {}\n", self.title));
        }

        if !self.description.is_empty() {
            doc.push_str("///\n");
            for line in self.description.lines() {
                doc.push_str(&format!("/// {}\n", line));
            }
        }

        doc.push_str("///\n");
        doc.push_str("/// ```");

        let mut attrs = vec![];
        if self.should_panic {
            attrs.push("should_panic");
        }
        if self.no_run {
            attrs.push("no_run");
        }
        if self.ignore {
            attrs.push("ignore");
        }
        if self.compile_fail {
            attrs.push("compile_fail");
        }

        if !attrs.is_empty() {
            doc.push_str(&attrs.join(","));
        }
        doc.push('\n');

        for line in self.code.lines() {
            doc.push_str(&format!("/// {}\n", line));
        }

        doc.push_str("/// ```\n");
        doc
    }
}

/// A documentation item (function, struct, etc.)
#[derive(Debug, Clone)]
pub struct DocItem {
    pub name: String,
    pub item_type: DocItemType,
    pub summary: String,
    pub description: String,
    pub parameters: Vec<DocParameter>,
    pub returns: Option<DocReturn>,
    pub examples: Vec<DocExample>,
    pub security_notes: Vec<SecurityNote>,
    pub panics: Vec<String>,
    pub errors: Vec<String>,
    pub safety: Option<String>,
    pub deprecated: Option<String>,
    pub since: Option<String>,
    pub see_also: Vec<String>,
}

impl DocItem {
    pub fn new(name: &str, item_type: DocItemType) -> Self {
        Self {
            name: name.into(),
            item_type,
            summary: String::new(),
            description: String::new(),
            parameters: vec![],
            returns: None,
            examples: vec![],
            security_notes: vec![],
            panics: vec![],
            errors: vec![],
            safety: None,
            deprecated: None,
            since: None,
            see_also: vec![],
        }
    }

    pub fn with_summary(mut self, summary: &str) -> Self {
        self.summary = summary.into();
        self
    }

    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = desc.into();
        self
    }

    pub fn with_param(mut self, param: DocParameter) -> Self {
        self.parameters.push(param);
        self
    }

    pub fn with_returns(mut self, ret: DocReturn) -> Self {
        self.returns = Some(ret);
        self
    }

    pub fn with_example(mut self, example: DocExample) -> Self {
        self.examples.push(example);
        self
    }

    pub fn with_security_note(mut self, note: SecurityNote) -> Self {
        self.security_notes.push(note);
        self
    }

    pub fn with_panic(mut self, panic: &str) -> Self {
        self.panics.push(panic.into());
        self
    }

    pub fn with_error(mut self, error: &str) -> Self {
        self.errors.push(error.into());
        self
    }

    pub fn unsafe_fn(mut self, safety: &str) -> Self {
        self.safety = Some(safety.into());
        self
    }

    pub fn deprecated(mut self, reason: &str) -> Self {
        self.deprecated = Some(reason.into());
        self
    }

    pub fn since(mut self, version: &str) -> Self {
        self.since = Some(version.into());
        self
    }

    /// Generate rustdoc comment
    pub fn to_rustdoc(&self) -> String {
        let mut doc = String::new();

        // Summary (first line)
        if !self.summary.is_empty() {
            doc.push_str(&format!("/// {}\n", self.summary));
            doc.push_str("///\n");
        }

        // Description
        if !self.description.is_empty() {
            for line in self.description.lines() {
                if line.is_empty() {
                    doc.push_str("///\n");
                } else {
                    doc.push_str(&format!("/// {}\n", line));
                }
            }
            doc.push_str("///\n");
        }

        // Parameters
        if !self.parameters.is_empty() {
            doc.push_str("/// # Arguments\n///\n");
            for param in &self.parameters {
                doc.push_str(&format!("/// * `{}` - {}\n", param.name, param.description));
            }
            doc.push_str("///\n");
        }

        // Returns
        if let Some(ret) = &self.returns {
            doc.push_str("/// # Returns\n///\n");
            doc.push_str(&format!("/// {}\n", ret.description));
            doc.push_str("///\n");
        }

        // Errors
        if !self.errors.is_empty() {
            doc.push_str("/// # Errors\n///\n");
            for error in &self.errors {
                doc.push_str(&format!("/// * {}\n", error));
            }
            doc.push_str("///\n");
        }

        // Panics
        if !self.panics.is_empty() {
            doc.push_str("/// # Panics\n///\n");
            for panic in &self.panics {
                doc.push_str(&format!("/// * {}\n", panic));
            }
            doc.push_str("///\n");
        }

        // Safety (for unsafe functions)
        if let Some(safety) = &self.safety {
            doc.push_str("/// # Safety\n///\n");
            for line in safety.lines() {
                doc.push_str(&format!("/// {}\n", line));
            }
            doc.push_str("///\n");
        }

        // Security notes
        if !self.security_notes.is_empty() {
            doc.push_str("/// # Security Considerations\n///\n");
            for note in &self.security_notes {
                let severity = match note.severity {
                    SecuritySeverity::Info => "ℹ️",
                    SecuritySeverity::Warning => "⚠️",
                    SecuritySeverity::Critical => "🔴",
                };
                doc.push_str(&format!(
                    "/// {} **{}**: {}\n",
                    severity,
                    note.category.as_str(),
                    note.description
                ));
            }
            doc.push_str("///\n");
        }

        // Examples
        for example in &self.examples {
            doc.push_str(&example.to_rustdoc());
        }

        // Deprecated
        if let Some(reason) = &self.deprecated {
            doc.push_str(&format!("#[deprecated(note = \"{}\")]\n", reason));
        }

        doc
    }
}

/// Function/method parameter documentation
#[derive(Debug, Clone)]
pub struct DocParameter {
    pub name: String,
    pub param_type: String,
    pub description: String,
    pub optional: bool,
    pub default: Option<String>,
}

impl DocParameter {
    pub fn new(name: &str, param_type: &str, description: &str) -> Self {
        Self {
            name: name.into(),
            param_type: param_type.into(),
            description: description.into(),
            optional: false,
            default: None,
        }
    }

    pub fn optional(mut self, default: Option<&str>) -> Self {
        self.optional = true;
        self.default = default.map(|s| s.into());
        self
    }
}

/// Return value documentation
#[derive(Debug, Clone)]
pub struct DocReturn {
    pub return_type: String,
    pub description: String,
}

impl DocReturn {
    pub fn new(return_type: &str, description: &str) -> Self {
        Self {
            return_type: return_type.into(),
            description: description.into(),
        }
    }
}

/// Module-level documentation
#[derive(Debug, Clone)]
pub struct ModuleDoc {
    pub name: String,
    pub summary: String,
    pub description: String,
    pub items: Vec<DocItem>,
    pub submodules: Vec<String>,
    pub examples: Vec<DocExample>,
    pub security_notes: Vec<SecurityNote>,
}

impl ModuleDoc {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.into(),
            summary: String::new(),
            description: String::new(),
            items: vec![],
            submodules: vec![],
            examples: vec![],
            security_notes: vec![],
        }
    }

    pub fn to_rustdoc(&self) -> String {
        let mut doc = String::new();

        doc.push_str(&format!("//! {}\n", self.summary));
        doc.push_str("//!\n");

        if !self.description.is_empty() {
            for line in self.description.lines() {
                if line.is_empty() {
                    doc.push_str("//!\n");
                } else {
                    doc.push_str(&format!("//! {}\n", line));
                }
            }
            doc.push_str("//!\n");
        }

        // Security notes
        if !self.security_notes.is_empty() {
            doc.push_str("//! # Security Considerations\n//!\n");
            for note in &self.security_notes {
                doc.push_str(&format!(
                    "//! - **{}**: {}\n",
                    note.category.as_str(),
                    note.description
                ));
            }
            doc.push_str("//!\n");
        }

        // Examples
        for example in &self.examples {
            doc.push_str(&format!("//! # {}\n//!\n", example.title));
            if !example.description.is_empty() {
                doc.push_str(&format!("//! {}\n//!\n", example.description));
            }
            doc.push_str("//! ```rust\n");
            for line in example.code.lines() {
                doc.push_str(&format!("//! {}\n", line));
            }
            doc.push_str("//! ```\n//!\n");
        }

        doc
    }
}

/// README generator
#[derive(Debug)]
pub struct ReadmeGenerator {
    pub project_name: String,
    pub description: String,
    pub badges: Vec<Badge>,
    pub sections: Vec<ReadmeSection>,
    pub installation: Option<String>,
    pub usage_examples: Vec<DocExample>,
    pub features: Vec<Feature>,
    pub license: Option<String>,
    pub authors: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Badge {
    pub name: String,
    pub image_url: String,
    pub link_url: Option<String>,
}

impl Badge {
    pub fn crates_io(crate_name: &str) -> Self {
        Self {
            name: "Crates.io".into(),
            image_url: format!("https://img.shields.io/crates/v/{}.svg", crate_name),
            link_url: Some(format!("https://crates.io/crates/{}", crate_name)),
        }
    }

    pub fn docs_rs(crate_name: &str) -> Self {
        Self {
            name: "Documentation".into(),
            image_url: format!("https://docs.rs/{}/badge.svg", crate_name),
            link_url: Some(format!("https://docs.rs/{}", crate_name)),
        }
    }

    pub fn github_actions(owner: &str, repo: &str, workflow: &str) -> Self {
        Self {
            name: "Build Status".into(),
            image_url: format!(
                "https://github.com/{}/{}/actions/workflows/{}/badge.svg",
                owner, repo, workflow
            ),
            link_url: Some(format!(
                "https://github.com/{}/{}/actions/workflows/{}",
                owner, repo, workflow
            )),
        }
    }

    pub fn license(license: &str) -> Self {
        Self {
            name: "License".into(),
            image_url: format!(
                "https://img.shields.io/badge/license-{}-blue.svg",
                license.replace('-', "--")
            ),
            link_url: None,
        }
    }

    pub fn to_markdown(&self) -> String {
        let img = format!("![{}]({})", self.name, self.image_url);
        if let Some(link) = &self.link_url {
            format!("[{}]({})", img, link)
        } else {
            img
        }
    }
}

#[derive(Debug, Clone)]
pub struct Feature {
    pub name: String,
    pub description: String,
    pub default: bool,
}

#[derive(Debug, Clone)]
pub struct ReadmeSection {
    pub title: String,
    pub content: String,
    pub level: u8,
}

impl ReadmeGenerator {
    pub fn new(project_name: &str, description: &str) -> Self {
        Self {
            project_name: project_name.into(),
            description: description.into(),
            badges: vec![],
            sections: vec![],
            installation: None,
            usage_examples: vec![],
            features: vec![],
            license: None,
            authors: vec![],
        }
    }

    pub fn with_badge(mut self, badge: Badge) -> Self {
        self.badges.push(badge);
        self
    }

    pub fn with_section(mut self, title: &str, content: &str) -> Self {
        self.sections.push(ReadmeSection {
            title: title.into(),
            content: content.into(),
            level: 2,
        });
        self
    }

    pub fn with_installation(mut self, install: &str) -> Self {
        self.installation = Some(install.into());
        self
    }

    pub fn with_example(mut self, example: DocExample) -> Self {
        self.usage_examples.push(example);
        self
    }

    pub fn with_feature(mut self, name: &str, description: &str, default: bool) -> Self {
        self.features.push(Feature {
            name: name.into(),
            description: description.into(),
            default,
        });
        self
    }

    pub fn with_license(mut self, license: &str) -> Self {
        self.license = Some(license.into());
        self
    }

    pub fn with_author(mut self, author: &str) -> Self {
        self.authors.push(author.into());
        self
    }

    pub fn generate(&self) -> String {
        let mut md = String::new();

        // Title
        md.push_str(&format!("# {}\n\n", self.project_name));

        // Badges
        if !self.badges.is_empty() {
            for badge in &self.badges {
                md.push_str(&badge.to_markdown());
                md.push(' ');
            }
            md.push_str("\n\n");
        }

        // Description
        md.push_str(&self.description);
        md.push_str("\n\n");

        // Installation
        if let Some(install) = &self.installation {
            md.push_str("## Installation\n\n");
            md.push_str(install);
            md.push_str("\n\n");
        } else {
            // Default Cargo installation
            md.push_str("## Installation\n\n");
            md.push_str("Add this to your `Cargo.toml`:\n\n");
            md.push_str("```toml\n");
            md.push_str(&format!(
                "[dependencies]\n{} = \"*\"\n",
                self.project_name.to_lowercase().replace(' ', "-")
            ));
            md.push_str("```\n\n");
        }

        // Features
        if !self.features.is_empty() {
            md.push_str("## Features\n\n");
            for feature in &self.features {
                let default_str = if feature.default { " (default)" } else { "" };
                md.push_str(&format!(
                    "- **{}**{}: {}\n",
                    feature.name, default_str, feature.description
                ));
            }
            md.push_str("\n");
        }

        // Usage examples
        if !self.usage_examples.is_empty() {
            md.push_str("## Usage\n\n");
            for example in &self.usage_examples {
                if !example.title.is_empty() {
                    md.push_str(&format!("### {}\n\n", example.title));
                }
                if !example.description.is_empty() {
                    md.push_str(&example.description);
                    md.push_str("\n\n");
                }
                md.push_str("```rust\n");
                md.push_str(&example.code);
                md.push_str("\n```\n\n");
            }
        }

        // Custom sections
        for section in &self.sections {
            let header = "#".repeat(section.level as usize);
            md.push_str(&format!("{} {}\n\n", header, section.title));
            md.push_str(&section.content);
            md.push_str("\n\n");
        }

        // License
        if let Some(license) = &self.license {
            md.push_str("## License\n\n");
            md.push_str(&format!(
                "This project is licensed under the {} License.\n\n",
                license
            ));
        }

        // Authors
        if !self.authors.is_empty() {
            md.push_str("## Authors\n\n");
            for author in &self.authors {
                md.push_str(&format!("- {}\n", author));
            }
            md.push_str("\n");
        }

        md
    }

    pub fn write_to_file<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        let content = self.generate();
        fs::write(path, content)
    }
}

/// API documentation builder
#[derive(Debug)]
pub struct ApiDocBuilder {
    pub modules: HashMap<String, ModuleDoc>,
    pub items: Vec<DocItem>,
}

impl ApiDocBuilder {
    pub fn new() -> Self {
        Self {
            modules: HashMap::new(),
            items: vec![],
        }
    }

    pub fn add_module(&mut self, module: ModuleDoc) {
        self.modules.insert(module.name.clone(), module);
    }

    pub fn add_item(&mut self, item: DocItem) {
        self.items.push(item);
    }

    /// Generate documentation as markdown
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();

        // API Reference header
        md.push_str("# API Reference\n\n");

        // Modules
        if !self.modules.is_empty() {
            md.push_str("## Modules\n\n");
            for (name, module) in &self.modules {
                md.push_str(&format!("### `{}`\n\n", name));
                md.push_str(&format!("{}\n\n", module.summary));
            }
        }

        // Items by type
        let mut by_type: HashMap<DocItemType, Vec<&DocItem>> = HashMap::new();
        for item in &self.items {
            by_type.entry(item.item_type).or_default().push(item);
        }

        let type_order = [
            DocItemType::Struct,
            DocItemType::Enum,
            DocItemType::Trait,
            DocItemType::Function,
            DocItemType::Type,
            DocItemType::Const,
            DocItemType::Macro,
        ];

        for item_type in &type_order {
            if let Some(items) = by_type.get(item_type) {
                let type_name = match item_type {
                    DocItemType::Struct => "Structs",
                    DocItemType::Enum => "Enums",
                    DocItemType::Trait => "Traits",
                    DocItemType::Function => "Functions",
                    DocItemType::Type => "Type Aliases",
                    DocItemType::Const => "Constants",
                    DocItemType::Macro => "Macros",
                    _ => continue,
                };

                md.push_str(&format!("## {}\n\n", type_name));

                for item in items {
                    md.push_str(&format!("### `{}`\n\n", item.name));
                    md.push_str(&format!("{}\n\n", item.summary));

                    if !item.description.is_empty() {
                        md.push_str(&format!("{}\n\n", item.description));
                    }

                    // Parameters
                    if !item.parameters.is_empty() {
                        md.push_str("**Parameters:**\n\n");
                        for param in &item.parameters {
                            md.push_str(&format!(
                                "- `{}` (`{}`): {}\n",
                                param.name, param.param_type, param.description
                            ));
                        }
                        md.push_str("\n");
                    }

                    // Returns
                    if let Some(ret) = &item.returns {
                        md.push_str(&format!(
                            "**Returns:** `{}` - {}\n\n",
                            ret.return_type, ret.description
                        ));
                    }

                    // Security notes
                    if !item.security_notes.is_empty() {
                        md.push_str("**Security Considerations:**\n\n");
                        for note in &item.security_notes {
                            md.push_str(&format!(
                                "- ⚠️ {}: {}\n",
                                note.category.as_str(),
                                note.description
                            ));
                        }
                        md.push_str("\n");
                    }
                }
            }
        }

        md
    }
}

fn main() {
    println!("Rust Documentation Generator\n");

    // Create a doc item
    let encrypt_fn = DocItem::new("encrypt", DocItemType::Function)
        .with_summary("Encrypts data using AES-256-GCM.")
        .with_description("This function encrypts the provided plaintext using AES-256-GCM\nwith the specified key and generates a random nonce.")
        .with_param(DocParameter::new("key", "&[u8; 32]", "The 256-bit encryption key"))
        .with_param(DocParameter::new("plaintext", "&[u8]", "The data to encrypt"))
        .with_returns(DocReturn::new("Result<Vec<u8>, CryptoError>", "The encrypted ciphertext with nonce prepended"))
        .with_error("Returns `CryptoError::InvalidKey` if the key is not 32 bytes")
        .with_security_note(SecurityNote {
            category: SecurityCategory::Cryptography,
            description: "Key must be generated using a CSPRNG".into(),
            severity: SecuritySeverity::Critical,
        })
        .with_security_note(SecurityNote {
            category: SecurityCategory::Memory,
            description: "Key is zeroized on drop".into(),
            severity: SecuritySeverity::Info,
        })
        .with_example(DocExample::new(
            "Basic Encryption",
            r#"use my_crate::encrypt;

let key = [0u8; 32]; // Use proper key derivation!
let plaintext = b"secret data";
let ciphertext = encrypt(&key, plaintext)?;"#,
        ).with_description("Encrypt some data with a 256-bit key."));

    println!("=== Generated Rustdoc ===\n");
    println!("{}", encrypt_fn.to_rustdoc());

    // Create module documentation
    let mut module = ModuleDoc::new("crypto");
    module.summary = "Cryptographic primitives for secure data handling.".into();
    module.description = "This module provides authenticated encryption using AES-256-GCM\nand secure key derivation using Argon2.".into();
    module.security_notes.push(SecurityNote {
        category: SecurityCategory::Cryptography,
        description: "All keys should be derived using the provided KDF functions.".into(),
        severity: SecuritySeverity::Warning,
    });

    println!("=== Module Documentation ===\n");
    println!("{}", module.to_rustdoc());

    // Generate README
    println!("=== Generated README.md ===\n");

    let readme = ReadmeGenerator::new(
        "secure-crypto",
        "A security-focused cryptography library for Rust providing authenticated encryption, secure key derivation, and memory-safe secret handling.",
    )
    .with_badge(Badge::crates_io("secure-crypto"))
    .with_badge(Badge::docs_rs("secure-crypto"))
    .with_badge(Badge::license("MIT"))
    .with_feature("aes-gcm", "AES-256-GCM authenticated encryption", true)
    .with_feature("argon2", "Argon2id password hashing", true)
    .with_feature("zeroize", "Secure memory wiping", true)
    .with_example(DocExample::new(
        "Encrypt Data",
        r#"use secure_crypto::{encrypt, Key};

let key = Key::generate();
let plaintext = b"Hello, World!";
let ciphertext = encrypt(&key, plaintext)?;"#,
    ))
    .with_section(
        "Security",
        "This library follows best practices for cryptographic implementations:\n\n- Constant-time comparisons for all security-sensitive operations\n- Automatic memory zeroization for sensitive data\n- No unsafe code in the public API",
    )
    .with_license("MIT")
    .with_author("Security Team <security@example.com>");

    println!("{}", readme.generate());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_doc_example_basic() {
        let example = DocExample::new("Test", "let x = 1;");
        let rustdoc = example.to_rustdoc();
        assert!(rustdoc.contains("# Test"));
        assert!(rustdoc.contains("let x = 1;"));
    }

    #[test]
    fn test_doc_example_should_panic() {
        let example = DocExample::new("Test", "panic!()").should_panic();
        let rustdoc = example.to_rustdoc();
        assert!(rustdoc.contains("should_panic"));
    }

    #[test]
    fn test_doc_example_no_run() {
        let example = DocExample::new("Test", "loop {}").no_run();
        let rustdoc = example.to_rustdoc();
        assert!(rustdoc.contains("no_run"));
    }

    #[test]
    fn test_doc_item_creation() {
        let item = DocItem::new("test_fn", DocItemType::Function).with_summary("A test function");

        assert_eq!(item.name, "test_fn");
        assert_eq!(item.summary, "A test function");
    }

    #[test]
    fn test_doc_item_with_params() {
        let item = DocItem::new("add", DocItemType::Function)
            .with_param(DocParameter::new("a", "i32", "First number"))
            .with_param(DocParameter::new("b", "i32", "Second number"));

        assert_eq!(item.parameters.len(), 2);
    }

    #[test]
    fn test_doc_item_to_rustdoc() {
        let item = DocItem::new("test", DocItemType::Function)
            .with_summary("Test function")
            .with_param(DocParameter::new("x", "i32", "Input value"))
            .with_returns(DocReturn::new("i32", "Output value"));

        let doc = item.to_rustdoc();
        assert!(doc.contains("Test function"));
        assert!(doc.contains("# Arguments"));
        assert!(doc.contains("# Returns"));
    }

    #[test]
    fn test_security_note() {
        let item = DocItem::new("hash", DocItemType::Function).with_security_note(SecurityNote {
            category: SecurityCategory::Cryptography,
            description: "Use with caution".into(),
            severity: SecuritySeverity::Warning,
        });

        let doc = item.to_rustdoc();
        assert!(doc.contains("Security Considerations"));
        assert!(doc.contains("Cryptography"));
    }

    #[test]
    fn test_deprecated_item() {
        let item = DocItem::new("old_fn", DocItemType::Function).deprecated("Use new_fn instead");

        let doc = item.to_rustdoc();
        assert!(doc.contains("#[deprecated"));
        assert!(doc.contains("Use new_fn instead"));
    }

    #[test]
    fn test_module_doc() {
        let module = ModuleDoc::new("test_module");
        assert_eq!(module.name, "test_module");
    }

    #[test]
    fn test_badge_crates_io() {
        let badge = Badge::crates_io("my-crate");
        let md = badge.to_markdown();
        assert!(md.contains("crates.io"));
        assert!(md.contains("my-crate"));
    }

    #[test]
    fn test_readme_generator() {
        let readme = ReadmeGenerator::new("test-project", "A test project").with_license("MIT");

        let content = readme.generate();
        assert!(content.contains("# test-project"));
        assert!(content.contains("A test project"));
        assert!(content.contains("MIT License"));
    }

    #[test]
    fn test_readme_with_badges() {
        let readme = ReadmeGenerator::new("test", "Test").with_badge(Badge::crates_io("test"));

        let content = readme.generate();
        assert!(content.contains("!["));
    }

    #[test]
    fn test_readme_with_features() {
        let readme = ReadmeGenerator::new("test", "Test")
            .with_feature("feature1", "First feature", true)
            .with_feature("feature2", "Second feature", false);

        let content = readme.generate();
        assert!(content.contains("## Features"));
        assert!(content.contains("feature1"));
        assert!(content.contains("(default)"));
    }

    #[test]
    fn test_api_doc_builder() {
        let mut builder = ApiDocBuilder::new();
        builder.add_item(DocItem::new("test_fn", DocItemType::Function).with_summary("Test"));

        let md = builder.to_markdown();
        assert!(content contains "test_fn");
    }

    #[test]
    fn test_doc_parameter_optional() {
        let param =
            DocParameter::new("timeout", "Duration", "Request timeout").optional(Some("30s"));

        assert!(param.optional);
        assert_eq!(param.default, Some("30s".into()));
    }

    fn content_contains(content: &str, needle: &str) -> bool {
        content.contains(needle)
    }
}
