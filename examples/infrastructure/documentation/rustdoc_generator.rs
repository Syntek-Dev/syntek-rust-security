//! Rustdoc and Documentation Generator
//!
//! Implements documentation generation for Rust projects including rustdoc,
//! doc tests, and comprehensive API documentation.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Documentation generator configuration
#[derive(Debug, Clone)]
pub struct DocConfig {
    /// Project root path
    pub project_root: PathBuf,
    /// Output directory for docs
    pub output_dir: PathBuf,
    /// Include private items
    pub document_private: bool,
    /// Include hidden items
    pub document_hidden: bool,
    /// Enable doc tests
    pub enable_doc_tests: bool,
    /// Generate search index
    pub generate_search_index: bool,
    /// Custom CSS file
    pub custom_css: Option<PathBuf>,
    /// Logo path
    pub logo: Option<PathBuf>,
    /// Additional HTML in header
    pub html_in_header: Option<String>,
    /// Features to document
    pub features: Vec<String>,
    /// All features
    pub all_features: bool,
}

impl Default for DocConfig {
    fn default() -> Self {
        Self {
            project_root: PathBuf::from("."),
            output_dir: PathBuf::from("target/doc"),
            document_private: false,
            document_hidden: false,
            enable_doc_tests: true,
            generate_search_index: true,
            custom_css: None,
            logo: None,
            html_in_header: None,
            features: Vec::new(),
            all_features: false,
        }
    }
}

/// Documentation item
#[derive(Debug, Clone)]
pub struct DocItem {
    /// Item name
    pub name: String,
    /// Item type
    pub item_type: DocItemType,
    /// Module path
    pub module_path: Vec<String>,
    /// Documentation comment
    pub doc_comment: Option<String>,
    /// Visibility
    pub visibility: Visibility,
    /// Attributes
    pub attributes: Vec<String>,
    /// Source location
    pub source_location: Option<SourceLocation>,
    /// Child items
    pub children: Vec<DocItem>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DocItemType {
    Module,
    Struct,
    Enum,
    Trait,
    Function,
    Method,
    Constant,
    Static,
    TypeAlias,
    Macro,
    Impl,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Visibility {
    Public,
    Crate,
    Private,
    Restricted(String),
}

#[derive(Debug, Clone)]
pub struct SourceLocation {
    pub file: PathBuf,
    pub line: usize,
    pub column: usize,
}

/// Doc test result
#[derive(Debug, Clone)]
pub struct DocTestResult {
    /// Test name/location
    pub name: String,
    /// Module path
    pub module_path: String,
    /// Whether test passed
    pub passed: bool,
    /// Error message if failed
    pub error: Option<String>,
    /// Test duration
    pub duration_ms: u64,
}

/// Documentation generator
pub struct DocGenerator {
    config: DocConfig,
    /// Parsed documentation items
    items: Vec<DocItem>,
    /// Statistics
    stats: DocStats,
}

#[derive(Debug, Default, Clone)]
pub struct DocStats {
    pub modules_documented: u32,
    pub structs_documented: u32,
    pub enums_documented: u32,
    pub traits_documented: u32,
    pub functions_documented: u32,
    pub items_without_docs: u32,
    pub doc_tests_found: u32,
    pub doc_tests_passed: u32,
    pub doc_tests_failed: u32,
}

impl DocGenerator {
    /// Create new documentation generator
    pub fn new(config: DocConfig) -> Self {
        Self {
            config,
            items: Vec::new(),
            stats: DocStats::default(),
        }
    }

    /// Parse source files for documentation
    pub fn parse_sources(&mut self) -> io::Result<()> {
        let src_dir = self.config.project_root.join("src");

        if src_dir.exists() {
            self.parse_directory(&src_dir, vec![])?;
        }

        Ok(())
    }

    fn parse_directory(&mut self, path: &Path, module_path: Vec<String>) -> io::Result<()> {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let entry_path = entry.path();

            if entry_path.is_dir() {
                // Check for mod.rs
                let mod_rs = entry_path.join("mod.rs");
                if mod_rs.exists() {
                    let mod_name = entry_path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown")
                        .to_string();

                    let mut new_path = module_path.clone();
                    new_path.push(mod_name);

                    self.parse_directory(&entry_path, new_path)?;
                }
            } else if entry_path.extension().map_or(false, |e| e == "rs") {
                self.parse_file(&entry_path, module_path.clone())?;
            }
        }

        Ok(())
    }

    fn parse_file(&mut self, path: &Path, module_path: Vec<String>) -> io::Result<()> {
        let content = fs::read_to_string(path)?;
        let items = self.parse_rust_source(&content, path, module_path);
        self.items.extend(items);
        Ok(())
    }

    fn parse_rust_source(
        &mut self,
        content: &str,
        file: &Path,
        module_path: Vec<String>,
    ) -> Vec<DocItem> {
        let mut items = Vec::new();
        let mut current_doc = String::new();
        let mut line_number = 0usize;

        for line in content.lines() {
            line_number += 1;
            let trimmed = line.trim();

            // Collect doc comments
            if trimmed.starts_with("///") {
                let doc_line = trimmed.strip_prefix("///").unwrap_or("").trim();
                if !current_doc.is_empty() {
                    current_doc.push('\n');
                }
                current_doc.push_str(doc_line);
                continue;
            }

            // Check for item declarations
            if let Some(item) =
                self.parse_item_declaration(trimmed, &current_doc, file, line_number, &module_path)
            {
                self.update_stats(&item);
                items.push(item);
            }

            // Reset doc comment if not continuing
            if !trimmed.starts_with("///") && !trimmed.starts_with("#[") && !trimmed.is_empty() {
                current_doc.clear();
            }
        }

        items
    }

    fn parse_item_declaration(
        &self,
        line: &str,
        doc_comment: &str,
        file: &Path,
        line_number: usize,
        module_path: &[String],
    ) -> Option<DocItem> {
        let visibility = self.extract_visibility(line);
        let line_after_vis = self.strip_visibility(line);

        // Parse different item types
        if line_after_vis.starts_with("struct ") {
            let name = self.extract_name(line_after_vis.strip_prefix("struct ")?);
            return Some(DocItem {
                name,
                item_type: DocItemType::Struct,
                module_path: module_path.to_vec(),
                doc_comment: if doc_comment.is_empty() {
                    None
                } else {
                    Some(doc_comment.to_string())
                },
                visibility,
                attributes: Vec::new(),
                source_location: Some(SourceLocation {
                    file: file.to_path_buf(),
                    line: line_number,
                    column: 0,
                }),
                children: Vec::new(),
            });
        }

        if line_after_vis.starts_with("enum ") {
            let name = self.extract_name(line_after_vis.strip_prefix("enum ")?);
            return Some(DocItem {
                name,
                item_type: DocItemType::Enum,
                module_path: module_path.to_vec(),
                doc_comment: if doc_comment.is_empty() {
                    None
                } else {
                    Some(doc_comment.to_string())
                },
                visibility,
                attributes: Vec::new(),
                source_location: Some(SourceLocation {
                    file: file.to_path_buf(),
                    line: line_number,
                    column: 0,
                }),
                children: Vec::new(),
            });
        }

        if line_after_vis.starts_with("trait ") {
            let name = self.extract_name(line_after_vis.strip_prefix("trait ")?);
            return Some(DocItem {
                name,
                item_type: DocItemType::Trait,
                module_path: module_path.to_vec(),
                doc_comment: if doc_comment.is_empty() {
                    None
                } else {
                    Some(doc_comment.to_string())
                },
                visibility,
                attributes: Vec::new(),
                source_location: Some(SourceLocation {
                    file: file.to_path_buf(),
                    line: line_number,
                    column: 0,
                }),
                children: Vec::new(),
            });
        }

        if line_after_vis.starts_with("fn ") {
            let name = self.extract_name(line_after_vis.strip_prefix("fn ")?);
            return Some(DocItem {
                name,
                item_type: DocItemType::Function,
                module_path: module_path.to_vec(),
                doc_comment: if doc_comment.is_empty() {
                    None
                } else {
                    Some(doc_comment.to_string())
                },
                visibility,
                attributes: Vec::new(),
                source_location: Some(SourceLocation {
                    file: file.to_path_buf(),
                    line: line_number,
                    column: 0,
                }),
                children: Vec::new(),
            });
        }

        if line_after_vis.starts_with("const ") {
            let name = self.extract_const_name(line_after_vis.strip_prefix("const ")?);
            return Some(DocItem {
                name,
                item_type: DocItemType::Constant,
                module_path: module_path.to_vec(),
                doc_comment: if doc_comment.is_empty() {
                    None
                } else {
                    Some(doc_comment.to_string())
                },
                visibility,
                attributes: Vec::new(),
                source_location: Some(SourceLocation {
                    file: file.to_path_buf(),
                    line: line_number,
                    column: 0,
                }),
                children: Vec::new(),
            });
        }

        if line_after_vis.starts_with("mod ") {
            let name = self.extract_name(line_after_vis.strip_prefix("mod ")?);
            self.stats.modules_documented += 1;
            return Some(DocItem {
                name,
                item_type: DocItemType::Module,
                module_path: module_path.to_vec(),
                doc_comment: if doc_comment.is_empty() {
                    None
                } else {
                    Some(doc_comment.to_string())
                },
                visibility,
                attributes: Vec::new(),
                source_location: Some(SourceLocation {
                    file: file.to_path_buf(),
                    line: line_number,
                    column: 0,
                }),
                children: Vec::new(),
            });
        }

        None
    }

    fn extract_visibility(&self, line: &str) -> Visibility {
        if line.starts_with("pub(crate)") {
            Visibility::Crate
        } else if line.starts_with("pub(super)") {
            Visibility::Restricted("super".to_string())
        } else if line.starts_with("pub(in ") {
            let path = line
                .strip_prefix("pub(in ")
                .and_then(|s| s.split(')').next())
                .unwrap_or("unknown")
                .to_string();
            Visibility::Restricted(path)
        } else if line.starts_with("pub ") {
            Visibility::Public
        } else {
            Visibility::Private
        }
    }

    fn strip_visibility<'a>(&self, line: &'a str) -> &'a str {
        if line.starts_with("pub(crate) ") {
            line.strip_prefix("pub(crate) ").unwrap_or(line)
        } else if line.starts_with("pub(super) ") {
            line.strip_prefix("pub(super) ").unwrap_or(line)
        } else if line.starts_with("pub(in ") {
            // Find closing paren
            if let Some(end) = line.find(") ") {
                &line[end + 2..]
            } else {
                line
            }
        } else if line.starts_with("pub ") {
            line.strip_prefix("pub ").unwrap_or(line)
        } else {
            line
        }
    }

    fn extract_name(&self, s: &str) -> String {
        s.split(|c: char| !c.is_alphanumeric() && c != '_')
            .next()
            .unwrap_or("unknown")
            .to_string()
    }

    fn extract_const_name(&self, s: &str) -> String {
        s.split(':')
            .next()
            .map(|s| s.trim())
            .unwrap_or("unknown")
            .to_string()
    }

    fn update_stats(&mut self, item: &DocItem) {
        match item.item_type {
            DocItemType::Module => self.stats.modules_documented += 1,
            DocItemType::Struct => self.stats.structs_documented += 1,
            DocItemType::Enum => self.stats.enums_documented += 1,
            DocItemType::Trait => self.stats.traits_documented += 1,
            DocItemType::Function => self.stats.functions_documented += 1,
            _ => {}
        }

        if item.doc_comment.is_none() && item.visibility == Visibility::Public {
            self.stats.items_without_docs += 1;
        }
    }

    /// Extract doc tests from documentation
    pub fn extract_doc_tests(&self) -> Vec<DocTest> {
        let mut tests = Vec::new();

        for item in &self.items {
            if let Some(ref doc) = item.doc_comment {
                tests.extend(self.extract_tests_from_doc(doc, &item.name, &item.module_path));
            }
        }

        tests
    }

    fn extract_tests_from_doc(
        &self,
        doc: &str,
        item_name: &str,
        module_path: &[String],
    ) -> Vec<DocTest> {
        let mut tests = Vec::new();
        let mut in_code_block = false;
        let mut code_block = String::new();
        let mut test_index = 0;

        for line in doc.lines() {
            if line.starts_with("```") {
                if in_code_block {
                    // End of code block
                    let test = DocTest {
                        name: format!("{}_{}", item_name, test_index),
                        module_path: module_path.join("::"),
                        code: code_block.clone(),
                        should_panic: false,
                        no_run: line.contains("no_run"),
                        ignore: line.contains("ignore"),
                    };
                    tests.push(test);
                    test_index += 1;
                    code_block.clear();
                }
                in_code_block = !in_code_block;
            } else if in_code_block {
                code_block.push_str(line);
                code_block.push('\n');
            }
        }

        tests
    }

    /// Generate HTML documentation
    pub fn generate_html(&self) -> io::Result<()> {
        fs::create_dir_all(&self.config.output_dir)?;

        // Generate index
        self.generate_index_html()?;

        // Generate module pages
        for item in &self.items {
            if item.item_type == DocItemType::Module {
                self.generate_module_html(item)?;
            }
        }

        // Generate CSS
        self.generate_css()?;

        Ok(())
    }

    fn generate_index_html(&self) -> io::Result<()> {
        let mut html = String::new();
        html.push_str("<!DOCTYPE html>\n<html>\n<head>\n");
        html.push_str("<meta charset=\"utf-8\">\n");
        html.push_str("<title>Documentation</title>\n");
        html.push_str("<link rel=\"stylesheet\" href=\"style.css\">\n");
        html.push_str("</head>\n<body>\n");

        html.push_str("<h1>API Documentation</h1>\n");

        // Modules
        html.push_str("<h2>Modules</h2>\n<ul>\n");
        for item in &self.items {
            if item.item_type == DocItemType::Module {
                html.push_str(&format!(
                    "<li><a href=\"{}.html\">{}</a>",
                    item.name, item.name
                ));
                if let Some(ref doc) = item.doc_comment {
                    let summary = doc.lines().next().unwrap_or("");
                    html.push_str(&format!(" - {}", summary));
                }
                html.push_str("</li>\n");
            }
        }
        html.push_str("</ul>\n");

        // Structs
        html.push_str("<h2>Structs</h2>\n<ul>\n");
        for item in &self.items {
            if item.item_type == DocItemType::Struct && item.visibility == Visibility::Public {
                html.push_str(&format!("<li><code>{}</code>", item.name));
                if let Some(ref doc) = item.doc_comment {
                    let summary = doc.lines().next().unwrap_or("");
                    html.push_str(&format!(" - {}", summary));
                }
                html.push_str("</li>\n");
            }
        }
        html.push_str("</ul>\n");

        // Traits
        html.push_str("<h2>Traits</h2>\n<ul>\n");
        for item in &self.items {
            if item.item_type == DocItemType::Trait && item.visibility == Visibility::Public {
                html.push_str(&format!("<li><code>{}</code>", item.name));
                if let Some(ref doc) = item.doc_comment {
                    let summary = doc.lines().next().unwrap_or("");
                    html.push_str(&format!(" - {}", summary));
                }
                html.push_str("</li>\n");
            }
        }
        html.push_str("</ul>\n");

        // Functions
        html.push_str("<h2>Functions</h2>\n<ul>\n");
        for item in &self.items {
            if item.item_type == DocItemType::Function && item.visibility == Visibility::Public {
                html.push_str(&format!("<li><code>{}</code>", item.name));
                if let Some(ref doc) = item.doc_comment {
                    let summary = doc.lines().next().unwrap_or("");
                    html.push_str(&format!(" - {}", summary));
                }
                html.push_str("</li>\n");
            }
        }
        html.push_str("</ul>\n");

        html.push_str("</body>\n</html>");

        fs::write(self.config.output_dir.join("index.html"), html)?;

        Ok(())
    }

    fn generate_module_html(&self, module: &DocItem) -> io::Result<()> {
        let mut html = String::new();
        html.push_str("<!DOCTYPE html>\n<html>\n<head>\n");
        html.push_str("<meta charset=\"utf-8\">\n");
        html.push_str(&format!("<title>{} - Documentation</title>\n", module.name));
        html.push_str("<link rel=\"stylesheet\" href=\"style.css\">\n");
        html.push_str("</head>\n<body>\n");

        html.push_str(&format!("<h1>Module {}</h1>\n", module.name));

        if let Some(ref doc) = module.doc_comment {
            html.push_str("<div class=\"doc-comment\">\n");
            html.push_str(&format!("<p>{}</p>\n", doc.replace('\n', "</p>\n<p>")));
            html.push_str("</div>\n");
        }

        html.push_str("<p><a href=\"index.html\">Back to index</a></p>\n");
        html.push_str("</body>\n</html>");

        fs::write(
            self.config.output_dir.join(format!("{}.html", module.name)),
            html,
        )?;

        Ok(())
    }

    fn generate_css(&self) -> io::Result<()> {
        let css = r#"
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    max-width: 900px;
    margin: 0 auto;
    padding: 20px;
    line-height: 1.6;
    color: #333;
}

h1, h2, h3 {
    color: #111;
}

code {
    background: #f4f4f4;
    padding: 2px 6px;
    border-radius: 3px;
    font-family: 'SF Mono', Consolas, monospace;
}

pre {
    background: #f4f4f4;
    padding: 15px;
    border-radius: 5px;
    overflow-x: auto;
}

a {
    color: #0066cc;
    text-decoration: none;
}

a:hover {
    text-decoration: underline;
}

.doc-comment {
    background: #f9f9f9;
    padding: 15px;
    border-left: 4px solid #0066cc;
    margin: 10px 0;
}

ul {
    list-style-type: none;
    padding-left: 0;
}

li {
    padding: 5px 0;
    border-bottom: 1px solid #eee;
}
"#;

        if let Some(ref custom_css) = self.config.custom_css {
            let custom = fs::read_to_string(custom_css)?;
            fs::write(
                self.config.output_dir.join("style.css"),
                format!("{}\n{}", css, custom),
            )?;
        } else {
            fs::write(self.config.output_dir.join("style.css"), css)?;
        }

        Ok(())
    }

    /// Generate coverage report
    pub fn generate_coverage_report(&self) -> DocCoverageReport {
        let total_items = self
            .items
            .iter()
            .filter(|i| i.visibility == Visibility::Public)
            .count();

        let documented_items = self
            .items
            .iter()
            .filter(|i| i.visibility == Visibility::Public && i.doc_comment.is_some())
            .count();

        let coverage = if total_items > 0 {
            (documented_items as f64 / total_items as f64) * 100.0
        } else {
            100.0
        };

        let missing_docs: Vec<_> = self
            .items
            .iter()
            .filter(|i| i.visibility == Visibility::Public && i.doc_comment.is_none())
            .map(|i| MissingDoc {
                name: i.name.clone(),
                item_type: i.item_type.clone(),
                module_path: i.module_path.join("::"),
                location: i.source_location.clone(),
            })
            .collect();

        DocCoverageReport {
            total_items,
            documented_items,
            coverage_percentage: coverage,
            missing_docs,
        }
    }

    /// Get statistics
    pub fn get_stats(&self) -> &DocStats {
        &self.stats
    }

    /// Get all parsed items
    pub fn get_items(&self) -> &[DocItem] {
        &self.items
    }
}

/// Doc test definition
#[derive(Debug, Clone)]
pub struct DocTest {
    pub name: String,
    pub module_path: String,
    pub code: String,
    pub should_panic: bool,
    pub no_run: bool,
    pub ignore: bool,
}

/// Documentation coverage report
#[derive(Debug, Clone)]
pub struct DocCoverageReport {
    pub total_items: usize,
    pub documented_items: usize,
    pub coverage_percentage: f64,
    pub missing_docs: Vec<MissingDoc>,
}

#[derive(Debug, Clone)]
pub struct MissingDoc {
    pub name: String,
    pub item_type: DocItemType,
    pub module_path: String,
    pub location: Option<SourceLocation>,
}

impl DocCoverageReport {
    pub fn print_report(&self) {
        println!("=== Documentation Coverage Report ===\n");
        println!("Total public items: {}", self.total_items);
        println!("Documented items: {}", self.documented_items);
        println!("Coverage: {:.1}%\n", self.coverage_percentage);

        if !self.missing_docs.is_empty() {
            println!("Items missing documentation:");
            for item in &self.missing_docs {
                let path = if item.module_path.is_empty() {
                    item.name.clone()
                } else {
                    format!("{}::{}", item.module_path, item.name)
                };

                let loc = item
                    .location
                    .as_ref()
                    .map(|l| format!(" ({}:{})", l.file.display(), l.line))
                    .unwrap_or_default();

                println!("  [{:?}] {}{}", item.item_type, path, loc);
            }
        }
    }
}

fn main() {
    println!("=== Rustdoc Generator Demo ===\n");

    // Create configuration
    let config = DocConfig {
        project_root: PathBuf::from("."),
        output_dir: PathBuf::from("/tmp/doc_demo"),
        document_private: false,
        enable_doc_tests: true,
        ..Default::default()
    };

    // Create generator
    let mut generator = DocGenerator::new(config);

    // Create sample source file for demo
    fs::create_dir_all("/tmp/doc_demo_src/src").ok();

    let sample_source = r#"
//! Sample module documentation
//!
//! This module provides example functionality.

/// A sample struct with documentation
///
/// # Examples
///
/// ```
/// let example = SampleStruct::new("test");
/// assert_eq!(example.name(), "test");
/// ```
pub struct SampleStruct {
    name: String,
}

impl SampleStruct {
    /// Create a new SampleStruct
    pub fn new(name: &str) -> Self {
        Self { name: name.to_string() }
    }

    /// Get the name
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// A sample enum
pub enum SampleEnum {
    /// First variant
    First,
    /// Second variant
    Second(i32),
}

/// A sample trait
pub trait SampleTrait {
    /// Required method
    fn required(&self);

    /// Provided method
    fn provided(&self) {
        println!("Default implementation");
    }
}

/// A public function without documentation
pub fn undocumented_function() {}

fn private_function() {}

/// A constant value
pub const MAX_VALUE: u32 = 100;
"#;

    fs::write("/tmp/doc_demo_src/src/lib.rs", sample_source).ok();

    // Update config to use temp source
    let config = DocConfig {
        project_root: PathBuf::from("/tmp/doc_demo_src"),
        output_dir: PathBuf::from("/tmp/doc_demo"),
        ..Default::default()
    };

    let mut generator = DocGenerator::new(config);

    // Parse sources
    println!("Parsing source files...");
    if let Err(e) = generator.parse_sources() {
        println!("Error parsing sources: {}", e);
    }

    // Display statistics
    println!("\nDocumentation Statistics:");
    let stats = generator.get_stats();
    println!("  Modules: {}", stats.modules_documented);
    println!("  Structs: {}", stats.structs_documented);
    println!("  Enums: {}", stats.enums_documented);
    println!("  Traits: {}", stats.traits_documented);
    println!("  Functions: {}", stats.functions_documented);
    println!("  Items without docs: {}", stats.items_without_docs);

    // Show parsed items
    println!("\nParsed items:");
    for item in generator.get_items() {
        let doc_status = if item.doc_comment.is_some() {
            "✓"
        } else {
            "✗"
        };
        println!(
            "  {} [{:?}] {} ({:?})",
            doc_status, item.item_type, item.name, item.visibility
        );
    }

    // Extract doc tests
    let doc_tests = generator.extract_doc_tests();
    println!("\nDoc tests found: {}", doc_tests.len());
    for test in &doc_tests {
        println!(
            "  - {} (ignore: {}, no_run: {})",
            test.name, test.ignore, test.no_run
        );
    }

    // Generate coverage report
    let coverage = generator.generate_coverage_report();
    println!();
    coverage.print_report();

    // Generate HTML
    println!("\nGenerating HTML documentation...");
    if let Err(e) = generator.generate_html() {
        println!("Error generating HTML: {}", e);
    } else {
        println!("Documentation generated in /tmp/doc_demo");
    }

    // Cleanup
    let _ = fs::remove_dir_all("/tmp/doc_demo_src");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_visibility_extraction() {
        let generator = DocGenerator::new(DocConfig::default());

        assert_eq!(
            generator.extract_visibility("pub fn test()"),
            Visibility::Public
        );
        assert_eq!(
            generator.extract_visibility("pub(crate) fn test()"),
            Visibility::Crate
        );
        assert_eq!(
            generator.extract_visibility("fn test()"),
            Visibility::Private
        );
    }

    #[test]
    fn test_name_extraction() {
        let generator = DocGenerator::new(DocConfig::default());

        assert_eq!(generator.extract_name("MyStruct {"), "MyStruct");
        assert_eq!(generator.extract_name("my_function("), "my_function");
        assert_eq!(generator.extract_name("GenericStruct<T>"), "GenericStruct");
    }

    #[test]
    fn test_doc_test_extraction() {
        let generator = DocGenerator::new(DocConfig::default());

        let doc = r#"
Some documentation.

# Examples

```
let x = 42;
assert_eq!(x, 42);
```

More text.

```no_run
// This won't run
```
"#;

        let tests = generator.extract_tests_from_doc(doc, "test_fn", &["module".to_string()]);

        assert_eq!(tests.len(), 2);
        assert!(!tests[0].no_run);
        assert!(tests[1].no_run);
    }

    #[test]
    fn test_coverage_calculation() {
        let config = DocConfig::default();
        let mut generator = DocGenerator::new(config);

        // Add test items
        generator.items.push(DocItem {
            name: "Documented".to_string(),
            item_type: DocItemType::Struct,
            module_path: vec![],
            doc_comment: Some("Has docs".to_string()),
            visibility: Visibility::Public,
            attributes: vec![],
            source_location: None,
            children: vec![],
        });

        generator.items.push(DocItem {
            name: "Undocumented".to_string(),
            item_type: DocItemType::Struct,
            module_path: vec![],
            doc_comment: None,
            visibility: Visibility::Public,
            attributes: vec![],
            source_location: None,
            children: vec![],
        });

        let report = generator.generate_coverage_report();

        assert_eq!(report.total_items, 2);
        assert_eq!(report.documented_items, 1);
        assert!((report.coverage_percentage - 50.0).abs() < 0.1);
    }

    #[test]
    fn test_strip_visibility() {
        let generator = DocGenerator::new(DocConfig::default());

        assert_eq!(generator.strip_visibility("pub fn test()"), "fn test()");
        assert_eq!(
            generator.strip_visibility("pub(crate) fn test()"),
            "fn test()"
        );
        assert_eq!(generator.strip_visibility("fn test()"), "fn test()");
    }
}
