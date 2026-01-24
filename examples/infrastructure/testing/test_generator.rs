//! Test Generation Framework
//!
//! Automated test generation with unit tests, integration tests,
//! property-based tests, and security test generation.

use std::collections::HashMap;

/// Test type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestType {
    Unit,
    Integration,
    PropertyBased,
    Security,
    Fuzz,
    Benchmark,
}

impl TestType {
    pub fn as_str(&self) -> &'static str {
        match self {
            TestType::Unit => "unit",
            TestType::Integration => "integration",
            TestType::PropertyBased => "property",
            TestType::Security => "security",
            TestType::Fuzz => "fuzz",
            TestType::Benchmark => "benchmark",
        }
    }
}

/// Function signature for test generation
#[derive(Debug, Clone)]
pub struct FunctionSignature {
    pub name: String,
    pub params: Vec<Parameter>,
    pub return_type: Option<String>,
    pub is_async: bool,
    pub visibility: Visibility,
    pub attributes: Vec<String>,
}

/// Function parameter
#[derive(Debug, Clone)]
pub struct Parameter {
    pub name: String,
    pub param_type: String,
    pub is_mutable: bool,
    pub is_reference: bool,
}

/// Visibility
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    Public,
    Private,
    Crate,
    Super,
}

/// Generated test
#[derive(Debug, Clone)]
pub struct GeneratedTest {
    pub name: String,
    pub test_type: TestType,
    pub function_under_test: String,
    pub code: String,
    pub imports: Vec<String>,
}

/// Test generator
#[derive(Debug)]
pub struct TestGenerator {
    module_name: String,
    tests: Vec<GeneratedTest>,
    config: TestConfig,
}

/// Test generation configuration
#[derive(Debug, Clone)]
pub struct TestConfig {
    /// Generate tests for private functions
    pub include_private: bool,
    /// Generate property-based tests
    pub property_tests: bool,
    /// Generate security tests
    pub security_tests: bool,
    /// Generate fuzz tests
    pub fuzz_tests: bool,
    /// Generate benchmarks
    pub benchmarks: bool,
    /// Test coverage target
    pub coverage_target: f32,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            include_private: false,
            property_tests: true,
            security_tests: true,
            fuzz_tests: false,
            benchmarks: false,
            coverage_target: 80.0,
        }
    }
}

impl TestGenerator {
    pub fn new(module_name: &str, config: TestConfig) -> Self {
        Self {
            module_name: module_name.to_string(),
            tests: Vec::new(),
            config,
        }
    }

    /// Generate tests for a function
    pub fn generate_for_function(&mut self, func: &FunctionSignature) {
        // Skip private functions if not configured
        if func.visibility == Visibility::Private && !self.config.include_private {
            return;
        }

        // Generate unit tests
        self.generate_unit_tests(func);

        // Generate property tests if enabled
        if self.config.property_tests {
            self.generate_property_tests(func);
        }

        // Generate security tests if enabled
        if self.config.security_tests {
            self.generate_security_tests(func);
        }

        // Generate fuzz tests if enabled
        if self.config.fuzz_tests {
            self.generate_fuzz_tests(func);
        }

        // Generate benchmarks if enabled
        if self.config.benchmarks {
            self.generate_benchmarks(func);
        }
    }

    /// Generate unit tests
    fn generate_unit_tests(&mut self, func: &FunctionSignature) {
        // Basic functionality test
        let basic_test = self.create_basic_test(func);
        self.tests.push(basic_test);

        // Edge case tests
        let edge_tests = self.create_edge_case_tests(func);
        self.tests.extend(edge_tests);

        // Error handling tests
        if func
            .return_type
            .as_ref()
            .map(|t| t.contains("Result"))
            .unwrap_or(false)
        {
            let error_tests = self.create_error_tests(func);
            self.tests.extend(error_tests);
        }
    }

    /// Create basic functionality test
    fn create_basic_test(&self, func: &FunctionSignature) -> GeneratedTest {
        let test_name = format!("test_{}_basic", func.name);
        let async_prefix = if func.is_async { "async " } else { "" };
        let await_suffix = if func.is_async { ".await" } else { "" };

        let params_setup = func
            .params
            .iter()
            .map(|p| {
                format!(
                    "    let {} = {};",
                    p.name,
                    self.default_value(&p.param_type)
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        let params_call = func
            .params
            .iter()
            .map(|p| {
                if p.is_reference {
                    if p.is_mutable {
                        format!("&mut {}", p.name)
                    } else {
                        format!("&{}", p.name)
                    }
                } else {
                    p.name.clone()
                }
            })
            .collect::<Vec<_>>()
            .join(", ");

        let assertion = if let Some(ref ret) = func.return_type {
            if ret.contains("Result") {
                format!("    assert!(result.is_ok(), \"Expected Ok result\");")
            } else if ret.contains("Option") {
                format!("    assert!(result.is_some(), \"Expected Some result\");")
            } else if ret == "bool" {
                format!("    // Verify the boolean result based on test conditions")
            } else {
                format!("    // Verify the result: {{:?}}",)
            }
        } else {
            String::new()
        };

        let code = format!(
            r#"#[test]
{}fn {}() {{
{}
    let result = {}({}){};
{}
}}"#,
            async_prefix, test_name, params_setup, func.name, params_call, await_suffix, assertion
        );

        GeneratedTest {
            name: test_name,
            test_type: TestType::Unit,
            function_under_test: func.name.clone(),
            code,
            imports: vec!["use super::*;".to_string()],
        }
    }

    /// Create edge case tests
    fn create_edge_case_tests(&self, func: &FunctionSignature) -> Vec<GeneratedTest> {
        let mut tests = Vec::new();

        for param in &func.params {
            // Empty string test
            if param.param_type.contains("str") || param.param_type.contains("String") {
                tests.push(self.create_edge_case_test(func, &param.name, "\"\"", "empty_string"));
                tests.push(self.create_edge_case_test(func, &param.name, "\" \"", "whitespace"));
            }

            // Zero/negative tests for numbers
            if self.is_numeric_type(&param.param_type) {
                tests.push(self.create_edge_case_test(func, &param.name, "0", "zero"));
                if param.param_type.starts_with('i') {
                    tests.push(self.create_edge_case_test(func, &param.name, "-1", "negative"));
                }
            }

            // Empty collection tests
            if param.param_type.contains("Vec") || param.param_type.contains("[") {
                tests.push(self.create_edge_case_test(
                    func,
                    &param.name,
                    "Vec::new()",
                    "empty_vec",
                ));
            }

            // Option None tests
            if param.param_type.contains("Option") {
                tests.push(self.create_edge_case_test(func, &param.name, "None", "none"));
            }
        }

        tests
    }

    /// Create a single edge case test
    fn create_edge_case_test(
        &self,
        func: &FunctionSignature,
        param_name: &str,
        edge_value: &str,
        edge_name: &str,
    ) -> GeneratedTest {
        let test_name = format!("test_{}_{}_with_{}", func.name, param_name, edge_name);
        let async_prefix = if func.is_async { "async " } else { "" };
        let await_suffix = if func.is_async { ".await" } else { "" };

        let params_setup = func
            .params
            .iter()
            .map(|p| {
                let value = if p.name == param_name {
                    edge_value.to_string()
                } else {
                    self.default_value(&p.param_type)
                };
                format!("    let {} = {};", p.name, value)
            })
            .collect::<Vec<_>>()
            .join("\n");

        let params_call = func
            .params
            .iter()
            .map(|p| {
                if p.is_reference {
                    if p.is_mutable {
                        format!("&mut {}", p.name)
                    } else {
                        format!("&{}", p.name)
                    }
                } else {
                    p.name.clone()
                }
            })
            .collect::<Vec<_>>()
            .join(", ");

        let code = format!(
            r#"#[test]
{}fn {}() {{
{}
    let result = {}({}){};
    // Edge case: {} with {}
    // Verify behavior is correct for this edge case
}}"#,
            async_prefix,
            test_name,
            params_setup,
            func.name,
            params_call,
            await_suffix,
            param_name,
            edge_name
        );

        GeneratedTest {
            name: test_name,
            test_type: TestType::Unit,
            function_under_test: func.name.clone(),
            code,
            imports: vec!["use super::*;".to_string()],
        }
    }

    /// Create error handling tests
    fn create_error_tests(&self, func: &FunctionSignature) -> Vec<GeneratedTest> {
        let mut tests = Vec::new();

        let test_name = format!("test_{}_returns_error_on_invalid_input", func.name);
        let async_prefix = if func.is_async { "async " } else { "" };
        let await_suffix = if func.is_async { ".await" } else { "" };

        let code = format!(
            r#"#[test]
{}fn {}() {{
    // Set up invalid input that should cause an error
    // let invalid_input = ...;

    // let result = {}(invalid_input){};
    // assert!(result.is_err(), "Expected error for invalid input");

    // Optionally verify the specific error type
    // match result {{
    //     Err(e) => assert!(matches!(e, ExpectedError::InvalidInput)),
    //     Ok(_) => panic!("Expected error"),
    // }}
}}"#,
            async_prefix, test_name, func.name, await_suffix
        );

        tests.push(GeneratedTest {
            name: test_name,
            test_type: TestType::Unit,
            function_under_test: func.name.clone(),
            code,
            imports: vec!["use super::*;".to_string()],
        });

        tests
    }

    /// Generate property-based tests
    fn generate_property_tests(&mut self, func: &FunctionSignature) {
        let test_name = format!("proptest_{}", func.name);

        let strategies = func
            .params
            .iter()
            .map(|p| format!("{} in {}", p.name, self.proptest_strategy(&p.param_type)))
            .collect::<Vec<_>>()
            .join(",\n            ");

        let params_call = func
            .params
            .iter()
            .map(|p| {
                if p.is_reference {
                    if p.is_mutable {
                        format!("&mut {}.clone()", p.name)
                    } else {
                        format!("&{}", p.name)
                    }
                } else {
                    format!("{}.clone()", p.name)
                }
            })
            .collect::<Vec<_>>()
            .join(", ");

        let code = format!(
            r#"proptest! {{
    #[test]
    fn {}(
            {}
    ) {{
        let result = {}({});

        // Property: function should not panic
        // Property: output should satisfy invariants
        // Add specific property assertions here
    }}
}}"#,
            test_name, strategies, func.name, params_call
        );

        self.tests.push(GeneratedTest {
            name: test_name,
            test_type: TestType::PropertyBased,
            function_under_test: func.name.clone(),
            code,
            imports: vec![
                "use super::*;".to_string(),
                "use proptest::prelude::*;".to_string(),
            ],
        });
    }

    /// Generate security tests
    fn generate_security_tests(&mut self, func: &FunctionSignature) {
        let mut security_tests = Vec::new();

        // Check for string parameters that might be vulnerable to injection
        for param in &func.params {
            if param.param_type.contains("str") || param.param_type.contains("String") {
                security_tests.push(self.create_injection_test(func, &param.name));
            }
        }

        // Check for numeric overflow
        for param in &func.params {
            if self.is_numeric_type(&param.param_type) {
                security_tests.push(self.create_overflow_test(
                    func,
                    &param.name,
                    &param.param_type,
                ));
            }
        }

        // Check for path traversal
        for param in &func.params {
            if param.name.contains("path") || param.name.contains("file") {
                security_tests.push(self.create_path_traversal_test(func, &param.name));
            }
        }

        self.tests.extend(security_tests);
    }

    /// Create injection test
    fn create_injection_test(&self, func: &FunctionSignature, param_name: &str) -> GeneratedTest {
        let test_name = format!("test_{}_injection_safety_{}", func.name, param_name);

        let code = format!(
            r#"#[test]
fn {}() {{
    let injection_payloads = [
        "'; DROP TABLE users; --",
        "<script>alert('xss')</script>",
        "{{{{evil}}}}",
        "../../../etc/passwd",
        "| cat /etc/passwd",
        "%00",
        "\x00",
    ];

    for payload in &injection_payloads {{
        // Should either reject malicious input or safely handle it
        // let result = {}(payload);
        // assert!(result.is_err() || is_safely_escaped(&result));
    }}
}}"#,
            test_name, func.name
        );

        GeneratedTest {
            name: test_name,
            test_type: TestType::Security,
            function_under_test: func.name.clone(),
            code,
            imports: vec!["use super::*;".to_string()],
        }
    }

    /// Create overflow test
    fn create_overflow_test(
        &self,
        func: &FunctionSignature,
        param_name: &str,
        param_type: &str,
    ) -> GeneratedTest {
        let test_name = format!("test_{}_overflow_safety_{}", func.name, param_name);

        let max_value = match param_type {
            "i8" => "i8::MAX",
            "i16" => "i16::MAX",
            "i32" => "i32::MAX",
            "i64" => "i64::MAX",
            "i128" => "i128::MAX",
            "u8" => "u8::MAX",
            "u16" => "u16::MAX",
            "u32" => "u32::MAX",
            "u64" => "u64::MAX",
            "u128" => "u128::MAX",
            "usize" => "usize::MAX",
            "isize" => "isize::MAX",
            _ => "i64::MAX",
        };

        let code = format!(
            r#"#[test]
fn {}() {{
    let boundary_values = [
        {},
        {} - 1,
        1,
        0,
    ];

    for value in boundary_values {{
        // Should handle boundary values without panicking
        // let result = {}(value);
        // Function should either succeed or return an error, not panic
    }}
}}"#,
            test_name, max_value, max_value, func.name
        );

        GeneratedTest {
            name: test_name,
            test_type: TestType::Security,
            function_under_test: func.name.clone(),
            code,
            imports: vec!["use super::*;".to_string()],
        }
    }

    /// Create path traversal test
    fn create_path_traversal_test(
        &self,
        func: &FunctionSignature,
        param_name: &str,
    ) -> GeneratedTest {
        let test_name = format!("test_{}_path_traversal_safety", func.name);

        let code = format!(
            r#"#[test]
fn {}() {{
    let malicious_paths = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32",
        "/etc/passwd",
        "C:\\Windows\\System32",
        "....//....//etc/passwd",
        "..%2f..%2f..%2fetc/passwd",
        "%2e%2e%2f%2e%2e%2fetc/passwd",
    ];

    for path in &malicious_paths {{
        // Should reject path traversal attempts
        // let result = {}(path);
        // assert!(result.is_err(), "Should reject path: {{}}", path);
    }}
}}"#,
            test_name, func.name
        );

        GeneratedTest {
            name: test_name,
            test_type: TestType::Security,
            function_under_test: func.name.clone(),
            code,
            imports: vec!["use super::*;".to_string()],
        }
    }

    /// Generate fuzz tests
    fn generate_fuzz_tests(&mut self, func: &FunctionSignature) {
        let test_name = format!("fuzz_{}", func.name);

        let code = format!(
            r#"#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {{
    // Convert fuzzer input to function parameters
    // let input = ...;

    // Call function with fuzzed input
    // let _ = {}(input);

    // Function should not panic on any input
}});"#,
            func.name
        );

        self.tests.push(GeneratedTest {
            name: test_name,
            test_type: TestType::Fuzz,
            function_under_test: func.name.clone(),
            code,
            imports: vec!["use super::*;".to_string()],
        });
    }

    /// Generate benchmarks
    fn generate_benchmarks(&mut self, func: &FunctionSignature) {
        let test_name = format!("bench_{}", func.name);

        let params_setup = func
            .params
            .iter()
            .map(|p| {
                format!(
                    "        let {} = {};",
                    p.name,
                    self.default_value(&p.param_type)
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        let params_call = func
            .params
            .iter()
            .map(|p| {
                if p.is_reference {
                    if p.is_mutable {
                        format!("&mut {}.clone()", p.name)
                    } else {
                        format!("&{}", p.name)
                    }
                } else {
                    format!("{}.clone()", p.name)
                }
            })
            .collect::<Vec<_>>()
            .join(", ");

        let code = format!(
            r#"fn {}(c: &mut Criterion) {{
    c.bench_function("{}", |b| {{
{}
        b.iter(|| {{
            black_box({}({}))
        }})
    }});
}}

criterion_group!(benches, {});
criterion_main!(benches);"#,
            test_name, func.name, params_setup, func.name, params_call, test_name
        );

        self.tests.push(GeneratedTest {
            name: test_name,
            test_type: TestType::Benchmark,
            function_under_test: func.name.clone(),
            code,
            imports: vec![
                "use super::*;".to_string(),
                "use criterion::{black_box, criterion_group, criterion_main, Criterion};"
                    .to_string(),
            ],
        });
    }

    /// Get default value for a type
    fn default_value(&self, type_name: &str) -> String {
        match type_name {
            "i8" | "i16" | "i32" | "i64" | "i128" | "isize" => "0".to_string(),
            "u8" | "u16" | "u32" | "u64" | "u128" | "usize" => "0".to_string(),
            "f32" | "f64" => "0.0".to_string(),
            "bool" => "false".to_string(),
            "char" => "'a'".to_string(),
            "&str" => "\"test\"".to_string(),
            "String" => "String::from(\"test\")".to_string(),
            t if t.starts_with("Vec<") => "Vec::new()".to_string(),
            t if t.starts_with("Option<") => "None".to_string(),
            t if t.starts_with("Result<") => "Ok(Default::default())".to_string(),
            t if t.starts_with("HashMap<") => "HashMap::new()".to_string(),
            t if t.starts_with("HashSet<") => "HashSet::new()".to_string(),
            _ => "Default::default()".to_string(),
        }
    }

    /// Get proptest strategy for a type
    fn proptest_strategy(&self, type_name: &str) -> String {
        match type_name {
            "i8" => "any::<i8>()".to_string(),
            "i16" => "any::<i16>()".to_string(),
            "i32" => "any::<i32>()".to_string(),
            "i64" => "any::<i64>()".to_string(),
            "u8" => "any::<u8>()".to_string(),
            "u16" => "any::<u16>()".to_string(),
            "u32" => "any::<u32>()".to_string(),
            "u64" => "any::<u64>()".to_string(),
            "bool" => "any::<bool>()".to_string(),
            "&str" | "String" => "\".*\"".to_string(),
            t if t.starts_with("Vec<") => "prop::collection::vec(any::<_>(), 0..100)".to_string(),
            t if t.starts_with("Option<") => "proptest::option::of(any::<_>())".to_string(),
            _ => "any::<_>()".to_string(),
        }
    }

    /// Check if type is numeric
    fn is_numeric_type(&self, type_name: &str) -> bool {
        matches!(
            type_name,
            "i8" | "i16"
                | "i32"
                | "i64"
                | "i128"
                | "isize"
                | "u8"
                | "u16"
                | "u32"
                | "u64"
                | "u128"
                | "usize"
                | "f32"
                | "f64"
        )
    }

    /// Get all generated tests
    pub fn tests(&self) -> &[GeneratedTest] {
        &self.tests
    }

    /// Generate test module code
    pub fn generate_test_module(&self) -> String {
        let mut output = String::new();

        // Collect unique imports
        let mut all_imports: Vec<String> =
            self.tests.iter().flat_map(|t| t.imports.clone()).collect();
        all_imports.sort();
        all_imports.dedup();

        output.push_str("#[cfg(test)]\n");
        output.push_str(&format!("mod {} {{\n", self.module_name));

        for import in &all_imports {
            output.push_str(&format!("    {}\n", import));
        }
        output.push('\n');

        for test in &self.tests {
            for line in test.code.lines() {
                output.push_str(&format!("    {}\n", line));
            }
            output.push('\n');
        }

        output.push_str("}\n");
        output
    }
}

fn main() {
    println!("=== Test Generation Framework Demo ===\n");

    let config = TestConfig {
        include_private: false,
        property_tests: true,
        security_tests: true,
        fuzz_tests: false,
        benchmarks: false,
        coverage_target: 80.0,
    };

    let mut generator = TestGenerator::new("tests", config);

    // Example function signatures
    let functions = vec![
        FunctionSignature {
            name: "process_user_input".to_string(),
            params: vec![Parameter {
                name: "input".to_string(),
                param_type: "String".to_string(),
                is_mutable: false,
                is_reference: true,
            }],
            return_type: Some("Result<String, Error>".to_string()),
            is_async: false,
            visibility: Visibility::Public,
            attributes: vec![],
        },
        FunctionSignature {
            name: "calculate_total".to_string(),
            params: vec![
                Parameter {
                    name: "items".to_string(),
                    param_type: "Vec<Item>".to_string(),
                    is_mutable: false,
                    is_reference: true,
                },
                Parameter {
                    name: "discount".to_string(),
                    param_type: "f64".to_string(),
                    is_mutable: false,
                    is_reference: false,
                },
            ],
            return_type: Some("f64".to_string()),
            is_async: false,
            visibility: Visibility::Public,
            attributes: vec![],
        },
        FunctionSignature {
            name: "read_file".to_string(),
            params: vec![Parameter {
                name: "path".to_string(),
                param_type: "String".to_string(),
                is_mutable: false,
                is_reference: true,
            }],
            return_type: Some("Result<Vec<u8>, IoError>".to_string()),
            is_async: true,
            visibility: Visibility::Public,
            attributes: vec![],
        },
    ];

    // Generate tests for each function
    for func in &functions {
        println!("Generating tests for: {}", func.name);
        generator.generate_for_function(func);
    }

    // Display generated tests
    println!("\n--- Generated Tests ---\n");
    for test in generator.tests() {
        println!("Test: {} ({})", test.name, test.test_type.as_str());
        println!("  Function: {}", test.function_under_test);
        println!();
    }

    // Generate test module
    println!("\n--- Generated Test Module ---\n");
    let module = generator.generate_test_module();

    // Print first 2000 characters to show structure
    let preview: String = module.chars().take(2000).collect();
    println!("{}", preview);
    if module.len() > 2000 {
        println!("\n... (truncated, {} total characters)", module.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_function() -> FunctionSignature {
        FunctionSignature {
            name: "sample".to_string(),
            params: vec![Parameter {
                name: "value".to_string(),
                param_type: "i32".to_string(),
                is_mutable: false,
                is_reference: false,
            }],
            return_type: Some("i32".to_string()),
            is_async: false,
            visibility: Visibility::Public,
            attributes: vec![],
        }
    }

    #[test]
    fn test_generator_creates_basic_test() {
        let config = TestConfig::default();
        let mut generator = TestGenerator::new("tests", config);

        generator.generate_for_function(&sample_function());

        assert!(!generator.tests().is_empty());
        assert!(generator.tests().iter().any(|t| t.name.contains("basic")));
    }

    #[test]
    fn test_generator_creates_edge_case_tests() {
        let config = TestConfig::default();
        let mut generator = TestGenerator::new("tests", config);

        generator.generate_for_function(&sample_function());

        assert!(generator.tests().iter().any(|t| t.name.contains("zero")));
    }

    #[test]
    fn test_generator_creates_property_tests() {
        let config = TestConfig {
            property_tests: true,
            ..TestConfig::default()
        };
        let mut generator = TestGenerator::new("tests", config);

        generator.generate_for_function(&sample_function());

        assert!(generator
            .tests()
            .iter()
            .any(|t| t.test_type == TestType::PropertyBased));
    }

    #[test]
    fn test_generator_creates_security_tests() {
        let config = TestConfig {
            security_tests: true,
            ..TestConfig::default()
        };
        let mut generator = TestGenerator::new("tests", config);

        let func = FunctionSignature {
            name: "process".to_string(),
            params: vec![Parameter {
                name: "input".to_string(),
                param_type: "String".to_string(),
                is_mutable: false,
                is_reference: true,
            }],
            return_type: Some("String".to_string()),
            is_async: false,
            visibility: Visibility::Public,
            attributes: vec![],
        };

        generator.generate_for_function(&func);

        assert!(generator
            .tests()
            .iter()
            .any(|t| t.test_type == TestType::Security));
    }

    #[test]
    fn test_generator_skips_private_by_default() {
        let config = TestConfig {
            include_private: false,
            ..TestConfig::default()
        };
        let mut generator = TestGenerator::new("tests", config);

        let private_func = FunctionSignature {
            name: "private_fn".to_string(),
            params: vec![],
            return_type: None,
            is_async: false,
            visibility: Visibility::Private,
            attributes: vec![],
        };

        generator.generate_for_function(&private_func);

        assert!(generator.tests().is_empty());
    }

    #[test]
    fn test_generator_includes_private_when_configured() {
        let config = TestConfig {
            include_private: true,
            ..TestConfig::default()
        };
        let mut generator = TestGenerator::new("tests", config);

        let private_func = FunctionSignature {
            name: "private_fn".to_string(),
            params: vec![],
            return_type: None,
            is_async: false,
            visibility: Visibility::Private,
            attributes: vec![],
        };

        generator.generate_for_function(&private_func);

        assert!(!generator.tests().is_empty());
    }

    #[test]
    fn test_default_values() {
        let generator = TestGenerator::new("tests", TestConfig::default());

        assert_eq!(generator.default_value("i32"), "0");
        assert_eq!(generator.default_value("bool"), "false");
        assert_eq!(generator.default_value("String"), "String::from(\"test\")");
        assert_eq!(generator.default_value("Vec<i32>"), "Vec::new()");
    }

    #[test]
    fn test_proptest_strategies() {
        let generator = TestGenerator::new("tests", TestConfig::default());

        assert!(generator.proptest_strategy("i32").contains("any::<i32>"));
        assert!(generator.proptest_strategy("String").contains(".*"));
        assert!(generator.proptest_strategy("Vec<u8>").contains("vec"));
    }

    #[test]
    fn test_is_numeric_type() {
        let generator = TestGenerator::new("tests", TestConfig::default());

        assert!(generator.is_numeric_type("i32"));
        assert!(generator.is_numeric_type("u64"));
        assert!(generator.is_numeric_type("f64"));
        assert!(!generator.is_numeric_type("String"));
        assert!(!generator.is_numeric_type("bool"));
    }

    #[test]
    fn test_generate_test_module() {
        let config = TestConfig {
            property_tests: false,
            security_tests: false,
            ..TestConfig::default()
        };
        let mut generator = TestGenerator::new("my_tests", config);

        generator.generate_for_function(&sample_function());

        let module = generator.generate_test_module();

        assert!(module.contains("#[cfg(test)]"));
        assert!(module.contains("mod my_tests"));
        assert!(module.contains("use super::*"));
        assert!(module.contains("#[test]"));
    }

    #[test]
    fn test_async_function_generation() {
        let config = TestConfig {
            property_tests: false,
            security_tests: false,
            ..TestConfig::default()
        };
        let mut generator = TestGenerator::new("tests", config);

        let async_func = FunctionSignature {
            name: "async_fn".to_string(),
            params: vec![],
            return_type: Some("Result<(), Error>".to_string()),
            is_async: true,
            visibility: Visibility::Public,
            attributes: vec![],
        };

        generator.generate_for_function(&async_func);

        let test = generator
            .tests()
            .iter()
            .find(|t| t.name.contains("basic"))
            .unwrap();
        assert!(test.code.contains("async fn"));
        assert!(test.code.contains(".await"));
    }

    #[test]
    fn test_path_traversal_test_generation() {
        let config = TestConfig {
            security_tests: true,
            property_tests: false,
            ..TestConfig::default()
        };
        let mut generator = TestGenerator::new("tests", config);

        let file_func = FunctionSignature {
            name: "read_file".to_string(),
            params: vec![Parameter {
                name: "file_path".to_string(),
                param_type: "String".to_string(),
                is_mutable: false,
                is_reference: true,
            }],
            return_type: Some("Result<String, Error>".to_string()),
            is_async: false,
            visibility: Visibility::Public,
            attributes: vec![],
        };

        generator.generate_for_function(&file_func);

        assert!(generator
            .tests()
            .iter()
            .any(|t| t.name.contains("path_traversal")));
    }
}
