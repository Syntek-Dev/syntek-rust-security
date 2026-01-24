//! CI/CD Pipeline Generator
//!
//! Generate security-focused CI/CD pipelines for:
//! - GitHub Actions
//! - GitLab CI
//! - Jenkins
//! - Custom configurations

use std::collections::HashMap;
use std::fmt;

/// Supported CI/CD platforms
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CiPlatform {
    GitHubActions,
    GitLabCi,
    Jenkins,
    CircleCi,
}

/// Pipeline configuration
#[derive(Clone, Debug)]
pub struct PipelineConfig {
    pub name: String,
    pub platform: CiPlatform,
    pub rust_version: String,
    pub targets: Vec<String>,
    pub features: PipelineFeatures,
    pub environment: HashMap<String, String>,
    pub secrets: Vec<String>,
}

/// Pipeline feature flags
#[derive(Clone, Debug, Default)]
pub struct PipelineFeatures {
    pub security_audit: bool,
    pub dependency_check: bool,
    pub code_coverage: bool,
    pub fuzzing: bool,
    pub benchmarks: bool,
    pub clippy: bool,
    pub rustfmt: bool,
    pub miri: bool,
    pub documentation: bool,
    pub cross_compilation: bool,
    pub release_build: bool,
    pub container_scan: bool,
}

/// A pipeline job
#[derive(Clone, Debug)]
pub struct Job {
    pub name: String,
    pub runs_on: String,
    pub needs: Vec<String>,
    pub steps: Vec<Step>,
    pub env: HashMap<String, String>,
    pub timeout_minutes: u32,
    pub continue_on_error: bool,
}

/// A step within a job
#[derive(Clone, Debug)]
pub struct Step {
    pub name: String,
    pub step_type: StepType,
    pub condition: Option<String>,
}

/// Type of step
#[derive(Clone, Debug)]
pub enum StepType {
    Checkout,
    SetupRust {
        version: String,
    },
    Cache {
        paths: Vec<String>,
        key: String,
    },
    Run {
        command: String,
    },
    Action {
        uses: String,
        with: HashMap<String, String>,
    },
    UploadArtifact {
        name: String,
        path: String,
    },
}

/// Pipeline generator
pub struct PipelineGenerator {
    config: PipelineConfig,
}

impl PipelineGenerator {
    /// Create new generator
    pub fn new(config: PipelineConfig) -> Self {
        Self { config }
    }

    /// Generate pipeline configuration
    pub fn generate(&self) -> String {
        match self.config.platform {
            CiPlatform::GitHubActions => self.generate_github_actions(),
            CiPlatform::GitLabCi => self.generate_gitlab_ci(),
            CiPlatform::Jenkins => self.generate_jenkinsfile(),
            CiPlatform::CircleCi => self.generate_circleci(),
        }
    }

    fn generate_github_actions(&self) -> String {
        let mut output = String::new();

        // Header
        output.push_str(&format!("name: {}\n\n", self.config.name));
        output.push_str("on:\n");
        output.push_str("  push:\n");
        output.push_str("    branches: [main, develop]\n");
        output.push_str("  pull_request:\n");
        output.push_str("    branches: [main]\n\n");

        // Environment
        if !self.config.environment.is_empty() {
            output.push_str("env:\n");
            for (key, value) in &self.config.environment {
                output.push_str(&format!("  {}: {}\n", key, value));
            }
            output.push('\n');
        }

        output.push_str("jobs:\n");

        // Security audit job
        if self.config.features.security_audit {
            output.push_str(&self.github_security_audit_job());
        }

        // Format check job
        if self.config.features.rustfmt {
            output.push_str(&self.github_format_job());
        }

        // Clippy job
        if self.config.features.clippy {
            output.push_str(&self.github_clippy_job());
        }

        // Test job
        output.push_str(&self.github_test_job());

        // Coverage job
        if self.config.features.code_coverage {
            output.push_str(&self.github_coverage_job());
        }

        // Miri job (for unsafe code verification)
        if self.config.features.miri {
            output.push_str(&self.github_miri_job());
        }

        // Fuzzing job
        if self.config.features.fuzzing {
            output.push_str(&self.github_fuzz_job());
        }

        // Documentation job
        if self.config.features.documentation {
            output.push_str(&self.github_docs_job());
        }

        // Release job
        if self.config.features.release_build {
            output.push_str(&self.github_release_job());
        }

        output
    }

    fn github_security_audit_job(&self) -> String {
        r#"  security-audit:
    name: Security Audit
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: rustsec/audit-check@v2
        with:
          token: ${{ secrets.GITHUB_TOKEN }}

      - name: Install cargo-deny
        run: cargo install cargo-deny

      - name: Check dependencies
        run: cargo deny check

      - name: Install cargo-geiger
        run: cargo install cargo-geiger

      - name: Count unsafe code
        run: cargo geiger --all-features

"#
        .to_string()
    }

    fn github_format_job(&self) -> String {
        format!(
            r#"  format:
    name: Format Check
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@{}
        with:
          components: rustfmt
      - name: Check formatting
        run: cargo fmt --all -- --check

"#,
            self.config.rust_version
        )
    }

    fn github_clippy_job(&self) -> String {
        format!(
            r#"  clippy:
    name: Clippy
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@{}
        with:
          components: clippy
      - uses: Swatinem/rust-cache@v2
      - name: Clippy check
        run: cargo clippy --all-targets --all-features -- -D warnings -D clippy::all -D clippy::pedantic

"#,
            self.config.rust_version
        )
    }

    fn github_test_job(&self) -> String {
        let mut targets = String::new();
        for target in &self.config.targets {
            targets.push_str(&format!("          - {}\n", target));
        }

        format!(
            r#"  test:
    name: Test (${{{{ matrix.os }}}})
    runs-on: ${{{{ matrix.os }}}}
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        rust: [{}]
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@${{{{ matrix.rust }}}}
      - uses: Swatinem/rust-cache@v2
      - name: Run tests
        run: cargo test --all-features --workspace
      - name: Run doc tests
        run: cargo test --doc --all-features

"#,
            self.config.rust_version
        )
    }

    fn github_coverage_job(&self) -> String {
        r#"  coverage:
    name: Code Coverage
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: llvm-tools-preview
      - uses: Swatinem/rust-cache@v2
      - name: Install cargo-llvm-cov
        run: cargo install cargo-llvm-cov
      - name: Generate coverage
        run: cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info
      - name: Upload to Codecov
        uses: codecov/codecov-action@v4
        with:
          files: lcov.info
          fail_ci_if_error: true

"#
        .to_string()
    }

    fn github_miri_job(&self) -> String {
        r#"  miri:
    name: Miri (UB Detection)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
        with:
          components: miri
      - uses: Swatinem/rust-cache@v2
      - name: Setup Miri
        run: cargo miri setup
      - name: Run tests under Miri
        run: cargo miri test --all-features
        env:
          MIRIFLAGS: -Zmiri-disable-isolation -Zmiri-strict-provenance

"#
        .to_string()
    }

    fn github_fuzz_job(&self) -> String {
        r#"  fuzz:
    name: Fuzz Testing
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
      - uses: Swatinem/rust-cache@v2
      - name: Install cargo-fuzz
        run: cargo install cargo-fuzz
      - name: Run fuzzer (60 seconds per target)
        run: |
          for target in $(cargo fuzz list); do
            cargo fuzz run $target -- -max_total_time=60
          done

"#
        .to_string()
    }

    fn github_docs_job(&self) -> String {
        r#"  docs:
    name: Documentation
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - name: Build documentation
        run: cargo doc --all-features --no-deps
        env:
          RUSTDOCFLAGS: --cfg docsrs -D warnings
      - name: Upload docs
        uses: actions/upload-pages-artifact@v3
        with:
          path: target/doc

"#
        .to_string()
    }

    fn github_release_job(&self) -> String {
        let mut matrix_entries = String::new();
        for target in &self.config.targets {
            let os = if target.contains("linux") {
                "ubuntu-latest"
            } else if target.contains("darwin") || target.contains("apple") {
                "macos-latest"
            } else if target.contains("windows") {
                "windows-latest"
            } else {
                "ubuntu-latest"
            };
            matrix_entries.push_str(&format!(
                "          - {{ target: {}, os: {} }}\n",
                target, os
            ));
        }

        format!(
            r#"  release:
    name: Release Build
    if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/')
    needs: [test, clippy, security-audit]
    runs-on: ${{{{ matrix.os }}}}
    strategy:
      matrix:
        include:
{}    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@{}
        with:
          targets: ${{{{ matrix.target }}}}
      - uses: Swatinem/rust-cache@v2
      - name: Build release binary
        run: cargo build --release --target ${{{{ matrix.target }}}}
      - name: Upload artifact
        uses: actions/upload-artifact@v4
        with:
          name: binary-${{{{ matrix.target }}}}
          path: target/${{{{ matrix.target }}}}/release/

"#,
            matrix_entries, self.config.rust_version
        )
    }

    fn generate_gitlab_ci(&self) -> String {
        let mut output = String::new();

        output.push_str("stages:\n");
        output.push_str("  - check\n");
        output.push_str("  - test\n");
        output.push_str("  - security\n");
        if self.config.features.release_build {
            output.push_str("  - release\n");
        }
        output.push('\n');

        output.push_str("variables:\n");
        output.push_str(&format!(
            "  RUST_VERSION: \"{}\"\n",
            self.config.rust_version
        ));
        output.push_str("  CARGO_HOME: $CI_PROJECT_DIR/.cargo\n\n");

        output.push_str("cache:\n");
        output.push_str("  key: $CI_COMMIT_REF_SLUG\n");
        output.push_str("  paths:\n");
        output.push_str("    - .cargo/\n");
        output.push_str("    - target/\n\n");

        // Format job
        if self.config.features.rustfmt {
            output.push_str(
                r#"format:
  stage: check
  image: rust:latest
  script:
    - rustup component add rustfmt
    - cargo fmt --all -- --check

"#,
            );
        }

        // Clippy job
        if self.config.features.clippy {
            output.push_str(
                r#"clippy:
  stage: check
  image: rust:latest
  script:
    - rustup component add clippy
    - cargo clippy --all-targets --all-features -- -D warnings

"#,
            );
        }

        // Test job
        output.push_str(
            r#"test:
  stage: test
  image: rust:latest
  script:
    - cargo test --all-features --workspace
  artifacts:
    reports:
      junit: target/nextest/ci/junit.xml

"#,
        );

        // Security audit
        if self.config.features.security_audit {
            output.push_str(
                r#"security-audit:
  stage: security
  image: rust:latest
  script:
    - cargo install cargo-audit cargo-deny
    - cargo audit
    - cargo deny check
  allow_failure: true

"#,
            );
        }

        output
    }

    fn generate_jenkinsfile(&self) -> String {
        let mut output = String::new();

        output.push_str("pipeline {\n");
        output.push_str("    agent any\n\n");

        output.push_str("    environment {\n");
        output.push_str(&format!(
            "        RUST_VERSION = '{}'\n",
            self.config.rust_version
        ));
        output.push_str("        CARGO_HOME = \"${WORKSPACE}/.cargo\"\n");
        output.push_str("    }\n\n");

        output.push_str("    stages {\n");

        // Setup stage
        output.push_str("        stage('Setup') {\n");
        output.push_str("            steps {\n");
        output.push_str("                sh 'rustup default ${RUST_VERSION}'\n");
        output.push_str("                sh 'rustup component add clippy rustfmt'\n");
        output.push_str("            }\n");
        output.push_str("        }\n\n");

        // Format stage
        if self.config.features.rustfmt {
            output.push_str("        stage('Format') {\n");
            output.push_str("            steps {\n");
            output.push_str("                sh 'cargo fmt --all -- --check'\n");
            output.push_str("            }\n");
            output.push_str("        }\n\n");
        }

        // Clippy stage
        if self.config.features.clippy {
            output.push_str("        stage('Lint') {\n");
            output.push_str("            steps {\n");
            output.push_str("                sh 'cargo clippy --all-targets -- -D warnings'\n");
            output.push_str("            }\n");
            output.push_str("        }\n\n");
        }

        // Test stage
        output.push_str("        stage('Test') {\n");
        output.push_str("            steps {\n");
        output.push_str("                sh 'cargo test --all-features'\n");
        output.push_str("            }\n");
        output.push_str("        }\n\n");

        // Security stage
        if self.config.features.security_audit {
            output.push_str("        stage('Security') {\n");
            output.push_str("            steps {\n");
            output.push_str("                sh 'cargo install cargo-audit'\n");
            output.push_str("                sh 'cargo audit'\n");
            output.push_str("            }\n");
            output.push_str("        }\n\n");
        }

        // Build stage
        if self.config.features.release_build {
            output.push_str("        stage('Build') {\n");
            output.push_str("            steps {\n");
            output.push_str("                sh 'cargo build --release'\n");
            output.push_str("            }\n");
            output.push_str("        }\n");
        }

        output.push_str("    }\n\n");

        // Post actions
        output.push_str("    post {\n");
        output.push_str("        always {\n");
        output.push_str("            cleanWs()\n");
        output.push_str("        }\n");
        output.push_str("    }\n");

        output.push_str("}\n");

        output
    }

    fn generate_circleci(&self) -> String {
        let mut output = String::new();

        output.push_str("version: 2.1\n\n");

        output.push_str("executors:\n");
        output.push_str("  rust:\n");
        output.push_str(&format!(
            "    docker:\n      - image: rust:{}\n\n",
            self.config.rust_version
        ));

        output.push_str("jobs:\n");

        // Test job
        output.push_str("  test:\n");
        output.push_str("    executor: rust\n");
        output.push_str("    steps:\n");
        output.push_str("      - checkout\n");
        output.push_str("      - run: cargo test --all-features\n\n");

        // Clippy job
        if self.config.features.clippy {
            output.push_str("  lint:\n");
            output.push_str("    executor: rust\n");
            output.push_str("    steps:\n");
            output.push_str("      - checkout\n");
            output.push_str("      - run: rustup component add clippy\n");
            output.push_str("      - run: cargo clippy -- -D warnings\n\n");
        }

        // Security job
        if self.config.features.security_audit {
            output.push_str("  security:\n");
            output.push_str("    executor: rust\n");
            output.push_str("    steps:\n");
            output.push_str("      - checkout\n");
            output.push_str("      - run: cargo install cargo-audit\n");
            output.push_str("      - run: cargo audit\n\n");
        }

        output.push_str("workflows:\n");
        output.push_str("  ci:\n");
        output.push_str("    jobs:\n");
        output.push_str("      - test\n");
        if self.config.features.clippy {
            output.push_str("      - lint\n");
        }
        if self.config.features.security_audit {
            output.push_str("      - security\n");
        }

        output
    }
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            name: "CI".to_string(),
            platform: CiPlatform::GitHubActions,
            rust_version: "stable".to_string(),
            targets: vec![
                "x86_64-unknown-linux-gnu".to_string(),
                "x86_64-apple-darwin".to_string(),
                "x86_64-pc-windows-msvc".to_string(),
            ],
            features: PipelineFeatures::default(),
            environment: HashMap::new(),
            secrets: Vec::new(),
        }
    }
}

impl PipelineFeatures {
    /// Enable all security features
    pub fn security_focused() -> Self {
        Self {
            security_audit: true,
            dependency_check: true,
            code_coverage: true,
            fuzzing: true,
            clippy: true,
            rustfmt: true,
            miri: true,
            documentation: true,
            release_build: true,
            container_scan: true,
            ..Default::default()
        }
    }

    /// Minimal CI setup
    pub fn minimal() -> Self {
        Self {
            clippy: true,
            rustfmt: true,
            ..Default::default()
        }
    }
}

impl fmt::Display for CiPlatform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CiPlatform::GitHubActions => write!(f, "GitHub Actions"),
            CiPlatform::GitLabCi => write!(f, "GitLab CI"),
            CiPlatform::Jenkins => write!(f, "Jenkins"),
            CiPlatform::CircleCi => write!(f, "CircleCI"),
        }
    }
}

fn main() {
    println!("=== CI/CD Pipeline Generator Demo ===\n");

    // Create security-focused config
    let config = PipelineConfig {
        name: "Security CI".to_string(),
        platform: CiPlatform::GitHubActions,
        rust_version: "1.92.0".to_string(),
        targets: vec![
            "x86_64-unknown-linux-gnu".to_string(),
            "aarch64-unknown-linux-gnu".to_string(),
            "x86_64-apple-darwin".to_string(),
        ],
        features: PipelineFeatures::security_focused(),
        environment: {
            let mut env = HashMap::new();
            env.insert("RUST_BACKTRACE".to_string(), "1".to_string());
            env.insert("CARGO_TERM_COLOR".to_string(), "always".to_string());
            env
        },
        secrets: vec!["CODECOV_TOKEN".to_string()],
    };

    println!("Generating {} pipeline:\n", config.platform);
    println!("Features enabled:");
    println!("  - Security audit: {}", config.features.security_audit);
    println!("  - Fuzzing: {}", config.features.fuzzing);
    println!("  - Miri: {}", config.features.miri);
    println!("  - Coverage: {}", config.features.code_coverage);
    println!();

    let generator = PipelineGenerator::new(config.clone());
    let pipeline = generator.generate();

    println!("=== Generated .github/workflows/ci.yml ===\n");
    println!("{}", pipeline);

    // Generate GitLab CI
    println!("\n=== GitLab CI Example ===\n");
    let gitlab_config = PipelineConfig {
        platform: CiPlatform::GitLabCi,
        features: PipelineFeatures::minimal(),
        ..config.clone()
    };
    let gitlab_generator = PipelineGenerator::new(gitlab_config);
    println!("{}", gitlab_generator.generate());

    // Generate Jenkinsfile
    println!("\n=== Jenkinsfile Example ===\n");
    let jenkins_config = PipelineConfig {
        platform: CiPlatform::Jenkins,
        features: PipelineFeatures {
            security_audit: true,
            clippy: true,
            rustfmt: true,
            release_build: true,
            ..Default::default()
        },
        ..config
    };
    let jenkins_generator = PipelineGenerator::new(jenkins_config);
    println!("{}", jenkins_generator.generate());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = PipelineConfig::default();
        assert_eq!(config.platform, CiPlatform::GitHubActions);
        assert_eq!(config.rust_version, "stable");
    }

    #[test]
    fn test_github_actions_generation() {
        let config = PipelineConfig {
            features: PipelineFeatures {
                clippy: true,
                rustfmt: true,
                ..Default::default()
            },
            ..Default::default()
        };

        let generator = PipelineGenerator::new(config);
        let output = generator.generate();

        assert!(output.contains("name: CI"));
        assert!(output.contains("clippy"));
        assert!(output.contains("cargo fmt"));
    }

    #[test]
    fn test_security_audit_job() {
        let config = PipelineConfig {
            features: PipelineFeatures {
                security_audit: true,
                ..Default::default()
            },
            ..Default::default()
        };

        let generator = PipelineGenerator::new(config);
        let output = generator.generate();

        assert!(output.contains("security-audit"));
        assert!(output.contains("cargo-audit"));
        assert!(output.contains("cargo-deny"));
    }

    #[test]
    fn test_miri_job() {
        let config = PipelineConfig {
            features: PipelineFeatures {
                miri: true,
                ..Default::default()
            },
            ..Default::default()
        };

        let generator = PipelineGenerator::new(config);
        let output = generator.generate();

        assert!(output.contains("miri"));
        assert!(output.contains("Miri"));
    }

    #[test]
    fn test_coverage_job() {
        let config = PipelineConfig {
            features: PipelineFeatures {
                code_coverage: true,
                ..Default::default()
            },
            ..Default::default()
        };

        let generator = PipelineGenerator::new(config);
        let output = generator.generate();

        assert!(output.contains("coverage"));
        assert!(output.contains("llvm-cov"));
    }

    #[test]
    fn test_gitlab_ci_generation() {
        let config = PipelineConfig {
            platform: CiPlatform::GitLabCi,
            features: PipelineFeatures::minimal(),
            ..Default::default()
        };

        let generator = PipelineGenerator::new(config);
        let output = generator.generate();

        assert!(output.contains("stages:"));
        assert!(output.contains("image: rust:"));
    }

    #[test]
    fn test_jenkinsfile_generation() {
        let config = PipelineConfig {
            platform: CiPlatform::Jenkins,
            ..Default::default()
        };

        let generator = PipelineGenerator::new(config);
        let output = generator.generate();

        assert!(output.contains("pipeline {"));
        assert!(output.contains("agent any"));
    }

    #[test]
    fn test_circleci_generation() {
        let config = PipelineConfig {
            platform: CiPlatform::CircleCi,
            ..Default::default()
        };

        let generator = PipelineGenerator::new(config);
        let output = generator.generate();

        assert!(output.contains("version: 2.1"));
        assert!(output.contains("executors:"));
    }

    #[test]
    fn test_release_job_with_targets() {
        let config = PipelineConfig {
            targets: vec![
                "x86_64-unknown-linux-gnu".to_string(),
                "x86_64-apple-darwin".to_string(),
            ],
            features: PipelineFeatures {
                release_build: true,
                ..Default::default()
            },
            ..Default::default()
        };

        let generator = PipelineGenerator::new(config);
        let output = generator.generate();

        assert!(output.contains("release"));
        assert!(output.contains("x86_64-unknown-linux-gnu"));
        assert!(output.contains("x86_64-apple-darwin"));
    }

    #[test]
    fn test_security_focused_features() {
        let features = PipelineFeatures::security_focused();

        assert!(features.security_audit);
        assert!(features.fuzzing);
        assert!(features.miri);
        assert!(features.code_coverage);
    }

    #[test]
    fn test_environment_variables() {
        let config = PipelineConfig {
            environment: {
                let mut env = HashMap::new();
                env.insert("RUST_BACKTRACE".to_string(), "1".to_string());
                env
            },
            ..Default::default()
        };

        let generator = PipelineGenerator::new(config);
        let output = generator.generate();

        assert!(output.contains("RUST_BACKTRACE"));
    }
}
