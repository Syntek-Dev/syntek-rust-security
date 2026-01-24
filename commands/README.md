# Syntek Rust Security Commands

This directory contains command markdown files that describe the available
commands in the syntek-rust-security plugin.

## Setup Commands (1)

1. **init.md** - Initialize a project with the Syntek Rust Security plugin

## Security Commands (10)

1. **threat-model.md** - STRIDE threat analysis for Rust projects
2. **vuln-scan.md** - Vulnerability scanning with cargo-audit and cargo-deny
3. **crypto-review.md** - Cryptographic implementation review
4. **memory-audit.md** - Memory safety and unsafe code auditing
5. **fuzz-setup.md** - Fuzzing infrastructure setup (libFuzzer, AFL++,
   honggfuzz)
6. **scan-secrets.md** - Secret detection in code and git history
7. **supply-chain-audit.md** - Dependency supply chain security analysis
8. **pentest-tools.md** - Custom penetration testing tool generation
9. **binary-check.md** - Binary hardening verification (ASLR, DEP, PIE, RELRO)
10. **compliance-report.md** - OWASP, CWE, CVSS compliance reporting

## Infrastructure Commands (12)

11. **version-bump.md** - Semantic versioning and changelog management
12. **generate-docs.md** - Rustdoc and documentation generation
13. **gdpr-check.md** - GDPR compliance verification
14. **write-support-article.md** - User-facing help documentation
15. **git-workflow.md** - Git branch management and release workflows
16. **refactor-code.md** - Code refactoring with ownership optimization
17. **review-code.md** - Expert code review with security focus
18. **write-tests.md** - Test generation (unit, integration, property-based)
19. **benchmark.md** - Performance benchmarking with criterion.rs
20. **manage-deps.md** - Dependency management and optimization
21. **minimize-unsafe.md** - Unsafe code minimization and auditing
22. **design-api.md** - Type-safe API design following Rust guidelines

## Command Structure

Each command file follows this structure:

- **Overview** - Command description and agent information
- **When to Use** - Scenarios for using the command
- **What It Does** - Detailed functionality breakdown
- **Parameters** - Command-line parameters and options
- **Output** - Expected console and file output
- **Examples** - Usage examples with different scenarios
- **Best Practices** - Guidelines and recommendations
- **Related Commands** - Links to related commands

## Agent Models

The plugin uses two Claude models:

### Opus Agents (Deep Reasoning)

- threat-model (threat-modeller)
- crypto-review (crypto-reviewer)
- pentest-tools (pentester)
- gdpr-check (rust-gdpr)
- refactor-code (rust-refactor)
- review-code (rust-review)
- minimize-unsafe (rust-unsafe-minimiser)
- design-api (rust-api-designer)

### Sonnet Agents (Standard Analysis)

- vuln-scan (vuln-scanner)
- memory-audit (memory-safety)
- fuzz-setup (fuzzer)
- scan-secrets (secrets-auditor)
- supply-chain-audit (supply-chain)
- binary-check (binary-analyser)
- compliance-report (compliance-auditor)
- version-bump (rust-version)
- generate-docs (rust-docs)
- write-support-article (rust-support-articles)
- git-workflow (rust-git)
- write-tests (rust-test-writer)
- benchmark (rust-benchmarker)
- manage-deps (rust-dependency-manager)

## Usage

Commands are invoked using the plugin namespace:

```bash
/rust-security:command-name [parameters]
```

For example:

```bash
# Initialize the plugin in your project
/rust-security:init

# Run security scans
/rust-security:threat-model
/rust-security:vuln-scan --output=report.json
/rust-security:crypto-review --target=src/crypto/
```

## Documentation

Each command file contains:

- Detailed parameter descriptions
- Multiple usage examples
- Best practices and guidelines
- Code snippets and templates
- Related command references

See individual command files for complete documentation.
