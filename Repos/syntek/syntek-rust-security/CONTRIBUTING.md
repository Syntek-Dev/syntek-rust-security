# Contributing to Syntek Rust Security Plugin

Thank you for your interest in contributing to the Syntek Rust Security Plugin! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Agent Development](#agent-development)
- [Skill Development](#skill-development)
- [Testing](#testing)
- [Documentation](#documentation)
- [Pull Request Process](#pull-request-process)
- [Release Process](#release-process)

## Code of Conduct

This project adheres to a code of conduct. By participating, you are expected to uphold this code:

- Be respectful and inclusive
- Welcome newcomers and help them learn
- Focus on what is best for the community
- Show empathy towards other community members

## Getting Started

### Prerequisites

- Rust 1.70 or higher
- Git
- Claude Code CLI
- Recommended: cargo-audit, cargo-deny, clippy, rustfmt

### Fork and Clone

```bash
# Fork the repository on GitHub
git clone https://github.com/YOUR_USERNAME/syntek-rust-security.git
cd syntek-rust-security

# Add upstream remote
git remote add upstream https://github.com/Syntek-Studio/syntek-rust-security.git
```

### Install Development Tools

```bash
# Install recommended Rust tools
cargo install cargo-audit
cargo install cargo-deny
cargo install cargo-geiger

# Install testing tools
cargo install cargo-tarpaulin
rustup component add clippy rustfmt
```

## Development Workflow

### Create a Feature Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/your-bug-fix
```

### Make Changes

1. Write your code following Rust conventions
2. Add tests for new functionality
3. Update documentation as needed
4. Run linters and formatters

```bash
cargo fmt
cargo clippy -- -D warnings
cargo test
```

### Commit Your Changes

Follow conventional commit format:

```bash
git commit -m "type(scope): brief description

Detailed explanation of changes.

Fixes #123"
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `security`

## Agent Development

Agents are specialized AI assistants for specific security tasks. Each agent is defined in a markdown file.

### Agent File Structure

```markdown
# Agent Name

You are a **[Role Title]** specialized in [expertise area].

## Role

[Clear description of the agent's purpose and capabilities]

## Capabilities

### Category 1
- Capability 1
- Capability 2

### Category 2
- Capability 3
- Capability 4

## Process

1. **Step 1**: Description
2. **Step 2**: Description
3. **Step 3**: Description

## Output Format

```markdown
# Output Template
[Expected output structure]
```

## Tools and Techniques

- Tool 1
- Tool 2
- Technique 1

## Best Practices

1. Best practice 1
2. Best practice 2

## Success Criteria

- Criterion 1
- Criterion 2
```

### Agent Naming Conventions

- Security agents: `/agents/security/[name].md`
- Infrastructure agents: `/agents/infrastructure/[name].md`
- Use kebab-case for file names
- Names should be descriptive and specific

### Agent Categories

**Security Agents** (10):
- threat-modeller
- vuln-scanner
- crypto-reviewer
- memory-safety
- fuzzer
- secrets-auditor
- supply-chain
- pentester
- binary-analyser
- compliance-auditor

**Infrastructure Agents** (12):
- rust-version
- rust-docs
- rust-gdpr
- rust-support-articles
- rust-git
- rust-refactor
- rust-review
- rust-test-writer
- rust-benchmarker
- rust-dependency-manager
- rust-unsafe-minimiser
- rust-api-designer

## Skill Development

Skills are user-invocable commands (e.g., `/vuln-scan`).

### Skill File Structure

```markdown
# Skill Name

## /command-name

Brief description of what this skill does.

### Usage
```bash
/command-name [arguments]
```

### What It Does
1. Step 1
2. Step 2
3. Step 3

### Output
- Output description

### Prerequisites
- Required tools
```

### Adding Skills to plugin.json

```json
{
  "skills": [
    {
      "name": "skill-name",
      "path": "skills/skill-file.md",
      "description": "Brief description",
      "userInvocable": true
    }
  ]
}
```

## Testing

### Running Tests

```bash
# Run all tests
cargo test

# Run tests with coverage
cargo tarpaulin --out Html

# Run doc tests
cargo test --doc

# Run integration tests
cargo test --test '*'
```

### Writing Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature() {
        // Arrange
        let input = setup_test_data();

        // Act
        let result = function_under_test(input);

        // Assert
        assert_eq!(result, expected);
    }
}
```

### Security Testing

- Run cargo-audit before committing
- Test for timing vulnerabilities
- Verify constant-time operations
- Check for memory leaks with valgrind/sanitizers

## Documentation

### Code Documentation

```rust
/// Brief description of function
///
/// # Arguments
///
/// * `arg1` - Description of arg1
/// * `arg2` - Description of arg2
///
/// # Returns
///
/// Description of return value
///
/// # Errors
///
/// When this function returns an error and why
///
/// # Examples
///
/// ```
/// use myapp::function;
///
/// let result = function(42)?;
/// assert_eq!(result, expected);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn function(arg1: i32, arg2: &str) -> Result<String, Error> {
    // Implementation
}
```

### README Updates

- Update README.md when adding new agents or skills
- Keep feature list current
- Update examples if API changes

### Changelog

Add entries to CHANGELOG.md:

```markdown
## [Unreleased]

### Added
- New feature description

### Changed
- Changed feature description

### Fixed
- Bug fix description
```

## Pull Request Process

### Before Submitting

- [ ] Code compiles without warnings
- [ ] All tests pass
- [ ] Code is formatted (`cargo fmt`)
- [ ] No clippy warnings (`cargo clippy -- -D warnings`)
- [ ] Documentation is updated
- [ ] CHANGELOG.md is updated
- [ ] Commits follow conventional format

### PR Description

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
Describe testing performed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests added/updated
- [ ] No new warnings
```

### Review Process

1. Automated checks must pass (CI/CD)
2. At least one maintainer review required
3. Address review feedback
4. Squash commits if requested
5. Maintainer will merge when approved

## Release Process

### Version Numbering

Follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backwards compatible)
- **PATCH**: Bug fixes

### Creating a Release

Maintainers only:

```bash
# Update version in Cargo.toml
cargo release patch --execute

# Tag release
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0

# Publish to crates.io (if applicable)
cargo publish
```

## Questions?

- **Issues**: [GitHub Issues](https://github.com/Syntek-Studio/syntek-rust-security/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Syntek-Studio/syntek-rust-security/discussions)
- **Security**: For security issues, email security@syntek.dev

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to Syntek Rust Security Plugin!
