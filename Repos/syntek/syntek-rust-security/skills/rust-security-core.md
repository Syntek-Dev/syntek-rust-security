# Rust Security Core Skills

This skill provides core security scanning and auditing capabilities for Rust projects.

## /vuln-scan

Scan your Rust project for known vulnerabilities using cargo-audit and cargo-deny.

### Usage
```bash
/vuln-scan
```

### What It Does
1. Runs `cargo audit` to check dependencies against RustSec Advisory Database
2. Runs `cargo deny check` for license and security policy enforcement
3. Identifies outdated dependencies with `cargo outdated`
4. Generates a comprehensive vulnerability report
5. Provides remediation recommendations

### Output
- List of vulnerabilities with severity ratings (Critical/High/Medium/Low)
- Affected crate versions and patched versions
- CVE identifiers and CVSS scores
- Recommended actions for each vulnerability
- Summary of unmaintained crates

### Prerequisites
- `cargo-audit` installed: `cargo install cargo-audit`
- `cargo-deny` installed: `cargo install cargo-deny`
- `cargo-outdated` installed: `cargo install cargo-outdated`

---

## /memory-audit

Analyze unsafe code blocks and verify memory safety in your Rust project.

### Usage
```bash
/memory-audit
```

### What It Does
1. Scans for all `unsafe` blocks in the codebase
2. Verifies safety documentation (SAFETY comments)
3. Checks FFI boundaries for safety invariants
4. Runs Miri tests if available
5. Suggests safer alternatives where possible

### Output
- Count of unsafe blocks and their locations
- Undocumented unsafe code
- FFI safety analysis
- Recommendations for reducing unsafe surface area
- Miri test results

### Prerequisites
- Miri: `rustup +nightly component add miri`
- Optional: `cargo-geiger` for unsafe usage metrics

---

## /threat-model

Perform STRIDE threat analysis on your Rust application.

### Usage
```bash
/threat-model
```

### What It Does
1. Analyzes application architecture
2. Identifies trust boundaries and attack surfaces
3. Applies STRIDE methodology to each component
4. Assesses Rust-specific security concerns
5. Generates prioritized threat list with mitigations

### Output
- Architecture overview with trust boundaries
- Identified threats categorized by STRIDE
- Risk assessment (likelihood × impact)
- Mitigation recommendations
- Residual risk documentation

### STRIDE Categories
- **S**poofing: Identity/authentication threats
- **T**ampering: Data integrity threats
- **R**epudiation: Non-repudiation threats
- **I**nformation Disclosure: Confidentiality threats
- **D**enial of Service: Availability threats
- **E**levation of Privilege: Authorization threats

---

## Agent Invocation

These skills invoke specialized agents that have access to all tools. The agents will:
- Read and analyze your codebase
- Run security scanning tools
- Generate detailed reports
- Provide actionable recommendations
- Create tracking issues if needed

## Best Practices

1. **Run /vuln-scan regularly** - Ideally before each release and in CI/CD
2. **Audit unsafe code** - Run /memory-audit when adding unsafe blocks
3. **Threat model early** - Run /threat-model during design phase
4. **Track findings** - Document and prioritize security issues
5. **Automate** - Integrate scans into your development workflow
