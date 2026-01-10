# Plugin Tools

Rust-based tools that provide Rust ecosystem integration for Claude Code agents.

## Available Tools

1. **cargo-tool** - Cargo project metadata extraction
2. **rustc-tool** - Rust toolchain detection
3. **vuln-db-tool** - RustSec vulnerability database management
4. **audit-tool** - Security audit orchestration
5. **fuzzer-tool** - Fuzzing infrastructure management
6. **compliance-tool** - Compliance report generation

## Usage

All tools follow a consistent CLI interface:

```bash
cargo run --bin TOOL_NAME -- COMMAND [OPTIONS]
```

Or after building:

```bash
./target/release/TOOL_NAME COMMAND [OPTIONS]
```

## Requirements

- Rust toolchain (cargo, rustc) >= 1.70.0
- Optional: cargo-audit, cargo-deny, cargo-geiger, cargo-fuzz

## Building

```bash
cargo build --release
```

This will build all plugin tools in `target/release/`.

## Security

Tools run in a sandboxed environment with restricted system access. See config.json for security policies.
