# Rust Workspace Security Template

## Overview

Multi-crate workspace template with shared security configuration, dependency
management, and unified auditing.

## Project Structure

```
my-workspace/
├── Cargo.toml
├── deny.toml
├── rustfmt.toml
├── clippy.toml
├── crates/
│   ├── core/
│   │   ├── Cargo.toml
│   │   └── src/lib.rs
│   ├── crypto/
│   │   ├── Cargo.toml
│   │   └── src/lib.rs
│   └── api/
│       ├── Cargo.toml
│       └── src/lib.rs
├── .github/
│   └── workflows/
│       └── security.yml
└── README.md
```

## Cargo.toml (Workspace Root)

```toml
[workspace]
members = ["crates/*"]
resolver = "2"

[workspace.package]
version = "0.1.0"
edition = "2021"
rust-version = "1.92.0"
license = "MIT"

[workspace.dependencies]
# Shared dependencies
tokio = { version = "1.40", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
thiserror = "2.0"
tracing = "0.1"

# Security dependencies
zeroize = { version = "1.8", features = ["derive"] }
secrecy = "0.10"
aes-gcm = "0.10"
rand = "0.8"

[profile.release]
lto = true
codegen-units = 1
strip = true
panic = "abort"
overflow-checks = true

[profile.dev]
overflow-checks = true
```

## deny.toml

```toml
[advisories]
vulnerability = "deny"
unmaintained = "warn"
yanked = "deny"

[licenses]
unlicensed = "deny"
allow = ["MIT", "Apache-2.0", "BSD-3-Clause"]

[bans]
multiple-versions = "warn"
wildcards = "deny"

[sources]
unknown-registry = "deny"
unknown-git = "deny"
```

## Security Checklist

- [ ] Workspace resolver = "2"
- [ ] Shared security dependencies
- [ ] cargo-deny configured
- [ ] Release profile hardened
- [ ] CI security checks
