# Gateway Security Init Command

## Overview

**Command:** `/rust-security:gateway-security-init`

Initialises a Rust internet gateway security wrapper project with HTTPS
inspection, download scanning, phishing detection, and content filtering.

**Agent:** `gateway-security-builder` (Sonnet - Standard Analysis)

---

## When to Use

- Building secure internet gateway with NixOS
- Implementing HTTPS inspection proxy
- Download scanning for malware
- Phishing and malicious site blocking
- Content filtering and safe browsing

---

## What It Does

1. **Creates project structure** - Cargo workspace for gateway security
2. **Implements HTTPS proxy** - MITM inspection for owned devices
3. **Adds download scanning** - Executable and archive scanning
4. **Integrates phishing detection** - Malicious URL blocking
5. **Implements content filtering** - Category-based filtering
6. **Configures CA management** - Certificate generation
7. **Creates NixOS module** - Declarative deployment

---

## Parameters

| Parameter    | Type   | Required | Default             | Description        |
| ------------ | ------ | -------- | ------------------- | ------------------ |
| `--name`     | string | No       | `gateway-security`  | Project name       |
| `--features` | string | No       | `https,scan,filter` | Features to enable |
| `--port`     | number | No       | `8443`              | Proxy listen port  |
| `--output`   | string | No       | `./`                | Output directory   |

---

## Output

Creates gateway security project:

```
gateway-security/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── proxy/            # HTTPS proxy
│   ├── scanner/          # Download scanning
│   ├── phishing/         # Phishing detection
│   ├── filter/           # Content filtering
│   ├── ca/               # CA management
│   └── config.rs
├── certs/
│   └── README.md         # CA setup instructions
├── config/
│   └── gateway.toml
├── nixos/
│   └── module.nix
└── systemd/
    └── gateway-security.service
```

---

## Examples

### Example 1: Full Gateway Security

```bash
/rust-security:gateway-security-init
```

### Example 2: HTTPS Inspection Only

```bash
/rust-security:gateway-security-init --features=https
```

### Example 3: Custom Port

```bash
/rust-security:gateway-security-init --port=3128
```

---

## Related Commands

- **[/rust-security:dns-proxy-setup](dns-proxy-setup.md)** - DNS security
- **[/rust-security:malware-scanner-setup](malware-scanner-setup.md)** - Malware
  scanning
- **[/rust-security:threat-feeds-setup](threat-feeds-setup.md)** - Threat
  intelligence
