# DPI Setup Command

## Overview

**Command:** `/rust-security:dpi-setup`

Configures deep packet inspection engine with protocol dissection, content
analysis, and traffic classification.

**Agent:** `dpi-setup` (Opus - Deep Reasoning)

---

## When to Use

- Setting up DPI for router security
- Implementing protocol dissection
- Traffic classification and analysis
- Application-layer filtering
- Network forensics

---

## What It Does

1. **Creates DPI engine** - Packet inspection framework
2. **Implements protocol parsers** - HTTP, TLS, DNS, etc.
3. **Adds content extraction** - Payload analysis
4. **Configures classification** - Traffic categorization
5. **Implements filtering** - Protocol-based filtering
6. **Creates statistics** - Traffic statistics
7. **Enables PCAP export** - Forensic capture

---

## Parameters

| Parameter     | Type    | Required | Default        | Description                      |
| ------------- | ------- | -------- | -------------- | -------------------------------- |
| `--protocols` | string  | No       | `http,tls,dns` | Protocols to parse               |
| `--depth`     | number  | No       | `1500`         | Maximum inspection depth (bytes) |
| `--pcap`      | boolean | No       | `true`         | Enable PCAP logging              |
| `--output`    | string  | No       | `src/dpi/`     | Output directory                 |

---

## Output

Creates DPI module:

- `src/dpi/mod.rs` - Module exports
- `src/dpi/engine.rs` - DPI engine
- `src/dpi/protocols/` - Protocol parsers
- `src/dpi/classify.rs` - Traffic classification
- `src/dpi/extract.rs` - Content extraction
- `src/dpi/pcap.rs` - PCAP logging
- `config/dpi.toml` - DPI configuration

---

## Supported Protocols

| Protocol    | Layer | Features                    |
| ----------- | ----- | --------------------------- |
| HTTP/1.1    | L7    | Headers, body, methods      |
| HTTP/2      | L7    | Stream extraction           |
| TLS 1.2/1.3 | L6    | JA3/JA4 fingerprinting, SNI |
| DNS         | L7    | Query/response parsing      |
| SMTP        | L7    | Email header extraction     |
| FTP         | L7    | Command parsing             |

---

## Examples

### Example 1: Default Setup

```bash
/rust-security:dpi-setup
```

### Example 2: All Protocols

```bash
/rust-security:dpi-setup --protocols=http,https,tls,dns,smtp,ftp
```

### Example 3: Lightweight (No PCAP)

```bash
/rust-security:dpi-setup --pcap=false --depth=512
```

---

## Reference Documents

This command invokes the `network-security-architect` agent. The agent reads these documents
from the target project's `.claude/` directory before starting work. Ensure the
project has been initialised with `/init`:

- **[CODING-PRINCIPLES.md](.claude/CODING-PRINCIPLES.md)**
- **[SECURITY.md](.claude/SECURITY.md)**
- **[TESTING.md](.claude/TESTING.md)**
- **[DEVELOPMENT.md](.claude/DEVELOPMENT.md)**
- **[API-DESIGN.md](.claude/API-DESIGN.md)**
- **[ARCHITECTURE-PATTERNS.md](.claude/ARCHITECTURE-PATTERNS.md)**
- **[DATA-STRUCTURES.md](.claude/DATA-STRUCTURES.md)**
- **[PERFORMANCE.md](.claude/PERFORMANCE.md)**

## Related Commands

- **[/rust-security:router-security-init](router-security-init.md)** - Router
  security
- **[/rust-security:ids-setup](ids-setup.md)** - Intrusion detection
- **[/rust-security:gateway-security-init](gateway-security-init.md)** - Gateway
  security
