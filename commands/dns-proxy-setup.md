# DNS Proxy Setup Command

## Overview

**Command:** `/rust-security:dns-proxy-setup`

Configures secure DNS proxy with DoH/DoT support, DNS sinkholing, ad/tracker
blocking, and query logging.

**Agent:** `dns-security-builder` (Sonnet - Standard Analysis)

---

## When to Use

- Setting up secure DNS for network
- Implementing DNS-over-HTTPS (DoH)
- Implementing DNS-over-TLS (DoT)
- Blocking ads and trackers at DNS level
- DNS sinkholing for malicious domains

---

## What It Does

1. **Creates DNS server** - UDP/TCP DNS listener
2. **Implements DoH client** - HTTPS upstream queries
3. **Implements DoT client** - TLS upstream queries
4. **Configures sinkholing** - Malicious domain blocking
5. **Sets up blocklists** - Ad/tracker domain lists
6. **Implements caching** - Response caching
7. **Enables query logging** - Audit logging

---

## Parameters

| Parameter      | Type   | Required | Default       | Description                                       |
| -------------- | ------ | -------- | ------------- | ------------------------------------------------- |
| `--upstream`   | string | No       | `cloudflare`  | Upstream: `cloudflare`, `google`, `quad9`, custom |
| `--mode`       | string | No       | `doh`         | Mode: `doh`, `dot`, `hybrid`                      |
| `--blocklists` | string | No       | `ads,malware` | Blocklists to enable                              |
| `--port`       | number | No       | `53`          | Listen port                                       |
| `--output`     | string | No       | `src/dns/`    | Output directory                                  |

---

## Output

Creates DNS proxy module:

- `src/dns/mod.rs` - Module exports
- `src/dns/server.rs` - DNS server
- `src/dns/doh.rs` - DoH client
- `src/dns/dot.rs` - DoT client
- `src/dns/blocklist.rs` - Blocklist management
- `src/dns/cache.rs` - Response caching
- `blocklists/` - Blocklist files
- `config/dns.toml` - DNS configuration

---

## Examples

### Example 1: Default Setup (DoH + Cloudflare)

```bash
/rust-security:dns-proxy-setup
```

### Example 2: DoT Mode with Google

```bash
/rust-security:dns-proxy-setup --mode=dot --upstream=google
```

### Example 3: All Blocklists

```bash
/rust-security:dns-proxy-setup --blocklists=ads,malware,trackers,phishing
```

---

## Related Commands

- **[/rust-security:router-security-init](router-security-init.md)** - Router
  security
- **[/rust-security:threat-feeds-setup](threat-feeds-setup.md)** - Threat
  intelligence
- **[/rust-security:gateway-security-init](gateway-security-init.md)** - Gateway
  security
