# Threat Feeds Setup Command

## Overview

**Command:** `/rust-security:threat-feeds-setup`

Configures threat intelligence feed integration with IP/domain blocklists, IOC
management, and automated updates.

**Agent:** `threat-intel-integrator` (Sonnet - Standard Analysis)

---

## When to Use

- Setting up threat intelligence for security appliances
- Integrating IP/domain blocklists
- Managing indicators of compromise (IOCs)
- Configuring automated feed updates
- Building threat intelligence platform

---

## What It Does

1. **Configures feed sources** - Multiple threat feeds
2. **Implements IOC database** - SQLite-based storage
3. **Sets up normalization** - Consistent IOC format
4. **Configures updates** - Scheduled feed updates
5. **Implements export** - Multiple export formats
6. **Creates API** - IOC lookup API
7. **Enables STIX/TAXII** - Standard threat sharing

---

## Parameters

| Parameter  | Type    | Required | Default                     | Description               |
| ---------- | ------- | -------- | --------------------------- | ------------------------- |
| `--feeds`  | string  | No       | `abuse.ch,emerging-threats` | Feed sources              |
| `--stix`   | boolean | No       | `false`                     | Enable STIX/TAXII support |
| `--api`    | boolean | No       | `true`                      | Enable lookup API         |
| `--update` | string  | No       | `1h`                        | Update interval           |
| `--output` | string  | No       | `src/threatintel/`          | Output directory          |

---

## Output

Creates threat intel module:

- `src/threatintel/mod.rs` - Module exports
- `src/threatintel/feeds.rs` - Feed fetching
- `src/threatintel/database.rs` - IOC database
- `src/threatintel/normalize.rs` - IOC normalization
- `src/threatintel/export.rs` - Export formats
- `src/threatintel/api.rs` - Lookup API
- `config/feeds.toml` - Feed configuration

---

## Supported Feeds

| Feed                   | Type   | Update Frequency |
| ---------------------- | ------ | ---------------- |
| Abuse.ch Feodo Tracker | IP     | Hourly           |
| Abuse.ch URLhaus       | URL    | Hourly           |
| MalwareBazaar          | Hash   | 6 hours          |
| Emerging Threats       | IP     | Daily            |
| Phishing Database      | Domain | 12 hours         |

---

## Examples

### Example 1: Default Setup

```bash
/rust-security:threat-feeds-setup
```

### Example 2: With STIX/TAXII

```bash
/rust-security:threat-feeds-setup --stix=true
```

### Example 3: Frequent Updates

```bash
/rust-security:threat-feeds-setup --update=15m
```

---

## Related Commands

- **[/rust-security:router-security-init](router-security-init.md)** - Router
  security
- **[/rust-security:ids-setup](ids-setup.md)** - Intrusion detection
- **[/rust-security:dns-proxy-setup](dns-proxy-setup.md)** - DNS security
