# Nginx Config Command

## Overview

**Command:** `/rust-security:nginx-config`

Generates security-hardened Nginx configuration with TLS best practices, rate
limiting, security headers, and WAF-like protections.

**Agent:** `nginx-configurator` (Sonnet - Standard Analysis)

---

## When to Use

- Setting up Nginx for production deployments
- Hardening existing Nginx configurations
- Configuring TLS with modern cipher suites
- Adding rate limiting and security headers
- Reverse proxy configuration for Rust services

---

## What It Does

1. **Generates TLS configuration** - Modern cipher suites, HSTS
2. **Adds security headers** - CSP, X-Frame-Options, etc.
3. **Configures rate limiting** - Request and connection limits
4. **Sets up WAF rules** - Basic attack pattern blocking
5. **Configures caching** - Static asset and proxy caching
6. **Creates upstream blocks** - Load balancing configuration
7. **Generates test configuration** - nginx -t validation

---

## Parameters

| Parameter    | Type   | Required | Default          | Description                                     |
| ------------ | ------ | -------- | ---------------- | ----------------------------------------------- |
| `--domain`   | string | Yes      | None             | Primary domain name                             |
| `--upstream` | string | No       | `localhost:8080` | Backend server address                          |
| `--tls`      | string | No       | `modern`         | TLS profile: `modern`, `intermediate`, `legacy` |
| `--output`   | string | No       | `nginx/`         | Output directory                                |

---

## Output

Creates Nginx configuration:

- `nginx/nginx.conf` - Main configuration
- `nginx/conf.d/{domain}.conf` - Site configuration
- `nginx/snippets/ssl.conf` - TLS settings
- `nginx/snippets/security-headers.conf` - Security headers
- `nginx/snippets/rate-limiting.conf` - Rate limit zones
- `nginx/snippets/proxy-params.conf` - Proxy settings

---

## Examples

### Example 1: Basic Setup

```bash
/rust-security:nginx-config --domain=example.com
```

### Example 2: Custom Upstream

```bash
/rust-security:nginx-config --domain=api.example.com --upstream=localhost:3000
```

### Example 3: Intermediate TLS (Older Client Support)

```bash
/rust-security:nginx-config --domain=example.com --tls=intermediate
```

---

## Generated Security Headers

```nginx
# Security headers
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'" always;
add_header Permissions-Policy "geolocation=(), microphone=()" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

---

## Related Commands

- **[/rust-security:cert-rotate](cert-rotate.md)** - TLS certificate management
- **[/rust-security:gunicorn-config](gunicorn-config.md)** - Backend
  configuration
- **[/rust-security:server-harden](server-harden.md)** - Server hardening
