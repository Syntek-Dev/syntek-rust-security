# Gunicorn Config Command

## Overview

**Command:** `/rust-security:gunicorn-config`

Generates secure Gunicorn and Uvicorn configuration for Django and FastAPI
applications with worker management, timeouts, and security settings.

**Agent:** `gunicorn-configurator` (Sonnet - Standard Analysis)

---

## When to Use

- Deploying Django applications with Gunicorn
- Setting up FastAPI with Uvicorn workers
- Configuring worker processes and threads
- Implementing graceful shutdown
- Production hardening for Python backends

---

## What It Does

1. **Generates Gunicorn config** - Worker class, count, timeouts
2. **Configures Uvicorn** - ASGI settings for async frameworks
3. **Sets security options** - Request limits, header sizes
4. **Creates systemd service** - Production deployment
5. **Configures logging** - Structured logging setup
6. **Sets resource limits** - Memory and file descriptor limits
7. **Enables health checks** - Readiness and liveness probes

---

## Parameters

| Parameter        | Type   | Required | Default                         | Description                    |
| ---------------- | ------ | -------- | ------------------------------- | ------------------------------ |
| `--framework`    | string | No       | `django`                        | Framework: `django`, `fastapi` |
| `--workers`      | number | No       | `auto`                          | Worker count (auto = 2\*CPU+1) |
| `--worker-class` | string | No       | `uvicorn.workers.UvicornWorker` | Worker class                   |
| `--bind`         | string | No       | `127.0.0.1:8000`                | Bind address                   |
| `--output`       | string | No       | `config/`                       | Output directory               |

---

## Output

Creates Gunicorn configuration:

- `config/gunicorn.conf.py` - Gunicorn configuration
- `config/uvicorn.json` - Uvicorn settings (if FastAPI)
- `systemd/gunicorn.service` - Systemd service file
- `systemd/gunicorn.socket` - Socket activation (optional)
- `scripts/start.sh` - Startup script

---

## Examples

### Example 1: Django with Defaults

```bash
/rust-security:gunicorn-config
```

### Example 2: FastAPI with Custom Workers

```bash
/rust-security:gunicorn-config --framework=fastapi --workers=4
```

### Example 3: Custom Bind Address

```bash
/rust-security:gunicorn-config --bind=0.0.0.0:8080
```

---

## Generated Configuration

```python
# gunicorn.conf.py
bind = "127.0.0.1:8000"
workers = 5
worker_class = "uvicorn.workers.UvicornWorker"
timeout = 30
keepalive = 5
max_requests = 1000
max_requests_jitter = 50
graceful_timeout = 30
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190
```

---

## Related Commands

- **[/rust-security:nginx-config](nginx-config.md)** - Nginx reverse proxy
- **[/rust-security:systemd-harden](systemd-harden.md)** - Service hardening
- **[/rust-security:docker-harden](docker-harden.md)** - Container configuration
