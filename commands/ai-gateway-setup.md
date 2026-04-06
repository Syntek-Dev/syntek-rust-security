# AI Gateway Setup Command

## Overview

**Command:** `/rust-security:ai-gateway-setup`

Initialises a unified Rust AI API gateway supporting multiple providers
(Anthropic, OpenAI, Gemini, Azure, Perplexity) with rate limiting, circuit
breakers, and cost tracking.

**Agent:** `ai-gateway-setup` (Opus - Deep Reasoning)

---

## When to Use

- Building a centralised AI API gateway
- Implementing multi-provider AI routing
- Adding rate limiting and cost controls
- Creating streaming-capable AI proxies
- Integrating AI services with Vault for key management

---

## What It Does

1. **Creates gateway project** - Axum-based HTTP server
2. **Implements provider clients** - All major AI providers
3. **Adds rate limiting** - Token bucket and sliding window
4. **Configures circuit breakers** - Resilience patterns
5. **Implements cost tracking** - Per-request cost calculation
6. **Enables streaming** - Server-sent events for streaming responses
7. **Integrates Vault** - Secure API key storage

---

## Parameters

| Parameter     | Type    | Required | Default            | Description              |
| ------------- | ------- | -------- | ------------------ | ------------------------ |
| `--providers` | string  | No       | `anthropic,openai` | Providers to enable      |
| `--port`      | number  | No       | `8080`             | Gateway listen port      |
| `--vault`     | boolean | No       | `true`             | Enable Vault integration |
| `--output`    | string  | No       | `./ai-gateway/`    | Output directory         |

---

## Output

Creates AI gateway project:

```
ai-gateway/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── config.rs
│   ├── providers/
│   │   ├── mod.rs
│   │   ├── anthropic.rs
│   │   ├── openai.rs
│   │   ├── gemini.rs
│   │   ├── azure.rs
│   │   └── perplexity.rs
│   ├── middleware/
│   │   ├── rate_limit.rs
│   │   ├── circuit_breaker.rs
│   │   └── cost_tracking.rs
│   ├── routes/
│   │   ├── chat.rs
│   │   └── embeddings.rs
│   └── vault.rs
├── config/
│   └── gateway.toml
└── tests/
    └── integration_tests.rs
```

---

## Examples

### Example 1: Default Setup (Anthropic + OpenAI)

```bash
/rust-security:ai-gateway-setup
```

### Example 2: All Providers

```bash
/rust-security:ai-gateway-setup --providers=anthropic,openai,gemini,azure,perplexity
```

### Example 3: Custom Port, No Vault

```bash
/rust-security:ai-gateway-setup --port=3000 --vault=false
```

---

## Reference Documents

This command invokes the `ai-gateway-architect` agent. The agent reads these documents
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

- **[/rust-security:ai-provider-add](ai-provider-add.md)** - Add provider to
  existing gateway
- **[/rust-security:vault-setup](vault-setup.md)** - Vault configuration
- **[/rust-security:token-rotate](token-rotate.md)** - API key rotation
