# AI Provider Add Command

## Overview

**Command:** `/rust-security:ai-provider-add`

Adds a new AI provider to an existing AI gateway, implementing the provider
client, configuration, and routing.

**Agent:** `ai-gateway-builder` (Sonnet - Standard Analysis)

---

## When to Use

- Adding a new AI provider to existing gateway
- Enabling additional models from a provider
- Configuring provider-specific settings
- Setting up fallback providers

---

## What It Does

1. **Detects existing gateway** - Reads current configuration
2. **Generates provider client** - API client implementation
3. **Updates routing** - Adds provider to request router
4. **Configures rate limits** - Provider-specific limits
5. **Updates cost tracking** - Provider pricing information
6. **Generates tests** - Provider integration tests

---

## Parameters

| Parameter    | Type    | Required | Default       | Description                                                                           |
| ------------ | ------- | -------- | ------------- | ------------------------------------------------------------------------------------- |
| `--provider` | string  | Yes      | None          | Provider: `anthropic`, `openai`, `gemini`, `azure`, `perplexity`, `mistral`, `cohere` |
| `--models`   | string  | No       | All available | Specific models to enable                                                             |
| `--priority` | number  | No       | `10`          | Routing priority (lower = higher priority)                                            |
| `--fallback` | boolean | No       | `false`       | Use as fallback provider                                                              |

---

## Output

Updates existing gateway:

- `src/providers/{provider}.rs` - Provider client
- `src/config.rs` - Updated configuration
- `src/routes/chat.rs` - Updated routing
- `config/gateway.toml` - Provider configuration
- `tests/{provider}_tests.rs` - Integration tests

---

## Examples

### Example 1: Add Gemini

```bash
/rust-security:ai-provider-add --provider=gemini
```

### Example 2: Add Azure as Fallback

```bash
/rust-security:ai-provider-add --provider=azure --fallback=true
```

### Example 3: Add Mistral with Specific Models

```bash
/rust-security:ai-provider-add --provider=mistral --models=mistral-large,mistral-medium
```

---

## Supported Providers

| Provider   | Models                                         | Streaming |
| ---------- | ---------------------------------------------- | --------- |
| anthropic  | claude-3-opus, claude-3-sonnet, claude-3-haiku | Yes       |
| openai     | gpt-4-turbo, gpt-4, gpt-3.5-turbo              | Yes       |
| gemini     | gemini-pro, gemini-pro-vision                  | Yes       |
| azure      | gpt-4, gpt-35-turbo (via Azure OpenAI)         | Yes       |
| perplexity | pplx-70b-online, pplx-7b-online                | Yes       |
| mistral    | mistral-large, mistral-medium, mistral-small   | Yes       |
| cohere     | command, command-light                         | Yes       |

---

## Related Commands

- **[/rust-security:ai-gateway-setup](ai-gateway-setup.md)** - Create new
  gateway
- **[/rust-security:vault-setup](vault-setup.md)** - API key management
- **[/rust-security:token-rotate](token-rotate.md)** - Key rotation
