# Rust AI Client Template

## Overview

This template provides a single AI provider client with retry logic, streaming
support, and secure credential handling.

**Target Use Cases:**

- Direct AI provider integration
- Chat completions
- Streaming responses
- Embeddings

## Project Structure

```
my-ai-client/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── client.rs
│   ├── types.rs
│   ├── streaming.rs
│   └── error.rs
└── README.md
```

## Cargo.toml

```toml
[package]
name = "my-ai-client"
version = "0.1.0"
edition = "2021"
rust-version = "1.92.0"

[dependencies]
tokio = { version = "1.40", features = ["full"] }
reqwest = { version = "0.12", features = ["json", "rustls-tls", "stream"], default-features = false }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
secrecy = "0.10"
thiserror = "2.0"
backoff = { version = "0.4", features = ["tokio"] }
futures = "0.3"
tokio-stream = "0.1"
```

## Core Implementation

### src/client.rs

```rust
use reqwest::Client;
use secrecy::{ExposeSecret, Secret};
use backoff::{ExponentialBackoff, future::retry};
use crate::types::{ChatRequest, ChatResponse};
use crate::error::AiError;

pub struct AiClient {
    client: Client,
    api_key: Secret<String>,
    base_url: String,
    max_retries: u32,
}

impl AiClient {
    pub fn new(api_key: Secret<String>, base_url: &str) -> Self {
        Self {
            client: Client::new(),
            api_key,
            base_url: base_url.to_string(),
            max_retries: 3,
        }
    }

    pub async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, AiError> {
        let backoff = ExponentialBackoff::default();

        let operation = || async {
            let response = self.client
                .post(format!("{}/chat/completions", self.base_url))
                .bearer_auth(self.api_key.expose_secret())
                .json(request)
                .send()
                .await
                .map_err(|e| backoff::Error::transient(AiError::NetworkError(e.to_string())))?;

            if response.status().is_server_error() {
                return Err(backoff::Error::transient(AiError::ServerError(
                    response.status().as_u16()
                )));
            }

            if !response.status().is_success() {
                let error = response.text().await.unwrap_or_default();
                return Err(backoff::Error::permanent(AiError::ApiError(error)));
            }

            response.json::<ChatResponse>()
                .await
                .map_err(|e| backoff::Error::permanent(AiError::ParseError(e.to_string())))
        };

        retry(backoff, operation).await
    }
}
```

### src/types.rs

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct ChatRequest {
    pub model: String,
    pub messages: Vec<Message>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChatResponse {
    pub id: String,
    pub choices: Vec<Choice>,
    pub usage: Usage,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Choice {
    pub message: Message,
    pub finish_reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Usage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

impl ChatRequest {
    pub fn new(model: &str, messages: Vec<Message>) -> Self {
        Self {
            model: model.to_string(),
            messages,
            max_tokens: None,
            temperature: None,
        }
    }
}
```

### src/error.rs

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AiError {
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("Server error: {0}")]
    ServerError(u16),
    #[error("API error: {0}")]
    ApiError(String),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Rate limited")]
    RateLimited,
}
```

## Security Checklist

- [ ] API key never logged
- [ ] TLS for all requests
- [ ] Retry with backoff
- [ ] Input validation
- [ ] Response validation
