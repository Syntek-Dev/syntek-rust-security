# Rust AI Gateway Template

## Overview

This template provides a unified AI API gateway supporting multiple providers
(Anthropic, OpenAI, Google, Azure, Perplexity) with rate limiting, circuit
breakers, cost tracking, and streaming support.

**Target Use Cases:**

- Multi-provider AI API management
- Rate limiting and cost control
- Request/response logging
- Failover and load balancing
- Streaming with backpressure

## Project Structure

```
my-ai-gateway/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── lib.rs
│   ├── providers/
│   │   ├── mod.rs
│   │   ├── anthropic.rs
│   │   ├── openai.rs
│   │   ├── google.rs
│   │   ├── azure.rs
│   │   └── perplexity.rs
│   ├── gateway/
│   │   ├── mod.rs
│   │   ├── router.rs
│   │   ├── rate_limit.rs
│   │   └── circuit_breaker.rs
│   ├── streaming/
│   │   ├── mod.rs
│   │   └── sse.rs
│   ├── cost/
│   │   ├── mod.rs
│   │   └── tracker.rs
│   └── error.rs
└── README.md
```

## Cargo.toml

```toml
[package]
name = "my-ai-gateway"
version = "0.1.0"
edition = "2021"
rust-version = "1.92.0"

[dependencies]
tokio = { version = "1.40", features = ["full"] }
axum = { version = "0.7", features = ["tokio"] }
reqwest = { version = "0.12", features = ["json", "rustls-tls", "stream"], default-features = false }
reqwest-eventsource = "0.6"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
secrecy = { version = "0.10", features = ["serde"] }
governor = "0.6"
tower = { version = "0.5", features = ["full"] }
tracing = "0.1"
tracing-subscriber = "0.3"
thiserror = "2.0"
async-trait = "0.1"
futures = "0.3"
tokio-stream = "0.1"
uuid = { version = "1.10", features = ["v4"] }
```

## Core Implementation

### src/providers/mod.rs

```rust
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use crate::error::GatewayError;

pub mod anthropic;
pub mod openai;
pub mod google;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatRequest {
    pub model: String,
    pub messages: Vec<Message>,
    pub max_tokens: Option<u32>,
    pub temperature: Option<f32>,
    pub stream: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatResponse {
    pub id: String,
    pub content: String,
    pub model: String,
    pub usage: Usage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Usage {
    pub input_tokens: u32,
    pub output_tokens: u32,
}

#[async_trait]
pub trait AiProvider: Send + Sync {
    fn name(&self) -> &str;
    async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, GatewayError>;
    async fn chat_stream(&self, request: &ChatRequest) -> Result<StreamHandle, GatewayError>;
    fn supported_models(&self) -> &[&str];
    fn cost_per_token(&self, model: &str, input: bool) -> f64;
}

pub struct StreamHandle {
    pub receiver: tokio::sync::mpsc::Receiver<Result<String, GatewayError>>,
}
```

### src/providers/anthropic.rs

```rust
use async_trait::async_trait;
use reqwest::Client;
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use crate::error::GatewayError;
use super::{AiProvider, ChatRequest, ChatResponse, Message, Usage, StreamHandle};

pub struct AnthropicProvider {
    client: Client,
    api_key: Secret<String>,
}

impl AnthropicProvider {
    pub fn new(api_key: Secret<String>) -> Self {
        Self {
            client: Client::new(),
            api_key,
        }
    }
}

#[derive(Serialize)]
struct AnthropicRequest {
    model: String,
    max_tokens: u32,
    messages: Vec<AnthropicMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stream: Option<bool>,
}

#[derive(Serialize)]
struct AnthropicMessage {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct AnthropicResponse {
    id: String,
    content: Vec<ContentBlock>,
    model: String,
    usage: AnthropicUsage,
}

#[derive(Deserialize)]
struct ContentBlock {
    text: String,
}

#[derive(Deserialize)]
struct AnthropicUsage {
    input_tokens: u32,
    output_tokens: u32,
}

#[async_trait]
impl AiProvider for AnthropicProvider {
    fn name(&self) -> &str {
        "anthropic"
    }

    async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, GatewayError> {
        let anthropic_req = AnthropicRequest {
            model: request.model.clone(),
            max_tokens: request.max_tokens.unwrap_or(4096),
            messages: request.messages.iter().map(|m| AnthropicMessage {
                role: m.role.clone(),
                content: m.content.clone(),
            }).collect(),
            temperature: request.temperature,
            stream: Some(false),
        };

        let response = self.client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", self.api_key.expose_secret())
            .header("anthropic-version", "2023-06-01")
            .json(&anthropic_req)
            .send()
            .await?;

        if !response.status().is_success() {
            let error = response.text().await?;
            return Err(GatewayError::ProviderError(error));
        }

        let anthropic_resp: AnthropicResponse = response.json().await?;

        Ok(ChatResponse {
            id: anthropic_resp.id,
            content: anthropic_resp.content.into_iter()
                .map(|c| c.text)
                .collect::<Vec<_>>()
                .join(""),
            model: anthropic_resp.model,
            usage: Usage {
                input_tokens: anthropic_resp.usage.input_tokens,
                output_tokens: anthropic_resp.usage.output_tokens,
            },
        })
    }

    async fn chat_stream(&self, request: &ChatRequest) -> Result<StreamHandle, GatewayError> {
        let (tx, rx) = tokio::sync::mpsc::channel(100);
        // Implement SSE streaming
        Ok(StreamHandle { receiver: rx })
    }

    fn supported_models(&self) -> &[&str] {
        &["claude-3-opus-20240229", "claude-3-sonnet-20240229", "claude-3-haiku-20240307"]
    }

    fn cost_per_token(&self, model: &str, input: bool) -> f64 {
        match (model, input) {
            ("claude-3-opus-20240229", true) => 0.000015,
            ("claude-3-opus-20240229", false) => 0.000075,
            ("claude-3-sonnet-20240229", true) => 0.000003,
            ("claude-3-sonnet-20240229", false) => 0.000015,
            _ => 0.000001,
        }
    }
}
```

### src/gateway/rate_limit.rs

```rust
use governor::{Quota, RateLimiter, state::InMemoryState, clock::DefaultClock};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;

pub struct RateLimitManager {
    limiters: Arc<RwLock<HashMap<String, RateLimiter<String, InMemoryState, DefaultClock>>>>,
    default_quota: Quota,
}

impl RateLimitManager {
    pub fn new(requests_per_minute: u32) -> Self {
        let quota = Quota::per_minute(NonZeroU32::new(requests_per_minute).unwrap());
        Self {
            limiters: Arc::new(RwLock::new(HashMap::new())),
            default_quota: quota,
        }
    }

    pub async fn check(&self, key: &str) -> bool {
        let limiters = self.limiters.read().await;
        if let Some(limiter) = limiters.get(key) {
            return limiter.check().is_ok();
        }
        drop(limiters);

        let mut limiters = self.limiters.write().await;
        let limiter = RateLimiter::keyed(self.default_quota);
        let result = limiter.check_key(&key.to_string()).is_ok();
        limiters.insert(key.to_string(), limiter);
        result
    }
}
```

### src/gateway/circuit_breaker.rs

```rust
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

pub struct CircuitBreaker {
    state: RwLock<CircuitState>,
    failure_count: AtomicU32,
    success_count: AtomicU32,
    failure_threshold: u32,
    success_threshold: u32,
    timeout: Duration,
    last_failure: RwLock<Option<Instant>>,
}

impl CircuitBreaker {
    pub fn new(failure_threshold: u32, success_threshold: u32, timeout: Duration) -> Self {
        Self {
            state: RwLock::new(CircuitState::Closed),
            failure_count: AtomicU32::new(0),
            success_count: AtomicU32::new(0),
            failure_threshold,
            success_threshold,
            timeout,
            last_failure: RwLock::new(None),
        }
    }

    pub async fn can_execute(&self) -> bool {
        let state = *self.state.read().await;
        match state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                let last = self.last_failure.read().await;
                if let Some(instant) = *last {
                    if instant.elapsed() >= self.timeout {
                        *self.state.write().await = CircuitState::HalfOpen;
                        return true;
                    }
                }
                false
            }
            CircuitState::HalfOpen => true,
        }
    }

    pub async fn record_success(&self) {
        let state = *self.state.read().await;
        match state {
            CircuitState::HalfOpen => {
                let count = self.success_count.fetch_add(1, Ordering::SeqCst) + 1;
                if count >= self.success_threshold {
                    *self.state.write().await = CircuitState::Closed;
                    self.failure_count.store(0, Ordering::SeqCst);
                    self.success_count.store(0, Ordering::SeqCst);
                }
            }
            _ => {
                self.failure_count.store(0, Ordering::SeqCst);
            }
        }
    }

    pub async fn record_failure(&self) {
        let count = self.failure_count.fetch_add(1, Ordering::SeqCst) + 1;
        *self.last_failure.write().await = Some(Instant::now());

        if count >= self.failure_threshold {
            *self.state.write().await = CircuitState::Open;
        }
    }
}
```

### src/cost/tracker.rs

```rust
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct CostEntry {
    pub timestamp: DateTime<Utc>,
    pub provider: String,
    pub model: String,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub cost: f64,
}

pub struct CostTracker {
    entries: Arc<RwLock<Vec<CostEntry>>>,
    budgets: Arc<RwLock<HashMap<String, f64>>>,
}

impl CostTracker {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(Vec::new())),
            budgets: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn record(&self, entry: CostEntry) {
        self.entries.write().await.push(entry);
    }

    pub async fn set_budget(&self, key: &str, amount: f64) {
        self.budgets.write().await.insert(key.to_string(), amount);
    }

    pub async fn check_budget(&self, key: &str) -> bool {
        let budgets = self.budgets.read().await;
        let entries = self.entries.read().await;

        if let Some(budget) = budgets.get(key) {
            let spent: f64 = entries.iter()
                .filter(|e| e.provider == key || e.model.starts_with(key))
                .map(|e| e.cost)
                .sum();
            return spent < *budget;
        }
        true
    }

    pub async fn get_total_cost(&self) -> f64 {
        self.entries.read().await.iter().map(|e| e.cost).sum()
    }

    pub async fn get_cost_by_provider(&self) -> HashMap<String, f64> {
        let entries = self.entries.read().await;
        let mut costs = HashMap::new();
        for entry in entries.iter() {
            *costs.entry(entry.provider.clone()).or_insert(0.0) += entry.cost;
        }
        costs
    }
}
```

## Security Checklist

- [ ] API keys stored securely
- [ ] Rate limiting per API key
- [ ] Request/response logging (redacted)
- [ ] Circuit breakers for reliability
- [ ] Cost tracking and budgets
- [ ] Input validation
- [ ] TLS for all connections
