# Rust AI Gateway Skills

This skill provides patterns for building a unified AI API gateway in Rust that
supports multiple providers including Anthropic Claude, OpenAI, Google Gemini,
Azure OpenAI, and Perplexity.

## Overview

An AI Gateway provides:

- **Unified API**: Single interface for multiple providers
- **Rate Limiting**: Token bucket and sliding window algorithms
- **Circuit Breakers**: Resilience patterns for provider outages
- **Cost Tracking**: Budget enforcement and usage monitoring
- **Streaming**: Backpressure handling for streaming responses
- **Caching**: Response caching for identical requests
- **Secret Management**: Vault integration for API keys

## /ai-gateway-setup

Initialize an AI API gateway project.

### Usage

```bash
/ai-gateway-setup
```

### What It Does

1. Creates project structure with provider modules
2. Sets up unified request/response types
3. Implements rate limiting middleware
4. Adds circuit breaker patterns
5. Creates Vault integration for API keys
6. Sets up cost tracking and logging

## /ai-provider-add

Add a new AI provider to the gateway.

### Usage

```bash
/ai-provider-add <provider>
```

Examples:

```bash
/ai-provider-add anthropic
/ai-provider-add openai
/ai-provider-add gemini
/ai-provider-add azure
/ai-provider-add perplexity
```

---

## Unified Types

### Request Types

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletionRequest {
    pub model: String,
    pub messages: Vec<Message>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<Tool>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: Role,
    pub content: MessageContent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MessageContent {
    Text(String),
    Parts(Vec<ContentPart>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ContentPart {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "image")]
    Image { source: ImageSource },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageSource {
    #[serde(rename = "type")]
    pub source_type: String,  // "base64" or "url"
    pub media_type: String,   // "image/jpeg", "image/png", etc.
    pub data: String,
}
```

### Response Types

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletionResponse {
    pub id: String,
    pub provider: Provider,
    pub model: String,
    pub content: String,
    pub usage: Usage,
    pub finish_reason: FinishReason,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCall>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Usage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
    pub estimated_cost_usd: f64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinishReason {
    Stop,
    Length,
    ToolUse,
    ContentFilter,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Anthropic,
    OpenAI,
    Gemini,
    Azure,
    Perplexity,
}
```

---

## Provider Implementations

### Anthropic Claude

```rust
use reqwest::Client;
use async_trait::async_trait;

pub struct AnthropicClient {
    client: Client,
    api_key: zeroize::Zeroizing<String>,
    base_url: String,
}

impl AnthropicClient {
    pub fn new(api_key: String) -> Self {
        Self {
            client: Client::new(),
            api_key: zeroize::Zeroizing::new(api_key),
            base_url: "https://api.anthropic.com/v1".to_string(),
        }
    }
}

#[async_trait]
impl AIProvider for AnthropicClient {
    async fn complete(&self, request: &CompletionRequest) -> Result<CompletionResponse, Error> {
        let anthropic_request = AnthropicRequest::from(request);

        let response = self.client
            .post(format!("{}/messages", self.base_url))
            .header("x-api-key", self.api_key.as_str())
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&anthropic_request)
            .send()
            .await?;

        if !response.status().is_success() {
            let error: AnthropicError = response.json().await?;
            return Err(Error::ProviderError {
                provider: Provider::Anthropic,
                message: error.error.message,
            });
        }

        let anthropic_response: AnthropicResponse = response.json().await?;
        Ok(CompletionResponse::from_anthropic(anthropic_response))
    }

    async fn stream(
        &self,
        request: &CompletionRequest,
    ) -> Result<impl Stream<Item = Result<StreamEvent, Error>>, Error> {
        let mut anthropic_request = AnthropicRequest::from(request);
        anthropic_request.stream = true;

        let response = self.client
            .post(format!("{}/messages", self.base_url))
            .header("x-api-key", self.api_key.as_str())
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&anthropic_request)
            .send()
            .await?;

        Ok(parse_sse_stream(response.bytes_stream()))
    }

    fn provider(&self) -> Provider {
        Provider::Anthropic
    }
}
```

### OpenAI

```rust
pub struct OpenAIClient {
    client: Client,
    api_key: zeroize::Zeroizing<String>,
    base_url: String,
    organization: Option<String>,
}

impl OpenAIClient {
    pub fn new(api_key: String) -> Self {
        Self {
            client: Client::new(),
            api_key: zeroize::Zeroizing::new(api_key),
            base_url: "https://api.openai.com/v1".to_string(),
            organization: None,
        }
    }

    pub fn with_organization(mut self, org: String) -> Self {
        self.organization = Some(org);
        self
    }
}

#[async_trait]
impl AIProvider for OpenAIClient {
    async fn complete(&self, request: &CompletionRequest) -> Result<CompletionResponse, Error> {
        let openai_request = OpenAIRequest::from(request);

        let mut req = self.client
            .post(format!("{}/chat/completions", self.base_url))
            .header("Authorization", format!("Bearer {}", self.api_key.as_str()))
            .header("content-type", "application/json");

        if let Some(org) = &self.organization {
            req = req.header("OpenAI-Organization", org);
        }

        let response = req.json(&openai_request).send().await?;

        if !response.status().is_success() {
            let error: OpenAIError = response.json().await?;
            return Err(Error::ProviderError {
                provider: Provider::OpenAI,
                message: error.error.message,
            });
        }

        let openai_response: OpenAIResponse = response.json().await?;
        Ok(CompletionResponse::from_openai(openai_response))
    }

    fn provider(&self) -> Provider {
        Provider::OpenAI
    }
}
```

### Google Gemini

```rust
pub struct GeminiClient {
    client: Client,
    api_key: zeroize::Zeroizing<String>,
    base_url: String,
}

impl GeminiClient {
    pub fn new(api_key: String) -> Self {
        Self {
            client: Client::new(),
            api_key: zeroize::Zeroizing::new(api_key),
            base_url: "https://generativelanguage.googleapis.com/v1beta".to_string(),
        }
    }
}

#[async_trait]
impl AIProvider for GeminiClient {
    async fn complete(&self, request: &CompletionRequest) -> Result<CompletionResponse, Error> {
        let gemini_request = GeminiRequest::from(request);
        let model = map_model_to_gemini(&request.model);

        let response = self.client
            .post(format!(
                "{}/models/{}:generateContent?key={}",
                self.base_url,
                model,
                self.api_key.as_str()
            ))
            .header("content-type", "application/json")
            .json(&gemini_request)
            .send()
            .await?;

        if !response.status().is_success() {
            let error: GeminiError = response.json().await?;
            return Err(Error::ProviderError {
                provider: Provider::Gemini,
                message: error.error.message,
            });
        }

        let gemini_response: GeminiResponse = response.json().await?;
        Ok(CompletionResponse::from_gemini(gemini_response))
    }

    fn provider(&self) -> Provider {
        Provider::Gemini
    }
}
```

### Azure OpenAI

```rust
pub struct AzureOpenAIClient {
    client: Client,
    api_key: zeroize::Zeroizing<String>,
    endpoint: String,
    deployment: String,
    api_version: String,
}

impl AzureOpenAIClient {
    pub fn new(endpoint: String, deployment: String, api_key: String) -> Self {
        Self {
            client: Client::new(),
            api_key: zeroize::Zeroizing::new(api_key),
            endpoint,
            deployment,
            api_version: "2024-02-15-preview".to_string(),
        }
    }
}

#[async_trait]
impl AIProvider for AzureOpenAIClient {
    async fn complete(&self, request: &CompletionRequest) -> Result<CompletionResponse, Error> {
        let azure_request = AzureRequest::from(request);

        let url = format!(
            "{}/openai/deployments/{}/chat/completions?api-version={}",
            self.endpoint,
            self.deployment,
            self.api_version
        );

        let response = self.client
            .post(&url)
            .header("api-key", self.api_key.as_str())
            .header("content-type", "application/json")
            .json(&azure_request)
            .send()
            .await?;

        if !response.status().is_success() {
            let error: AzureError = response.json().await?;
            return Err(Error::ProviderError {
                provider: Provider::Azure,
                message: error.error.message,
            });
        }

        let azure_response: AzureResponse = response.json().await?;
        Ok(CompletionResponse::from_azure(azure_response))
    }

    fn provider(&self) -> Provider {
        Provider::Azure
    }
}
```

### Perplexity

```rust
pub struct PerplexityClient {
    client: Client,
    api_key: zeroize::Zeroizing<String>,
    base_url: String,
}

impl PerplexityClient {
    pub fn new(api_key: String) -> Self {
        Self {
            client: Client::new(),
            api_key: zeroize::Zeroizing::new(api_key),
            base_url: "https://api.perplexity.ai".to_string(),
        }
    }
}

#[async_trait]
impl AIProvider for PerplexityClient {
    async fn complete(&self, request: &CompletionRequest) -> Result<CompletionResponse, Error> {
        let perplexity_request = PerplexityRequest::from(request);

        let response = self.client
            .post(format!("{}/chat/completions", self.base_url))
            .header("Authorization", format!("Bearer {}", self.api_key.as_str()))
            .header("content-type", "application/json")
            .json(&perplexity_request)
            .send()
            .await?;

        if !response.status().is_success() {
            let error: PerplexityError = response.json().await?;
            return Err(Error::ProviderError {
                provider: Provider::Perplexity,
                message: error.error.message,
            });
        }

        let perplexity_response: PerplexityResponse = response.json().await?;
        Ok(CompletionResponse::from_perplexity(perplexity_response))
    }

    fn provider(&self) -> Provider {
        Provider::Perplexity
    }
}
```

---

## Rate Limiting

### Token Bucket Algorithm

```rust
use std::sync::Arc;
use tokio::sync::Mutex;
use std::time::{Duration, Instant};

pub struct TokenBucket {
    capacity: u32,
    tokens: f64,
    refill_rate: f64,  // tokens per second
    last_refill: Instant,
}

impl TokenBucket {
    pub fn new(capacity: u32, refill_rate: f64) -> Self {
        Self {
            capacity,
            tokens: capacity as f64,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    pub fn try_acquire(&mut self, tokens: u32) -> bool {
        self.refill();

        if self.tokens >= tokens as f64 {
            self.tokens -= tokens as f64;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity as f64);
        self.last_refill = now;
    }
}

pub struct RateLimiter {
    buckets: Arc<Mutex<HashMap<Provider, TokenBucket>>>,
}

impl RateLimiter {
    pub fn new(config: &RateLimitConfig) -> Self {
        let mut buckets = HashMap::new();

        for (provider, limits) in &config.provider_limits {
            buckets.insert(
                *provider,
                TokenBucket::new(limits.requests_per_minute, limits.requests_per_minute as f64 / 60.0),
            );
        }

        Self {
            buckets: Arc::new(Mutex::new(buckets)),
        }
    }

    pub async fn acquire(&self, provider: Provider) -> Result<(), Error> {
        let mut buckets = self.buckets.lock().await;

        if let Some(bucket) = buckets.get_mut(&provider) {
            if bucket.try_acquire(1) {
                Ok(())
            } else {
                Err(Error::RateLimited { provider })
            }
        } else {
            Ok(())  // No limit configured
        }
    }
}
```

### Sliding Window

```rust
use std::collections::VecDeque;

pub struct SlidingWindow {
    window_size: Duration,
    max_requests: u32,
    requests: VecDeque<Instant>,
}

impl SlidingWindow {
    pub fn new(window_size: Duration, max_requests: u32) -> Self {
        Self {
            window_size,
            max_requests,
            requests: VecDeque::new(),
        }
    }

    pub fn try_acquire(&mut self) -> bool {
        let now = Instant::now();
        let window_start = now - self.window_size;

        // Remove old requests
        while self.requests.front().map_or(false, |&t| t < window_start) {
            self.requests.pop_front();
        }

        if self.requests.len() < self.max_requests as usize {
            self.requests.push_back(now);
            true
        } else {
            false
        }
    }
}
```

---

## Circuit Breaker

```rust
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

pub struct CircuitBreaker {
    failure_threshold: u32,
    success_threshold: u32,
    timeout: Duration,
    failures: AtomicU32,
    successes: AtomicU32,
    last_failure_time: AtomicU64,
    state: parking_lot::RwLock<CircuitState>,
}

impl CircuitBreaker {
    pub fn new(failure_threshold: u32, success_threshold: u32, timeout: Duration) -> Self {
        Self {
            failure_threshold,
            success_threshold,
            timeout,
            failures: AtomicU32::new(0),
            successes: AtomicU32::new(0),
            last_failure_time: AtomicU64::new(0),
            state: parking_lot::RwLock::new(CircuitState::Closed),
        }
    }

    pub fn can_execute(&self) -> bool {
        let state = *self.state.read();
        match state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                let last_failure = self.last_failure_time.load(Ordering::Relaxed);
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                if now - last_failure >= self.timeout.as_secs() {
                    // Transition to half-open
                    *self.state.write() = CircuitState::HalfOpen;
                    self.successes.store(0, Ordering::Relaxed);
                    true
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => true,
        }
    }

    pub fn record_success(&self) {
        let state = *self.state.read();
        match state {
            CircuitState::HalfOpen => {
                let successes = self.successes.fetch_add(1, Ordering::Relaxed) + 1;
                if successes >= self.success_threshold {
                    *self.state.write() = CircuitState::Closed;
                    self.failures.store(0, Ordering::Relaxed);
                }
            }
            CircuitState::Closed => {
                self.failures.store(0, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    pub fn record_failure(&self) {
        let failures = self.failures.fetch_add(1, Ordering::Relaxed) + 1;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.last_failure_time.store(now, Ordering::Relaxed);

        if failures >= self.failure_threshold {
            *self.state.write() = CircuitState::Open;
        }
    }
}
```

---

## Cost Tracking

```rust
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct PricingConfig {
    pub models: HashMap<String, ModelPricing>,
}

#[derive(Debug, Clone)]
pub struct ModelPricing {
    pub input_cost_per_1k: f64,   // USD per 1000 tokens
    pub output_cost_per_1k: f64,  // USD per 1000 tokens
}

impl Default for PricingConfig {
    fn default() -> Self {
        let mut models = HashMap::new();

        // Anthropic
        models.insert("claude-3-opus-20240229".to_string(), ModelPricing {
            input_cost_per_1k: 0.015,
            output_cost_per_1k: 0.075,
        });
        models.insert("claude-3-sonnet-20240229".to_string(), ModelPricing {
            input_cost_per_1k: 0.003,
            output_cost_per_1k: 0.015,
        });

        // OpenAI
        models.insert("gpt-4-turbo".to_string(), ModelPricing {
            input_cost_per_1k: 0.01,
            output_cost_per_1k: 0.03,
        });
        models.insert("gpt-4o".to_string(), ModelPricing {
            input_cost_per_1k: 0.005,
            output_cost_per_1k: 0.015,
        });

        Self { models }
    }
}

pub struct CostTracker {
    pricing: PricingConfig,
    usage: parking_lot::RwLock<HashMap<String, UsageStats>>,
}

#[derive(Debug, Default)]
pub struct UsageStats {
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub total_cost_usd: f64,
    pub request_count: u64,
}

impl CostTracker {
    pub fn new(pricing: PricingConfig) -> Self {
        Self {
            pricing,
            usage: parking_lot::RwLock::new(HashMap::new()),
        }
    }

    pub fn calculate_cost(&self, model: &str, input_tokens: u32, output_tokens: u32) -> f64 {
        self.pricing.models.get(model).map_or(0.0, |pricing| {
            let input_cost = (input_tokens as f64 / 1000.0) * pricing.input_cost_per_1k;
            let output_cost = (output_tokens as f64 / 1000.0) * pricing.output_cost_per_1k;
            input_cost + output_cost
        })
    }

    pub fn record_usage(&self, model: &str, input_tokens: u32, output_tokens: u32) {
        let cost = self.calculate_cost(model, input_tokens, output_tokens);

        let mut usage = self.usage.write();
        let stats = usage.entry(model.to_string()).or_default();
        stats.total_input_tokens += input_tokens as u64;
        stats.total_output_tokens += output_tokens as u64;
        stats.total_cost_usd += cost;
        stats.request_count += 1;
    }

    pub fn get_stats(&self) -> HashMap<String, UsageStats> {
        self.usage.read().clone()
    }
}
```

---

## Streaming with Backpressure

```rust
use futures::{Stream, StreamExt};
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub enum StreamEvent {
    Start { id: String },
    Delta { content: String },
    ToolCall { id: String, name: String, input: String },
    Usage { input_tokens: u32, output_tokens: u32 },
    End { finish_reason: FinishReason },
    Error { message: String },
}

pub async fn stream_with_backpressure<S>(
    mut source: S,
    buffer_size: usize,
) -> impl Stream<Item = Result<StreamEvent, Error>>
where
    S: Stream<Item = Result<StreamEvent, Error>> + Unpin,
{
    let (tx, rx) = mpsc::channel(buffer_size);

    tokio::spawn(async move {
        while let Some(event) = source.next().await {
            // Backpressure: if channel is full, this will wait
            if tx.send(event).await.is_err() {
                break;  // Receiver dropped
            }
        }
    });

    tokio_stream::wrappers::ReceiverStream::new(rx)
}
```

---

## Gateway Service

```rust
use std::sync::Arc;

pub struct AIGateway {
    providers: HashMap<Provider, Arc<dyn AIProvider + Send + Sync>>,
    rate_limiter: RateLimiter,
    circuit_breakers: HashMap<Provider, CircuitBreaker>,
    cost_tracker: CostTracker,
}

impl AIGateway {
    pub async fn complete(
        &self,
        provider: Provider,
        request: CompletionRequest,
    ) -> Result<CompletionResponse, Error> {
        // Check circuit breaker
        let breaker = self.circuit_breakers.get(&provider)
            .ok_or(Error::ProviderNotConfigured(provider))?;

        if !breaker.can_execute() {
            return Err(Error::CircuitOpen { provider });
        }

        // Check rate limit
        self.rate_limiter.acquire(provider).await?;

        // Get provider client
        let client = self.providers.get(&provider)
            .ok_or(Error::ProviderNotConfigured(provider))?;

        // Execute request
        match client.complete(&request).await {
            Ok(response) => {
                breaker.record_success();

                // Track costs
                self.cost_tracker.record_usage(
                    &response.model,
                    response.usage.prompt_tokens,
                    response.usage.completion_tokens,
                );

                Ok(response)
            }
            Err(e) => {
                breaker.record_failure();
                Err(e)
            }
        }
    }

    pub async fn complete_with_fallback(
        &self,
        providers: &[Provider],
        request: CompletionRequest,
    ) -> Result<CompletionResponse, Error> {
        let mut last_error = None;

        for &provider in providers {
            match self.complete(provider, request.clone()).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    tracing::warn!("Provider {:?} failed: {}", provider, e);
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or(Error::NoProvidersAvailable))
    }
}
```

---

## Vault Integration for API Keys

```rust
use vaultrs::kv2;

pub struct VaultKeyManager {
    vault_client: VaultClient,
    mount: String,
    cache: parking_lot::RwLock<HashMap<Provider, CachedKey>>,
    cache_ttl: Duration,
}

struct CachedKey {
    key: zeroize::Zeroizing<String>,
    fetched_at: Instant,
}

impl VaultKeyManager {
    pub async fn get_api_key(&self, provider: Provider) -> Result<String, Error> {
        // Check cache
        {
            let cache = self.cache.read();
            if let Some(cached) = cache.get(&provider) {
                if cached.fetched_at.elapsed() < self.cache_ttl {
                    return Ok(cached.key.to_string());
                }
            }
        }

        // Fetch from Vault
        let path = format!("ai-keys/{:?}", provider).to_lowercase();
        let secret: ApiKeySecret = kv2::read(&self.vault_client, &self.mount, &path)
            .await
            .map_err(Error::VaultError)?;

        // Update cache
        {
            let mut cache = self.cache.write();
            cache.insert(provider, CachedKey {
                key: zeroize::Zeroizing::new(secret.api_key.clone()),
                fetched_at: Instant::now(),
            });
        }

        Ok(secret.api_key)
    }
}

#[derive(Deserialize)]
struct ApiKeySecret {
    api_key: String,
}
```

---

## Request Logging

```rust
use tracing::{info, instrument};
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub struct RequestLog {
    pub request_id: String,
    pub provider: Provider,
    pub model: String,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub latency_ms: u64,
    pub cost_usd: f64,
    pub success: bool,
    pub error: Option<String>,
}

#[instrument(skip(gateway, request), fields(request_id = %Uuid::new_v4()))]
pub async fn logged_complete(
    gateway: &AIGateway,
    provider: Provider,
    request: CompletionRequest,
) -> Result<CompletionResponse, Error> {
    let start = Instant::now();
    let request_id = Uuid::new_v4().to_string();

    let result = gateway.complete(provider, request.clone()).await;
    let latency_ms = start.elapsed().as_millis() as u64;

    let log = match &result {
        Ok(response) => RequestLog {
            request_id,
            provider,
            model: response.model.clone(),
            input_tokens: response.usage.prompt_tokens,
            output_tokens: response.usage.completion_tokens,
            latency_ms,
            cost_usd: response.usage.estimated_cost_usd,
            success: true,
            error: None,
        },
        Err(e) => RequestLog {
            request_id,
            provider,
            model: request.model,
            input_tokens: 0,
            output_tokens: 0,
            latency_ms,
            cost_usd: 0.0,
            success: false,
            error: Some(e.to_string()),
        },
    };

    info!(target: "ai_gateway", log = ?log, "Request completed");
    result
}
```

---

## Security Best Practices

1. **Store API keys in Vault** - Never hardcode or use environment variables
   directly
2. **Use short-lived cached keys** - Refresh from Vault periodically
3. **Implement rate limiting** - Prevent abuse and control costs
4. **Use circuit breakers** - Handle provider outages gracefully
5. **Log requests without secrets** - Audit trail without exposing keys
6. **Validate all inputs** - Prevent injection attacks
7. **Set budget limits** - Automatic cutoff when costs exceed threshold
8. **Use TLS everywhere** - Encrypt all API traffic
9. **Zeroize keys on drop** - Prevent key material in memory dumps

## Recommended Crates

- **reqwest**: HTTP client
- **tokio**: Async runtime
- **serde**: Serialization
- **vaultrs**: HashiCorp Vault client
- **zeroize**: Secure memory clearing
- **tracing**: Logging/observability
- **parking_lot**: Fast synchronization primitives
- **futures**: Async streams

## Integration Points

This skill works well with:

- `/vault-setup` - Store and rotate API keys
- `/token-rotate` - Automate key rotation
- `/nginx-config` - Reverse proxy configuration
