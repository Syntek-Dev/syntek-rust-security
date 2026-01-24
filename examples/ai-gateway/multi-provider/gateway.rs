//! Multi-Provider AI Gateway
//!
//! Unified gateway supporting multiple AI providers with fallback and load balancing.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};

/// Supported AI providers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Anthropic,
    OpenAI,
    Google,
    Azure,
    Perplexity,
}

/// Unified message format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: MessageRole,
    pub content: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MessageRole {
    System,
    User,
    Assistant,
}

/// Unified request format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatRequest {
    pub messages: Vec<ChatMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<Provider>,
}

/// Unified response format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatResponse {
    pub provider: Provider,
    pub model: String,
    pub content: String,
    pub usage: TokenUsage,
    pub latency_ms: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenUsage {
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub total_tokens: u32,
}

/// Provider configuration
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    pub api_key: String,
    pub base_url: Option<String>,
    pub default_model: String,
    pub max_retries: u32,
    pub timeout: Duration,
    pub enabled: bool,
}

/// Circuit breaker state
#[derive(Debug, Clone)]
struct CircuitBreaker {
    failures: u32,
    last_failure: Option<std::time::Instant>,
    state: CircuitState,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

impl CircuitBreaker {
    fn new() -> Self {
        Self {
            failures: 0,
            last_failure: None,
            state: CircuitState::Closed,
        }
    }

    fn record_failure(&mut self) {
        self.failures += 1;
        self.last_failure = Some(std::time::Instant::now());
        if self.failures >= 5 {
            self.state = CircuitState::Open;
        }
    }

    fn record_success(&mut self) {
        self.failures = 0;
        self.state = CircuitState::Closed;
    }

    fn is_available(&self) -> bool {
        match self.state {
            CircuitState::Closed => true,
            CircuitState::HalfOpen => true,
            CircuitState::Open => {
                // Check if enough time has passed to try again
                if let Some(last) = self.last_failure {
                    last.elapsed() > Duration::from_secs(30)
                } else {
                    true
                }
            }
        }
    }
}

/// AI Gateway with multi-provider support
pub struct AiGateway {
    providers: HashMap<Provider, ProviderConfig>,
    circuit_breakers: Arc<RwLock<HashMap<Provider, CircuitBreaker>>>,
    fallback_order: Vec<Provider>,
}

impl AiGateway {
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
            circuit_breakers: Arc::new(RwLock::new(HashMap::new())),
            fallback_order: vec![
                Provider::Anthropic,
                Provider::OpenAI,
                Provider::Google,
                Provider::Azure,
                Provider::Perplexity,
            ],
        }
    }

    /// Register a provider
    pub fn register_provider(&mut self, provider: Provider, config: ProviderConfig) {
        self.providers.insert(provider, config);
    }

    /// Set fallback order
    pub fn set_fallback_order(&mut self, order: Vec<Provider>) {
        self.fallback_order = order;
    }

    /// Send a chat request with automatic fallback
    pub async fn chat(&self, request: ChatRequest) -> Result<ChatResponse, GatewayError> {
        let providers_to_try = if let Some(provider) = request.provider {
            vec![provider]
        } else {
            self.fallback_order.clone()
        };

        let mut last_error = None;

        for provider in providers_to_try {
            // Check circuit breaker
            {
                let breakers = self.circuit_breakers.read().await;
                if let Some(breaker) = breakers.get(&provider) {
                    if !breaker.is_available() {
                        continue;
                    }
                }
            }

            // Check if provider is configured and enabled
            let config = match self.providers.get(&provider) {
                Some(c) if c.enabled => c,
                _ => continue,
            };

            let start = std::time::Instant::now();

            match self.call_provider(provider, config, &request).await {
                Ok(mut response) => {
                    response.latency_ms = start.elapsed().as_millis() as u64;

                    // Record success
                    let mut breakers = self.circuit_breakers.write().await;
                    breakers.entry(provider).or_insert_with(CircuitBreaker::new).record_success();

                    return Ok(response);
                }
                Err(e) => {
                    // Record failure
                    let mut breakers = self.circuit_breakers.write().await;
                    breakers.entry(provider).or_insert_with(CircuitBreaker::new).record_failure();

                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or(GatewayError::NoProvidersAvailable))
    }

    async fn call_provider(
        &self,
        provider: Provider,
        config: &ProviderConfig,
        request: &ChatRequest,
    ) -> Result<ChatResponse, GatewayError> {
        // Simulated provider calls - in production, implement actual API calls
        match provider {
            Provider::Anthropic => self.call_anthropic(config, request).await,
            Provider::OpenAI => self.call_openai(config, request).await,
            Provider::Google => self.call_google(config, request).await,
            Provider::Azure => self.call_azure(config, request).await,
            Provider::Perplexity => self.call_perplexity(config, request).await,
        }
    }

    async fn call_anthropic(&self, config: &ProviderConfig, request: &ChatRequest) -> Result<ChatResponse, GatewayError> {
        // Simulate API call
        let model = request.model.clone().unwrap_or_else(|| config.default_model.clone());

        Ok(ChatResponse {
            provider: Provider::Anthropic,
            model,
            content: "Response from Anthropic".to_string(),
            usage: TokenUsage {
                input_tokens: 10,
                output_tokens: 5,
                total_tokens: 15,
            },
            latency_ms: 0,
        })
    }

    async fn call_openai(&self, config: &ProviderConfig, request: &ChatRequest) -> Result<ChatResponse, GatewayError> {
        let model = request.model.clone().unwrap_or_else(|| config.default_model.clone());

        Ok(ChatResponse {
            provider: Provider::OpenAI,
            model,
            content: "Response from OpenAI".to_string(),
            usage: TokenUsage::default(),
            latency_ms: 0,
        })
    }

    async fn call_google(&self, config: &ProviderConfig, request: &ChatRequest) -> Result<ChatResponse, GatewayError> {
        let model = request.model.clone().unwrap_or_else(|| config.default_model.clone());

        Ok(ChatResponse {
            provider: Provider::Google,
            model,
            content: "Response from Google".to_string(),
            usage: TokenUsage::default(),
            latency_ms: 0,
        })
    }

    async fn call_azure(&self, config: &ProviderConfig, request: &ChatRequest) -> Result<ChatResponse, GatewayError> {
        let model = request.model.clone().unwrap_or_else(|| config.default_model.clone());

        Ok(ChatResponse {
            provider: Provider::Azure,
            model,
            content: "Response from Azure".to_string(),
            usage: TokenUsage::default(),
            latency_ms: 0,
        })
    }

    async fn call_perplexity(&self, config: &ProviderConfig, request: &ChatRequest) -> Result<ChatResponse, GatewayError> {
        let model = request.model.clone().unwrap_or_else(|| config.default_model.clone());

        Ok(ChatResponse {
            provider: Provider::Perplexity,
            model,
            content: "Response from Perplexity".to_string(),
            usage: TokenUsage::default(),
            latency_ms: 0,
        })
    }

    /// Get circuit breaker status for all providers
    pub async fn get_health(&self) -> HashMap<Provider, bool> {
        let breakers = self.circuit_breakers.read().await;
        self.providers.keys()
            .map(|p| {
                let available = breakers.get(p)
                    .map(|b| b.is_available())
                    .unwrap_or(true);
                (*p, available)
            })
            .collect()
    }
}

impl Default for AiGateway {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error("No providers available")]
    NoProvidersAvailable,
    #[error("Provider error: {0}")]
    ProviderError(String),
    #[error("Rate limited")]
    RateLimited,
    #[error("Timeout")]
    Timeout,
}

#[tokio::main]
async fn main() {
    let mut gateway = AiGateway::new();

    // Register providers
    gateway.register_provider(Provider::Anthropic, ProviderConfig {
        api_key: "sk-ant-xxx".to_string(),
        base_url: None,
        default_model: "claude-sonnet-4-20250514".to_string(),
        max_retries: 3,
        timeout: Duration::from_secs(30),
        enabled: true,
    });

    gateway.register_provider(Provider::OpenAI, ProviderConfig {
        api_key: "sk-xxx".to_string(),
        base_url: None,
        default_model: "gpt-4".to_string(),
        max_retries: 3,
        timeout: Duration::from_secs(30),
        enabled: true,
    });

    // Send request
    let request = ChatRequest {
        messages: vec![ChatMessage {
            role: MessageRole::User,
            content: "Hello!".to_string(),
        }],
        model: None,
        max_tokens: Some(100),
        temperature: None,
        provider: None, // Will use fallback order
    };

    match gateway.chat(request).await {
        Ok(response) => {
            println!("Provider: {:?}", response.provider);
            println!("Model: {}", response.model);
            println!("Response: {}", response.content);
            println!("Latency: {}ms", response.latency_ms);
        }
        Err(e) => eprintln!("Error: {}", e),
    }

    // Check health
    println!("\nProvider Health:");
    for (provider, healthy) in gateway.get_health().await {
        println!("  {:?}: {}", provider, if healthy { "OK" } else { "UNHEALTHY" });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_gateway_fallback() {
        let mut gateway = AiGateway::new();

        gateway.register_provider(Provider::Anthropic, ProviderConfig {
            api_key: "test".to_string(),
            base_url: None,
            default_model: "claude-3".to_string(),
            max_retries: 1,
            timeout: Duration::from_secs(5),
            enabled: true,
        });

        let request = ChatRequest {
            messages: vec![],
            model: None,
            max_tokens: None,
            temperature: None,
            provider: None,
        };

        let response = gateway.chat(request).await.unwrap();
        assert_eq!(response.provider, Provider::Anthropic);
    }

    #[test]
    fn test_circuit_breaker() {
        let mut breaker = CircuitBreaker::new();

        assert!(breaker.is_available());

        for _ in 0..5 {
            breaker.record_failure();
        }

        assert!(!breaker.is_available());

        breaker.record_success();
        assert!(breaker.is_available());
    }
}
