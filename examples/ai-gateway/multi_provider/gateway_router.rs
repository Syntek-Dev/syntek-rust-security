//! Multi-Provider AI Gateway Router
//!
//! Unified gateway for routing requests to multiple AI providers
//! with load balancing, failover, cost optimization, and rate limiting.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Supported AI providers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Provider {
    Anthropic,
    OpenAI,
    Google,
    Azure,
    Perplexity,
}

impl Provider {
    pub fn as_str(&self) -> &'static str {
        match self {
            Provider::Anthropic => "anthropic",
            Provider::OpenAI => "openai",
            Provider::Google => "google",
            Provider::Azure => "azure",
            Provider::Perplexity => "perplexity",
        }
    }

    pub fn base_url(&self) -> &'static str {
        match self {
            Provider::Anthropic => "https://api.anthropic.com",
            Provider::OpenAI => "https://api.openai.com",
            Provider::Google => "https://generativelanguage.googleapis.com",
            Provider::Azure => "https://api.azure.com",
            Provider::Perplexity => "https://api.perplexity.ai",
        }
    }
}

/// Routing strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingStrategy {
    /// Use primary provider, failover to others on error
    Failover,
    /// Round-robin between providers
    RoundRobin,
    /// Route to cheapest available provider
    CostOptimized,
    /// Route based on latency
    LatencyOptimized,
    /// Manual selection per request
    Manual,
}

/// Provider configuration
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    pub provider: Provider,
    pub api_key: String,
    pub weight: u32,
    pub enabled: bool,
    pub timeout: Duration,
    pub max_retries: u32,
    pub rate_limit_rpm: u32,
}

impl ProviderConfig {
    pub fn new(provider: Provider, api_key: &str) -> Self {
        Self {
            provider,
            api_key: api_key.to_string(),
            weight: 100,
            enabled: true,
            timeout: Duration::from_secs(60),
            max_retries: 3,
            rate_limit_rpm: 60,
        }
    }

    pub fn with_weight(mut self, weight: u32) -> Self {
        self.weight = weight;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// Gateway configuration
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub strategy: RoutingStrategy,
    pub global_timeout: Duration,
    pub enable_caching: bool,
    pub cache_ttl: Duration,
    pub enable_logging: bool,
    pub enable_metrics: bool,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            strategy: RoutingStrategy::Failover,
            global_timeout: Duration::from_secs(120),
            enable_caching: false,
            cache_ttl: Duration::from_secs(3600),
            enable_logging: true,
            enable_metrics: true,
        }
    }
}

/// Gateway request
#[derive(Debug, Clone)]
pub struct GatewayRequest {
    pub prompt: String,
    pub system: Option<String>,
    pub max_tokens: Option<u32>,
    pub temperature: Option<f32>,
    pub preferred_provider: Option<Provider>,
    pub fallback_providers: Vec<Provider>,
    pub request_id: String,
    pub metadata: HashMap<String, String>,
}

impl GatewayRequest {
    pub fn new(prompt: &str) -> Self {
        Self {
            prompt: prompt.to_string(),
            system: None,
            max_tokens: None,
            temperature: None,
            preferred_provider: None,
            fallback_providers: Vec::new(),
            request_id: generate_request_id(),
            metadata: HashMap::new(),
        }
    }

    pub fn system(mut self, system: &str) -> Self {
        self.system = Some(system.to_string());
        self
    }

    pub fn max_tokens(mut self, tokens: u32) -> Self {
        self.max_tokens = Some(tokens);
        self
    }

    pub fn temperature(mut self, temp: f32) -> Self {
        self.temperature = Some(temp);
        self
    }

    pub fn prefer(mut self, provider: Provider) -> Self {
        self.preferred_provider = Some(provider);
        self
    }

    pub fn fallback(mut self, provider: Provider) -> Self {
        self.fallback_providers.push(provider);
        self
    }
}

/// Gateway response
#[derive(Debug, Clone)]
pub struct GatewayResponse {
    pub text: String,
    pub provider: Provider,
    pub model: String,
    pub usage: TokenUsage,
    pub latency: Duration,
    pub request_id: String,
    pub cached: bool,
}

/// Token usage
#[derive(Debug, Clone, Default)]
pub struct TokenUsage {
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub total_tokens: u32,
    pub estimated_cost: f64,
}

/// Gateway error
#[derive(Debug)]
pub enum GatewayError {
    NoProvidersAvailable,
    AllProvidersFailed(Vec<(Provider, String)>),
    RateLimited(Provider),
    Timeout(Provider),
    InvalidRequest(String),
    ConfigurationError(String),
}

impl std::fmt::Display for GatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GatewayError::NoProvidersAvailable => write!(f, "No providers available"),
            GatewayError::AllProvidersFailed(errors) => {
                write!(f, "All providers failed: ")?;
                for (provider, error) in errors {
                    write!(f, "{}: {}; ", provider.as_str(), error)?;
                }
                Ok(())
            }
            GatewayError::RateLimited(p) => write!(f, "Rate limited by {}", p.as_str()),
            GatewayError::Timeout(p) => write!(f, "Timeout from {}", p.as_str()),
            GatewayError::InvalidRequest(msg) => write!(f, "Invalid request: {}", msg),
            GatewayError::ConfigurationError(msg) => write!(f, "Configuration error: {}", msg),
        }
    }
}

impl std::error::Error for GatewayError {}

/// Provider health status
#[derive(Debug, Clone)]
pub struct ProviderHealth {
    pub provider: Provider,
    pub is_healthy: bool,
    pub last_check: Instant,
    pub success_rate: f64,
    pub avg_latency: Duration,
    pub error_count: u32,
}

/// Rate limiter per provider
#[derive(Debug)]
struct ProviderRateLimiter {
    requests: Vec<Instant>,
    limit: u32,
}

impl ProviderRateLimiter {
    fn new(rpm_limit: u32) -> Self {
        Self {
            requests: Vec::new(),
            limit: rpm_limit,
        }
    }

    fn check(&mut self) -> bool {
        let now = Instant::now();
        let one_minute_ago = now - Duration::from_secs(60);
        self.requests.retain(|&t| t > one_minute_ago);

        if self.requests.len() < self.limit as usize {
            self.requests.push(now);
            true
        } else {
            false
        }
    }
}

/// AI Gateway Router
pub struct GatewayRouter {
    config: GatewayConfig,
    providers: HashMap<Provider, ProviderConfig>,
    health: HashMap<Provider, ProviderHealth>,
    rate_limiters: HashMap<Provider, ProviderRateLimiter>,
    round_robin_index: usize,
    metrics: GatewayMetrics,
}

impl GatewayRouter {
    /// Create a new gateway router
    pub fn new(config: GatewayConfig) -> Self {
        Self {
            config,
            providers: HashMap::new(),
            health: HashMap::new(),
            rate_limiters: HashMap::new(),
            round_robin_index: 0,
            metrics: GatewayMetrics::default(),
        }
    }

    /// Register a provider
    pub fn register_provider(&mut self, config: ProviderConfig) {
        let provider = config.provider;
        let rate_limit = config.rate_limit_rpm;

        self.health.insert(
            provider,
            ProviderHealth {
                provider,
                is_healthy: true,
                last_check: Instant::now(),
                success_rate: 1.0,
                avg_latency: Duration::ZERO,
                error_count: 0,
            },
        );

        self.rate_limiters
            .insert(provider, ProviderRateLimiter::new(rate_limit));
        self.providers.insert(provider, config);
    }

    /// Route a request
    pub fn route(&mut self, request: GatewayRequest) -> Result<GatewayResponse, GatewayError> {
        if request.prompt.is_empty() {
            return Err(GatewayError::InvalidRequest("Empty prompt".to_string()));
        }

        let start_time = Instant::now();
        self.metrics.total_requests += 1;

        // Get provider order based on strategy
        let provider_order = self.get_provider_order(&request)?;

        if provider_order.is_empty() {
            return Err(GatewayError::NoProvidersAvailable);
        }

        let mut errors = Vec::new();

        for provider in provider_order {
            // Check rate limit
            if let Some(limiter) = self.rate_limiters.get_mut(&provider) {
                if !limiter.check() {
                    errors.push((provider, "Rate limited".to_string()));
                    continue;
                }
            }

            // Try to execute request
            match self.execute_request(&request, provider) {
                Ok(mut response) => {
                    response.latency = start_time.elapsed();
                    self.update_health(provider, true, response.latency);
                    self.metrics.successful_requests += 1;
                    self.metrics.total_tokens += response.usage.total_tokens as u64;
                    return Ok(response);
                }
                Err(error) => {
                    errors.push((provider, error));
                    self.update_health(provider, false, Duration::ZERO);
                }
            }
        }

        self.metrics.failed_requests += 1;
        Err(GatewayError::AllProvidersFailed(errors))
    }

    /// Get provider order based on routing strategy
    fn get_provider_order(
        &mut self,
        request: &GatewayRequest,
    ) -> Result<Vec<Provider>, GatewayError> {
        let enabled_providers: Vec<Provider> = self
            .providers
            .iter()
            .filter(|(_, config)| config.enabled)
            .filter(|(provider, _)| {
                self.health
                    .get(provider)
                    .map(|h| h.is_healthy)
                    .unwrap_or(false)
            })
            .map(|(provider, _)| *provider)
            .collect();

        if enabled_providers.is_empty() {
            return Err(GatewayError::NoProvidersAvailable);
        }

        match self.config.strategy {
            RoutingStrategy::Manual => {
                if let Some(preferred) = request.preferred_provider {
                    let mut order = vec![preferred];
                    order.extend(request.fallback_providers.iter().copied());
                    Ok(order)
                } else {
                    Ok(enabled_providers)
                }
            }
            RoutingStrategy::Failover => {
                // Primary provider first, then by weight
                let mut providers = enabled_providers;
                providers.sort_by(|a, b| {
                    let weight_a = self.providers.get(a).map(|c| c.weight).unwrap_or(0);
                    let weight_b = self.providers.get(b).map(|c| c.weight).unwrap_or(0);
                    weight_b.cmp(&weight_a)
                });
                Ok(providers)
            }
            RoutingStrategy::RoundRobin => {
                let mut providers = enabled_providers;
                self.round_robin_index = (self.round_robin_index + 1) % providers.len();
                providers.rotate_left(self.round_robin_index);
                Ok(providers)
            }
            RoutingStrategy::CostOptimized => {
                // Sort by estimated cost (simplified)
                let mut providers = enabled_providers;
                providers.sort_by(|a, b| {
                    let cost_a = get_provider_cost(*a);
                    let cost_b = get_provider_cost(*b);
                    cost_a
                        .partial_cmp(&cost_b)
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
                Ok(providers)
            }
            RoutingStrategy::LatencyOptimized => {
                // Sort by average latency
                let mut providers = enabled_providers;
                providers.sort_by(|a, b| {
                    let latency_a = self
                        .health
                        .get(a)
                        .map(|h| h.avg_latency)
                        .unwrap_or(Duration::MAX);
                    let latency_b = self
                        .health
                        .get(b)
                        .map(|h| h.avg_latency)
                        .unwrap_or(Duration::MAX);
                    latency_a.cmp(&latency_b)
                });
                Ok(providers)
            }
        }
    }

    /// Execute request against a provider (simulated)
    fn execute_request(
        &self,
        request: &GatewayRequest,
        provider: Provider,
    ) -> Result<GatewayResponse, String> {
        // Simulate provider response
        let model = match provider {
            Provider::Anthropic => "claude-3-5-sonnet-20241022",
            Provider::OpenAI => "gpt-4-turbo",
            Provider::Google => "gemini-pro",
            Provider::Azure => "gpt-4",
            Provider::Perplexity => "pplx-70b-online",
        };

        Ok(GatewayResponse {
            text: format!("Response from {} ({})", provider.as_str(), model),
            provider,
            model: model.to_string(),
            usage: TokenUsage {
                input_tokens: (request.prompt.len() / 4) as u32,
                output_tokens: 50,
                total_tokens: (request.prompt.len() / 4) as u32 + 50,
                estimated_cost: calculate_cost(provider, (request.prompt.len() / 4) as u32, 50),
            },
            latency: Duration::ZERO,
            request_id: request.request_id.clone(),
            cached: false,
        })
    }

    /// Update provider health
    fn update_health(&mut self, provider: Provider, success: bool, latency: Duration) {
        if let Some(health) = self.health.get_mut(&provider) {
            health.last_check = Instant::now();

            if success {
                health.success_rate = health.success_rate * 0.9 + 0.1;
                health.avg_latency = Duration::from_nanos(
                    (health.avg_latency.as_nanos() as f64 * 0.9 + latency.as_nanos() as f64 * 0.1)
                        as u64,
                );
            } else {
                health.error_count += 1;
                health.success_rate = health.success_rate * 0.9;

                // Mark as unhealthy if too many errors
                if health.success_rate < 0.5 {
                    health.is_healthy = false;
                }
            }
        }
    }

    /// Get provider health status
    pub fn get_health(&self, provider: Provider) -> Option<&ProviderHealth> {
        self.health.get(&provider)
    }

    /// Get all health statuses
    pub fn get_all_health(&self) -> Vec<&ProviderHealth> {
        self.health.values().collect()
    }

    /// Get gateway metrics
    pub fn get_metrics(&self) -> &GatewayMetrics {
        &self.metrics
    }

    /// Reset provider health (after recovery)
    pub fn reset_health(&mut self, provider: Provider) {
        if let Some(health) = self.health.get_mut(&provider) {
            health.is_healthy = true;
            health.success_rate = 1.0;
            health.error_count = 0;
        }
    }
}

/// Gateway metrics
#[derive(Debug, Default)]
pub struct GatewayMetrics {
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub total_tokens: u64,
    pub total_cost: f64,
}

impl GatewayMetrics {
    pub fn success_rate(&self) -> f64 {
        if self.total_requests == 0 {
            0.0
        } else {
            self.successful_requests as f64 / self.total_requests as f64
        }
    }
}

fn generate_request_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("req_{:x}", timestamp)
}

fn get_provider_cost(provider: Provider) -> f64 {
    // Cost per 1K tokens (simplified)
    match provider {
        Provider::Anthropic => 0.003,
        Provider::OpenAI => 0.01,
        Provider::Google => 0.001,
        Provider::Azure => 0.012,
        Provider::Perplexity => 0.002,
    }
}

fn calculate_cost(provider: Provider, input_tokens: u32, output_tokens: u32) -> f64 {
    let cost_per_1k = get_provider_cost(provider);
    ((input_tokens + output_tokens) as f64 / 1000.0) * cost_per_1k
}

fn main() {
    println!("=== AI Gateway Router Demo ===\n");

    // Create gateway with failover strategy
    let config = GatewayConfig {
        strategy: RoutingStrategy::Failover,
        enable_logging: true,
        enable_metrics: true,
        ..Default::default()
    };

    let mut gateway = GatewayRouter::new(config);

    // Register providers
    println!("--- Registering Providers ---\n");

    gateway
        .register_provider(ProviderConfig::new(Provider::Anthropic, "sk-ant-xxx").with_weight(100));
    gateway.register_provider(ProviderConfig::new(Provider::OpenAI, "sk-xxx").with_weight(80));
    gateway.register_provider(ProviderConfig::new(Provider::Google, "xxx").with_weight(60));

    for (provider, _) in &gateway.providers {
        println!("Registered: {}", provider.as_str());
    }

    // Simple request
    println!("\n--- Simple Request ---\n");
    let request = GatewayRequest::new("What is the capital of France?")
        .max_tokens(100)
        .temperature(0.7);

    match gateway.route(request) {
        Ok(response) => {
            println!("Provider: {}", response.provider.as_str());
            println!("Model: {}", response.model);
            println!("Response: {}", response.text);
            println!("Tokens: {}", response.usage.total_tokens);
            println!("Cost: ${:.6}", response.usage.estimated_cost);
        }
        Err(e) => println!("Error: {}", e),
    }

    // Request with preferred provider
    println!("\n--- Request with Preferred Provider ---\n");
    let request = GatewayRequest::new("Explain quantum computing")
        .prefer(Provider::Anthropic)
        .fallback(Provider::OpenAI);

    match gateway.route(request) {
        Ok(response) => {
            println!("Routed to: {}", response.provider.as_str());
            println!("Request ID: {}", response.request_id);
        }
        Err(e) => println!("Error: {}", e),
    }

    // Multiple requests
    println!("\n--- Multiple Requests ---\n");
    for i in 0..5 {
        let request = GatewayRequest::new(&format!("Question {}", i));
        match gateway.route(request) {
            Ok(response) => println!(
                "Request {}: {} -> {}",
                i,
                response.provider.as_str(),
                response.model
            ),
            Err(e) => println!("Request {}: Error - {}", i, e),
        }
    }

    // Health status
    println!("\n--- Provider Health ---\n");
    for health in gateway.get_all_health() {
        println!(
            "{}: healthy={}, success_rate={:.1}%, avg_latency={:?}",
            health.provider.as_str(),
            health.is_healthy,
            health.success_rate * 100.0,
            health.avg_latency
        );
    }

    // Metrics
    println!("\n--- Gateway Metrics ---\n");
    let metrics = gateway.get_metrics();
    println!("Total requests: {}", metrics.total_requests);
    println!("Successful: {}", metrics.successful_requests);
    println!("Failed: {}", metrics.failed_requests);
    println!("Success rate: {:.1}%", metrics.success_rate() * 100.0);
    println!("Total tokens: {}", metrics.total_tokens);

    // Routing strategies
    println!("\n--- Routing Strategies ---\n");
    for strategy in [
        RoutingStrategy::Failover,
        RoutingStrategy::RoundRobin,
        RoutingStrategy::CostOptimized,
        RoutingStrategy::LatencyOptimized,
    ] {
        println!("{:?}", strategy);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_gateway() -> GatewayRouter {
        let config = GatewayConfig::default();
        let mut gateway = GatewayRouter::new(config);

        gateway.register_provider(ProviderConfig::new(Provider::Anthropic, "test-key"));
        gateway.register_provider(ProviderConfig::new(Provider::OpenAI, "test-key"));

        gateway
    }

    #[test]
    fn test_provider_registration() {
        let mut gateway = GatewayRouter::new(GatewayConfig::default());
        gateway.register_provider(ProviderConfig::new(Provider::Anthropic, "key"));

        assert!(gateway.providers.contains_key(&Provider::Anthropic));
        assert!(gateway.health.contains_key(&Provider::Anthropic));
    }

    #[test]
    fn test_simple_routing() {
        let mut gateway = create_test_gateway();
        let request = GatewayRequest::new("Test prompt");

        let result = gateway.route(request);
        assert!(result.is_ok());
    }

    #[test]
    fn test_preferred_provider() {
        let mut gateway = create_test_gateway();
        let request = GatewayRequest::new("Test").prefer(Provider::OpenAI);

        // With manual strategy, should respect preference
        gateway.config.strategy = RoutingStrategy::Manual;
        let result = gateway.route(request);

        assert!(result.is_ok());
    }

    #[test]
    fn test_empty_prompt_rejected() {
        let mut gateway = create_test_gateway();
        let request = GatewayRequest::new("");

        let result = gateway.route(request);
        assert!(matches!(result, Err(GatewayError::InvalidRequest(_))));
    }

    #[test]
    fn test_health_tracking() {
        let mut gateway = create_test_gateway();
        let request = GatewayRequest::new("Test");

        gateway.route(request).ok();

        let health = gateway.get_health(Provider::Anthropic).unwrap();
        assert!(health.is_healthy);
    }

    #[test]
    fn test_metrics_tracking() {
        let mut gateway = create_test_gateway();

        for _ in 0..5 {
            let request = GatewayRequest::new("Test");
            gateway.route(request).ok();
        }

        let metrics = gateway.get_metrics();
        assert_eq!(metrics.total_requests, 5);
    }

    #[test]
    fn test_request_builder() {
        let request = GatewayRequest::new("Test")
            .system("You are helpful")
            .max_tokens(100)
            .temperature(0.5)
            .prefer(Provider::Anthropic)
            .fallback(Provider::OpenAI);

        assert_eq!(request.system, Some("You are helpful".to_string()));
        assert_eq!(request.max_tokens, Some(100));
        assert_eq!(request.preferred_provider, Some(Provider::Anthropic));
        assert_eq!(request.fallback_providers.len(), 1);
    }

    #[test]
    fn test_provider_config_builder() {
        let config = ProviderConfig::new(Provider::Anthropic, "key")
            .with_weight(50)
            .with_timeout(Duration::from_secs(30));

        assert_eq!(config.weight, 50);
        assert_eq!(config.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_success_rate_calculation() {
        let metrics = GatewayMetrics {
            total_requests: 100,
            successful_requests: 90,
            failed_requests: 10,
            total_tokens: 1000,
            total_cost: 0.1,
        };

        assert!((metrics.success_rate() - 0.9).abs() < 0.001);
    }

    #[test]
    fn test_cost_calculation() {
        let cost = calculate_cost(Provider::Anthropic, 1000, 500);
        assert!(cost > 0.0);
    }

    #[test]
    fn test_provider_base_urls() {
        assert!(Provider::Anthropic.base_url().contains("anthropic"));
        assert!(Provider::OpenAI.base_url().contains("openai"));
    }

    #[test]
    fn test_health_reset() {
        let mut gateway = create_test_gateway();

        // Simulate unhealthy
        if let Some(health) = gateway.health.get_mut(&Provider::Anthropic) {
            health.is_healthy = false;
            health.success_rate = 0.3;
        }

        gateway.reset_health(Provider::Anthropic);

        let health = gateway.get_health(Provider::Anthropic).unwrap();
        assert!(health.is_healthy);
        assert!((health.success_rate - 1.0).abs() < 0.001);
    }
}
