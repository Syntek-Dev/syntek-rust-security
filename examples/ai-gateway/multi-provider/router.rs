//! Multi-Provider AI Gateway Router
//!
//! Implements intelligent routing between multiple AI providers with
//! load balancing, failover, and cost optimization.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

/// AI provider definition
#[derive(Debug, Clone)]
pub struct Provider {
    /// Provider name
    pub name: String,
    /// Provider type
    pub provider_type: ProviderType,
    /// API endpoint
    pub endpoint: String,
    /// Supported models
    pub models: Vec<ModelInfo>,
    /// Current health status
    pub health: HealthStatus,
    /// Rate limit configuration
    pub rate_limit: RateLimit,
    /// Cost per 1K tokens (input, output)
    pub cost_per_1k: (f64, f64),
    /// Priority (higher = preferred)
    pub priority: u32,
    /// Weight for load balancing
    pub weight: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ProviderType {
    Anthropic,
    OpenAI,
    Google,
    Azure,
    Perplexity,
    Custom,
}

#[derive(Debug, Clone)]
pub struct ModelInfo {
    pub name: String,
    pub max_tokens: u32,
    pub supports_streaming: bool,
    pub supports_function_calling: bool,
    pub supports_vision: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct RateLimit {
    pub requests_per_minute: u32,
    pub tokens_per_minute: u32,
    pub requests_per_day: u32,
}

/// Routing strategy
#[derive(Debug, Clone, PartialEq)]
pub enum RoutingStrategy {
    /// Route to primary provider, failover on error
    PrimaryWithFailover,
    /// Round-robin across providers
    RoundRobin,
    /// Weighted random selection
    WeightedRandom,
    /// Route based on lowest cost
    CostOptimized,
    /// Route based on latency
    LatencyOptimized,
    /// Route based on model capabilities
    CapabilityBased,
}

/// Request to route
#[derive(Debug, Clone)]
pub struct RoutingRequest {
    /// Requested model (optional)
    pub model: Option<String>,
    /// Estimated input tokens
    pub estimated_tokens: u32,
    /// Required capabilities
    pub capabilities: RequestCapabilities,
    /// Maximum cost per request
    pub max_cost: Option<f64>,
    /// Maximum latency (ms)
    pub max_latency_ms: Option<u64>,
    /// Preferred providers
    pub preferred_providers: Vec<String>,
    /// Excluded providers
    pub excluded_providers: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct RequestCapabilities {
    pub requires_streaming: bool,
    pub requires_function_calling: bool,
    pub requires_vision: bool,
    pub requires_long_context: bool,
    pub min_context_tokens: u32,
}

/// Routing decision
#[derive(Debug, Clone)]
pub struct RoutingDecision {
    pub provider: String,
    pub model: String,
    pub endpoint: String,
    pub estimated_cost: f64,
    pub estimated_latency_ms: u64,
    pub fallback_providers: Vec<String>,
    pub reason: String,
}

/// Provider metrics
#[derive(Debug, Clone, Default)]
pub struct ProviderMetrics {
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub total_tokens: u64,
    pub total_cost: f64,
    pub average_latency_ms: f64,
    pub p99_latency_ms: f64,
    pub error_rate: f64,
    pub last_request: Option<SystemTime>,
    pub last_error: Option<String>,
}

/// Multi-provider router
pub struct ProviderRouter {
    /// Configured providers
    providers: HashMap<String, Provider>,
    /// Provider metrics
    metrics: HashMap<String, ProviderMetrics>,
    /// Routing strategy
    strategy: RoutingStrategy,
    /// Circuit breaker states
    circuit_breakers: HashMap<String, CircuitBreaker>,
    /// Round-robin counter
    round_robin_counter: AtomicU64,
    /// Latency samples per provider
    latency_samples: HashMap<String, Vec<u64>>,
}

#[derive(Debug, Clone)]
struct CircuitBreaker {
    state: CircuitState,
    failures: u32,
    last_failure: Option<Instant>,
    last_success: Option<Instant>,
    threshold: u32,
    reset_timeout: Duration,
}

#[derive(Debug, Clone, PartialEq)]
enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self {
            state: CircuitState::Closed,
            failures: 0,
            last_failure: None,
            last_success: None,
            threshold: 5,
            reset_timeout: Duration::from_secs(30),
        }
    }
}

impl ProviderRouter {
    /// Create new router
    pub fn new(strategy: RoutingStrategy) -> Self {
        Self {
            providers: HashMap::new(),
            metrics: HashMap::new(),
            strategy,
            circuit_breakers: HashMap::new(),
            round_robin_counter: AtomicU64::new(0),
            latency_samples: HashMap::new(),
        }
    }

    /// Add a provider
    pub fn add_provider(&mut self, provider: Provider) {
        let name = provider.name.clone();
        self.providers.insert(name.clone(), provider);
        self.metrics
            .insert(name.clone(), ProviderMetrics::default());
        self.circuit_breakers
            .insert(name.clone(), CircuitBreaker::default());
        self.latency_samples.insert(name, Vec::new());
    }

    /// Route a request
    pub fn route(&mut self, request: &RoutingRequest) -> Result<RoutingDecision, String> {
        let available = self.get_available_providers(request)?;

        if available.is_empty() {
            return Err("No providers available for this request".to_string());
        }

        let selected = match self.strategy {
            RoutingStrategy::PrimaryWithFailover => self.route_primary_failover(&available),
            RoutingStrategy::RoundRobin => self.route_round_robin(&available),
            RoutingStrategy::WeightedRandom => self.route_weighted_random(&available),
            RoutingStrategy::CostOptimized => self.route_cost_optimized(&available, request),
            RoutingStrategy::LatencyOptimized => self.route_latency_optimized(&available),
            RoutingStrategy::CapabilityBased => self.route_capability_based(&available, request),
        };

        let provider = selected.ok_or("Failed to select provider")?;
        let model = self.select_model(provider, request)?;

        // Build fallback list
        let fallbacks: Vec<String> = available
            .iter()
            .filter(|p| p.name != provider.name)
            .take(2)
            .map(|p| p.name.clone())
            .collect();

        // Estimate cost
        let estimated_cost = self.estimate_cost(provider, request);

        // Get average latency
        let estimated_latency = self.get_average_latency(&provider.name);

        Ok(RoutingDecision {
            provider: provider.name.clone(),
            model: model.name.clone(),
            endpoint: provider.endpoint.clone(),
            estimated_cost,
            estimated_latency_ms: estimated_latency,
            fallback_providers: fallbacks,
            reason: format!("Selected via {:?} strategy", self.strategy),
        })
    }

    fn get_available_providers(&self, request: &RoutingRequest) -> Result<Vec<&Provider>, String> {
        let mut available = Vec::new();

        for (name, provider) in &self.providers {
            // Check exclusions
            if request.excluded_providers.contains(name) {
                continue;
            }

            // Check health
            if provider.health == HealthStatus::Unhealthy {
                continue;
            }

            // Check circuit breaker
            if let Some(cb) = self.circuit_breakers.get(name) {
                if cb.state == CircuitState::Open {
                    // Check if we should try half-open
                    if let Some(last_failure) = cb.last_failure {
                        if last_failure.elapsed() < cb.reset_timeout {
                            continue;
                        }
                    }
                }
            }

            // Check capabilities
            if !self.provider_meets_capabilities(provider, &request.capabilities) {
                continue;
            }

            // Check cost limit
            if let Some(max_cost) = request.max_cost {
                let estimated = self.estimate_cost(provider, request);
                if estimated > max_cost {
                    continue;
                }
            }

            available.push(provider);
        }

        // Sort by preference if specified
        if !request.preferred_providers.is_empty() {
            available.sort_by(|a, b| {
                let a_pref = request
                    .preferred_providers
                    .iter()
                    .position(|p| p == &a.name);
                let b_pref = request
                    .preferred_providers
                    .iter()
                    .position(|p| p == &b.name);

                match (a_pref, b_pref) {
                    (Some(a), Some(b)) => a.cmp(&b),
                    (Some(_), None) => std::cmp::Ordering::Less,
                    (None, Some(_)) => std::cmp::Ordering::Greater,
                    (None, None) => b.priority.cmp(&a.priority),
                }
            });
        }

        Ok(available)
    }

    fn provider_meets_capabilities(&self, provider: &Provider, caps: &RequestCapabilities) -> bool {
        for model in &provider.models {
            let meets = (!caps.requires_streaming || model.supports_streaming)
                && (!caps.requires_function_calling || model.supports_function_calling)
                && (!caps.requires_vision || model.supports_vision)
                && (!caps.requires_long_context || model.max_tokens >= caps.min_context_tokens);

            if meets {
                return true;
            }
        }
        false
    }

    fn route_primary_failover<'a>(&self, available: &[&'a Provider]) -> Option<&'a Provider> {
        available.iter().max_by_key(|p| p.priority).copied()
    }

    fn route_round_robin<'a>(&self, available: &[&'a Provider]) -> Option<&'a Provider> {
        if available.is_empty() {
            return None;
        }

        let idx = self.round_robin_counter.fetch_add(1, Ordering::SeqCst) as usize;
        Some(available[idx % available.len()])
    }

    fn route_weighted_random<'a>(&self, available: &[&'a Provider]) -> Option<&'a Provider> {
        if available.is_empty() {
            return None;
        }

        let total_weight: u32 = available.iter().map(|p| p.weight).sum();
        if total_weight == 0 {
            return available.first().copied();
        }

        // Simple deterministic selection based on counter
        let counter = self.round_robin_counter.fetch_add(1, Ordering::SeqCst);
        let target = (counter % total_weight as u64) as u32;

        let mut cumulative = 0;
        for provider in available {
            cumulative += provider.weight;
            if target < cumulative {
                return Some(provider);
            }
        }

        available.last().copied()
    }

    fn route_cost_optimized<'a>(
        &self,
        available: &[&'a Provider],
        request: &RoutingRequest,
    ) -> Option<&'a Provider> {
        available
            .iter()
            .min_by(|a, b| {
                let cost_a = self.estimate_cost(a, request);
                let cost_b = self.estimate_cost(b, request);
                cost_a
                    .partial_cmp(&cost_b)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .copied()
    }

    fn route_latency_optimized<'a>(&self, available: &[&'a Provider]) -> Option<&'a Provider> {
        available
            .iter()
            .min_by_key(|p| self.get_average_latency(&p.name))
            .copied()
    }

    fn route_capability_based<'a>(
        &self,
        available: &[&'a Provider],
        request: &RoutingRequest,
    ) -> Option<&'a Provider> {
        // Score providers by capability match
        available
            .iter()
            .max_by_key(|p| {
                let mut score = 0u32;
                for model in &p.models {
                    if request.capabilities.requires_streaming && model.supports_streaming {
                        score += 10;
                    }
                    if request.capabilities.requires_function_calling
                        && model.supports_function_calling
                    {
                        score += 10;
                    }
                    if request.capabilities.requires_vision && model.supports_vision {
                        score += 10;
                    }
                    score += model.max_tokens / 10000;
                }
                score + p.priority
            })
            .copied()
    }

    fn select_model<'a>(
        &self,
        provider: &'a Provider,
        request: &RoutingRequest,
    ) -> Result<&'a ModelInfo, String> {
        // If specific model requested
        if let Some(ref model_name) = request.model {
            return provider
                .models
                .iter()
                .find(|m| m.name == *model_name)
                .ok_or_else(|| {
                    format!(
                        "Model {} not found in provider {}",
                        model_name, provider.name
                    )
                });
        }

        // Select best matching model
        provider
            .models
            .iter()
            .filter(|m| {
                (!request.capabilities.requires_streaming || m.supports_streaming)
                    && (!request.capabilities.requires_function_calling
                        || m.supports_function_calling)
                    && (!request.capabilities.requires_vision || m.supports_vision)
                    && m.max_tokens >= request.capabilities.min_context_tokens
            })
            .max_by_key(|m| m.max_tokens)
            .ok_or_else(|| "No suitable model found".to_string())
    }

    fn estimate_cost(&self, provider: &Provider, request: &RoutingRequest) -> f64 {
        let tokens = request.estimated_tokens as f64;
        let (input_cost, output_cost) = provider.cost_per_1k;

        // Assume 1:1 input:output ratio for estimation
        (tokens / 1000.0) * (input_cost + output_cost)
    }

    fn get_average_latency(&self, provider_name: &str) -> u64 {
        self.latency_samples
            .get(provider_name)
            .and_then(|samples| {
                if samples.is_empty() {
                    None
                } else {
                    Some(samples.iter().sum::<u64>() / samples.len() as u64)
                }
            })
            .unwrap_or(100) // Default 100ms if no data
    }

    /// Record request result
    pub fn record_result(
        &mut self,
        provider: &str,
        success: bool,
        latency_ms: u64,
        tokens: u32,
        cost: f64,
    ) {
        if let Some(metrics) = self.metrics.get_mut(provider) {
            metrics.total_requests += 1;
            if success {
                metrics.successful_requests += 1;
            } else {
                metrics.failed_requests += 1;
            }
            metrics.total_tokens += tokens as u64;
            metrics.total_cost += cost;

            // Update average latency
            let prev_avg = metrics.average_latency_ms;
            let n = metrics.total_requests as f64;
            metrics.average_latency_ms = prev_avg + (latency_ms as f64 - prev_avg) / n;

            metrics.error_rate = metrics.failed_requests as f64 / metrics.total_requests as f64;
            metrics.last_request = Some(SystemTime::now());
        }

        // Update latency samples
        if let Some(samples) = self.latency_samples.get_mut(provider) {
            samples.push(latency_ms);
            if samples.len() > 100 {
                samples.remove(0);
            }
        }

        // Update circuit breaker
        if let Some(cb) = self.circuit_breakers.get_mut(provider) {
            if success {
                cb.failures = 0;
                cb.last_success = Some(Instant::now());
                cb.state = CircuitState::Closed;
            } else {
                cb.failures += 1;
                cb.last_failure = Some(Instant::now());

                if cb.failures >= cb.threshold {
                    cb.state = CircuitState::Open;
                }
            }
        }
    }

    /// Get provider metrics
    pub fn get_metrics(&self, provider: &str) -> Option<&ProviderMetrics> {
        self.metrics.get(provider)
    }

    /// Get all metrics
    pub fn get_all_metrics(&self) -> &HashMap<String, ProviderMetrics> {
        &self.metrics
    }

    /// Update provider health
    pub fn update_health(&mut self, provider: &str, health: HealthStatus) {
        if let Some(p) = self.providers.get_mut(provider) {
            p.health = health;
        }
    }

    /// Get routing strategy
    pub fn strategy(&self) -> &RoutingStrategy {
        &self.strategy
    }

    /// Set routing strategy
    pub fn set_strategy(&mut self, strategy: RoutingStrategy) {
        self.strategy = strategy;
    }
}

fn main() {
    println!("=== Multi-Provider AI Gateway Router Demo ===\n");

    // Create router
    let mut router = ProviderRouter::new(RoutingStrategy::CostOptimized);

    // Add providers
    router.add_provider(Provider {
        name: "anthropic".to_string(),
        provider_type: ProviderType::Anthropic,
        endpoint: "https://api.anthropic.com/v1/messages".to_string(),
        models: vec![
            ModelInfo {
                name: "claude-3-opus".to_string(),
                max_tokens: 200000,
                supports_streaming: true,
                supports_function_calling: true,
                supports_vision: true,
            },
            ModelInfo {
                name: "claude-3-sonnet".to_string(),
                max_tokens: 200000,
                supports_streaming: true,
                supports_function_calling: true,
                supports_vision: true,
            },
        ],
        health: HealthStatus::Healthy,
        rate_limit: RateLimit {
            requests_per_minute: 100,
            tokens_per_minute: 100000,
            requests_per_day: 10000,
        },
        cost_per_1k: (0.015, 0.075), // Input, Output
        priority: 90,
        weight: 30,
    });

    router.add_provider(Provider {
        name: "openai".to_string(),
        provider_type: ProviderType::OpenAI,
        endpoint: "https://api.openai.com/v1/chat/completions".to_string(),
        models: vec![
            ModelInfo {
                name: "gpt-4-turbo".to_string(),
                max_tokens: 128000,
                supports_streaming: true,
                supports_function_calling: true,
                supports_vision: true,
            },
            ModelInfo {
                name: "gpt-3.5-turbo".to_string(),
                max_tokens: 16384,
                supports_streaming: true,
                supports_function_calling: true,
                supports_vision: false,
            },
        ],
        health: HealthStatus::Healthy,
        rate_limit: RateLimit {
            requests_per_minute: 500,
            tokens_per_minute: 200000,
            requests_per_day: 50000,
        },
        cost_per_1k: (0.01, 0.03),
        priority: 80,
        weight: 40,
    });

    router.add_provider(Provider {
        name: "google".to_string(),
        provider_type: ProviderType::Google,
        endpoint: "https://generativelanguage.googleapis.com/v1/models".to_string(),
        models: vec![ModelInfo {
            name: "gemini-pro".to_string(),
            max_tokens: 32000,
            supports_streaming: true,
            supports_function_calling: true,
            supports_vision: true,
        }],
        health: HealthStatus::Healthy,
        rate_limit: RateLimit {
            requests_per_minute: 60,
            tokens_per_minute: 100000,
            requests_per_day: 10000,
        },
        cost_per_1k: (0.0005, 0.0015),
        priority: 70,
        weight: 30,
    });

    println!("Configured {} providers\n", router.providers.len());

    // Test different routing scenarios
    println!("=== Routing Scenarios ===\n");

    // Scenario 1: Basic request
    let request1 = RoutingRequest {
        model: None,
        estimated_tokens: 1000,
        capabilities: RequestCapabilities::default(),
        max_cost: None,
        max_latency_ms: None,
        preferred_providers: vec![],
        excluded_providers: vec![],
    };

    println!("1. Basic request (cost optimized):");
    match router.route(&request1) {
        Ok(decision) => {
            println!("   Provider: {}", decision.provider);
            println!("   Model: {}", decision.model);
            println!("   Estimated cost: ${:.4}", decision.estimated_cost);
            println!("   Fallbacks: {:?}", decision.fallback_providers);
        }
        Err(e) => println!("   Error: {}", e),
    }

    // Scenario 2: Vision required
    let request2 = RoutingRequest {
        model: None,
        estimated_tokens: 2000,
        capabilities: RequestCapabilities {
            requires_vision: true,
            ..Default::default()
        },
        max_cost: None,
        max_latency_ms: None,
        preferred_providers: vec![],
        excluded_providers: vec![],
    };

    println!("\n2. Request requiring vision:");
    router.set_strategy(RoutingStrategy::CapabilityBased);
    match router.route(&request2) {
        Ok(decision) => {
            println!("   Provider: {}", decision.provider);
            println!("   Model: {}", decision.model);
            println!("   Reason: {}", decision.reason);
        }
        Err(e) => println!("   Error: {}", e),
    }

    // Scenario 3: Preferred provider
    let request3 = RoutingRequest {
        model: None,
        estimated_tokens: 500,
        capabilities: RequestCapabilities::default(),
        max_cost: None,
        max_latency_ms: None,
        preferred_providers: vec!["anthropic".to_string()],
        excluded_providers: vec![],
    };

    println!("\n3. Request with preferred provider:");
    router.set_strategy(RoutingStrategy::PrimaryWithFailover);
    match router.route(&request3) {
        Ok(decision) => {
            println!("   Provider: {}", decision.provider);
            println!("   Model: {}", decision.model);
        }
        Err(e) => println!("   Error: {}", e),
    }

    // Scenario 4: Cost constrained
    let request4 = RoutingRequest {
        model: None,
        estimated_tokens: 10000,
        capabilities: RequestCapabilities::default(),
        max_cost: Some(0.10),
        max_latency_ms: None,
        preferred_providers: vec![],
        excluded_providers: vec![],
    };

    println!("\n4. Request with cost constraint ($0.10 max):");
    router.set_strategy(RoutingStrategy::CostOptimized);
    match router.route(&request4) {
        Ok(decision) => {
            println!("   Provider: {}", decision.provider);
            println!("   Estimated cost: ${:.4}", decision.estimated_cost);
        }
        Err(e) => println!("   Error: {}", e),
    }

    // Simulate some request results
    println!("\n=== Simulating Request Results ===\n");

    router.record_result("openai", true, 150, 1000, 0.04);
    router.record_result("openai", true, 120, 800, 0.032);
    router.record_result("anthropic", true, 200, 1500, 0.135);
    router.record_result("google", true, 100, 500, 0.001);
    router.record_result("openai", false, 0, 0, 0.0);

    // Show metrics
    println!("Provider Metrics:");
    for (name, metrics) in router.get_all_metrics() {
        println!("  {}:", name);
        println!(
            "    Requests: {} ({} successful)",
            metrics.total_requests, metrics.successful_requests
        );
        println!("    Tokens: {}", metrics.total_tokens);
        println!("    Cost: ${:.4}", metrics.total_cost);
        println!("    Avg Latency: {:.1}ms", metrics.average_latency_ms);
        println!("    Error Rate: {:.1}%", metrics.error_rate * 100.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_router() -> ProviderRouter {
        let mut router = ProviderRouter::new(RoutingStrategy::CostOptimized);

        router.add_provider(Provider {
            name: "test1".to_string(),
            provider_type: ProviderType::OpenAI,
            endpoint: "https://test1.api".to_string(),
            models: vec![ModelInfo {
                name: "model1".to_string(),
                max_tokens: 4096,
                supports_streaming: true,
                supports_function_calling: false,
                supports_vision: false,
            }],
            health: HealthStatus::Healthy,
            rate_limit: RateLimit {
                requests_per_minute: 100,
                tokens_per_minute: 100000,
                requests_per_day: 10000,
            },
            cost_per_1k: (0.01, 0.02),
            priority: 50,
            weight: 50,
        });

        router.add_provider(Provider {
            name: "test2".to_string(),
            provider_type: ProviderType::Anthropic,
            endpoint: "https://test2.api".to_string(),
            models: vec![ModelInfo {
                name: "model2".to_string(),
                max_tokens: 100000,
                supports_streaming: true,
                supports_function_calling: true,
                supports_vision: true,
            }],
            health: HealthStatus::Healthy,
            rate_limit: RateLimit {
                requests_per_minute: 50,
                tokens_per_minute: 50000,
                requests_per_day: 5000,
            },
            cost_per_1k: (0.02, 0.04),
            priority: 80,
            weight: 50,
        });

        router
    }

    #[test]
    fn test_cost_optimized_routing() {
        let mut router = create_test_router();

        let request = RoutingRequest {
            model: None,
            estimated_tokens: 1000,
            capabilities: RequestCapabilities::default(),
            max_cost: None,
            max_latency_ms: None,
            preferred_providers: vec![],
            excluded_providers: vec![],
        };

        let decision = router.route(&request).unwrap();
        assert_eq!(decision.provider, "test1"); // Cheaper
    }

    #[test]
    fn test_capability_based_routing() {
        let mut router = create_test_router();
        router.set_strategy(RoutingStrategy::CapabilityBased);

        let request = RoutingRequest {
            model: None,
            estimated_tokens: 1000,
            capabilities: RequestCapabilities {
                requires_vision: true,
                ..Default::default()
            },
            max_cost: None,
            max_latency_ms: None,
            preferred_providers: vec![],
            excluded_providers: vec![],
        };

        let decision = router.route(&request).unwrap();
        assert_eq!(decision.provider, "test2"); // Has vision
    }

    #[test]
    fn test_excluded_provider() {
        let mut router = create_test_router();

        let request = RoutingRequest {
            model: None,
            estimated_tokens: 1000,
            capabilities: RequestCapabilities::default(),
            max_cost: None,
            max_latency_ms: None,
            preferred_providers: vec![],
            excluded_providers: vec!["test1".to_string()],
        };

        let decision = router.route(&request).unwrap();
        assert_eq!(decision.provider, "test2");
    }

    #[test]
    fn test_record_result() {
        let mut router = create_test_router();

        router.record_result("test1", true, 100, 500, 0.015);

        let metrics = router.get_metrics("test1").unwrap();
        assert_eq!(metrics.total_requests, 1);
        assert_eq!(metrics.successful_requests, 1);
        assert_eq!(metrics.total_tokens, 500);
    }

    #[test]
    fn test_unhealthy_provider_excluded() {
        let mut router = create_test_router();
        router.update_health("test1", HealthStatus::Unhealthy);

        let request = RoutingRequest {
            model: None,
            estimated_tokens: 1000,
            capabilities: RequestCapabilities::default(),
            max_cost: None,
            max_latency_ms: None,
            preferred_providers: vec![],
            excluded_providers: vec![],
        };

        let decision = router.route(&request).unwrap();
        assert_eq!(decision.provider, "test2");
    }
}
