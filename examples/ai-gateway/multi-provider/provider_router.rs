//! Multi-Provider AI Gateway Router
//!
//! Intelligent routing between multiple AI providers with fallback and load balancing.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Supported AI providers
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Provider {
    Anthropic,
    OpenAI,
    Google,
    Azure,
    Perplexity,
    Mistral,
    Cohere,
    Custom(String),
}

impl Provider {
    pub fn name(&self) -> &str {
        match self {
            Self::Anthropic => "Anthropic",
            Self::OpenAI => "OpenAI",
            Self::Google => "Google Gemini",
            Self::Azure => "Azure OpenAI",
            Self::Perplexity => "Perplexity",
            Self::Mistral => "Mistral",
            Self::Cohere => "Cohere",
            Self::Custom(name) => name,
        }
    }

    pub fn default_endpoint(&self) -> &str {
        match self {
            Self::Anthropic => "https://api.anthropic.com/v1",
            Self::OpenAI => "https://api.openai.com/v1",
            Self::Google => "https://generativelanguage.googleapis.com/v1beta",
            Self::Azure => "https://{resource}.openai.azure.com/openai",
            Self::Perplexity => "https://api.perplexity.ai",
            Self::Mistral => "https://api.mistral.ai/v1",
            Self::Cohere => "https://api.cohere.ai/v1",
            Self::Custom(_) => "",
        }
    }
}

impl fmt::Display for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Model identifier with provider
#[derive(Debug, Clone)]
pub struct Model {
    pub provider: Provider,
    pub model_id: String,
    pub context_window: usize,
    pub max_output_tokens: usize,
    pub cost_per_input_token: f64,
    pub cost_per_output_token: f64,
    pub supports_vision: bool,
    pub supports_function_calling: bool,
    pub supports_streaming: bool,
}

impl Model {
    pub fn new(provider: Provider, model_id: impl Into<String>) -> Self {
        Self {
            provider,
            model_id: model_id.into(),
            context_window: 128000,
            max_output_tokens: 4096,
            cost_per_input_token: 0.0,
            cost_per_output_token: 0.0,
            supports_vision: false,
            supports_function_calling: true,
            supports_streaming: true,
        }
    }

    pub fn with_costs(mut self, input: f64, output: f64) -> Self {
        self.cost_per_input_token = input;
        self.cost_per_output_token = output;
        self
    }

    pub fn with_vision(mut self) -> Self {
        self.supports_vision = true;
        self
    }

    pub fn estimate_cost(&self, input_tokens: usize, output_tokens: usize) -> f64 {
        (input_tokens as f64 * self.cost_per_input_token)
            + (output_tokens as f64 * self.cost_per_output_token)
    }
}

/// Provider health status
#[derive(Debug, Clone)]
pub struct ProviderHealth {
    pub provider: Provider,
    pub is_healthy: bool,
    pub latency_ms: u64,
    pub success_rate: f64,
    pub last_check: Instant,
    pub consecutive_failures: u32,
    pub requests_today: u64,
    pub errors_today: u64,
}

impl ProviderHealth {
    pub fn new(provider: Provider) -> Self {
        Self {
            provider,
            is_healthy: true,
            latency_ms: 0,
            success_rate: 1.0,
            last_check: Instant::now(),
            consecutive_failures: 0,
            requests_today: 0,
            errors_today: 0,
        }
    }

    pub fn record_success(&mut self, latency: Duration) {
        self.requests_today += 1;
        self.consecutive_failures = 0;
        self.is_healthy = true;
        self.latency_ms = latency.as_millis() as u64;
        self.success_rate = 1.0 - (self.errors_today as f64 / self.requests_today.max(1) as f64);
        self.last_check = Instant::now();
    }

    pub fn record_failure(&mut self) {
        self.requests_today += 1;
        self.errors_today += 1;
        self.consecutive_failures += 1;
        self.success_rate = 1.0 - (self.errors_today as f64 / self.requests_today.max(1) as f64);
        self.last_check = Instant::now();

        if self.consecutive_failures >= 3 {
            self.is_healthy = false;
        }
    }

    pub fn should_use(&self) -> bool {
        self.is_healthy && self.success_rate > 0.5
    }
}

/// Routing strategy
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingStrategy {
    /// Always use the primary provider
    Primary,
    /// Round-robin between providers
    RoundRobin,
    /// Route based on latency
    LowestLatency,
    /// Route based on cost
    LowestCost,
    /// Random selection
    Random,
    /// Weighted distribution
    Weighted,
    /// Based on request content
    ContentBased,
}

/// Routing request
#[derive(Debug, Clone)]
pub struct RoutingRequest {
    pub prompt: String,
    pub input_tokens: usize,
    pub max_output_tokens: usize,
    pub requires_vision: bool,
    pub requires_function_calling: bool,
    pub requires_streaming: bool,
    pub preferred_provider: Option<Provider>,
    pub excluded_providers: Vec<Provider>,
    pub max_cost: Option<f64>,
    pub max_latency_ms: Option<u64>,
}

impl RoutingRequest {
    pub fn new(prompt: impl Into<String>) -> Self {
        Self {
            prompt: prompt.into(),
            input_tokens: 0,
            max_output_tokens: 4096,
            requires_vision: false,
            requires_function_calling: false,
            requires_streaming: false,
            preferred_provider: None,
            excluded_providers: Vec::new(),
            max_cost: None,
            max_latency_ms: None,
        }
    }

    pub fn with_vision(mut self) -> Self {
        self.requires_vision = true;
        self
    }

    pub fn with_function_calling(mut self) -> Self {
        self.requires_function_calling = true;
        self
    }

    pub fn prefer_provider(mut self, provider: Provider) -> Self {
        self.preferred_provider = Some(provider);
        self
    }

    pub fn exclude_provider(mut self, provider: Provider) -> Self {
        self.excluded_providers.push(provider);
        self
    }

    pub fn max_cost(mut self, cost: f64) -> Self {
        self.max_cost = Some(cost);
        self
    }
}

/// Routing decision
#[derive(Debug, Clone)]
pub struct RoutingDecision {
    pub selected_model: Model,
    pub fallback_models: Vec<Model>,
    pub reason: String,
    pub estimated_cost: f64,
    pub estimated_latency_ms: u64,
}

/// Provider configuration
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    pub provider: Provider,
    pub api_key: String,
    pub endpoint: String,
    pub weight: u32,
    pub rate_limit_rpm: u32,
    pub rate_limit_tpm: u32,
    pub enabled: bool,
}

impl ProviderConfig {
    pub fn new(provider: Provider, api_key: impl Into<String>) -> Self {
        let endpoint = provider.default_endpoint().to_string();
        Self {
            provider,
            api_key: api_key.into(),
            endpoint,
            weight: 100,
            rate_limit_rpm: 60,
            rate_limit_tpm: 100000,
            enabled: true,
        }
    }

    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into();
        self
    }

    pub fn with_weight(mut self, weight: u32) -> Self {
        self.weight = weight;
        self
    }

    pub fn with_rate_limits(mut self, rpm: u32, tpm: u32) -> Self {
        self.rate_limit_rpm = rpm;
        self.rate_limit_tpm = tpm;
        self
    }
}

/// Multi-provider router
pub struct ProviderRouter {
    providers: HashMap<Provider, ProviderConfig>,
    models: Vec<Model>,
    health: HashMap<Provider, ProviderHealth>,
    strategy: RoutingStrategy,
    round_robin_counter: AtomicU64,
    fallback_enabled: bool,
    circuit_breaker_threshold: u32,
}

impl ProviderRouter {
    pub fn new(strategy: RoutingStrategy) -> Self {
        Self {
            providers: HashMap::new(),
            models: Vec::new(),
            health: HashMap::new(),
            strategy,
            round_robin_counter: AtomicU64::new(0),
            fallback_enabled: true,
            circuit_breaker_threshold: 5,
        }
    }

    pub fn add_provider(&mut self, config: ProviderConfig) {
        let provider = config.provider.clone();
        self.health
            .insert(provider.clone(), ProviderHealth::new(provider.clone()));
        self.providers.insert(provider, config);
    }

    pub fn add_model(&mut self, model: Model) {
        self.models.push(model);
    }

    pub fn with_fallback(mut self, enabled: bool) -> Self {
        self.fallback_enabled = enabled;
        self
    }

    pub fn route(&self, request: &RoutingRequest) -> Result<RoutingDecision, RouterError> {
        // Filter compatible models
        let compatible_models = self.filter_compatible_models(request);

        if compatible_models.is_empty() {
            return Err(RouterError::NoCompatibleModel);
        }

        // Select based on strategy
        let selected = match self.strategy {
            RoutingStrategy::Primary => self.select_primary(&compatible_models)?,
            RoutingStrategy::RoundRobin => self.select_round_robin(&compatible_models),
            RoutingStrategy::LowestLatency => self.select_lowest_latency(&compatible_models)?,
            RoutingStrategy::LowestCost => self.select_lowest_cost(&compatible_models, request),
            RoutingStrategy::Random => self.select_random(&compatible_models),
            RoutingStrategy::Weighted => self.select_weighted(&compatible_models),
            RoutingStrategy::ContentBased => self.select_content_based(&compatible_models, request),
        };

        // Build fallback list
        let fallback_models: Vec<Model> = if self.fallback_enabled {
            compatible_models
                .into_iter()
                .filter(|m| m.model_id != selected.model_id)
                .take(2)
                .cloned()
                .collect()
        } else {
            Vec::new()
        };

        let estimated_cost =
            selected.estimate_cost(request.input_tokens, request.max_output_tokens);
        let estimated_latency = self
            .health
            .get(&selected.provider)
            .map(|h| h.latency_ms)
            .unwrap_or(500);

        Ok(RoutingDecision {
            selected_model: selected.clone(),
            fallback_models,
            reason: format!("Selected by {:?} strategy", self.strategy),
            estimated_cost,
            estimated_latency_ms: estimated_latency,
        })
    }

    fn filter_compatible_models(&self, request: &RoutingRequest) -> Vec<&Model> {
        self.models
            .iter()
            .filter(|model| {
                // Check provider is enabled and healthy
                let config = self.providers.get(&model.provider);
                let health = self.health.get(&model.provider);

                if config.map(|c| !c.enabled).unwrap_or(true) {
                    return false;
                }

                if health.map(|h| !h.should_use()).unwrap_or(false) {
                    return false;
                }

                // Check excluded providers
                if request.excluded_providers.contains(&model.provider) {
                    return false;
                }

                // Check requirements
                if request.requires_vision && !model.supports_vision {
                    return false;
                }

                if request.requires_function_calling && !model.supports_function_calling {
                    return false;
                }

                if request.requires_streaming && !model.supports_streaming {
                    return false;
                }

                // Check cost constraint
                if let Some(max_cost) = request.max_cost {
                    let estimated =
                        model.estimate_cost(request.input_tokens, request.max_output_tokens);
                    if estimated > max_cost {
                        return false;
                    }
                }

                true
            })
            .collect()
    }

    fn select_primary(&self, models: &[&Model]) -> Result<&Model, RouterError> {
        models
            .first()
            .copied()
            .ok_or(RouterError::NoCompatibleModel)
    }

    fn select_round_robin(&self, models: &[&Model]) -> &Model {
        let count = self.round_robin_counter.fetch_add(1, Ordering::Relaxed);
        let index = (count as usize) % models.len();
        models[index]
    }

    fn select_lowest_latency(&self, models: &[&Model]) -> Result<&Model, RouterError> {
        models
            .iter()
            .min_by_key(|m| {
                self.health
                    .get(&m.provider)
                    .map(|h| h.latency_ms)
                    .unwrap_or(u64::MAX)
            })
            .copied()
            .ok_or(RouterError::NoCompatibleModel)
    }

    fn select_lowest_cost(&self, models: &[&Model], request: &RoutingRequest) -> &Model {
        models
            .iter()
            .min_by(|a, b| {
                let cost_a = a.estimate_cost(request.input_tokens, request.max_output_tokens);
                let cost_b = b.estimate_cost(request.input_tokens, request.max_output_tokens);
                cost_a
                    .partial_cmp(&cost_b)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .copied()
            .unwrap_or(models[0])
    }

    fn select_random(&self, models: &[&Model]) -> &Model {
        // Simple pseudo-random selection
        let index = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as usize)
            % models.len();
        models[index]
    }

    fn select_weighted(&self, models: &[&Model]) -> &Model {
        let total_weight: u32 = models
            .iter()
            .filter_map(|m| self.providers.get(&m.provider))
            .map(|c| c.weight)
            .sum();

        if total_weight == 0 {
            return models[0];
        }

        let random_weight = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u32)
            % total_weight;

        let mut cumulative = 0u32;
        for model in models {
            if let Some(config) = self.providers.get(&model.provider) {
                cumulative += config.weight;
                if random_weight < cumulative {
                    return model;
                }
            }
        }

        models[0]
    }

    fn select_content_based(&self, models: &[&Model], request: &RoutingRequest) -> &Model {
        // Simple content-based routing
        let prompt_lower = request.prompt.to_lowercase();

        // Route code questions to Claude
        if prompt_lower.contains("code") || prompt_lower.contains("programming") {
            if let Some(model) = models.iter().find(|m| m.provider == Provider::Anthropic) {
                return model;
            }
        }

        // Route search queries to Perplexity
        if prompt_lower.contains("search") || prompt_lower.contains("latest") {
            if let Some(model) = models.iter().find(|m| m.provider == Provider::Perplexity) {
                return model;
            }
        }

        // Default to first model
        models[0]
    }

    pub fn record_success(&mut self, provider: &Provider, latency: Duration) {
        if let Some(health) = self.health.get_mut(provider) {
            health.record_success(latency);
        }
    }

    pub fn record_failure(&mut self, provider: &Provider) {
        if let Some(health) = self.health.get_mut(provider) {
            health.record_failure();
        }
    }

    pub fn get_health(&self) -> Vec<&ProviderHealth> {
        self.health.values().collect()
    }

    pub fn get_statistics(&self) -> RouterStatistics {
        let mut total_requests = 0u64;
        let mut total_errors = 0u64;
        let mut healthy_providers = 0;
        let mut total_providers = 0;

        for health in self.health.values() {
            total_requests += health.requests_today;
            total_errors += health.errors_today;
            total_providers += 1;
            if health.is_healthy {
                healthy_providers += 1;
            }
        }

        RouterStatistics {
            total_providers,
            healthy_providers,
            total_requests,
            total_errors,
            success_rate: if total_requests > 0 {
                1.0 - (total_errors as f64 / total_requests as f64)
            } else {
                1.0
            },
            strategy: self.strategy.clone(),
        }
    }
}

/// Router error
#[derive(Debug)]
pub enum RouterError {
    NoCompatibleModel,
    AllProvidersUnhealthy,
    RateLimitExceeded,
    ConfigurationError(String),
}

impl fmt::Display for RouterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCompatibleModel => write!(f, "No compatible model found"),
            Self::AllProvidersUnhealthy => write!(f, "All providers are unhealthy"),
            Self::RateLimitExceeded => write!(f, "Rate limit exceeded"),
            Self::ConfigurationError(msg) => write!(f, "Configuration error: {}", msg),
        }
    }
}

impl std::error::Error for RouterError {}

/// Router statistics
#[derive(Debug)]
pub struct RouterStatistics {
    pub total_providers: usize,
    pub healthy_providers: usize,
    pub total_requests: u64,
    pub total_errors: u64,
    pub success_rate: f64,
    pub strategy: RoutingStrategy,
}

fn main() {
    println!("=== Multi-Provider AI Gateway Router Demo ===\n");

    // Create router
    let mut router = ProviderRouter::new(RoutingStrategy::LowestLatency);

    // Add providers
    router.add_provider(
        ProviderConfig::new(Provider::Anthropic, "sk-ant-xxx")
            .with_weight(100)
            .with_rate_limits(60, 100000),
    );

    router.add_provider(
        ProviderConfig::new(Provider::OpenAI, "sk-xxx")
            .with_weight(80)
            .with_rate_limits(60, 150000),
    );

    router.add_provider(
        ProviderConfig::new(Provider::Google, "AIzaxxx")
            .with_weight(60)
            .with_rate_limits(60, 120000),
    );

    router.add_provider(ProviderConfig::new(Provider::Perplexity, "pplx-xxx").with_weight(40));

    // Add models
    router.add_model(
        Model::new(Provider::Anthropic, "claude-sonnet-4-20250514")
            .with_costs(0.003, 0.015)
            .with_vision(),
    );

    router.add_model(
        Model::new(Provider::OpenAI, "gpt-4o")
            .with_costs(0.005, 0.015)
            .with_vision(),
    );

    router.add_model(
        Model::new(Provider::Google, "gemini-1.5-pro")
            .with_costs(0.00125, 0.005)
            .with_vision(),
    );

    router.add_model(
        Model::new(Provider::Perplexity, "llama-3.1-sonar-large-128k-online")
            .with_costs(0.001, 0.001),
    );

    // Simulate some health data
    router.record_success(&Provider::Anthropic, Duration::from_millis(200));
    router.record_success(&Provider::OpenAI, Duration::from_millis(350));
    router.record_success(&Provider::Google, Duration::from_millis(150));
    router.record_success(&Provider::Perplexity, Duration::from_millis(400));

    // Route a simple request
    println!("--- Simple Request ---");
    let request = RoutingRequest::new("Explain quantum computing").max_cost(0.10);

    match router.route(&request) {
        Ok(decision) => {
            println!(
                "Selected: {} ({})",
                decision.selected_model.model_id, decision.selected_model.provider
            );
            println!("Reason: {}", decision.reason);
            println!("Estimated cost: ${:.4}", decision.estimated_cost);
            println!("Estimated latency: {}ms", decision.estimated_latency_ms);
            println!(
                "Fallbacks: {:?}",
                decision
                    .fallback_models
                    .iter()
                    .map(|m| &m.model_id)
                    .collect::<Vec<_>>()
            );
        }
        Err(e) => println!("Error: {}", e),
    }

    // Route a vision request
    println!("\n--- Vision Request ---");
    let vision_request = RoutingRequest::new("Describe this image").with_vision();

    match router.route(&vision_request) {
        Ok(decision) => {
            println!(
                "Selected: {} ({})",
                decision.selected_model.model_id, decision.selected_model.provider
            );
            println!(
                "Supports vision: {}",
                decision.selected_model.supports_vision
            );
        }
        Err(e) => println!("Error: {}", e),
    }

    // Route with provider preference
    println!("\n--- Preferred Provider Request ---");
    let preferred_request =
        RoutingRequest::new("Write some code").prefer_provider(Provider::Anthropic);

    match router.route(&preferred_request) {
        Ok(decision) => {
            println!(
                "Selected: {} ({})",
                decision.selected_model.model_id, decision.selected_model.provider
            );
        }
        Err(e) => println!("Error: {}", e),
    }

    // Route excluding a provider
    println!("\n--- Excluding Provider Request ---");
    let exclude_request = RoutingRequest::new("General question")
        .exclude_provider(Provider::OpenAI)
        .exclude_provider(Provider::Google);

    match router.route(&exclude_request) {
        Ok(decision) => {
            println!(
                "Selected: {} ({})",
                decision.selected_model.model_id, decision.selected_model.provider
            );
        }
        Err(e) => println!("Error: {}", e),
    }

    // Show health status
    println!("\n--- Provider Health ---");
    for health in router.get_health() {
        println!(
            "{}: {} (latency: {}ms, success: {:.1}%)",
            health.provider,
            if health.is_healthy {
                "Healthy"
            } else {
                "Unhealthy"
            },
            health.latency_ms,
            health.success_rate * 100.0
        );
    }

    // Show statistics
    println!("\n--- Router Statistics ---");
    let stats = router.get_statistics();
    println!("Total providers: {}", stats.total_providers);
    println!("Healthy providers: {}", stats.healthy_providers);
    println!("Total requests: {}", stats.total_requests);
    println!("Success rate: {:.1}%", stats.success_rate * 100.0);
    println!("Strategy: {:?}", stats.strategy);

    // Test different strategies
    println!("\n--- Strategy Comparison ---");
    let strategies = vec![
        RoutingStrategy::Primary,
        RoutingStrategy::RoundRobin,
        RoutingStrategy::LowestLatency,
        RoutingStrategy::LowestCost,
        RoutingStrategy::Weighted,
    ];

    let test_request = RoutingRequest::new("Test prompt");

    for strategy in strategies {
        let mut test_router = ProviderRouter::new(strategy.clone());

        // Copy configuration
        test_router.add_provider(ProviderConfig::new(Provider::Anthropic, "xxx").with_weight(100));
        test_router.add_provider(ProviderConfig::new(Provider::OpenAI, "xxx").with_weight(80));

        test_router.add_model(
            Model::new(Provider::Anthropic, "claude-sonnet-4-20250514").with_costs(0.003, 0.015),
        );
        test_router.add_model(Model::new(Provider::OpenAI, "gpt-4o").with_costs(0.005, 0.015));

        test_router.record_success(&Provider::Anthropic, Duration::from_millis(200));
        test_router.record_success(&Provider::OpenAI, Duration::from_millis(150));

        if let Ok(decision) = test_router.route(&test_request) {
            println!("{:?}: {}", strategy, decision.selected_model.model_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_router() -> ProviderRouter {
        let mut router = ProviderRouter::new(RoutingStrategy::LowestLatency);

        router.add_provider(ProviderConfig::new(Provider::Anthropic, "key1").with_weight(100));
        router.add_provider(ProviderConfig::new(Provider::OpenAI, "key2").with_weight(80));

        router.add_model(Model::new(Provider::Anthropic, "claude").with_costs(0.003, 0.015));
        router.add_model(
            Model::new(Provider::OpenAI, "gpt-4")
                .with_costs(0.005, 0.015)
                .with_vision(),
        );

        router.record_success(&Provider::Anthropic, Duration::from_millis(200));
        router.record_success(&Provider::OpenAI, Duration::from_millis(150));

        router
    }

    #[test]
    fn test_provider_properties() {
        assert_eq!(Provider::Anthropic.name(), "Anthropic");
        assert!(!Provider::OpenAI.default_endpoint().is_empty());
    }

    #[test]
    fn test_model_cost_estimation() {
        let model = Model::new(Provider::Anthropic, "test").with_costs(0.001, 0.002);

        let cost = model.estimate_cost(1000, 500);
        assert!((cost - 2.0).abs() < 0.001);
    }

    #[test]
    fn test_routing_simple() {
        let router = setup_router();
        let request = RoutingRequest::new("Hello");

        let decision = router.route(&request).unwrap();
        assert!(!decision.selected_model.model_id.is_empty());
    }

    #[test]
    fn test_routing_with_vision() {
        let router = setup_router();
        let request = RoutingRequest::new("Describe image").with_vision();

        let decision = router.route(&request).unwrap();
        assert!(decision.selected_model.supports_vision);
    }

    #[test]
    fn test_routing_exclude_provider() {
        let router = setup_router();
        let request = RoutingRequest::new("Test").exclude_provider(Provider::OpenAI);

        let decision = router.route(&request).unwrap();
        assert_ne!(decision.selected_model.provider, Provider::OpenAI);
    }

    #[test]
    fn test_health_recording() {
        let mut router = setup_router();

        router.record_success(&Provider::Anthropic, Duration::from_millis(100));
        let health = router.health.get(&Provider::Anthropic).unwrap();
        assert!(health.is_healthy);
        assert_eq!(health.latency_ms, 100);

        router.record_failure(&Provider::Anthropic);
        router.record_failure(&Provider::Anthropic);
        router.record_failure(&Provider::Anthropic);
        let health = router.health.get(&Provider::Anthropic).unwrap();
        assert!(!health.is_healthy);
    }

    #[test]
    fn test_round_robin() {
        let mut router = ProviderRouter::new(RoutingStrategy::RoundRobin);

        router.add_provider(ProviderConfig::new(Provider::Anthropic, "key1"));
        router.add_provider(ProviderConfig::new(Provider::OpenAI, "key2"));

        router.add_model(Model::new(Provider::Anthropic, "claude"));
        router.add_model(Model::new(Provider::OpenAI, "gpt"));

        router.record_success(&Provider::Anthropic, Duration::from_millis(100));
        router.record_success(&Provider::OpenAI, Duration::from_millis(100));

        let request = RoutingRequest::new("Test");

        let d1 = router.route(&request).unwrap();
        let d2 = router.route(&request).unwrap();

        assert_ne!(d1.selected_model.provider, d2.selected_model.provider);
    }

    #[test]
    fn test_lowest_latency() {
        let mut router = ProviderRouter::new(RoutingStrategy::LowestLatency);

        router.add_provider(ProviderConfig::new(Provider::Anthropic, "key1"));
        router.add_provider(ProviderConfig::new(Provider::OpenAI, "key2"));

        router.add_model(Model::new(Provider::Anthropic, "claude"));
        router.add_model(Model::new(Provider::OpenAI, "gpt"));

        router.record_success(&Provider::Anthropic, Duration::from_millis(500));
        router.record_success(&Provider::OpenAI, Duration::from_millis(100));

        let request = RoutingRequest::new("Test");
        let decision = router.route(&request).unwrap();

        assert_eq!(decision.selected_model.provider, Provider::OpenAI);
    }

    #[test]
    fn test_lowest_cost() {
        let mut router = ProviderRouter::new(RoutingStrategy::LowestCost);

        router.add_provider(ProviderConfig::new(Provider::Anthropic, "key1"));
        router.add_provider(ProviderConfig::new(Provider::OpenAI, "key2"));

        router.add_model(Model::new(Provider::Anthropic, "claude").with_costs(0.01, 0.02));
        router.add_model(Model::new(Provider::OpenAI, "gpt").with_costs(0.001, 0.002));

        router.record_success(&Provider::Anthropic, Duration::from_millis(100));
        router.record_success(&Provider::OpenAI, Duration::from_millis(100));

        let mut request = RoutingRequest::new("Test");
        request.input_tokens = 1000;
        request.max_output_tokens = 500;

        let decision = router.route(&request).unwrap();
        assert_eq!(decision.selected_model.provider, Provider::OpenAI);
    }

    #[test]
    fn test_fallback_models() {
        let router = setup_router();
        let request = RoutingRequest::new("Test");

        let decision = router.route(&request).unwrap();
        assert!(!decision.fallback_models.is_empty());
    }

    #[test]
    fn test_no_compatible_model() {
        let mut router = ProviderRouter::new(RoutingStrategy::Primary);
        router.add_provider(ProviderConfig::new(Provider::Anthropic, "key"));
        router.add_model(Model::new(Provider::Anthropic, "claude"));
        router.record_success(&Provider::Anthropic, Duration::from_millis(100));

        let request = RoutingRequest::new("Test").with_vision();

        let result = router.route(&request);
        assert!(result.is_err());
    }

    #[test]
    fn test_statistics() {
        let mut router = setup_router();

        router.record_success(&Provider::Anthropic, Duration::from_millis(100));
        router.record_success(&Provider::OpenAI, Duration::from_millis(100));
        router.record_failure(&Provider::Anthropic);

        let stats = router.get_statistics();
        assert_eq!(stats.total_providers, 2);
        assert!(stats.total_requests > 0);
    }
}
