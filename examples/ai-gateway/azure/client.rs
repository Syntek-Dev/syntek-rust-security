//! Azure OpenAI / GitHub Copilot Client
//!
//! Secure client for Azure OpenAI Service with:
//! - Azure AD / API key authentication
//! - Deployment-based model routing
//! - Content filtering integration
//! - Enterprise compliance features
//! - Cost tracking and quotas

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ============================================================================
// Configuration
// ============================================================================

/// Azure OpenAI authentication method
#[derive(Debug, Clone)]
pub enum AzureAuth {
    /// API key authentication
    ApiKey(String),
    /// Azure AD token (managed identity or service principal)
    AzureAd {
        tenant_id: String,
        client_id: String,
        client_secret: String,
    },
    /// Managed Identity (for Azure-hosted apps)
    ManagedIdentity,
}

/// Azure OpenAI configuration
#[derive(Debug, Clone)]
pub struct AzureOpenAIConfig {
    /// Azure resource endpoint (e.g., https://myresource.openai.azure.com)
    pub endpoint: String,
    /// API version (e.g., 2024-02-15-preview)
    pub api_version: String,
    /// Authentication method
    pub auth: AzureAuth,
    /// Default deployment name
    pub default_deployment: String,
    /// Request timeout
    pub timeout: Duration,
    /// Enable content filtering logging
    pub log_content_filtering: bool,
}

impl AzureOpenAIConfig {
    pub fn new(endpoint: &str, api_key: &str, deployment: &str) -> Self {
        Self {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            api_version: "2024-02-15-preview".to_string(),
            auth: AzureAuth::ApiKey(api_key.to_string()),
            default_deployment: deployment.to_string(),
            timeout: Duration::from_secs(60),
            log_content_filtering: true,
        }
    }

    pub fn with_azure_ad(
        endpoint: &str,
        tenant_id: &str,
        client_id: &str,
        client_secret: &str,
        deployment: &str,
    ) -> Self {
        Self {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            api_version: "2024-02-15-preview".to_string(),
            auth: AzureAuth::AzureAd {
                tenant_id: tenant_id.to_string(),
                client_id: client_id.to_string(),
                client_secret: client_secret.to_string(),
            },
            default_deployment: deployment.to_string(),
            timeout: Duration::from_secs(60),
            log_content_filtering: true,
        }
    }
}

// ============================================================================
// Request/Response Types
// ============================================================================

/// Chat message role
#[derive(Debug, Clone, PartialEq)]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
}

impl Role {
    fn as_str(&self) -> &'static str {
        match self {
            Role::System => "system",
            Role::User => "user",
            Role::Assistant => "assistant",
            Role::Tool => "tool",
        }
    }
}

/// Chat message
#[derive(Debug, Clone)]
pub struct Message {
    pub role: Role,
    pub content: String,
    pub name: Option<String>,
    pub tool_call_id: Option<String>,
}

impl Message {
    pub fn system(content: &str) -> Self {
        Self {
            role: Role::System,
            content: content.to_string(),
            name: None,
            tool_call_id: None,
        }
    }

    pub fn user(content: &str) -> Self {
        Self {
            role: Role::User,
            content: content.to_string(),
            name: None,
            tool_call_id: None,
        }
    }

    pub fn assistant(content: &str) -> Self {
        Self {
            role: Role::Assistant,
            content: content.to_string(),
            name: None,
            tool_call_id: None,
        }
    }
}

/// Function/tool definition for function calling
#[derive(Debug, Clone)]
pub struct FunctionDefinition {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

/// Tool call from the model
#[derive(Debug, Clone)]
pub struct ToolCall {
    pub id: String,
    pub function_name: String,
    pub arguments: String,
}

/// Chat completion request
#[derive(Debug, Clone)]
pub struct ChatCompletionRequest {
    pub messages: Vec<Message>,
    pub deployment: Option<String>,
    pub max_tokens: Option<u32>,
    pub temperature: Option<f32>,
    pub top_p: Option<f32>,
    pub stop: Option<Vec<String>>,
    pub functions: Option<Vec<FunctionDefinition>>,
    pub stream: bool,
    /// Azure-specific: data sources for RAG
    pub data_sources: Option<Vec<AzureDataSource>>,
}

impl ChatCompletionRequest {
    pub fn new(messages: Vec<Message>) -> Self {
        Self {
            messages,
            deployment: None,
            max_tokens: None,
            temperature: None,
            top_p: None,
            stop: None,
            functions: None,
            stream: false,
            data_sources: None,
        }
    }

    pub fn with_deployment(mut self, deployment: &str) -> Self {
        self.deployment = Some(deployment.to_string());
        self
    }

    pub fn with_max_tokens(mut self, max_tokens: u32) -> Self {
        self.max_tokens = Some(max_tokens);
        self
    }

    pub fn with_temperature(mut self, temperature: f32) -> Self {
        self.temperature = Some(temperature.clamp(0.0, 2.0));
        self
    }

    pub fn with_stream(mut self) -> Self {
        self.stream = true;
        self
    }
}

/// Azure-specific data source for RAG (Retrieval Augmented Generation)
#[derive(Debug, Clone)]
pub struct AzureDataSource {
    pub source_type: DataSourceType,
    pub parameters: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub enum DataSourceType {
    AzureCognitiveSearch,
    AzureCosmosDB,
    AzureBlobStorage,
}

/// Chat completion response
#[derive(Debug, Clone)]
pub struct ChatCompletionResponse {
    pub id: String,
    pub model: String,
    pub choices: Vec<Choice>,
    pub usage: Usage,
    pub content_filter_results: Option<ContentFilterResults>,
}

#[derive(Debug, Clone)]
pub struct Choice {
    pub index: u32,
    pub message: Message,
    pub finish_reason: String,
    pub tool_calls: Option<Vec<ToolCall>>,
}

#[derive(Debug, Clone)]
pub struct Usage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

/// Azure content filtering results
#[derive(Debug, Clone)]
pub struct ContentFilterResults {
    pub hate: FilterResult,
    pub self_harm: FilterResult,
    pub sexual: FilterResult,
    pub violence: FilterResult,
    pub jailbreak: Option<bool>,
    pub profanity: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct FilterResult {
    pub filtered: bool,
    pub severity: FilterSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FilterSeverity {
    Safe,
    Low,
    Medium,
    High,
}

// ============================================================================
// Azure AD Token Manager
// ============================================================================

/// Manages Azure AD tokens with automatic refresh
pub struct TokenManager {
    tenant_id: String,
    client_id: String,
    client_secret: String,
    current_token: std::sync::Mutex<Option<(String, Instant)>>,
    token_lifetime: Duration,
}

impl TokenManager {
    pub fn new(tenant_id: &str, client_id: &str, client_secret: &str) -> Self {
        Self {
            tenant_id: tenant_id.to_string(),
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            current_token: std::sync::Mutex::new(None),
            token_lifetime: Duration::from_secs(3600), // 1 hour default
        }
    }

    /// Get a valid token, refreshing if necessary
    pub fn get_token(&self) -> Result<String, AzureError> {
        let mut token = self.current_token.lock().unwrap();

        if let Some((ref t, ref issued)) = *token {
            if issued.elapsed() < self.token_lifetime - Duration::from_secs(300) {
                return Ok(t.clone());
            }
        }

        // Refresh token
        let new_token = self.fetch_token()?;
        *token = Some((new_token.clone(), Instant::now()));
        Ok(new_token)
    }

    fn fetch_token(&self) -> Result<String, AzureError> {
        // Simulate Azure AD token fetch
        // In production: POST to https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
        let token = format!(
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Imk2bEdrM0ZaenhSY{}",
            generate_random_hex(32)
        );
        Ok(token)
    }
}

// ============================================================================
// Client Implementation
// ============================================================================

/// Azure OpenAI client with enterprise features
pub struct AzureOpenAIClient {
    config: AzureOpenAIConfig,
    token_manager: Option<TokenManager>,
    request_count: AtomicU64,
    total_tokens: AtomicU64,
    deployments: HashMap<String, DeploymentInfo>,
}

#[derive(Debug, Clone)]
pub struct DeploymentInfo {
    pub name: String,
    pub model: String,
    pub capacity: u32,
    pub rate_limit_requests: u32,
    pub rate_limit_tokens: u32,
}

impl AzureOpenAIClient {
    pub fn new(config: AzureOpenAIConfig) -> Self {
        let token_manager = match &config.auth {
            AzureAuth::AzureAd {
                tenant_id,
                client_id,
                client_secret,
            } => Some(TokenManager::new(tenant_id, client_id, client_secret)),
            _ => None,
        };

        Self {
            config,
            token_manager,
            request_count: AtomicU64::new(0),
            total_tokens: AtomicU64::new(0),
            deployments: HashMap::new(),
        }
    }

    /// Register a deployment
    pub fn register_deployment(&mut self, info: DeploymentInfo) {
        self.deployments.insert(info.name.clone(), info);
    }

    /// Build the API URL for a deployment
    fn build_url(&self, deployment: &str, operation: &str) -> String {
        format!(
            "{}/openai/deployments/{}/{}?api-version={}",
            self.config.endpoint, deployment, operation, self.config.api_version
        )
    }

    /// Get authentication header
    fn get_auth_header(&self) -> Result<(String, String), AzureError> {
        match &self.config.auth {
            AzureAuth::ApiKey(key) => Ok(("api-key".to_string(), key.clone())),
            AzureAuth::AzureAd { .. } => {
                let token = self
                    .token_manager
                    .as_ref()
                    .ok_or_else(|| AzureError::AuthError("Token manager not initialized".into()))?
                    .get_token()?;
                Ok(("Authorization".to_string(), format!("Bearer {}", token)))
            }
            AzureAuth::ManagedIdentity => {
                // In production: fetch from Azure Instance Metadata Service (IMDS)
                Err(AzureError::AuthError(
                    "Managed identity not in Azure environment".into(),
                ))
            }
        }
    }

    /// Create a chat completion
    pub fn chat_completion(
        &self,
        request: ChatCompletionRequest,
    ) -> Result<ChatCompletionResponse, AzureError> {
        self.request_count.fetch_add(1, Ordering::Relaxed);

        let deployment = request
            .deployment
            .as_ref()
            .unwrap_or(&self.config.default_deployment);

        let _url = self.build_url(deployment, "chat/completions");
        let (_header_name, _header_value) = self.get_auth_header()?;

        // Build request body
        let _body = self.build_request_body(&request);

        // Simulate API response
        let response = self.simulate_response(&request)?;

        // Track token usage
        self.total_tokens
            .fetch_add(response.usage.total_tokens as u64, Ordering::Relaxed);

        // Log content filtering if enabled
        if self.config.log_content_filtering {
            if let Some(ref filter) = response.content_filter_results {
                if filter.hate.filtered
                    || filter.violence.filtered
                    || filter.sexual.filtered
                    || filter.self_harm.filtered
                {
                    eprintln!("Content filter triggered: {:?}", filter);
                }
            }
        }

        Ok(response)
    }

    fn build_request_body(&self, request: &ChatCompletionRequest) -> serde_json::Value {
        let messages: Vec<serde_json::Value> = request
            .messages
            .iter()
            .map(|m| {
                let mut msg = serde_json::json!({
                    "role": m.role.as_str(),
                    "content": m.content,
                });
                if let Some(ref name) = m.name {
                    msg["name"] = serde_json::Value::String(name.clone());
                }
                msg
            })
            .collect();

        let mut body = serde_json::json!({
            "messages": messages,
        });

        if let Some(max_tokens) = request.max_tokens {
            body["max_tokens"] = serde_json::Value::Number(max_tokens.into());
        }
        if let Some(temperature) = request.temperature {
            body["temperature"] = serde_json::json!(temperature);
        }
        if let Some(top_p) = request.top_p {
            body["top_p"] = serde_json::json!(top_p);
        }
        if request.stream {
            body["stream"] = serde_json::Value::Bool(true);
        }

        // Azure-specific: data sources for RAG
        if let Some(ref sources) = request.data_sources {
            let data_sources: Vec<serde_json::Value> = sources
                .iter()
                .map(|s| {
                    serde_json::json!({
                        "type": match s.source_type {
                            DataSourceType::AzureCognitiveSearch => "azure_search",
                            DataSourceType::AzureCosmosDB => "azure_cosmos_db",
                            DataSourceType::AzureBlobStorage => "azure_blob_storage",
                        },
                        "parameters": s.parameters,
                    })
                })
                .collect();
            body["data_sources"] = serde_json::Value::Array(data_sources);
        }

        body
    }

    fn simulate_response(
        &self,
        request: &ChatCompletionRequest,
    ) -> Result<ChatCompletionResponse, AzureError> {
        // Simulate response for demonstration
        let prompt_tokens = request
            .messages
            .iter()
            .map(|m| m.content.len() / 4)
            .sum::<usize>() as u32;

        Ok(ChatCompletionResponse {
            id: format!("chatcmpl-azure-{}", generate_random_hex(8)),
            model: "gpt-4".to_string(),
            choices: vec![Choice {
                index: 0,
                message: Message::assistant("This is a simulated response from Azure OpenAI."),
                finish_reason: "stop".to_string(),
                tool_calls: None,
            }],
            usage: Usage {
                prompt_tokens,
                completion_tokens: 20,
                total_tokens: prompt_tokens + 20,
            },
            content_filter_results: Some(ContentFilterResults {
                hate: FilterResult {
                    filtered: false,
                    severity: FilterSeverity::Safe,
                },
                self_harm: FilterResult {
                    filtered: false,
                    severity: FilterSeverity::Safe,
                },
                sexual: FilterResult {
                    filtered: false,
                    severity: FilterSeverity::Safe,
                },
                violence: FilterResult {
                    filtered: false,
                    severity: FilterSeverity::Safe,
                },
                jailbreak: Some(false),
                profanity: Some(false),
            }),
        })
    }

    /// Get client statistics
    pub fn stats(&self) -> ClientStats {
        ClientStats {
            total_requests: self.request_count.load(Ordering::Relaxed),
            total_tokens: self.total_tokens.load(Ordering::Relaxed),
            deployments: self.deployments.len(),
        }
    }
}

#[derive(Debug)]
pub struct ClientStats {
    pub total_requests: u64,
    pub total_tokens: u64,
    pub deployments: usize,
}

// ============================================================================
// Quota and Cost Management
// ============================================================================

/// Tracks usage and costs for Azure OpenAI
pub struct CostTracker {
    /// Cost per 1K prompt tokens by model
    prompt_costs: HashMap<String, f64>,
    /// Cost per 1K completion tokens by model
    completion_costs: HashMap<String, f64>,
    /// Usage by deployment
    usage: std::sync::Mutex<HashMap<String, DeploymentUsage>>,
}

#[derive(Debug, Clone, Default)]
pub struct DeploymentUsage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub requests: u64,
}

impl CostTracker {
    pub fn new() -> Self {
        let mut prompt_costs = HashMap::new();
        let mut completion_costs = HashMap::new();

        // Azure OpenAI pricing (example - check current pricing)
        prompt_costs.insert("gpt-4".to_string(), 0.03);
        prompt_costs.insert("gpt-4-32k".to_string(), 0.06);
        prompt_costs.insert("gpt-35-turbo".to_string(), 0.0015);
        prompt_costs.insert("gpt-35-turbo-16k".to_string(), 0.003);

        completion_costs.insert("gpt-4".to_string(), 0.06);
        completion_costs.insert("gpt-4-32k".to_string(), 0.12);
        completion_costs.insert("gpt-35-turbo".to_string(), 0.002);
        completion_costs.insert("gpt-35-turbo-16k".to_string(), 0.004);

        Self {
            prompt_costs,
            completion_costs,
            usage: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Record token usage
    pub fn record(&self, deployment: &str, model: &str, usage: &Usage) {
        let mut usage_map = self.usage.lock().unwrap();
        let entry = usage_map.entry(deployment.to_string()).or_default();
        entry.prompt_tokens += usage.prompt_tokens as u64;
        entry.completion_tokens += usage.completion_tokens as u64;
        entry.requests += 1;
        drop(usage_map);

        // Calculate cost
        let prompt_cost = self.prompt_costs.get(model).unwrap_or(&0.03);
        let completion_cost = self.completion_costs.get(model).unwrap_or(&0.06);

        let cost = (usage.prompt_tokens as f64 / 1000.0 * prompt_cost)
            + (usage.completion_tokens as f64 / 1000.0 * completion_cost);

        println!("Request cost: ${:.6}", cost);
    }

    /// Get total cost estimate
    pub fn total_cost(&self, model: &str) -> f64 {
        let usage = self.usage.lock().unwrap();
        let prompt_cost = self.prompt_costs.get(model).unwrap_or(&0.03);
        let completion_cost = self.completion_costs.get(model).unwrap_or(&0.06);

        usage
            .values()
            .map(|u| {
                (u.prompt_tokens as f64 / 1000.0 * prompt_cost)
                    + (u.completion_tokens as f64 / 1000.0 * completion_cost)
            })
            .sum()
    }

    /// Get usage report
    pub fn report(&self) -> HashMap<String, DeploymentUsage> {
        self.usage.lock().unwrap().clone()
    }
}

impl Default for CostTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug)]
pub enum AzureError {
    AuthError(String),
    RateLimitExceeded { retry_after: Duration },
    ContentFiltered { category: String },
    DeploymentNotFound(String),
    QuotaExceeded(String),
    NetworkError(String),
    InvalidRequest(String),
}

impl std::fmt::Display for AzureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthError(msg) => write!(f, "Authentication error: {}", msg),
            Self::RateLimitExceeded { retry_after } => {
                write!(f, "Rate limit exceeded, retry after {:?}", retry_after)
            }
            Self::ContentFiltered { category } => {
                write!(f, "Content filtered: {}", category)
            }
            Self::DeploymentNotFound(name) => write!(f, "Deployment not found: {}", name),
            Self::QuotaExceeded(msg) => write!(f, "Quota exceeded: {}", msg),
            Self::NetworkError(msg) => write!(f, "Network error: {}", msg),
            Self::InvalidRequest(msg) => write!(f, "Invalid request: {}", msg),
        }
    }
}

// ============================================================================
// JSON Value (minimal implementation)
// ============================================================================

mod serde_json {
    use std::collections::HashMap;

    #[derive(Debug, Clone)]
    pub enum Value {
        Null,
        Bool(bool),
        Number(i64),
        Float(f64),
        String(String),
        Array(Vec<Value>),
        Object(HashMap<String, Value>),
    }

    impl Value {
        pub fn to_string(&self) -> String {
            match self {
                Value::Null => "null".to_string(),
                Value::Bool(b) => b.to_string(),
                Value::Number(n) => n.to_string(),
                Value::Float(f) => f.to_string(),
                Value::String(s) => format!("\"{}\"", s),
                Value::Array(arr) => {
                    let items: Vec<String> = arr.iter().map(|v| v.to_string()).collect();
                    format!("[{}]", items.join(","))
                }
                Value::Object(obj) => {
                    let items: Vec<String> = obj
                        .iter()
                        .map(|(k, v)| format!("\"{}\":{}", k, v.to_string()))
                        .collect();
                    format!("{{{}}}", items.join(","))
                }
            }
        }
    }

    impl From<i64> for Value {
        fn from(n: i64) -> Self {
            Value::Number(n)
        }
    }

    impl std::ops::IndexMut<&str> for Value {
        fn index_mut(&mut self, key: &str) -> &mut Value {
            if let Value::Object(ref mut map) = self {
                map.entry(key.to_string()).or_insert(Value::Null)
            } else {
                panic!("Not an object");
            }
        }
    }

    impl std::ops::Index<&str> for Value {
        type Output = Value;
        fn index(&self, key: &str) -> &Value {
            if let Value::Object(map) = self {
                map.get(key).unwrap_or(&Value::Null)
            } else {
                &Value::Null
            }
        }
    }

    #[macro_export]
    macro_rules! json {
        (null) => { Value::Null };
        (true) => { Value::Bool(true) };
        (false) => { Value::Bool(false) };
        ($e:expr) => {
            {
                let v = $e;
                if let Some(s) = (&v as &dyn std::any::Any).downcast_ref::<String>() {
                    Value::String(s.clone())
                } else if let Some(s) = (&v as &dyn std::any::Any).downcast_ref::<&str>() {
                    Value::String(s.to_string())
                } else if let Some(n) = (&v as &dyn std::any::Any).downcast_ref::<i32>() {
                    Value::Number(*n as i64)
                } else if let Some(f) = (&v as &dyn std::any::Any).downcast_ref::<f32>() {
                    Value::Float(*f as f64)
                } else {
                    Value::Null
                }
            }
        };
        ({ $($key:tt : $value:tt),* $(,)? }) => {{
            let mut map = HashMap::new();
            $(
                map.insert($key.to_string(), json!($value));
            )*
            Value::Object(map)
        }};
        ([ $($value:tt),* $(,)? ]) => {{
            let mut arr = Vec::new();
            $(
                arr.push(json!($value));
            )*
            Value::Array(arr)
        }};
    }

    pub(crate) use json;
}

// ============================================================================
// Utilities
// ============================================================================

fn generate_random_hex(len: usize) -> String {
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let mut state = seed as u64;
    let mut result = String::with_capacity(len);

    for _ in 0..len {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let digit = (state >> 60) as u8;
        result.push(if digit < 10 {
            (b'0' + digit) as char
        } else {
            (b'a' + digit - 10) as char
        });
    }

    result
}

// ============================================================================
// Main and Tests
// ============================================================================

fn main() {
    println!("Azure OpenAI Client Example\n");

    // Create client with API key
    let config = AzureOpenAIConfig::new(
        "https://my-resource.openai.azure.com",
        "your-api-key",
        "gpt-4-deployment",
    );

    let mut client = AzureOpenAIClient::new(config);

    // Register deployments
    client.register_deployment(DeploymentInfo {
        name: "gpt-4-deployment".to_string(),
        model: "gpt-4".to_string(),
        capacity: 120,
        rate_limit_requests: 120,
        rate_limit_tokens: 40000,
    });

    client.register_deployment(DeploymentInfo {
        name: "gpt-35-turbo-deployment".to_string(),
        model: "gpt-35-turbo".to_string(),
        capacity: 240,
        rate_limit_requests: 240,
        rate_limit_tokens: 80000,
    });

    // Create chat completion request
    let request = ChatCompletionRequest::new(vec![
        Message::system("You are a helpful assistant for enterprise users."),
        Message::user("What are the key security features of Azure OpenAI?"),
    ])
    .with_max_tokens(500)
    .with_temperature(0.7);

    println!("Sending request to Azure OpenAI...");

    match client.chat_completion(request) {
        Ok(response) => {
            println!("\nResponse ID: {}", response.id);
            println!("Model: {}", response.model);

            if let Some(choice) = response.choices.first() {
                println!("Response: {}", choice.message.content);
                println!("Finish reason: {}", choice.finish_reason);
            }

            println!("\nUsage:");
            println!("  Prompt tokens: {}", response.usage.prompt_tokens);
            println!("  Completion tokens: {}", response.usage.completion_tokens);
            println!("  Total tokens: {}", response.usage.total_tokens);

            if let Some(filter) = &response.content_filter_results {
                println!("\nContent Filtering:");
                println!(
                    "  Hate: filtered={}, severity={:?}",
                    filter.hate.filtered, filter.hate.severity
                );
                println!(
                    "  Violence: filtered={}, severity={:?}",
                    filter.violence.filtered, filter.violence.severity
                );
                println!("  Jailbreak detected: {:?}", filter.jailbreak);
            }
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }

    // Cost tracking
    println!("\n--- Cost Tracking ---");
    let tracker = CostTracker::new();
    tracker.record(
        "gpt-4-deployment",
        "gpt-4",
        &Usage {
            prompt_tokens: 100,
            completion_tokens: 50,
            total_tokens: 150,
        },
    );

    println!("Total estimated cost: ${:.4}", tracker.total_cost("gpt-4"));

    // Client stats
    println!("\n--- Client Statistics ---");
    let stats = client.stats();
    println!("Total requests: {}", stats.total_requests);
    println!("Total tokens: {}", stats.total_tokens);
    println!("Registered deployments: {}", stats.deployments);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_creation() {
        let config = AzureOpenAIConfig::new("https://test.openai.azure.com/", "key", "deployment");
        assert_eq!(config.endpoint, "https://test.openai.azure.com");
        assert!(matches!(config.auth, AzureAuth::ApiKey(_)));
    }

    #[test]
    fn test_message_creation() {
        let system = Message::system("You are helpful");
        assert_eq!(system.role, Role::System);

        let user = Message::user("Hello");
        assert_eq!(user.role, Role::User);
    }

    #[test]
    fn test_request_builder() {
        let request = ChatCompletionRequest::new(vec![Message::user("Test")])
            .with_max_tokens(100)
            .with_temperature(0.5)
            .with_deployment("my-deployment");

        assert_eq!(request.max_tokens, Some(100));
        assert_eq!(request.temperature, Some(0.5));
        assert_eq!(request.deployment, Some("my-deployment".to_string()));
    }

    #[test]
    fn test_temperature_clamping() {
        let request = ChatCompletionRequest::new(vec![]).with_temperature(5.0);
        assert_eq!(request.temperature, Some(2.0));

        let request = ChatCompletionRequest::new(vec![]).with_temperature(-1.0);
        assert_eq!(request.temperature, Some(0.0));
    }

    #[test]
    fn test_client_creation() {
        let config = AzureOpenAIConfig::new("https://test.openai.azure.com", "key", "deployment");
        let client = AzureOpenAIClient::new(config);

        let stats = client.stats();
        assert_eq!(stats.total_requests, 0);
    }

    #[test]
    fn test_chat_completion() {
        let config = AzureOpenAIConfig::new("https://test.openai.azure.com", "key", "deployment");
        let client = AzureOpenAIClient::new(config);

        let request = ChatCompletionRequest::new(vec![Message::user("Hello")]);

        let response = client.chat_completion(request);
        assert!(response.is_ok());

        let stats = client.stats();
        assert_eq!(stats.total_requests, 1);
    }

    #[test]
    fn test_cost_tracker() {
        let tracker = CostTracker::new();

        tracker.record(
            "test",
            "gpt-4",
            &Usage {
                prompt_tokens: 1000,
                completion_tokens: 500,
                total_tokens: 1500,
            },
        );

        let report = tracker.report();
        assert!(report.contains_key("test"));
        assert_eq!(report["test"].prompt_tokens, 1000);
    }

    #[test]
    fn test_filter_severity() {
        let filter = FilterResult {
            filtered: false,
            severity: FilterSeverity::Safe,
        };
        assert!(!filter.filtered);
        assert_eq!(filter.severity, FilterSeverity::Safe);
    }
}
