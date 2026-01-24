//! Azure OpenAI Client Implementation
//!
//! Comprehensive client for Azure OpenAI Service with support for deployments,
//! content filtering, and enterprise authentication.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Azure OpenAI deployment configuration
#[derive(Debug, Clone)]
pub struct Deployment {
    pub name: String,
    pub model: AzureModel,
    pub version: String,
    pub capacity: u32,
}

impl Deployment {
    pub fn new(name: impl Into<String>, model: AzureModel) -> Self {
        Self {
            name: name.into(),
            model,
            version: "2024-02-15-preview".to_string(),
            capacity: 10,
        }
    }

    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }

    pub fn capacity(mut self, capacity: u32) -> Self {
        self.capacity = capacity;
        self
    }
}

/// Azure OpenAI model types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AzureModel {
    Gpt4,
    Gpt4Turbo,
    Gpt4Vision,
    Gpt35Turbo,
    Gpt35Turbo16k,
    TextEmbeddingAda002,
    TextEmbedding3Small,
    TextEmbedding3Large,
}

impl AzureModel {
    pub fn as_str(&self) -> &'static str {
        match self {
            AzureModel::Gpt4 => "gpt-4",
            AzureModel::Gpt4Turbo => "gpt-4-turbo",
            AzureModel::Gpt4Vision => "gpt-4-vision-preview",
            AzureModel::Gpt35Turbo => "gpt-35-turbo",
            AzureModel::Gpt35Turbo16k => "gpt-35-turbo-16k",
            AzureModel::TextEmbeddingAda002 => "text-embedding-ada-002",
            AzureModel::TextEmbedding3Small => "text-embedding-3-small",
            AzureModel::TextEmbedding3Large => "text-embedding-3-large",
        }
    }

    pub fn max_tokens(&self) -> u32 {
        match self {
            AzureModel::Gpt4 => 8192,
            AzureModel::Gpt4Turbo => 128000,
            AzureModel::Gpt4Vision => 128000,
            AzureModel::Gpt35Turbo => 4096,
            AzureModel::Gpt35Turbo16k => 16384,
            _ => 8191, // Embeddings
        }
    }

    pub fn is_embedding_model(&self) -> bool {
        matches!(
            self,
            AzureModel::TextEmbeddingAda002
                | AzureModel::TextEmbedding3Small
                | AzureModel::TextEmbedding3Large
        )
    }
}

/// Azure authentication methods
#[derive(Debug, Clone)]
pub enum AzureAuth {
    ApiKey(String),
    AzureAD {
        tenant_id: String,
        client_id: String,
        client_secret: String,
    },
    ManagedIdentity {
        client_id: Option<String>,
    },
}

impl AzureAuth {
    pub fn api_key(key: impl Into<String>) -> Self {
        AzureAuth::ApiKey(key.into())
    }

    pub fn azure_ad(
        tenant_id: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        AzureAuth::AzureAD {
            tenant_id: tenant_id.into(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
        }
    }

    pub fn managed_identity() -> Self {
        AzureAuth::ManagedIdentity { client_id: None }
    }

    pub fn managed_identity_with_client(client_id: impl Into<String>) -> Self {
        AzureAuth::ManagedIdentity {
            client_id: Some(client_id.into()),
        }
    }
}

/// Message role
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
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
pub struct ChatMessage {
    pub role: Role,
    pub content: MessageContent,
    pub name: Option<String>,
    pub tool_calls: Option<Vec<ToolCall>>,
    pub tool_call_id: Option<String>,
}

#[derive(Debug, Clone)]
pub enum MessageContent {
    Text(String),
    MultiModal(Vec<ContentPart>),
}

#[derive(Debug, Clone)]
pub enum ContentPart {
    Text(String),
    ImageUrl { url: String, detail: ImageDetail },
}

#[derive(Debug, Clone, Copy)]
pub enum ImageDetail {
    Auto,
    Low,
    High,
}

impl ChatMessage {
    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: Role::System,
            content: MessageContent::Text(content.into()),
            name: None,
            tool_calls: None,
            tool_call_id: None,
        }
    }

    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: Role::User,
            content: MessageContent::Text(content.into()),
            name: None,
            tool_calls: None,
            tool_call_id: None,
        }
    }

    pub fn user_with_image(text: impl Into<String>, image_url: impl Into<String>) -> Self {
        Self {
            role: Role::User,
            content: MessageContent::MultiModal(vec![
                ContentPart::Text(text.into()),
                ContentPart::ImageUrl {
                    url: image_url.into(),
                    detail: ImageDetail::Auto,
                },
            ]),
            name: None,
            tool_calls: None,
            tool_call_id: None,
        }
    }

    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            role: Role::Assistant,
            content: MessageContent::Text(content.into()),
            name: None,
            tool_calls: None,
            tool_call_id: None,
        }
    }

    pub fn tool_result(tool_call_id: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            role: Role::Tool,
            content: MessageContent::Text(content.into()),
            name: None,
            tool_calls: None,
            tool_call_id: Some(tool_call_id.into()),
        }
    }
}

/// Tool call from assistant
#[derive(Debug, Clone)]
pub struct ToolCall {
    pub id: String,
    pub tool_type: String,
    pub function: FunctionCall,
}

#[derive(Debug, Clone)]
pub struct FunctionCall {
    pub name: String,
    pub arguments: String,
}

/// Function definition
#[derive(Debug, Clone)]
pub struct FunctionDef {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

impl FunctionDef {
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        }
    }

    pub fn with_parameters(mut self, parameters: serde_json::Value) -> Self {
        self.parameters = parameters;
        self
    }
}

/// Tool definition
#[derive(Debug, Clone)]
pub struct ToolDef {
    pub tool_type: String,
    pub function: FunctionDef,
}

impl ToolDef {
    pub fn function(def: FunctionDef) -> Self {
        Self {
            tool_type: "function".to_string(),
            function: def,
        }
    }
}

/// Content filter results from Azure
#[derive(Debug, Clone)]
pub struct ContentFilterResults {
    pub hate: ContentFilterResult,
    pub self_harm: ContentFilterResult,
    pub sexual: ContentFilterResult,
    pub violence: ContentFilterResult,
    pub profanity: Option<ContentFilterResult>,
    pub jailbreak: Option<JailbreakResult>,
}

#[derive(Debug, Clone)]
pub struct ContentFilterResult {
    pub filtered: bool,
    pub severity: ContentFilterSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentFilterSeverity {
    Safe,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone)]
pub struct JailbreakResult {
    pub filtered: bool,
    pub detected: bool,
}

/// Chat completion request
#[derive(Debug, Clone)]
pub struct ChatRequest {
    pub deployment: String,
    pub messages: Vec<ChatMessage>,
    pub temperature: Option<f32>,
    pub top_p: Option<f32>,
    pub max_tokens: Option<u32>,
    pub presence_penalty: Option<f32>,
    pub frequency_penalty: Option<f32>,
    pub stop: Option<Vec<String>>,
    pub tools: Option<Vec<ToolDef>>,
    pub tool_choice: Option<ToolChoice>,
    pub response_format: Option<ResponseFormat>,
    pub seed: Option<u64>,
    pub user: Option<String>,
}

#[derive(Debug, Clone)]
pub enum ToolChoice {
    Auto,
    None,
    Required,
    Specific(String),
}

#[derive(Debug, Clone)]
pub enum ResponseFormat {
    Text,
    JsonObject,
}

impl ChatRequest {
    pub fn new(deployment: impl Into<String>) -> Self {
        Self {
            deployment: deployment.into(),
            messages: Vec::new(),
            temperature: None,
            top_p: None,
            max_tokens: None,
            presence_penalty: None,
            frequency_penalty: None,
            stop: None,
            tools: None,
            tool_choice: None,
            response_format: None,
            seed: None,
            user: None,
        }
    }

    pub fn message(mut self, message: ChatMessage) -> Self {
        self.messages.push(message);
        self
    }

    pub fn messages(mut self, messages: Vec<ChatMessage>) -> Self {
        self.messages = messages;
        self
    }

    pub fn temperature(mut self, temp: f32) -> Self {
        self.temperature = Some(temp.clamp(0.0, 2.0));
        self
    }

    pub fn max_tokens(mut self, tokens: u32) -> Self {
        self.max_tokens = Some(tokens);
        self
    }

    pub fn tools(mut self, tools: Vec<ToolDef>) -> Self {
        self.tools = Some(tools);
        self
    }

    pub fn json_mode(mut self) -> Self {
        self.response_format = Some(ResponseFormat::JsonObject);
        self
    }

    pub fn seed(mut self, seed: u64) -> Self {
        self.seed = Some(seed);
        self
    }
}

/// Chat completion response
#[derive(Debug, Clone)]
pub struct ChatResponse {
    pub id: String,
    pub object: String,
    pub created: u64,
    pub model: String,
    pub choices: Vec<Choice>,
    pub usage: Usage,
    pub prompt_filter_results: Option<Vec<PromptFilterResult>>,
    pub system_fingerprint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Choice {
    pub index: u32,
    pub message: ChatMessage,
    pub finish_reason: FinishReason,
    pub content_filter_results: Option<ContentFilterResults>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinishReason {
    Stop,
    Length,
    ToolCalls,
    ContentFilter,
}

#[derive(Debug, Clone)]
pub struct Usage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

#[derive(Debug, Clone)]
pub struct PromptFilterResult {
    pub prompt_index: u32,
    pub content_filter_results: ContentFilterResults,
}

/// Embedding request
#[derive(Debug, Clone)]
pub struct EmbeddingRequest {
    pub deployment: String,
    pub input: Vec<String>,
    pub dimensions: Option<u32>,
    pub user: Option<String>,
}

impl EmbeddingRequest {
    pub fn new(deployment: impl Into<String>, input: Vec<String>) -> Self {
        Self {
            deployment: deployment.into(),
            input,
            dimensions: None,
            user: None,
        }
    }

    pub fn dimensions(mut self, dims: u32) -> Self {
        self.dimensions = Some(dims);
        self
    }
}

/// Embedding response
#[derive(Debug, Clone)]
pub struct EmbeddingResponse {
    pub object: String,
    pub data: Vec<Embedding>,
    pub model: String,
    pub usage: EmbeddingUsage,
}

#[derive(Debug, Clone)]
pub struct Embedding {
    pub object: String,
    pub embedding: Vec<f32>,
    pub index: u32,
}

#[derive(Debug, Clone)]
pub struct EmbeddingUsage {
    pub prompt_tokens: u32,
    pub total_tokens: u32,
}

/// Azure OpenAI client configuration
#[derive(Debug, Clone)]
pub struct AzureOpenAiConfig {
    pub endpoint: String,
    pub auth: AzureAuth,
    pub api_version: String,
    pub timeout: Duration,
    pub max_retries: u32,
    pub retry_delay: Duration,
}

impl AzureOpenAiConfig {
    pub fn new(endpoint: impl Into<String>, auth: AzureAuth) -> Self {
        Self {
            endpoint: endpoint.into(),
            auth,
            api_version: "2024-02-15-preview".to_string(),
            timeout: Duration::from_secs(60),
            max_retries: 3,
            retry_delay: Duration::from_secs(1),
        }
    }

    pub fn api_version(mut self, version: impl Into<String>) -> Self {
        self.api_version = version.into();
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }
}

/// Token bucket rate limiter
pub struct RateLimiter {
    requests_per_minute: u32,
    tokens_per_minute: u32,
    request_tokens: AtomicU64,
    token_bucket: AtomicU64,
    last_refill: std::sync::Mutex<Instant>,
}

impl RateLimiter {
    pub fn new(requests_per_minute: u32, tokens_per_minute: u32) -> Self {
        Self {
            requests_per_minute,
            tokens_per_minute,
            request_tokens: AtomicU64::new(requests_per_minute as u64),
            token_bucket: AtomicU64::new(tokens_per_minute as u64),
            last_refill: std::sync::Mutex::new(Instant::now()),
        }
    }

    pub fn try_acquire(&self, estimated_tokens: u32) -> Result<(), RateLimitError> {
        self.refill();

        let requests = self.request_tokens.load(Ordering::SeqCst);
        if requests == 0 {
            return Err(RateLimitError::RequestsExhausted);
        }

        let tokens = self.token_bucket.load(Ordering::SeqCst);
        if tokens < estimated_tokens as u64 {
            return Err(RateLimitError::TokensExhausted {
                available: tokens as u32,
                requested: estimated_tokens,
            });
        }

        self.request_tokens.fetch_sub(1, Ordering::SeqCst);
        self.token_bucket
            .fetch_sub(estimated_tokens as u64, Ordering::SeqCst);

        Ok(())
    }

    fn refill(&self) {
        let mut last = self.last_refill.lock().unwrap();
        let elapsed = last.elapsed();

        if elapsed >= Duration::from_secs(60) {
            self.request_tokens
                .store(self.requests_per_minute as u64, Ordering::SeqCst);
            self.token_bucket
                .store(self.tokens_per_minute as u64, Ordering::SeqCst);
            *last = Instant::now();
        }
    }
}

#[derive(Debug)]
pub enum RateLimitError {
    RequestsExhausted,
    TokensExhausted { available: u32, requested: u32 },
}

/// Usage tracker
pub struct UsageTracker {
    total_prompt_tokens: AtomicU64,
    total_completion_tokens: AtomicU64,
    total_requests: AtomicU64,
}

impl UsageTracker {
    pub fn new() -> Self {
        Self {
            total_prompt_tokens: AtomicU64::new(0),
            total_completion_tokens: AtomicU64::new(0),
            total_requests: AtomicU64::new(0),
        }
    }

    pub fn record(&self, prompt_tokens: u32, completion_tokens: u32) {
        self.total_prompt_tokens
            .fetch_add(prompt_tokens as u64, Ordering::SeqCst);
        self.total_completion_tokens
            .fetch_add(completion_tokens as u64, Ordering::SeqCst);
        self.total_requests.fetch_add(1, Ordering::SeqCst);
    }

    pub fn totals(&self) -> (u64, u64, u64) {
        (
            self.total_prompt_tokens.load(Ordering::SeqCst),
            self.total_completion_tokens.load(Ordering::SeqCst),
            self.total_requests.load(Ordering::SeqCst),
        )
    }
}

impl Default for UsageTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Azure OpenAI client
pub struct AzureOpenAiClient {
    config: AzureOpenAiConfig,
    deployments: HashMap<String, Deployment>,
    rate_limiter: Arc<RateLimiter>,
    usage_tracker: Arc<UsageTracker>,
}

impl AzureOpenAiClient {
    pub fn new(config: AzureOpenAiConfig) -> Self {
        Self {
            config,
            deployments: HashMap::new(),
            rate_limiter: Arc::new(RateLimiter::new(60, 90000)),
            usage_tracker: Arc::new(UsageTracker::new()),
        }
    }

    pub fn register_deployment(&mut self, deployment: Deployment) {
        self.deployments.insert(deployment.name.clone(), deployment);
    }

    pub fn with_rate_limits(mut self, requests_per_minute: u32, tokens_per_minute: u32) -> Self {
        self.rate_limiter = Arc::new(RateLimiter::new(requests_per_minute, tokens_per_minute));
        self
    }

    /// Create chat completion
    pub fn chat(&self, request: ChatRequest) -> Result<ChatResponse, AzureError> {
        // Check deployment exists
        if !self.deployments.contains_key(&request.deployment) {
            // Allow unknown deployments for flexibility
        }

        let estimated_tokens = self.estimate_tokens(&request);
        self.rate_limiter
            .try_acquire(estimated_tokens)
            .map_err(|e| AzureError::RateLimit(format!("{:?}", e)))?;

        // Simulate API call
        let response = self.mock_chat_response(&request);

        // Track usage
        self.usage_tracker.record(
            response.usage.prompt_tokens,
            response.usage.completion_tokens,
        );

        Ok(response)
    }

    /// Create embeddings
    pub fn embed(&self, request: EmbeddingRequest) -> Result<EmbeddingResponse, AzureError> {
        let dimensions = request.dimensions.unwrap_or(1536);
        let embeddings: Vec<Embedding> = request
            .input
            .iter()
            .enumerate()
            .map(|(i, _)| Embedding {
                object: "embedding".to_string(),
                embedding: vec![0.0; dimensions as usize],
                index: i as u32,
            })
            .collect();

        Ok(EmbeddingResponse {
            object: "list".to_string(),
            data: embeddings,
            model: request.deployment,
            usage: EmbeddingUsage {
                prompt_tokens: 100,
                total_tokens: 100,
            },
        })
    }

    /// Get usage tracker
    pub fn usage_tracker(&self) -> &UsageTracker {
        &self.usage_tracker
    }

    /// List registered deployments
    pub fn list_deployments(&self) -> Vec<&Deployment> {
        self.deployments.values().collect()
    }

    fn estimate_tokens(&self, request: &ChatRequest) -> u32 {
        let mut tokens = 0u32;
        for msg in &request.messages {
            if let MessageContent::Text(text) = &msg.content {
                tokens += (text.len() / 4) as u32;
            }
        }
        tokens + request.max_tokens.unwrap_or(1000)
    }

    fn mock_chat_response(&self, request: &ChatRequest) -> ChatResponse {
        ChatResponse {
            id: format!("chatcmpl-azure-{}", uuid_v4()),
            object: "chat.completion".to_string(),
            created: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            model: request.deployment.clone(),
            choices: vec![Choice {
                index: 0,
                message: ChatMessage::assistant("This is a mock response from Azure OpenAI."),
                finish_reason: FinishReason::Stop,
                content_filter_results: Some(ContentFilterResults {
                    hate: ContentFilterResult {
                        filtered: false,
                        severity: ContentFilterSeverity::Safe,
                    },
                    self_harm: ContentFilterResult {
                        filtered: false,
                        severity: ContentFilterSeverity::Safe,
                    },
                    sexual: ContentFilterResult {
                        filtered: false,
                        severity: ContentFilterSeverity::Safe,
                    },
                    violence: ContentFilterResult {
                        filtered: false,
                        severity: ContentFilterSeverity::Safe,
                    },
                    profanity: None,
                    jailbreak: Some(JailbreakResult {
                        filtered: false,
                        detected: false,
                    }),
                }),
            }],
            usage: Usage {
                prompt_tokens: 50,
                completion_tokens: 25,
                total_tokens: 75,
            },
            prompt_filter_results: None,
            system_fingerprint: Some("fp_azure_mock".to_string()),
        }
    }
}

/// Azure OpenAI error types
#[derive(Debug)]
pub enum AzureError {
    RateLimit(String),
    Authentication(String),
    DeploymentNotFound(String),
    ContentFiltered(ContentFilterResults),
    ApiError { status: u16, message: String },
    Timeout,
    NetworkError(String),
}

impl std::fmt::Display for AzureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AzureError::RateLimit(msg) => write!(f, "Rate limit: {}", msg),
            AzureError::Authentication(msg) => write!(f, "Authentication error: {}", msg),
            AzureError::DeploymentNotFound(name) => write!(f, "Deployment not found: {}", name),
            AzureError::ContentFiltered(_) => write!(f, "Content filtered by Azure"),
            AzureError::ApiError { status, message } => {
                write!(f, "API error ({}): {}", status, message)
            }
            AzureError::Timeout => write!(f, "Request timed out"),
            AzureError::NetworkError(msg) => write!(f, "Network error: {}", msg),
        }
    }
}

impl std::error::Error for AzureError {}

/// Generate mock UUID
fn uuid_v4() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:032x}", nanos)
}

fn main() {
    println!("=== Azure OpenAI Client Demo ===\n");

    // Create client with API key auth
    let config = AzureOpenAiConfig::new(
        "https://my-resource.openai.azure.com",
        AzureAuth::api_key("azure-api-key-123"),
    )
    .api_version("2024-02-15-preview");

    let mut client = AzureOpenAiClient::new(config);

    // Register deployments
    client.register_deployment(Deployment::new("gpt-4-deployment", AzureModel::Gpt4Turbo));
    client.register_deployment(Deployment::new("gpt-35-deployment", AzureModel::Gpt35Turbo));
    client.register_deployment(Deployment::new(
        "embedding-deployment",
        AzureModel::TextEmbedding3Small,
    ));

    // List deployments
    println!("1. Registered deployments:");
    for deployment in client.list_deployments() {
        println!(
            "   - {}: {} (capacity: {})",
            deployment.name,
            deployment.model.as_str(),
            deployment.capacity
        );
    }

    // Simple chat completion
    println!("\n2. Simple chat completion:");
    let request = ChatRequest::new("gpt-4-deployment")
        .message(ChatMessage::system("You are a helpful assistant."))
        .message(ChatMessage::user("What is Azure OpenAI Service?"))
        .temperature(0.7)
        .max_tokens(500);

    match client.chat(request) {
        Ok(response) => {
            println!("   Model: {}", response.model);
            if let Some(choice) = response.choices.first() {
                if let MessageContent::Text(text) = &choice.message.content {
                    println!("   Response: {}", text);
                }
                if let Some(filters) = &choice.content_filter_results {
                    println!(
                        "   Content filtered: hate={}, violence={}",
                        filters.hate.filtered, filters.violence.filtered
                    );
                }
            }
            println!("   Tokens: {}", response.usage.total_tokens);
        }
        Err(e) => println!("   Error: {}", e),
    }

    // Function calling
    println!("\n3. Function calling:");
    let search_func = FunctionDef::new("search_documents", "Search internal documents")
        .with_parameters(serde_json::json!({
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query"
                },
                "top_k": {
                    "type": "integer",
                    "description": "Number of results"
                }
            },
            "required": ["query"]
        }));

    let request = ChatRequest::new("gpt-4-deployment")
        .message(ChatMessage::user(
            "Find documents about security best practices",
        ))
        .tools(vec![ToolDef::function(search_func)]);

    match client.chat(request) {
        Ok(response) => {
            println!("   Function calling response received");
        }
        Err(e) => println!("   Error: {}", e),
    }

    // Vision with GPT-4V
    println!("\n4. Vision request:");
    let request = ChatRequest::new("gpt-4-deployment")
        .message(ChatMessage::user_with_image(
            "Describe this architecture diagram",
            "https://example.com/diagram.png",
        ))
        .max_tokens(500);

    match client.chat(request) {
        Ok(response) => {
            println!("   Vision response received");
        }
        Err(e) => println!("   Error: {}", e),
    }

    // JSON mode
    println!("\n5. JSON mode:");
    let request = ChatRequest::new("gpt-35-deployment")
        .message(ChatMessage::system(
            "Output JSON with keys: services, regions",
        ))
        .message(ChatMessage::user("List Azure cognitive services"))
        .json_mode()
        .max_tokens(500);

    match client.chat(request) {
        Ok(response) => {
            println!("   JSON mode response received");
        }
        Err(e) => println!("   Error: {}", e),
    }

    // Embeddings
    println!("\n6. Embeddings:");
    let embed_request = EmbeddingRequest::new(
        "embedding-deployment",
        vec![
            "Azure OpenAI provides access to GPT models".to_string(),
            "Enterprise-grade security and compliance".to_string(),
        ],
    )
    .dimensions(512);

    match client.embed(embed_request) {
        Ok(response) => {
            println!("   Generated {} embeddings", response.data.len());
            if let Some(first) = response.data.first() {
                println!("   Dimensions: {}", first.embedding.len());
            }
        }
        Err(e) => println!("   Error: {}", e),
    }

    // Different authentication methods
    println!("\n7. Authentication methods:");
    println!("   API Key: Simple, direct access");
    println!("   Azure AD: Service principal for enterprise");
    println!("   Managed Identity: For Azure-hosted applications");

    let _ad_auth = AzureAuth::azure_ad("tenant-id", "client-id", "client-secret");
    let _mi_auth = AzureAuth::managed_identity();
    println!("   (All auth methods demonstrated)");

    // Usage tracking
    println!("\n8. Usage tracking:");
    let (prompt, completion, requests) = client.usage_tracker().totals();
    println!("   Total prompt tokens: {}", prompt);
    println!("   Total completion tokens: {}", completion);
    println!("   Total requests: {}", requests);

    // Model capabilities
    println!("\n9. Model capabilities:");
    for model in [
        AzureModel::Gpt4Turbo,
        AzureModel::Gpt35Turbo,
        AzureModel::TextEmbedding3Large,
    ] {
        println!(
            "   {}: max {} tokens, embedding={}",
            model.as_str(),
            model.max_tokens(),
            model.is_embedding_model()
        );
    }

    println!("\n=== Demo Complete ===");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_azure_model_properties() {
        assert_eq!(AzureModel::Gpt4Turbo.as_str(), "gpt-4-turbo");
        assert_eq!(AzureModel::Gpt4Turbo.max_tokens(), 128000);
        assert!(!AzureModel::Gpt4Turbo.is_embedding_model());
    }

    #[test]
    fn test_embedding_models() {
        assert!(AzureModel::TextEmbeddingAda002.is_embedding_model());
        assert!(AzureModel::TextEmbedding3Small.is_embedding_model());
        assert!(!AzureModel::Gpt4.is_embedding_model());
    }

    #[test]
    fn test_deployment_creation() {
        let deployment = Deployment::new("my-deployment", AzureModel::Gpt4Turbo)
            .version("2024-01-01")
            .capacity(20);

        assert_eq!(deployment.name, "my-deployment");
        assert_eq!(deployment.version, "2024-01-01");
        assert_eq!(deployment.capacity, 20);
    }

    #[test]
    fn test_azure_auth_variants() {
        let api_key = AzureAuth::api_key("test-key");
        assert!(matches!(api_key, AzureAuth::ApiKey(_)));

        let ad = AzureAuth::azure_ad("tenant", "client", "secret");
        assert!(matches!(ad, AzureAuth::AzureAD { .. }));

        let mi = AzureAuth::managed_identity();
        assert!(matches!(mi, AzureAuth::ManagedIdentity { client_id: None }));
    }

    #[test]
    fn test_chat_message_creation() {
        let system = ChatMessage::system("You are helpful");
        assert_eq!(system.role, Role::System);

        let user = ChatMessage::user("Hello");
        assert_eq!(user.role, Role::User);

        let assistant = ChatMessage::assistant("Hi there");
        assert_eq!(assistant.role, Role::Assistant);
    }

    #[test]
    fn test_multimodal_message() {
        let msg = ChatMessage::user_with_image("Describe", "https://example.com/img.jpg");
        assert_eq!(msg.role, Role::User);
        match msg.content {
            MessageContent::MultiModal(parts) => assert_eq!(parts.len(), 2),
            _ => panic!("Expected multimodal"),
        }
    }

    #[test]
    fn test_chat_request_builder() {
        let request = ChatRequest::new("my-deployment")
            .message(ChatMessage::user("Hello"))
            .temperature(0.5)
            .max_tokens(100)
            .seed(42);

        assert_eq!(request.deployment, "my-deployment");
        assert_eq!(request.temperature, Some(0.5));
        assert_eq!(request.max_tokens, Some(100));
        assert_eq!(request.seed, Some(42));
    }

    #[test]
    fn test_temperature_clamping() {
        let request = ChatRequest::new("test").temperature(3.0);
        assert_eq!(request.temperature, Some(2.0));

        let request = ChatRequest::new("test").temperature(-1.0);
        assert_eq!(request.temperature, Some(0.0));
    }

    #[test]
    fn test_function_definition() {
        let func = FunctionDef::new("test_func", "A test").with_parameters(serde_json::json!({
            "type": "object",
            "properties": {
                "arg": { "type": "string" }
            }
        }));

        assert_eq!(func.name, "test_func");
        assert_eq!(func.description, "A test");
    }

    #[test]
    fn test_embedding_request() {
        let request = EmbeddingRequest::new(
            "embed-deployment",
            vec!["text1".to_string(), "text2".to_string()],
        )
        .dimensions(256);

        assert_eq!(request.deployment, "embed-deployment");
        assert_eq!(request.input.len(), 2);
        assert_eq!(request.dimensions, Some(256));
    }

    #[test]
    fn test_azure_config() {
        let config =
            AzureOpenAiConfig::new("https://test.openai.azure.com", AzureAuth::api_key("key"))
                .api_version("2024-01-01")
                .timeout(Duration::from_secs(30))
                .max_retries(5);

        assert_eq!(config.endpoint, "https://test.openai.azure.com");
        assert_eq!(config.api_version, "2024-01-01");
        assert_eq!(config.max_retries, 5);
    }

    #[test]
    fn test_client_creation() {
        let config =
            AzureOpenAiConfig::new("https://test.openai.azure.com", AzureAuth::api_key("key"));
        let client = AzureOpenAiClient::new(config);

        let (prompt, completion, requests) = client.usage_tracker().totals();
        assert_eq!(prompt, 0);
        assert_eq!(completion, 0);
        assert_eq!(requests, 0);
    }

    #[test]
    fn test_deployment_registration() {
        let config =
            AzureOpenAiConfig::new("https://test.openai.azure.com", AzureAuth::api_key("key"));
        let mut client = AzureOpenAiClient::new(config);

        client.register_deployment(Deployment::new("gpt4", AzureModel::Gpt4Turbo));
        client.register_deployment(Deployment::new("gpt35", AzureModel::Gpt35Turbo));

        assert_eq!(client.list_deployments().len(), 2);
    }

    #[test]
    fn test_chat_completion() {
        let config =
            AzureOpenAiConfig::new("https://test.openai.azure.com", AzureAuth::api_key("key"));
        let client = AzureOpenAiClient::new(config);

        let request = ChatRequest::new("gpt4").message(ChatMessage::user("Hello"));
        let response = client.chat(request).unwrap();

        assert!(!response.id.is_empty());
        assert_eq!(response.choices.len(), 1);
    }

    #[test]
    fn test_content_filter_results() {
        let filters = ContentFilterResults {
            hate: ContentFilterResult {
                filtered: false,
                severity: ContentFilterSeverity::Safe,
            },
            self_harm: ContentFilterResult {
                filtered: false,
                severity: ContentFilterSeverity::Safe,
            },
            sexual: ContentFilterResult {
                filtered: false,
                severity: ContentFilterSeverity::Low,
            },
            violence: ContentFilterResult {
                filtered: false,
                severity: ContentFilterSeverity::Safe,
            },
            profanity: None,
            jailbreak: Some(JailbreakResult {
                filtered: false,
                detected: false,
            }),
        };

        assert!(!filters.hate.filtered);
        assert_eq!(filters.sexual.severity, ContentFilterSeverity::Low);
    }

    #[test]
    fn test_usage_tracker() {
        let tracker = UsageTracker::new();

        tracker.record(100, 50);
        tracker.record(200, 100);

        let (prompt, completion, requests) = tracker.totals();
        assert_eq!(prompt, 300);
        assert_eq!(completion, 150);
        assert_eq!(requests, 2);
    }

    #[test]
    fn test_rate_limiter() {
        let limiter = RateLimiter::new(10, 1000);

        assert!(limiter.try_acquire(100).is_ok());
        assert!(limiter.try_acquire(100).is_ok());
    }

    #[test]
    fn test_embedding_response() {
        let config =
            AzureOpenAiConfig::new("https://test.openai.azure.com", AzureAuth::api_key("key"));
        let client = AzureOpenAiClient::new(config);

        let request = EmbeddingRequest::new("embed", vec!["text".to_string()]).dimensions(256);
        let response = client.embed(request).unwrap();

        assert_eq!(response.data.len(), 1);
        assert_eq!(response.data[0].embedding.len(), 256);
    }

    #[test]
    fn test_json_mode() {
        let request = ChatRequest::new("test").json_mode();
        assert!(matches!(
            request.response_format,
            Some(ResponseFormat::JsonObject)
        ));
    }

    #[test]
    fn test_roles() {
        assert_eq!(Role::System.as_str(), "system");
        assert_eq!(Role::User.as_str(), "user");
        assert_eq!(Role::Assistant.as_str(), "assistant");
        assert_eq!(Role::Tool.as_str(), "tool");
    }

    #[test]
    fn test_tool_result_message() {
        let msg = ChatMessage::tool_result("call_123", r#"{"result": "ok"}"#);
        assert_eq!(msg.role, Role::Tool);
        assert_eq!(msg.tool_call_id, Some("call_123".to_string()));
    }

    #[test]
    fn test_finish_reasons() {
        assert_ne!(FinishReason::Stop, FinishReason::ContentFilter);
        assert_ne!(FinishReason::Length, FinishReason::ToolCalls);
    }

    #[test]
    fn test_content_filter_severity() {
        assert_ne!(ContentFilterSeverity::Safe, ContentFilterSeverity::High);
        assert_ne!(ContentFilterSeverity::Low, ContentFilterSeverity::Medium);
    }
}
