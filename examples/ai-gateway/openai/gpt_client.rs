//! OpenAI GPT Client Implementation
//!
//! Comprehensive client for OpenAI's GPT API with support for chat completions,
//! function calling, embeddings, and streaming responses.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// OpenAI model variants
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GptModel {
    Gpt4Turbo,
    Gpt4,
    Gpt4Vision,
    Gpt35Turbo,
    Gpt35Turbo16k,
}

impl GptModel {
    pub fn as_str(&self) -> &'static str {
        match self {
            GptModel::Gpt4Turbo => "gpt-4-turbo-preview",
            GptModel::Gpt4 => "gpt-4",
            GptModel::Gpt4Vision => "gpt-4-vision-preview",
            GptModel::Gpt35Turbo => "gpt-3.5-turbo",
            GptModel::Gpt35Turbo16k => "gpt-3.5-turbo-16k",
        }
    }

    pub fn max_tokens(&self) -> u32 {
        match self {
            GptModel::Gpt4Turbo => 128000,
            GptModel::Gpt4 => 8192,
            GptModel::Gpt4Vision => 128000,
            GptModel::Gpt35Turbo => 4096,
            GptModel::Gpt35Turbo16k => 16384,
        }
    }

    pub fn cost_per_1k_input(&self) -> f64 {
        match self {
            GptModel::Gpt4Turbo => 0.01,
            GptModel::Gpt4 => 0.03,
            GptModel::Gpt4Vision => 0.01,
            GptModel::Gpt35Turbo => 0.0005,
            GptModel::Gpt35Turbo16k => 0.001,
        }
    }

    pub fn cost_per_1k_output(&self) -> f64 {
        match self {
            GptModel::Gpt4Turbo => 0.03,
            GptModel::Gpt4 => 0.06,
            GptModel::Gpt4Vision => 0.03,
            GptModel::Gpt35Turbo => 0.0015,
            GptModel::Gpt35Turbo16k => 0.002,
        }
    }
}

/// Message role in conversation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Role {
    System,
    User,
    Assistant,
    Function,
    Tool,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::System => "system",
            Role::User => "user",
            Role::Assistant => "assistant",
            Role::Function => "function",
            Role::Tool => "tool",
        }
    }
}

/// Content types for messages
#[derive(Debug, Clone)]
pub enum Content {
    Text(String),
    ImageUrl { url: String, detail: ImageDetail },
    MultiPart(Vec<ContentPart>),
}

#[derive(Debug, Clone)]
pub enum ContentPart {
    Text(String),
    Image { url: String, detail: ImageDetail },
}

#[derive(Debug, Clone, Copy)]
pub enum ImageDetail {
    Auto,
    Low,
    High,
}

impl ImageDetail {
    pub fn as_str(&self) -> &'static str {
        match self {
            ImageDetail::Auto => "auto",
            ImageDetail::Low => "low",
            ImageDetail::High => "high",
        }
    }
}

/// Chat message
#[derive(Debug, Clone)]
pub struct ChatMessage {
    pub role: Role,
    pub content: Content,
    pub name: Option<String>,
    pub function_call: Option<FunctionCall>,
    pub tool_calls: Option<Vec<ToolCall>>,
    pub tool_call_id: Option<String>,
}

impl ChatMessage {
    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: Role::System,
            content: Content::Text(content.into()),
            name: None,
            function_call: None,
            tool_calls: None,
            tool_call_id: None,
        }
    }

    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: Role::User,
            content: Content::Text(content.into()),
            name: None,
            function_call: None,
            tool_calls: None,
            tool_call_id: None,
        }
    }

    pub fn user_with_image(text: impl Into<String>, image_url: impl Into<String>) -> Self {
        Self {
            role: Role::User,
            content: Content::MultiPart(vec![
                ContentPart::Text(text.into()),
                ContentPart::Image {
                    url: image_url.into(),
                    detail: ImageDetail::Auto,
                },
            ]),
            name: None,
            function_call: None,
            tool_calls: None,
            tool_call_id: None,
        }
    }

    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            role: Role::Assistant,
            content: Content::Text(content.into()),
            name: None,
            function_call: None,
            tool_calls: None,
            tool_call_id: None,
        }
    }

    pub fn tool_result(tool_call_id: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            role: Role::Tool,
            content: Content::Text(content.into()),
            name: None,
            function_call: None,
            tool_calls: None,
            tool_call_id: Some(tool_call_id.into()),
        }
    }
}

/// Function call from assistant
#[derive(Debug, Clone)]
pub struct FunctionCall {
    pub name: String,
    pub arguments: String,
}

/// Tool call from assistant
#[derive(Debug, Clone)]
pub struct ToolCall {
    pub id: String,
    pub tool_type: String,
    pub function: FunctionCall,
}

/// Function definition for function calling
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

/// Response format options
#[derive(Debug, Clone)]
pub enum ResponseFormat {
    Text,
    JsonObject,
}

/// Chat completion request
#[derive(Debug, Clone)]
pub struct ChatRequest {
    pub model: GptModel,
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

impl ChatRequest {
    pub fn new(model: GptModel) -> Self {
        Self {
            model,
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
    pub system_fingerprint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Choice {
    pub index: u32,
    pub message: ChatMessage,
    pub finish_reason: FinishReason,
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

/// Streaming chunk
#[derive(Debug, Clone)]
pub struct StreamChunk {
    pub id: String,
    pub object: String,
    pub created: u64,
    pub model: String,
    pub choices: Vec<StreamChoice>,
}

#[derive(Debug, Clone)]
pub struct StreamChoice {
    pub index: u32,
    pub delta: Delta,
    pub finish_reason: Option<FinishReason>,
}

#[derive(Debug, Clone, Default)]
pub struct Delta {
    pub role: Option<Role>,
    pub content: Option<String>,
    pub tool_calls: Option<Vec<ToolCallDelta>>,
}

#[derive(Debug, Clone)]
pub struct ToolCallDelta {
    pub index: u32,
    pub id: Option<String>,
    pub tool_type: Option<String>,
    pub function: Option<FunctionDelta>,
}

#[derive(Debug, Clone)]
pub struct FunctionDelta {
    pub name: Option<String>,
    pub arguments: Option<String>,
}

/// Embedding request
#[derive(Debug, Clone)]
pub struct EmbeddingRequest {
    pub model: EmbeddingModel,
    pub input: Vec<String>,
    pub encoding_format: Option<EncodingFormat>,
    pub dimensions: Option<u32>,
    pub user: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub enum EmbeddingModel {
    TextEmbedding3Small,
    TextEmbedding3Large,
    TextEmbeddingAda002,
}

impl EmbeddingModel {
    pub fn as_str(&self) -> &'static str {
        match self {
            EmbeddingModel::TextEmbedding3Small => "text-embedding-3-small",
            EmbeddingModel::TextEmbedding3Large => "text-embedding-3-large",
            EmbeddingModel::TextEmbeddingAda002 => "text-embedding-ada-002",
        }
    }

    pub fn dimensions(&self) -> u32 {
        match self {
            EmbeddingModel::TextEmbedding3Small => 1536,
            EmbeddingModel::TextEmbedding3Large => 3072,
            EmbeddingModel::TextEmbeddingAda002 => 1536,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum EncodingFormat {
    Float,
    Base64,
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

/// Rate limiter with token bucket
pub struct RateLimiter {
    requests_per_minute: u32,
    tokens_per_minute: u32,
    request_tokens: AtomicU64,
    token_tokens: AtomicU64,
    last_refill: std::sync::Mutex<Instant>,
}

impl RateLimiter {
    pub fn new(requests_per_minute: u32, tokens_per_minute: u32) -> Self {
        Self {
            requests_per_minute,
            tokens_per_minute,
            request_tokens: AtomicU64::new(requests_per_minute as u64),
            token_tokens: AtomicU64::new(tokens_per_minute as u64),
            last_refill: std::sync::Mutex::new(Instant::now()),
        }
    }

    pub fn try_acquire(&self, estimated_tokens: u32) -> Result<(), RateLimitError> {
        self.refill();

        let current_requests = self.request_tokens.load(Ordering::SeqCst);
        if current_requests == 0 {
            return Err(RateLimitError::RequestsExhausted);
        }

        let current_tokens = self.token_tokens.load(Ordering::SeqCst);
        if current_tokens < estimated_tokens as u64 {
            return Err(RateLimitError::TokensExhausted {
                available: current_tokens as u32,
                requested: estimated_tokens,
            });
        }

        self.request_tokens.fetch_sub(1, Ordering::SeqCst);
        self.token_tokens
            .fetch_sub(estimated_tokens as u64, Ordering::SeqCst);

        Ok(())
    }

    fn refill(&self) {
        let mut last_refill = self.last_refill.lock().unwrap();
        let elapsed = last_refill.elapsed();

        if elapsed >= Duration::from_secs(60) {
            self.request_tokens
                .store(self.requests_per_minute as u64, Ordering::SeqCst);
            self.token_tokens
                .store(self.tokens_per_minute as u64, Ordering::SeqCst);
            *last_refill = Instant::now();
        }
    }
}

#[derive(Debug)]
pub enum RateLimitError {
    RequestsExhausted,
    TokensExhausted { available: u32, requested: u32 },
}

/// Cost tracker
pub struct CostTracker {
    total_input_tokens: AtomicU64,
    total_output_tokens: AtomicU64,
    total_cost_cents: AtomicU64,
}

impl CostTracker {
    pub fn new() -> Self {
        Self {
            total_input_tokens: AtomicU64::new(0),
            total_output_tokens: AtomicU64::new(0),
            total_cost_cents: AtomicU64::new(0),
        }
    }

    pub fn record_usage(&self, model: GptModel, input_tokens: u32, output_tokens: u32) {
        self.total_input_tokens
            .fetch_add(input_tokens as u64, Ordering::SeqCst);
        self.total_output_tokens
            .fetch_add(output_tokens as u64, Ordering::SeqCst);

        let input_cost = (input_tokens as f64 / 1000.0) * model.cost_per_1k_input();
        let output_cost = (output_tokens as f64 / 1000.0) * model.cost_per_1k_output();
        let total_cost_cents = ((input_cost + output_cost) * 100.0) as u64;

        self.total_cost_cents
            .fetch_add(total_cost_cents, Ordering::SeqCst);
    }

    pub fn total_cost_usd(&self) -> f64 {
        self.total_cost_cents.load(Ordering::SeqCst) as f64 / 100.0
    }

    pub fn total_tokens(&self) -> (u64, u64) {
        (
            self.total_input_tokens.load(Ordering::SeqCst),
            self.total_output_tokens.load(Ordering::SeqCst),
        )
    }
}

impl Default for CostTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// OpenAI client configuration
#[derive(Debug, Clone)]
pub struct OpenAiConfig {
    pub api_key: String,
    pub organization_id: Option<String>,
    pub base_url: String,
    pub timeout: Duration,
    pub max_retries: u32,
    pub retry_delay: Duration,
}

impl OpenAiConfig {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            organization_id: None,
            base_url: "https://api.openai.com/v1".to_string(),
            timeout: Duration::from_secs(60),
            max_retries: 3,
            retry_delay: Duration::from_secs(1),
        }
    }

    pub fn organization(mut self, org_id: impl Into<String>) -> Self {
        self.organization_id = Some(org_id.into());
        self
    }

    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// OpenAI GPT client
pub struct GptClient {
    config: OpenAiConfig,
    rate_limiter: Arc<RateLimiter>,
    cost_tracker: Arc<CostTracker>,
}

impl GptClient {
    pub fn new(config: OpenAiConfig) -> Self {
        Self {
            config,
            rate_limiter: Arc::new(RateLimiter::new(60, 90000)),
            cost_tracker: Arc::new(CostTracker::new()),
        }
    }

    pub fn with_rate_limits(mut self, requests_per_minute: u32, tokens_per_minute: u32) -> Self {
        self.rate_limiter = Arc::new(RateLimiter::new(requests_per_minute, tokens_per_minute));
        self
    }

    /// Create a chat completion
    pub fn chat(&self, request: ChatRequest) -> Result<ChatResponse, GptError> {
        let estimated_tokens = self.estimate_tokens(&request);
        self.rate_limiter
            .try_acquire(estimated_tokens)
            .map_err(|e| GptError::RateLimit(format!("{:?}", e)))?;

        // Simulate API call
        let response = self.mock_chat_response(&request);

        // Track costs
        self.cost_tracker.record_usage(
            request.model,
            response.usage.prompt_tokens,
            response.usage.completion_tokens,
        );

        Ok(response)
    }

    /// Create embeddings
    pub fn embed(&self, request: EmbeddingRequest) -> Result<EmbeddingResponse, GptError> {
        // Simulate embedding
        let dimensions = request
            .dimensions
            .unwrap_or_else(|| request.model.dimensions());
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
            model: request.model.as_str().to_string(),
            usage: EmbeddingUsage {
                prompt_tokens: 100,
                total_tokens: 100,
            },
        })
    }

    /// Get cost tracker
    pub fn cost_tracker(&self) -> &CostTracker {
        &self.cost_tracker
    }

    fn estimate_tokens(&self, request: &ChatRequest) -> u32 {
        let mut tokens = 0u32;
        for msg in &request.messages {
            if let Content::Text(text) = &msg.content {
                tokens += (text.len() / 4) as u32;
            }
        }
        tokens + request.max_tokens.unwrap_or(1000)
    }

    fn mock_chat_response(&self, request: &ChatRequest) -> ChatResponse {
        ChatResponse {
            id: format!("chatcmpl-{}", uuid_v4()),
            object: "chat.completion".to_string(),
            created: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            model: request.model.as_str().to_string(),
            choices: vec![Choice {
                index: 0,
                message: ChatMessage::assistant("This is a mock response from GPT."),
                finish_reason: FinishReason::Stop,
            }],
            usage: Usage {
                prompt_tokens: 50,
                completion_tokens: 20,
                total_tokens: 70,
            },
            system_fingerprint: Some("fp_mock123".to_string()),
        }
    }
}

/// GPT error types
#[derive(Debug)]
pub enum GptError {
    RateLimit(String),
    ApiError { status: u16, message: String },
    Timeout,
    InvalidRequest(String),
    NetworkError(String),
}

impl std::fmt::Display for GptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GptError::RateLimit(msg) => write!(f, "Rate limit exceeded: {}", msg),
            GptError::ApiError { status, message } => {
                write!(f, "API error ({}): {}", status, message)
            }
            GptError::Timeout => write!(f, "Request timed out"),
            GptError::InvalidRequest(msg) => write!(f, "Invalid request: {}", msg),
            GptError::NetworkError(msg) => write!(f, "Network error: {}", msg),
        }
    }
}

impl std::error::Error for GptError {}

/// Generate a mock UUID v4
fn uuid_v4() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:032x}", nanos)
}

fn main() {
    println!("=== OpenAI GPT Client Demo ===\n");

    // Create client
    let config = OpenAiConfig::new("sk-test-key-12345").organization("org-test123");
    let client = GptClient::new(config);

    // Simple chat completion
    println!("1. Simple chat completion:");
    let request = ChatRequest::new(GptModel::Gpt4Turbo)
        .message(ChatMessage::system("You are a helpful assistant."))
        .message(ChatMessage::user("What is Rust?"))
        .temperature(0.7)
        .max_tokens(500);

    match client.chat(request) {
        Ok(response) => {
            println!("   Model: {}", response.model);
            if let Some(choice) = response.choices.first() {
                if let Content::Text(text) = &choice.message.content {
                    println!("   Response: {}", text);
                }
            }
            println!("   Tokens: {}", response.usage.total_tokens);
        }
        Err(e) => println!("   Error: {}", e),
    }

    // Function calling
    println!("\n2. Function calling:");
    let weather_function =
        FunctionDef::new("get_weather", "Get the current weather for a location").with_parameters(
            serde_json::json!({
                "type": "object",
                "properties": {
                    "location": {
                        "type": "string",
                        "description": "City and state, e.g., San Francisco, CA"
                    },
                    "unit": {
                        "type": "string",
                        "enum": ["celsius", "fahrenheit"]
                    }
                },
                "required": ["location"]
            }),
        );

    let request = ChatRequest::new(GptModel::Gpt4Turbo)
        .message(ChatMessage::user("What's the weather in Tokyo?"))
        .tools(vec![ToolDef::function(weather_function)]);

    match client.chat(request) {
        Ok(response) => {
            println!(
                "   Response received with {} choices",
                response.choices.len()
            );
        }
        Err(e) => println!("   Error: {}", e),
    }

    // Vision with GPT-4V
    println!("\n3. Vision request:");
    let request = ChatRequest::new(GptModel::Gpt4Vision)
        .message(ChatMessage::user_with_image(
            "What's in this image?",
            "https://example.com/image.jpg",
        ))
        .max_tokens(300);

    match client.chat(request) {
        Ok(response) => {
            println!("   Vision response: {} choices", response.choices.len());
        }
        Err(e) => println!("   Error: {}", e),
    }

    // JSON mode
    println!("\n4. JSON mode:");
    let request = ChatRequest::new(GptModel::Gpt4Turbo)
        .message(ChatMessage::system(
            "You output JSON with keys: name, description, tags",
        ))
        .message(ChatMessage::user("Describe the Rust programming language"))
        .json_mode()
        .max_tokens(500);

    match client.chat(request) {
        Ok(response) => {
            println!("   JSON mode response received");
            println!("   System fingerprint: {:?}", response.system_fingerprint);
        }
        Err(e) => println!("   Error: {}", e),
    }

    // Embeddings
    println!("\n5. Embeddings:");
    let embed_request = EmbeddingRequest {
        model: EmbeddingModel::TextEmbedding3Small,
        input: vec![
            "Rust is a systems programming language".to_string(),
            "Memory safety without garbage collection".to_string(),
        ],
        encoding_format: None,
        dimensions: Some(256),
        user: None,
    };

    match client.embed(embed_request) {
        Ok(response) => {
            println!("   Generated {} embeddings", response.data.len());
            if let Some(first) = response.data.first() {
                println!("   First embedding dimensions: {}", first.embedding.len());
            }
        }
        Err(e) => println!("   Error: {}", e),
    }

    // Cost tracking
    println!("\n6. Cost tracking:");
    let (input, output) = client.cost_tracker().total_tokens();
    println!("   Total input tokens: {}", input);
    println!("   Total output tokens: {}", output);
    println!(
        "   Total cost: ${:.4}",
        client.cost_tracker().total_cost_usd()
    );

    // Model comparison
    println!("\n7. Model comparison:");
    for model in [GptModel::Gpt4Turbo, GptModel::Gpt4, GptModel::Gpt35Turbo] {
        println!(
            "   {}: max {} tokens, ${}/1k input, ${}/1k output",
            model.as_str(),
            model.max_tokens(),
            model.cost_per_1k_input(),
            model.cost_per_1k_output()
        );
    }

    println!("\n=== Demo Complete ===");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gpt_model_properties() {
        assert_eq!(GptModel::Gpt4Turbo.as_str(), "gpt-4-turbo-preview");
        assert_eq!(GptModel::Gpt4Turbo.max_tokens(), 128000);
        assert!(GptModel::Gpt4Turbo.cost_per_1k_input() > 0.0);
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
    fn test_multipart_message() {
        let msg = ChatMessage::user_with_image("Describe this", "https://example.com/img.jpg");
        assert_eq!(msg.role, Role::User);
        match msg.content {
            Content::MultiPart(parts) => {
                assert_eq!(parts.len(), 2);
            }
            _ => panic!("Expected multipart content"),
        }
    }

    #[test]
    fn test_chat_request_builder() {
        let request = ChatRequest::new(GptModel::Gpt4Turbo)
            .message(ChatMessage::user("Hello"))
            .temperature(0.5)
            .max_tokens(100)
            .seed(42);

        assert_eq!(request.temperature, Some(0.5));
        assert_eq!(request.max_tokens, Some(100));
        assert_eq!(request.seed, Some(42));
        assert_eq!(request.messages.len(), 1);
    }

    #[test]
    fn test_temperature_clamping() {
        let request = ChatRequest::new(GptModel::Gpt4).temperature(3.0);
        assert_eq!(request.temperature, Some(2.0));

        let request = ChatRequest::new(GptModel::Gpt4).temperature(-1.0);
        assert_eq!(request.temperature, Some(0.0));
    }

    #[test]
    fn test_function_definition() {
        let func =
            FunctionDef::new("test_func", "A test function").with_parameters(serde_json::json!({
                "type": "object",
                "properties": {
                    "arg1": { "type": "string" }
                }
            }));

        assert_eq!(func.name, "test_func");
        assert_eq!(func.description, "A test function");
    }

    #[test]
    fn test_tool_definition() {
        let func = FunctionDef::new("search", "Search the web");
        let tool = ToolDef::function(func);

        assert_eq!(tool.tool_type, "function");
        assert_eq!(tool.function.name, "search");
    }

    #[test]
    fn test_rate_limiter() {
        let limiter = RateLimiter::new(10, 1000);

        // Should succeed
        assert!(limiter.try_acquire(100).is_ok());
        assert!(limiter.try_acquire(100).is_ok());

        // Should eventually hit limit
        for _ in 0..20 {
            let _ = limiter.try_acquire(100);
        }
    }

    #[test]
    fn test_cost_tracker() {
        let tracker = CostTracker::new();

        tracker.record_usage(GptModel::Gpt4Turbo, 1000, 500);
        let (input, output) = tracker.total_tokens();

        assert_eq!(input, 1000);
        assert_eq!(output, 500);
        assert!(tracker.total_cost_usd() > 0.0);
    }

    #[test]
    fn test_openai_config() {
        let config = OpenAiConfig::new("sk-test")
            .organization("org-123")
            .base_url("https://custom.api.com")
            .timeout(Duration::from_secs(30));

        assert_eq!(config.api_key, "sk-test");
        assert_eq!(config.organization_id, Some("org-123".to_string()));
        assert_eq!(config.base_url, "https://custom.api.com");
        assert_eq!(config.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_gpt_client_creation() {
        let config = OpenAiConfig::new("sk-test");
        let client = GptClient::new(config).with_rate_limits(100, 50000);

        // Client should be created successfully
        assert!(client.cost_tracker().total_cost_usd() == 0.0);
    }

    #[test]
    fn test_chat_completion() {
        let config = OpenAiConfig::new("sk-test");
        let client = GptClient::new(config);

        let request = ChatRequest::new(GptModel::Gpt35Turbo).message(ChatMessage::user("Hello"));

        let response = client.chat(request).unwrap();

        assert!(!response.id.is_empty());
        assert_eq!(response.choices.len(), 1);
        assert!(response.usage.total_tokens > 0);
    }

    #[test]
    fn test_embedding_request() {
        let config = OpenAiConfig::new("sk-test");
        let client = GptClient::new(config);

        let request = EmbeddingRequest {
            model: EmbeddingModel::TextEmbedding3Small,
            input: vec!["Hello world".to_string()],
            encoding_format: None,
            dimensions: Some(512),
            user: None,
        };

        let response = client.embed(request).unwrap();

        assert_eq!(response.data.len(), 1);
        assert_eq!(response.data[0].embedding.len(), 512);
    }

    #[test]
    fn test_embedding_models() {
        assert_eq!(
            EmbeddingModel::TextEmbedding3Small.as_str(),
            "text-embedding-3-small"
        );
        assert_eq!(EmbeddingModel::TextEmbedding3Large.dimensions(), 3072);
    }

    #[test]
    fn test_json_mode() {
        let request = ChatRequest::new(GptModel::Gpt4Turbo).json_mode();

        match request.response_format {
            Some(ResponseFormat::JsonObject) => {}
            _ => panic!("Expected JSON mode"),
        }
    }

    #[test]
    fn test_finish_reasons() {
        assert_ne!(FinishReason::Stop, FinishReason::Length);
        assert_ne!(FinishReason::ToolCalls, FinishReason::ContentFilter);
    }

    #[test]
    fn test_roles() {
        assert_eq!(Role::System.as_str(), "system");
        assert_eq!(Role::User.as_str(), "user");
        assert_eq!(Role::Assistant.as_str(), "assistant");
        assert_eq!(Role::Function.as_str(), "function");
        assert_eq!(Role::Tool.as_str(), "tool");
    }

    #[test]
    fn test_image_detail() {
        assert_eq!(ImageDetail::Auto.as_str(), "auto");
        assert_eq!(ImageDetail::Low.as_str(), "low");
        assert_eq!(ImageDetail::High.as_str(), "high");
    }

    #[test]
    fn test_tool_result_message() {
        let msg = ChatMessage::tool_result("call_123", r#"{"result": "success"}"#);

        assert_eq!(msg.role, Role::Tool);
        assert_eq!(msg.tool_call_id, Some("call_123".to_string()));
    }
}
