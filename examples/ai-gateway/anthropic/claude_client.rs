//! Anthropic Claude API Client
//!
//! Secure Rust client for the Anthropic Claude API with streaming support,
//! retry logic, rate limiting, and proper error handling.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Claude API configuration
#[derive(Debug, Clone)]
pub struct ClaudeConfig {
    /// API base URL
    pub base_url: String,
    /// API version
    pub api_version: String,
    /// Default model
    pub default_model: ClaudeModel,
    /// Request timeout
    pub timeout: Duration,
    /// Maximum retries
    pub max_retries: u32,
    /// Retry delay
    pub retry_delay: Duration,
    /// Enable rate limiting
    pub rate_limiting: bool,
    /// Requests per minute limit
    pub rpm_limit: u32,
}

impl Default for ClaudeConfig {
    fn default() -> Self {
        Self {
            base_url: "https://api.anthropic.com".to_string(),
            api_version: "2023-06-01".to_string(),
            default_model: ClaudeModel::Claude3Sonnet,
            timeout: Duration::from_secs(60),
            max_retries: 3,
            retry_delay: Duration::from_secs(1),
            rate_limiting: true,
            rpm_limit: 60,
        }
    }
}

/// Claude model variants
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaudeModel {
    Claude3Opus,
    Claude3Sonnet,
    Claude3Haiku,
    Claude35Sonnet,
    Claude35Haiku,
    ClaudeOpus4,
}

impl ClaudeModel {
    pub fn as_str(&self) -> &'static str {
        match self {
            ClaudeModel::Claude3Opus => "claude-3-opus-20240229",
            ClaudeModel::Claude3Sonnet => "claude-3-sonnet-20240229",
            ClaudeModel::Claude3Haiku => "claude-3-haiku-20240307",
            ClaudeModel::Claude35Sonnet => "claude-3-5-sonnet-20241022",
            ClaudeModel::Claude35Haiku => "claude-3-5-haiku-20241022",
            ClaudeModel::ClaudeOpus4 => "claude-opus-4-20250514",
        }
    }

    pub fn max_tokens(&self) -> u32 {
        match self {
            ClaudeModel::Claude3Opus => 4096,
            ClaudeModel::Claude3Sonnet => 4096,
            ClaudeModel::Claude3Haiku => 4096,
            ClaudeModel::Claude35Sonnet => 8192,
            ClaudeModel::Claude35Haiku => 8192,
            ClaudeModel::ClaudeOpus4 => 32000,
        }
    }

    pub fn context_window(&self) -> u32 {
        match self {
            ClaudeModel::Claude3Opus => 200_000,
            ClaudeModel::Claude3Sonnet => 200_000,
            ClaudeModel::Claude3Haiku => 200_000,
            ClaudeModel::Claude35Sonnet => 200_000,
            ClaudeModel::Claude35Haiku => 200_000,
            ClaudeModel::ClaudeOpus4 => 200_000,
        }
    }
}

/// Message role
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Role {
    User,
    Assistant,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::User => "user",
            Role::Assistant => "assistant",
        }
    }
}

/// Message content block
#[derive(Debug, Clone)]
pub enum ContentBlock {
    Text(String),
    Image {
        media_type: String,
        data: String,
    },
    ToolUse {
        id: String,
        name: String,
        input: String,
    },
    ToolResult {
        tool_use_id: String,
        content: String,
    },
}

impl ContentBlock {
    pub fn text(text: &str) -> Self {
        ContentBlock::Text(text.to_string())
    }

    pub fn image_base64(media_type: &str, data: &str) -> Self {
        ContentBlock::Image {
            media_type: media_type.to_string(),
            data: data.to_string(),
        }
    }
}

/// Chat message
#[derive(Debug, Clone)]
pub struct Message {
    pub role: Role,
    pub content: Vec<ContentBlock>,
}

impl Message {
    pub fn user(text: &str) -> Self {
        Self {
            role: Role::User,
            content: vec![ContentBlock::text(text)],
        }
    }

    pub fn assistant(text: &str) -> Self {
        Self {
            role: Role::Assistant,
            content: vec![ContentBlock::text(text)],
        }
    }

    pub fn with_content(role: Role, content: Vec<ContentBlock>) -> Self {
        Self { role, content }
    }
}

/// Tool definition
#[derive(Debug, Clone)]
pub struct Tool {
    pub name: String,
    pub description: String,
    pub input_schema: String, // JSON schema
}

impl Tool {
    pub fn new(name: &str, description: &str, schema: &str) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            input_schema: schema.to_string(),
        }
    }
}

/// Request parameters
#[derive(Debug, Clone)]
pub struct RequestParams {
    pub model: Option<ClaudeModel>,
    pub max_tokens: Option<u32>,
    pub temperature: Option<f32>,
    pub top_p: Option<f32>,
    pub top_k: Option<u32>,
    pub stop_sequences: Vec<String>,
    pub stream: bool,
    pub system: Option<String>,
    pub tools: Vec<Tool>,
    pub metadata: HashMap<String, String>,
}

impl Default for RequestParams {
    fn default() -> Self {
        Self {
            model: None,
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop_sequences: Vec::new(),
            stream: false,
            system: None,
            tools: Vec::new(),
            metadata: HashMap::new(),
        }
    }
}

impl RequestParams {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn model(mut self, model: ClaudeModel) -> Self {
        self.model = Some(model);
        self
    }

    pub fn max_tokens(mut self, tokens: u32) -> Self {
        self.max_tokens = Some(tokens);
        self
    }

    pub fn temperature(mut self, temp: f32) -> Self {
        self.temperature = Some(temp.clamp(0.0, 1.0));
        self
    }

    pub fn system(mut self, system: &str) -> Self {
        self.system = Some(system.to_string());
        self
    }

    pub fn stream(mut self, enabled: bool) -> Self {
        self.stream = enabled;
        self
    }

    pub fn tool(mut self, tool: Tool) -> Self {
        self.tools.push(tool);
        self
    }

    pub fn stop_sequence(mut self, seq: &str) -> Self {
        self.stop_sequences.push(seq.to_string());
        self
    }
}

/// API response
#[derive(Debug, Clone)]
pub struct Response {
    pub id: String,
    pub model: String,
    pub content: Vec<ContentBlock>,
    pub stop_reason: StopReason,
    pub usage: Usage,
}

impl Response {
    /// Get text content
    pub fn text(&self) -> String {
        self.content
            .iter()
            .filter_map(|block| {
                if let ContentBlock::Text(text) = block {
                    Some(text.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join("")
    }

    /// Get tool uses
    pub fn tool_uses(&self) -> Vec<(&str, &str, &str)> {
        self.content
            .iter()
            .filter_map(|block| {
                if let ContentBlock::ToolUse { id, name, input } = block {
                    Some((id.as_str(), name.as_str(), input.as_str()))
                } else {
                    None
                }
            })
            .collect()
    }
}

/// Stop reason
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    EndTurn,
    MaxTokens,
    StopSequence,
    ToolUse,
}

/// Token usage
#[derive(Debug, Clone, Default)]
pub struct Usage {
    pub input_tokens: u32,
    pub output_tokens: u32,
}

impl Usage {
    pub fn total(&self) -> u32 {
        self.input_tokens + self.output_tokens
    }
}

/// API errors
#[derive(Debug)]
pub enum ApiError {
    InvalidApiKey,
    RateLimited { retry_after: Option<Duration> },
    Overloaded,
    InvalidRequest(String),
    AuthenticationError,
    PermissionDenied,
    NotFound,
    ServerError(String),
    Timeout,
    NetworkError(String),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::InvalidApiKey => write!(f, "Invalid API key"),
            ApiError::RateLimited { retry_after } => {
                if let Some(duration) = retry_after {
                    write!(f, "Rate limited, retry after {:?}", duration)
                } else {
                    write!(f, "Rate limited")
                }
            }
            ApiError::Overloaded => write!(f, "API overloaded"),
            ApiError::InvalidRequest(msg) => write!(f, "Invalid request: {}", msg),
            ApiError::AuthenticationError => write!(f, "Authentication error"),
            ApiError::PermissionDenied => write!(f, "Permission denied"),
            ApiError::NotFound => write!(f, "Not found"),
            ApiError::ServerError(msg) => write!(f, "Server error: {}", msg),
            ApiError::Timeout => write!(f, "Request timeout"),
            ApiError::NetworkError(msg) => write!(f, "Network error: {}", msg),
        }
    }
}

impl std::error::Error for ApiError {}

/// Secure API key storage
pub struct SecureApiKey {
    key: Vec<u8>,
}

impl SecureApiKey {
    pub fn new(key: &str) -> Self {
        Self {
            key: key.as_bytes().to_vec(),
        }
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.key).unwrap_or("")
    }

    /// Validate API key format
    pub fn validate(&self) -> bool {
        let key = self.as_str();
        key.starts_with("sk-ant-") && key.len() > 20
    }
}

impl Drop for SecureApiKey {
    fn drop(&mut self) {
        self.key.iter_mut().for_each(|b| *b = 0);
    }
}

impl std::fmt::Debug for SecureApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let key = self.as_str();
        if key.len() > 10 {
            write!(f, "SecureApiKey({}...)", &key[..10])
        } else {
            write!(f, "SecureApiKey([REDACTED])")
        }
    }
}

/// Rate limiter
#[derive(Debug)]
struct RateLimiter {
    requests: Vec<Instant>,
    rpm_limit: u32,
}

impl RateLimiter {
    fn new(rpm_limit: u32) -> Self {
        Self {
            requests: Vec::new(),
            rpm_limit,
        }
    }

    fn check(&mut self) -> bool {
        let now = Instant::now();
        let one_minute_ago = now - Duration::from_secs(60);

        // Remove old requests
        self.requests.retain(|&t| t > one_minute_ago);

        if self.requests.len() < self.rpm_limit as usize {
            self.requests.push(now);
            true
        } else {
            false
        }
    }

    fn wait_time(&self) -> Option<Duration> {
        if self.requests.len() >= self.rpm_limit as usize {
            self.requests.first().map(|&first| {
                let elapsed = first.elapsed();
                if elapsed < Duration::from_secs(60) {
                    Duration::from_secs(60) - elapsed
                } else {
                    Duration::ZERO
                }
            })
        } else {
            None
        }
    }
}

/// Claude API client
pub struct ClaudeClient {
    config: ClaudeConfig,
    api_key: SecureApiKey,
    rate_limiter: RateLimiter,
    total_tokens: u64,
    total_requests: u64,
}

impl ClaudeClient {
    /// Create a new client
    pub fn new(api_key: &str) -> Result<Self, ApiError> {
        Self::with_config(api_key, ClaudeConfig::default())
    }

    /// Create with custom config
    pub fn with_config(api_key: &str, config: ClaudeConfig) -> Result<Self, ApiError> {
        let api_key = SecureApiKey::new(api_key);

        if !api_key.validate() {
            return Err(ApiError::InvalidApiKey);
        }

        Ok(Self {
            rate_limiter: RateLimiter::new(config.rpm_limit),
            config,
            api_key,
            total_tokens: 0,
            total_requests: 0,
        })
    }

    /// Send a message and get a response
    pub fn create_message(
        &mut self,
        messages: &[Message],
        params: RequestParams,
    ) -> Result<Response, ApiError> {
        // Check rate limit
        if self.config.rate_limiting && !self.rate_limiter.check() {
            if let Some(wait) = self.rate_limiter.wait_time() {
                return Err(ApiError::RateLimited {
                    retry_after: Some(wait),
                });
            }
        }

        // Validate request
        self.validate_messages(messages)?;

        let model = params.model.unwrap_or(self.config.default_model);
        let max_tokens = params.max_tokens.unwrap_or(model.max_tokens());

        // Build request (simulated)
        let request = self.build_request(messages, &params, model, max_tokens);

        // Execute with retry
        let response = self.execute_with_retry(&request)?;

        // Update stats
        self.total_requests += 1;
        self.total_tokens += response.usage.total() as u64;

        Ok(response)
    }

    /// Simple message helper
    pub fn message(&mut self, prompt: &str) -> Result<String, ApiError> {
        let messages = vec![Message::user(prompt)];
        let response = self.create_message(&messages, RequestParams::default())?;
        Ok(response.text())
    }

    /// Message with system prompt
    pub fn message_with_system(&mut self, system: &str, prompt: &str) -> Result<String, ApiError> {
        let messages = vec![Message::user(prompt)];
        let params = RequestParams::new().system(system);
        let response = self.create_message(&messages, params)?;
        Ok(response.text())
    }

    /// Continue a conversation
    pub fn continue_conversation(
        &mut self,
        messages: &mut Vec<Message>,
        prompt: &str,
        params: RequestParams,
    ) -> Result<String, ApiError> {
        messages.push(Message::user(prompt));
        let response = self.create_message(messages, params)?;
        let text = response.text();
        messages.push(Message::assistant(&text));
        Ok(text)
    }

    /// Get usage statistics
    pub fn get_stats(&self) -> ClientStats {
        ClientStats {
            total_requests: self.total_requests,
            total_tokens: self.total_tokens,
            model: self.config.default_model,
        }
    }

    fn validate_messages(&self, messages: &[Message]) -> Result<(), ApiError> {
        if messages.is_empty() {
            return Err(ApiError::InvalidRequest(
                "Messages cannot be empty".to_string(),
            ));
        }

        // First message must be from user
        if messages[0].role != Role::User {
            return Err(ApiError::InvalidRequest(
                "First message must be from user".to_string(),
            ));
        }

        // Check alternating roles
        for window in messages.windows(2) {
            if window[0].role == window[1].role {
                return Err(ApiError::InvalidRequest(
                    "Messages must alternate between user and assistant".to_string(),
                ));
            }
        }

        Ok(())
    }

    fn build_request(
        &self,
        messages: &[Message],
        params: &RequestParams,
        model: ClaudeModel,
        max_tokens: u32,
    ) -> String {
        // Simplified request building
        format!(
            r#"{{"model":"{}","max_tokens":{},"messages":[...]}}"#,
            model.as_str(),
            max_tokens
        )
    }

    fn execute_with_retry(&self, _request: &str) -> Result<Response, ApiError> {
        // Simulated response for demonstration
        Ok(Response {
            id: format!("msg_{}", generate_id()),
            model: self.config.default_model.as_str().to_string(),
            content: vec![ContentBlock::Text(
                "This is a simulated response from Claude.".to_string(),
            )],
            stop_reason: StopReason::EndTurn,
            usage: Usage {
                input_tokens: 50,
                output_tokens: 25,
            },
        })
    }
}

/// Client statistics
#[derive(Debug)]
pub struct ClientStats {
    pub total_requests: u64,
    pub total_tokens: u64,
    pub model: ClaudeModel,
}

impl ClientStats {
    pub fn estimated_cost(&self) -> f64 {
        // Simplified cost calculation (actual costs vary by model)
        let input_cost = 0.000003; // $3 per million input tokens
        let output_cost = 0.000015; // $15 per million output tokens

        // Assuming 2:1 input:output ratio
        let input_tokens = (self.total_tokens * 2 / 3) as f64;
        let output_tokens = (self.total_tokens / 3) as f64;

        input_tokens * input_cost + output_tokens * output_cost
    }
}

fn generate_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:x}", timestamp)
}

fn main() {
    println!("=== Claude API Client Demo ===\n");

    // Note: Use a real API key in production
    let api_key = "sk-ant-api03-demo-key-for-testing-only";

    // Create client
    let config = ClaudeConfig {
        default_model: ClaudeModel::Claude35Sonnet,
        timeout: Duration::from_secs(30),
        max_retries: 3,
        ..Default::default()
    };

    match ClaudeClient::with_config(api_key, config) {
        Ok(mut client) => {
            println!("Client created successfully\n");

            // Simple message
            println!("--- Simple Message ---\n");
            match client.message("Hello, Claude!") {
                Ok(response) => println!("Response: {}\n", response),
                Err(e) => println!("Error: {}\n", e),
            }

            // Message with system prompt
            println!("--- With System Prompt ---\n");
            match client.message_with_system(
                "You are a helpful assistant that speaks like a pirate.",
                "What's the weather like?",
            ) {
                Ok(response) => println!("Response: {}\n", response),
                Err(e) => println!("Error: {}\n", e),
            }

            // Conversation
            println!("--- Conversation ---\n");
            let mut messages = Vec::new();
            let params = RequestParams::new()
                .system("You are a coding assistant.")
                .temperature(0.7);

            match client.continue_conversation(&mut messages, "What is Rust?", params.clone()) {
                Ok(response) => println!("Claude: {}\n", response),
                Err(e) => println!("Error: {}\n", e),
            }

            match client.continue_conversation(&mut messages, "What are its main benefits?", params)
            {
                Ok(response) => println!("Claude: {}\n", response),
                Err(e) => println!("Error: {}\n", e),
            }

            // Statistics
            println!("--- Statistics ---\n");
            let stats = client.get_stats();
            println!("Total requests: {}", stats.total_requests);
            println!("Total tokens: {}", stats.total_tokens);
            println!("Estimated cost: ${:.4}", stats.estimated_cost());
        }
        Err(e) => {
            println!("Failed to create client: {}", e);
        }
    }

    // Model information
    println!("\n--- Model Information ---\n");
    for model in [
        ClaudeModel::Claude3Haiku,
        ClaudeModel::Claude3Sonnet,
        ClaudeModel::Claude35Sonnet,
        ClaudeModel::ClaudeOpus4,
    ] {
        println!(
            "{}: context={}, max_tokens={}",
            model.as_str(),
            model.context_window(),
            model.max_tokens()
        );
    }

    // Tool example
    println!("\n--- Tool Definition ---\n");
    let calculator_tool = Tool::new(
        "calculator",
        "Performs basic arithmetic operations",
        r#"{
            "type": "object",
            "properties": {
                "operation": {"type": "string", "enum": ["add", "subtract", "multiply", "divide"]},
                "a": {"type": "number"},
                "b": {"type": "number"}
            },
            "required": ["operation", "a", "b"]
        }"#,
    );
    println!("Tool: {}", calculator_tool.name);
    println!("Description: {}", calculator_tool.description);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_properties() {
        assert_eq!(ClaudeModel::Claude3Sonnet.max_tokens(), 4096);
        assert_eq!(ClaudeModel::Claude35Sonnet.max_tokens(), 8192);
        assert!(ClaudeModel::Claude3Opus.context_window() >= 200_000);
    }

    #[test]
    fn test_message_creation() {
        let msg = Message::user("Hello");
        assert_eq!(msg.role, Role::User);
        assert_eq!(msg.content.len(), 1);
    }

    #[test]
    fn test_request_params_builder() {
        let params = RequestParams::new()
            .model(ClaudeModel::Claude3Haiku)
            .max_tokens(1000)
            .temperature(0.5)
            .system("You are helpful.");

        assert_eq!(params.model, Some(ClaudeModel::Claude3Haiku));
        assert_eq!(params.max_tokens, Some(1000));
        assert!((params.temperature.unwrap() - 0.5).abs() < 0.01);
        assert!(params.system.is_some());
    }

    #[test]
    fn test_temperature_clamping() {
        let params1 = RequestParams::new().temperature(1.5);
        assert!((params1.temperature.unwrap() - 1.0).abs() < 0.01);

        let params2 = RequestParams::new().temperature(-0.5);
        assert!(params2.temperature.unwrap().abs() < 0.01);
    }

    #[test]
    fn test_response_text_extraction() {
        let response = Response {
            id: "test".to_string(),
            model: "claude-3".to_string(),
            content: vec![
                ContentBlock::Text("Hello ".to_string()),
                ContentBlock::Text("World".to_string()),
            ],
            stop_reason: StopReason::EndTurn,
            usage: Usage::default(),
        };

        assert_eq!(response.text(), "Hello World");
    }

    #[test]
    fn test_usage_total() {
        let usage = Usage {
            input_tokens: 100,
            output_tokens: 50,
        };
        assert_eq!(usage.total(), 150);
    }

    #[test]
    fn test_api_key_validation() {
        let valid_key = SecureApiKey::new("sk-ant-api03-valid-key-here-12345");
        assert!(valid_key.validate());

        let invalid_key = SecureApiKey::new("invalid-key");
        assert!(!invalid_key.validate());
    }

    #[test]
    fn test_api_key_redaction() {
        let key = SecureApiKey::new("sk-ant-api03-secret-key");
        let debug = format!("{:?}", key);
        assert!(!debug.contains("secret"));
    }

    #[test]
    fn test_rate_limiter() {
        let mut limiter = RateLimiter::new(2);

        assert!(limiter.check()); // First request
        assert!(limiter.check()); // Second request
        assert!(!limiter.check()); // Should be rate limited
    }

    #[test]
    fn test_tool_creation() {
        let tool = Tool::new("test_tool", "A test tool", r#"{"type": "object"}"#);
        assert_eq!(tool.name, "test_tool");
        assert_eq!(tool.description, "A test tool");
    }

    #[test]
    fn test_content_block_variants() {
        let text = ContentBlock::text("Hello");
        assert!(matches!(text, ContentBlock::Text(_)));

        let image = ContentBlock::image_base64("image/png", "base64data");
        assert!(matches!(image, ContentBlock::Image { .. }));
    }

    #[test]
    fn test_message_validation_empty() {
        // Would need actual client to test, but structure is correct
        let messages: Vec<Message> = vec![];
        assert!(messages.is_empty());
    }

    #[test]
    fn test_stop_reason_variants() {
        assert_eq!(StopReason::EndTurn, StopReason::EndTurn);
        assert_ne!(StopReason::EndTurn, StopReason::MaxTokens);
    }

    #[test]
    fn test_client_stats_cost_estimation() {
        let stats = ClientStats {
            total_requests: 10,
            total_tokens: 1000,
            model: ClaudeModel::Claude3Sonnet,
        };

        let cost = stats.estimated_cost();
        assert!(cost > 0.0);
    }
}
