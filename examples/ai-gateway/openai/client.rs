//! OpenAI API Client Example
//!
//! Demonstrates a secure Rust client for OpenAI's API with proper
//! error handling, rate limiting, and streaming support.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// OpenAI API configuration
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
    pub fn new(api_key: &str) -> Self {
        Self {
            api_key: api_key.to_string(),
            organization_id: None,
            base_url: "https://api.openai.com/v1".to_string(),
            timeout: Duration::from_secs(60),
            max_retries: 3,
            retry_delay: Duration::from_secs(1),
        }
    }

    pub fn with_organization(mut self, org_id: &str) -> Self {
        self.organization_id = Some(org_id.to_string());
        self
    }

    pub fn with_base_url(mut self, url: &str) -> Self {
        self.base_url = url.to_string();
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// Chat message role
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

/// Chat message
#[derive(Debug, Clone)]
pub struct Message {
    pub role: Role,
    pub content: String,
    pub name: Option<String>,
    pub function_call: Option<FunctionCall>,
    pub tool_calls: Option<Vec<ToolCall>>,
}

impl Message {
    pub fn system(content: &str) -> Self {
        Self {
            role: Role::System,
            content: content.to_string(),
            name: None,
            function_call: None,
            tool_calls: None,
        }
    }

    pub fn user(content: &str) -> Self {
        Self {
            role: Role::User,
            content: content.to_string(),
            name: None,
            function_call: None,
            tool_calls: None,
        }
    }

    pub fn assistant(content: &str) -> Self {
        Self {
            role: Role::Assistant,
            content: content.to_string(),
            name: None,
            function_call: None,
            tool_calls: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FunctionCall {
    pub name: String,
    pub arguments: String,
}

#[derive(Debug, Clone)]
pub struct ToolCall {
    pub id: String,
    pub r#type: String,
    pub function: FunctionCall,
}

/// Function definition for function calling
#[derive(Debug, Clone)]
pub struct FunctionDef {
    pub name: String,
    pub description: String,
    pub parameters: serde_json_value::Value,
}

/// Simplified JSON value for function parameters
pub mod serde_json_value {
    use std::collections::HashMap;

    #[derive(Debug, Clone)]
    pub enum Value {
        Null,
        Bool(bool),
        Number(f64),
        String(String),
        Array(Vec<Value>),
        Object(HashMap<String, Value>),
    }

    impl Value {
        pub fn object() -> ObjectBuilder {
            ObjectBuilder::new()
        }
    }

    pub struct ObjectBuilder {
        map: HashMap<String, Value>,
    }

    impl ObjectBuilder {
        pub fn new() -> Self {
            Self {
                map: HashMap::new(),
            }
        }

        pub fn property(mut self, key: &str, value: Value) -> Self {
            self.map.insert(key.to_string(), value);
            self
        }

        pub fn build(self) -> Value {
            Value::Object(self.map)
        }
    }
}

/// Chat completion request
#[derive(Debug, Clone)]
pub struct ChatCompletionRequest {
    pub model: String,
    pub messages: Vec<Message>,
    pub temperature: Option<f32>,
    pub max_tokens: Option<u32>,
    pub top_p: Option<f32>,
    pub frequency_penalty: Option<f32>,
    pub presence_penalty: Option<f32>,
    pub stop: Option<Vec<String>>,
    pub stream: bool,
    pub functions: Option<Vec<FunctionDef>>,
    pub function_call: Option<String>,
    pub user: Option<String>,
}

impl ChatCompletionRequest {
    pub fn new(model: &str, messages: Vec<Message>) -> Self {
        Self {
            model: model.to_string(),
            messages,
            temperature: None,
            max_tokens: None,
            top_p: None,
            frequency_penalty: None,
            presence_penalty: None,
            stop: None,
            stream: false,
            functions: None,
            function_call: None,
            user: None,
        }
    }

    pub fn with_temperature(mut self, temp: f32) -> Self {
        self.temperature = Some(temp.clamp(0.0, 2.0));
        self
    }

    pub fn with_max_tokens(mut self, tokens: u32) -> Self {
        self.max_tokens = Some(tokens);
        self
    }

    pub fn with_stream(mut self, stream: bool) -> Self {
        self.stream = stream;
        self
    }

    pub fn with_functions(mut self, functions: Vec<FunctionDef>) -> Self {
        self.functions = Some(functions);
        self
    }
}

/// Chat completion response
#[derive(Debug, Clone)]
pub struct ChatCompletionResponse {
    pub id: String,
    pub object: String,
    pub created: u64,
    pub model: String,
    pub choices: Vec<Choice>,
    pub usage: Usage,
}

#[derive(Debug, Clone)]
pub struct Choice {
    pub index: u32,
    pub message: Message,
    pub finish_reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Usage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

/// Streaming response chunk
#[derive(Debug, Clone)]
pub struct StreamChunk {
    pub id: String,
    pub choices: Vec<StreamChoice>,
}

#[derive(Debug, Clone)]
pub struct StreamChoice {
    pub index: u32,
    pub delta: Delta,
    pub finish_reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Delta {
    pub role: Option<Role>,
    pub content: Option<String>,
    pub function_call: Option<FunctionCall>,
}

/// OpenAI API error
#[derive(Debug)]
pub enum OpenAiError {
    Unauthorized,
    RateLimited { retry_after: Option<Duration> },
    InvalidRequest(String),
    ServerError(String),
    Timeout,
    NetworkError(String),
    ParseError(String),
}

/// Rate limiter for API calls
pub struct RateLimiter {
    requests_per_minute: u32,
    tokens_per_minute: u32,
    request_times: Vec<Instant>,
    token_count: u32,
    last_reset: Instant,
}

impl RateLimiter {
    pub fn new(requests_per_minute: u32, tokens_per_minute: u32) -> Self {
        Self {
            requests_per_minute,
            tokens_per_minute,
            request_times: Vec::new(),
            token_count: 0,
            last_reset: Instant::now(),
        }
    }

    pub fn check_request(&mut self) -> Result<(), Duration> {
        let now = Instant::now();

        // Reset token count every minute
        if now.duration_since(self.last_reset) >= Duration::from_secs(60) {
            self.token_count = 0;
            self.last_reset = now;
        }

        // Clean old request times
        let minute_ago = now - Duration::from_secs(60);
        self.request_times.retain(|&t| t > minute_ago);

        // Check request limit
        if self.request_times.len() >= self.requests_per_minute as usize {
            let oldest = self.request_times.first().unwrap();
            let wait = Duration::from_secs(60) - now.duration_since(*oldest);
            return Err(wait);
        }

        self.request_times.push(now);
        Ok(())
    }

    pub fn record_tokens(&mut self, tokens: u32) -> Result<(), Duration> {
        let now = Instant::now();

        if now.duration_since(self.last_reset) >= Duration::from_secs(60) {
            self.token_count = 0;
            self.last_reset = now;
        }

        if self.token_count + tokens > self.tokens_per_minute {
            let wait = Duration::from_secs(60) - now.duration_since(self.last_reset);
            return Err(wait);
        }

        self.token_count += tokens;
        Ok(())
    }
}

/// OpenAI API client
pub struct OpenAiClient {
    config: OpenAiConfig,
    rate_limiter: RateLimiter,
}

impl OpenAiClient {
    pub fn new(config: OpenAiConfig) -> Self {
        Self {
            config,
            // GPT-4 limits: 10,000 RPM, 300,000 TPM (Tier 1)
            rate_limiter: RateLimiter::new(500, 40_000),
        }
    }

    /// Create chat completion
    pub fn chat_completion(
        &mut self,
        request: ChatCompletionRequest,
    ) -> Result<ChatCompletionResponse, OpenAiError> {
        // Check rate limit
        if let Err(wait) = self.rate_limiter.check_request() {
            return Err(OpenAiError::RateLimited {
                retry_after: Some(wait),
            });
        }

        // Build request (simplified - would use reqwest in real impl)
        let _endpoint = format!("{}/chat/completions", self.config.base_url);

        // Simulate API response
        let response = ChatCompletionResponse {
            id: "chatcmpl-abc123".to_string(),
            object: "chat.completion".to_string(),
            created: 1699000000,
            model: request.model.clone(),
            choices: vec![Choice {
                index: 0,
                message: Message::assistant("This is a simulated response from OpenAI."),
                finish_reason: Some("stop".to_string()),
            }],
            usage: Usage {
                prompt_tokens: 50,
                completion_tokens: 20,
                total_tokens: 70,
            },
        };

        // Record token usage
        let _ = self.rate_limiter.record_tokens(response.usage.total_tokens);

        Ok(response)
    }

    /// Create streaming chat completion
    pub fn chat_completion_stream(
        &mut self,
        request: ChatCompletionRequest,
    ) -> Result<StreamingResponse, OpenAiError> {
        if !request.stream {
            return Err(OpenAiError::InvalidRequest(
                "Request must have stream=true".to_string(),
            ));
        }

        // Check rate limit
        if let Err(wait) = self.rate_limiter.check_request() {
            return Err(OpenAiError::RateLimited {
                retry_after: Some(wait),
            });
        }

        Ok(StreamingResponse {
            chunks: vec![
                StreamChunk {
                    id: "chatcmpl-abc123".to_string(),
                    choices: vec![StreamChoice {
                        index: 0,
                        delta: Delta {
                            role: Some(Role::Assistant),
                            content: None,
                            function_call: None,
                        },
                        finish_reason: None,
                    }],
                },
                StreamChunk {
                    id: "chatcmpl-abc123".to_string(),
                    choices: vec![StreamChoice {
                        index: 0,
                        delta: Delta {
                            role: None,
                            content: Some("Hello".to_string()),
                            function_call: None,
                        },
                        finish_reason: None,
                    }],
                },
                StreamChunk {
                    id: "chatcmpl-abc123".to_string(),
                    choices: vec![StreamChoice {
                        index: 0,
                        delta: Delta {
                            role: None,
                            content: Some(" from".to_string()),
                            function_call: None,
                        },
                        finish_reason: None,
                    }],
                },
                StreamChunk {
                    id: "chatcmpl-abc123".to_string(),
                    choices: vec![StreamChoice {
                        index: 0,
                        delta: Delta {
                            role: None,
                            content: Some(" OpenAI!".to_string()),
                            function_call: None,
                        },
                        finish_reason: Some("stop".to_string()),
                    }],
                },
            ],
            current: 0,
        })
    }

    /// Generate embeddings
    pub fn create_embedding(&mut self, input: &str, model: &str) -> Result<Vec<f32>, OpenAiError> {
        if let Err(wait) = self.rate_limiter.check_request() {
            return Err(OpenAiError::RateLimited {
                retry_after: Some(wait),
            });
        }

        // Simulate embedding (1536 dimensions for text-embedding-ada-002)
        let embedding: Vec<f32> = (0..1536).map(|i| (i as f32 * 0.001).sin()).collect();

        Ok(embedding)
    }
}

/// Streaming response iterator
pub struct StreamingResponse {
    chunks: Vec<StreamChunk>,
    current: usize,
}

impl Iterator for StreamingResponse {
    type Item = StreamChunk;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current < self.chunks.len() {
            let chunk = self.chunks[self.current].clone();
            self.current += 1;
            Some(chunk)
        } else {
            None
        }
    }
}

/// Cost calculator for OpenAI usage
pub struct CostCalculator {
    prices: HashMap<String, (f64, f64)>, // (input_per_1k, output_per_1k)
}

impl Default for CostCalculator {
    fn default() -> Self {
        Self::new()
    }
}

impl CostCalculator {
    pub fn new() -> Self {
        let mut prices = HashMap::new();
        // Prices as of 2024 (per 1K tokens)
        prices.insert("gpt-4".to_string(), (0.03, 0.06));
        prices.insert("gpt-4-turbo".to_string(), (0.01, 0.03));
        prices.insert("gpt-4o".to_string(), (0.005, 0.015));
        prices.insert("gpt-3.5-turbo".to_string(), (0.0005, 0.0015));
        prices.insert("text-embedding-ada-002".to_string(), (0.0001, 0.0));
        prices.insert("text-embedding-3-small".to_string(), (0.00002, 0.0));
        Self { prices }
    }

    pub fn calculate(&self, model: &str, usage: &Usage) -> f64 {
        if let Some(&(input_price, output_price)) = self.prices.get(model) {
            let input_cost = (usage.prompt_tokens as f64 / 1000.0) * input_price;
            let output_cost = (usage.completion_tokens as f64 / 1000.0) * output_price;
            input_cost + output_cost
        } else {
            0.0
        }
    }
}

fn main() {
    println!("OpenAI API Client Example");
    println!("=========================\n");

    // Create client
    let config = OpenAiConfig::new("sk-your-api-key")
        .with_organization("org-your-org-id")
        .with_timeout(Duration::from_secs(30));

    let mut client = OpenAiClient::new(config);

    // Create chat completion request
    let request = ChatCompletionRequest::new(
        "gpt-4",
        vec![
            Message::system("You are a helpful assistant."),
            Message::user("What is Rust?"),
        ],
    )
    .with_temperature(0.7)
    .with_max_tokens(500);

    println!("Request:");
    println!("  Model: {}", request.model);
    println!("  Messages: {} message(s)", request.messages.len());
    println!("  Temperature: {:?}", request.temperature);
    println!("  Max tokens: {:?}\n", request.max_tokens);

    // Execute request
    match client.chat_completion(request) {
        Ok(response) => {
            println!("Response:");
            println!("  ID: {}", response.id);
            println!("  Model: {}", response.model);
            println!("  Content: {}", response.choices[0].message.content);
            println!("\nUsage:");
            println!("  Prompt tokens: {}", response.usage.prompt_tokens);
            println!("  Completion tokens: {}", response.usage.completion_tokens);
            println!("  Total tokens: {}", response.usage.total_tokens);

            // Calculate cost
            let calculator = CostCalculator::new();
            let cost = calculator.calculate(&response.model, &response.usage);
            println!("\nEstimated cost: ${:.6}", cost);
        }
        Err(e) => {
            println!("Error: {:?}", e);
        }
    }

    // Streaming example
    println!("\n\nStreaming Example:");
    println!("==================");

    let stream_request =
        ChatCompletionRequest::new("gpt-4", vec![Message::user("Say hello!")]).with_stream(true);

    match client.chat_completion_stream(stream_request) {
        Ok(stream) => {
            print!("Response: ");
            for chunk in stream {
                if let Some(content) = chunk.choices.first().and_then(|c| c.delta.content.as_ref())
                {
                    print!("{}", content);
                }
            }
            println!("\n");
        }
        Err(e) => {
            println!("Error: {:?}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_builder() {
        let config = OpenAiConfig::new("sk-test")
            .with_organization("org-test")
            .with_timeout(Duration::from_secs(120));

        assert_eq!(config.api_key, "sk-test");
        assert_eq!(config.organization_id, Some("org-test".to_string()));
        assert_eq!(config.timeout, Duration::from_secs(120));
    }

    #[test]
    fn test_message_constructors() {
        let system = Message::system("System prompt");
        assert_eq!(system.role, Role::System);
        assert_eq!(system.content, "System prompt");

        let user = Message::user("User input");
        assert_eq!(user.role, Role::User);

        let assistant = Message::assistant("AI response");
        assert_eq!(assistant.role, Role::Assistant);
    }

    #[test]
    fn test_request_builder() {
        let request = ChatCompletionRequest::new("gpt-4", vec![])
            .with_temperature(0.5)
            .with_max_tokens(100)
            .with_stream(true);

        assert_eq!(request.model, "gpt-4");
        assert_eq!(request.temperature, Some(0.5));
        assert_eq!(request.max_tokens, Some(100));
        assert!(request.stream);
    }

    #[test]
    fn test_temperature_clamping() {
        let request = ChatCompletionRequest::new("gpt-4", vec![]).with_temperature(5.0); // Should clamp to 2.0

        assert_eq!(request.temperature, Some(2.0));
    }

    #[test]
    fn test_rate_limiter() {
        let mut limiter = RateLimiter::new(10, 1000);

        // Should allow first request
        assert!(limiter.check_request().is_ok());

        // Should allow tokens
        assert!(limiter.record_tokens(100).is_ok());
    }

    #[test]
    fn test_cost_calculator() {
        let calc = CostCalculator::new();

        let usage = Usage {
            prompt_tokens: 1000,
            completion_tokens: 500,
            total_tokens: 1500,
        };

        let cost = calc.calculate("gpt-4", &usage);
        // 1000/1000 * 0.03 + 500/1000 * 0.06 = 0.03 + 0.03 = 0.06
        assert!((cost - 0.06).abs() < 0.001);
    }

    #[test]
    fn test_streaming_response() {
        let config = OpenAiConfig::new("test");
        let mut client = OpenAiClient::new(config);

        let request = ChatCompletionRequest::new("gpt-4", vec![]).with_stream(true);

        let stream = client.chat_completion_stream(request).unwrap();
        let chunks: Vec<_> = stream.collect();

        assert!(!chunks.is_empty());
    }

    #[test]
    fn test_role_serialization() {
        assert_eq!(Role::System.as_str(), "system");
        assert_eq!(Role::User.as_str(), "user");
        assert_eq!(Role::Assistant.as_str(), "assistant");
        assert_eq!(Role::Function.as_str(), "function");
        assert_eq!(Role::Tool.as_str(), "tool");
    }
}
