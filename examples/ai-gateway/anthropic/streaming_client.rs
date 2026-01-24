//! Anthropic Claude API Streaming Client
//!
//! This example demonstrates a secure Rust client for the Anthropic
//! Claude API with streaming support, function calling, vision
//! capabilities, and proper error handling.

use std::collections::HashMap;
use std::fmt;
use std::io::{self, Write};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ============================================================================
// API Types
// ============================================================================

/// Claude model variants
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaudeModel {
    Claude3Opus,
    Claude3Sonnet,
    Claude3Haiku,
    Claude35Sonnet,
    Claude35Haiku,
    Claude4Opus,
    Claude4Sonnet,
}

impl ClaudeModel {
    pub fn as_str(&self) -> &'static str {
        match self {
            ClaudeModel::Claude3Opus => "claude-3-opus-20240229",
            ClaudeModel::Claude3Sonnet => "claude-3-sonnet-20240229",
            ClaudeModel::Claude3Haiku => "claude-3-haiku-20240307",
            ClaudeModel::Claude35Sonnet => "claude-3-5-sonnet-20241022",
            ClaudeModel::Claude35Haiku => "claude-3-5-haiku-20241022",
            ClaudeModel::Claude4Opus => "claude-4-opus-20250514",
            ClaudeModel::Claude4Sonnet => "claude-4-sonnet-20250514",
        }
    }

    pub fn max_tokens(&self) -> u32 {
        match self {
            ClaudeModel::Claude3Opus => 4096,
            ClaudeModel::Claude3Sonnet => 4096,
            ClaudeModel::Claude3Haiku => 4096,
            ClaudeModel::Claude35Sonnet => 8192,
            ClaudeModel::Claude35Haiku => 8192,
            ClaudeModel::Claude4Opus => 32000,
            ClaudeModel::Claude4Sonnet => 16000,
        }
    }

    pub fn context_window(&self) -> u32 {
        match self {
            ClaudeModel::Claude3Opus => 200000,
            ClaudeModel::Claude3Sonnet => 200000,
            ClaudeModel::Claude3Haiku => 200000,
            ClaudeModel::Claude35Sonnet => 200000,
            ClaudeModel::Claude35Haiku => 200000,
            ClaudeModel::Claude4Opus => 200000,
            ClaudeModel::Claude4Sonnet => 200000,
        }
    }

    pub fn cost_per_million_input(&self) -> f64 {
        match self {
            ClaudeModel::Claude3Opus => 15.0,
            ClaudeModel::Claude3Sonnet => 3.0,
            ClaudeModel::Claude3Haiku => 0.25,
            ClaudeModel::Claude35Sonnet => 3.0,
            ClaudeModel::Claude35Haiku => 0.80,
            ClaudeModel::Claude4Opus => 15.0,
            ClaudeModel::Claude4Sonnet => 3.0,
        }
    }

    pub fn cost_per_million_output(&self) -> f64 {
        match self {
            ClaudeModel::Claude3Opus => 75.0,
            ClaudeModel::Claude3Sonnet => 15.0,
            ClaudeModel::Claude3Haiku => 1.25,
            ClaudeModel::Claude35Sonnet => 15.0,
            ClaudeModel::Claude35Haiku => 4.0,
            ClaudeModel::Claude4Opus => 75.0,
            ClaudeModel::Claude4Sonnet => 15.0,
        }
    }
}

/// Message role
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// Message content types
#[derive(Debug, Clone)]
pub enum ContentBlock {
    /// Plain text content
    Text { text: String },
    /// Image content
    Image { source: ImageSource },
    /// Tool use request
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
    /// Tool result
    ToolResult {
        tool_use_id: String,
        content: String,
        is_error: bool,
    },
}

/// Image source
#[derive(Debug, Clone)]
pub struct ImageSource {
    pub media_type: String,
    pub data: String, // Base64 encoded
}

/// Message in conversation
#[derive(Debug, Clone)]
pub struct Message {
    pub role: Role,
    pub content: Vec<ContentBlock>,
}

impl Message {
    pub fn user(text: &str) -> Self {
        Self {
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: text.to_string(),
            }],
        }
    }

    pub fn assistant(text: &str) -> Self {
        Self {
            role: Role::Assistant,
            content: vec![ContentBlock::Text {
                text: text.to_string(),
            }],
        }
    }

    pub fn user_with_image(text: &str, image: ImageSource) -> Self {
        Self {
            role: Role::User,
            content: vec![
                ContentBlock::Image { source: image },
                ContentBlock::Text {
                    text: text.to_string(),
                },
            ],
        }
    }
}

/// Tool definition
#[derive(Debug, Clone)]
pub struct Tool {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
}

impl Tool {
    pub fn new(name: &str, description: &str) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        }
    }

    pub fn with_schema(mut self, schema: serde_json::Value) -> Self {
        self.input_schema = schema;
        self
    }
}

/// Stop reason
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    EndTurn,
    MaxTokens,
    StopSequence,
    ToolUse,
}

/// API response
#[derive(Debug, Clone)]
pub struct ApiResponse {
    pub id: String,
    pub model: String,
    pub content: Vec<ContentBlock>,
    pub stop_reason: Option<StopReason>,
    pub usage: Usage,
}

/// Token usage
#[derive(Debug, Clone, Default)]
pub struct Usage {
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub cache_creation_input_tokens: u32,
    pub cache_read_input_tokens: u32,
}

impl Usage {
    pub fn total_tokens(&self) -> u32 {
        self.input_tokens + self.output_tokens
    }

    pub fn calculate_cost(&self, model: ClaudeModel) -> f64 {
        let input_cost = (self.input_tokens as f64 / 1_000_000.0) * model.cost_per_million_input();
        let output_cost =
            (self.output_tokens as f64 / 1_000_000.0) * model.cost_per_million_output();
        input_cost + output_cost
    }
}

// ============================================================================
// Streaming Types
// ============================================================================

/// Server-sent event types
#[derive(Debug, Clone)]
pub enum StreamEvent {
    MessageStart {
        message_id: String,
        model: String,
    },
    ContentBlockStart {
        index: usize,
        content_type: String,
    },
    ContentBlockDelta {
        index: usize,
        delta: ContentDelta,
    },
    ContentBlockStop {
        index: usize,
    },
    MessageDelta {
        stop_reason: Option<StopReason>,
        usage: Option<Usage>,
    },
    MessageStop,
    Ping,
    Error {
        error_type: String,
        message: String,
    },
}

/// Content delta types
#[derive(Debug, Clone)]
pub enum ContentDelta {
    TextDelta { text: String },
    InputJsonDelta { partial_json: String },
}

/// Stream handler callback
pub type StreamCallback = Box<dyn FnMut(StreamEvent) -> bool + Send>;

// ============================================================================
// Request Builder
// ============================================================================

/// API request builder
pub struct RequestBuilder {
    model: ClaudeModel,
    messages: Vec<Message>,
    system: Option<String>,
    max_tokens: u32,
    temperature: Option<f32>,
    top_p: Option<f32>,
    top_k: Option<u32>,
    stop_sequences: Vec<String>,
    tools: Vec<Tool>,
    tool_choice: Option<ToolChoice>,
    stream: bool,
    metadata: HashMap<String, String>,
}

/// Tool choice options
#[derive(Debug, Clone)]
pub enum ToolChoice {
    Auto,
    Any,
    Tool { name: String },
}

impl RequestBuilder {
    pub fn new(model: ClaudeModel) -> Self {
        Self {
            model,
            messages: Vec::new(),
            system: None,
            max_tokens: model.max_tokens(),
            temperature: None,
            top_p: None,
            top_k: None,
            stop_sequences: Vec::new(),
            tools: Vec::new(),
            tool_choice: None,
            stream: false,
            metadata: HashMap::new(),
        }
    }

    pub fn system(mut self, system: &str) -> Self {
        self.system = Some(system.to_string());
        self
    }

    pub fn message(mut self, message: Message) -> Self {
        self.messages.push(message);
        self
    }

    pub fn messages(mut self, messages: Vec<Message>) -> Self {
        self.messages = messages;
        self
    }

    pub fn max_tokens(mut self, max_tokens: u32) -> Self {
        self.max_tokens = max_tokens;
        self
    }

    pub fn temperature(mut self, temperature: f32) -> Self {
        self.temperature = Some(temperature.clamp(0.0, 1.0));
        self
    }

    pub fn top_p(mut self, top_p: f32) -> Self {
        self.top_p = Some(top_p.clamp(0.0, 1.0));
        self
    }

    pub fn top_k(mut self, top_k: u32) -> Self {
        self.top_k = Some(top_k);
        self
    }

    pub fn stop_sequence(mut self, sequence: &str) -> Self {
        self.stop_sequences.push(sequence.to_string());
        self
    }

    pub fn tool(mut self, tool: Tool) -> Self {
        self.tools.push(tool);
        self
    }

    pub fn tools(mut self, tools: Vec<Tool>) -> Self {
        self.tools = tools;
        self
    }

    pub fn tool_choice(mut self, choice: ToolChoice) -> Self {
        self.tool_choice = Some(choice);
        self
    }

    pub fn stream(mut self) -> Self {
        self.stream = true;
        self
    }

    pub fn metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }

    /// Build JSON request body
    pub fn build(&self) -> serde_json::Value {
        let mut body = serde_json::json!({
            "model": self.model.as_str(),
            "messages": self.build_messages(),
            "max_tokens": self.max_tokens,
        });

        if let Some(system) = &self.system {
            body["system"] = serde_json::json!(system);
        }

        if let Some(temp) = self.temperature {
            body["temperature"] = serde_json::json!(temp);
        }

        if let Some(top_p) = self.top_p {
            body["top_p"] = serde_json::json!(top_p);
        }

        if let Some(top_k) = self.top_k {
            body["top_k"] = serde_json::json!(top_k);
        }

        if !self.stop_sequences.is_empty() {
            body["stop_sequences"] = serde_json::json!(self.stop_sequences);
        }

        if !self.tools.is_empty() {
            body["tools"] = serde_json::json!(self.build_tools());
        }

        if let Some(choice) = &self.tool_choice {
            body["tool_choice"] = match choice {
                ToolChoice::Auto => serde_json::json!({"type": "auto"}),
                ToolChoice::Any => serde_json::json!({"type": "any"}),
                ToolChoice::Tool { name } => serde_json::json!({"type": "tool", "name": name}),
            };
        }

        if self.stream {
            body["stream"] = serde_json::json!(true);
        }

        if !self.metadata.is_empty() {
            body["metadata"] = serde_json::json!(self.metadata);
        }

        body
    }

    fn build_messages(&self) -> Vec<serde_json::Value> {
        self.messages
            .iter()
            .map(|msg| {
                serde_json::json!({
                    "role": msg.role.as_str(),
                    "content": self.build_content(&msg.content),
                })
            })
            .collect()
    }

    fn build_content(&self, blocks: &[ContentBlock]) -> serde_json::Value {
        if blocks.len() == 1 {
            if let ContentBlock::Text { text } = &blocks[0] {
                return serde_json::json!(text);
            }
        }

        let content: Vec<serde_json::Value> = blocks
            .iter()
            .map(|block| match block {
                ContentBlock::Text { text } => serde_json::json!({
                    "type": "text",
                    "text": text,
                }),
                ContentBlock::Image { source } => serde_json::json!({
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": source.media_type,
                        "data": source.data,
                    }
                }),
                ContentBlock::ToolUse { id, name, input } => serde_json::json!({
                    "type": "tool_use",
                    "id": id,
                    "name": name,
                    "input": input,
                }),
                ContentBlock::ToolResult {
                    tool_use_id,
                    content,
                    is_error,
                } => serde_json::json!({
                    "type": "tool_result",
                    "tool_use_id": tool_use_id,
                    "content": content,
                    "is_error": is_error,
                }),
            })
            .collect();

        serde_json::json!(content)
    }

    fn build_tools(&self) -> Vec<serde_json::Value> {
        self.tools
            .iter()
            .map(|tool| {
                serde_json::json!({
                    "name": tool.name,
                    "description": tool.description,
                    "input_schema": tool.input_schema,
                })
            })
            .collect()
    }
}

// ============================================================================
// Client Configuration
// ============================================================================

/// Client configuration
#[derive(Clone)]
pub struct ClientConfig {
    pub api_key: String,
    pub base_url: String,
    pub timeout: Duration,
    pub max_retries: u32,
    pub retry_delay: Duration,
    pub anthropic_version: String,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            api_key: String::new(),
            base_url: "https://api.anthropic.com".to_string(),
            timeout: Duration::from_secs(60),
            max_retries: 3,
            retry_delay: Duration::from_millis(1000),
            anthropic_version: "2023-06-01".to_string(),
        }
    }
}

impl ClientConfig {
    pub fn new(api_key: &str) -> Self {
        Self {
            api_key: api_key.to_string(),
            ..Default::default()
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }
}

// ============================================================================
// Anthropic Client
// ============================================================================

/// Anthropic API client
pub struct AnthropicClient {
    config: ClientConfig,
    stats: ClientStats,
}

/// Client statistics
#[derive(Debug, Default)]
pub struct ClientStats {
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub total_cost: f64,
    pub total_latency_ms: u64,
}

/// API Error
#[derive(Debug)]
pub enum ApiError {
    InvalidApiKey,
    RateLimited { retry_after: Option<Duration> },
    Overloaded,
    InvalidRequest(String),
    ServerError(String),
    NetworkError(String),
    Timeout,
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiError::InvalidApiKey => write!(f, "Invalid API key"),
            ApiError::RateLimited { retry_after } => {
                if let Some(d) = retry_after {
                    write!(f, "Rate limited, retry after {:?}", d)
                } else {
                    write!(f, "Rate limited")
                }
            }
            ApiError::Overloaded => write!(f, "API overloaded"),
            ApiError::InvalidRequest(msg) => write!(f, "Invalid request: {}", msg),
            ApiError::ServerError(msg) => write!(f, "Server error: {}", msg),
            ApiError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            ApiError::Timeout => write!(f, "Request timeout"),
        }
    }
}

impl std::error::Error for ApiError {}

impl AnthropicClient {
    pub fn new(config: ClientConfig) -> Self {
        Self {
            config,
            stats: ClientStats::default(),
        }
    }

    pub fn from_env() -> Result<Self, ApiError> {
        let api_key = std::env::var("ANTHROPIC_API_KEY").map_err(|_| ApiError::InvalidApiKey)?;

        Ok(Self::new(ClientConfig::new(&api_key)))
    }

    /// Send a message (non-streaming)
    pub fn send(&mut self, request: &RequestBuilder) -> Result<ApiResponse, ApiError> {
        let start = Instant::now();
        self.stats.total_requests += 1;

        // Build request
        let body = request.build();

        // Simulate API call (in real implementation, use reqwest or similar)
        let result = self.simulate_api_call(&body);

        match &result {
            Ok(response) => {
                self.stats.successful_requests += 1;
                self.stats.total_input_tokens += response.usage.input_tokens as u64;
                self.stats.total_output_tokens += response.usage.output_tokens as u64;
                self.stats.total_cost += response.usage.calculate_cost(request.model);
            }
            Err(_) => {
                self.stats.failed_requests += 1;
            }
        }

        self.stats.total_latency_ms += start.elapsed().as_millis() as u64;

        result
    }

    /// Send a streaming message
    pub fn stream(
        &mut self,
        request: &RequestBuilder,
        mut callback: StreamCallback,
    ) -> Result<ApiResponse, ApiError> {
        let start = Instant::now();
        self.stats.total_requests += 1;

        // Build request with streaming
        let mut streaming_request = RequestBuilder::new(request.model);
        streaming_request.messages = request.messages.clone();
        streaming_request.system = request.system.clone();
        streaming_request.max_tokens = request.max_tokens;
        streaming_request.stream = true;

        // Simulate streaming events
        let events = self.simulate_streaming_events();

        let mut full_text = String::new();
        let mut usage = Usage::default();

        for event in events {
            match &event {
                StreamEvent::ContentBlockDelta { delta, .. } => {
                    if let ContentDelta::TextDelta { text } = delta {
                        full_text.push_str(text);
                    }
                }
                StreamEvent::MessageDelta { usage: Some(u), .. } => {
                    usage = u.clone();
                }
                _ => {}
            }

            if !callback(event) {
                break;
            }
        }

        self.stats.successful_requests += 1;
        self.stats.total_input_tokens += usage.input_tokens as u64;
        self.stats.total_output_tokens += usage.output_tokens as u64;
        self.stats.total_cost += usage.calculate_cost(request.model);
        self.stats.total_latency_ms += start.elapsed().as_millis() as u64;

        Ok(ApiResponse {
            id: "msg_demo_123".to_string(),
            model: request.model.as_str().to_string(),
            content: vec![ContentBlock::Text { text: full_text }],
            stop_reason: Some(StopReason::EndTurn),
            usage,
        })
    }

    /// Get client statistics
    pub fn stats(&self) -> &ClientStats {
        &self.stats
    }

    /// Build headers for request
    pub fn build_headers(&self) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("x-api-key".to_string(), self.config.api_key.clone());
        headers.insert(
            "anthropic-version".to_string(),
            self.config.anthropic_version.clone(),
        );
        headers.insert("content-type".to_string(), "application/json".to_string());
        headers
    }

    // Simulation methods for demonstration

    fn simulate_api_call(&self, _body: &serde_json::Value) -> Result<ApiResponse, ApiError> {
        // Simulate successful response
        Ok(ApiResponse {
            id: format!("msg_{}", self.generate_id()),
            model: "claude-3-5-sonnet-20241022".to_string(),
            content: vec![ContentBlock::Text {
                text: "Hello! I'm Claude, an AI assistant. How can I help you today?".to_string(),
            }],
            stop_reason: Some(StopReason::EndTurn),
            usage: Usage {
                input_tokens: 25,
                output_tokens: 15,
                cache_creation_input_tokens: 0,
                cache_read_input_tokens: 0,
            },
        })
    }

    fn simulate_streaming_events(&self) -> Vec<StreamEvent> {
        let response_text = "Hello! I'm Claude, an AI assistant. How can I help you today?";
        let words: Vec<&str> = response_text.split(' ').collect();

        let mut events = vec![
            StreamEvent::MessageStart {
                message_id: format!("msg_{}", self.generate_id()),
                model: "claude-3-5-sonnet-20241022".to_string(),
            },
            StreamEvent::ContentBlockStart {
                index: 0,
                content_type: "text".to_string(),
            },
        ];

        // Stream word by word
        for (i, word) in words.iter().enumerate() {
            let text = if i == 0 {
                word.to_string()
            } else {
                format!(" {}", word)
            };

            events.push(StreamEvent::ContentBlockDelta {
                index: 0,
                delta: ContentDelta::TextDelta { text },
            });
        }

        events.push(StreamEvent::ContentBlockStop { index: 0 });
        events.push(StreamEvent::MessageDelta {
            stop_reason: Some(StopReason::EndTurn),
            usage: Some(Usage {
                input_tokens: 25,
                output_tokens: 15,
                cache_creation_input_tokens: 0,
                cache_read_input_tokens: 0,
            }),
        });
        events.push(StreamEvent::MessageStop);

        events
    }

    fn generate_id(&self) -> String {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        format!("{:x}", timestamp)
    }
}

// ============================================================================
// Conversation Manager
// ============================================================================

/// Manages multi-turn conversations
pub struct Conversation {
    messages: Vec<Message>,
    system: Option<String>,
    model: ClaudeModel,
    tools: Vec<Tool>,
}

impl Conversation {
    pub fn new(model: ClaudeModel) -> Self {
        Self {
            messages: Vec::new(),
            system: None,
            model,
            tools: Vec::new(),
        }
    }

    pub fn with_system(mut self, system: &str) -> Self {
        self.system = Some(system.to_string());
        self
    }

    pub fn with_tools(mut self, tools: Vec<Tool>) -> Self {
        self.tools = tools;
        self
    }

    pub fn add_user_message(&mut self, text: &str) {
        self.messages.push(Message::user(text));
    }

    pub fn add_assistant_message(&mut self, text: &str) {
        self.messages.push(Message::assistant(text));
    }

    pub fn add_tool_result(&mut self, tool_use_id: &str, content: &str, is_error: bool) {
        self.messages.push(Message {
            role: Role::User,
            content: vec![ContentBlock::ToolResult {
                tool_use_id: tool_use_id.to_string(),
                content: content.to_string(),
                is_error,
            }],
        });
    }

    /// Build request for next turn
    pub fn build_request(&self) -> RequestBuilder {
        let mut builder = RequestBuilder::new(self.model)
            .messages(self.messages.clone())
            .tools(self.tools.clone());

        if let Some(system) = &self.system {
            builder = builder.system(system);
        }

        builder
    }

    /// Get message history
    pub fn messages(&self) -> &[Message] {
        &self.messages
    }

    /// Clear conversation
    pub fn clear(&mut self) {
        self.messages.clear();
    }

    /// Get token estimate
    pub fn estimate_tokens(&self) -> u32 {
        // Rough estimate: ~4 characters per token
        let mut chars = 0;

        if let Some(system) = &self.system {
            chars += system.len();
        }

        for msg in &self.messages {
            for block in &msg.content {
                if let ContentBlock::Text { text } = block {
                    chars += text.len();
                }
            }
        }

        (chars / 4) as u32
    }
}

// ============================================================================
// Main Demonstration
// ============================================================================

fn main() {
    println!("=== Anthropic Claude API Streaming Client ===\n");

    // Example 1: Client configuration
    println!("1. Client Configuration:");
    let config = ClientConfig::new("sk-ant-demo-key")
        .with_timeout(Duration::from_secs(120))
        .with_retries(3);

    let mut client = AnthropicClient::new(config);
    println!("   Base URL: {}", client.config.base_url);
    println!("   Timeout: {:?}", client.config.timeout);

    // Example 2: Simple request
    println!("\n2. Simple Request:");
    let request = RequestBuilder::new(ClaudeModel::Claude35Sonnet)
        .system("You are a helpful assistant.")
        .message(Message::user("Hello, who are you?"))
        .max_tokens(1024)
        .temperature(0.7);

    println!("   Request JSON:");
    let json = request.build();
    println!("   {}", serde_json::to_string_pretty(&json).unwrap());

    // Example 3: Send request
    println!("\n3. Sending Request:");
    match client.send(&request) {
        Ok(response) => {
            println!("   Response ID: {}", response.id);
            println!("   Model: {}", response.model);
            if let Some(ContentBlock::Text { text }) = response.content.first() {
                println!("   Content: {}", text);
            }
            println!(
                "   Usage: {} input, {} output tokens",
                response.usage.input_tokens, response.usage.output_tokens
            );
            println!(
                "   Cost: ${:.6}",
                response.usage.calculate_cost(ClaudeModel::Claude35Sonnet)
            );
        }
        Err(e) => println!("   Error: {}", e),
    }

    // Example 4: Streaming
    println!("\n4. Streaming Response:");
    let stream_request = RequestBuilder::new(ClaudeModel::Claude35Sonnet)
        .message(Message::user("Tell me a short joke."))
        .stream();

    print!("   ");
    let _ = io::stdout().flush();

    let _ = client.stream(
        &stream_request,
        Box::new(|event| {
            match event {
                StreamEvent::ContentBlockDelta { delta, .. } => {
                    if let ContentDelta::TextDelta { text } = delta {
                        print!("{}", text);
                        let _ = io::stdout().flush();
                    }
                }
                StreamEvent::MessageStop => {
                    println!();
                }
                _ => {}
            }
            true
        }),
    );

    // Example 5: Tool use
    println!("\n5. Tool Definition:");
    let weather_tool = Tool::new("get_weather", "Get the current weather for a location")
        .with_schema(serde_json::json!({
            "type": "object",
            "properties": {
                "location": {
                    "type": "string",
                    "description": "City and country, e.g., 'London, UK'"
                },
                "unit": {
                    "type": "string",
                    "enum": ["celsius", "fahrenheit"],
                    "description": "Temperature unit"
                }
            },
            "required": ["location"]
        }));

    let tool_request = RequestBuilder::new(ClaudeModel::Claude35Sonnet)
        .message(Message::user("What's the weather in Tokyo?"))
        .tool(weather_tool)
        .tool_choice(ToolChoice::Auto);

    println!("   Tool: get_weather");
    println!("   Request includes tool definition");

    // Example 6: Conversation management
    println!("\n6. Multi-turn Conversation:");
    let mut conversation = Conversation::new(ClaudeModel::Claude35Sonnet)
        .with_system("You are a helpful coding assistant.");

    conversation.add_user_message("What is Rust?");
    conversation.add_assistant_message("Rust is a systems programming language...");
    conversation.add_user_message("What are its main features?");

    println!(
        "   Messages in conversation: {}",
        conversation.messages().len()
    );
    println!("   Estimated tokens: {}", conversation.estimate_tokens());

    let conv_request = conversation.build_request();
    println!(
        "   Request built with {} messages",
        conversation.messages().len()
    );

    // Example 7: Image input
    println!("\n7. Vision/Image Input:");
    let image_source = ImageSource {
        media_type: "image/png".to_string(),
        data: "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==".to_string(),
    };

    let vision_message = Message::user_with_image("What do you see in this image?", image_source);
    println!("   Created message with image content");
    println!("   Content blocks: {}", vision_message.content.len());

    // Example 8: Model comparison
    println!("\n8. Model Comparison:");
    let models = [
        ClaudeModel::Claude3Haiku,
        ClaudeModel::Claude35Sonnet,
        ClaudeModel::Claude4Opus,
    ];

    for model in models {
        println!(
            "   {} - Max tokens: {}, Context: {}k, Input: ${}/M, Output: ${}/M",
            model.as_str(),
            model.max_tokens(),
            model.context_window() / 1000,
            model.cost_per_million_input(),
            model.cost_per_million_output()
        );
    }

    // Example 9: Client statistics
    println!("\n9. Client Statistics:");
    let stats = client.stats();
    println!("   Total requests: {}", stats.total_requests);
    println!("   Successful: {}", stats.successful_requests);
    println!("   Failed: {}", stats.failed_requests);
    println!(
        "   Total tokens: {} input, {} output",
        stats.total_input_tokens, stats.total_output_tokens
    );
    println!("   Total cost: ${:.4}", stats.total_cost);
    println!("   Total latency: {}ms", stats.total_latency_ms);

    // Example 10: Request headers
    println!("\n10. Request Headers:");
    let headers = client.build_headers();
    for (key, value) in &headers {
        let display_value = if key == "x-api-key" {
            "sk-ant-***".to_string()
        } else {
            value.clone()
        };
        println!("   {}: {}", key, display_value);
    }

    println!("\n=== Anthropic Client Complete ===");
}

// ============================================================================
// Tests
// ============================================================================

// Simple JSON value for testing without serde dependency in tests
mod serde_json {
    #[derive(Debug, Clone)]
    pub enum Value {
        Null,
        Bool(bool),
        Number(f64),
        String(String),
        Array(Vec<Value>),
        Object(std::collections::HashMap<String, Value>),
    }

    #[macro_export]
    macro_rules! json {
        (null) => { serde_json::Value::Null };
        (true) => { serde_json::Value::Bool(true) };
        (false) => { serde_json::Value::Bool(false) };
        ($s:literal) => { serde_json::Value::String($s.to_string()) };
        ({ $($key:literal : $value:tt),* $(,)? }) => {{
            let mut map = std::collections::HashMap::new();
            $(
                map.insert($key.to_string(), json!($value));
            )*
            serde_json::Value::Object(map)
        }};
        ([ $($value:tt),* $(,)? ]) => {{
            serde_json::Value::Array(vec![ $(json!($value)),* ])
        }};
        ($e:expr) => { serde_json::Value::from($e) };
    }

    pub use json;

    impl From<String> for Value {
        fn from(s: String) -> Self {
            Value::String(s)
        }
    }

    impl From<&str> for Value {
        fn from(s: &str) -> Self {
            Value::String(s.to_string())
        }
    }

    impl From<i32> for Value {
        fn from(n: i32) -> Self {
            Value::Number(n as f64)
        }
    }

    impl From<u32> for Value {
        fn from(n: u32) -> Self {
            Value::Number(n as f64)
        }
    }

    impl From<f32> for Value {
        fn from(n: f32) -> Self {
            Value::Number(n as f64)
        }
    }

    impl From<bool> for Value {
        fn from(b: bool) -> Self {
            Value::Bool(b)
        }
    }

    pub fn to_string_pretty(_value: &Value) -> Result<String, ()> {
        Ok("{}".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_properties() {
        let model = ClaudeModel::Claude35Sonnet;
        assert_eq!(model.as_str(), "claude-3-5-sonnet-20241022");
        assert!(model.max_tokens() > 0);
        assert!(model.context_window() > 0);
    }

    #[test]
    fn test_usage_cost_calculation() {
        let usage = Usage {
            input_tokens: 1000,
            output_tokens: 500,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
        };

        let cost = usage.calculate_cost(ClaudeModel::Claude35Sonnet);
        assert!(cost > 0.0);
    }

    #[test]
    fn test_usage_total_tokens() {
        let usage = Usage {
            input_tokens: 100,
            output_tokens: 50,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
        };

        assert_eq!(usage.total_tokens(), 150);
    }

    #[test]
    fn test_message_creation() {
        let msg = Message::user("Hello");
        assert_eq!(msg.role, Role::User);
        assert_eq!(msg.content.len(), 1);
    }

    #[test]
    fn test_assistant_message() {
        let msg = Message::assistant("Hi there");
        assert_eq!(msg.role, Role::Assistant);
    }

    #[test]
    fn test_tool_creation() {
        let tool = Tool::new("test_tool", "A test tool");
        assert_eq!(tool.name, "test_tool");
        assert_eq!(tool.description, "A test tool");
    }

    #[test]
    fn test_request_builder() {
        let request = RequestBuilder::new(ClaudeModel::Claude35Sonnet)
            .system("You are helpful")
            .message(Message::user("Hello"))
            .max_tokens(100)
            .temperature(0.5);

        assert_eq!(request.model, ClaudeModel::Claude35Sonnet);
        assert!(request.system.is_some());
        assert_eq!(request.messages.len(), 1);
        assert_eq!(request.max_tokens, 100);
    }

    #[test]
    fn test_temperature_clamping() {
        let request = RequestBuilder::new(ClaudeModel::Claude35Sonnet).temperature(1.5);

        assert_eq!(request.temperature, Some(1.0));

        let request = RequestBuilder::new(ClaudeModel::Claude35Sonnet).temperature(-0.5);

        assert_eq!(request.temperature, Some(0.0));
    }

    #[test]
    fn test_client_config() {
        let config = ClientConfig::new("test-key")
            .with_timeout(Duration::from_secs(30))
            .with_retries(5);

        assert_eq!(config.api_key, "test-key");
        assert_eq!(config.timeout, Duration::from_secs(30));
        assert_eq!(config.max_retries, 5);
    }

    #[test]
    fn test_client_creation() {
        let config = ClientConfig::new("test-key");
        let client = AnthropicClient::new(config);

        assert_eq!(client.stats().total_requests, 0);
    }

    #[test]
    fn test_conversation_creation() {
        let conversation =
            Conversation::new(ClaudeModel::Claude35Sonnet).with_system("You are helpful");

        assert!(conversation.system.is_some());
        assert!(conversation.messages().is_empty());
    }

    #[test]
    fn test_conversation_messages() {
        let mut conversation = Conversation::new(ClaudeModel::Claude35Sonnet);
        conversation.add_user_message("Hello");
        conversation.add_assistant_message("Hi");

        assert_eq!(conversation.messages().len(), 2);
    }

    #[test]
    fn test_conversation_clear() {
        let mut conversation = Conversation::new(ClaudeModel::Claude35Sonnet);
        conversation.add_user_message("Hello");
        conversation.clear();

        assert!(conversation.messages().is_empty());
    }

    #[test]
    fn test_conversation_token_estimate() {
        let mut conversation = Conversation::new(ClaudeModel::Claude35Sonnet);
        conversation.add_user_message("Hello world");

        let estimate = conversation.estimate_tokens();
        assert!(estimate > 0);
    }

    #[test]
    fn test_role_as_str() {
        assert_eq!(Role::User.as_str(), "user");
        assert_eq!(Role::Assistant.as_str(), "assistant");
    }

    #[test]
    fn test_stop_reason() {
        let reason = StopReason::EndTurn;
        assert_eq!(reason, StopReason::EndTurn);
    }

    #[test]
    fn test_image_source() {
        let source = ImageSource {
            media_type: "image/png".to_string(),
            data: "base64data".to_string(),
        };

        assert_eq!(source.media_type, "image/png");
    }

    #[test]
    fn test_content_block_variants() {
        let text = ContentBlock::Text {
            text: "hello".to_string(),
        };
        matches!(text, ContentBlock::Text { .. });

        let tool_use = ContentBlock::ToolUse {
            id: "id".to_string(),
            name: "tool".to_string(),
            input: serde_json::Value::Null,
        };
        matches!(tool_use, ContentBlock::ToolUse { .. });
    }

    #[test]
    fn test_api_error_display() {
        let err = ApiError::InvalidApiKey;
        assert_eq!(format!("{}", err), "Invalid API key");

        let err = ApiError::RateLimited {
            retry_after: Some(Duration::from_secs(60)),
        };
        assert!(format!("{}", err).contains("Rate limited"));
    }

    #[test]
    fn test_client_headers() {
        let config = ClientConfig::new("test-key");
        let client = AnthropicClient::new(config);
        let headers = client.build_headers();

        assert!(headers.contains_key("x-api-key"));
        assert!(headers.contains_key("anthropic-version"));
        assert!(headers.contains_key("content-type"));
    }
}
