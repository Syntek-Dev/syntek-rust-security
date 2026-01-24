//! Google Gemini API Client - Multimodal AI Integration
//!
//! This example demonstrates building a secure Rust client for Google's
//! Gemini API with support for multimodal inputs, streaming, and function calling.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Gemini model variants
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeminiModel {
    /// Gemini 1.5 Pro - Most capable
    Gemini15Pro,
    /// Gemini 1.5 Flash - Fast and efficient
    Gemini15Flash,
    /// Gemini 1.0 Pro - Previous generation
    Gemini10Pro,
    /// Gemini 1.0 Pro Vision - Multimodal
    Gemini10ProVision,
    /// Gemini 2.0 Flash - Latest model
    Gemini20Flash,
}

impl GeminiModel {
    pub fn model_id(&self) -> &'static str {
        match self {
            Self::Gemini15Pro => "gemini-1.5-pro",
            Self::Gemini15Flash => "gemini-1.5-flash",
            Self::Gemini10Pro => "gemini-1.0-pro",
            Self::Gemini10ProVision => "gemini-1.0-pro-vision",
            Self::Gemini20Flash => "gemini-2.0-flash",
        }
    }

    pub fn max_tokens(&self) -> u32 {
        match self {
            Self::Gemini15Pro => 8192,
            Self::Gemini15Flash => 8192,
            Self::Gemini10Pro => 2048,
            Self::Gemini10ProVision => 4096,
            Self::Gemini20Flash => 8192,
        }
    }

    pub fn supports_vision(&self) -> bool {
        matches!(
            self,
            Self::Gemini15Pro | Self::Gemini15Flash | Self::Gemini10ProVision | Self::Gemini20Flash
        )
    }

    pub fn supports_function_calling(&self) -> bool {
        matches!(
            self,
            Self::Gemini15Pro | Self::Gemini15Flash | Self::Gemini20Flash
        )
    }

    pub fn context_window(&self) -> u32 {
        match self {
            Self::Gemini15Pro => 1000000, // 1M context
            Self::Gemini15Flash => 1000000,
            Self::Gemini10Pro => 32000,
            Self::Gemini10ProVision => 16000,
            Self::Gemini20Flash => 1000000,
        }
    }
}

/// Content part types
#[derive(Debug, Clone)]
pub enum ContentPart {
    Text(String),
    Image {
        mime_type: String,
        data: Vec<u8>,
    },
    ImageUrl {
        url: String,
    },
    Video {
        mime_type: String,
        data: Vec<u8>,
    },
    Audio {
        mime_type: String,
        data: Vec<u8>,
    },
    FunctionCall {
        name: String,
        args: HashMap<String, String>,
    },
    FunctionResponse {
        name: String,
        response: String,
    },
}

/// Message role
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    User,
    Model,
    Function,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Model => "model",
            Self::Function => "function",
        }
    }
}

/// Content message
#[derive(Debug, Clone)]
pub struct Content {
    pub role: Role,
    pub parts: Vec<ContentPart>,
}

impl Content {
    pub fn text(role: Role, text: impl Into<String>) -> Self {
        Self {
            role,
            parts: vec![ContentPart::Text(text.into())],
        }
    }

    pub fn user(text: impl Into<String>) -> Self {
        Self::text(Role::User, text)
    }

    pub fn model(text: impl Into<String>) -> Self {
        Self::text(Role::Model, text)
    }

    pub fn with_image(
        role: Role,
        text: impl Into<String>,
        image_data: Vec<u8>,
        mime_type: &str,
    ) -> Self {
        Self {
            role,
            parts: vec![
                ContentPart::Text(text.into()),
                ContentPart::Image {
                    mime_type: mime_type.to_string(),
                    data: image_data,
                },
            ],
        }
    }
}

/// Function declaration for tool use
#[derive(Debug, Clone)]
pub struct FunctionDeclaration {
    pub name: String,
    pub description: String,
    pub parameters: HashMap<String, ParameterSpec>,
    pub required: Vec<String>,
}

/// Parameter specification
#[derive(Debug, Clone)]
pub struct ParameterSpec {
    pub param_type: String,
    pub description: String,
    pub enum_values: Option<Vec<String>>,
}

impl FunctionDeclaration {
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            parameters: HashMap::new(),
            required: Vec::new(),
        }
    }

    pub fn add_parameter(
        mut self,
        name: impl Into<String>,
        param_type: impl Into<String>,
        description: impl Into<String>,
        required: bool,
    ) -> Self {
        let name = name.into();
        self.parameters.insert(
            name.clone(),
            ParameterSpec {
                param_type: param_type.into(),
                description: description.into(),
                enum_values: None,
            },
        );
        if required {
            self.required.push(name);
        }
        self
    }
}

/// Safety settings
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HarmCategory {
    HateSpeech,
    DangerousContent,
    Harassment,
    SexuallyExplicit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HarmBlockThreshold {
    BlockNone,
    BlockLowAndAbove,
    BlockMediumAndAbove,
    BlockOnlyHigh,
}

#[derive(Debug, Clone)]
pub struct SafetySetting {
    pub category: HarmCategory,
    pub threshold: HarmBlockThreshold,
}

/// Generation configuration
#[derive(Debug, Clone)]
pub struct GenerationConfig {
    pub temperature: f32,
    pub top_p: f32,
    pub top_k: u32,
    pub max_output_tokens: u32,
    pub stop_sequences: Vec<String>,
    pub candidate_count: u32,
}

impl Default for GenerationConfig {
    fn default() -> Self {
        Self {
            temperature: 0.7,
            top_p: 0.95,
            top_k: 40,
            max_output_tokens: 2048,
            stop_sequences: Vec::new(),
            candidate_count: 1,
        }
    }
}

impl GenerationConfig {
    pub fn deterministic() -> Self {
        Self {
            temperature: 0.0,
            top_p: 1.0,
            top_k: 1,
            ..Default::default()
        }
    }

    pub fn creative() -> Self {
        Self {
            temperature: 1.0,
            top_p: 0.95,
            top_k: 64,
            ..Default::default()
        }
    }

    pub fn balanced() -> Self {
        Self::default()
    }
}

/// Gemini API errors
#[derive(Debug, Clone)]
pub enum GeminiError {
    ApiKeyMissing,
    InvalidRequest { message: String },
    RateLimited { retry_after: Duration },
    ServerError { status: u16, message: String },
    NetworkError { message: String },
    SafetyBlocked { categories: Vec<HarmCategory> },
    InvalidResponse { message: String },
    FunctionCallRequired { function_name: String },
    QuotaExceeded,
    ModelNotAvailable { model: String },
}

impl std::fmt::Display for GeminiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiKeyMissing => write!(f, "API key not configured"),
            Self::InvalidRequest { message } => write!(f, "Invalid request: {}", message),
            Self::RateLimited { retry_after } => {
                write!(f, "Rate limited, retry after {:?}", retry_after)
            }
            Self::ServerError { status, message } => {
                write!(f, "Server error ({}): {}", status, message)
            }
            Self::NetworkError { message } => write!(f, "Network error: {}", message),
            Self::SafetyBlocked { categories } => {
                write!(f, "Blocked by safety filters: {:?}", categories)
            }
            Self::InvalidResponse { message } => write!(f, "Invalid response: {}", message),
            Self::FunctionCallRequired { function_name } => {
                write!(f, "Function call required: {}", function_name)
            }
            Self::QuotaExceeded => write!(f, "API quota exceeded"),
            Self::ModelNotAvailable { model } => write!(f, "Model not available: {}", model),
        }
    }
}

impl std::error::Error for GeminiError {}

/// Response candidate
#[derive(Debug, Clone)]
pub struct Candidate {
    pub content: Content,
    pub finish_reason: String,
    pub safety_ratings: Vec<SafetyRating>,
    pub citation_metadata: Option<CitationMetadata>,
}

#[derive(Debug, Clone)]
pub struct SafetyRating {
    pub category: HarmCategory,
    pub probability: String,
    pub blocked: bool,
}

#[derive(Debug, Clone)]
pub struct CitationMetadata {
    pub citations: Vec<Citation>,
}

#[derive(Debug, Clone)]
pub struct Citation {
    pub start_index: u32,
    pub end_index: u32,
    pub uri: String,
    pub title: Option<String>,
}

/// Generation response
#[derive(Debug, Clone)]
pub struct GenerationResponse {
    pub candidates: Vec<Candidate>,
    pub usage: UsageMetadata,
    pub model_version: String,
}

#[derive(Debug, Clone)]
pub struct UsageMetadata {
    pub prompt_tokens: u32,
    pub candidates_tokens: u32,
    pub total_tokens: u32,
}

impl GenerationResponse {
    pub fn text(&self) -> Option<&str> {
        self.candidates.first().and_then(|c| {
            c.content.parts.iter().find_map(|p| {
                if let ContentPart::Text(t) = p {
                    Some(t.as_str())
                } else {
                    None
                }
            })
        })
    }

    pub fn function_calls(&self) -> Vec<(&str, &HashMap<String, String>)> {
        self.candidates
            .iter()
            .flat_map(|c| {
                c.content.parts.iter().filter_map(|p| {
                    if let ContentPart::FunctionCall { name, args } = p {
                        Some((name.as_str(), args))
                    } else {
                        None
                    }
                })
            })
            .collect()
    }
}

/// Streaming chunk
#[derive(Debug, Clone)]
pub struct StreamChunk {
    pub text: String,
    pub is_final: bool,
    pub safety_ratings: Option<Vec<SafetyRating>>,
}

/// Usage tracking
#[derive(Debug, Default)]
pub struct UsageTracker {
    total_requests: AtomicU64,
    total_prompt_tokens: AtomicU64,
    total_completion_tokens: AtomicU64,
    errors: AtomicU64,
}

impl UsageTracker {
    pub fn record_usage(&self, usage: &UsageMetadata) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.total_prompt_tokens
            .fetch_add(usage.prompt_tokens as u64, Ordering::Relaxed);
        self.total_completion_tokens
            .fetch_add(usage.candidates_tokens as u64, Ordering::Relaxed);
    }

    pub fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn summary(&self) -> UsageSummary {
        UsageSummary {
            total_requests: self.total_requests.load(Ordering::Relaxed),
            total_prompt_tokens: self.total_prompt_tokens.load(Ordering::Relaxed),
            total_completion_tokens: self.total_completion_tokens.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
pub struct UsageSummary {
    pub total_requests: u64,
    pub total_prompt_tokens: u64,
    pub total_completion_tokens: u64,
    pub errors: u64,
}

/// Rate limiter for Gemini API
pub struct RateLimiter {
    requests_per_minute: u32,
    tokens_per_minute: u32,
    request_times: Mutex<Vec<Instant>>,
    token_counts: Mutex<Vec<(Instant, u32)>>,
}

impl RateLimiter {
    pub fn new(requests_per_minute: u32, tokens_per_minute: u32) -> Self {
        Self {
            requests_per_minute,
            tokens_per_minute,
            request_times: Mutex::new(Vec::new()),
            token_counts: Mutex::new(Vec::new()),
        }
    }

    pub fn check_request(&self) -> Result<(), Duration> {
        let now = Instant::now();
        let one_minute_ago = now - Duration::from_secs(60);

        let mut times = self.request_times.lock().unwrap();
        times.retain(|t| *t > one_minute_ago);

        if times.len() >= self.requests_per_minute as usize {
            let oldest = times[0];
            let wait = Duration::from_secs(60) - (now - oldest);
            return Err(wait);
        }

        times.push(now);
        Ok(())
    }

    pub fn check_tokens(&self, tokens: u32) -> Result<(), Duration> {
        let now = Instant::now();
        let one_minute_ago = now - Duration::from_secs(60);

        let mut counts = self.token_counts.lock().unwrap();
        counts.retain(|(t, _)| *t > one_minute_ago);

        let current_tokens: u32 = counts.iter().map(|(_, c)| c).sum();
        if current_tokens + tokens > self.tokens_per_minute {
            let oldest = counts.first().map(|(t, _)| *t).unwrap_or(now);
            let wait = Duration::from_secs(60) - (now - oldest);
            return Err(wait);
        }

        counts.push((now, tokens));
        Ok(())
    }
}

/// Gemini client configuration
#[derive(Debug, Clone)]
pub struct GeminiConfig {
    pub api_key: String,
    pub default_model: GeminiModel,
    pub default_config: GenerationConfig,
    pub safety_settings: Vec<SafetySetting>,
    pub timeout: Duration,
    pub max_retries: u32,
}

impl GeminiConfig {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            default_model: GeminiModel::Gemini15Flash,
            default_config: GenerationConfig::default(),
            safety_settings: Vec::new(),
            timeout: Duration::from_secs(60),
            max_retries: 3,
        }
    }

    pub fn with_model(mut self, model: GeminiModel) -> Self {
        self.default_model = model;
        self
    }

    pub fn with_safety_settings(mut self, settings: Vec<SafetySetting>) -> Self {
        self.safety_settings = settings;
        self
    }
}

/// Main Gemini client
pub struct GeminiClient {
    config: GeminiConfig,
    usage: Arc<UsageTracker>,
    rate_limiter: Arc<RateLimiter>,
}

impl GeminiClient {
    pub fn new(config: GeminiConfig) -> Self {
        Self {
            config,
            usage: Arc::new(UsageTracker::default()),
            rate_limiter: Arc::new(RateLimiter::new(60, 60000)),
        }
    }

    /// Simple text generation
    pub fn generate(&self, prompt: &str) -> Result<GenerationResponse, GeminiError> {
        let contents = vec![Content::user(prompt)];
        self.generate_content(&contents, None, None)
    }

    /// Generate with custom config
    pub fn generate_with_config(
        &self,
        prompt: &str,
        config: GenerationConfig,
    ) -> Result<GenerationResponse, GeminiError> {
        let contents = vec![Content::user(prompt)];
        self.generate_content(&contents, Some(config), None)
    }

    /// Multi-turn chat
    pub fn chat(&self, contents: &[Content]) -> Result<GenerationResponse, GeminiError> {
        self.generate_content(contents, None, None)
    }

    /// Generate with function calling
    pub fn generate_with_functions(
        &self,
        contents: &[Content],
        functions: &[FunctionDeclaration],
    ) -> Result<GenerationResponse, GeminiError> {
        self.generate_content(contents, None, Some(functions))
    }

    /// Core generation method
    pub fn generate_content(
        &self,
        contents: &[Content],
        config: Option<GenerationConfig>,
        functions: Option<&[FunctionDeclaration]>,
    ) -> Result<GenerationResponse, GeminiError> {
        // Check rate limit
        if let Err(wait) = self.rate_limiter.check_request() {
            return Err(GeminiError::RateLimited { retry_after: wait });
        }

        let config = config.unwrap_or_else(|| self.config.default_config.clone());
        let _ = functions; // Would be used in actual API call

        // Simulate API call
        let response = self.simulate_response(contents, &config)?;

        // Track usage
        self.usage.record_usage(&response.usage);

        Ok(response)
    }

    /// Stream generation
    pub fn generate_stream<F>(
        &self,
        prompt: &str,
        mut callback: F,
    ) -> Result<GenerationResponse, GeminiError>
    where
        F: FnMut(StreamChunk),
    {
        // Check rate limit
        if let Err(wait) = self.rate_limiter.check_request() {
            return Err(GeminiError::RateLimited { retry_after: wait });
        }

        // Simulate streaming
        let response_text = format!("Response to: {}", prompt);
        let words: Vec<&str> = response_text.split_whitespace().collect();

        for (i, word) in words.iter().enumerate() {
            callback(StreamChunk {
                text: format!("{} ", word),
                is_final: i == words.len() - 1,
                safety_ratings: None,
            });
        }

        let response = GenerationResponse {
            candidates: vec![Candidate {
                content: Content::model(response_text),
                finish_reason: "STOP".to_string(),
                safety_ratings: Vec::new(),
                citation_metadata: None,
            }],
            usage: UsageMetadata {
                prompt_tokens: (prompt.len() / 4) as u32,
                candidates_tokens: (words.len() * 2) as u32,
                total_tokens: ((prompt.len() / 4) + words.len() * 2) as u32,
            },
            model_version: self.config.default_model.model_id().to_string(),
        };

        self.usage.record_usage(&response.usage);
        Ok(response)
    }

    /// Vision - analyze image
    pub fn analyze_image(
        &self,
        image_data: &[u8],
        mime_type: &str,
        prompt: &str,
    ) -> Result<GenerationResponse, GeminiError> {
        if !self.config.default_model.supports_vision() {
            return Err(GeminiError::ModelNotAvailable {
                model: format!("{:?} does not support vision", self.config.default_model),
            });
        }

        let content = Content::with_image(Role::User, prompt, image_data.to_vec(), mime_type);
        self.generate_content(&[content], None, None)
    }

    /// Count tokens
    pub fn count_tokens(&self, contents: &[Content]) -> Result<u32, GeminiError> {
        // Simplified token counting
        let total_chars: usize = contents
            .iter()
            .flat_map(|c| &c.parts)
            .filter_map(|p| {
                if let ContentPart::Text(t) = p {
                    Some(t.len())
                } else {
                    None
                }
            })
            .sum();

        Ok((total_chars / 4) as u32)
    }

    /// Get usage summary
    pub fn usage_summary(&self) -> UsageSummary {
        self.usage.summary()
    }

    /// Embed text
    pub fn embed(&self, text: &str) -> Result<Vec<f32>, GeminiError> {
        // Simulate embedding
        let embedding: Vec<f32> = (0..768)
            .map(|i| ((i as f32 * 0.001) + (text.len() as f32 * 0.0001)).sin())
            .collect();
        Ok(embedding)
    }

    /// Batch embed
    pub fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, GeminiError> {
        texts.iter().map(|t| self.embed(t)).collect()
    }

    // Simulate API response
    fn simulate_response(
        &self,
        contents: &[Content],
        _config: &GenerationConfig,
    ) -> Result<GenerationResponse, GeminiError> {
        let last_content = contents.last().ok_or(GeminiError::InvalidRequest {
            message: "No content provided".to_string(),
        })?;

        let prompt_text = last_content
            .parts
            .iter()
            .find_map(|p| {
                if let ContentPart::Text(t) = p {
                    Some(t.as_str())
                } else {
                    None
                }
            })
            .unwrap_or("");

        let response_text = format!("Gemini response to: {}", prompt_text);

        Ok(GenerationResponse {
            candidates: vec![Candidate {
                content: Content::model(&response_text),
                finish_reason: "STOP".to_string(),
                safety_ratings: vec![
                    SafetyRating {
                        category: HarmCategory::HateSpeech,
                        probability: "NEGLIGIBLE".to_string(),
                        blocked: false,
                    },
                    SafetyRating {
                        category: HarmCategory::DangerousContent,
                        probability: "NEGLIGIBLE".to_string(),
                        blocked: false,
                    },
                ],
                citation_metadata: None,
            }],
            usage: UsageMetadata {
                prompt_tokens: (prompt_text.len() / 4) as u32,
                candidates_tokens: (response_text.len() / 4) as u32,
                total_tokens: ((prompt_text.len() + response_text.len()) / 4) as u32,
            },
            model_version: self.config.default_model.model_id().to_string(),
        })
    }
}

/// Chat session for multi-turn conversations
pub struct ChatSession {
    client: Arc<GeminiClient>,
    history: Vec<Content>,
    system_instruction: Option<String>,
}

impl ChatSession {
    pub fn new(client: Arc<GeminiClient>) -> Self {
        Self {
            client,
            history: Vec::new(),
            system_instruction: None,
        }
    }

    pub fn with_system_instruction(mut self, instruction: impl Into<String>) -> Self {
        self.system_instruction = Some(instruction.into());
        self
    }

    pub fn send(&mut self, message: impl Into<String>) -> Result<String, GeminiError> {
        let user_content = Content::user(message.into());
        self.history.push(user_content);

        let response = self.client.chat(&self.history)?;

        if let Some(candidate) = response.candidates.first() {
            self.history.push(candidate.content.clone());
            if let Some(text) = response.text() {
                return Ok(text.to_string());
            }
        }

        Err(GeminiError::InvalidResponse {
            message: "No text in response".to_string(),
        })
    }

    pub fn history(&self) -> &[Content] {
        &self.history
    }

    pub fn clear_history(&mut self) {
        self.history.clear();
    }
}

fn main() {
    println!("=== Google Gemini API Client ===\n");

    // Create client
    let config = GeminiConfig::new("your-api-key-here").with_model(GeminiModel::Gemini15Flash);
    let client = Arc::new(GeminiClient::new(config));

    // Simple generation
    println!("--- Simple Generation ---");
    let response = client
        .generate("Explain quantum computing in 50 words")
        .unwrap();
    println!("Response: {}", response.text().unwrap_or("No text"));
    println!("Tokens used: {}", response.usage.total_tokens);

    // Custom config
    println!("\n--- Deterministic Generation ---");
    let response = client
        .generate_with_config("What is 2 + 2?", GenerationConfig::deterministic())
        .unwrap();
    println!("Response: {}", response.text().unwrap_or("No text"));

    // Streaming
    println!("\n--- Streaming ---");
    print!("Stream: ");
    let _response = client
        .generate_stream("Count from 1 to 5", |chunk| {
            print!("{}", chunk.text);
        })
        .unwrap();
    println!();

    // Chat session
    println!("\n--- Chat Session ---");
    let mut chat = ChatSession::new(Arc::clone(&client))
        .with_system_instruction("You are a helpful coding assistant.");

    let reply1 = chat
        .send("What's the best way to handle errors in Rust?")
        .unwrap();
    println!("User: What's the best way to handle errors in Rust?");
    println!("Gemini: {}", reply1);

    let reply2 = chat.send("Can you show me an example?").unwrap();
    println!("\nUser: Can you show me an example?");
    println!("Gemini: {}", reply2);

    println!("\nChat history: {} messages", chat.history().len());

    // Function calling
    println!("\n--- Function Calling ---");
    let weather_fn = FunctionDeclaration::new("get_weather", "Get current weather for a location")
        .add_parameter("location", "string", "City and country", true)
        .add_parameter(
            "unit",
            "string",
            "Temperature unit (celsius/fahrenheit)",
            false,
        );

    let contents = vec![Content::user("What's the weather in Tokyo?")];
    let response = client
        .generate_with_functions(&contents, &[weather_fn])
        .unwrap();
    println!("Response: {}", response.text().unwrap_or("No text"));

    // Token counting
    println!("\n--- Token Counting ---");
    let contents = vec![
        Content::user("Hello, how are you?"),
        Content::model("I'm doing well, thank you for asking!"),
    ];
    let tokens = client.count_tokens(&contents).unwrap();
    println!("Token count: {}", tokens);

    // Embeddings
    println!("\n--- Embeddings ---");
    let embedding = client.embed("This is a test sentence").unwrap();
    println!("Embedding dimension: {}", embedding.len());
    println!("First 5 values: {:?}", &embedding[..5]);

    // Batch embeddings
    let texts = vec!["Hello world", "Goodbye world", "Rust is great"];
    let embeddings = client.embed_batch(&texts).unwrap();
    println!("Batch embedded {} texts", embeddings.len());

    // Usage summary
    println!("\n--- Usage Summary ---");
    let summary = client.usage_summary();
    println!("Total requests: {}", summary.total_requests);
    println!("Total prompt tokens: {}", summary.total_prompt_tokens);
    println!(
        "Total completion tokens: {}",
        summary.total_completion_tokens
    );

    // Model info
    println!("\n--- Model Capabilities ---");
    for model in [
        GeminiModel::Gemini15Pro,
        GeminiModel::Gemini15Flash,
        GeminiModel::Gemini20Flash,
    ] {
        println!(
            "{}: context={}K, vision={}, functions={}",
            model.model_id(),
            model.context_window() / 1000,
            model.supports_vision(),
            model.supports_function_calling()
        );
    }

    println!("\n=== Gemini Client Complete ===");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_client() -> GeminiClient {
        GeminiClient::new(GeminiConfig::new("test-key"))
    }

    #[test]
    fn test_simple_generation() {
        let client = test_client();
        let response = client.generate("Hello").unwrap();
        assert!(!response.candidates.is_empty());
        assert!(response.text().is_some());
    }

    #[test]
    fn test_generation_config_presets() {
        let deterministic = GenerationConfig::deterministic();
        assert_eq!(deterministic.temperature, 0.0);

        let creative = GenerationConfig::creative();
        assert_eq!(creative.temperature, 1.0);
    }

    #[test]
    fn test_chat_session() {
        let client = Arc::new(test_client());
        let mut chat = ChatSession::new(client);

        let reply = chat.send("Hello").unwrap();
        assert!(!reply.is_empty());
        assert_eq!(chat.history().len(), 2); // User + Model
    }

    #[test]
    fn test_token_counting() {
        let client = test_client();
        let contents = vec![Content::user("Hello world")];
        let tokens = client.count_tokens(&contents).unwrap();
        assert!(tokens > 0);
    }

    #[test]
    fn test_embeddings() {
        let client = test_client();
        let embedding = client.embed("Test").unwrap();
        assert_eq!(embedding.len(), 768);
    }

    #[test]
    fn test_model_capabilities() {
        assert!(GeminiModel::Gemini15Pro.supports_vision());
        assert!(GeminiModel::Gemini15Pro.supports_function_calling());
        assert_eq!(GeminiModel::Gemini15Pro.context_window(), 1000000);
    }

    #[test]
    fn test_content_creation() {
        let user_content = Content::user("Hello");
        assert_eq!(user_content.role, Role::User);
        assert_eq!(user_content.parts.len(), 1);

        let image_content =
            Content::with_image(Role::User, "Describe this", vec![0, 1, 2], "image/png");
        assert_eq!(image_content.parts.len(), 2);
    }

    #[test]
    fn test_function_declaration() {
        let func = FunctionDeclaration::new("test_func", "A test function")
            .add_parameter("param1", "string", "First parameter", true)
            .add_parameter("param2", "number", "Second parameter", false);

        assert_eq!(func.name, "test_func");
        assert_eq!(func.parameters.len(), 2);
        assert_eq!(func.required.len(), 1);
    }

    #[test]
    fn test_usage_tracking() {
        let client = test_client();
        client.generate("Test 1").unwrap();
        client.generate("Test 2").unwrap();

        let summary = client.usage_summary();
        assert_eq!(summary.total_requests, 2);
    }

    #[test]
    fn test_rate_limiter() {
        let limiter = RateLimiter::new(2, 1000);

        assert!(limiter.check_request().is_ok());
        assert!(limiter.check_request().is_ok());
        // Third request within minute should fail
        assert!(limiter.check_request().is_err());
    }

    #[test]
    fn test_streaming() {
        let client = test_client();
        let mut chunks = Vec::new();

        let _response = client
            .generate_stream("Test", |chunk| {
                chunks.push(chunk.text);
            })
            .unwrap();

        assert!(!chunks.is_empty());
    }

    #[test]
    fn test_safety_settings() {
        let settings = vec![SafetySetting {
            category: HarmCategory::HateSpeech,
            threshold: HarmBlockThreshold::BlockMediumAndAbove,
        }];

        let config = GeminiConfig::new("key").with_safety_settings(settings);

        assert_eq!(config.safety_settings.len(), 1);
    }
}
