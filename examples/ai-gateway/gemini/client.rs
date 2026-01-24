//! Google Gemini API Client Example
//!
//! Demonstrates a secure Rust client for Google's Gemini API
//! with multimodal support and streaming capabilities.

use std::time::Duration;

/// Gemini API configuration
#[derive(Debug, Clone)]
pub struct GeminiConfig {
    pub api_key: String,
    pub base_url: String,
    pub timeout: Duration,
    pub max_retries: u32,
}

impl GeminiConfig {
    pub fn new(api_key: &str) -> Self {
        Self {
            api_key: api_key.to_string(),
            base_url: "https://generativelanguage.googleapis.com/v1".to_string(),
            timeout: Duration::from_secs(60),
            max_retries: 3,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// Available Gemini models
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeminiModel {
    Gemini15Pro,
    Gemini15Flash,
    Gemini10Pro,
    Gemini10ProVision,
    GeminiPro,
}

impl GeminiModel {
    pub fn as_str(&self) -> &'static str {
        match self {
            GeminiModel::Gemini15Pro => "gemini-1.5-pro",
            GeminiModel::Gemini15Flash => "gemini-1.5-flash",
            GeminiModel::Gemini10Pro => "gemini-1.0-pro",
            GeminiModel::Gemini10ProVision => "gemini-1.0-pro-vision",
            GeminiModel::GeminiPro => "gemini-pro",
        }
    }

    pub fn supports_vision(&self) -> bool {
        matches!(
            self,
            GeminiModel::Gemini15Pro | GeminiModel::Gemini15Flash | GeminiModel::Gemini10ProVision
        )
    }

    pub fn context_window(&self) -> u32 {
        match self {
            GeminiModel::Gemini15Pro => 2_097_152,
            GeminiModel::Gemini15Flash => 1_048_576,
            GeminiModel::Gemini10Pro => 32_768,
            GeminiModel::Gemini10ProVision => 16_384,
            GeminiModel::GeminiPro => 32_768,
        }
    }
}

/// Content part for multimodal input
#[derive(Debug, Clone)]
pub enum Part {
    Text(String),
    InlineData {
        mime_type: String,
        data: String, // base64 encoded
    },
    FileData {
        mime_type: String,
        file_uri: String,
    },
}

impl Part {
    pub fn text(content: &str) -> Self {
        Part::Text(content.to_string())
    }

    pub fn image_base64(data: &str, mime_type: &str) -> Self {
        Part::InlineData {
            mime_type: mime_type.to_string(),
            data: data.to_string(),
        }
    }

    pub fn file(uri: &str, mime_type: &str) -> Self {
        Part::FileData {
            mime_type: mime_type.to_string(),
            file_uri: uri.to_string(),
        }
    }
}

/// Content with role
#[derive(Debug, Clone)]
pub struct Content {
    pub role: String, // "user" or "model"
    pub parts: Vec<Part>,
}

impl Content {
    pub fn user(parts: Vec<Part>) -> Self {
        Self {
            role: "user".to_string(),
            parts,
        }
    }

    pub fn model(parts: Vec<Part>) -> Self {
        Self {
            role: "model".to_string(),
            parts,
        }
    }

    pub fn user_text(text: &str) -> Self {
        Self::user(vec![Part::text(text)])
    }

    pub fn model_text(text: &str) -> Self {
        Self::model(vec![Part::text(text)])
    }
}

/// Safety settings
#[derive(Debug, Clone)]
pub struct SafetySetting {
    pub category: HarmCategory,
    pub threshold: HarmBlockThreshold,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HarmCategory {
    HateSpeech,
    DangerousContent,
    Harassment,
    SexuallyExplicit,
}

impl HarmCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            HarmCategory::HateSpeech => "HARM_CATEGORY_HATE_SPEECH",
            HarmCategory::DangerousContent => "HARM_CATEGORY_DANGEROUS_CONTENT",
            HarmCategory::Harassment => "HARM_CATEGORY_HARASSMENT",
            HarmCategory::SexuallyExplicit => "HARM_CATEGORY_SEXUALLY_EXPLICIT",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HarmBlockThreshold {
    BlockNone,
    BlockLowAndAbove,
    BlockMediumAndAbove,
    BlockHighAndAbove,
}

impl HarmBlockThreshold {
    pub fn as_str(&self) -> &'static str {
        match self {
            HarmBlockThreshold::BlockNone => "BLOCK_NONE",
            HarmBlockThreshold::BlockLowAndAbove => "BLOCK_LOW_AND_ABOVE",
            HarmBlockThreshold::BlockMediumAndAbove => "BLOCK_MEDIUM_AND_ABOVE",
            HarmBlockThreshold::BlockHighAndAbove => "BLOCK_ONLY_HIGH",
        }
    }
}

/// Generation configuration
#[derive(Debug, Clone, Default)]
pub struct GenerationConfig {
    pub temperature: Option<f32>,
    pub top_p: Option<f32>,
    pub top_k: Option<u32>,
    pub max_output_tokens: Option<u32>,
    pub stop_sequences: Option<Vec<String>>,
}

impl GenerationConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_temperature(mut self, temp: f32) -> Self {
        self.temperature = Some(temp.clamp(0.0, 2.0));
        self
    }

    pub fn with_max_tokens(mut self, tokens: u32) -> Self {
        self.max_output_tokens = Some(tokens);
        self
    }

    pub fn with_top_p(mut self, p: f32) -> Self {
        self.top_p = Some(p.clamp(0.0, 1.0));
        self
    }

    pub fn with_top_k(mut self, k: u32) -> Self {
        self.top_k = Some(k);
        self
    }
}

/// Generate content request
#[derive(Debug, Clone)]
pub struct GenerateContentRequest {
    pub model: GeminiModel,
    pub contents: Vec<Content>,
    pub generation_config: Option<GenerationConfig>,
    pub safety_settings: Option<Vec<SafetySetting>>,
    pub system_instruction: Option<Content>,
}

impl GenerateContentRequest {
    pub fn new(model: GeminiModel, contents: Vec<Content>) -> Self {
        Self {
            model,
            contents,
            generation_config: None,
            safety_settings: None,
            system_instruction: None,
        }
    }

    pub fn with_config(mut self, config: GenerationConfig) -> Self {
        self.generation_config = Some(config);
        self
    }

    pub fn with_safety(mut self, settings: Vec<SafetySetting>) -> Self {
        self.safety_settings = Some(settings);
        self
    }

    pub fn with_system_instruction(mut self, instruction: &str) -> Self {
        self.system_instruction = Some(Content::user(vec![Part::text(instruction)]));
        self
    }
}

/// Generate content response
#[derive(Debug, Clone)]
pub struct GenerateContentResponse {
    pub candidates: Vec<Candidate>,
    pub prompt_feedback: Option<PromptFeedback>,
    pub usage_metadata: Option<UsageMetadata>,
}

#[derive(Debug, Clone)]
pub struct Candidate {
    pub content: Content,
    pub finish_reason: Option<FinishReason>,
    pub safety_ratings: Vec<SafetyRating>,
    pub index: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinishReason {
    Stop,
    MaxTokens,
    Safety,
    Recitation,
    Other,
}

#[derive(Debug, Clone)]
pub struct SafetyRating {
    pub category: HarmCategory,
    pub probability: String,
    pub blocked: bool,
}

#[derive(Debug, Clone)]
pub struct PromptFeedback {
    pub block_reason: Option<String>,
    pub safety_ratings: Vec<SafetyRating>,
}

#[derive(Debug, Clone)]
pub struct UsageMetadata {
    pub prompt_token_count: u32,
    pub candidates_token_count: u32,
    pub total_token_count: u32,
}

/// Gemini API error
#[derive(Debug)]
pub enum GeminiError {
    InvalidApiKey,
    QuotaExceeded,
    InvalidRequest(String),
    SafetyBlocked(String),
    ServerError(String),
    Timeout,
    NetworkError(String),
}

/// Gemini API client
pub struct GeminiClient {
    config: GeminiConfig,
}

impl GeminiClient {
    pub fn new(config: GeminiConfig) -> Self {
        Self { config }
    }

    /// Generate content
    pub fn generate_content(
        &self,
        request: GenerateContentRequest,
    ) -> Result<GenerateContentResponse, GeminiError> {
        // Validate request
        if request.contents.is_empty() {
            return Err(GeminiError::InvalidRequest(
                "Contents cannot be empty".to_string(),
            ));
        }

        // Check for vision model if images are present
        let has_images = request.contents.iter().any(|c| {
            c.parts
                .iter()
                .any(|p| matches!(p, Part::InlineData { .. } | Part::FileData { .. }))
        });

        if has_images && !request.model.supports_vision() {
            return Err(GeminiError::InvalidRequest(
                "Selected model does not support vision".to_string(),
            ));
        }

        // Build endpoint
        let _endpoint = format!(
            "{}/models/{}:generateContent?key={}",
            self.config.base_url,
            request.model.as_str(),
            self.config.api_key
        );

        // Simulate response
        let response_text = self.simulate_response(&request);

        Ok(GenerateContentResponse {
            candidates: vec![Candidate {
                content: Content::model(vec![Part::text(&response_text)]),
                finish_reason: Some(FinishReason::Stop),
                safety_ratings: vec![],
                index: 0,
            }],
            prompt_feedback: None,
            usage_metadata: Some(UsageMetadata {
                prompt_token_count: 50,
                candidates_token_count: 30,
                total_token_count: 80,
            }),
        })
    }

    /// Stream generate content
    pub fn stream_generate_content(
        &self,
        request: GenerateContentRequest,
    ) -> Result<StreamingGeminiResponse, GeminiError> {
        let response_text = self.simulate_response(&request);

        Ok(StreamingGeminiResponse {
            chunks: response_text
                .split_whitespace()
                .map(|s| s.to_string())
                .collect(),
            current: 0,
        })
    }

    /// Count tokens
    pub fn count_tokens(&self, contents: &[Content]) -> Result<u32, GeminiError> {
        // Simplified token counting (4 chars per token approximation)
        let total_chars: usize = contents
            .iter()
            .flat_map(|c| &c.parts)
            .map(|p| match p {
                Part::Text(t) => t.len(),
                _ => 100, // Approximate for images
            })
            .sum();

        Ok((total_chars / 4) as u32)
    }

    fn simulate_response(&self, _request: &GenerateContentRequest) -> String {
        "This is a simulated response from Google Gemini API.".to_string()
    }
}

/// Streaming response
pub struct StreamingGeminiResponse {
    chunks: Vec<String>,
    current: usize,
}

impl Iterator for StreamingGeminiResponse {
    type Item = String;

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

/// Multimodal helper for building requests
pub struct MultimodalBuilder {
    contents: Vec<Content>,
}

impl MultimodalBuilder {
    pub fn new() -> Self {
        Self {
            contents: Vec::new(),
        }
    }

    pub fn add_text(mut self, role: &str, text: &str) -> Self {
        let content = if role == "user" {
            Content::user_text(text)
        } else {
            Content::model_text(text)
        };
        self.contents.push(content);
        self
    }

    pub fn add_image(mut self, base64_data: &str, mime_type: &str) -> Self {
        let content = Content::user(vec![Part::image_base64(base64_data, mime_type)]);
        self.contents.push(content);
        self
    }

    pub fn add_text_and_image(mut self, text: &str, base64_data: &str, mime_type: &str) -> Self {
        let content = Content::user(vec![
            Part::text(text),
            Part::image_base64(base64_data, mime_type),
        ]);
        self.contents.push(content);
        self
    }

    pub fn build(self) -> Vec<Content> {
        self.contents
    }
}

impl Default for MultimodalBuilder {
    fn default() -> Self {
        Self::new()
    }
}

fn main() {
    println!("Google Gemini API Client Example");
    println!("=================================\n");

    // Create client
    let config = GeminiConfig::new("your-api-key").with_timeout(Duration::from_secs(60));

    let client = GeminiClient::new(config);

    // Simple text generation
    println!("Text Generation:");
    println!("----------------");

    let request = GenerateContentRequest::new(
        GeminiModel::Gemini15Pro,
        vec![Content::user_text(
            "Explain quantum computing in simple terms.",
        )],
    )
    .with_config(
        GenerationConfig::new()
            .with_temperature(0.7)
            .with_max_tokens(500),
    )
    .with_system_instruction("You are a helpful science teacher.");

    match client.generate_content(request) {
        Ok(response) => {
            if let Some(candidate) = response.candidates.first() {
                if let Some(Part::Text(text)) = candidate.content.parts.first() {
                    println!("Response: {}\n", text);
                }
            }
            if let Some(usage) = response.usage_metadata {
                println!("Tokens used: {}", usage.total_token_count);
            }
        }
        Err(e) => println!("Error: {:?}\n", e),
    }

    // Multimodal example
    println!("\nMultimodal Request:");
    println!("-------------------");

    let contents = MultimodalBuilder::new()
        .add_text_and_image(
            "What do you see in this image?",
            "base64_encoded_image_data_here",
            "image/jpeg",
        )
        .build();

    let multimodal_request = GenerateContentRequest::new(GeminiModel::Gemini15Pro, contents);

    println!("Model: {}", multimodal_request.model.as_str());
    println!(
        "Supports vision: {}",
        multimodal_request.model.supports_vision()
    );
    println!(
        "Context window: {} tokens",
        multimodal_request.model.context_window()
    );

    // Safety settings example
    println!("\nSafety Settings:");
    println!("----------------");

    let safety_settings = vec![
        SafetySetting {
            category: HarmCategory::HateSpeech,
            threshold: HarmBlockThreshold::BlockMediumAndAbove,
        },
        SafetySetting {
            category: HarmCategory::DangerousContent,
            threshold: HarmBlockThreshold::BlockHighAndAbove,
        },
    ];

    for setting in &safety_settings {
        println!(
            "  {}: {}",
            setting.category.as_str(),
            setting.threshold.as_str()
        );
    }

    // Streaming example
    println!("\nStreaming Response:");
    println!("-------------------");

    let stream_request = GenerateContentRequest::new(
        GeminiModel::Gemini15Flash,
        vec![Content::user_text("Count from 1 to 5.")],
    );

    match client.stream_generate_content(stream_request) {
        Ok(stream) => {
            print!("Response: ");
            for chunk in stream {
                print!("{} ", chunk);
            }
            println!();
        }
        Err(e) => println!("Error: {:?}", e),
    }

    // Token counting
    println!("\nToken Counting:");
    println!("---------------");

    let contents = vec![
        Content::user_text("Hello, how are you?"),
        Content::model_text("I'm doing well, thank you!"),
    ];

    match client.count_tokens(&contents) {
        Ok(count) => println!("Estimated tokens: {}", count),
        Err(e) => println!("Error: {:?}", e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_properties() {
        assert!(GeminiModel::Gemini15Pro.supports_vision());
        assert!(!GeminiModel::Gemini10Pro.supports_vision());
        assert_eq!(GeminiModel::Gemini15Pro.context_window(), 2_097_152);
    }

    #[test]
    fn test_content_creation() {
        let content = Content::user_text("Hello");
        assert_eq!(content.role, "user");
        assert_eq!(content.parts.len(), 1);

        let model_content = Content::model_text("Hi there");
        assert_eq!(model_content.role, "model");
    }

    #[test]
    fn test_generation_config() {
        let config = GenerationConfig::new()
            .with_temperature(0.5)
            .with_max_tokens(100)
            .with_top_p(0.9)
            .with_top_k(40);

        assert_eq!(config.temperature, Some(0.5));
        assert_eq!(config.max_output_tokens, Some(100));
        assert_eq!(config.top_p, Some(0.9));
        assert_eq!(config.top_k, Some(40));
    }

    #[test]
    fn test_temperature_clamping() {
        let config = GenerationConfig::new().with_temperature(5.0);
        assert_eq!(config.temperature, Some(2.0));
    }

    #[test]
    fn test_multimodal_builder() {
        let contents = MultimodalBuilder::new()
            .add_text("user", "Hello")
            .add_text("model", "Hi")
            .build();

        assert_eq!(contents.len(), 2);
    }

    #[test]
    fn test_generate_content() {
        let config = GeminiConfig::new("test-key");
        let client = GeminiClient::new(config);

        let request =
            GenerateContentRequest::new(GeminiModel::GeminiPro, vec![Content::user_text("Test")]);

        let response = client.generate_content(request);
        assert!(response.is_ok());
    }

    #[test]
    fn test_empty_contents_error() {
        let config = GeminiConfig::new("test-key");
        let client = GeminiClient::new(config);

        let request = GenerateContentRequest::new(GeminiModel::GeminiPro, vec![]);

        assert!(matches!(
            client.generate_content(request),
            Err(GeminiError::InvalidRequest(_))
        ));
    }

    #[test]
    fn test_vision_model_check() {
        let config = GeminiConfig::new("test-key");
        let client = GeminiClient::new(config);

        let contents = vec![Content::user(vec![
            Part::text("What's this?"),
            Part::image_base64("data", "image/png"),
        ])];

        // Non-vision model should fail
        let request = GenerateContentRequest::new(GeminiModel::Gemini10Pro, contents);

        assert!(matches!(
            client.generate_content(request),
            Err(GeminiError::InvalidRequest(_))
        ));
    }

    #[test]
    fn test_streaming() {
        let config = GeminiConfig::new("test-key");
        let client = GeminiClient::new(config);

        let request =
            GenerateContentRequest::new(GeminiModel::GeminiPro, vec![Content::user_text("Test")]);

        let stream = client.stream_generate_content(request).unwrap();
        let chunks: Vec<_> = stream.collect();
        assert!(!chunks.is_empty());
    }

    #[test]
    fn test_token_counting() {
        let config = GeminiConfig::new("test-key");
        let client = GeminiClient::new(config);

        let contents = vec![Content::user_text("Hello world")];
        let count = client.count_tokens(&contents).unwrap();
        assert!(count > 0);
    }
}
