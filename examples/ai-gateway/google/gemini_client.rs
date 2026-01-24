//! Google Gemini Client Implementation
//!
//! Comprehensive client for Google's Gemini API with support for multimodal
//! content, streaming, function calling, and safety settings.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Gemini model variants
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeminiModel {
    Gemini15Pro,
    Gemini15Flash,
    Gemini10Pro,
    Gemini10ProVision,
    GeminiUltra,
}

impl GeminiModel {
    pub fn as_str(&self) -> &'static str {
        match self {
            GeminiModel::Gemini15Pro => "gemini-1.5-pro",
            GeminiModel::Gemini15Flash => "gemini-1.5-flash",
            GeminiModel::Gemini10Pro => "gemini-1.0-pro",
            GeminiModel::Gemini10ProVision => "gemini-1.0-pro-vision",
            GeminiModel::GeminiUltra => "gemini-ultra",
        }
    }

    pub fn max_input_tokens(&self) -> u32 {
        match self {
            GeminiModel::Gemini15Pro => 2097152,   // 2M tokens
            GeminiModel::Gemini15Flash => 1048576, // 1M tokens
            GeminiModel::Gemini10Pro => 30720,
            GeminiModel::Gemini10ProVision => 12288,
            GeminiModel::GeminiUltra => 32768,
        }
    }

    pub fn max_output_tokens(&self) -> u32 {
        match self {
            GeminiModel::Gemini15Pro => 8192,
            GeminiModel::Gemini15Flash => 8192,
            GeminiModel::Gemini10Pro => 2048,
            GeminiModel::Gemini10ProVision => 4096,
            GeminiModel::GeminiUltra => 8192,
        }
    }

    pub fn supports_vision(&self) -> bool {
        match self {
            GeminiModel::Gemini15Pro => true,
            GeminiModel::Gemini15Flash => true,
            GeminiModel::Gemini10ProVision => true,
            _ => false,
        }
    }

    pub fn supports_audio(&self) -> bool {
        matches!(self, GeminiModel::Gemini15Pro | GeminiModel::Gemini15Flash)
    }

    pub fn supports_video(&self) -> bool {
        matches!(self, GeminiModel::Gemini15Pro | GeminiModel::Gemini15Flash)
    }
}

/// Content role
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Role {
    User,
    Model,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::User => "user",
            Role::Model => "model",
        }
    }
}

/// Content part - can be text, image, audio, or video
#[derive(Debug, Clone)]
pub enum Part {
    Text(String),
    InlineData {
        mime_type: String,
        data: Vec<u8>,
    },
    FileData {
        mime_type: String,
        file_uri: String,
    },
    FunctionCall {
        name: String,
        args: serde_json::Value,
    },
    FunctionResponse {
        name: String,
        response: serde_json::Value,
    },
}

impl Part {
    pub fn text(text: impl Into<String>) -> Self {
        Part::Text(text.into())
    }

    pub fn image_base64(data: Vec<u8>, mime_type: impl Into<String>) -> Self {
        Part::InlineData {
            mime_type: mime_type.into(),
            data,
        }
    }

    pub fn file_uri(uri: impl Into<String>, mime_type: impl Into<String>) -> Self {
        Part::FileData {
            mime_type: mime_type.into(),
            file_uri: uri.into(),
        }
    }

    pub fn function_call(name: impl Into<String>, args: serde_json::Value) -> Self {
        Part::FunctionCall {
            name: name.into(),
            args,
        }
    }

    pub fn function_response(name: impl Into<String>, response: serde_json::Value) -> Self {
        Part::FunctionResponse {
            name: name.into(),
            response,
        }
    }
}

/// Content with role and parts
#[derive(Debug, Clone)]
pub struct Content {
    pub role: Role,
    pub parts: Vec<Part>,
}

impl Content {
    pub fn user(parts: Vec<Part>) -> Self {
        Self {
            role: Role::User,
            parts,
        }
    }

    pub fn model(parts: Vec<Part>) -> Self {
        Self {
            role: Role::Model,
            parts,
        }
    }

    pub fn user_text(text: impl Into<String>) -> Self {
        Self::user(vec![Part::text(text)])
    }

    pub fn model_text(text: impl Into<String>) -> Self {
        Self::model(vec![Part::text(text)])
    }
}

/// Safety category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

/// Safety threshold
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HarmBlockThreshold {
    BlockNone,
    BlockLowAndAbove,
    BlockMediumAndAbove,
    BlockOnlyHigh,
}

impl HarmBlockThreshold {
    pub fn as_str(&self) -> &'static str {
        match self {
            HarmBlockThreshold::BlockNone => "BLOCK_NONE",
            HarmBlockThreshold::BlockLowAndAbove => "BLOCK_LOW_AND_ABOVE",
            HarmBlockThreshold::BlockMediumAndAbove => "BLOCK_MEDIUM_AND_ABOVE",
            HarmBlockThreshold::BlockOnlyHigh => "BLOCK_ONLY_HIGH",
        }
    }
}

/// Safety setting
#[derive(Debug, Clone)]
pub struct SafetySetting {
    pub category: HarmCategory,
    pub threshold: HarmBlockThreshold,
}

impl SafetySetting {
    pub fn new(category: HarmCategory, threshold: HarmBlockThreshold) -> Self {
        Self {
            category,
            threshold,
        }
    }
}

/// Safety rating in response
#[derive(Debug, Clone)]
pub struct SafetyRating {
    pub category: HarmCategory,
    pub probability: HarmProbability,
    pub blocked: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HarmProbability {
    Negligible,
    Low,
    Medium,
    High,
}

/// Generation configuration
#[derive(Debug, Clone, Default)]
pub struct GenerationConfig {
    pub temperature: Option<f32>,
    pub top_p: Option<f32>,
    pub top_k: Option<u32>,
    pub max_output_tokens: Option<u32>,
    pub stop_sequences: Option<Vec<String>>,
    pub candidate_count: Option<u32>,
    pub response_mime_type: Option<String>,
}

impl GenerationConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn temperature(mut self, temp: f32) -> Self {
        self.temperature = Some(temp.clamp(0.0, 2.0));
        self
    }

    pub fn top_p(mut self, p: f32) -> Self {
        self.top_p = Some(p.clamp(0.0, 1.0));
        self
    }

    pub fn top_k(mut self, k: u32) -> Self {
        self.top_k = Some(k);
        self
    }

    pub fn max_output_tokens(mut self, tokens: u32) -> Self {
        self.max_output_tokens = Some(tokens);
        self
    }

    pub fn stop_sequences(mut self, sequences: Vec<String>) -> Self {
        self.stop_sequences = Some(sequences);
        self
    }

    pub fn json_response(mut self) -> Self {
        self.response_mime_type = Some("application/json".to_string());
        self
    }
}

/// Function declaration for function calling
#[derive(Debug, Clone)]
pub struct FunctionDeclaration {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

impl FunctionDeclaration {
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {}
            }),
        }
    }

    pub fn with_parameters(mut self, parameters: serde_json::Value) -> Self {
        self.parameters = parameters;
        self
    }
}

/// Tool containing function declarations
#[derive(Debug, Clone)]
pub struct Tool {
    pub function_declarations: Vec<FunctionDeclaration>,
}

impl Tool {
    pub fn new(functions: Vec<FunctionDeclaration>) -> Self {
        Self {
            function_declarations: functions,
        }
    }
}

/// Tool configuration
#[derive(Debug, Clone)]
pub struct ToolConfig {
    pub function_calling_config: FunctionCallingConfig,
}

#[derive(Debug, Clone)]
pub struct FunctionCallingConfig {
    pub mode: FunctionCallingMode,
    pub allowed_function_names: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy)]
pub enum FunctionCallingMode {
    Auto,
    Any,
    None,
}

/// Generate content request
#[derive(Debug, Clone)]
pub struct GenerateRequest {
    pub model: GeminiModel,
    pub contents: Vec<Content>,
    pub system_instruction: Option<Content>,
    pub generation_config: Option<GenerationConfig>,
    pub safety_settings: Option<Vec<SafetySetting>>,
    pub tools: Option<Vec<Tool>>,
    pub tool_config: Option<ToolConfig>,
}

impl GenerateRequest {
    pub fn new(model: GeminiModel) -> Self {
        Self {
            model,
            contents: Vec::new(),
            system_instruction: None,
            generation_config: None,
            safety_settings: None,
            tools: None,
            tool_config: None,
        }
    }

    pub fn content(mut self, content: Content) -> Self {
        self.contents.push(content);
        self
    }

    pub fn contents(mut self, contents: Vec<Content>) -> Self {
        self.contents = contents;
        self
    }

    pub fn system_instruction(mut self, instruction: impl Into<String>) -> Self {
        self.system_instruction = Some(Content::model(vec![Part::text(instruction)]));
        self
    }

    pub fn generation_config(mut self, config: GenerationConfig) -> Self {
        self.generation_config = Some(config);
        self
    }

    pub fn safety_settings(mut self, settings: Vec<SafetySetting>) -> Self {
        self.safety_settings = Some(settings);
        self
    }

    pub fn tools(mut self, tools: Vec<Tool>) -> Self {
        self.tools = Some(tools);
        self
    }
}

/// Generate content response
#[derive(Debug, Clone)]
pub struct GenerateResponse {
    pub candidates: Vec<Candidate>,
    pub prompt_feedback: Option<PromptFeedback>,
    pub usage_metadata: Option<UsageMetadata>,
}

impl GenerateResponse {
    pub fn text(&self) -> Option<&str> {
        self.candidates.first().and_then(|c| c.text())
    }

    pub fn function_calls(&self) -> Vec<(&str, &serde_json::Value)> {
        self.candidates
            .first()
            .map(|c| c.function_calls())
            .unwrap_or_default()
    }
}

/// Candidate response
#[derive(Debug, Clone)]
pub struct Candidate {
    pub content: Content,
    pub finish_reason: FinishReason,
    pub safety_ratings: Vec<SafetyRating>,
    pub citation_metadata: Option<CitationMetadata>,
    pub index: u32,
}

impl Candidate {
    pub fn text(&self) -> Option<&str> {
        for part in &self.content.parts {
            if let Part::Text(text) = part {
                return Some(text);
            }
        }
        None
    }

    pub fn function_calls(&self) -> Vec<(&str, &serde_json::Value)> {
        self.content
            .parts
            .iter()
            .filter_map(|p| {
                if let Part::FunctionCall { name, args } = p {
                    Some((name.as_str(), args))
                } else {
                    None
                }
            })
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinishReason {
    Stop,
    MaxTokens,
    Safety,
    Recitation,
    Other,
}

/// Prompt feedback
#[derive(Debug, Clone)]
pub struct PromptFeedback {
    pub block_reason: Option<BlockReason>,
    pub safety_ratings: Vec<SafetyRating>,
}

#[derive(Debug, Clone, Copy)]
pub enum BlockReason {
    Safety,
    Other,
}

/// Citation metadata
#[derive(Debug, Clone)]
pub struct CitationMetadata {
    pub citation_sources: Vec<CitationSource>,
}

#[derive(Debug, Clone)]
pub struct CitationSource {
    pub start_index: u32,
    pub end_index: u32,
    pub uri: Option<String>,
    pub license: Option<String>,
}

/// Usage metadata
#[derive(Debug, Clone)]
pub struct UsageMetadata {
    pub prompt_token_count: u32,
    pub candidates_token_count: u32,
    pub total_token_count: u32,
}

/// Streaming chunk
#[derive(Debug, Clone)]
pub struct StreamChunk {
    pub candidates: Vec<StreamCandidate>,
    pub usage_metadata: Option<UsageMetadata>,
}

#[derive(Debug, Clone)]
pub struct StreamCandidate {
    pub content: Content,
    pub finish_reason: Option<FinishReason>,
    pub index: u32,
}

/// Gemini client configuration
#[derive(Debug, Clone)]
pub struct GeminiConfig {
    pub api_key: String,
    pub project_id: Option<String>,
    pub location: String,
    pub timeout: Duration,
    pub max_retries: u32,
}

impl GeminiConfig {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            project_id: None,
            location: "us-central1".to_string(),
            timeout: Duration::from_secs(60),
            max_retries: 3,
        }
    }

    pub fn project(mut self, project_id: impl Into<String>) -> Self {
        self.project_id = Some(project_id.into());
        self
    }

    pub fn location(mut self, location: impl Into<String>) -> Self {
        self.location = location.into();
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// Token counter for rate limiting
pub struct TokenCounter {
    input_tokens: AtomicU64,
    output_tokens: AtomicU64,
}

impl TokenCounter {
    pub fn new() -> Self {
        Self {
            input_tokens: AtomicU64::new(0),
            output_tokens: AtomicU64::new(0),
        }
    }

    pub fn record(&self, input: u32, output: u32) {
        self.input_tokens.fetch_add(input as u64, Ordering::SeqCst);
        self.output_tokens
            .fetch_add(output as u64, Ordering::SeqCst);
    }

    pub fn totals(&self) -> (u64, u64) {
        (
            self.input_tokens.load(Ordering::SeqCst),
            self.output_tokens.load(Ordering::SeqCst),
        )
    }
}

impl Default for TokenCounter {
    fn default() -> Self {
        Self::new()
    }
}

/// Gemini client
pub struct GeminiClient {
    config: GeminiConfig,
    token_counter: Arc<TokenCounter>,
}

impl GeminiClient {
    pub fn new(config: GeminiConfig) -> Self {
        Self {
            config,
            token_counter: Arc::new(TokenCounter::new()),
        }
    }

    /// Generate content
    pub fn generate(&self, request: GenerateRequest) -> Result<GenerateResponse, GeminiError> {
        // Validate request
        self.validate_request(&request)?;

        // Simulate API call
        let response = self.mock_generate_response(&request);

        // Record token usage
        if let Some(usage) = &response.usage_metadata {
            self.token_counter
                .record(usage.prompt_token_count, usage.candidates_token_count);
        }

        Ok(response)
    }

    /// Count tokens for content
    pub fn count_tokens(&self, contents: &[Content]) -> Result<u32, GeminiError> {
        let mut total = 0u32;
        for content in contents {
            for part in &content.parts {
                if let Part::Text(text) = part {
                    // Rough estimation: ~4 chars per token
                    total += (text.len() / 4) as u32;
                }
            }
        }
        Ok(total)
    }

    /// Get token counter
    pub fn token_counter(&self) -> &TokenCounter {
        &self.token_counter
    }

    fn validate_request(&self, request: &GenerateRequest) -> Result<(), GeminiError> {
        if request.contents.is_empty() {
            return Err(GeminiError::InvalidRequest(
                "Contents cannot be empty".to_string(),
            ));
        }

        // Check for vision content with non-vision model
        let has_media = request.contents.iter().any(|c| {
            c.parts
                .iter()
                .any(|p| matches!(p, Part::InlineData { .. } | Part::FileData { .. }))
        });

        if has_media && !request.model.supports_vision() {
            return Err(GeminiError::InvalidRequest(format!(
                "Model {} does not support vision/media",
                request.model.as_str()
            )));
        }

        Ok(())
    }

    fn mock_generate_response(&self, request: &GenerateRequest) -> GenerateResponse {
        GenerateResponse {
            candidates: vec![Candidate {
                content: Content::model(vec![Part::text("This is a mock response from Gemini.")]),
                finish_reason: FinishReason::Stop,
                safety_ratings: vec![
                    SafetyRating {
                        category: HarmCategory::HateSpeech,
                        probability: HarmProbability::Negligible,
                        blocked: false,
                    },
                    SafetyRating {
                        category: HarmCategory::DangerousContent,
                        probability: HarmProbability::Negligible,
                        blocked: false,
                    },
                ],
                citation_metadata: None,
                index: 0,
            }],
            prompt_feedback: Some(PromptFeedback {
                block_reason: None,
                safety_ratings: vec![],
            }),
            usage_metadata: Some(UsageMetadata {
                prompt_token_count: 50,
                candidates_token_count: 30,
                total_token_count: 80,
            }),
        }
    }
}

/// Gemini error types
#[derive(Debug)]
pub enum GeminiError {
    InvalidRequest(String),
    ApiError { status: u16, message: String },
    SafetyBlocked(Vec<SafetyRating>),
    QuotaExceeded,
    Timeout,
    NetworkError(String),
}

impl std::fmt::Display for GeminiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GeminiError::InvalidRequest(msg) => write!(f, "Invalid request: {}", msg),
            GeminiError::ApiError { status, message } => {
                write!(f, "API error ({}): {}", status, message)
            }
            GeminiError::SafetyBlocked(ratings) => {
                write!(f, "Blocked by safety filters: {:?}", ratings)
            }
            GeminiError::QuotaExceeded => write!(f, "Quota exceeded"),
            GeminiError::Timeout => write!(f, "Request timed out"),
            GeminiError::NetworkError(msg) => write!(f, "Network error: {}", msg),
        }
    }
}

impl std::error::Error for GeminiError {}

/// Conversation helper for multi-turn chat
pub struct Conversation {
    history: Vec<Content>,
    system_instruction: Option<String>,
}

impl Conversation {
    pub fn new() -> Self {
        Self {
            history: Vec::new(),
            system_instruction: None,
        }
    }

    pub fn with_system_instruction(mut self, instruction: impl Into<String>) -> Self {
        self.system_instruction = Some(instruction.into());
        self
    }

    pub fn add_user_message(&mut self, text: impl Into<String>) {
        self.history.push(Content::user_text(text));
    }

    pub fn add_model_response(&mut self, text: impl Into<String>) {
        self.history.push(Content::model_text(text));
    }

    pub fn add_user_with_media(&mut self, text: impl Into<String>, media: Part) {
        self.history
            .push(Content::user(vec![Part::text(text), media]));
    }

    pub fn history(&self) -> &[Content] {
        &self.history
    }

    pub fn to_request(&self, model: GeminiModel) -> GenerateRequest {
        let mut request = GenerateRequest::new(model).contents(self.history.clone());

        if let Some(instruction) = &self.system_instruction {
            request = request.system_instruction(instruction.clone());
        }

        request
    }

    pub fn clear(&mut self) {
        self.history.clear();
    }
}

impl Default for Conversation {
    fn default() -> Self {
        Self::new()
    }
}

fn main() {
    println!("=== Google Gemini Client Demo ===\n");

    // Create client
    let config = GeminiConfig::new("AIzaSy-test-key").project("my-project");
    let client = GeminiClient::new(config);

    // Simple text generation
    println!("1. Simple text generation:");
    let request = GenerateRequest::new(GeminiModel::Gemini15Pro)
        .content(Content::user_text("What is Rust programming language?"))
        .generation_config(
            GenerationConfig::new()
                .temperature(0.7)
                .max_output_tokens(500),
        );

    match client.generate(request) {
        Ok(response) => {
            if let Some(text) = response.text() {
                println!("   Response: {}", text);
            }
            if let Some(usage) = &response.usage_metadata {
                println!("   Tokens: {}", usage.total_token_count);
            }
        }
        Err(e) => println!("   Error: {}", e),
    }

    // With system instruction
    println!("\n2. With system instruction:");
    let request = GenerateRequest::new(GeminiModel::Gemini15Flash)
        .system_instruction("You are a helpful coding assistant. Be concise.")
        .content(Content::user_text("Explain ownership in Rust"));

    match client.generate(request) {
        Ok(response) => {
            println!("   Response: {:?}", response.text());
        }
        Err(e) => println!("   Error: {}", e),
    }

    // Safety settings
    println!("\n3. With safety settings:");
    let request = GenerateRequest::new(GeminiModel::Gemini15Pro)
        .content(Content::user_text(
            "Tell me about cybersecurity best practices",
        ))
        .safety_settings(vec![
            SafetySetting::new(
                HarmCategory::DangerousContent,
                HarmBlockThreshold::BlockOnlyHigh,
            ),
            SafetySetting::new(
                HarmCategory::HateSpeech,
                HarmBlockThreshold::BlockMediumAndAbove,
            ),
        ]);

    match client.generate(request) {
        Ok(response) => {
            if let Some(candidate) = response.candidates.first() {
                println!(
                    "   Safety ratings: {} categories",
                    candidate.safety_ratings.len()
                );
            }
        }
        Err(e) => println!("   Error: {}", e),
    }

    // Function calling
    println!("\n4. Function calling:");
    let weather_func = FunctionDeclaration::new("get_weather", "Get weather for a location")
        .with_parameters(serde_json::json!({
            "type": "object",
            "properties": {
                "location": {
                    "type": "string",
                    "description": "City name"
                }
            },
            "required": ["location"]
        }));

    let request = GenerateRequest::new(GeminiModel::Gemini15Pro)
        .content(Content::user_text("What's the weather in Paris?"))
        .tools(vec![Tool::new(vec![weather_func])]);

    match client.generate(request) {
        Ok(response) => {
            let calls = response.function_calls();
            println!("   Function calls: {}", calls.len());
        }
        Err(e) => println!("   Error: {}", e),
    }

    // JSON mode
    println!("\n5. JSON response mode:");
    let request = GenerateRequest::new(GeminiModel::Gemini15Pro)
        .content(Content::user_text(
            "List 3 programming languages with their main use cases as JSON",
        ))
        .generation_config(GenerationConfig::new().json_response());

    match client.generate(request) {
        Ok(response) => {
            println!("   JSON mode response received");
        }
        Err(e) => println!("   Error: {}", e),
    }

    // Multi-turn conversation
    println!("\n6. Multi-turn conversation:");
    let mut conversation = Conversation::new().with_system_instruction("You are a Rust expert.");

    conversation.add_user_message("What are lifetimes?");
    conversation.add_model_response(
        "Lifetimes are annotations that tell the compiler how long references are valid...",
    );
    conversation.add_user_message("Can you give an example?");

    let request = conversation.to_request(GeminiModel::Gemini15Pro);
    match client.generate(request) {
        Ok(response) => {
            if let Some(text) = response.text() {
                println!("   Conversation response received");
                conversation.add_model_response(text);
            }
            println!("   History length: {} turns", conversation.history().len());
        }
        Err(e) => println!("   Error: {}", e),
    }

    // Token counting
    println!("\n7. Token counting:");
    let contents = vec![Content::user_text(
        "This is a sample text for token counting purposes.",
    )];
    match client.count_tokens(&contents) {
        Ok(count) => println!("   Estimated tokens: {}", count),
        Err(e) => println!("   Error: {}", e),
    }

    // Model capabilities
    println!("\n8. Model capabilities:");
    for model in [
        GeminiModel::Gemini15Pro,
        GeminiModel::Gemini15Flash,
        GeminiModel::Gemini10Pro,
    ] {
        println!(
            "   {}: max input {}, vision={}, audio={}, video={}",
            model.as_str(),
            model.max_input_tokens(),
            model.supports_vision(),
            model.supports_audio(),
            model.supports_video()
        );
    }

    // Token usage summary
    println!("\n9. Token usage summary:");
    let (input, output) = client.token_counter().totals();
    println!("   Total input tokens: {}", input);
    println!("   Total output tokens: {}", output);

    println!("\n=== Demo Complete ===");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gemini_model_properties() {
        assert_eq!(GeminiModel::Gemini15Pro.as_str(), "gemini-1.5-pro");
        assert_eq!(GeminiModel::Gemini15Pro.max_input_tokens(), 2097152);
        assert!(GeminiModel::Gemini15Pro.supports_vision());
        assert!(GeminiModel::Gemini15Pro.supports_audio());
    }

    #[test]
    fn test_model_vision_support() {
        assert!(GeminiModel::Gemini15Pro.supports_vision());
        assert!(GeminiModel::Gemini10ProVision.supports_vision());
        assert!(!GeminiModel::Gemini10Pro.supports_vision());
    }

    #[test]
    fn test_content_creation() {
        let content = Content::user_text("Hello");
        assert_eq!(content.role, Role::User);
        assert_eq!(content.parts.len(), 1);

        let content = Content::model_text("Hi there");
        assert_eq!(content.role, Role::Model);
    }

    #[test]
    fn test_multipart_content() {
        let content = Content::user(vec![
            Part::text("Look at this image"),
            Part::image_base64(vec![1, 2, 3], "image/png"),
        ]);

        assert_eq!(content.parts.len(), 2);
    }

    #[test]
    fn test_part_variants() {
        let text = Part::text("Hello");
        assert!(matches!(text, Part::Text(_)));

        let image = Part::image_base64(vec![1, 2, 3], "image/jpeg");
        assert!(matches!(image, Part::InlineData { .. }));

        let file = Part::file_uri("gs://bucket/file", "video/mp4");
        assert!(matches!(file, Part::FileData { .. }));

        let func_call = Part::function_call("test", serde_json::json!({}));
        assert!(matches!(func_call, Part::FunctionCall { .. }));
    }

    #[test]
    fn test_generation_config() {
        let config = GenerationConfig::new()
            .temperature(0.5)
            .top_p(0.9)
            .top_k(40)
            .max_output_tokens(1000)
            .json_response();

        assert_eq!(config.temperature, Some(0.5));
        assert_eq!(config.top_p, Some(0.9));
        assert_eq!(config.top_k, Some(40));
        assert_eq!(config.max_output_tokens, Some(1000));
        assert_eq!(
            config.response_mime_type,
            Some("application/json".to_string())
        );
    }

    #[test]
    fn test_temperature_clamping() {
        let config = GenerationConfig::new().temperature(3.0);
        assert_eq!(config.temperature, Some(2.0));

        let config = GenerationConfig::new().temperature(-1.0);
        assert_eq!(config.temperature, Some(0.0));
    }

    #[test]
    fn test_safety_setting() {
        let setting = SafetySetting::new(
            HarmCategory::HateSpeech,
            HarmBlockThreshold::BlockMediumAndAbove,
        );

        assert_eq!(setting.category, HarmCategory::HateSpeech);
        assert_eq!(setting.threshold, HarmBlockThreshold::BlockMediumAndAbove);
    }

    #[test]
    fn test_harm_category_strings() {
        assert_eq!(
            HarmCategory::HateSpeech.as_str(),
            "HARM_CATEGORY_HATE_SPEECH"
        );
        assert_eq!(
            HarmCategory::DangerousContent.as_str(),
            "HARM_CATEGORY_DANGEROUS_CONTENT"
        );
    }

    #[test]
    fn test_function_declaration() {
        let func = FunctionDeclaration::new("search", "Search the web").with_parameters(
            serde_json::json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string" }
                }
            }),
        );

        assert_eq!(func.name, "search");
        assert_eq!(func.description, "Search the web");
    }

    #[test]
    fn test_generate_request_builder() {
        let request = GenerateRequest::new(GeminiModel::Gemini15Pro)
            .content(Content::user_text("Hello"))
            .system_instruction("Be helpful")
            .generation_config(GenerationConfig::new().temperature(0.5));

        assert_eq!(request.contents.len(), 1);
        assert!(request.system_instruction.is_some());
        assert!(request.generation_config.is_some());
    }

    #[test]
    fn test_gemini_config() {
        let config = GeminiConfig::new("test-key")
            .project("my-project")
            .location("europe-west1")
            .timeout(Duration::from_secs(30));

        assert_eq!(config.api_key, "test-key");
        assert_eq!(config.project_id, Some("my-project".to_string()));
        assert_eq!(config.location, "europe-west1");
    }

    #[test]
    fn test_gemini_client_creation() {
        let config = GeminiConfig::new("test-key");
        let client = GeminiClient::new(config);

        let (input, output) = client.token_counter().totals();
        assert_eq!(input, 0);
        assert_eq!(output, 0);
    }

    #[test]
    fn test_generate_content() {
        let config = GeminiConfig::new("test-key");
        let client = GeminiClient::new(config);

        let request =
            GenerateRequest::new(GeminiModel::Gemini15Pro).content(Content::user_text("Hello"));

        let response = client.generate(request).unwrap();

        assert!(!response.candidates.is_empty());
        assert!(response.text().is_some());
    }

    #[test]
    fn test_empty_contents_error() {
        let config = GeminiConfig::new("test-key");
        let client = GeminiClient::new(config);

        let request = GenerateRequest::new(GeminiModel::Gemini15Pro);
        let result = client.generate(request);

        assert!(matches!(result, Err(GeminiError::InvalidRequest(_))));
    }

    #[test]
    fn test_vision_model_validation() {
        let config = GeminiConfig::new("test-key");
        let client = GeminiClient::new(config);

        // Vision content with non-vision model should fail
        let request = GenerateRequest::new(GeminiModel::Gemini10Pro).content(Content::user(vec![
            Part::text("What's in this image?"),
            Part::image_base64(vec![1, 2, 3], "image/png"),
        ]));

        let result = client.generate(request);
        assert!(matches!(result, Err(GeminiError::InvalidRequest(_))));
    }

    #[test]
    fn test_token_counting() {
        let config = GeminiConfig::new("test-key");
        let client = GeminiClient::new(config);

        let contents = vec![Content::user_text("Hello world")];
        let count = client.count_tokens(&contents).unwrap();

        assert!(count > 0);
    }

    #[test]
    fn test_token_counter() {
        let counter = TokenCounter::new();

        counter.record(100, 50);
        counter.record(200, 100);

        let (input, output) = counter.totals();
        assert_eq!(input, 300);
        assert_eq!(output, 150);
    }

    #[test]
    fn test_conversation() {
        let mut conv = Conversation::new().with_system_instruction("Be helpful");

        conv.add_user_message("Hello");
        conv.add_model_response("Hi there!");
        conv.add_user_message("How are you?");

        assert_eq!(conv.history().len(), 3);

        let request = conv.to_request(GeminiModel::Gemini15Flash);
        assert_eq!(request.contents.len(), 3);
        assert!(request.system_instruction.is_some());
    }

    #[test]
    fn test_conversation_clear() {
        let mut conv = Conversation::new();
        conv.add_user_message("Test");
        conv.add_model_response("Response");

        assert_eq!(conv.history().len(), 2);

        conv.clear();
        assert_eq!(conv.history().len(), 0);
    }

    #[test]
    fn test_candidate_helpers() {
        let candidate = Candidate {
            content: Content::model(vec![
                Part::text("Hello"),
                Part::function_call("test", serde_json::json!({"arg": "value"})),
            ]),
            finish_reason: FinishReason::Stop,
            safety_ratings: vec![],
            citation_metadata: None,
            index: 0,
        };

        assert_eq!(candidate.text(), Some("Hello"));
        assert_eq!(candidate.function_calls().len(), 1);
    }

    #[test]
    fn test_response_helpers() {
        let response = GenerateResponse {
            candidates: vec![Candidate {
                content: Content::model_text("Test response"),
                finish_reason: FinishReason::Stop,
                safety_ratings: vec![],
                citation_metadata: None,
                index: 0,
            }],
            prompt_feedback: None,
            usage_metadata: None,
        };

        assert_eq!(response.text(), Some("Test response"));
    }

    #[test]
    fn test_finish_reasons() {
        assert_ne!(FinishReason::Stop, FinishReason::MaxTokens);
        assert_ne!(FinishReason::Safety, FinishReason::Recitation);
    }

    #[test]
    fn test_roles() {
        assert_eq!(Role::User.as_str(), "user");
        assert_eq!(Role::Model.as_str(), "model");
    }
}
