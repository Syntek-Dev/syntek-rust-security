//! Perplexity AI Client Implementation
//!
//! Comprehensive client for Perplexity's search-augmented generation API
//! with support for real-time web search and citations.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Perplexity model variants
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerplexityModel {
    /// Lightweight model for quick responses
    SonarSmall,
    /// Medium model balancing speed and quality
    SonarMedium,
    /// Large model for complex queries
    SonarLarge,
    /// Online model with real-time web search
    SonarSmallOnline,
    /// Online medium model
    SonarMediumOnline,
    /// Online large model
    SonarLargeOnline,
    /// Code-focused model
    Codellama34bInstruct,
    /// Mixtral model
    Mixtral8x7bInstruct,
}

impl PerplexityModel {
    pub fn as_str(&self) -> &'static str {
        match self {
            PerplexityModel::SonarSmall => "sonar-small-chat",
            PerplexityModel::SonarMedium => "sonar-medium-chat",
            PerplexityModel::SonarLarge => "sonar-large-chat",
            PerplexityModel::SonarSmallOnline => "sonar-small-online",
            PerplexityModel::SonarMediumOnline => "sonar-medium-online",
            PerplexityModel::SonarLargeOnline => "sonar-large-online",
            PerplexityModel::Codellama34bInstruct => "codellama-34b-instruct",
            PerplexityModel::Mixtral8x7bInstruct => "mixtral-8x7b-instruct",
        }
    }

    pub fn max_tokens(&self) -> u32 {
        match self {
            PerplexityModel::SonarSmall => 16384,
            PerplexityModel::SonarMedium => 16384,
            PerplexityModel::SonarLarge => 16384,
            PerplexityModel::SonarSmallOnline => 12000,
            PerplexityModel::SonarMediumOnline => 12000,
            PerplexityModel::SonarLargeOnline => 12000,
            PerplexityModel::Codellama34bInstruct => 16384,
            PerplexityModel::Mixtral8x7bInstruct => 16384,
        }
    }

    pub fn supports_online_search(&self) -> bool {
        matches!(
            self,
            PerplexityModel::SonarSmallOnline
                | PerplexityModel::SonarMediumOnline
                | PerplexityModel::SonarLargeOnline
        )
    }

    pub fn is_code_model(&self) -> bool {
        matches!(self, PerplexityModel::Codellama34bInstruct)
    }

    pub fn cost_per_1k_tokens(&self) -> f64 {
        match self {
            PerplexityModel::SonarSmall => 0.0002,
            PerplexityModel::SonarMedium => 0.0006,
            PerplexityModel::SonarLarge => 0.001,
            PerplexityModel::SonarSmallOnline => 0.0005,
            PerplexityModel::SonarMediumOnline => 0.001,
            PerplexityModel::SonarLargeOnline => 0.002,
            PerplexityModel::Codellama34bInstruct => 0.0004,
            PerplexityModel::Mixtral8x7bInstruct => 0.0006,
        }
    }
}

/// Message role
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Role {
    System,
    User,
    Assistant,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::System => "system",
            Role::User => "user",
            Role::Assistant => "assistant",
        }
    }
}

/// Chat message
#[derive(Debug, Clone)]
pub struct Message {
    pub role: Role,
    pub content: String,
}

impl Message {
    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: Role::System,
            content: content.into(),
        }
    }

    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: Role::User,
            content: content.into(),
        }
    }

    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            role: Role::Assistant,
            content: content.into(),
        }
    }
}

/// Search domain filter
#[derive(Debug, Clone)]
pub enum SearchDomain {
    /// Include only these domains
    Include(Vec<String>),
    /// Exclude these domains
    Exclude(Vec<String>),
}

/// Search recency filter
#[derive(Debug, Clone, Copy)]
pub enum SearchRecency {
    /// Last hour
    Hour,
    /// Last day
    Day,
    /// Last week
    Week,
    /// Last month
    Month,
    /// Last year
    Year,
}

impl SearchRecency {
    pub fn as_str(&self) -> &'static str {
        match self {
            SearchRecency::Hour => "hour",
            SearchRecency::Day => "day",
            SearchRecency::Week => "week",
            SearchRecency::Month => "month",
            SearchRecency::Year => "year",
        }
    }
}

/// Chat completion request
#[derive(Debug, Clone)]
pub struct ChatRequest {
    pub model: PerplexityModel,
    pub messages: Vec<Message>,
    pub temperature: Option<f32>,
    pub top_p: Option<f32>,
    pub top_k: Option<u32>,
    pub max_tokens: Option<u32>,
    pub presence_penalty: Option<f32>,
    pub frequency_penalty: Option<f32>,
    pub search_domain_filter: Option<SearchDomain>,
    pub search_recency_filter: Option<SearchRecency>,
    pub return_citations: bool,
    pub return_images: bool,
    pub return_related_questions: bool,
    pub stream: bool,
}

impl ChatRequest {
    pub fn new(model: PerplexityModel) -> Self {
        Self {
            model,
            messages: Vec::new(),
            temperature: None,
            top_p: None,
            top_k: None,
            max_tokens: None,
            presence_penalty: None,
            frequency_penalty: None,
            search_domain_filter: None,
            search_recency_filter: None,
            return_citations: true,
            return_images: false,
            return_related_questions: false,
            stream: false,
        }
    }

    pub fn message(mut self, message: Message) -> Self {
        self.messages.push(message);
        self
    }

    pub fn messages(mut self, messages: Vec<Message>) -> Self {
        self.messages = messages;
        self
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

    pub fn max_tokens(mut self, tokens: u32) -> Self {
        self.max_tokens = Some(tokens);
        self
    }

    pub fn include_domains(mut self, domains: Vec<String>) -> Self {
        self.search_domain_filter = Some(SearchDomain::Include(domains));
        self
    }

    pub fn exclude_domains(mut self, domains: Vec<String>) -> Self {
        self.search_domain_filter = Some(SearchDomain::Exclude(domains));
        self
    }

    pub fn recency(mut self, recency: SearchRecency) -> Self {
        self.search_recency_filter = Some(recency);
        self
    }

    pub fn with_citations(mut self, enable: bool) -> Self {
        self.return_citations = enable;
        self
    }

    pub fn with_images(mut self, enable: bool) -> Self {
        self.return_images = enable;
        self
    }

    pub fn with_related_questions(mut self, enable: bool) -> Self {
        self.return_related_questions = enable;
        self
    }

    pub fn stream(mut self) -> Self {
        self.stream = true;
        self
    }
}

/// Citation from web search
#[derive(Debug, Clone)]
pub struct Citation {
    pub url: String,
    pub title: Option<String>,
    pub snippet: Option<String>,
    pub published_date: Option<String>,
}

impl Citation {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            title: None,
            snippet: None,
            published_date: None,
        }
    }

    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    pub fn with_snippet(mut self, snippet: impl Into<String>) -> Self {
        self.snippet = Some(snippet.into());
        self
    }
}

/// Image from search results
#[derive(Debug, Clone)]
pub struct SearchImage {
    pub url: String,
    pub alt_text: Option<String>,
    pub source_url: Option<String>,
}

/// Related question suggestion
#[derive(Debug, Clone)]
pub struct RelatedQuestion {
    pub question: String,
}

/// Chat completion response
#[derive(Debug, Clone)]
pub struct ChatResponse {
    pub id: String,
    pub model: String,
    pub object: String,
    pub created: u64,
    pub choices: Vec<Choice>,
    pub usage: Usage,
    pub citations: Vec<Citation>,
    pub images: Vec<SearchImage>,
    pub related_questions: Vec<RelatedQuestion>,
}

impl ChatResponse {
    pub fn text(&self) -> Option<&str> {
        self.choices.first().map(|c| c.message.content.as_str())
    }

    pub fn has_citations(&self) -> bool {
        !self.citations.is_empty()
    }

    pub fn citation_urls(&self) -> Vec<&str> {
        self.citations.iter().map(|c| c.url.as_str()).collect()
    }
}

#[derive(Debug, Clone)]
pub struct Choice {
    pub index: u32,
    pub message: Message,
    pub finish_reason: FinishReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinishReason {
    Stop,
    Length,
    Error,
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
    pub model: String,
    pub object: String,
    pub created: u64,
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
}

/// Perplexity client configuration
#[derive(Debug, Clone)]
pub struct PerplexityConfig {
    pub api_key: String,
    pub base_url: String,
    pub timeout: Duration,
    pub max_retries: u32,
    pub retry_delay: Duration,
}

impl PerplexityConfig {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            base_url: "https://api.perplexity.ai".to_string(),
            timeout: Duration::from_secs(60),
            max_retries: 3,
            retry_delay: Duration::from_secs(1),
        }
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

/// Rate limiter
pub struct RateLimiter {
    requests_per_minute: u32,
    tokens: AtomicU64,
    last_refill: std::sync::Mutex<Instant>,
}

impl RateLimiter {
    pub fn new(requests_per_minute: u32) -> Self {
        Self {
            requests_per_minute,
            tokens: AtomicU64::new(requests_per_minute as u64),
            last_refill: std::sync::Mutex::new(Instant::now()),
        }
    }

    pub fn try_acquire(&self) -> bool {
        self.refill();

        let current = self.tokens.load(Ordering::SeqCst);
        if current > 0 {
            self.tokens.fetch_sub(1, Ordering::SeqCst);
            true
        } else {
            false
        }
    }

    fn refill(&self) {
        let mut last = self.last_refill.lock().unwrap();
        let elapsed = last.elapsed();

        if elapsed >= Duration::from_secs(60) {
            self.tokens
                .store(self.requests_per_minute as u64, Ordering::SeqCst);
            *last = Instant::now();
        }
    }
}

/// Cost tracker
pub struct CostTracker {
    total_tokens: AtomicU64,
    total_cost_micros: AtomicU64,
}

impl CostTracker {
    pub fn new() -> Self {
        Self {
            total_tokens: AtomicU64::new(0),
            total_cost_micros: AtomicU64::new(0),
        }
    }

    pub fn record(&self, model: PerplexityModel, tokens: u32) {
        self.total_tokens.fetch_add(tokens as u64, Ordering::SeqCst);

        let cost = (tokens as f64 / 1000.0) * model.cost_per_1k_tokens();
        let cost_micros = (cost * 1_000_000.0) as u64;
        self.total_cost_micros
            .fetch_add(cost_micros, Ordering::SeqCst);
    }

    pub fn total_tokens(&self) -> u64 {
        self.total_tokens.load(Ordering::SeqCst)
    }

    pub fn total_cost_usd(&self) -> f64 {
        self.total_cost_micros.load(Ordering::SeqCst) as f64 / 1_000_000.0
    }
}

impl Default for CostTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Perplexity client
pub struct PerplexityClient {
    config: PerplexityConfig,
    rate_limiter: Arc<RateLimiter>,
    cost_tracker: Arc<CostTracker>,
}

impl PerplexityClient {
    pub fn new(config: PerplexityConfig) -> Self {
        Self {
            config,
            rate_limiter: Arc::new(RateLimiter::new(60)),
            cost_tracker: Arc::new(CostTracker::new()),
        }
    }

    pub fn with_rate_limit(mut self, requests_per_minute: u32) -> Self {
        self.rate_limiter = Arc::new(RateLimiter::new(requests_per_minute));
        self
    }

    /// Create a chat completion with search-augmented generation
    pub fn chat(&self, request: ChatRequest) -> Result<ChatResponse, PerplexityError> {
        if !self.rate_limiter.try_acquire() {
            return Err(PerplexityError::RateLimit);
        }

        // Validate request
        self.validate_request(&request)?;

        // Simulate API call
        let response = self.mock_chat_response(&request);

        // Track costs
        self.cost_tracker
            .record(request.model, response.usage.total_tokens);

        Ok(response)
    }

    /// Get cost tracker
    pub fn cost_tracker(&self) -> &CostTracker {
        &self.cost_tracker
    }

    fn validate_request(&self, request: &ChatRequest) -> Result<(), PerplexityError> {
        if request.messages.is_empty() {
            return Err(PerplexityError::InvalidRequest(
                "Messages cannot be empty".to_string(),
            ));
        }

        // Check if online search is requested with non-online model
        if request.search_domain_filter.is_some() || request.search_recency_filter.is_some() {
            if !request.model.supports_online_search() {
                return Err(PerplexityError::InvalidRequest(format!(
                    "Model {} does not support online search. Use an online model.",
                    request.model.as_str()
                )));
            }
        }

        Ok(())
    }

    fn mock_chat_response(&self, request: &ChatRequest) -> ChatResponse {
        let citations = if request.return_citations && request.model.supports_online_search() {
            vec![
                Citation::new("https://example.com/article1")
                    .with_title("Relevant Article 1")
                    .with_snippet("This is a relevant snippet..."),
                Citation::new("https://example.com/article2").with_title("Relevant Article 2"),
            ]
        } else {
            vec![]
        };

        let images = if request.return_images && request.model.supports_online_search() {
            vec![SearchImage {
                url: "https://example.com/image.jpg".to_string(),
                alt_text: Some("Related image".to_string()),
                source_url: Some("https://example.com".to_string()),
            }]
        } else {
            vec![]
        };

        let related_questions = if request.return_related_questions {
            vec![
                RelatedQuestion {
                    question: "What are related topics?".to_string(),
                },
                RelatedQuestion {
                    question: "How does this compare to alternatives?".to_string(),
                },
            ]
        } else {
            vec![]
        };

        ChatResponse {
            id: format!("pplx-{}", uuid_v4()),
            model: request.model.as_str().to_string(),
            object: "chat.completion".to_string(),
            created: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            choices: vec![Choice {
                index: 0,
                message: Message::assistant(
                    "This is a mock response from Perplexity with search-augmented generation.",
                ),
                finish_reason: FinishReason::Stop,
            }],
            usage: Usage {
                prompt_tokens: 50,
                completion_tokens: 30,
                total_tokens: 80,
            },
            citations,
            images,
            related_questions,
        }
    }
}

/// Perplexity error types
#[derive(Debug)]
pub enum PerplexityError {
    RateLimit,
    InvalidRequest(String),
    ApiError { status: u16, message: String },
    Timeout,
    NetworkError(String),
}

impl std::fmt::Display for PerplexityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PerplexityError::RateLimit => write!(f, "Rate limit exceeded"),
            PerplexityError::InvalidRequest(msg) => write!(f, "Invalid request: {}", msg),
            PerplexityError::ApiError { status, message } => {
                write!(f, "API error ({}): {}", status, message)
            }
            PerplexityError::Timeout => write!(f, "Request timed out"),
            PerplexityError::NetworkError(msg) => write!(f, "Network error: {}", msg),
        }
    }
}

impl std::error::Error for PerplexityError {}

/// Research assistant for complex queries
pub struct ResearchAssistant {
    client: Arc<PerplexityClient>,
    model: PerplexityModel,
    system_prompt: Option<String>,
}

impl ResearchAssistant {
    pub fn new(client: Arc<PerplexityClient>) -> Self {
        Self {
            client,
            model: PerplexityModel::SonarLargeOnline,
            system_prompt: None,
        }
    }

    pub fn model(mut self, model: PerplexityModel) -> Self {
        self.model = model;
        self
    }

    pub fn system_prompt(mut self, prompt: impl Into<String>) -> Self {
        self.system_prompt = Some(prompt.into());
        self
    }

    /// Research a topic with citations
    pub fn research(&self, query: impl Into<String>) -> Result<ResearchResult, PerplexityError> {
        let mut request = ChatRequest::new(self.model)
            .message(Message::user(query))
            .with_citations(true)
            .with_related_questions(true);

        if let Some(system) = &self.system_prompt {
            request = ChatRequest::new(self.model)
                .message(Message::system(system.clone()))
                .message(request.messages.into_iter().next().unwrap())
                .with_citations(true)
                .with_related_questions(true);
        }

        let response = self.client.chat(request)?;

        Ok(ResearchResult {
            answer: response.text().unwrap_or("").to_string(),
            citations: response.citations,
            related_questions: response
                .related_questions
                .into_iter()
                .map(|rq| rq.question)
                .collect(),
            tokens_used: response.usage.total_tokens,
        })
    }

    /// Research with domain filtering
    pub fn research_from_domains(
        &self,
        query: impl Into<String>,
        domains: Vec<String>,
    ) -> Result<ResearchResult, PerplexityError> {
        let request = ChatRequest::new(self.model)
            .message(Message::user(query))
            .include_domains(domains)
            .with_citations(true);

        let response = self.client.chat(request)?;

        Ok(ResearchResult {
            answer: response.text().unwrap_or("").to_string(),
            citations: response.citations,
            related_questions: vec![],
            tokens_used: response.usage.total_tokens,
        })
    }

    /// Research recent information
    pub fn research_recent(
        &self,
        query: impl Into<String>,
        recency: SearchRecency,
    ) -> Result<ResearchResult, PerplexityError> {
        let request = ChatRequest::new(self.model)
            .message(Message::user(query))
            .recency(recency)
            .with_citations(true);

        let response = self.client.chat(request)?;

        Ok(ResearchResult {
            answer: response.text().unwrap_or("").to_string(),
            citations: response.citations,
            related_questions: vec![],
            tokens_used: response.usage.total_tokens,
        })
    }
}

/// Research result with citations
#[derive(Debug, Clone)]
pub struct ResearchResult {
    pub answer: String,
    pub citations: Vec<Citation>,
    pub related_questions: Vec<String>,
    pub tokens_used: u32,
}

impl ResearchResult {
    pub fn format_with_citations(&self) -> String {
        let mut output = self.answer.clone();

        if !self.citations.is_empty() {
            output.push_str("\n\nSources:\n");
            for (i, citation) in self.citations.iter().enumerate() {
                let title = citation.title.as_deref().unwrap_or("Source");
                output.push_str(&format!("[{}] {} - {}\n", i + 1, title, citation.url));
            }
        }

        output
    }
}

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
    println!("=== Perplexity AI Client Demo ===\n");

    // Create client
    let config = PerplexityConfig::new("pplx-test-key-12345");
    let client = Arc::new(PerplexityClient::new(config));

    // Simple chat without search
    println!("1. Simple chat (no search):");
    let request = ChatRequest::new(PerplexityModel::SonarMedium)
        .message(Message::system("You are a helpful assistant."))
        .message(Message::user("Explain what Rust ownership is."))
        .temperature(0.7)
        .max_tokens(500);

    match client.chat(request) {
        Ok(response) => {
            println!("   Model: {}", response.model);
            if let Some(text) = response.text() {
                println!("   Response: {}", text);
            }
            println!("   Tokens: {}", response.usage.total_tokens);
            println!("   Citations: {}", response.citations.len());
        }
        Err(e) => println!("   Error: {}", e),
    }

    // Search-augmented generation
    println!("\n2. Search-augmented generation:");
    let request = ChatRequest::new(PerplexityModel::SonarLargeOnline)
        .message(Message::user(
            "What are the latest developments in Rust async?",
        ))
        .with_citations(true)
        .with_images(true)
        .with_related_questions(true)
        .max_tokens(1000);

    match client.chat(request) {
        Ok(response) => {
            println!("   Response with {} citations", response.citations.len());
            for citation in &response.citations {
                println!("   - {}", citation.url);
                if let Some(title) = &citation.title {
                    println!("     Title: {}", title);
                }
            }
            println!("   Related questions: {}", response.related_questions.len());
        }
        Err(e) => println!("   Error: {}", e),
    }

    // Domain-filtered search
    println!("\n3. Domain-filtered search:");
    let request = ChatRequest::new(PerplexityModel::SonarMediumOnline)
        .message(Message::user("Rust memory safety"))
        .include_domains(vec![
            "rust-lang.org".to_string(),
            "doc.rust-lang.org".to_string(),
            "github.com".to_string(),
        ])
        .with_citations(true);

    match client.chat(request) {
        Ok(response) => {
            println!(
                "   Filtered search returned {} citations",
                response.citations.len()
            );
        }
        Err(e) => println!("   Error: {}", e),
    }

    // Recency-filtered search
    println!("\n4. Recent information search:");
    let request = ChatRequest::new(PerplexityModel::SonarSmallOnline)
        .message(Message::user("Latest Rust version releases"))
        .recency(SearchRecency::Week)
        .with_citations(true);

    match client.chat(request) {
        Ok(response) => {
            println!("   Recent search (last week) completed");
            println!("   Citations: {}", response.citations.len());
        }
        Err(e) => println!("   Error: {}", e),
    }

    // Research assistant
    println!("\n5. Research assistant:");
    let assistant = ResearchAssistant::new(client.clone())
        .model(PerplexityModel::SonarLargeOnline)
        .system_prompt("You are a technical research assistant. Provide detailed, accurate information with citations.");

    match assistant.research("What is the state of WebAssembly support in Rust?") {
        Ok(result) => {
            println!("   Answer length: {} chars", result.answer.len());
            println!("   Citations: {}", result.citations.len());
            println!("   Related questions: {}", result.related_questions.len());
            for q in &result.related_questions {
                println!("   - {}", q);
            }
        }
        Err(e) => println!("   Error: {}", e),
    }

    // Research from specific domains
    println!("\n6. Research from specific domains:");
    match assistant.research_from_domains(
        "Rust async runtime comparison",
        vec!["tokio.rs".to_string(), "async.rs".to_string()],
    ) {
        Ok(result) => {
            println!("   Domain-filtered research complete");
            println!("   Tokens used: {}", result.tokens_used);
        }
        Err(e) => println!("   Error: {}", e),
    }

    // Code-focused model
    println!("\n7. Code-focused model:");
    let request = ChatRequest::new(PerplexityModel::Codellama34bInstruct)
        .message(Message::user(
            "Write a Rust function that implements binary search",
        ))
        .max_tokens(500);

    match client.chat(request) {
        Ok(response) => {
            println!("   Code model response received");
            println!("   Model: {}", response.model);
        }
        Err(e) => println!("   Error: {}", e),
    }

    // Model comparison
    println!("\n8. Model comparison:");
    for model in [
        PerplexityModel::SonarSmall,
        PerplexityModel::SonarLargeOnline,
        PerplexityModel::Codellama34bInstruct,
    ] {
        println!(
            "   {}: max {} tokens, online={}, code={}, ${}/1k",
            model.as_str(),
            model.max_tokens(),
            model.supports_online_search(),
            model.is_code_model(),
            model.cost_per_1k_tokens()
        );
    }

    // Cost tracking
    println!("\n9. Cost tracking:");
    println!("   Total tokens: {}", client.cost_tracker().total_tokens());
    println!(
        "   Total cost: ${:.6}",
        client.cost_tracker().total_cost_usd()
    );

    println!("\n=== Demo Complete ===");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_perplexity_model_properties() {
        assert_eq!(
            PerplexityModel::SonarLargeOnline.as_str(),
            "sonar-large-online"
        );
        assert!(PerplexityModel::SonarLargeOnline.supports_online_search());
        assert!(!PerplexityModel::SonarSmall.supports_online_search());
    }

    #[test]
    fn test_code_model() {
        assert!(PerplexityModel::Codellama34bInstruct.is_code_model());
        assert!(!PerplexityModel::SonarLarge.is_code_model());
    }

    #[test]
    fn test_model_costs() {
        assert!(PerplexityModel::SonarSmall.cost_per_1k_tokens() > 0.0);
        assert!(
            PerplexityModel::SonarLargeOnline.cost_per_1k_tokens()
                > PerplexityModel::SonarSmall.cost_per_1k_tokens()
        );
    }

    #[test]
    fn test_message_creation() {
        let system = Message::system("You are helpful");
        assert_eq!(system.role, Role::System);

        let user = Message::user("Hello");
        assert_eq!(user.role, Role::User);

        let assistant = Message::assistant("Hi");
        assert_eq!(assistant.role, Role::Assistant);
    }

    #[test]
    fn test_chat_request_builder() {
        let request = ChatRequest::new(PerplexityModel::SonarLargeOnline)
            .message(Message::user("Hello"))
            .temperature(0.5)
            .max_tokens(100)
            .with_citations(true)
            .with_related_questions(true);

        assert_eq!(request.temperature, Some(0.5));
        assert_eq!(request.max_tokens, Some(100));
        assert!(request.return_citations);
        assert!(request.return_related_questions);
    }

    #[test]
    fn test_domain_filtering() {
        let request = ChatRequest::new(PerplexityModel::SonarSmallOnline)
            .include_domains(vec!["example.com".to_string()]);

        match request.search_domain_filter {
            Some(SearchDomain::Include(domains)) => {
                assert_eq!(domains.len(), 1);
            }
            _ => panic!("Expected include domains"),
        }
    }

    #[test]
    fn test_exclude_domains() {
        let request = ChatRequest::new(PerplexityModel::SonarSmallOnline)
            .exclude_domains(vec!["bad-site.com".to_string()]);

        match request.search_domain_filter {
            Some(SearchDomain::Exclude(domains)) => {
                assert_eq!(domains.len(), 1);
            }
            _ => panic!("Expected exclude domains"),
        }
    }

    #[test]
    fn test_recency_filter() {
        let request =
            ChatRequest::new(PerplexityModel::SonarSmallOnline).recency(SearchRecency::Week);

        assert!(matches!(
            request.search_recency_filter,
            Some(SearchRecency::Week)
        ));
    }

    #[test]
    fn test_recency_strings() {
        assert_eq!(SearchRecency::Hour.as_str(), "hour");
        assert_eq!(SearchRecency::Day.as_str(), "day");
        assert_eq!(SearchRecency::Week.as_str(), "week");
        assert_eq!(SearchRecency::Month.as_str(), "month");
        assert_eq!(SearchRecency::Year.as_str(), "year");
    }

    #[test]
    fn test_citation_creation() {
        let citation = Citation::new("https://example.com")
            .with_title("Test Article")
            .with_snippet("This is a test...");

        assert_eq!(citation.url, "https://example.com");
        assert_eq!(citation.title, Some("Test Article".to_string()));
    }

    #[test]
    fn test_perplexity_config() {
        let config = PerplexityConfig::new("test-key")
            .base_url("https://custom.api.com")
            .timeout(Duration::from_secs(30));

        assert_eq!(config.api_key, "test-key");
        assert_eq!(config.base_url, "https://custom.api.com");
    }

    #[test]
    fn test_client_creation() {
        let config = PerplexityConfig::new("test-key");
        let client = PerplexityClient::new(config);

        assert_eq!(client.cost_tracker().total_tokens(), 0);
    }

    #[test]
    fn test_chat_completion() {
        let config = PerplexityConfig::new("test-key");
        let client = PerplexityClient::new(config);

        let request =
            ChatRequest::new(PerplexityModel::SonarMedium).message(Message::user("Hello"));

        let response = client.chat(request).unwrap();

        assert!(!response.id.is_empty());
        assert_eq!(response.choices.len(), 1);
    }

    #[test]
    fn test_online_search_validation() {
        let config = PerplexityConfig::new("test-key");
        let client = PerplexityClient::new(config);

        // Non-online model with search options should fail
        let request = ChatRequest::new(PerplexityModel::SonarMedium)
            .message(Message::user("Hello"))
            .recency(SearchRecency::Week);

        let result = client.chat(request);
        assert!(matches!(result, Err(PerplexityError::InvalidRequest(_))));
    }

    #[test]
    fn test_empty_messages_error() {
        let config = PerplexityConfig::new("test-key");
        let client = PerplexityClient::new(config);

        let request = ChatRequest::new(PerplexityModel::SonarMedium);
        let result = client.chat(request);

        assert!(matches!(result, Err(PerplexityError::InvalidRequest(_))));
    }

    #[test]
    fn test_cost_tracker() {
        let tracker = CostTracker::new();

        tracker.record(PerplexityModel::SonarSmall, 1000);
        tracker.record(PerplexityModel::SonarLarge, 1000);

        assert_eq!(tracker.total_tokens(), 2000);
        assert!(tracker.total_cost_usd() > 0.0);
    }

    #[test]
    fn test_rate_limiter() {
        let limiter = RateLimiter::new(10);

        for _ in 0..10 {
            assert!(limiter.try_acquire());
        }
        // Should fail after limit
        assert!(!limiter.try_acquire());
    }

    #[test]
    fn test_response_helpers() {
        let response = ChatResponse {
            id: "test".to_string(),
            model: "sonar-large".to_string(),
            object: "chat.completion".to_string(),
            created: 0,
            choices: vec![Choice {
                index: 0,
                message: Message::assistant("Test response"),
                finish_reason: FinishReason::Stop,
            }],
            usage: Usage {
                prompt_tokens: 10,
                completion_tokens: 5,
                total_tokens: 15,
            },
            citations: vec![Citation::new("https://example.com")],
            images: vec![],
            related_questions: vec![],
        };

        assert_eq!(response.text(), Some("Test response"));
        assert!(response.has_citations());
        assert_eq!(response.citation_urls().len(), 1);
    }

    #[test]
    fn test_research_result_format() {
        let result = ResearchResult {
            answer: "This is the answer.".to_string(),
            citations: vec![
                Citation::new("https://example.com/1").with_title("Source 1"),
                Citation::new("https://example.com/2").with_title("Source 2"),
            ],
            related_questions: vec!["Question 1?".to_string()],
            tokens_used: 100,
        };

        let formatted = result.format_with_citations();
        assert!(formatted.contains("This is the answer."));
        assert!(formatted.contains("Sources:"));
        assert!(formatted.contains("[1]"));
        assert!(formatted.contains("Source 1"));
    }

    #[test]
    fn test_roles() {
        assert_eq!(Role::System.as_str(), "system");
        assert_eq!(Role::User.as_str(), "user");
        assert_eq!(Role::Assistant.as_str(), "assistant");
    }

    #[test]
    fn test_finish_reasons() {
        assert_ne!(FinishReason::Stop, FinishReason::Length);
        assert_ne!(FinishReason::Stop, FinishReason::Error);
    }

    #[test]
    fn test_stream_mode() {
        let request = ChatRequest::new(PerplexityModel::SonarMedium).stream();
        assert!(request.stream);
    }

    #[test]
    fn test_temperature_clamping() {
        let request = ChatRequest::new(PerplexityModel::SonarMedium).temperature(3.0);
        assert_eq!(request.temperature, Some(2.0));
    }

    #[test]
    fn test_top_p_clamping() {
        let request = ChatRequest::new(PerplexityModel::SonarMedium).top_p(1.5);
        assert_eq!(request.top_p, Some(1.0));
    }
}
