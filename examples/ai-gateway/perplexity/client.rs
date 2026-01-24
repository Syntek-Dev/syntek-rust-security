//! Perplexity AI Client
//!
//! Secure client for Perplexity API with:
//! - Search-augmented generation
//! - Citation tracking and verification
//! - Source attribution
//! - Rate limiting and retries
//! - Response caching

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ============================================================================
// Configuration
// ============================================================================

/// Perplexity API configuration
#[derive(Debug, Clone)]
pub struct PerplexityConfig {
    /// API key
    pub api_key: String,
    /// Base URL
    pub base_url: String,
    /// Request timeout
    pub timeout: Duration,
    /// Maximum retries
    pub max_retries: u32,
    /// Enable response caching
    pub enable_cache: bool,
    /// Cache TTL
    pub cache_ttl: Duration,
}

impl PerplexityConfig {
    pub fn new(api_key: &str) -> Self {
        Self {
            api_key: api_key.to_string(),
            base_url: "https://api.perplexity.ai".to_string(),
            timeout: Duration::from_secs(60),
            max_retries: 3,
            enable_cache: true,
            cache_ttl: Duration::from_secs(3600), // 1 hour
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_cache_disabled(mut self) -> Self {
        self.enable_cache = false;
        self
    }
}

// ============================================================================
// Models
// ============================================================================

/// Available Perplexity models
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PerplexityModel {
    /// Sonar small - fast, efficient
    SonarSmall,
    /// Sonar medium - balanced
    SonarMedium,
    /// Sonar large - most capable
    SonarLarge,
    /// Codellama for code tasks
    Codellama,
}

impl PerplexityModel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SonarSmall => "sonar-small-chat",
            Self::SonarMedium => "sonar-medium-chat",
            Self::SonarLarge => "sonar-large-chat",
            Self::Codellama => "codellama-70b-instruct",
        }
    }

    /// Get context window size
    pub fn context_window(&self) -> usize {
        match self {
            Self::SonarSmall => 16384,
            Self::SonarMedium => 16384,
            Self::SonarLarge => 16384,
            Self::Codellama => 16384,
        }
    }

    /// Whether this model supports search
    pub fn supports_search(&self) -> bool {
        matches!(
            self,
            Self::SonarSmall | Self::SonarMedium | Self::SonarLarge
        )
    }
}

impl Default for PerplexityModel {
    fn default() -> Self {
        Self::SonarMedium
    }
}

// ============================================================================
// Request/Response Types
// ============================================================================

/// Message role
#[derive(Debug, Clone, PartialEq)]
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
    pub fn system(content: &str) -> Self {
        Self {
            role: Role::System,
            content: content.to_string(),
        }
    }

    pub fn user(content: &str) -> Self {
        Self {
            role: Role::User,
            content: content.to_string(),
        }
    }

    pub fn assistant(content: &str) -> Self {
        Self {
            role: Role::Assistant,
            content: content.to_string(),
        }
    }
}

/// Search domain filter
#[derive(Debug, Clone)]
pub enum SearchDomain {
    /// Search all domains
    All,
    /// Academic sources only
    Academic,
    /// News sources
    News,
    /// Specific domains
    Domains(Vec<String>),
    /// Exclude specific domains
    ExcludeDomains(Vec<String>),
}

/// Chat completion request
#[derive(Debug, Clone)]
pub struct ChatRequest {
    pub model: PerplexityModel,
    pub messages: Vec<Message>,
    pub max_tokens: Option<u32>,
    pub temperature: Option<f32>,
    pub top_p: Option<f32>,
    pub return_citations: bool,
    pub return_images: bool,
    pub search_domain: SearchDomain,
    pub search_recency: Option<SearchRecency>,
}

/// How recent search results should be
#[derive(Debug, Clone, Copy)]
pub enum SearchRecency {
    Day,
    Week,
    Month,
    Year,
}

impl SearchRecency {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Day => "day",
            Self::Week => "week",
            Self::Month => "month",
            Self::Year => "year",
        }
    }
}

impl ChatRequest {
    pub fn new(model: PerplexityModel, messages: Vec<Message>) -> Self {
        Self {
            model,
            messages,
            max_tokens: None,
            temperature: None,
            top_p: None,
            return_citations: true,
            return_images: false,
            search_domain: SearchDomain::All,
            search_recency: None,
        }
    }

    pub fn with_max_tokens(mut self, max_tokens: u32) -> Self {
        self.max_tokens = Some(max_tokens);
        self
    }

    pub fn with_temperature(mut self, temperature: f32) -> Self {
        self.temperature = Some(temperature.clamp(0.0, 2.0));
        self
    }

    pub fn with_citations(mut self, enabled: bool) -> Self {
        self.return_citations = enabled;
        self
    }

    pub fn with_images(mut self, enabled: bool) -> Self {
        self.return_images = enabled;
        self
    }

    pub fn with_search_domain(mut self, domain: SearchDomain) -> Self {
        self.search_domain = domain;
        self
    }

    pub fn with_recency(mut self, recency: SearchRecency) -> Self {
        self.search_recency = Some(recency);
        self
    }
}

/// Citation from search results
#[derive(Debug, Clone)]
pub struct Citation {
    pub index: usize,
    pub url: String,
    pub title: String,
    pub snippet: Option<String>,
    pub published_date: Option<String>,
    pub author: Option<String>,
}

/// Image from search results
#[derive(Debug, Clone)]
pub struct SearchImage {
    pub url: String,
    pub description: Option<String>,
    pub source_url: Option<String>,
}

/// Chat completion response
#[derive(Debug, Clone)]
pub struct ChatResponse {
    pub id: String,
    pub model: String,
    pub content: String,
    pub citations: Vec<Citation>,
    pub images: Vec<SearchImage>,
    pub usage: Usage,
    pub finish_reason: String,
}

#[derive(Debug, Clone)]
pub struct Usage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

// ============================================================================
// Response Cache
// ============================================================================

struct CacheEntry {
    response: ChatResponse,
    created_at: Instant,
}

/// Simple response cache
pub struct ResponseCache {
    entries: Mutex<HashMap<String, CacheEntry>>,
    ttl: Duration,
    max_entries: usize,
}

impl ResponseCache {
    pub fn new(ttl: Duration, max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl,
            max_entries,
        }
    }

    /// Generate cache key from request
    fn cache_key(request: &ChatRequest) -> String {
        let mut hasher = SimpleHasher::new();
        hasher.update(request.model.as_str().as_bytes());
        for msg in &request.messages {
            hasher.update(msg.role.as_str().as_bytes());
            hasher.update(msg.content.as_bytes());
        }
        if let Some(max_tokens) = request.max_tokens {
            hasher.update(&max_tokens.to_le_bytes());
        }
        format!("{:016x}", hasher.finish())
    }

    /// Get cached response if valid
    pub fn get(&self, request: &ChatRequest) -> Option<ChatResponse> {
        let key = Self::cache_key(request);
        let entries = self.entries.lock().unwrap();

        if let Some(entry) = entries.get(&key) {
            if entry.created_at.elapsed() < self.ttl {
                return Some(entry.response.clone());
            }
        }
        None
    }

    /// Store response in cache
    pub fn put(&self, request: &ChatRequest, response: ChatResponse) {
        let key = Self::cache_key(request);
        let mut entries = self.entries.lock().unwrap();

        // Evict oldest if full
        if entries.len() >= self.max_entries {
            if let Some(oldest_key) = entries
                .iter()
                .min_by_key(|(_, v)| v.created_at)
                .map(|(k, _)| k.clone())
            {
                entries.remove(&oldest_key);
            }
        }

        entries.insert(
            key,
            CacheEntry {
                response,
                created_at: Instant::now(),
            },
        );
    }

    /// Clear expired entries
    pub fn cleanup(&self) {
        let mut entries = self.entries.lock().unwrap();
        entries.retain(|_, v| v.created_at.elapsed() < self.ttl);
    }
}

struct SimpleHasher {
    state: u64,
}

impl SimpleHasher {
    fn new() -> Self {
        Self {
            state: 0xcbf29ce484222325,
        }
    }

    fn update(&mut self, data: &[u8]) {
        for &byte in data {
            self.state ^= byte as u64;
            self.state = self.state.wrapping_mul(0x100000001b3);
        }
    }

    fn finish(&self) -> u64 {
        self.state
    }
}

// ============================================================================
// Citation Verifier
// ============================================================================

/// Verifies and validates citations
pub struct CitationVerifier;

impl CitationVerifier {
    /// Check if a citation URL is from a trusted domain
    pub fn is_trusted_source(citation: &Citation) -> bool {
        let trusted_domains = [
            "wikipedia.org",
            "arxiv.org",
            "github.com",
            "docs.rs",
            "rust-lang.org",
            "mozilla.org",
            "stackoverflow.com",
            "nist.gov",
            "owasp.org",
        ];

        trusted_domains.iter().any(|d| citation.url.contains(d))
    }

    /// Extract domain from URL
    pub fn extract_domain(url: &str) -> Option<String> {
        let url = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))?;
        let domain = url.split('/').next()?;
        Some(domain.to_string())
    }

    /// Check if citation has required fields
    pub fn is_complete(citation: &Citation) -> bool {
        !citation.url.is_empty() && !citation.title.is_empty()
    }

    /// Get citation quality score (0-100)
    pub fn quality_score(citation: &Citation) -> u32 {
        let mut score = 0u32;

        // Has URL
        if !citation.url.is_empty() {
            score += 20;
        }

        // Has title
        if !citation.title.is_empty() {
            score += 20;
        }

        // Has snippet
        if citation.snippet.is_some() {
            score += 20;
        }

        // Has date
        if citation.published_date.is_some() {
            score += 20;
        }

        // From trusted source
        if Self::is_trusted_source(citation) {
            score += 20;
        }

        score
    }
}

// ============================================================================
// Client Implementation
// ============================================================================

/// Perplexity AI client
pub struct PerplexityClient {
    config: PerplexityConfig,
    cache: Option<ResponseCache>,
    request_count: AtomicU64,
    total_tokens: AtomicU64,
}

impl PerplexityClient {
    pub fn new(config: PerplexityConfig) -> Self {
        let cache = if config.enable_cache {
            Some(ResponseCache::new(config.cache_ttl, 1000))
        } else {
            None
        };

        Self {
            config,
            cache,
            request_count: AtomicU64::new(0),
            total_tokens: AtomicU64::new(0),
        }
    }

    /// Send a chat completion request
    pub fn chat(&self, request: ChatRequest) -> Result<ChatResponse, PerplexityError> {
        // Check cache first
        if let Some(ref cache) = self.cache {
            if let Some(cached) = cache.get(&request) {
                return Ok(cached);
            }
        }

        self.request_count.fetch_add(1, Ordering::Relaxed);

        // Build API request
        let _url = format!("{}/chat/completions", self.config.base_url);
        let _body = self.build_request_body(&request);

        // Simulate API call with retries
        let response = self.execute_with_retry(&request)?;

        // Track tokens
        self.total_tokens
            .fetch_add(response.usage.total_tokens as u64, Ordering::Relaxed);

        // Cache response
        if let Some(ref cache) = self.cache {
            cache.put(&request, response.clone());
        }

        Ok(response)
    }

    fn build_request_body(&self, request: &ChatRequest) -> String {
        let messages: Vec<String> = request
            .messages
            .iter()
            .map(|m| {
                format!(
                    r#"{{"role":"{}","content":"{}"}}"#,
                    m.role.as_str(),
                    escape_json(&m.content)
                )
            })
            .collect();

        let mut body = format!(
            r#"{{"model":"{}","messages":[{}]"#,
            request.model.as_str(),
            messages.join(",")
        );

        if let Some(max_tokens) = request.max_tokens {
            body.push_str(&format!(r#","max_tokens":{}"#, max_tokens));
        }
        if let Some(temperature) = request.temperature {
            body.push_str(&format!(r#","temperature":{}"#, temperature));
        }
        if request.return_citations {
            body.push_str(r#","return_citations":true"#);
        }
        if request.return_images {
            body.push_str(r#","return_images":true"#);
        }

        // Search domain filter
        match &request.search_domain {
            SearchDomain::All => {}
            SearchDomain::Academic => {
                body.push_str(r#","search_domain_filter":["academic"]"#);
            }
            SearchDomain::News => {
                body.push_str(r#","search_domain_filter":["news"]"#);
            }
            SearchDomain::Domains(domains) => {
                let domains_str = domains
                    .iter()
                    .map(|d| format!(r#""{}""#, d))
                    .collect::<Vec<_>>()
                    .join(",");
                body.push_str(&format!(r#","search_domain_filter":[{}]"#, domains_str));
            }
            SearchDomain::ExcludeDomains(domains) => {
                let domains_str = domains
                    .iter()
                    .map(|d| format!(r#""{}""#, d))
                    .collect::<Vec<_>>()
                    .join(",");
                body.push_str(&format!(
                    r#","search_domain_filter_exclude":[{}]"#,
                    domains_str
                ));
            }
        }

        if let Some(recency) = request.search_recency {
            body.push_str(&format!(
                r#","search_recency_filter":"{}""#,
                recency.as_str()
            ));
        }

        body.push('}');
        body
    }

    fn execute_with_retry(&self, request: &ChatRequest) -> Result<ChatResponse, PerplexityError> {
        let mut last_error = None;

        for attempt in 0..self.config.max_retries {
            match self.simulate_api_call(request) {
                Ok(response) => return Ok(response),
                Err(e) => {
                    if !e.is_retryable() {
                        return Err(e);
                    }
                    last_error = Some(e);

                    // Exponential backoff
                    let delay = Duration::from_millis(100 * 2u64.pow(attempt));
                    std::thread::sleep(delay);
                }
            }
        }

        Err(last_error.unwrap_or(PerplexityError::Unknown("Max retries exceeded".into())))
    }

    fn simulate_api_call(&self, request: &ChatRequest) -> Result<ChatResponse, PerplexityError> {
        // Simulate API response for demonstration
        let prompt_tokens = request
            .messages
            .iter()
            .map(|m| m.content.len() / 4)
            .sum::<usize>() as u32;

        // Generate simulated citations
        let citations = if request.return_citations {
            vec![
                Citation {
                    index: 1,
                    url: "https://docs.rs/example".to_string(),
                    title: "Example Documentation".to_string(),
                    snippet: Some("Relevant documentation about the topic...".to_string()),
                    published_date: Some("2024-01-15".to_string()),
                    author: None,
                },
                Citation {
                    index: 2,
                    url: "https://github.com/rust-lang/rust".to_string(),
                    title: "Rust Programming Language".to_string(),
                    snippet: Some("The Rust programming language repository...".to_string()),
                    published_date: None,
                    author: Some("Rust Team".to_string()),
                },
            ]
        } else {
            vec![]
        };

        Ok(ChatResponse {
            id: format!("pplx-{}", generate_id()),
            model: request.model.as_str().to_string(),
            content: "This is a simulated response from Perplexity AI with search-augmented generation. [1][2]".to_string(),
            citations,
            images: vec![],
            usage: Usage {
                prompt_tokens,
                completion_tokens: 30,
                total_tokens: prompt_tokens + 30,
            },
            finish_reason: "stop".to_string(),
        })
    }

    /// Get client statistics
    pub fn stats(&self) -> ClientStats {
        ClientStats {
            total_requests: self.request_count.load(Ordering::Relaxed),
            total_tokens: self.total_tokens.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug)]
pub struct ClientStats {
    pub total_requests: u64,
    pub total_tokens: u64,
}

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug)]
pub enum PerplexityError {
    AuthError(String),
    RateLimited { retry_after: Option<Duration> },
    InvalidRequest(String),
    ServerError(String),
    NetworkError(String),
    Unknown(String),
}

impl PerplexityError {
    fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::RateLimited { .. } | Self::ServerError(_) | Self::NetworkError(_)
        )
    }
}

impl std::fmt::Display for PerplexityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthError(msg) => write!(f, "Authentication error: {}", msg),
            Self::RateLimited { retry_after } => {
                write!(f, "Rate limited")?;
                if let Some(dur) = retry_after {
                    write!(f, ", retry after {:?}", dur)?;
                }
                Ok(())
            }
            Self::InvalidRequest(msg) => write!(f, "Invalid request: {}", msg),
            Self::ServerError(msg) => write!(f, "Server error: {}", msg),
            Self::NetworkError(msg) => write!(f, "Network error: {}", msg),
            Self::Unknown(msg) => write!(f, "Unknown error: {}", msg),
        }
    }
}

// ============================================================================
// Utilities
// ============================================================================

fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

fn generate_id() -> String {
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:016x}", seed)
}

// ============================================================================
// Main and Tests
// ============================================================================

fn main() {
    println!("Perplexity AI Client Example\n");

    // Create client
    let config = PerplexityConfig::new("your-api-key").with_timeout(Duration::from_secs(30));
    let client = PerplexityClient::new(config);

    // Simple query with search
    println!("--- Simple Search Query ---");
    let request = ChatRequest::new(
        PerplexityModel::SonarMedium,
        vec![Message::user(
            "What are the latest developments in Rust memory safety?",
        )],
    )
    .with_max_tokens(500)
    .with_citations(true)
    .with_recency(SearchRecency::Month);

    match client.chat(request) {
        Ok(response) => {
            println!("Response: {}\n", response.content);

            println!("Citations:");
            for citation in &response.citations {
                let quality = CitationVerifier::quality_score(citation);
                let trusted = if CitationVerifier::is_trusted_source(citation) {
                    " [trusted]"
                } else {
                    ""
                };
                println!(
                    "  [{}] {} - {}{} (quality: {}%)",
                    citation.index, citation.title, citation.url, trusted, quality
                );
            }

            println!("\nUsage: {} tokens", response.usage.total_tokens);
        }
        Err(e) => println!("Error: {}", e),
    }

    // Academic search
    println!("\n--- Academic Search ---");
    let academic_request = ChatRequest::new(
        PerplexityModel::SonarLarge,
        vec![
            Message::system("You are a research assistant. Cite academic sources."),
            Message::user("Explain formal verification in Rust"),
        ],
    )
    .with_search_domain(SearchDomain::Academic)
    .with_citations(true);

    match client.chat(academic_request) {
        Ok(response) => {
            println!("Academic response: {}", response.content);
        }
        Err(e) => println!("Error: {}", e),
    }

    // Code-focused query
    println!("\n--- Code Query ---");
    let code_request = ChatRequest::new(
        PerplexityModel::Codellama,
        vec![Message::user(
            "Write a Rust function to safely parse JSON with error handling",
        )],
    )
    .with_max_tokens(1000)
    .with_temperature(0.2);

    match client.chat(code_request) {
        Ok(response) => {
            println!("Code response: {}", response.content);
        }
        Err(e) => println!("Error: {}", e),
    }

    // Client statistics
    println!("\n--- Client Statistics ---");
    let stats = client.stats();
    println!("Total requests: {}", stats.total_requests);
    println!("Total tokens: {}", stats.total_tokens);

    // Citation verification demo
    println!("\n--- Citation Verification ---");
    let test_citations = vec![
        Citation {
            index: 1,
            url: "https://doc.rust-lang.org/book/".to_string(),
            title: "The Rust Programming Language".to_string(),
            snippet: Some("The official Rust book".to_string()),
            published_date: Some("2024-01-01".to_string()),
            author: Some("Steve Klabnik".to_string()),
        },
        Citation {
            index: 2,
            url: "https://random-blog.example.com/post".to_string(),
            title: "Some Blog Post".to_string(),
            snippet: None,
            published_date: None,
            author: None,
        },
    ];

    for citation in &test_citations {
        println!(
            "Citation [{}]: {} - Quality: {}%, Trusted: {}",
            citation.index,
            citation.title,
            CitationVerifier::quality_score(citation),
            CitationVerifier::is_trusted_source(citation)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_properties() {
        assert!(PerplexityModel::SonarMedium.supports_search());
        assert!(!PerplexityModel::Codellama.supports_search());
        assert_eq!(PerplexityModel::SonarLarge.context_window(), 16384);
    }

    #[test]
    fn test_message_creation() {
        let msg = Message::user("Hello");
        assert_eq!(msg.role, Role::User);
        assert_eq!(msg.content, "Hello");
    }

    #[test]
    fn test_request_builder() {
        let request = ChatRequest::new(PerplexityModel::SonarMedium, vec![Message::user("Test")])
            .with_max_tokens(100)
            .with_temperature(0.5)
            .with_citations(true);

        assert_eq!(request.max_tokens, Some(100));
        assert_eq!(request.temperature, Some(0.5));
        assert!(request.return_citations);
    }

    #[test]
    fn test_temperature_clamping() {
        let request = ChatRequest::new(PerplexityModel::SonarMedium, vec![]).with_temperature(5.0);

        assert_eq!(request.temperature, Some(2.0));
    }

    #[test]
    fn test_client_creation() {
        let config = PerplexityConfig::new("test-key");
        let client = PerplexityClient::new(config);

        let stats = client.stats();
        assert_eq!(stats.total_requests, 0);
    }

    #[test]
    fn test_chat_request() {
        let config = PerplexityConfig::new("test-key");
        let client = PerplexityClient::new(config);

        let request = ChatRequest::new(PerplexityModel::SonarMedium, vec![Message::user("Hello")]);

        let response = client.chat(request);
        assert!(response.is_ok());
    }

    #[test]
    fn test_citation_verifier_trusted() {
        let trusted = Citation {
            index: 1,
            url: "https://docs.rs/serde".to_string(),
            title: "Serde".to_string(),
            snippet: None,
            published_date: None,
            author: None,
        };
        assert!(CitationVerifier::is_trusted_source(&trusted));

        let untrusted = Citation {
            index: 2,
            url: "https://random-site.com".to_string(),
            title: "Random".to_string(),
            snippet: None,
            published_date: None,
            author: None,
        };
        assert!(!CitationVerifier::is_trusted_source(&untrusted));
    }

    #[test]
    fn test_citation_quality_score() {
        let complete = Citation {
            index: 1,
            url: "https://rust-lang.org".to_string(),
            title: "Rust".to_string(),
            snippet: Some("Content".to_string()),
            published_date: Some("2024-01-01".to_string()),
            author: None,
        };
        assert_eq!(CitationVerifier::quality_score(&complete), 100);

        let minimal = Citation {
            index: 2,
            url: "https://example.com".to_string(),
            title: "".to_string(),
            snippet: None,
            published_date: None,
            author: None,
        };
        assert_eq!(CitationVerifier::quality_score(&minimal), 20);
    }

    #[test]
    fn test_extract_domain() {
        assert_eq!(
            CitationVerifier::extract_domain("https://docs.rs/crate/version"),
            Some("docs.rs".to_string())
        );
        assert_eq!(
            CitationVerifier::extract_domain("http://example.com/path"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_cache() {
        let cache = ResponseCache::new(Duration::from_secs(60), 10);

        let request = ChatRequest::new(PerplexityModel::SonarMedium, vec![Message::user("Test")]);

        let response = ChatResponse {
            id: "test".to_string(),
            model: "sonar-medium-chat".to_string(),
            content: "Cached response".to_string(),
            citations: vec![],
            images: vec![],
            usage: Usage {
                prompt_tokens: 10,
                completion_tokens: 5,
                total_tokens: 15,
            },
            finish_reason: "stop".to_string(),
        };

        cache.put(&request, response.clone());
        let cached = cache.get(&request);
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().id, "test");
    }

    #[test]
    fn test_error_retryable() {
        assert!(PerplexityError::RateLimited { retry_after: None }.is_retryable());
        assert!(PerplexityError::ServerError("500".into()).is_retryable());
        assert!(!PerplexityError::AuthError("Invalid".into()).is_retryable());
        assert!(!PerplexityError::InvalidRequest("Bad".into()).is_retryable());
    }
}
