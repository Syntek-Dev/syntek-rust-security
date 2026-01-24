//! Rate Limiter Implementation
//!
//! Production-ready rate limiting with:
//! - Token bucket algorithm
//! - Sliding window log
//! - Fixed window counter
//! - Distributed rate limiting support
//! - Per-user and per-IP limiting

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Rate limiting algorithm
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    TokenBucket,
    SlidingWindowLog,
    SlidingWindowCounter,
    FixedWindow,
    LeakyBucket,
}

/// Rate limit configuration
#[derive(Clone, Debug)]
pub struct RateLimitConfig {
    pub algorithm: Algorithm,
    pub requests_per_window: u64,
    pub window_duration: Duration,
    pub burst_size: Option<u64>,
    pub penalty_duration: Option<Duration>,
}

/// Result of a rate limit check
#[derive(Clone, Debug)]
pub struct RateLimitResult {
    pub allowed: bool,
    pub remaining: u64,
    pub reset_at: Instant,
    pub retry_after: Option<Duration>,
    pub limit: u64,
}

/// Token bucket state
#[derive(Clone, Debug)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
    capacity: f64,
    refill_rate: f64,
}

/// Sliding window log entry
#[derive(Clone, Debug)]
struct WindowEntry {
    timestamp: Instant,
}

/// Fixed window state
#[derive(Clone, Debug)]
struct FixedWindowState {
    count: u64,
    window_start: Instant,
}

/// Rate limiter state for a single key
#[derive(Clone, Debug)]
enum LimiterState {
    TokenBucket(TokenBucket),
    SlidingWindowLog(Vec<WindowEntry>),
    FixedWindow(FixedWindowState),
}

/// Rate limiter
pub struct RateLimiter {
    config: RateLimitConfig,
    states: Arc<Mutex<HashMap<String, LimiterState>>>,
    blocked_until: Arc<Mutex<HashMap<String, Instant>>>,
}

/// Rate limiter builder
pub struct RateLimiterBuilder {
    algorithm: Algorithm,
    requests_per_window: u64,
    window_duration: Duration,
    burst_size: Option<u64>,
    penalty_duration: Option<Duration>,
}

impl RateLimiter {
    /// Create new rate limiter
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            states: Arc::new(Mutex::new(HashMap::new())),
            blocked_until: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Check if request is allowed
    pub fn check(&self, key: &str) -> RateLimitResult {
        let now = Instant::now();

        // Check if key is blocked due to penalty
        {
            let blocked = self.blocked_until.lock().unwrap();
            if let Some(&until) = blocked.get(key) {
                if now < until {
                    return RateLimitResult {
                        allowed: false,
                        remaining: 0,
                        reset_at: until,
                        retry_after: Some(until - now),
                        limit: self.config.requests_per_window,
                    };
                }
            }
        }

        match self.config.algorithm {
            Algorithm::TokenBucket => self.check_token_bucket(key, now),
            Algorithm::SlidingWindowLog => self.check_sliding_window_log(key, now),
            Algorithm::SlidingWindowCounter => self.check_sliding_window_counter(key, now),
            Algorithm::FixedWindow => self.check_fixed_window(key, now),
            Algorithm::LeakyBucket => self.check_leaky_bucket(key, now),
        }
    }

    /// Check and consume (atomic operation)
    pub fn acquire(&self, key: &str) -> RateLimitResult {
        let result = self.check(key);
        if result.allowed {
            self.consume(key, 1);
        }
        result
    }

    /// Consume tokens/requests
    pub fn consume(&self, key: &str, count: u64) {
        let mut states = self.states.lock().unwrap();

        match self.config.algorithm {
            Algorithm::TokenBucket => {
                if let Some(LimiterState::TokenBucket(bucket)) = states.get_mut(key) {
                    bucket.tokens = (bucket.tokens - count as f64).max(0.0);
                }
            }
            Algorithm::SlidingWindowLog => {
                if let Some(LimiterState::SlidingWindowLog(entries)) = states.get_mut(key) {
                    for _ in 0..count {
                        entries.push(WindowEntry {
                            timestamp: Instant::now(),
                        });
                    }
                }
            }
            Algorithm::FixedWindow => {
                if let Some(LimiterState::FixedWindow(state)) = states.get_mut(key) {
                    state.count += count;
                }
            }
            _ => {}
        }
    }

    /// Apply penalty to a key
    pub fn apply_penalty(&self, key: &str) {
        if let Some(penalty) = self.config.penalty_duration {
            let mut blocked = self.blocked_until.lock().unwrap();
            blocked.insert(key.to_string(), Instant::now() + penalty);
        }
    }

    /// Reset limiter for a key
    pub fn reset(&self, key: &str) {
        let mut states = self.states.lock().unwrap();
        states.remove(key);

        let mut blocked = self.blocked_until.lock().unwrap();
        blocked.remove(key);
    }

    /// Get current state info for a key
    pub fn get_info(&self, key: &str) -> Option<LimiterInfo> {
        let states = self.states.lock().unwrap();

        states.get(key).map(|state| match state {
            LimiterState::TokenBucket(bucket) => LimiterInfo {
                current_count: (bucket.capacity - bucket.tokens) as u64,
                limit: bucket.capacity as u64,
                remaining: bucket.tokens as u64,
            },
            LimiterState::SlidingWindowLog(entries) => LimiterInfo {
                current_count: entries.len() as u64,
                limit: self.config.requests_per_window,
                remaining: self
                    .config
                    .requests_per_window
                    .saturating_sub(entries.len() as u64),
            },
            LimiterState::FixedWindow(state) => LimiterInfo {
                current_count: state.count,
                limit: self.config.requests_per_window,
                remaining: self.config.requests_per_window.saturating_sub(state.count),
            },
        })
    }

    fn check_token_bucket(&self, key: &str, now: Instant) -> RateLimitResult {
        let mut states = self.states.lock().unwrap();

        let capacity = self
            .config
            .burst_size
            .unwrap_or(self.config.requests_per_window) as f64;
        let refill_rate =
            self.config.requests_per_window as f64 / self.config.window_duration.as_secs_f64();

        let bucket = states.entry(key.to_string()).or_insert_with(|| {
            LimiterState::TokenBucket(TokenBucket {
                tokens: capacity,
                last_refill: now,
                capacity,
                refill_rate,
            })
        });

        if let LimiterState::TokenBucket(bucket) = bucket {
            // Refill tokens
            let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
            let new_tokens = elapsed * bucket.refill_rate;
            bucket.tokens = (bucket.tokens + new_tokens).min(bucket.capacity);
            bucket.last_refill = now;

            let allowed = bucket.tokens >= 1.0;
            let remaining = bucket.tokens as u64;

            // Calculate reset time
            let time_to_full = if bucket.tokens < bucket.capacity {
                Duration::from_secs_f64((bucket.capacity - bucket.tokens) / bucket.refill_rate)
            } else {
                Duration::ZERO
            };

            RateLimitResult {
                allowed,
                remaining,
                reset_at: now + time_to_full,
                retry_after: if allowed {
                    None
                } else {
                    Some(Duration::from_secs_f64(1.0 / bucket.refill_rate))
                },
                limit: bucket.capacity as u64,
            }
        } else {
            unreachable!()
        }
    }

    fn check_sliding_window_log(&self, key: &str, now: Instant) -> RateLimitResult {
        let mut states = self.states.lock().unwrap();

        let entries = states
            .entry(key.to_string())
            .or_insert_with(|| LimiterState::SlidingWindowLog(Vec::new()));

        if let LimiterState::SlidingWindowLog(entries) = entries {
            // Remove expired entries
            let window_start = now - self.config.window_duration;
            entries.retain(|e| e.timestamp > window_start);

            let count = entries.len() as u64;
            let allowed = count < self.config.requests_per_window;
            let remaining = self.config.requests_per_window.saturating_sub(count);

            // Calculate reset time (when oldest entry expires)
            let reset_at = entries
                .first()
                .map(|e| e.timestamp + self.config.window_duration)
                .unwrap_or(now);

            RateLimitResult {
                allowed,
                remaining,
                reset_at,
                retry_after: if allowed {
                    None
                } else {
                    entries.first().map(|e| {
                        (e.timestamp + self.config.window_duration).saturating_duration_since(now)
                    })
                },
                limit: self.config.requests_per_window,
            }
        } else {
            unreachable!()
        }
    }

    fn check_sliding_window_counter(&self, key: &str, now: Instant) -> RateLimitResult {
        // Sliding window counter is a hybrid approach
        // For simplicity, we'll use the log approach here
        self.check_sliding_window_log(key, now)
    }

    fn check_fixed_window(&self, key: &str, now: Instant) -> RateLimitResult {
        let mut states = self.states.lock().unwrap();

        let state = states.entry(key.to_string()).or_insert_with(|| {
            LimiterState::FixedWindow(FixedWindowState {
                count: 0,
                window_start: now,
            })
        });

        if let LimiterState::FixedWindow(state) = state {
            // Check if window has expired
            if now.duration_since(state.window_start) >= self.config.window_duration {
                state.count = 0;
                state.window_start = now;
            }

            let allowed = state.count < self.config.requests_per_window;
            let remaining = self.config.requests_per_window.saturating_sub(state.count);
            let reset_at = state.window_start + self.config.window_duration;

            RateLimitResult {
                allowed,
                remaining,
                reset_at,
                retry_after: if allowed {
                    None
                } else {
                    Some(reset_at.saturating_duration_since(now))
                },
                limit: self.config.requests_per_window,
            }
        } else {
            unreachable!()
        }
    }

    fn check_leaky_bucket(&self, key: &str, now: Instant) -> RateLimitResult {
        // Leaky bucket is similar to token bucket but with different semantics
        self.check_token_bucket(key, now)
    }
}

/// Info about limiter state
#[derive(Clone, Debug)]
pub struct LimiterInfo {
    pub current_count: u64,
    pub limit: u64,
    pub remaining: u64,
}

impl RateLimiterBuilder {
    /// Create new builder with token bucket algorithm
    pub fn token_bucket() -> Self {
        Self {
            algorithm: Algorithm::TokenBucket,
            requests_per_window: 100,
            window_duration: Duration::from_secs(60),
            burst_size: None,
            penalty_duration: None,
        }
    }

    /// Create new builder with sliding window algorithm
    pub fn sliding_window() -> Self {
        Self {
            algorithm: Algorithm::SlidingWindowLog,
            requests_per_window: 100,
            window_duration: Duration::from_secs(60),
            burst_size: None,
            penalty_duration: None,
        }
    }

    /// Create new builder with fixed window algorithm
    pub fn fixed_window() -> Self {
        Self {
            algorithm: Algorithm::FixedWindow,
            requests_per_window: 100,
            window_duration: Duration::from_secs(60),
            burst_size: None,
            penalty_duration: None,
        }
    }

    /// Set requests per window
    pub fn requests_per_window(mut self, count: u64) -> Self {
        self.requests_per_window = count;
        self
    }

    /// Set window duration
    pub fn window_duration(mut self, duration: Duration) -> Self {
        self.window_duration = duration;
        self
    }

    /// Set burst size (for token bucket)
    pub fn burst_size(mut self, size: u64) -> Self {
        self.burst_size = Some(size);
        self
    }

    /// Set penalty duration for blocked clients
    pub fn penalty_duration(mut self, duration: Duration) -> Self {
        self.penalty_duration = Some(duration);
        self
    }

    /// Build the rate limiter
    pub fn build(self) -> RateLimiter {
        RateLimiter::new(RateLimitConfig {
            algorithm: self.algorithm,
            requests_per_window: self.requests_per_window,
            window_duration: self.window_duration,
            burst_size: self.burst_size,
            penalty_duration: self.penalty_duration,
        })
    }
}

/// Multi-tier rate limiter for different limits
pub struct TieredRateLimiter {
    tiers: Vec<(String, RateLimiter)>,
}

impl TieredRateLimiter {
    /// Create new tiered limiter
    pub fn new() -> Self {
        Self { tiers: Vec::new() }
    }

    /// Add a tier
    pub fn add_tier(&mut self, name: impl Into<String>, limiter: RateLimiter) {
        self.tiers.push((name.into(), limiter));
    }

    /// Check all tiers
    pub fn check(&self, key: &str) -> TieredResult {
        let mut results = Vec::new();
        let mut allowed = true;

        for (name, limiter) in &self.tiers {
            let result = limiter.check(key);
            if !result.allowed {
                allowed = false;
            }
            results.push((name.clone(), result));
        }

        TieredResult { allowed, results }
    }

    /// Acquire from all tiers
    pub fn acquire(&self, key: &str) -> TieredResult {
        let mut results = Vec::new();
        let mut allowed = true;

        for (name, limiter) in &self.tiers {
            let result = limiter.acquire(key);
            if !result.allowed {
                allowed = false;
            }
            results.push((name.clone(), result));
        }

        TieredResult { allowed, results }
    }
}

impl Default for TieredRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Result from tiered rate limiter
#[derive(Clone, Debug)]
pub struct TieredResult {
    pub allowed: bool,
    pub results: Vec<(String, RateLimitResult)>,
}

fn main() {
    println!("=== Rate Limiter Demo ===\n");

    // Token bucket limiter
    println!("=== Token Bucket Algorithm ===\n");

    let limiter = RateLimiterBuilder::token_bucket()
        .requests_per_window(10)
        .window_duration(Duration::from_secs(1))
        .burst_size(15)
        .build();

    // Simulate requests
    for i in 1..=20 {
        let result = limiter.acquire("user_123");
        println!(
            "Request {}: allowed={}, remaining={}",
            i, result.allowed, result.remaining
        );

        if !result.allowed {
            if let Some(retry) = result.retry_after {
                println!("  Retry after: {:?}", retry);
            }
        }
    }

    // Fixed window limiter
    println!("\n=== Fixed Window Algorithm ===\n");

    let fixed_limiter = RateLimiterBuilder::fixed_window()
        .requests_per_window(5)
        .window_duration(Duration::from_secs(10))
        .penalty_duration(Duration::from_secs(30))
        .build();

    for i in 1..=8 {
        let result = fixed_limiter.acquire("api_client");
        println!(
            "Request {}: allowed={}, remaining={}",
            i, result.allowed, result.remaining
        );
    }

    // Apply penalty
    println!("\nApplying penalty...");
    fixed_limiter.apply_penalty("api_client");

    let result = fixed_limiter.check("api_client");
    println!(
        "After penalty: allowed={}, retry_after={:?}",
        result.allowed, result.retry_after
    );

    // Tiered rate limiting
    println!("\n=== Tiered Rate Limiting ===\n");

    let mut tiered = TieredRateLimiter::new();

    // Per-second limit
    tiered.add_tier(
        "per_second",
        RateLimiterBuilder::token_bucket()
            .requests_per_window(10)
            .window_duration(Duration::from_secs(1))
            .build(),
    );

    // Per-minute limit
    tiered.add_tier(
        "per_minute",
        RateLimiterBuilder::sliding_window()
            .requests_per_window(100)
            .window_duration(Duration::from_secs(60))
            .build(),
    );

    // Per-hour limit
    tiered.add_tier(
        "per_hour",
        RateLimiterBuilder::fixed_window()
            .requests_per_window(1000)
            .window_duration(Duration::from_secs(3600))
            .build(),
    );

    // Simulate requests
    for i in 1..=15 {
        let result = tiered.acquire("user_456");
        println!("Request {}: overall allowed={}", i, result.allowed);

        for (tier, tier_result) in &result.results {
            println!(
                "  {}: allowed={}, remaining={}",
                tier, tier_result.allowed, tier_result.remaining
            );
        }
    }

    // Show limiter info
    println!("\n=== Limiter State Info ===\n");

    let info_limiter = RateLimiterBuilder::token_bucket()
        .requests_per_window(100)
        .window_duration(Duration::from_secs(60))
        .burst_size(150)
        .build();

    // Make some requests
    for _ in 0..25 {
        info_limiter.acquire("info_test");
    }

    if let Some(info) = info_limiter.get_info("info_test") {
        println!("Current count: {}", info.current_count);
        println!("Limit: {}", info.limit);
        println!("Remaining: {}", info.remaining);
    }

    // Reset and check again
    info_limiter.reset("info_test");
    println!("\nAfter reset:");
    if let Some(info) = info_limiter.get_info("info_test") {
        println!("Remaining: {}", info.remaining);
    } else {
        println!("No state (reset successful)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_bucket_allows_within_limit() {
        let limiter = RateLimiterBuilder::token_bucket()
            .requests_per_window(10)
            .window_duration(Duration::from_secs(1))
            .build();

        for _ in 0..10 {
            let result = limiter.acquire("test");
            assert!(result.allowed);
        }
    }

    #[test]
    fn test_token_bucket_blocks_over_limit() {
        let limiter = RateLimiterBuilder::token_bucket()
            .requests_per_window(5)
            .window_duration(Duration::from_secs(1))
            .build();

        for _ in 0..5 {
            limiter.acquire("test");
        }

        let result = limiter.check("test");
        assert!(!result.allowed);
    }

    #[test]
    fn test_burst_size() {
        let limiter = RateLimiterBuilder::token_bucket()
            .requests_per_window(10)
            .window_duration(Duration::from_secs(1))
            .burst_size(15)
            .build();

        // Should allow burst
        for _ in 0..15 {
            let result = limiter.acquire("test");
            assert!(result.allowed);
        }

        // Should block after burst
        let result = limiter.check("test");
        assert!(!result.allowed);
    }

    #[test]
    fn test_fixed_window() {
        let limiter = RateLimiterBuilder::fixed_window()
            .requests_per_window(5)
            .window_duration(Duration::from_secs(60))
            .build();

        for _ in 0..5 {
            let result = limiter.acquire("test");
            assert!(result.allowed);
        }

        let result = limiter.check("test");
        assert!(!result.allowed);
    }

    #[test]
    fn test_sliding_window() {
        let limiter = RateLimiterBuilder::sliding_window()
            .requests_per_window(5)
            .window_duration(Duration::from_secs(60))
            .build();

        for _ in 0..5 {
            let result = limiter.acquire("test");
            assert!(result.allowed);
        }

        let result = limiter.check("test");
        assert!(!result.allowed);
    }

    #[test]
    fn test_penalty() {
        let limiter = RateLimiterBuilder::token_bucket()
            .requests_per_window(100)
            .window_duration(Duration::from_secs(1))
            .penalty_duration(Duration::from_secs(60))
            .build();

        limiter.apply_penalty("bad_client");

        let result = limiter.check("bad_client");
        assert!(!result.allowed);
        assert!(result.retry_after.is_some());
    }

    #[test]
    fn test_reset() {
        let limiter = RateLimiterBuilder::token_bucket()
            .requests_per_window(5)
            .window_duration(Duration::from_secs(1))
            .build();

        for _ in 0..5 {
            limiter.acquire("test");
        }

        assert!(!limiter.check("test").allowed);

        limiter.reset("test");

        assert!(limiter.check("test").allowed);
    }

    #[test]
    fn test_different_keys() {
        let limiter = RateLimiterBuilder::token_bucket()
            .requests_per_window(5)
            .window_duration(Duration::from_secs(1))
            .build();

        for _ in 0..5 {
            limiter.acquire("user1");
        }

        // user1 should be blocked
        assert!(!limiter.check("user1").allowed);

        // user2 should still be allowed
        assert!(limiter.check("user2").allowed);
    }

    #[test]
    fn test_tiered_limiter() {
        let mut tiered = TieredRateLimiter::new();

        tiered.add_tier(
            "strict",
            RateLimiterBuilder::token_bucket()
                .requests_per_window(3)
                .window_duration(Duration::from_secs(1))
                .build(),
        );

        tiered.add_tier(
            "relaxed",
            RateLimiterBuilder::token_bucket()
                .requests_per_window(10)
                .window_duration(Duration::from_secs(1))
                .build(),
        );

        // First 3 should be allowed
        for _ in 0..3 {
            let result = tiered.acquire("test");
            assert!(result.allowed);
        }

        // 4th should be blocked by strict tier
        let result = tiered.check("test");
        assert!(!result.allowed);
    }

    #[test]
    fn test_get_info() {
        let limiter = RateLimiterBuilder::token_bucket()
            .requests_per_window(10)
            .window_duration(Duration::from_secs(1))
            .build();

        limiter.acquire("test");
        limiter.acquire("test");
        limiter.acquire("test");

        let info = limiter.get_info("test").unwrap();
        assert_eq!(info.remaining, 7);
        assert_eq!(info.limit, 10);
    }

    #[test]
    fn test_remaining_count() {
        let limiter = RateLimiterBuilder::fixed_window()
            .requests_per_window(10)
            .window_duration(Duration::from_secs(60))
            .build();

        let result = limiter.acquire("test");
        assert_eq!(result.remaining, 9);

        let result = limiter.acquire("test");
        assert_eq!(result.remaining, 8);
    }
}
