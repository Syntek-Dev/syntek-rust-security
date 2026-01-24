//! Token Bucket Rate Limiter
//!
//! Implements token bucket algorithm for API rate limiting.

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use std::collections::HashMap;

/// Token bucket rate limiter
pub struct TokenBucket {
    capacity: u64,
    tokens: f64,
    refill_rate: f64, // tokens per second
    last_refill: Instant,
}

impl TokenBucket {
    pub fn new(capacity: u64, refill_rate: f64) -> Self {
        Self {
            capacity,
            tokens: capacity as f64,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    /// Try to acquire tokens, returns true if successful
    pub fn try_acquire(&mut self, tokens: u64) -> bool {
        self.refill();

        if self.tokens >= tokens as f64 {
            self.tokens -= tokens as f64;
            true
        } else {
            false
        }
    }

    /// Get current token count
    pub fn available(&mut self) -> u64 {
        self.refill();
        self.tokens as u64
    }

    /// Time until requested tokens are available
    pub fn time_until_available(&mut self, tokens: u64) -> Duration {
        self.refill();

        if self.tokens >= tokens as f64 {
            return Duration::ZERO;
        }

        let needed = tokens as f64 - self.tokens;
        let seconds = needed / self.refill_rate;
        Duration::from_secs_f64(seconds)
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        let new_tokens = elapsed * self.refill_rate;

        self.tokens = (self.tokens + new_tokens).min(self.capacity as f64);
        self.last_refill = now;
    }
}

/// Per-key rate limiter
pub struct RateLimiter {
    buckets: Arc<Mutex<HashMap<String, TokenBucket>>>,
    default_capacity: u64,
    default_refill_rate: f64,
}

impl RateLimiter {
    pub fn new(capacity: u64, refill_rate: f64) -> Self {
        Self {
            buckets: Arc::new(Mutex::new(HashMap::new())),
            default_capacity: capacity,
            default_refill_rate: refill_rate,
        }
    }

    /// Check if request is allowed for a key
    pub async fn check(&self, key: &str, tokens: u64) -> RateLimitResult {
        let mut buckets = self.buckets.lock().await;

        let bucket = buckets.entry(key.to_string())
            .or_insert_with(|| TokenBucket::new(
                self.default_capacity,
                self.default_refill_rate,
            ));

        if bucket.try_acquire(tokens) {
            RateLimitResult::Allowed {
                remaining: bucket.available(),
            }
        } else {
            RateLimitResult::Limited {
                retry_after: bucket.time_until_available(tokens),
            }
        }
    }

    /// Get current limit info for a key
    pub async fn get_info(&self, key: &str) -> RateLimitInfo {
        let mut buckets = self.buckets.lock().await;

        let bucket = buckets.entry(key.to_string())
            .or_insert_with(|| TokenBucket::new(
                self.default_capacity,
                self.default_refill_rate,
            ));

        RateLimitInfo {
            limit: self.default_capacity,
            remaining: bucket.available(),
            reset_in: bucket.time_until_available(1),
        }
    }

    /// Clean up expired buckets
    pub async fn cleanup(&self, max_age: Duration) {
        let mut buckets = self.buckets.lock().await;
        let now = Instant::now();

        buckets.retain(|_, bucket| {
            now.duration_since(bucket.last_refill) < max_age
        });
    }
}

#[derive(Debug)]
pub enum RateLimitResult {
    Allowed { remaining: u64 },
    Limited { retry_after: Duration },
}

#[derive(Debug)]
pub struct RateLimitInfo {
    pub limit: u64,
    pub remaining: u64,
    pub reset_in: Duration,
}

/// Sliding window rate limiter (more accurate)
pub struct SlidingWindowLimiter {
    windows: Arc<Mutex<HashMap<String, SlidingWindow>>>,
    window_size: Duration,
    max_requests: u64,
}

struct SlidingWindow {
    current_count: u64,
    previous_count: u64,
    window_start: Instant,
}

impl SlidingWindowLimiter {
    pub fn new(window_size: Duration, max_requests: u64) -> Self {
        Self {
            windows: Arc::new(Mutex::new(HashMap::new())),
            window_size,
            max_requests,
        }
    }

    pub async fn check(&self, key: &str) -> RateLimitResult {
        let mut windows = self.windows.lock().await;
        let now = Instant::now();

        let window = windows.entry(key.to_string())
            .or_insert_with(|| SlidingWindow {
                current_count: 0,
                previous_count: 0,
                window_start: now,
            });

        let elapsed = now.duration_since(window.window_start);

        // Check if we need to advance the window
        if elapsed >= self.window_size {
            let windows_passed = (elapsed.as_secs_f64() / self.window_size.as_secs_f64()) as u64;

            if windows_passed >= 2 {
                window.previous_count = 0;
                window.current_count = 0;
            } else {
                window.previous_count = window.current_count;
                window.current_count = 0;
            }
            window.window_start = now;
        }

        // Calculate weighted count
        let weight = 1.0 - (elapsed.as_secs_f64() / self.window_size.as_secs_f64()).min(1.0);
        let weighted_count = (window.previous_count as f64 * weight) + window.current_count as f64;

        if weighted_count < self.max_requests as f64 {
            window.current_count += 1;
            RateLimitResult::Allowed {
                remaining: (self.max_requests as f64 - weighted_count - 1.0).max(0.0) as u64,
            }
        } else {
            let time_to_next = self.window_size.as_secs_f64() *
                (1.0 - (weighted_count - self.max_requests as f64) / self.max_requests as f64);
            RateLimitResult::Limited {
                retry_after: Duration::from_secs_f64(time_to_next.max(0.1)),
            }
        }
    }
}

/// Rate limiter middleware for HTTP frameworks
pub struct RateLimitMiddleware {
    limiter: RateLimiter,
    key_extractor: Box<dyn Fn(&str) -> String + Send + Sync>,
}

impl RateLimitMiddleware {
    pub fn new(limiter: RateLimiter) -> Self {
        Self {
            limiter,
            key_extractor: Box::new(|req| req.to_string()),
        }
    }

    pub fn with_key_extractor<F>(mut self, f: F) -> Self
    where
        F: Fn(&str) -> String + Send + Sync + 'static,
    {
        self.key_extractor = Box::new(f);
        self
    }

    pub async fn check(&self, request_key: &str, tokens: u64) -> RateLimitResult {
        let key = (self.key_extractor)(request_key);
        self.limiter.check(&key, tokens).await
    }
}

#[tokio::main]
async fn main() {
    println!("=== Token Bucket Rate Limiter ===\n");

    // Basic token bucket
    let mut bucket = TokenBucket::new(10, 1.0); // 10 capacity, 1 token/sec

    println!("Initial tokens: {}", bucket.available());

    for i in 1..=12 {
        if bucket.try_acquire(1) {
            println!("Request {}: ALLOWED (remaining: {})", i, bucket.available());
        } else {
            println!("Request {}: DENIED (retry in {:?})", i, bucket.time_until_available(1));
        }
    }

    // Per-key rate limiter
    println!("\n=== Per-Key Rate Limiter ===\n");

    let limiter = RateLimiter::new(5, 1.0); // 5 requests, 1/sec refill

    for user in ["user1", "user2", "user1", "user1", "user1", "user1", "user2"] {
        match limiter.check(user, 1).await {
            RateLimitResult::Allowed { remaining } => {
                println!("{}: ALLOWED (remaining: {})", user, remaining);
            }
            RateLimitResult::Limited { retry_after } => {
                println!("{}: LIMITED (retry in {:?})", user, retry_after);
            }
        }
    }

    // Sliding window
    println!("\n=== Sliding Window Limiter ===\n");

    let sliding = SlidingWindowLimiter::new(Duration::from_secs(10), 5);

    for i in 1..=7 {
        match sliding.check("api_key").await {
            RateLimitResult::Allowed { remaining } => {
                println!("Request {}: ALLOWED (remaining: {})", i, remaining);
            }
            RateLimitResult::Limited { retry_after } => {
                println!("Request {}: LIMITED (retry in {:?})", i, retry_after);
            }
        }
    }

    // Get rate limit info
    println!("\n=== Rate Limit Info ===");
    let info = limiter.get_info("user1").await;
    println!("Limit: {}", info.limit);
    println!("Remaining: {}", info.remaining);
    println!("Resets in: {:?}", info.reset_in);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_bucket_basic() {
        let mut bucket = TokenBucket::new(5, 1.0);

        assert_eq!(bucket.available(), 5);
        assert!(bucket.try_acquire(3));
        assert_eq!(bucket.available(), 2);
        assert!(bucket.try_acquire(2));
        assert!(!bucket.try_acquire(1)); // Empty
    }

    #[tokio::test]
    async fn test_rate_limiter_per_key() {
        let limiter = RateLimiter::new(2, 10.0);

        // First two requests should be allowed
        assert!(matches!(
            limiter.check("key1", 1).await,
            RateLimitResult::Allowed { .. }
        ));
        assert!(matches!(
            limiter.check("key1", 1).await,
            RateLimitResult::Allowed { .. }
        ));

        // Third should be limited
        assert!(matches!(
            limiter.check("key1", 1).await,
            RateLimitResult::Limited { .. }
        ));

        // Different key should be allowed
        assert!(matches!(
            limiter.check("key2", 1).await,
            RateLimitResult::Allowed { .. }
        ));
    }

    #[test]
    fn test_time_until_available() {
        let mut bucket = TokenBucket::new(5, 1.0);
        bucket.try_acquire(5); // Empty the bucket

        let time = bucket.time_until_available(3);
        assert!(time.as_secs_f64() > 2.5 && time.as_secs_f64() < 3.5);
    }
}
