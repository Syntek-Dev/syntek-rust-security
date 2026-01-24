//! Property-Based Testing Framework for Security Code
//!
//! This example demonstrates property-based testing patterns for security-critical
//! Rust code using QuickCheck-style approaches with custom generators for
//! cryptographic data, network packets, and security tokens.

use std::collections::HashMap;
use std::fmt;
use std::hash::Hash;
use std::sync::atomic::{AtomicU64, Ordering};

// ============================================================================
// Random Generator Infrastructure
// ============================================================================

/// Pseudo-random number generator (xorshift64)
#[derive(Clone)]
pub struct Rng {
    state: u64,
}

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0xDEADBEEF } else { seed },
        }
    }

    pub fn from_entropy() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        Self::new(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    pub fn next_usize(&mut self, max: usize) -> usize {
        if max == 0 {
            return 0;
        }
        (self.next_u64() as usize) % max
    }

    pub fn next_bool(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }

    pub fn next_f64(&mut self) -> f64 {
        (self.next_u64() as f64) / (u64::MAX as f64)
    }

    pub fn next_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(len);
        let mut remaining = len;
        while remaining >= 8 {
            bytes.extend_from_slice(&self.next_u64().to_le_bytes());
            remaining -= 8;
        }
        if remaining > 0 {
            let last = self.next_u64().to_le_bytes();
            bytes.extend_from_slice(&last[..remaining]);
        }
        bytes
    }

    pub fn shuffle<T>(&mut self, slice: &mut [T]) {
        for i in (1..slice.len()).rev() {
            let j = self.next_usize(i + 1);
            slice.swap(i, j);
        }
    }

    pub fn choose<'a, T>(&mut self, slice: &'a [T]) -> Option<&'a T> {
        if slice.is_empty() {
            None
        } else {
            Some(&slice[self.next_usize(slice.len())])
        }
    }
}

// ============================================================================
// Arbitrary Trait and Implementations
// ============================================================================

/// Trait for generating arbitrary values of a type
pub trait Arbitrary: Sized + Clone {
    fn arbitrary(rng: &mut Rng) -> Self;

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        Box::new(std::iter::empty())
    }
}

impl Arbitrary for bool {
    fn arbitrary(rng: &mut Rng) -> Self {
        rng.next_bool()
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        if *self {
            Box::new(std::iter::once(false))
        } else {
            Box::new(std::iter::empty())
        }
    }
}

impl Arbitrary for u8 {
    fn arbitrary(rng: &mut Rng) -> Self {
        rng.next_u64() as u8
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        let val = *self;
        Box::new((0..val).rev())
    }
}

impl Arbitrary for u16 {
    fn arbitrary(rng: &mut Rng) -> Self {
        rng.next_u64() as u16
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        let val = *self;
        Box::new((0..val).rev().take(16))
    }
}

impl Arbitrary for u32 {
    fn arbitrary(rng: &mut Rng) -> Self {
        rng.next_u32()
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        let val = *self;
        let mut shrinks = Vec::new();
        if val > 0 {
            shrinks.push(0);
            let mut x = val;
            while x > 0 {
                x /= 2;
                if x > 0 && x < val {
                    shrinks.push(x);
                }
            }
            if val > 1 {
                shrinks.push(val - 1);
            }
        }
        Box::new(shrinks.into_iter())
    }
}

impl Arbitrary for u64 {
    fn arbitrary(rng: &mut Rng) -> Self {
        rng.next_u64()
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        let val = *self;
        let mut shrinks = Vec::new();
        if val > 0 {
            shrinks.push(0);
            let mut x = val;
            while x > 0 {
                x /= 2;
                if x > 0 && x < val {
                    shrinks.push(x);
                }
            }
            if val > 1 {
                shrinks.push(val - 1);
            }
        }
        Box::new(shrinks.into_iter())
    }
}

impl Arbitrary for i32 {
    fn arbitrary(rng: &mut Rng) -> Self {
        rng.next_u32() as i32
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        let val = *self;
        let mut shrinks = Vec::new();
        if val != 0 {
            shrinks.push(0);
            if val > 0 {
                shrinks.push(val - 1);
            } else {
                shrinks.push(val + 1);
                shrinks.push(-val);
            }
        }
        Box::new(shrinks.into_iter())
    }
}

impl Arbitrary for i64 {
    fn arbitrary(rng: &mut Rng) -> Self {
        rng.next_u64() as i64
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        let val = *self;
        let mut shrinks = Vec::new();
        if val != 0 {
            shrinks.push(0);
            if val > 0 {
                shrinks.push(val - 1);
            } else {
                shrinks.push(val + 1);
                shrinks.push(-val);
            }
        }
        Box::new(shrinks.into_iter())
    }
}

impl Arbitrary for String {
    fn arbitrary(rng: &mut Rng) -> Self {
        let len = rng.next_usize(64);
        (0..len)
            .map(|_| {
                let c = match rng.next_usize(4) {
                    0 => (b'a' + (rng.next_u64() % 26) as u8) as char,
                    1 => (b'A' + (rng.next_u64() % 26) as u8) as char,
                    2 => (b'0' + (rng.next_u64() % 10) as u8) as char,
                    _ => ['!', '@', '#', '$', '%', '^', '&', '*'][rng.next_usize(8)],
                };
                c
            })
            .collect()
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        let s = self.clone();
        let mut shrinks = Vec::new();
        if !s.is_empty() {
            shrinks.push(String::new());
            if s.len() > 1 {
                shrinks.push(s[..s.len() / 2].to_string());
                shrinks.push(s[1..].to_string());
                shrinks.push(s[..s.len() - 1].to_string());
            }
        }
        Box::new(shrinks.into_iter())
    }
}

impl<T: Arbitrary> Arbitrary for Vec<T> {
    fn arbitrary(rng: &mut Rng) -> Self {
        let len = rng.next_usize(32);
        (0..len).map(|_| T::arbitrary(rng)).collect()
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        let v = self.clone();
        let mut shrinks: Vec<Self> = Vec::new();
        if !v.is_empty() {
            shrinks.push(Vec::new());
            if v.len() > 1 {
                shrinks.push(v[..v.len() / 2].to_vec());
                shrinks.push(v[1..].to_vec());
                shrinks.push(v[..v.len() - 1].to_vec());
            }
            // Shrink individual elements
            for (i, elem) in v.iter().enumerate() {
                for shrunk in elem.shrink() {
                    let mut new_v = v.clone();
                    new_v[i] = shrunk;
                    shrinks.push(new_v);
                }
            }
        }
        Box::new(shrinks.into_iter())
    }
}

impl<T: Arbitrary> Arbitrary for Option<T> {
    fn arbitrary(rng: &mut Rng) -> Self {
        if rng.next_bool() {
            Some(T::arbitrary(rng))
        } else {
            None
        }
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        match self {
            None => Box::new(std::iter::empty()),
            Some(x) => {
                let mut shrinks = vec![None];
                for shrunk in x.shrink() {
                    shrinks.push(Some(shrunk));
                }
                Box::new(shrinks.into_iter())
            }
        }
    }
}

impl<T: Arbitrary, U: Arbitrary> Arbitrary for (T, U) {
    fn arbitrary(rng: &mut Rng) -> Self {
        (T::arbitrary(rng), U::arbitrary(rng))
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        let (a, b) = self.clone();
        let mut shrinks = Vec::new();
        for shrunk_a in a.shrink() {
            shrinks.push((shrunk_a, b.clone()));
        }
        for shrunk_b in b.shrink() {
            shrinks.push((a.clone(), shrunk_b));
        }
        Box::new(shrinks.into_iter())
    }
}

// ============================================================================
// Security-Specific Generators
// ============================================================================

/// Cryptographic key for testing
#[derive(Clone, Debug)]
pub struct CryptoKey {
    pub algorithm: KeyAlgorithm,
    pub key_data: Vec<u8>,
    pub key_id: String,
}

#[derive(Clone, Debug)]
pub enum KeyAlgorithm {
    Aes128,
    Aes256,
    ChaCha20,
    Rsa2048,
    Rsa4096,
    Ed25519,
    X25519,
}

impl Arbitrary for KeyAlgorithm {
    fn arbitrary(rng: &mut Rng) -> Self {
        match rng.next_usize(7) {
            0 => KeyAlgorithm::Aes128,
            1 => KeyAlgorithm::Aes256,
            2 => KeyAlgorithm::ChaCha20,
            3 => KeyAlgorithm::Rsa2048,
            4 => KeyAlgorithm::Rsa4096,
            5 => KeyAlgorithm::Ed25519,
            _ => KeyAlgorithm::X25519,
        }
    }
}

impl Arbitrary for CryptoKey {
    fn arbitrary(rng: &mut Rng) -> Self {
        let algorithm = KeyAlgorithm::arbitrary(rng);
        let key_size = match &algorithm {
            KeyAlgorithm::Aes128 => 16,
            KeyAlgorithm::Aes256 => 32,
            KeyAlgorithm::ChaCha20 => 32,
            KeyAlgorithm::Rsa2048 => 256,
            KeyAlgorithm::Rsa4096 => 512,
            KeyAlgorithm::Ed25519 => 32,
            KeyAlgorithm::X25519 => 32,
        };
        let key_data = rng.next_bytes(key_size);
        let key_id = format!("key-{:016x}", rng.next_u64());

        Self {
            algorithm,
            key_data,
            key_id,
        }
    }
}

/// Network packet for security testing
#[derive(Clone, Debug)]
pub struct NetworkPacket {
    pub protocol: Protocol,
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: Vec<u8>,
    pub flags: PacketFlags,
}

#[derive(Clone, Debug)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Http,
    Https,
    Dns,
    Ssh,
}

#[derive(Clone, Debug, Default)]
pub struct PacketFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub urg: bool,
}

impl Arbitrary for Protocol {
    fn arbitrary(rng: &mut Rng) -> Self {
        match rng.next_usize(7) {
            0 => Protocol::Tcp,
            1 => Protocol::Udp,
            2 => Protocol::Icmp,
            3 => Protocol::Http,
            4 => Protocol::Https,
            5 => Protocol::Dns,
            _ => Protocol::Ssh,
        }
    }
}

impl Arbitrary for PacketFlags {
    fn arbitrary(rng: &mut Rng) -> Self {
        Self {
            syn: rng.next_bool(),
            ack: rng.next_bool(),
            fin: rng.next_bool(),
            rst: rng.next_bool(),
            psh: rng.next_bool(),
            urg: rng.next_bool(),
        }
    }
}

impl Arbitrary for NetworkPacket {
    fn arbitrary(rng: &mut Rng) -> Self {
        let protocol = Protocol::arbitrary(rng);
        let src_ip = [
            rng.next_u64() as u8,
            rng.next_u64() as u8,
            rng.next_u64() as u8,
            rng.next_u64() as u8,
        ];
        let dst_ip = [
            rng.next_u64() as u8,
            rng.next_u64() as u8,
            rng.next_u64() as u8,
            rng.next_u64() as u8,
        ];
        let src_port = rng.next_u64() as u16;
        let dst_port = match &protocol {
            Protocol::Http => 80,
            Protocol::Https => 443,
            Protocol::Dns => 53,
            Protocol::Ssh => 22,
            _ => rng.next_u64() as u16,
        };
        let payload_len = rng.next_usize(1500);
        let payload = rng.next_bytes(payload_len);
        let flags = PacketFlags::arbitrary(rng);

        Self {
            protocol,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            payload,
            flags,
        }
    }
}

/// JWT token for testing authentication
#[derive(Clone, Debug)]
pub struct JwtToken {
    pub header: JwtHeader,
    pub claims: JwtClaims,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct JwtHeader {
    pub alg: JwtAlgorithm,
    pub typ: String,
    pub kid: Option<String>,
}

#[derive(Clone, Debug)]
pub enum JwtAlgorithm {
    Hs256,
    Hs384,
    Hs512,
    Rs256,
    Rs384,
    Rs512,
    Es256,
    Es384,
    EdDsa,
    None,
}

#[derive(Clone, Debug)]
pub struct JwtClaims {
    pub sub: String,
    pub iss: String,
    pub aud: Vec<String>,
    pub exp: u64,
    pub iat: u64,
    pub nbf: Option<u64>,
    pub jti: Option<String>,
    pub roles: Vec<String>,
}

impl Arbitrary for JwtAlgorithm {
    fn arbitrary(rng: &mut Rng) -> Self {
        match rng.next_usize(10) {
            0 => JwtAlgorithm::Hs256,
            1 => JwtAlgorithm::Hs384,
            2 => JwtAlgorithm::Hs512,
            3 => JwtAlgorithm::Rs256,
            4 => JwtAlgorithm::Rs384,
            5 => JwtAlgorithm::Rs512,
            6 => JwtAlgorithm::Es256,
            7 => JwtAlgorithm::Es384,
            8 => JwtAlgorithm::EdDsa,
            _ => JwtAlgorithm::None,
        }
    }
}

impl Arbitrary for JwtHeader {
    fn arbitrary(rng: &mut Rng) -> Self {
        Self {
            alg: JwtAlgorithm::arbitrary(rng),
            typ: "JWT".to_string(),
            kid: if rng.next_bool() {
                Some(format!("kid-{:08x}", rng.next_u32()))
            } else {
                None
            },
        }
    }
}

impl Arbitrary for JwtClaims {
    fn arbitrary(rng: &mut Rng) -> Self {
        let now = 1700000000u64 + rng.next_u64() % 1000000;
        let roles = ["admin", "user", "moderator", "guest", "api"];
        let num_roles = rng.next_usize(3) + 1;
        let selected_roles: Vec<String> = (0..num_roles)
            .map(|_| roles[rng.next_usize(roles.len())].to_string())
            .collect();

        Self {
            sub: format!("user-{:016x}", rng.next_u64()),
            iss: format!("auth.example-{}.com", rng.next_usize(10)),
            aud: vec!["api.example.com".to_string()],
            exp: now + 3600 + rng.next_u64() % 86400,
            iat: now,
            nbf: if rng.next_bool() { Some(now) } else { None },
            jti: if rng.next_bool() {
                Some(format!("jti-{:032x}", rng.next_u64()))
            } else {
                None
            },
            roles: selected_roles,
        }
    }
}

impl Arbitrary for JwtToken {
    fn arbitrary(rng: &mut Rng) -> Self {
        let sig_len = match JwtAlgorithm::arbitrary(rng) {
            JwtAlgorithm::Hs256 | JwtAlgorithm::Es256 => 32,
            JwtAlgorithm::Hs384 | JwtAlgorithm::Es384 => 48,
            JwtAlgorithm::Hs512 => 64,
            JwtAlgorithm::Rs256 | JwtAlgorithm::Rs384 | JwtAlgorithm::Rs512 => 256,
            JwtAlgorithm::EdDsa => 64,
            JwtAlgorithm::None => 0,
        };

        Self {
            header: JwtHeader::arbitrary(rng),
            claims: JwtClaims::arbitrary(rng),
            signature: rng.next_bytes(sig_len),
        }
    }
}

/// HTTP request for web security testing
#[derive(Clone, Debug)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub query_params: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
    pub cookies: HashMap<String, String>,
}

#[derive(Clone, Debug)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Options,
    Head,
}

impl Arbitrary for HttpMethod {
    fn arbitrary(rng: &mut Rng) -> Self {
        match rng.next_usize(7) {
            0 => HttpMethod::Get,
            1 => HttpMethod::Post,
            2 => HttpMethod::Put,
            3 => HttpMethod::Delete,
            4 => HttpMethod::Patch,
            5 => HttpMethod::Options,
            _ => HttpMethod::Head,
        }
    }
}

impl Arbitrary for HttpRequest {
    fn arbitrary(rng: &mut Rng) -> Self {
        let method = HttpMethod::arbitrary(rng);

        // Generate path segments
        let num_segments = rng.next_usize(5);
        let path_segments: Vec<String> = (0..num_segments)
            .map(|_| {
                let len = rng.next_usize(12) + 1;
                (0..len)
                    .map(|_| (b'a' + (rng.next_u64() % 26) as u8) as char)
                    .collect()
            })
            .collect();
        let path = format!("/{}", path_segments.join("/"));

        // Generate headers
        let mut headers = HashMap::new();
        headers.insert("Host".to_string(), "example.com".to_string());
        headers.insert("User-Agent".to_string(), "SecurityTest/1.0".to_string());
        if rng.next_bool() {
            headers.insert(
                "Authorization".to_string(),
                format!(
                    "Bearer {}",
                    rng.next_bytes(32)
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<String>()
                ),
            );
        }
        if rng.next_bool() {
            headers.insert("Content-Type".to_string(), "application/json".to_string());
        }

        // Generate query params
        let mut query_params = HashMap::new();
        let num_params = rng.next_usize(5);
        for _ in 0..num_params {
            let key_len = rng.next_usize(8) + 1;
            let key: String = (0..key_len)
                .map(|_| (b'a' + (rng.next_u64() % 26) as u8) as char)
                .collect();
            let val_len = rng.next_usize(16) + 1;
            let val: String = (0..val_len)
                .map(|_| (b'a' + (rng.next_u64() % 26) as u8) as char)
                .collect();
            query_params.insert(key, val);
        }

        // Generate body for POST/PUT/PATCH
        let body = match &method {
            HttpMethod::Post | HttpMethod::Put | HttpMethod::Patch => {
                if rng.next_bool() {
                    Some(rng.next_bytes(rng.next_usize(1024)))
                } else {
                    None
                }
            }
            _ => None,
        };

        // Generate cookies
        let mut cookies = HashMap::new();
        if rng.next_bool() {
            cookies.insert("session".to_string(), format!("{:032x}", rng.next_u64()));
        }

        Self {
            method,
            path,
            headers,
            query_params,
            body,
            cookies,
        }
    }
}

// ============================================================================
// Property Testing Framework
// ============================================================================

/// Result of a property test
#[derive(Debug)]
pub enum TestResult {
    Passed,
    Failed {
        seed: u64,
        iteration: usize,
        error: String,
    },
    Discarded,
}

/// Configuration for property tests
#[derive(Clone)]
pub struct TestConfig {
    pub num_tests: usize,
    pub max_shrinks: usize,
    pub seed: Option<u64>,
    pub verbose: bool,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            num_tests: 100,
            max_shrinks: 100,
            seed: None,
            verbose: false,
        }
    }
}

impl TestConfig {
    pub fn with_tests(mut self, n: usize) -> Self {
        self.num_tests = n;
        self
    }

    pub fn with_seed(mut self, seed: u64) -> Self {
        self.seed = Some(seed);
        self
    }

    pub fn verbose(mut self) -> Self {
        self.verbose = true;
        self
    }
}

/// Statistics for test runs
#[derive(Default)]
pub struct TestStats {
    pub passed: AtomicU64,
    pub failed: AtomicU64,
    pub discarded: AtomicU64,
    pub shrink_steps: AtomicU64,
}

impl TestStats {
    pub fn record_passed(&self) {
        self.passed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_failed(&self) {
        self.failed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_discarded(&self) {
        self.discarded.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_shrink(&self) {
        self.shrink_steps.fetch_add(1, Ordering::Relaxed);
    }

    pub fn summary(&self) -> String {
        format!(
            "Passed: {}, Failed: {}, Discarded: {}, Shrink steps: {}",
            self.passed.load(Ordering::Relaxed),
            self.failed.load(Ordering::Relaxed),
            self.discarded.load(Ordering::Relaxed),
            self.shrink_steps.load(Ordering::Relaxed),
        )
    }
}

/// Property test runner
pub struct PropertyTest {
    config: TestConfig,
    stats: TestStats,
}

impl PropertyTest {
    pub fn new() -> Self {
        Self {
            config: TestConfig::default(),
            stats: TestStats::default(),
        }
    }

    pub fn with_config(config: TestConfig) -> Self {
        Self {
            config,
            stats: TestStats::default(),
        }
    }

    /// Run a property test with one arbitrary input
    pub fn for_all<A, F>(&self, prop: F) -> TestResult
    where
        A: Arbitrary + fmt::Debug,
        F: Fn(A) -> bool,
    {
        let seed = self.config.seed.unwrap_or_else(|| {
            use std::time::{SystemTime, UNIX_EPOCH};
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64
        });

        let mut rng = Rng::new(seed);

        for iteration in 0..self.config.num_tests {
            let input = A::arbitrary(&mut rng);

            if self.config.verbose {
                println!("Test {}: {:?}", iteration, input);
            }

            if !prop(input.clone()) {
                self.stats.record_failed();

                // Try to shrink the failing input
                let mut smallest = input.clone();
                let mut shrink_count = 0;

                for shrunk in input.shrink().take(self.config.max_shrinks) {
                    self.stats.record_shrink();
                    shrink_count += 1;

                    if !prop(shrunk.clone()) {
                        smallest = shrunk;
                    }
                }

                return TestResult::Failed {
                    seed,
                    iteration,
                    error: format!(
                        "Property failed for input: {:?} (shrunk {} times from original)",
                        smallest, shrink_count
                    ),
                };
            }

            self.stats.record_passed();
        }

        TestResult::Passed
    }

    /// Run a property test with two arbitrary inputs
    pub fn for_all2<A, B, F>(&self, prop: F) -> TestResult
    where
        A: Arbitrary + fmt::Debug,
        B: Arbitrary + fmt::Debug,
        F: Fn(A, B) -> bool,
    {
        let seed = self.config.seed.unwrap_or_else(|| {
            use std::time::{SystemTime, UNIX_EPOCH};
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64
        });

        let mut rng = Rng::new(seed);

        for iteration in 0..self.config.num_tests {
            let a = A::arbitrary(&mut rng);
            let b = B::arbitrary(&mut rng);

            if self.config.verbose {
                println!("Test {}: ({:?}, {:?})", iteration, a, b);
            }

            if !prop(a.clone(), b.clone()) {
                self.stats.record_failed();

                return TestResult::Failed {
                    seed,
                    iteration,
                    error: format!("Property failed for inputs: ({:?}, {:?})", a, b),
                };
            }

            self.stats.record_passed();
        }

        TestResult::Passed
    }

    pub fn stats(&self) -> &TestStats {
        &self.stats
    }
}

// ============================================================================
// Security Property Assertions
// ============================================================================

/// Common security properties to test
pub struct SecurityProperties;

impl SecurityProperties {
    /// Property: Encryption should be reversible
    pub fn encryption_reversible<E, D>(
        encrypt: E,
        decrypt: D,
        key: &[u8],
    ) -> impl Fn(Vec<u8>) -> bool
    where
        E: Fn(&[u8], &[u8]) -> Vec<u8>,
        D: Fn(&[u8], &[u8]) -> Vec<u8>,
    {
        let key = key.to_vec();
        move |plaintext: Vec<u8>| {
            let ciphertext = encrypt(&plaintext, &key);
            let decrypted = decrypt(&ciphertext, &key);
            plaintext == decrypted
        }
    }

    /// Property: Hash should be deterministic
    pub fn hash_deterministic<H>(hash: H) -> impl Fn(Vec<u8>) -> bool
    where
        H: Fn(&[u8]) -> Vec<u8>,
    {
        move |input: Vec<u8>| {
            let hash1 = hash(&input);
            let hash2 = hash(&input);
            hash1 == hash2
        }
    }

    /// Property: Different inputs should (usually) produce different hashes
    pub fn hash_collision_resistant<H>(hash: H) -> impl Fn(Vec<u8>, Vec<u8>) -> bool
    where
        H: Fn(&[u8]) -> Vec<u8>,
    {
        move |a: Vec<u8>, b: Vec<u8>| {
            if a == b {
                true // Same input, same hash is expected
            } else {
                hash(&a) != hash(&b)
            }
        }
    }

    /// Property: Token validation should reject tampered tokens
    pub fn token_tamper_detection<V>(validate: V) -> impl Fn(JwtToken) -> bool
    where
        V: Fn(&JwtToken) -> bool,
    {
        move |mut token: JwtToken| {
            // Tamper with the signature
            if !token.signature.is_empty() {
                token.signature[0] ^= 0xFF;
            }
            !validate(&token)
        }
    }

    /// Property: Access control should deny unauthorized access
    pub fn access_control_denies<C>(
        check: C,
        protected_resources: Vec<String>,
    ) -> impl Fn(String, Vec<String>) -> bool
    where
        C: Fn(&str, &[String]) -> bool,
    {
        move |resource: String, roles: Vec<String>| {
            if protected_resources.contains(&resource) {
                // Protected resource should only be accessible with proper roles
                let has_access = check(&resource, &roles);
                let should_have_access = roles.iter().any(|r| r == "admin");
                has_access == should_have_access
            } else {
                true // Unprotected resources are always accessible
            }
        }
    }

    /// Property: Rate limiting should enforce limits
    pub fn rate_limit_enforced(max_requests: usize, window_ms: u64) -> impl Fn(Vec<u64>) -> bool {
        move |timestamps: Vec<u64>| {
            if timestamps.is_empty() {
                return true;
            }

            let mut allowed = 0;
            let mut window_start = timestamps[0];
            let mut count_in_window = 0;

            for &ts in &timestamps {
                if ts - window_start > window_ms {
                    window_start = ts;
                    count_in_window = 0;
                }

                if count_in_window < max_requests {
                    allowed += 1;
                    count_in_window += 1;
                }
            }

            allowed
                <= max_requests
                    * ((timestamps.last().unwrap() - timestamps[0]) / window_ms + 1) as usize
        }
    }
}

// ============================================================================
// Example Security Functions to Test
// ============================================================================

/// Simple XOR encryption (for demonstration)
fn xor_encrypt(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    plaintext
        .iter()
        .zip(key.iter().cycle())
        .map(|(p, k)| p ^ k)
        .collect()
}

fn xor_decrypt(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    xor_encrypt(ciphertext, key) // XOR is symmetric
}

/// Simple hash function (for demonstration)
fn simple_hash(data: &[u8]) -> Vec<u8> {
    let mut hash = [0u8; 32];
    for (i, byte) in data.iter().enumerate() {
        hash[i % 32] ^= byte;
        hash[(i + 1) % 32] = hash[(i + 1) % 32].wrapping_add(*byte);
    }
    hash.to_vec()
}

/// Validate JWT token (simplified)
fn validate_jwt(token: &JwtToken) -> bool {
    // Check algorithm is not None
    if matches!(token.header.alg, JwtAlgorithm::None) {
        return false;
    }

    // Check expiration
    let now = 1700000000u64;
    if token.claims.exp < now {
        return false;
    }

    // Check not-before
    if let Some(nbf) = token.claims.nbf {
        if nbf > now {
            return false;
        }
    }

    // Verify signature exists
    !token.signature.is_empty()
}

/// Access control check
fn check_access(resource: &str, roles: &[String]) -> bool {
    if resource.starts_with("/admin") {
        roles.iter().any(|r| r == "admin")
    } else if resource.starts_with("/api") {
        roles
            .iter()
            .any(|r| r == "admin" || r == "user" || r == "api")
    } else {
        true
    }
}

// ============================================================================
// Main Demonstration
// ============================================================================

fn main() {
    println!("=== Property-Based Testing for Security Code ===\n");

    // Test 1: XOR encryption reversibility
    println!("Test 1: XOR Encryption Reversibility");
    let test = PropertyTest::with_config(TestConfig::default().with_tests(1000).with_seed(12345));

    let key = b"secret_key_12345";
    let result = test.for_all(SecurityProperties::encryption_reversible(
        xor_encrypt,
        xor_decrypt,
        key,
    ));

    match result {
        TestResult::Passed => println!("  PASSED: All {} tests passed", 1000),
        TestResult::Failed {
            seed,
            iteration,
            error,
        } => {
            println!(
                "  FAILED at iteration {} (seed: {}): {}",
                iteration, seed, error
            );
        }
        TestResult::Discarded => println!("  DISCARDED"),
    }
    println!("  Stats: {}\n", test.stats().summary());

    // Test 2: Hash determinism
    println!("Test 2: Hash Determinism");
    let test = PropertyTest::with_config(TestConfig::default().with_tests(500));

    let result = test.for_all(SecurityProperties::hash_deterministic(simple_hash));

    match result {
        TestResult::Passed => println!("  PASSED: Hash is deterministic"),
        TestResult::Failed { error, .. } => println!("  FAILED: {}", error),
        TestResult::Discarded => println!("  DISCARDED"),
    }
    println!("  Stats: {}\n", test.stats().summary());

    // Test 3: JWT validation
    println!("Test 3: JWT Token Validation");
    let test = PropertyTest::with_config(TestConfig::default().with_tests(200));

    let result = test.for_all(|token: JwtToken| {
        // Valid tokens should pass, expired should fail
        let now = 1700000000u64;
        let should_be_valid = !matches!(token.header.alg, JwtAlgorithm::None)
            && token.claims.exp >= now
            && !token.signature.is_empty();
        validate_jwt(&token) == should_be_valid
    });

    match result {
        TestResult::Passed => println!("  PASSED: JWT validation works correctly"),
        TestResult::Failed { error, .. } => println!("  FAILED: {}", error),
        TestResult::Discarded => println!("  DISCARDED"),
    }
    println!("  Stats: {}\n", test.stats().summary());

    // Test 4: Access control
    println!("Test 4: Access Control");
    let test = PropertyTest::with_config(TestConfig::default().with_tests(500));

    let result = test.for_all2(|path: String, roles: Vec<String>| {
        let path = format!("/{}", path);
        let result = check_access(&path, &roles);

        if path.starts_with("/admin") {
            result == roles.iter().any(|r| r == "admin")
        } else {
            true
        }
    });

    match result {
        TestResult::Passed => println!("  PASSED: Access control enforced correctly"),
        TestResult::Failed { error, .. } => println!("  FAILED: {}", error),
        TestResult::Discarded => println!("  DISCARDED"),
    }
    println!("  Stats: {}\n", test.stats().summary());

    // Test 5: Network packet generation
    println!("Test 5: Network Packet Fuzzing");
    let test = PropertyTest::with_config(TestConfig::default().with_tests(100));

    let result = test.for_all(|packet: NetworkPacket| {
        // Property: packets should have valid port ranges
        packet.src_port <= 65535 && packet.dst_port <= 65535
    });

    match result {
        TestResult::Passed => println!("  PASSED: All packets have valid ports"),
        TestResult::Failed { error, .. } => println!("  FAILED: {}", error),
        TestResult::Discarded => println!("  DISCARDED"),
    }
    println!("  Stats: {}\n", test.stats().summary());

    // Test 6: HTTP request fuzzing
    println!("Test 6: HTTP Request Fuzzing");
    let test = PropertyTest::with_config(TestConfig::default().with_tests(100));

    let result = test.for_all(|request: HttpRequest| {
        // Property: paths should start with /
        request.path.starts_with('/')
    });

    match result {
        TestResult::Passed => println!("  PASSED: All request paths are valid"),
        TestResult::Failed { error, .. } => println!("  FAILED: {}", error),
        TestResult::Discarded => println!("  DISCARDED"),
    }
    println!("  Stats: {}\n", test.stats().summary());

    // Test 7: Crypto key generation
    println!("Test 7: Cryptographic Key Properties");
    let test = PropertyTest::with_config(TestConfig::default().with_tests(100));

    let result = test.for_all(|key: CryptoKey| {
        // Property: key size should match algorithm
        let expected_size = match key.algorithm {
            KeyAlgorithm::Aes128 => 16,
            KeyAlgorithm::Aes256 => 32,
            KeyAlgorithm::ChaCha20 => 32,
            KeyAlgorithm::Rsa2048 => 256,
            KeyAlgorithm::Rsa4096 => 512,
            KeyAlgorithm::Ed25519 => 32,
            KeyAlgorithm::X25519 => 32,
        };
        key.key_data.len() == expected_size
    });

    match result {
        TestResult::Passed => println!("  PASSED: All keys have correct sizes"),
        TestResult::Failed { error, .. } => println!("  FAILED: {}", error),
        TestResult::Discarded => println!("  DISCARDED"),
    }
    println!("  Stats: {}\n", test.stats().summary());

    println!("=== Property-Based Testing Complete ===");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rng_deterministic() {
        let mut rng1 = Rng::new(12345);
        let mut rng2 = Rng::new(12345);

        for _ in 0..100 {
            assert_eq!(rng1.next_u64(), rng2.next_u64());
        }
    }

    #[test]
    fn test_rng_bytes() {
        let mut rng = Rng::new(42);
        let bytes = rng.next_bytes(100);
        assert_eq!(bytes.len(), 100);
    }

    #[test]
    fn test_arbitrary_bool() {
        let mut rng = Rng::new(1);
        let mut trues = 0;
        let mut falses = 0;

        for _ in 0..1000 {
            if bool::arbitrary(&mut rng) {
                trues += 1;
            } else {
                falses += 1;
            }
        }

        // Should have roughly equal distribution
        assert!(trues > 400 && trues < 600);
        assert!(falses > 400 && falses < 600);
    }

    #[test]
    fn test_arbitrary_vec() {
        let mut rng = Rng::new(42);
        let vec: Vec<u8> = Vec::arbitrary(&mut rng);
        assert!(vec.len() <= 32);
    }

    #[test]
    fn test_shrink_u32() {
        let val: u32 = 100;
        let shrinks: Vec<u32> = val.shrink().collect();
        assert!(shrinks.contains(&0));
        assert!(shrinks.contains(&99));
        assert!(shrinks.iter().all(|&x| x < val));
    }

    #[test]
    fn test_shrink_string() {
        let val = "hello".to_string();
        let shrinks: Vec<String> = val.shrink().collect();
        assert!(shrinks.contains(&String::new()));
        assert!(shrinks.iter().all(|s| s.len() < val.len()));
    }

    #[test]
    fn test_xor_encryption_property() {
        let test = PropertyTest::with_config(TestConfig::default().with_tests(100).with_seed(42));

        let key = b"test_key";
        let result = test.for_all(SecurityProperties::encryption_reversible(
            xor_encrypt,
            xor_decrypt,
            key,
        ));

        assert!(matches!(result, TestResult::Passed));
    }

    #[test]
    fn test_hash_determinism_property() {
        let test = PropertyTest::with_config(TestConfig::default().with_tests(50).with_seed(123));

        let result = test.for_all(SecurityProperties::hash_deterministic(simple_hash));
        assert!(matches!(result, TestResult::Passed));
    }

    #[test]
    fn test_crypto_key_generation() {
        let mut rng = Rng::new(999);

        for _ in 0..50 {
            let key = CryptoKey::arbitrary(&mut rng);
            let expected_size = match key.algorithm {
                KeyAlgorithm::Aes128 => 16,
                KeyAlgorithm::Aes256 => 32,
                KeyAlgorithm::ChaCha20 => 32,
                KeyAlgorithm::Rsa2048 => 256,
                KeyAlgorithm::Rsa4096 => 512,
                KeyAlgorithm::Ed25519 => 32,
                KeyAlgorithm::X25519 => 32,
            };
            assert_eq!(key.key_data.len(), expected_size);
        }
    }

    #[test]
    fn test_network_packet_generation() {
        let mut rng = Rng::new(777);

        for _ in 0..50 {
            let packet = NetworkPacket::arbitrary(&mut rng);
            assert!(packet.payload.len() <= 1500);
        }
    }

    #[test]
    fn test_jwt_token_generation() {
        let mut rng = Rng::new(555);

        for _ in 0..50 {
            let token = JwtToken::arbitrary(&mut rng);
            assert!(!token.claims.sub.is_empty());
            assert!(token.claims.exp > token.claims.iat);
        }
    }

    #[test]
    fn test_http_request_generation() {
        let mut rng = Rng::new(333);

        for _ in 0..50 {
            let request = HttpRequest::arbitrary(&mut rng);
            assert!(request.path.starts_with('/'));
            assert!(request.headers.contains_key("Host"));
        }
    }

    #[test]
    fn test_property_test_failure_detection() {
        let test = PropertyTest::with_config(TestConfig::default().with_tests(100).with_seed(1));

        // This property will fail: not all u8 values are less than 200
        let result = test.for_all(|x: u8| x < 200);

        assert!(matches!(result, TestResult::Failed { .. }));
    }

    #[test]
    fn test_for_all2() {
        let test = PropertyTest::with_config(TestConfig::default().with_tests(100).with_seed(42));

        // Property: addition is commutative
        let result = test.for_all2(|a: u32, b: u32| a.wrapping_add(b) == b.wrapping_add(a));

        assert!(matches!(result, TestResult::Passed));
    }

    #[test]
    fn test_access_control_property() {
        let test = PropertyTest::with_config(TestConfig::default().with_tests(100).with_seed(42));

        let result = test.for_all(|roles: Vec<String>| {
            // Admin path should only be accessible to admins
            let is_admin = roles.iter().any(|r| r == "admin");
            check_access("/admin/users", &roles) == is_admin
        });

        assert!(matches!(result, TestResult::Passed));
    }

    #[test]
    fn test_rate_limit_property() {
        let property = SecurityProperties::rate_limit_enforced(10, 1000);

        // 5 requests in one window should all be allowed
        assert!(property(vec![0, 100, 200, 300, 400]));

        // 15 requests in one window should be limited
        let timestamps: Vec<u64> = (0..15).map(|i| i * 50).collect();
        assert!(property(timestamps));
    }
}
