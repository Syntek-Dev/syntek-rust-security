//! Fuzzing Harness - Comprehensive Fuzz Testing Infrastructure
//!
//! This example demonstrates building a fuzz testing framework with
//! corpus management, crash analysis, and coverage tracking.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Fuzzing target type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetType {
    /// Pure Rust function
    Function,
    /// Binary executable
    Binary,
    /// Network service
    Network,
    /// File format parser
    Parser,
    /// API endpoint
    Api,
}

/// Fuzzing strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuzzStrategy {
    /// Random byte mutation
    Random,
    /// Bit flipping
    BitFlip,
    /// Arithmetic mutations
    Arithmetic,
    /// Known interesting values
    Dictionary,
    /// Structure-aware fuzzing
    Grammar,
    /// Coverage-guided fuzzing
    CoverageGuided,
    /// Hybrid approach
    Hybrid,
}

/// Crash severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub enum CrashSeverity {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

/// Crash type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CrashType {
    Panic,
    StackOverflow,
    HeapOverflow,
    UseAfterFree,
    NullDereference,
    IntegerOverflow,
    OutOfBounds,
    DoubleFree,
    MemoryLeak,
    Timeout,
    Assertion,
    Unknown,
}

impl CrashType {
    pub fn severity(&self) -> CrashSeverity {
        match self {
            Self::UseAfterFree | Self::DoubleFree | Self::HeapOverflow => CrashSeverity::Critical,
            Self::StackOverflow | Self::OutOfBounds | Self::NullDereference => CrashSeverity::High,
            Self::IntegerOverflow | Self::MemoryLeak => CrashSeverity::Medium,
            Self::Panic | Self::Assertion | Self::Timeout => CrashSeverity::Low,
            Self::Unknown => CrashSeverity::Unknown,
        }
    }
}

/// Fuzz input
#[derive(Debug, Clone)]
pub struct FuzzInput {
    pub id: u64,
    pub data: Vec<u8>,
    pub parent_id: Option<u64>,
    pub generation: u32,
    pub mutations: Vec<Mutation>,
    pub coverage_hash: u64,
    pub created_at: u64,
}

impl FuzzInput {
    pub fn new(data: Vec<u8>) -> Self {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        Self {
            id: COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            data,
            parent_id: None,
            generation: 0,
            mutations: Vec::new(),
            coverage_hash: 0,
            created_at: current_timestamp(),
        }
    }

    pub fn mutate(&self, mutation: Mutation) -> Self {
        let mut new_data = self.data.clone();
        mutation.apply(&mut new_data);

        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let mut mutations = self.mutations.clone();
        mutations.push(mutation);

        Self {
            id: COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            data: new_data,
            parent_id: Some(self.id),
            generation: self.generation + 1,
            mutations,
            coverage_hash: 0,
            created_at: current_timestamp(),
        }
    }
}

/// Mutation operation
#[derive(Debug, Clone)]
pub enum Mutation {
    BitFlip { offset: usize, bit: u8 },
    ByteFlip { offset: usize },
    ByteSet { offset: usize, value: u8 },
    ByteInsert { offset: usize, value: u8 },
    ByteDelete { offset: usize },
    ChunkInsert { offset: usize, data: Vec<u8> },
    ChunkDelete { offset: usize, length: usize },
    ChunkReplace { offset: usize, data: Vec<u8> },
    Arithmetic { offset: usize, delta: i32, size: u8 },
    Interesting { offset: usize, value: Vec<u8> },
    Havoc { seed: u64 },
    Splice { other_id: u64, point: usize },
}

impl Mutation {
    pub fn apply(&self, data: &mut Vec<u8>) {
        match self {
            Mutation::BitFlip { offset, bit } => {
                if *offset < data.len() {
                    data[*offset] ^= 1 << bit;
                }
            }
            Mutation::ByteFlip { offset } => {
                if *offset < data.len() {
                    data[*offset] = !data[*offset];
                }
            }
            Mutation::ByteSet { offset, value } => {
                if *offset < data.len() {
                    data[*offset] = *value;
                }
            }
            Mutation::ByteInsert { offset, value } => {
                let pos = (*offset).min(data.len());
                data.insert(pos, *value);
            }
            Mutation::ByteDelete { offset } => {
                if *offset < data.len() {
                    data.remove(*offset);
                }
            }
            Mutation::ChunkInsert {
                offset,
                data: chunk,
            } => {
                let pos = (*offset).min(data.len());
                for (i, b) in chunk.iter().enumerate() {
                    data.insert(pos + i, *b);
                }
            }
            Mutation::ChunkDelete { offset, length } => {
                let end = (*offset + *length).min(data.len());
                if *offset < data.len() {
                    data.drain(*offset..end);
                }
            }
            Mutation::ChunkReplace {
                offset,
                data: chunk,
            } => {
                for (i, b) in chunk.iter().enumerate() {
                    if offset + i < data.len() {
                        data[offset + i] = *b;
                    }
                }
            }
            Mutation::Arithmetic {
                offset,
                delta,
                size,
            } => {
                if *offset + (*size as usize) <= data.len() {
                    match size {
                        1 => {
                            let v = data[*offset] as i32 + delta;
                            data[*offset] = v as u8;
                        }
                        2 => {
                            let v = u16::from_le_bytes([data[*offset], data[*offset + 1]]) as i32
                                + delta;
                            let bytes = (v as u16).to_le_bytes();
                            data[*offset] = bytes[0];
                            data[*offset + 1] = bytes[1];
                        }
                        _ => {}
                    }
                }
            }
            Mutation::Interesting { offset, value } => {
                for (i, b) in value.iter().enumerate() {
                    if offset + i < data.len() {
                        data[offset + i] = *b;
                    }
                }
            }
            Mutation::Havoc { seed } => {
                // Apply multiple random mutations
                let mut rng = simple_rng(*seed);
                let count = (rng % 10) + 1;
                for _ in 0..count {
                    if !data.is_empty() {
                        let offset = rng as usize % data.len();
                        data[offset] = (rng >> 8) as u8;
                        rng = simple_rng(rng);
                    }
                }
            }
            Mutation::Splice { other_id: _, point } => {
                // Would splice with another input
                if *point < data.len() {
                    data.truncate(*point);
                }
            }
        }
    }
}

/// Crash report
#[derive(Debug, Clone)]
pub struct CrashReport {
    pub id: String,
    pub input: FuzzInput,
    pub crash_type: CrashType,
    pub severity: CrashSeverity,
    pub message: String,
    pub stack_trace: Option<String>,
    pub memory_address: Option<u64>,
    pub discovered_at: u64,
    pub minimized: bool,
    pub deduplicated: bool,
}

/// Coverage information
#[derive(Debug, Clone, Default)]
pub struct Coverage {
    pub edges_hit: HashSet<u64>,
    pub basic_blocks: HashSet<u64>,
    pub total_edges: u64,
    pub coverage_percent: f64,
}

impl Coverage {
    pub fn hash(&self) -> u64 {
        let mut hash = 0u64;
        for edge in &self.edges_hit {
            hash = hash.wrapping_add(*edge);
            hash = hash.rotate_left(7);
        }
        hash
    }

    pub fn is_new_coverage(&self, other: &Coverage) -> bool {
        self.edges_hit.difference(&other.edges_hit).next().is_some()
    }
}

/// Corpus - collection of interesting inputs
pub struct Corpus {
    inputs: RwLock<HashMap<u64, FuzzInput>>,
    coverage_map: RwLock<HashSet<u64>>,
    corpus_dir: PathBuf,
    max_size: usize,
}

impl Corpus {
    pub fn new(corpus_dir: PathBuf, max_size: usize) -> Self {
        Self {
            inputs: RwLock::new(HashMap::new()),
            coverage_map: RwLock::new(HashSet::new()),
            corpus_dir,
            max_size,
        }
    }

    /// Add input to corpus if it provides new coverage
    pub fn add(&self, input: FuzzInput, coverage: &Coverage) -> bool {
        let mut coverage_map = self.coverage_map.write().unwrap();
        let new_edges: HashSet<_> = coverage
            .edges_hit
            .difference(&coverage_map)
            .cloned()
            .collect();

        if new_edges.is_empty() {
            return false;
        }

        // Add new edges to coverage map
        for edge in new_edges {
            coverage_map.insert(edge);
        }

        // Add input to corpus
        let mut inputs = self.inputs.write().unwrap();
        if inputs.len() >= self.max_size {
            // Remove oldest input
            if let Some(oldest) = inputs.values().min_by_key(|i| i.created_at).map(|i| i.id) {
                inputs.remove(&oldest);
            }
        }
        inputs.insert(input.id, input);

        true
    }

    /// Get a random input from corpus
    pub fn get_random(&self) -> Option<FuzzInput> {
        let inputs = self.inputs.read().unwrap();
        if inputs.is_empty() {
            return None;
        }
        let idx = simple_rng(current_timestamp()) as usize % inputs.len();
        inputs.values().nth(idx).cloned()
    }

    /// Get corpus size
    pub fn size(&self) -> usize {
        self.inputs.read().unwrap().len()
    }

    /// Get total coverage
    pub fn coverage_count(&self) -> usize {
        self.coverage_map.read().unwrap().len()
    }
}

/// Fuzzer statistics
#[derive(Debug, Clone, Default)]
pub struct FuzzStats {
    pub total_executions: u64,
    pub executions_per_second: f64,
    pub unique_crashes: u64,
    pub total_crashes: u64,
    pub corpus_size: usize,
    pub coverage_edges: usize,
    pub last_new_coverage: u64,
    pub start_time: u64,
    pub running_time_secs: u64,
}

/// Fuzzer configuration
#[derive(Debug, Clone)]
pub struct FuzzConfig {
    pub target_type: TargetType,
    pub strategy: FuzzStrategy,
    pub corpus_dir: PathBuf,
    pub crash_dir: PathBuf,
    pub max_input_size: usize,
    pub timeout: Duration,
    pub memory_limit: usize,
    pub max_corpus_size: usize,
    pub dictionary: Vec<Vec<u8>>,
    pub seed: u64,
    pub workers: usize,
}

impl Default for FuzzConfig {
    fn default() -> Self {
        Self {
            target_type: TargetType::Function,
            strategy: FuzzStrategy::CoverageGuided,
            corpus_dir: PathBuf::from("corpus"),
            crash_dir: PathBuf::from("crashes"),
            max_input_size: 1024 * 1024, // 1MB
            timeout: Duration::from_secs(1),
            memory_limit: 100 * 1024 * 1024, // 100MB
            max_corpus_size: 10000,
            dictionary: Self::default_dictionary(),
            seed: 0,
            workers: 1,
        }
    }
}

impl FuzzConfig {
    fn default_dictionary() -> Vec<Vec<u8>> {
        vec![
            vec![0x00],
            vec![0xFF],
            vec![0x00, 0x00],
            vec![0xFF, 0xFF],
            vec![0x00, 0x00, 0x00, 0x00],
            vec![0xFF, 0xFF, 0xFF, 0xFF],
            vec![0x7F],       // Max i8
            vec![0x80],       // Min i8
            vec![0xFF, 0x7F], // Max i16 LE
            vec![0x00, 0x80], // Min i16 LE
            b"AAAA".to_vec(),
            b"%%%%".to_vec(),
            b"%s%s%s".to_vec(),
            b"../".to_vec(),
            b"<script>".to_vec(),
        ]
    }
}

/// Main fuzzer
pub struct Fuzzer {
    config: FuzzConfig,
    corpus: Arc<Corpus>,
    crashes: RwLock<Vec<CrashReport>>,
    crash_hashes: RwLock<HashSet<u64>>,
    stats: RwLock<FuzzStats>,
    running: std::sync::atomic::AtomicBool,
    rng_state: std::sync::atomic::AtomicU64,
}

impl Fuzzer {
    pub fn new(config: FuzzConfig) -> Self {
        let corpus = Arc::new(Corpus::new(
            config.corpus_dir.clone(),
            config.max_corpus_size,
        ));

        let stats = FuzzStats {
            start_time: current_timestamp(),
            ..Default::default()
        };

        Self {
            config,
            corpus,
            crashes: RwLock::new(Vec::new()),
            crash_hashes: RwLock::new(HashSet::new()),
            stats: RwLock::new(stats),
            running: std::sync::atomic::AtomicBool::new(false),
            rng_state: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Seed corpus with initial inputs
    pub fn seed_corpus(&self, inputs: Vec<Vec<u8>>) {
        for data in inputs {
            let input = FuzzInput::new(data);
            let coverage = Coverage::default(); // Would get actual coverage
            self.corpus.add(input, &coverage);
        }
    }

    /// Run fuzzing for specified duration
    pub fn fuzz_for(&self, duration: Duration, target: impl Fn(&[u8]) -> FuzzResult + Sync) {
        self.running
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let start = Instant::now();

        while start.elapsed() < duration && self.running.load(std::sync::atomic::Ordering::SeqCst) {
            self.fuzz_iteration(&target);
        }

        self.running
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    /// Run single fuzzing iteration
    pub fn fuzz_iteration(&self, target: &impl Fn(&[u8]) -> FuzzResult) {
        // Get input (from corpus or generate new)
        let input = if let Some(base) = self.corpus.get_random() {
            self.mutate_input(&base)
        } else {
            self.generate_input()
        };

        // Execute target
        let result = target(&input.data);

        // Update stats
        {
            let mut stats = self.stats.write().unwrap();
            stats.total_executions += 1;
            stats.corpus_size = self.corpus.size();
            stats.coverage_edges = self.corpus.coverage_count();
            stats.running_time_secs = current_timestamp() - stats.start_time;
            if stats.running_time_secs > 0 {
                stats.executions_per_second =
                    stats.total_executions as f64 / stats.running_time_secs as f64;
            }
        }

        // Handle result
        match result {
            FuzzResult::Ok(coverage) => {
                let mut input_with_coverage = input.clone();
                input_with_coverage.coverage_hash = coverage.hash();

                if self.corpus.add(input_with_coverage, &coverage) {
                    let mut stats = self.stats.write().unwrap();
                    stats.last_new_coverage = current_timestamp();
                }
            }
            FuzzResult::Crash(crash_type, message) => {
                self.handle_crash(input, crash_type, message);
            }
            FuzzResult::Timeout => {
                self.handle_crash(input, CrashType::Timeout, "Execution timeout".to_string());
            }
        }
    }

    /// Generate new random input
    fn generate_input(&self) -> FuzzInput {
        let size = self.next_random() as usize % self.config.max_input_size.max(1) + 1;
        let mut data = Vec::with_capacity(size);
        for _ in 0..size {
            data.push(self.next_random() as u8);
        }
        FuzzInput::new(data)
    }

    /// Mutate an existing input
    fn mutate_input(&self, base: &FuzzInput) -> FuzzInput {
        let mutation = match self.config.strategy {
            FuzzStrategy::Random => self.random_mutation(base.data.len()),
            FuzzStrategy::BitFlip => self.bitflip_mutation(base.data.len()),
            FuzzStrategy::Arithmetic => self.arithmetic_mutation(base.data.len()),
            FuzzStrategy::Dictionary => self.dictionary_mutation(base.data.len()),
            FuzzStrategy::CoverageGuided | FuzzStrategy::Hybrid => {
                // Mix of strategies
                match self.next_random() % 4 {
                    0 => self.bitflip_mutation(base.data.len()),
                    1 => self.arithmetic_mutation(base.data.len()),
                    2 => self.dictionary_mutation(base.data.len()),
                    _ => self.random_mutation(base.data.len()),
                }
            }
            FuzzStrategy::Grammar => {
                // Would use grammar rules
                self.random_mutation(base.data.len())
            }
        };

        base.mutate(mutation)
    }

    fn random_mutation(&self, len: usize) -> Mutation {
        if len == 0 {
            return Mutation::ByteInsert {
                offset: 0,
                value: self.next_random() as u8,
            };
        }
        let offset = self.next_random() as usize % len;
        Mutation::ByteSet {
            offset,
            value: self.next_random() as u8,
        }
    }

    fn bitflip_mutation(&self, len: usize) -> Mutation {
        if len == 0 {
            return Mutation::ByteInsert {
                offset: 0,
                value: 0,
            };
        }
        Mutation::BitFlip {
            offset: self.next_random() as usize % len,
            bit: (self.next_random() % 8) as u8,
        }
    }

    fn arithmetic_mutation(&self, len: usize) -> Mutation {
        if len == 0 {
            return Mutation::ByteInsert {
                offset: 0,
                value: 0,
            };
        }
        let delta = (self.next_random() % 70) as i32 - 35;
        Mutation::Arithmetic {
            offset: self.next_random() as usize % len,
            delta,
            size: 1,
        }
    }

    fn dictionary_mutation(&self, len: usize) -> Mutation {
        if self.config.dictionary.is_empty() {
            return self.random_mutation(len);
        }
        let idx = self.next_random() as usize % self.config.dictionary.len();
        let value = self.config.dictionary[idx].clone();
        Mutation::Interesting {
            offset: if len > 0 {
                self.next_random() as usize % len
            } else {
                0
            },
            value,
        }
    }

    /// Handle a crash
    fn handle_crash(&self, input: FuzzInput, crash_type: CrashType, message: String) {
        // Deduplicate by crash hash
        let crash_hash = self.calculate_crash_hash(&input, crash_type);

        {
            let mut hashes = self.crash_hashes.write().unwrap();
            if hashes.contains(&crash_hash) {
                let mut stats = self.stats.write().unwrap();
                stats.total_crashes += 1;
                return;
            }
            hashes.insert(crash_hash);
        }

        let crash = CrashReport {
            id: format!("crash-{}", current_timestamp()),
            input,
            crash_type,
            severity: crash_type.severity(),
            message,
            stack_trace: None,
            memory_address: None,
            discovered_at: current_timestamp(),
            minimized: false,
            deduplicated: true,
        };

        {
            let mut crashes = self.crashes.write().unwrap();
            crashes.push(crash);
        }

        {
            let mut stats = self.stats.write().unwrap();
            stats.total_crashes += 1;
            stats.unique_crashes += 1;
        }
    }

    fn calculate_crash_hash(&self, input: &FuzzInput, crash_type: CrashType) -> u64 {
        let mut hash = crash_type as u64;
        for byte in &input.data[..input.data.len().min(32)] {
            hash = hash.wrapping_mul(31).wrapping_add(*byte as u64);
        }
        hash
    }

    /// Get statistics
    pub fn get_stats(&self) -> FuzzStats {
        self.stats.read().unwrap().clone()
    }

    /// Get unique crashes
    pub fn get_crashes(&self) -> Vec<CrashReport> {
        self.crashes.read().unwrap().clone()
    }

    /// Stop fuzzing
    pub fn stop(&self) {
        self.running
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    fn next_random(&self) -> u64 {
        let state = self
            .rng_state
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        simple_rng(state.wrapping_add(current_timestamp()))
    }
}

/// Fuzz execution result
pub enum FuzzResult {
    Ok(Coverage),
    Crash(CrashType, String),
    Timeout,
}

// Helper functions

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn simple_rng(seed: u64) -> u64 {
    seed.wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407)
}

fn main() {
    println!("=== Fuzzing Harness ===\n");

    // Create fuzzer configuration
    let config = FuzzConfig {
        strategy: FuzzStrategy::CoverageGuided,
        max_input_size: 1024,
        timeout: Duration::from_millis(100),
        max_corpus_size: 1000,
        ..Default::default()
    };

    // Create fuzzer
    let fuzzer = Fuzzer::new(config);

    // Seed initial corpus
    fuzzer.seed_corpus(vec![
        b"test".to_vec(),
        b"hello".to_vec(),
        b"\x00\x00\x00\x00".to_vec(),
        b"AAAA".to_vec(),
    ]);

    // Define target function
    let target = |data: &[u8]| -> FuzzResult {
        // Simulated vulnerable function
        if data.len() >= 4
            && data[0] == b'B'
            && data[1] == b'U'
            && data[2] == b'G'
            && data[3] == b'!'
        {
            return FuzzResult::Crash(CrashType::Panic, "Found magic sequence!".to_string());
        }

        if data.len() > 100 && data.iter().all(|b| *b == 0xFF) {
            return FuzzResult::Crash(CrashType::HeapOverflow, "Buffer overflow".to_string());
        }

        // Return coverage (simulated)
        let mut coverage = Coverage::default();
        for (i, b) in data.iter().enumerate().take(10) {
            let edge = (i as u64) << 8 | (*b as u64);
            coverage.edges_hit.insert(edge);
        }
        FuzzResult::Ok(coverage)
    };

    // Run fuzzing
    println!("--- Running Fuzzer (5 seconds) ---");
    fuzzer.fuzz_for(Duration::from_secs(5), target);

    // Print statistics
    println!("\n--- Fuzzing Statistics ---");
    let stats = fuzzer.get_stats();
    println!("Total executions: {}", stats.total_executions);
    println!("Executions/sec: {:.2}", stats.executions_per_second);
    println!("Corpus size: {}", stats.corpus_size);
    println!("Coverage edges: {}", stats.coverage_edges);
    println!("Unique crashes: {}", stats.unique_crashes);
    println!("Total crashes: {}", stats.total_crashes);

    // Print crashes
    println!("\n--- Crashes Found ---");
    for crash in fuzzer.get_crashes() {
        println!(
            "[{:?}] {:?}: {} (input size: {} bytes)",
            crash.severity,
            crash.crash_type,
            crash.message,
            crash.input.data.len()
        );
    }

    // Demonstrate mutations
    println!("\n--- Mutation Examples ---");
    let input = FuzzInput::new(b"Hello, World!".to_vec());

    let mutations = vec![
        Mutation::BitFlip { offset: 0, bit: 0 },
        Mutation::ByteSet {
            offset: 5,
            value: b'_',
        },
        Mutation::ChunkInsert {
            offset: 5,
            data: b"XXX".to_vec(),
        },
        Mutation::Arithmetic {
            offset: 0,
            delta: 1,
            size: 1,
        },
    ];

    for mutation in mutations {
        let mutated = input.mutate(mutation.clone());
        println!(
            "{:?}: {:?} -> {:?}",
            mutation,
            String::from_utf8_lossy(&input.data),
            String::from_utf8_lossy(&mutated.data)
        );
    }

    println!("\n=== Fuzzing Complete ===");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bit_flip_mutation() {
        let mut data = vec![0b00000001];
        let mutation = Mutation::BitFlip { offset: 0, bit: 0 };
        mutation.apply(&mut data);
        assert_eq!(data[0], 0b00000000);
    }

    #[test]
    fn test_byte_insert_mutation() {
        let mut data = vec![1, 2, 3];
        let mutation = Mutation::ByteInsert {
            offset: 1,
            value: 99,
        };
        mutation.apply(&mut data);
        assert_eq!(data, vec![1, 99, 2, 3]);
    }

    #[test]
    fn test_chunk_delete_mutation() {
        let mut data = vec![1, 2, 3, 4, 5];
        let mutation = Mutation::ChunkDelete {
            offset: 1,
            length: 2,
        };
        mutation.apply(&mut data);
        assert_eq!(data, vec![1, 4, 5]);
    }

    #[test]
    fn test_fuzz_input_mutate() {
        let input = FuzzInput::new(vec![1, 2, 3]);
        let mutated = input.mutate(Mutation::ByteFlip { offset: 0 });

        assert_ne!(input.data, mutated.data);
        assert_eq!(mutated.parent_id, Some(input.id));
        assert_eq!(mutated.generation, input.generation + 1);
    }

    #[test]
    fn test_corpus_add_new_coverage() {
        let corpus = Corpus::new(PathBuf::from("/tmp/corpus"), 100);

        let input = FuzzInput::new(vec![1, 2, 3]);
        let mut coverage = Coverage::default();
        coverage.edges_hit.insert(1);
        coverage.edges_hit.insert(2);

        assert!(corpus.add(input, &coverage));
        assert_eq!(corpus.size(), 1);
        assert_eq!(corpus.coverage_count(), 2);
    }

    #[test]
    fn test_corpus_reject_duplicate_coverage() {
        let corpus = Corpus::new(PathBuf::from("/tmp/corpus"), 100);

        let mut coverage = Coverage::default();
        coverage.edges_hit.insert(1);

        let input1 = FuzzInput::new(vec![1]);
        let input2 = FuzzInput::new(vec![2]);

        assert!(corpus.add(input1, &coverage));
        assert!(!corpus.add(input2, &coverage)); // Same coverage
    }

    #[test]
    fn test_crash_severity() {
        assert_eq!(CrashType::UseAfterFree.severity(), CrashSeverity::Critical);
        assert_eq!(CrashType::StackOverflow.severity(), CrashSeverity::High);
        assert_eq!(CrashType::IntegerOverflow.severity(), CrashSeverity::Medium);
        assert_eq!(CrashType::Panic.severity(), CrashSeverity::Low);
    }

    #[test]
    fn test_coverage_hash() {
        let mut cov1 = Coverage::default();
        cov1.edges_hit.insert(1);
        cov1.edges_hit.insert(2);

        let mut cov2 = Coverage::default();
        cov2.edges_hit.insert(1);
        cov2.edges_hit.insert(2);

        assert_eq!(cov1.hash(), cov2.hash());
    }

    #[test]
    fn test_coverage_new_coverage() {
        let mut cov1 = Coverage::default();
        cov1.edges_hit.insert(1);

        let mut cov2 = Coverage::default();
        cov2.edges_hit.insert(1);
        cov2.edges_hit.insert(2);

        assert!(cov2.is_new_coverage(&cov1));
        assert!(!cov1.is_new_coverage(&cov2));
    }

    #[test]
    fn test_fuzzer_basic() {
        let config = FuzzConfig {
            max_corpus_size: 10,
            ..Default::default()
        };
        let fuzzer = Fuzzer::new(config);

        fuzzer.seed_corpus(vec![b"test".to_vec()]);

        let target = |_data: &[u8]| -> FuzzResult { FuzzResult::Ok(Coverage::default()) };

        fuzzer.fuzz_for(Duration::from_millis(100), target);

        let stats = fuzzer.get_stats();
        assert!(stats.total_executions > 0);
    }

    #[test]
    fn test_fuzzer_finds_crash() {
        let config = FuzzConfig::default();
        let fuzzer = Fuzzer::new(config);

        fuzzer.seed_corpus(vec![b"BUG!".to_vec()]);

        let target = |data: &[u8]| -> FuzzResult {
            if data.starts_with(b"BUG!") {
                FuzzResult::Crash(CrashType::Panic, "Found bug".to_string())
            } else {
                FuzzResult::Ok(Coverage::default())
            }
        };

        fuzzer.fuzz_for(Duration::from_millis(100), target);

        let stats = fuzzer.get_stats();
        assert!(stats.unique_crashes >= 1);
    }

    #[test]
    fn test_dictionary_entries() {
        let dict = FuzzConfig::default_dictionary();
        assert!(!dict.is_empty());
        assert!(dict.contains(&vec![0x00]));
        assert!(dict.contains(&vec![0xFF]));
    }
}
