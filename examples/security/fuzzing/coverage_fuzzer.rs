//! Coverage-Guided Fuzzer
//!
//! A coverage-guided fuzzing framework for Rust applications.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Coverage type for fuzzing
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CoverageType {
    Edge,
    Block,
    Line,
    Branch,
    Path,
}

/// Coverage information from a single execution
#[derive(Debug, Clone, Default)]
pub struct CoverageInfo {
    pub edges_hit: HashSet<u64>,
    pub blocks_hit: HashSet<u64>,
    pub branches_taken: HashSet<(u64, bool)>,
    pub new_coverage: bool,
    pub execution_time: Duration,
}

impl CoverageInfo {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_edge(&mut self, edge_id: u64) {
        self.edges_hit.insert(edge_id);
    }

    pub fn add_block(&mut self, block_id: u64) {
        self.blocks_hit.insert(block_id);
    }

    pub fn add_branch(&mut self, branch_id: u64, taken: bool) {
        self.branches_taken.insert((branch_id, taken));
    }

    pub fn merge(&mut self, other: &CoverageInfo) {
        self.edges_hit.extend(&other.edges_hit);
        self.blocks_hit.extend(&other.blocks_hit);
        self.branches_taken.extend(&other.branches_taken);
    }

    pub fn total_coverage(&self) -> usize {
        self.edges_hit.len() + self.blocks_hit.len() + self.branches_taken.len()
    }
}

/// Mutation strategy for input generation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutationStrategy {
    BitFlip,
    ByteFlip,
    ArithmeticAdd,
    ArithmeticSub,
    InterestingValues,
    BlockDelete,
    BlockInsert,
    BlockShuffle,
    Havoc,
    Splice,
    Dictionary,
    Custom(String),
}

impl MutationStrategy {
    pub fn all() -> Vec<Self> {
        vec![
            Self::BitFlip,
            Self::ByteFlip,
            Self::ArithmeticAdd,
            Self::ArithmeticSub,
            Self::InterestingValues,
            Self::BlockDelete,
            Self::BlockInsert,
            Self::BlockShuffle,
            Self::Havoc,
            Self::Splice,
            Self::Dictionary,
        ]
    }
}

/// Mutator for generating test inputs
pub struct Mutator {
    strategies: Vec<MutationStrategy>,
    dictionary: Vec<Vec<u8>>,
    interesting_values: Vec<Vec<u8>>,
    rng_seed: u64,
}

impl Mutator {
    pub fn new() -> Self {
        let interesting_values = vec![
            vec![0x00],
            vec![0x01],
            vec![0xff],
            vec![0x7f],
            vec![0x80],
            vec![0x00, 0x00],
            vec![0xff, 0xff],
            vec![0x00, 0x00, 0x00, 0x00],
            vec![0xff, 0xff, 0xff, 0xff],
            vec![0x7f, 0xff, 0xff, 0xff],
            vec![0x80, 0x00, 0x00, 0x00],
        ];

        Self {
            strategies: MutationStrategy::all(),
            dictionary: Vec::new(),
            interesting_values,
            rng_seed: 0,
        }
    }

    pub fn add_dictionary_entry(&mut self, entry: Vec<u8>) {
        self.dictionary.push(entry);
    }

    pub fn mutate(&mut self, input: &[u8]) -> Vec<u8> {
        if input.is_empty() {
            return vec![0u8; 16];
        }

        let strategy_idx = self.next_random() as usize % self.strategies.len();
        let strategy = &self.strategies[strategy_idx];

        match strategy {
            MutationStrategy::BitFlip => self.bit_flip(input),
            MutationStrategy::ByteFlip => self.byte_flip(input),
            MutationStrategy::ArithmeticAdd => self.arithmetic_add(input),
            MutationStrategy::ArithmeticSub => self.arithmetic_sub(input),
            MutationStrategy::InterestingValues => self.insert_interesting(input),
            MutationStrategy::BlockDelete => self.block_delete(input),
            MutationStrategy::BlockInsert => self.block_insert(input),
            MutationStrategy::BlockShuffle => self.block_shuffle(input),
            MutationStrategy::Havoc => self.havoc(input),
            MutationStrategy::Splice => self.splice(input, input),
            MutationStrategy::Dictionary => self.dictionary_insert(input),
            MutationStrategy::Custom(_) => input.to_vec(),
        }
    }

    fn next_random(&mut self) -> u64 {
        // Simple LCG PRNG
        self.rng_seed = self
            .rng_seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1);
        self.rng_seed
    }

    fn bit_flip(&mut self, input: &[u8]) -> Vec<u8> {
        let mut result = input.to_vec();
        if !result.is_empty() {
            let byte_idx = self.next_random() as usize % result.len();
            let bit_idx = self.next_random() as usize % 8;
            result[byte_idx] ^= 1 << bit_idx;
        }
        result
    }

    fn byte_flip(&mut self, input: &[u8]) -> Vec<u8> {
        let mut result = input.to_vec();
        if !result.is_empty() {
            let idx = self.next_random() as usize % result.len();
            result[idx] = result[idx].wrapping_add(1);
        }
        result
    }

    fn arithmetic_add(&mut self, input: &[u8]) -> Vec<u8> {
        let mut result = input.to_vec();
        if !result.is_empty() {
            let idx = self.next_random() as usize % result.len();
            let delta = (self.next_random() % 35) as u8 + 1;
            result[idx] = result[idx].wrapping_add(delta);
        }
        result
    }

    fn arithmetic_sub(&mut self, input: &[u8]) -> Vec<u8> {
        let mut result = input.to_vec();
        if !result.is_empty() {
            let idx = self.next_random() as usize % result.len();
            let delta = (self.next_random() % 35) as u8 + 1;
            result[idx] = result[idx].wrapping_sub(delta);
        }
        result
    }

    fn insert_interesting(&mut self, input: &[u8]) -> Vec<u8> {
        let mut result = input.to_vec();
        if !self.interesting_values.is_empty() && !result.is_empty() {
            let val_idx = self.next_random() as usize % self.interesting_values.len();
            let insert_idx = self.next_random() as usize % result.len();
            let value = &self.interesting_values[val_idx];

            for (i, &byte) in value.iter().enumerate() {
                if insert_idx + i < result.len() {
                    result[insert_idx + i] = byte;
                }
            }
        }
        result
    }

    fn block_delete(&mut self, input: &[u8]) -> Vec<u8> {
        if input.len() < 2 {
            return input.to_vec();
        }

        let start = self.next_random() as usize % input.len();
        let len = self.next_random() as usize % (input.len() - start).max(1);

        let mut result = input[..start].to_vec();
        result.extend_from_slice(&input[start + len..]);
        result
    }

    fn block_insert(&mut self, input: &[u8]) -> Vec<u8> {
        let insert_len = (self.next_random() % 16) as usize + 1;
        let insert_pos = if input.is_empty() {
            0
        } else {
            self.next_random() as usize % input.len()
        };

        let mut result = input[..insert_pos].to_vec();
        for _ in 0..insert_len {
            result.push(self.next_random() as u8);
        }
        result.extend_from_slice(&input[insert_pos..]);
        result
    }

    fn block_shuffle(&mut self, input: &[u8]) -> Vec<u8> {
        if input.len() < 4 {
            return input.to_vec();
        }

        let mut result = input.to_vec();
        let block_size = (self.next_random() % 8) as usize + 1;
        let pos1 = self.next_random() as usize % (result.len() - block_size);
        let pos2 = self.next_random() as usize % (result.len() - block_size);

        for i in 0..block_size {
            if pos1 + i < result.len() && pos2 + i < result.len() {
                result.swap(pos1 + i, pos2 + i);
            }
        }
        result
    }

    fn havoc(&mut self, input: &[u8]) -> Vec<u8> {
        let mut result = input.to_vec();
        let num_mutations = (self.next_random() % 16) + 1;

        for _ in 0..num_mutations {
            result = match self.next_random() % 6 {
                0 => self.bit_flip(&result),
                1 => self.byte_flip(&result),
                2 => self.arithmetic_add(&result),
                3 => self.block_delete(&result),
                4 => self.block_insert(&result),
                _ => self.insert_interesting(&result),
            };
        }
        result
    }

    fn splice(&mut self, input1: &[u8], input2: &[u8]) -> Vec<u8> {
        if input1.is_empty() || input2.is_empty() {
            return input1.to_vec();
        }

        let split1 = self.next_random() as usize % input1.len();
        let split2 = self.next_random() as usize % input2.len();

        let mut result = input1[..split1].to_vec();
        result.extend_from_slice(&input2[split2..]);
        result
    }

    fn dictionary_insert(&mut self, input: &[u8]) -> Vec<u8> {
        if self.dictionary.is_empty() {
            return self.byte_flip(input);
        }

        let dict_idx = self.next_random() as usize % self.dictionary.len();
        let entry = self.dictionary[dict_idx].clone();

        let insert_pos = if input.is_empty() {
            0
        } else {
            self.next_random() as usize % input.len()
        };

        let mut result = input[..insert_pos].to_vec();
        result.extend_from_slice(&entry);
        result.extend_from_slice(&input[insert_pos..]);
        result
    }
}

impl Default for Mutator {
    fn default() -> Self {
        Self::new()
    }
}

/// Test case in the corpus
#[derive(Debug, Clone)]
pub struct TestCase {
    pub id: u64,
    pub input: Vec<u8>,
    pub coverage: CoverageInfo,
    pub found_at: Instant,
    pub parent_id: Option<u64>,
    pub mutation_strategy: Option<MutationStrategy>,
    pub is_crash: bool,
    pub is_timeout: bool,
    pub execution_count: u64,
}

impl TestCase {
    pub fn new(id: u64, input: Vec<u8>) -> Self {
        Self {
            id,
            input,
            coverage: CoverageInfo::new(),
            found_at: Instant::now(),
            parent_id: None,
            mutation_strategy: None,
            is_crash: false,
            is_timeout: false,
            execution_count: 0,
        }
    }

    pub fn with_coverage(mut self, coverage: CoverageInfo) -> Self {
        self.coverage = coverage;
        self
    }

    pub fn with_parent(mut self, parent_id: u64) -> Self {
        self.parent_id = Some(parent_id);
        self
    }

    pub fn mark_crash(mut self) -> Self {
        self.is_crash = true;
        self
    }

    pub fn mark_timeout(mut self) -> Self {
        self.is_timeout = true;
        self
    }
}

/// Corpus of test cases
pub struct Corpus {
    test_cases: HashMap<u64, TestCase>,
    next_id: u64,
    global_coverage: CoverageInfo,
    crashes: Vec<u64>,
    timeouts: Vec<u64>,
}

impl Corpus {
    pub fn new() -> Self {
        Self {
            test_cases: HashMap::new(),
            next_id: 0,
            global_coverage: CoverageInfo::new(),
            crashes: Vec::new(),
            timeouts: Vec::new(),
        }
    }

    pub fn add(&mut self, input: Vec<u8>, coverage: CoverageInfo) -> u64 {
        let id = self.next_id;
        self.next_id += 1;

        let is_new = self.check_new_coverage(&coverage);
        let mut tc = TestCase::new(id, input).with_coverage(coverage.clone());

        if is_new {
            self.global_coverage.merge(&coverage);
        }

        self.test_cases.insert(id, tc);
        id
    }

    pub fn add_crash(&mut self, input: Vec<u8>, coverage: CoverageInfo) -> u64 {
        let id = self.add(input, coverage);
        if let Some(tc) = self.test_cases.get_mut(&id) {
            tc.is_crash = true;
        }
        self.crashes.push(id);
        id
    }

    pub fn add_timeout(&mut self, input: Vec<u8>, coverage: CoverageInfo) -> u64 {
        let id = self.add(input, coverage);
        if let Some(tc) = self.test_cases.get_mut(&id) {
            tc.is_timeout = true;
        }
        self.timeouts.push(id);
        id
    }

    pub fn check_new_coverage(&self, coverage: &CoverageInfo) -> bool {
        !coverage
            .edges_hit
            .is_subset(&self.global_coverage.edges_hit)
            || !coverage
                .blocks_hit
                .is_subset(&self.global_coverage.blocks_hit)
            || !coverage
                .branches_taken
                .is_subset(&self.global_coverage.branches_taken)
    }

    pub fn get(&self, id: u64) -> Option<&TestCase> {
        self.test_cases.get(&id)
    }

    pub fn select_random(&self, seed: u64) -> Option<&TestCase> {
        if self.test_cases.is_empty() {
            return None;
        }

        let idx = seed as usize % self.test_cases.len();
        self.test_cases.values().nth(idx)
    }

    pub fn len(&self) -> usize {
        self.test_cases.len()
    }

    pub fn is_empty(&self) -> bool {
        self.test_cases.is_empty()
    }

    pub fn crash_count(&self) -> usize {
        self.crashes.len()
    }

    pub fn timeout_count(&self) -> usize {
        self.timeouts.len()
    }

    pub fn coverage_count(&self) -> usize {
        self.global_coverage.total_coverage()
    }
}

impl Default for Corpus {
    fn default() -> Self {
        Self::new()
    }
}

/// Fuzzer configuration
#[derive(Debug, Clone)]
pub struct FuzzerConfig {
    pub max_input_size: usize,
    pub timeout: Duration,
    pub max_iterations: u64,
    pub seed_dir: Option<PathBuf>,
    pub crash_dir: PathBuf,
    pub corpus_dir: PathBuf,
    pub dictionary: Vec<Vec<u8>>,
    pub coverage_type: CoverageType,
    pub parallel_jobs: usize,
}

impl Default for FuzzerConfig {
    fn default() -> Self {
        Self {
            max_input_size: 1024 * 1024, // 1MB
            timeout: Duration::from_secs(1),
            max_iterations: u64::MAX,
            seed_dir: None,
            crash_dir: PathBuf::from("crashes"),
            corpus_dir: PathBuf::from("corpus"),
            dictionary: Vec::new(),
            coverage_type: CoverageType::Edge,
            parallel_jobs: 1,
        }
    }
}

/// Fuzzer statistics
#[derive(Debug, Default)]
pub struct FuzzerStats {
    pub iterations: u64,
    pub corpus_size: usize,
    pub coverage: usize,
    pub crashes: usize,
    pub timeouts: usize,
    pub exec_per_sec: f64,
    pub start_time: Option<Instant>,
    pub last_new_coverage: Option<Instant>,
    pub total_execs: u64,
}

impl FuzzerStats {
    pub fn new() -> Self {
        Self {
            start_time: Some(Instant::now()),
            ..Default::default()
        }
    }

    pub fn update(&mut self, corpus: &Corpus) {
        self.corpus_size = corpus.len();
        self.coverage = corpus.coverage_count();
        self.crashes = corpus.crash_count();
        self.timeouts = corpus.timeout_count();

        if let Some(start) = self.start_time {
            let elapsed = start.elapsed().as_secs_f64();
            if elapsed > 0.0 {
                self.exec_per_sec = self.total_execs as f64 / elapsed;
            }
        }
    }

    pub fn report(&self) -> String {
        let runtime = self
            .start_time
            .map(|s| s.elapsed())
            .unwrap_or(Duration::ZERO);

        format!(
            "Fuzzer Stats:\n\
             ├─ Runtime: {:?}\n\
             ├─ Iterations: {}\n\
             ├─ Corpus size: {}\n\
             ├─ Coverage: {} edges\n\
             ├─ Crashes: {}\n\
             ├─ Timeouts: {}\n\
             └─ Exec/sec: {:.2}",
            runtime,
            self.iterations,
            self.corpus_size,
            self.coverage,
            self.crashes,
            self.timeouts,
            self.exec_per_sec
        )
    }
}

/// Target function trait
pub trait FuzzTarget {
    fn execute(&self, input: &[u8]) -> FuzzResult;
}

/// Result of fuzzing execution
#[derive(Debug)]
pub enum FuzzResult {
    Ok(CoverageInfo),
    Crash(CoverageInfo, String),
    Timeout(CoverageInfo),
    InvalidInput,
}

/// Coverage-guided fuzzer
pub struct CoverageFuzzer<T: FuzzTarget> {
    target: T,
    config: FuzzerConfig,
    corpus: Corpus,
    mutator: Mutator,
    stats: FuzzerStats,
}

impl<T: FuzzTarget> CoverageFuzzer<T> {
    pub fn new(target: T, config: FuzzerConfig) -> Self {
        let mut mutator = Mutator::new();
        for entry in &config.dictionary {
            mutator.add_dictionary_entry(entry.clone());
        }

        Self {
            target,
            config,
            corpus: Corpus::new(),
            mutator,
            stats: FuzzerStats::new(),
        }
    }

    pub fn add_seed(&mut self, input: Vec<u8>) {
        let coverage = match self.target.execute(&input) {
            FuzzResult::Ok(cov) => cov,
            FuzzResult::Crash(cov, _) => cov,
            FuzzResult::Timeout(cov) => cov,
            FuzzResult::InvalidInput => CoverageInfo::new(),
        };

        self.corpus.add(input, coverage);
    }

    pub fn fuzz_one(&mut self) -> Option<FuzzResult> {
        // Select input from corpus
        let base_input = if let Some(tc) = self.corpus.select_random(self.stats.iterations) {
            tc.input.clone()
        } else {
            vec![0u8; 16]
        };

        // Mutate input
        let mutated = self.mutator.mutate(&base_input);

        // Enforce size limit
        let input = if mutated.len() > self.config.max_input_size {
            mutated[..self.config.max_input_size].to_vec()
        } else {
            mutated
        };

        // Execute target
        let result = self.target.execute(&input);
        self.stats.total_execs += 1;

        match &result {
            FuzzResult::Ok(coverage) => {
                if self.corpus.check_new_coverage(coverage) {
                    self.corpus.add(input, coverage.clone());
                    self.stats.last_new_coverage = Some(Instant::now());
                }
            }
            FuzzResult::Crash(coverage, _) => {
                self.corpus.add_crash(input, coverage.clone());
            }
            FuzzResult::Timeout(coverage) => {
                self.corpus.add_timeout(input, coverage.clone());
            }
            FuzzResult::InvalidInput => {}
        }

        self.stats.iterations += 1;
        self.stats.update(&self.corpus);

        Some(result)
    }

    pub fn run(&mut self, max_iterations: u64) -> &FuzzerStats {
        for _ in 0..max_iterations {
            self.fuzz_one();

            // Print stats periodically
            if self.stats.iterations % 10000 == 0 {
                println!("{}", self.stats.report());
            }
        }

        &self.stats
    }

    pub fn corpus(&self) -> &Corpus {
        &self.corpus
    }

    pub fn stats(&self) -> &FuzzerStats {
        &self.stats
    }
}

/// Simple test target for demonstration
pub struct TestParserTarget;

impl FuzzTarget for TestParserTarget {
    fn execute(&self, input: &[u8]) -> FuzzResult {
        let mut coverage = CoverageInfo::new();

        // Simulate coverage tracking
        if !input.is_empty() {
            coverage.add_edge(1);

            if input[0] == b'F' {
                coverage.add_edge(2);
                if input.len() > 1 && input[1] == b'U' {
                    coverage.add_edge(3);
                    if input.len() > 2 && input[2] == b'Z' {
                        coverage.add_edge(4);
                        if input.len() > 3 && input[3] == b'Z' {
                            coverage.add_edge(5);
                            // Simulated crash
                            return FuzzResult::Crash(coverage, "Found FUZZ!".to_string());
                        }
                    }
                }
            }

            if input.len() > 100 {
                coverage.add_edge(10);
            }
        }

        FuzzResult::Ok(coverage)
    }
}

fn main() {
    println!("=== Coverage-Guided Fuzzer Demo ===\n");

    // Create fuzzer configuration
    let config = FuzzerConfig {
        max_input_size: 1024,
        timeout: Duration::from_millis(100),
        dictionary: vec![
            b"FUZZ".to_vec(),
            b"test".to_vec(),
            b"\x00\x00\x00\x00".to_vec(),
        ],
        ..Default::default()
    };

    // Create fuzzer with test target
    let target = TestParserTarget;
    let mut fuzzer = CoverageFuzzer::new(target, config);

    // Add initial seeds
    fuzzer.add_seed(b"initial".to_vec());
    fuzzer.add_seed(b"test input".to_vec());
    fuzzer.add_seed(b"F".to_vec());

    // Run fuzzer
    println!("Starting fuzzer...\n");
    let stats = fuzzer.run(100000);

    // Print final stats
    println!("\n=== Final Results ===");
    println!("{}", stats.report());

    // Print crashes
    if fuzzer.corpus().crash_count() > 0 {
        println!("\nCrashes found: {}", fuzzer.corpus().crash_count());
    }

    // Demonstrate mutator
    println!("\n=== Mutation Demo ===");
    let mut mutator = Mutator::new();
    let input = b"hello world";

    for i in 0..5 {
        let mutated = mutator.mutate(input);
        println!(
            "Mutation {}: {:?}",
            i + 1,
            String::from_utf8_lossy(&mutated)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coverage_info() {
        let mut coverage = CoverageInfo::new();
        coverage.add_edge(1);
        coverage.add_edge(2);
        coverage.add_block(1);

        assert_eq!(coverage.edges_hit.len(), 2);
        assert_eq!(coverage.blocks_hit.len(), 1);
    }

    #[test]
    fn test_coverage_merge() {
        let mut cov1 = CoverageInfo::new();
        cov1.add_edge(1);

        let mut cov2 = CoverageInfo::new();
        cov2.add_edge(2);
        cov2.add_block(1);

        cov1.merge(&cov2);

        assert_eq!(cov1.edges_hit.len(), 2);
        assert_eq!(cov1.blocks_hit.len(), 1);
    }

    #[test]
    fn test_mutator_bit_flip() {
        let mut mutator = Mutator::new();
        let input = vec![0x00, 0x00, 0x00, 0x00];

        let mutated = mutator.bit_flip(&input);

        // At least one bit should be different
        assert!(mutated != input || input.is_empty());
    }

    #[test]
    fn test_mutator_byte_flip() {
        let mut mutator = Mutator::new();
        let input = vec![0x00, 0x00];

        let mutated = mutator.byte_flip(&input);

        assert!(mutated.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_mutator_block_insert() {
        let mut mutator = Mutator::new();
        let input = vec![1, 2, 3, 4];

        let mutated = mutator.block_insert(&input);

        assert!(mutated.len() > input.len());
    }

    #[test]
    fn test_mutator_block_delete() {
        let mut mutator = Mutator::new();
        let input = vec![1, 2, 3, 4, 5];

        let mutated = mutator.block_delete(&input);

        assert!(mutated.len() <= input.len());
    }

    #[test]
    fn test_mutator_dictionary() {
        let mut mutator = Mutator::new();
        mutator.add_dictionary_entry(b"MAGIC".to_vec());

        let input = vec![0, 0, 0, 0];
        let mutated = mutator.dictionary_insert(&input);

        assert!(mutated.len() >= input.len());
    }

    #[test]
    fn test_corpus_add() {
        let mut corpus = Corpus::new();
        let input = vec![1, 2, 3];
        let coverage = CoverageInfo::new();

        let id = corpus.add(input.clone(), coverage);

        assert_eq!(corpus.len(), 1);
        assert!(corpus.get(id).is_some());
    }

    #[test]
    fn test_corpus_new_coverage() {
        let mut corpus = Corpus::new();

        let mut cov1 = CoverageInfo::new();
        cov1.add_edge(1);
        corpus.add(vec![1], cov1);

        let mut cov2 = CoverageInfo::new();
        cov2.add_edge(2);
        assert!(corpus.check_new_coverage(&cov2));

        let mut cov3 = CoverageInfo::new();
        cov3.add_edge(1);
        assert!(!corpus.check_new_coverage(&cov3));
    }

    #[test]
    fn test_corpus_crashes() {
        let mut corpus = Corpus::new();
        corpus.add_crash(vec![1], CoverageInfo::new());
        corpus.add_crash(vec![2], CoverageInfo::new());

        assert_eq!(corpus.crash_count(), 2);
    }

    #[test]
    fn test_test_case() {
        let tc = TestCase::new(1, vec![1, 2, 3]).with_parent(0).mark_crash();

        assert_eq!(tc.id, 1);
        assert_eq!(tc.parent_id, Some(0));
        assert!(tc.is_crash);
    }

    #[test]
    fn test_fuzzer_config() {
        let config = FuzzerConfig::default();

        assert!(config.max_input_size > 0);
        assert!(config.timeout > Duration::ZERO);
    }

    #[test]
    fn test_fuzzer_stats() {
        let stats = FuzzerStats::new();

        assert!(stats.start_time.is_some());
        assert_eq!(stats.iterations, 0);
    }

    #[test]
    fn test_test_parser_target() {
        let target = TestParserTarget;

        // Normal input
        let result = target.execute(b"hello");
        assert!(matches!(result, FuzzResult::Ok(_)));

        // Crash input
        let result = target.execute(b"FUZZ");
        assert!(matches!(result, FuzzResult::Crash(_, _)));
    }

    #[test]
    fn test_fuzzer_basic() {
        let config = FuzzerConfig::default();
        let target = TestParserTarget;
        let mut fuzzer = CoverageFuzzer::new(target, config);

        fuzzer.add_seed(b"test".to_vec());

        for _ in 0..100 {
            fuzzer.fuzz_one();
        }

        assert!(fuzzer.stats().iterations >= 100);
    }

    #[test]
    fn test_mutation_strategies() {
        let strategies = MutationStrategy::all();
        assert!(!strategies.is_empty());
        assert!(strategies.contains(&MutationStrategy::BitFlip));
        assert!(strategies.contains(&MutationStrategy::Havoc));
    }
}
