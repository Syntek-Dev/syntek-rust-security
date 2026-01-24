//! Property-Based Testing
//!
//! Implements property-based testing patterns for Rust using quickcheck
//! and proptest style approaches.

use std::collections::HashMap;
use std::fmt::Debug;

/// Test generator trait
pub trait Arbitrary: Clone + Debug {
    /// Generate a random value
    fn arbitrary(g: &mut Gen) -> Self;

    /// Shrink a value towards simpler cases
    fn shrink(&self) -> Box<dyn Iterator<Item = Self>>;
}

/// Random value generator
pub struct Gen {
    seed: u64,
    size: usize,
}

impl Gen {
    /// Create new generator with seed
    pub fn new(seed: u64, size: usize) -> Self {
        Self { seed, size }
    }

    /// Get current size hint
    pub fn size(&self) -> usize {
        self.size
    }

    /// Generate random u64
    pub fn gen_u64(&mut self) -> u64 {
        // Simple LCG PRNG
        self.seed = self
            .seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.seed
    }

    /// Generate random bool
    pub fn gen_bool(&mut self) -> bool {
        self.gen_u64() % 2 == 0
    }

    /// Generate random in range [0, n)
    pub fn gen_range(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        self.gen_u64() % n
    }

    /// Choose from slice
    pub fn choose<'a, T>(&mut self, slice: &'a [T]) -> Option<&'a T> {
        if slice.is_empty() {
            None
        } else {
            let idx = self.gen_range(slice.len() as u64) as usize;
            Some(&slice[idx])
        }
    }
}

// Implement Arbitrary for common types
impl Arbitrary for bool {
    fn arbitrary(g: &mut Gen) -> Self {
        g.gen_bool()
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
    fn arbitrary(g: &mut Gen) -> Self {
        g.gen_u64() as u8
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        let val = *self;
        Box::new((0..val).rev())
    }
}

impl Arbitrary for u32 {
    fn arbitrary(g: &mut Gen) -> Self {
        (g.gen_u64() % (g.size() as u64 + 1)) as u32
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        let val = *self;
        Box::new(ShrinkInt::new(val))
    }
}

impl Arbitrary for u64 {
    fn arbitrary(g: &mut Gen) -> Self {
        g.gen_u64() % (g.size() as u64 * g.size() as u64 + 1)
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        let val = *self;
        Box::new(ShrinkInt::new(val))
    }
}

impl Arbitrary for i32 {
    fn arbitrary(g: &mut Gen) -> Self {
        let u = u32::arbitrary(g);
        if g.gen_bool() {
            u as i32
        } else {
            -(u as i32)
        }
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        let val = *self;
        let shrinks: Vec<i32> = if val == 0 {
            vec![]
        } else if val > 0 {
            vec![0, val / 2, val - 1]
        } else {
            vec![0, -val, val / 2, val + 1]
        };
        Box::new(shrinks.into_iter().filter(move |&x| x.abs() < val.abs()))
    }
}

impl Arbitrary for String {
    fn arbitrary(g: &mut Gen) -> Self {
        let len = g.gen_range(g.size() as u64 + 1) as usize;
        let chars: Vec<char> = (0..len)
            .map(|_| {
                // Generate ASCII printable characters
                (32 + g.gen_range(95)) as u8 as char
            })
            .collect();
        chars.into_iter().collect()
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        let s = self.clone();
        let shrinks = vec![
            String::new(),
            s.chars().take(s.len() / 2).collect(),
            s.chars().skip(1).collect(),
            s.chars().take(s.len().saturating_sub(1)).collect(),
        ];
        Box::new(shrinks.into_iter().filter(move |x| x.len() < s.len()))
    }
}

impl<T: Arbitrary> Arbitrary for Vec<T> {
    fn arbitrary(g: &mut Gen) -> Self {
        let len = g.gen_range(g.size() as u64 + 1) as usize;
        (0..len).map(|_| T::arbitrary(g)).collect()
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        let v = self.clone();
        let mut shrinks = Vec::new();

        // Empty vector
        if !v.is_empty() {
            shrinks.push(Vec::new());
        }

        // Remove each element
        for i in 0..v.len() {
            let mut smaller = v.clone();
            smaller.remove(i);
            shrinks.push(smaller);
        }

        // Shrink each element
        for (i, elem) in v.iter().enumerate() {
            for shrunk in elem.shrink() {
                let mut new_v = v.clone();
                new_v[i] = shrunk;
                shrinks.push(new_v);
            }
        }

        Box::new(shrinks.into_iter())
    }
}

impl<T: Arbitrary> Arbitrary for Option<T> {
    fn arbitrary(g: &mut Gen) -> Self {
        if g.gen_bool() {
            Some(T::arbitrary(g))
        } else {
            None
        }
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        match self {
            None => Box::new(std::iter::empty()),
            Some(val) => {
                let shrinks = std::iter::once(None).chain(val.shrink().map(Some));
                Box::new(shrinks)
            }
        }
    }
}

/// Integer shrinking iterator
struct ShrinkInt<T> {
    value: T,
    current: T,
    done: bool,
}

impl<T: Copy + PartialOrd + From<u8> + std::ops::Div<Output = T> + std::ops::Sub<Output = T>>
    ShrinkInt<T>
{
    fn new(value: T) -> Self {
        Self {
            value,
            current: value,
            done: false,
        }
    }
}

impl<T: Copy + PartialOrd + From<u8> + std::ops::Div<Output = T> + std::ops::Sub<Output = T>>
    Iterator for ShrinkInt<T>
{
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        let zero: T = 0u8.into();
        let two: T = 2u8.into();
        let one: T = 1u8.into();

        if self.current <= zero {
            self.done = true;
            return None;
        }

        let result = self.current;

        if self.current == one {
            self.current = zero;
        } else {
            self.current = self.current / two;
        }

        if result < self.value {
            Some(result)
        } else {
            self.next()
        }
    }
}

/// Test result
#[derive(Debug, Clone)]
pub struct TestResult {
    pub success: bool,
    pub passed: u64,
    pub failed: u64,
    pub discarded: u64,
    pub failure: Option<FailureInfo>,
}

#[derive(Debug, Clone)]
pub struct FailureInfo {
    pub input: String,
    pub shrunk_input: Option<String>,
    pub error: String,
    pub seed: u64,
}

/// Property-based test configuration
#[derive(Debug, Clone)]
pub struct TestConfig {
    /// Number of test cases
    pub num_tests: u64,
    /// Maximum shrink iterations
    pub max_shrinks: u64,
    /// Initial size
    pub initial_size: usize,
    /// Maximum size
    pub max_size: usize,
    /// Random seed
    pub seed: Option<u64>,
    /// Verbose output
    pub verbose: bool,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            num_tests: 100,
            max_shrinks: 100,
            initial_size: 10,
            max_size: 100,
            seed: None,
            verbose: false,
        }
    }
}

/// Property-based test runner
pub struct TestRunner {
    config: TestConfig,
    stats: TestStats,
}

#[derive(Debug, Default, Clone)]
pub struct TestStats {
    pub tests_run: u64,
    pub tests_passed: u64,
    pub tests_failed: u64,
    pub tests_discarded: u64,
    pub total_shrinks: u64,
}

impl TestRunner {
    /// Create new test runner
    pub fn new(config: TestConfig) -> Self {
        Self {
            config,
            stats: TestStats::default(),
        }
    }

    /// Run a property test
    pub fn run<A, F>(&mut self, property: F) -> TestResult
    where
        A: Arbitrary + 'static,
        F: Fn(A) -> bool,
    {
        let seed = self.config.seed.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(42)
        });

        let mut passed = 0u64;
        let mut failed = 0u64;
        let mut discarded = 0u64;
        let mut failure = None;

        for i in 0..self.config.num_tests {
            let size = self.config.initial_size
                + (i as usize * (self.config.max_size - self.config.initial_size)
                    / self.config.num_tests as usize);

            let mut gen = Gen::new(seed.wrapping_add(i), size);
            let input = A::arbitrary(&mut gen);

            let result =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| property(input.clone())));

            match result {
                Ok(true) => {
                    passed += 1;
                    if self.config.verbose {
                        println!("Test {}: PASS", i + 1);
                    }
                }
                Ok(false) | Err(_) => {
                    failed += 1;

                    // Try to shrink
                    let (shrunk, shrink_count) = self.shrink(&input, &property);
                    self.stats.total_shrinks += shrink_count;

                    let error = match result {
                        Ok(false) => "Property returned false".to_string(),
                        Err(e) => format!("Panic: {:?}", e.downcast_ref::<&str>()),
                    };

                    failure = Some(FailureInfo {
                        input: format!("{:?}", input),
                        shrunk_input: shrunk.map(|s| format!("{:?}", s)),
                        error,
                        seed: seed.wrapping_add(i),
                    });

                    break;
                }
            }
        }

        self.stats.tests_run += passed + failed;
        self.stats.tests_passed += passed;
        self.stats.tests_failed += failed;
        self.stats.tests_discarded += discarded;

        TestResult {
            success: failed == 0,
            passed,
            failed,
            discarded,
            failure,
        }
    }

    fn shrink<A, F>(&self, input: &A, property: &F) -> (Option<A>, u64)
    where
        A: Arbitrary + 'static,
        F: Fn(A) -> bool,
    {
        let mut current = input.clone();
        let mut shrink_count = 0u64;
        let mut improved = true;

        while improved && shrink_count < self.config.max_shrinks {
            improved = false;

            for candidate in current.shrink() {
                shrink_count += 1;

                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    property(candidate.clone())
                }));

                if matches!(result, Ok(false) | Err(_)) {
                    current = candidate;
                    improved = true;
                    break;
                }

                if shrink_count >= self.config.max_shrinks {
                    break;
                }
            }
        }

        if shrink_count > 0 {
            (Some(current), shrink_count)
        } else {
            (None, 0)
        }
    }

    /// Run property test with multiple inputs
    pub fn run2<A, B, F>(&mut self, property: F) -> TestResult
    where
        A: Arbitrary + 'static,
        B: Arbitrary + 'static,
        F: Fn(A, B) -> bool,
    {
        self.run(move |(a, b): (A, B)| property(a, b))
    }

    /// Run property test with three inputs
    pub fn run3<A, B, C, F>(&mut self, property: F) -> TestResult
    where
        A: Arbitrary + 'static,
        B: Arbitrary + 'static,
        C: Arbitrary + 'static,
        F: Fn(A, B, C) -> bool,
    {
        self.run(move |(a, b, c): (A, B, C)| property(a, b, c))
    }

    /// Get statistics
    pub fn stats(&self) -> &TestStats {
        &self.stats
    }
}

// Implement Arbitrary for tuples
impl<A: Arbitrary, B: Arbitrary> Arbitrary for (A, B) {
    fn arbitrary(g: &mut Gen) -> Self {
        (A::arbitrary(g), B::arbitrary(g))
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        let (a, b) = self.clone();

        let a_shrinks = a.shrink().map({
            let b = b.clone();
            move |a| (a, b.clone())
        });

        let b_shrinks = b.shrink().map({
            let a = a.clone();
            move |b| (a.clone(), b)
        });

        Box::new(a_shrinks.chain(b_shrinks))
    }
}

impl<A: Arbitrary, B: Arbitrary, C: Arbitrary> Arbitrary for (A, B, C) {
    fn arbitrary(g: &mut Gen) -> Self {
        (A::arbitrary(g), B::arbitrary(g), C::arbitrary(g))
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        let (a, b, c) = self.clone();

        let a_shrinks = a.shrink().map({
            let b = b.clone();
            let c = c.clone();
            move |a| (a, b.clone(), c.clone())
        });

        let b_shrinks = b.shrink().map({
            let a = a.clone();
            let c = c.clone();
            move |b| (a.clone(), b, c.clone())
        });

        let c_shrinks = c.shrink().map({
            let a = a.clone();
            let b = b.clone();
            move |c| (a.clone(), b.clone(), c)
        });

        Box::new(a_shrinks.chain(b_shrinks).chain(c_shrinks))
    }
}

/// Property builder for fluent API
pub struct Property<A> {
    _phantom: std::marker::PhantomData<A>,
}

impl<A: Arbitrary + 'static> Property<A> {
    pub fn for_all() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn check<F>(self, property: F) -> TestResult
    where
        F: Fn(A) -> bool,
    {
        let mut runner = TestRunner::new(TestConfig::default());
        runner.run(property)
    }

    pub fn check_with_config<F>(self, config: TestConfig, property: F) -> TestResult
    where
        F: Fn(A) -> bool,
    {
        let mut runner = TestRunner::new(config);
        runner.run(property)
    }
}

/// Macro-like helper for defining properties
pub fn prop_assert(condition: bool) -> bool {
    condition
}

pub fn prop_assert_eq<T: PartialEq + Debug>(left: T, right: T) -> bool {
    if left == right {
        true
    } else {
        eprintln!("Assertion failed: {:?} != {:?}", left, right);
        false
    }
}

fn main() {
    println!("=== Property-Based Testing Demo ===\n");

    let config = TestConfig {
        num_tests: 100,
        verbose: false,
        ..Default::default()
    };

    let mut runner = TestRunner::new(config.clone());

    // Test 1: Addition is commutative
    println!("Test 1: Addition is commutative");
    let result = runner.run2(|a: u32, b: u32| a.wrapping_add(b) == b.wrapping_add(a));
    print_result(&result);

    // Test 2: Vec reverse twice is identity
    println!("\nTest 2: Reversing twice returns original");
    let result = runner.run(|v: Vec<u8>| {
        let mut reversed = v.clone();
        reversed.reverse();
        reversed.reverse();
        v == reversed
    });
    print_result(&result);

    // Test 3: String length after append
    println!("\nTest 3: String concatenation length");
    let result = runner.run2(|a: String, b: String| {
        let combined = format!("{}{}", a, b);
        combined.len() == a.len() + b.len()
    });
    print_result(&result);

    // Test 4: Sorting is idempotent
    println!("\nTest 4: Sorting is idempotent");
    let result = runner.run(|mut v: Vec<u32>| {
        v.sort();
        let sorted_once = v.clone();
        v.sort();
        v == sorted_once
    });
    print_result(&result);

    // Test 5: Intentional failure to show shrinking
    println!("\nTest 5: Finding minimum failing case (intentional failure)");
    let result = runner.run(|v: Vec<u32>| {
        // This property fails when vector has more than 5 elements
        v.len() <= 5
    });
    print_result(&result);

    // Test 6: Integer division property
    println!("\nTest 6: Division and multiplication (a/b)*b + a%b == a");
    let result = runner.run2(|a: u32, b: u32| {
        if b == 0 {
            return true; // Skip zero divisor
        }
        (a / b) * b + (a % b) == a
    });
    print_result(&result);

    // Show statistics
    println!("\n=== Test Statistics ===");
    let stats = runner.stats();
    println!("Total tests run: {}", stats.tests_run);
    println!("Tests passed: {}", stats.tests_passed);
    println!("Tests failed: {}", stats.tests_failed);
    println!("Total shrink iterations: {}", stats.total_shrinks);

    // Demonstrate fluent API
    println!("\n=== Fluent API Demo ===");
    let result = Property::<(u32, u32)>::for_all().check(|(a, b)| a + b >= a.min(b));
    println!(
        "a + b >= min(a, b): {}",
        if result.success { "PASS" } else { "FAIL" }
    );
}

fn print_result(result: &TestResult) {
    if result.success {
        println!("  PASS ({} tests)", result.passed);
    } else {
        println!("  FAIL after {} passes", result.passed);
        if let Some(ref failure) = result.failure {
            println!("  Original input: {}", failure.input);
            if let Some(ref shrunk) = failure.shrunk_input {
                println!("  Shrunk input: {}", shrunk);
            }
            println!("  Error: {}", failure.error);
            println!("  Seed: {}", failure.seed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gen_reproducibility() {
        let mut g1 = Gen::new(42, 10);
        let mut g2 = Gen::new(42, 10);

        for _ in 0..100 {
            assert_eq!(g1.gen_u64(), g2.gen_u64());
        }
    }

    #[test]
    fn test_arbitrary_bool() {
        let mut g = Gen::new(123, 10);
        let mut trues = 0;
        let mut falses = 0;

        for _ in 0..100 {
            if bool::arbitrary(&mut g) {
                trues += 1;
            } else {
                falses += 1;
            }
        }

        // Should have roughly even distribution
        assert!(trues > 20);
        assert!(falses > 20);
    }

    #[test]
    fn test_shrink_u32() {
        let shrinks: Vec<u32> = 100u32.shrink().collect();

        // Should shrink towards 0
        assert!(!shrinks.is_empty());
        assert!(shrinks.iter().all(|&x| x < 100));
        assert!(shrinks.contains(&50) || shrinks.contains(&25));
    }

    #[test]
    fn test_shrink_vec() {
        let v = vec![1u32, 2, 3, 4, 5];
        let shrinks: Vec<Vec<u32>> = v.shrink().take(10).collect();

        assert!(!shrinks.is_empty());
        assert!(shrinks.iter().any(|s| s.len() < v.len()));
    }

    #[test]
    fn test_property_passes() {
        let mut runner = TestRunner::new(TestConfig {
            num_tests: 50,
            ..Default::default()
        });

        let result = runner.run(|n: u32| n + 0 == n);

        assert!(result.success);
        assert_eq!(result.passed, 50);
    }

    #[test]
    fn test_property_fails_and_shrinks() {
        let mut runner = TestRunner::new(TestConfig {
            num_tests: 100,
            max_shrinks: 50,
            ..Default::default()
        });

        let result = runner.run(|n: u32| n < 10);

        assert!(!result.success);
        assert!(result.failure.is_some());

        // Should have shrunk to minimal failing case
        if let Some(ref failure) = result.failure {
            if let Some(ref shrunk) = failure.shrunk_input {
                // The shrunk value should be small (close to 10)
                assert!(
                    shrunk.contains("10")
                        || shrunk.contains("11")
                        || shrunk.contains("12")
                        || shrunk.contains("13")
                );
            }
        }
    }

    #[test]
    fn test_tuple_arbitrary() {
        let mut g = Gen::new(999, 10);
        let tuple: (u32, bool) = Arbitrary::arbitrary(&mut g);

        // Just verify it generates without panic
        let _ = tuple;
    }
}
