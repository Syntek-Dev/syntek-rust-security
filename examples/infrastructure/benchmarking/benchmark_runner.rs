//! Benchmark Runner Framework
//!
//! Performance benchmarking with statistical analysis, comparison reports,
//! and regression detection for Rust security applications.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Benchmark configuration
#[derive(Debug, Clone)]
pub struct BenchmarkConfig {
    /// Number of warmup iterations
    pub warmup_iterations: usize,
    /// Number of measurement iterations
    pub measurement_iterations: usize,
    /// Minimum time per benchmark
    pub min_time: Duration,
    /// Maximum time per benchmark
    pub max_time: Duration,
    /// Confidence level for statistical analysis (0.0-1.0)
    pub confidence_level: f64,
    /// Noise threshold for regression detection (percentage)
    pub noise_threshold: f64,
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        Self {
            warmup_iterations: 3,
            measurement_iterations: 100,
            min_time: Duration::from_millis(100),
            max_time: Duration::from_secs(5),
            confidence_level: 0.95,
            noise_threshold: 5.0, // 5% noise threshold
        }
    }
}

/// Benchmark result
#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    pub name: String,
    pub samples: Vec<Duration>,
    pub mean: Duration,
    pub median: Duration,
    pub std_dev: Duration,
    pub min: Duration,
    pub max: Duration,
    pub percentile_95: Duration,
    pub percentile_99: Duration,
    pub throughput: Option<Throughput>,
}

/// Throughput measurement
#[derive(Debug, Clone)]
pub struct Throughput {
    pub value: f64,
    pub unit: ThroughputUnit,
}

/// Throughput unit
#[derive(Debug, Clone, Copy)]
pub enum ThroughputUnit {
    BytesPerSecond,
    KilobytesPerSecond,
    MegabytesPerSecond,
    OperationsPerSecond,
    ElementsPerSecond,
}

impl ThroughputUnit {
    pub fn as_str(&self) -> &'static str {
        match self {
            ThroughputUnit::BytesPerSecond => "B/s",
            ThroughputUnit::KilobytesPerSecond => "KB/s",
            ThroughputUnit::MegabytesPerSecond => "MB/s",
            ThroughputUnit::OperationsPerSecond => "ops/s",
            ThroughputUnit::ElementsPerSecond => "elem/s",
        }
    }
}

/// Benchmark comparison
#[derive(Debug)]
pub struct Comparison {
    pub name: String,
    pub baseline: BenchmarkResult,
    pub current: BenchmarkResult,
    pub change_percent: f64,
    pub is_regression: bool,
    pub is_improvement: bool,
    pub confidence: f64,
}

/// Benchmark group
#[derive(Debug)]
pub struct BenchmarkGroup {
    name: String,
    benchmarks: Vec<Box<dyn Benchmark>>,
    config: BenchmarkConfig,
    results: Vec<BenchmarkResult>,
}

impl BenchmarkGroup {
    pub fn new(name: &str, config: BenchmarkConfig) -> Self {
        Self {
            name: name.to_string(),
            benchmarks: Vec::new(),
            config,
            results: Vec::new(),
        }
    }

    /// Add a benchmark to the group
    pub fn add<B: Benchmark + 'static>(&mut self, benchmark: B) {
        self.benchmarks.push(Box::new(benchmark));
    }

    /// Run all benchmarks
    pub fn run(&mut self) {
        self.results.clear();

        for benchmark in &self.benchmarks {
            let result = self.run_single(benchmark.as_ref());
            self.results.push(result);
        }
    }

    /// Run a single benchmark
    fn run_single(&self, benchmark: &dyn Benchmark) -> BenchmarkResult {
        // Warmup phase
        for _ in 0..self.config.warmup_iterations {
            benchmark.run();
        }

        // Measurement phase
        let mut samples = Vec::with_capacity(self.config.measurement_iterations);
        let start_time = Instant::now();

        while samples.len() < self.config.measurement_iterations
            && start_time.elapsed() < self.config.max_time
        {
            let sample_start = Instant::now();
            benchmark.run();
            let elapsed = sample_start.elapsed();
            samples.push(elapsed);
        }

        // Calculate statistics
        let mut sorted_samples = samples.clone();
        sorted_samples.sort();

        let mean = Self::calculate_mean(&samples);
        let median = sorted_samples[samples.len() / 2];
        let std_dev = Self::calculate_std_dev(&samples, mean);
        let min = *sorted_samples.first().unwrap();
        let max = *sorted_samples.last().unwrap();
        let percentile_95 = sorted_samples[(samples.len() as f64 * 0.95) as usize];
        let percentile_99 =
            sorted_samples[(samples.len() as f64 * 0.99).min(samples.len() as f64 - 1.0) as usize];

        // Calculate throughput if available
        let throughput = benchmark.throughput_size().map(|size| {
            let mean_secs = mean.as_secs_f64();
            let bytes_per_sec = size as f64 / mean_secs;

            if bytes_per_sec > 1_000_000.0 {
                Throughput {
                    value: bytes_per_sec / 1_000_000.0,
                    unit: ThroughputUnit::MegabytesPerSecond,
                }
            } else if bytes_per_sec > 1_000.0 {
                Throughput {
                    value: bytes_per_sec / 1_000.0,
                    unit: ThroughputUnit::KilobytesPerSecond,
                }
            } else {
                Throughput {
                    value: bytes_per_sec,
                    unit: ThroughputUnit::BytesPerSecond,
                }
            }
        });

        BenchmarkResult {
            name: benchmark.name().to_string(),
            samples,
            mean,
            median,
            std_dev,
            min,
            max,
            percentile_95,
            percentile_99,
            throughput,
        }
    }

    /// Calculate mean duration
    fn calculate_mean(samples: &[Duration]) -> Duration {
        let total: Duration = samples.iter().sum();
        total / samples.len() as u32
    }

    /// Calculate standard deviation
    fn calculate_std_dev(samples: &[Duration], mean: Duration) -> Duration {
        let mean_nanos = mean.as_nanos() as f64;
        let variance: f64 = samples
            .iter()
            .map(|s| {
                let diff = s.as_nanos() as f64 - mean_nanos;
                diff * diff
            })
            .sum::<f64>()
            / samples.len() as f64;

        Duration::from_nanos(variance.sqrt() as u64)
    }

    /// Get results
    pub fn results(&self) -> &[BenchmarkResult] {
        &self.results
    }

    /// Generate report
    pub fn report(&self) -> String {
        let mut output = String::new();

        output.push_str(&format!("\n=== Benchmark Group: {} ===\n\n", self.name));

        for result in &self.results {
            output.push_str(&format!("Benchmark: {}\n", result.name));
            output.push_str(&format!("  Mean:     {:?}\n", result.mean));
            output.push_str(&format!("  Median:   {:?}\n", result.median));
            output.push_str(&format!("  Std Dev:  {:?}\n", result.std_dev));
            output.push_str(&format!("  Min:      {:?}\n", result.min));
            output.push_str(&format!("  Max:      {:?}\n", result.max));
            output.push_str(&format!("  P95:      {:?}\n", result.percentile_95));
            output.push_str(&format!("  P99:      {:?}\n", result.percentile_99));

            if let Some(ref tp) = result.throughput {
                output.push_str(&format!(
                    "  Throughput: {:.2} {}\n",
                    tp.value,
                    tp.unit.as_str()
                ));
            }

            output.push('\n');
        }

        output
    }
}

/// Benchmark trait
pub trait Benchmark: Send + Sync {
    /// Benchmark name
    fn name(&self) -> &str;

    /// Run the benchmark
    fn run(&self);

    /// Optional: size for throughput calculation
    fn throughput_size(&self) -> Option<usize> {
        None
    }
}

/// Simple function benchmark
pub struct FunctionBenchmark<F>
where
    F: Fn() + Send + Sync,
{
    name: String,
    func: F,
    throughput_size: Option<usize>,
}

impl<F> FunctionBenchmark<F>
where
    F: Fn() + Send + Sync,
{
    pub fn new(name: &str, func: F) -> Self {
        Self {
            name: name.to_string(),
            func,
            throughput_size: None,
        }
    }

    pub fn with_throughput(mut self, size: usize) -> Self {
        self.throughput_size = Some(size);
        self
    }
}

impl<F> Benchmark for FunctionBenchmark<F>
where
    F: Fn() + Send + Sync,
{
    fn name(&self) -> &str {
        &self.name
    }

    fn run(&self) {
        (self.func)();
    }

    fn throughput_size(&self) -> Option<usize> {
        self.throughput_size
    }
}

/// Benchmark comparator for regression detection
#[derive(Debug)]
pub struct BenchmarkComparator {
    baseline_results: HashMap<String, BenchmarkResult>,
    noise_threshold: f64,
    confidence_level: f64,
}

impl BenchmarkComparator {
    pub fn new(noise_threshold: f64, confidence_level: f64) -> Self {
        Self {
            baseline_results: HashMap::new(),
            noise_threshold,
            confidence_level,
        }
    }

    /// Set baseline results
    pub fn set_baseline(&mut self, results: Vec<BenchmarkResult>) {
        for result in results {
            self.baseline_results.insert(result.name.clone(), result);
        }
    }

    /// Compare current results with baseline
    pub fn compare(&self, current_results: &[BenchmarkResult]) -> Vec<Comparison> {
        let mut comparisons = Vec::new();

        for current in current_results {
            if let Some(baseline) = self.baseline_results.get(&current.name) {
                let comparison = self.compare_single(baseline, current);
                comparisons.push(comparison);
            }
        }

        comparisons
    }

    /// Compare single benchmark result
    fn compare_single(&self, baseline: &BenchmarkResult, current: &BenchmarkResult) -> Comparison {
        let baseline_mean = baseline.mean.as_nanos() as f64;
        let current_mean = current.mean.as_nanos() as f64;

        let change_percent = ((current_mean - baseline_mean) / baseline_mean) * 100.0;

        // Calculate confidence using t-test approximation
        let baseline_std = baseline.std_dev.as_nanos() as f64;
        let current_std = current.std_dev.as_nanos() as f64;
        let n = baseline.samples.len().min(current.samples.len()) as f64;

        let pooled_std = ((baseline_std.powi(2) + current_std.powi(2)) / 2.0).sqrt();
        let standard_error = pooled_std * (2.0 / n).sqrt();
        let t_statistic = (current_mean - baseline_mean).abs() / standard_error;

        // Approximate confidence (simplified)
        let confidence = 1.0 - (-t_statistic / 2.0).exp();

        let is_regression =
            change_percent > self.noise_threshold && confidence > self.confidence_level;
        let is_improvement =
            change_percent < -self.noise_threshold && confidence > self.confidence_level;

        Comparison {
            name: current.name.clone(),
            baseline: baseline.clone(),
            current: current.clone(),
            change_percent,
            is_regression,
            is_improvement,
            confidence,
        }
    }

    /// Generate comparison report
    pub fn report(&self, comparisons: &[Comparison]) -> String {
        let mut output = String::new();

        output.push_str("\n=== Benchmark Comparison Report ===\n\n");

        let regressions: Vec<_> = comparisons.iter().filter(|c| c.is_regression).collect();
        let improvements: Vec<_> = comparisons.iter().filter(|c| c.is_improvement).collect();
        let unchanged: Vec<_> = comparisons
            .iter()
            .filter(|c| !c.is_regression && !c.is_improvement)
            .collect();

        output.push_str(&format!("Total Benchmarks: {}\n", comparisons.len()));
        output.push_str(&format!("Regressions: {}\n", regressions.len()));
        output.push_str(&format!("Improvements: {}\n", improvements.len()));
        output.push_str(&format!("Unchanged: {}\n\n", unchanged.len()));

        if !regressions.is_empty() {
            output.push_str("=== REGRESSIONS ===\n\n");
            for comparison in regressions {
                output.push_str(&self.format_comparison(comparison));
            }
        }

        if !improvements.is_empty() {
            output.push_str("=== IMPROVEMENTS ===\n\n");
            for comparison in improvements {
                output.push_str(&self.format_comparison(comparison));
            }
        }

        if !unchanged.is_empty() {
            output.push_str("=== UNCHANGED ===\n\n");
            for comparison in unchanged {
                output.push_str(&self.format_comparison(comparison));
            }
        }

        output
    }

    /// Format single comparison
    fn format_comparison(&self, comparison: &Comparison) -> String {
        let status = if comparison.is_regression {
            "REGRESSION"
        } else if comparison.is_improvement {
            "IMPROVEMENT"
        } else {
            "unchanged"
        };

        let change_direction = if comparison.change_percent > 0.0 {
            "slower"
        } else {
            "faster"
        };

        format!(
            "{}: {} ({:.1}% {}, confidence: {:.1}%)\n  Baseline: {:?}\n  Current:  {:?}\n\n",
            comparison.name,
            status,
            comparison.change_percent.abs(),
            change_direction,
            comparison.confidence * 100.0,
            comparison.baseline.mean,
            comparison.current.mean
        )
    }
}

/// Memory benchmark helper
#[derive(Debug)]
pub struct MemoryBenchmark {
    name: String,
    allocations: Vec<usize>,
}

impl MemoryBenchmark {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            allocations: Vec::new(),
        }
    }

    /// Record an allocation
    pub fn record_allocation(&mut self, size: usize) {
        self.allocations.push(size);
    }

    /// Get total allocations
    pub fn total_allocated(&self) -> usize {
        self.allocations.iter().sum()
    }

    /// Get allocation count
    pub fn allocation_count(&self) -> usize {
        self.allocations.len()
    }

    /// Get peak allocation
    pub fn peak_allocation(&self) -> usize {
        self.allocations.iter().max().copied().unwrap_or(0)
    }

    /// Get average allocation size
    pub fn average_allocation(&self) -> f64 {
        if self.allocations.is_empty() {
            0.0
        } else {
            self.total_allocated() as f64 / self.allocations.len() as f64
        }
    }

    /// Generate report
    pub fn report(&self) -> String {
        format!(
            "Memory Benchmark: {}\n  Total Allocated: {} bytes\n  Allocation Count: {}\n  Peak Allocation: {} bytes\n  Average Allocation: {:.1} bytes\n",
            self.name,
            self.total_allocated(),
            self.allocation_count(),
            self.peak_allocation(),
            self.average_allocation()
        )
    }
}

/// Black box function to prevent optimization
#[inline(never)]
pub fn black_box<T>(value: T) -> T {
    // Use volatile read to prevent optimization
    let result = unsafe {
        let ptr = &value as *const T;
        std::ptr::read_volatile(ptr)
    };
    std::mem::forget(value);
    result
}

fn main() {
    println!("=== Benchmark Runner Demo ===\n");

    // Create benchmark group
    let config = BenchmarkConfig {
        warmup_iterations: 2,
        measurement_iterations: 50,
        ..BenchmarkConfig::default()
    };

    let mut group = BenchmarkGroup::new("String Operations", config.clone());

    // Add benchmarks
    group.add(FunctionBenchmark::new("string_allocation", || {
        let s: String = (0..1000).map(|_| 'a').collect();
        black_box(s);
    }));

    group.add(FunctionBenchmark::new("string_concatenation", || {
        let mut s = String::new();
        for _ in 0..100 {
            s.push_str("hello");
        }
        black_box(s);
    }));

    group.add(
        FunctionBenchmark::new("vec_allocation", || {
            let v: Vec<u8> = (0..10000).map(|i| i as u8).collect();
            black_box(v);
        })
        .with_throughput(10000),
    );

    group.add(FunctionBenchmark::new("hash_map_insert", || {
        let mut map = HashMap::new();
        for i in 0..1000 {
            map.insert(i, i * 2);
        }
        black_box(map);
    }));

    // Run benchmarks
    println!("Running benchmarks...\n");
    group.run();

    // Print report
    println!("{}", group.report());

    // Simulate baseline comparison
    println!("=== Regression Detection Demo ===\n");

    // Create baseline results (simulated)
    let baseline_results = group.results().to_vec();

    // Create comparator
    let mut comparator = BenchmarkComparator::new(5.0, 0.95);
    comparator.set_baseline(baseline_results);

    // Run again (simulating "current" results)
    group.run();

    // Compare
    let comparisons = comparator.compare(group.results());
    println!("{}", comparator.report(&comparisons));

    // Memory benchmark demo
    println!("=== Memory Benchmark Demo ===\n");

    let mut mem_bench = MemoryBenchmark::new("allocation_test");

    // Simulate recording allocations
    for size in [64, 128, 256, 512, 1024, 2048] {
        mem_bench.record_allocation(size);
    }

    println!("{}", mem_bench.report());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_benchmark_result_statistics() {
        let samples: Vec<Duration> = vec![
            Duration::from_micros(100),
            Duration::from_micros(110),
            Duration::from_micros(105),
            Duration::from_micros(95),
            Duration::from_micros(102),
        ];

        let mean = BenchmarkGroup::calculate_mean(&samples);
        assert!(mean.as_micros() > 100 && mean.as_micros() < 110);
    }

    #[test]
    fn test_benchmark_group_run() {
        let config = BenchmarkConfig {
            warmup_iterations: 1,
            measurement_iterations: 10,
            ..BenchmarkConfig::default()
        };

        let mut group = BenchmarkGroup::new("test", config);
        group.add(FunctionBenchmark::new("simple", || {
            let _ = 1 + 1;
        }));

        group.run();

        assert_eq!(group.results().len(), 1);
        assert!(!group.results()[0].samples.is_empty());
    }

    #[test]
    fn test_benchmark_comparator() {
        let baseline = BenchmarkResult {
            name: "test".to_string(),
            samples: vec![Duration::from_micros(100); 10],
            mean: Duration::from_micros(100),
            median: Duration::from_micros(100),
            std_dev: Duration::from_micros(5),
            min: Duration::from_micros(95),
            max: Duration::from_micros(105),
            percentile_95: Duration::from_micros(104),
            percentile_99: Duration::from_micros(105),
            throughput: None,
        };

        let current = BenchmarkResult {
            name: "test".to_string(),
            samples: vec![Duration::from_micros(120); 10],
            mean: Duration::from_micros(120),
            median: Duration::from_micros(120),
            std_dev: Duration::from_micros(5),
            min: Duration::from_micros(115),
            max: Duration::from_micros(125),
            percentile_95: Duration::from_micros(124),
            percentile_99: Duration::from_micros(125),
            throughput: None,
        };

        let mut comparator = BenchmarkComparator::new(5.0, 0.5);
        comparator.set_baseline(vec![baseline]);

        let comparisons = comparator.compare(&[current]);

        assert_eq!(comparisons.len(), 1);
        assert!(comparisons[0].change_percent > 0.0); // Current is slower
    }

    #[test]
    fn test_memory_benchmark() {
        let mut bench = MemoryBenchmark::new("test");

        bench.record_allocation(100);
        bench.record_allocation(200);
        bench.record_allocation(300);

        assert_eq!(bench.total_allocated(), 600);
        assert_eq!(bench.allocation_count(), 3);
        assert_eq!(bench.peak_allocation(), 300);
        assert!((bench.average_allocation() - 200.0).abs() < 0.01);
    }

    #[test]
    fn test_throughput() {
        let bench = FunctionBenchmark::new("test", || {}).with_throughput(1024);

        assert_eq!(bench.throughput_size(), Some(1024));
    }

    #[test]
    fn test_black_box() {
        let value = 42;
        let result = black_box(value);
        assert_eq!(result, 42);
    }

    #[test]
    fn test_benchmark_report_generation() {
        let config = BenchmarkConfig {
            warmup_iterations: 1,
            measurement_iterations: 5,
            ..BenchmarkConfig::default()
        };

        let mut group = BenchmarkGroup::new("test_group", config);
        group.add(FunctionBenchmark::new("bench1", || {}));
        group.run();

        let report = group.report();
        assert!(report.contains("test_group"));
        assert!(report.contains("bench1"));
        assert!(report.contains("Mean"));
    }

    #[test]
    fn test_comparison_report_generation() {
        let baseline = BenchmarkResult {
            name: "test".to_string(),
            samples: vec![Duration::from_micros(100); 10],
            mean: Duration::from_micros(100),
            median: Duration::from_micros(100),
            std_dev: Duration::from_micros(5),
            min: Duration::from_micros(95),
            max: Duration::from_micros(105),
            percentile_95: Duration::from_micros(104),
            percentile_99: Duration::from_micros(105),
            throughput: None,
        };

        let comparator = BenchmarkComparator::new(5.0, 0.5);
        let comparison = Comparison {
            name: "test".to_string(),
            baseline: baseline.clone(),
            current: baseline.clone(),
            change_percent: 0.0,
            is_regression: false,
            is_improvement: false,
            confidence: 0.5,
        };

        let report = comparator.report(&[comparison]);
        assert!(report.contains("Benchmark Comparison Report"));
        assert!(report.contains("Unchanged"));
    }

    #[test]
    fn test_throughput_units() {
        assert_eq!(ThroughputUnit::BytesPerSecond.as_str(), "B/s");
        assert_eq!(ThroughputUnit::KilobytesPerSecond.as_str(), "KB/s");
        assert_eq!(ThroughputUnit::MegabytesPerSecond.as_str(), "MB/s");
        assert_eq!(ThroughputUnit::OperationsPerSecond.as_str(), "ops/s");
    }
}
