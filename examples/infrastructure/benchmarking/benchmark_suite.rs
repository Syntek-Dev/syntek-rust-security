//! Benchmark Suite - Performance Testing Infrastructure
//!
//! This example demonstrates building a comprehensive benchmark framework
//! with statistical analysis, comparison reporting, and regression detection.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Benchmark result
#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    pub name: String,
    pub iterations: u64,
    pub total_time: Duration,
    pub mean: Duration,
    pub median: Duration,
    pub min: Duration,
    pub max: Duration,
    pub std_dev: Duration,
    pub throughput: Option<Throughput>,
    pub samples: Vec<Duration>,
}

impl BenchmarkResult {
    /// Calculate from samples
    pub fn from_samples(name: impl Into<String>, samples: Vec<Duration>) -> Self {
        let n = samples.len();
        if n == 0 {
            return Self {
                name: name.into(),
                iterations: 0,
                total_time: Duration::ZERO,
                mean: Duration::ZERO,
                median: Duration::ZERO,
                min: Duration::ZERO,
                max: Duration::ZERO,
                std_dev: Duration::ZERO,
                throughput: None,
                samples: Vec::new(),
            };
        }

        let total: Duration = samples.iter().sum();
        let mean = total / n as u32;

        let mut sorted = samples.clone();
        sorted.sort();

        let median = if n % 2 == 0 {
            (sorted[n / 2 - 1] + sorted[n / 2]) / 2
        } else {
            sorted[n / 2]
        };

        let min = *sorted.first().unwrap();
        let max = *sorted.last().unwrap();

        // Calculate standard deviation
        let mean_nanos = mean.as_nanos() as f64;
        let variance: f64 = samples
            .iter()
            .map(|s| {
                let diff = s.as_nanos() as f64 - mean_nanos;
                diff * diff
            })
            .sum::<f64>()
            / n as f64;
        let std_dev = Duration::from_nanos(variance.sqrt() as u64);

        Self {
            name: name.into(),
            iterations: n as u64,
            total_time: total,
            mean,
            median,
            min,
            max,
            std_dev,
            throughput: None,
            samples,
        }
    }

    /// Add throughput measurement
    pub fn with_throughput(mut self, throughput: Throughput) -> Self {
        self.throughput = Some(throughput);
        self
    }

    /// Calculate coefficient of variation
    pub fn coefficient_of_variation(&self) -> f64 {
        if self.mean.as_nanos() == 0 {
            return 0.0;
        }
        (self.std_dev.as_nanos() as f64 / self.mean.as_nanos() as f64) * 100.0
    }

    /// Calculate percentile
    pub fn percentile(&self, p: f64) -> Duration {
        if self.samples.is_empty() {
            return Duration::ZERO;
        }
        let mut sorted = self.samples.clone();
        sorted.sort();
        let idx = ((p / 100.0) * (sorted.len() - 1) as f64) as usize;
        sorted[idx.min(sorted.len() - 1)]
    }
}

/// Throughput measurement
#[derive(Debug, Clone)]
pub struct Throughput {
    pub value: f64,
    pub unit: ThroughputUnit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThroughputUnit {
    BytesPerSecond,
    KiloBytesPerSecond,
    MegaBytesPerSecond,
    GigaBytesPerSecond,
    ElementsPerSecond,
    OperationsPerSecond,
}

impl Throughput {
    pub fn bytes_per_sec(bytes: u64, duration: Duration) -> Self {
        let bps = bytes as f64 / duration.as_secs_f64();
        Self {
            value: bps,
            unit: ThroughputUnit::BytesPerSecond,
        }
    }

    pub fn ops_per_sec(ops: u64, duration: Duration) -> Self {
        let ops_s = ops as f64 / duration.as_secs_f64();
        Self {
            value: ops_s,
            unit: ThroughputUnit::OperationsPerSecond,
        }
    }

    pub fn format(&self) -> String {
        match self.unit {
            ThroughputUnit::BytesPerSecond => {
                if self.value >= 1_000_000_000.0 {
                    format!("{:.2} GB/s", self.value / 1_000_000_000.0)
                } else if self.value >= 1_000_000.0 {
                    format!("{:.2} MB/s", self.value / 1_000_000.0)
                } else if self.value >= 1_000.0 {
                    format!("{:.2} KB/s", self.value / 1_000.0)
                } else {
                    format!("{:.2} B/s", self.value)
                }
            }
            ThroughputUnit::OperationsPerSecond => {
                if self.value >= 1_000_000.0 {
                    format!("{:.2}M ops/s", self.value / 1_000_000.0)
                } else if self.value >= 1_000.0 {
                    format!("{:.2}K ops/s", self.value / 1_000.0)
                } else {
                    format!("{:.2} ops/s", self.value)
                }
            }
            _ => format!("{:.2} units/s", self.value),
        }
    }
}

/// Benchmark configuration
#[derive(Debug, Clone)]
pub struct BenchmarkConfig {
    /// Warmup iterations
    pub warmup_iterations: u32,
    /// Measurement iterations
    pub measurement_iterations: u32,
    /// Minimum measurement time
    pub min_measurement_time: Duration,
    /// Maximum measurement time
    pub max_measurement_time: Duration,
    /// Sample size for statistical analysis
    pub sample_size: u32,
    /// Confidence level (e.g., 0.95)
    pub confidence_level: f64,
    /// Enable outlier detection
    pub detect_outliers: bool,
    /// Outlier threshold (IQR multiplier)
    pub outlier_threshold: f64,
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        Self {
            warmup_iterations: 3,
            measurement_iterations: 100,
            min_measurement_time: Duration::from_millis(100),
            max_measurement_time: Duration::from_secs(10),
            sample_size: 100,
            confidence_level: 0.95,
            detect_outliers: true,
            outlier_threshold: 1.5,
        }
    }
}

/// Benchmark group for comparing related benchmarks
#[derive(Debug)]
pub struct BenchmarkGroup {
    pub name: String,
    pub benchmarks: Vec<Benchmark>,
    pub config: BenchmarkConfig,
    pub baseline: Option<String>,
}

impl BenchmarkGroup {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            benchmarks: Vec::new(),
            config: BenchmarkConfig::default(),
            baseline: None,
        }
    }

    pub fn with_config(mut self, config: BenchmarkConfig) -> Self {
        self.config = config;
        self
    }

    pub fn baseline(mut self, name: impl Into<String>) -> Self {
        self.baseline = Some(name.into());
        self
    }

    pub fn bench(&mut self, name: impl Into<String>, f: impl Fn() + 'static) {
        self.benchmarks.push(Benchmark {
            name: name.into(),
            function: Box::new(f),
        });
    }

    pub fn bench_with_input<I: Clone + 'static>(
        &mut self,
        name: impl Into<String>,
        input: I,
        f: impl Fn(&I) + 'static,
    ) {
        let input = input.clone();
        self.benchmarks.push(Benchmark {
            name: name.into(),
            function: Box::new(move || f(&input)),
        });
    }

    /// Run all benchmarks in the group
    pub fn run(&self) -> GroupReport {
        let mut results = HashMap::new();

        for bench in &self.benchmarks {
            let result = self.run_benchmark(bench);
            results.insert(bench.name.clone(), result);
        }

        let comparisons = self.compute_comparisons(&results);

        GroupReport {
            name: self.name.clone(),
            results,
            comparisons,
            baseline: self.baseline.clone(),
        }
    }

    fn run_benchmark(&self, bench: &Benchmark) -> BenchmarkResult {
        // Warmup
        for _ in 0..self.config.warmup_iterations {
            (bench.function)();
        }

        // Measure
        let mut samples = Vec::with_capacity(self.config.sample_size as usize);
        let measurement_start = Instant::now();

        while samples.len() < self.config.sample_size as usize
            && measurement_start.elapsed() < self.config.max_measurement_time
        {
            let start = Instant::now();
            for _ in 0..self.config.measurement_iterations {
                (bench.function)();
            }
            let elapsed = start.elapsed() / self.config.measurement_iterations;
            samples.push(elapsed);
        }

        // Remove outliers if enabled
        let samples = if self.config.detect_outliers {
            self.remove_outliers(samples)
        } else {
            samples
        };

        BenchmarkResult::from_samples(&bench.name, samples)
    }

    fn remove_outliers(&self, mut samples: Vec<Duration>) -> Vec<Duration> {
        if samples.len() < 4 {
            return samples;
        }

        samples.sort();
        let q1_idx = samples.len() / 4;
        let q3_idx = (samples.len() * 3) / 4;
        let q1 = samples[q1_idx].as_nanos() as f64;
        let q3 = samples[q3_idx].as_nanos() as f64;
        let iqr = q3 - q1;

        let lower = q1 - self.config.outlier_threshold * iqr;
        let upper = q3 + self.config.outlier_threshold * iqr;

        samples
            .into_iter()
            .filter(|s| {
                let nanos = s.as_nanos() as f64;
                nanos >= lower && nanos <= upper
            })
            .collect()
    }

    fn compute_comparisons(&self, results: &HashMap<String, BenchmarkResult>) -> Vec<Comparison> {
        let baseline_name = self.baseline.as_ref();
        let baseline = baseline_name.and_then(|n| results.get(n));

        if baseline.is_none() {
            return Vec::new();
        }

        let baseline = baseline.unwrap();
        let mut comparisons = Vec::new();

        for (name, result) in results {
            if Some(name) == baseline_name {
                continue;
            }

            let speedup = baseline.mean.as_nanos() as f64 / result.mean.as_nanos() as f64;
            let diff_percent = ((result.mean.as_nanos() as f64 - baseline.mean.as_nanos() as f64)
                / baseline.mean.as_nanos() as f64)
                * 100.0;

            comparisons.push(Comparison {
                name: name.clone(),
                baseline_name: baseline.name.clone(),
                speedup,
                diff_percent,
                is_regression: speedup < 0.95, // 5% slower = regression
                is_improvement: speedup > 1.05, // 5% faster = improvement
            });
        }

        comparisons
    }
}

/// Single benchmark
pub struct Benchmark {
    pub name: String,
    pub function: Box<dyn Fn()>,
}

impl std::fmt::Debug for Benchmark {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Benchmark")
            .field("name", &self.name)
            .finish()
    }
}

/// Comparison between benchmark and baseline
#[derive(Debug, Clone)]
pub struct Comparison {
    pub name: String,
    pub baseline_name: String,
    pub speedup: f64,
    pub diff_percent: f64,
    pub is_regression: bool,
    pub is_improvement: bool,
}

/// Report for a benchmark group
#[derive(Debug)]
pub struct GroupReport {
    pub name: String,
    pub results: HashMap<String, BenchmarkResult>,
    pub comparisons: Vec<Comparison>,
    pub baseline: Option<String>,
}

impl GroupReport {
    /// Format as table
    pub fn format_table(&self) -> String {
        let mut output = String::new();
        output.push_str(&format!("\n{}\n", self.name));
        output.push_str(&"=".repeat(self.name.len()));
        output.push('\n');
        output.push_str(&format!(
            "{:<30} {:>15} {:>15} {:>15} {:>10}\n",
            "Benchmark", "Mean", "Min", "Max", "Std Dev"
        ));
        output.push_str(&"-".repeat(85));
        output.push('\n');

        for (name, result) in &self.results {
            output.push_str(&format!(
                "{:<30} {:>15} {:>15} {:>15} {:>10}\n",
                name,
                format_duration(result.mean),
                format_duration(result.min),
                format_duration(result.max),
                format_duration(result.std_dev),
            ));
        }

        if !self.comparisons.is_empty() {
            output.push_str("\nComparisons:\n");
            for comp in &self.comparisons {
                let indicator = if comp.is_improvement {
                    "↑"
                } else if comp.is_regression {
                    "↓"
                } else {
                    "≈"
                };
                output.push_str(&format!(
                    "  {} vs {}: {:.2}x ({:+.1}%) {}\n",
                    comp.name, comp.baseline_name, comp.speedup, comp.diff_percent, indicator
                ));
            }
        }

        output
    }

    /// Export as JSON
    pub fn to_json(&self) -> String {
        let mut json = String::from("{\n");
        json.push_str(&format!("  \"name\": \"{}\",\n", self.name));
        json.push_str("  \"results\": {\n");

        let results: Vec<_> = self.results.iter().collect();
        for (i, (name, result)) in results.iter().enumerate() {
            json.push_str(&format!("    \"{}\": {{\n", name));
            json.push_str(&format!("      \"mean_ns\": {},\n", result.mean.as_nanos()));
            json.push_str(&format!("      \"min_ns\": {},\n", result.min.as_nanos()));
            json.push_str(&format!("      \"max_ns\": {},\n", result.max.as_nanos()));
            json.push_str(&format!(
                "      \"std_dev_ns\": {},\n",
                result.std_dev.as_nanos()
            ));
            json.push_str(&format!("      \"iterations\": {}\n", result.iterations));
            json.push_str("    }");
            if i < results.len() - 1 {
                json.push(',');
            }
            json.push('\n');
        }

        json.push_str("  }\n");
        json.push_str("}\n");
        json
    }
}

/// Benchmark runner for running multiple groups
pub struct BenchmarkRunner {
    groups: Vec<BenchmarkGroup>,
    config: BenchmarkConfig,
}

impl BenchmarkRunner {
    pub fn new() -> Self {
        Self {
            groups: Vec::new(),
            config: BenchmarkConfig::default(),
        }
    }

    pub fn with_config(mut self, config: BenchmarkConfig) -> Self {
        self.config = config;
        self
    }

    pub fn add_group(&mut self, group: BenchmarkGroup) {
        self.groups.push(group);
    }

    pub fn run(&self) -> Vec<GroupReport> {
        self.groups.iter().map(|g| g.run()).collect()
    }
}

impl Default for BenchmarkRunner {
    fn default() -> Self {
        Self::new()
    }
}

/// Regression detector
pub struct RegressionDetector {
    baseline_results: HashMap<String, BenchmarkResult>,
    threshold_percent: f64,
}

impl RegressionDetector {
    pub fn new(threshold_percent: f64) -> Self {
        Self {
            baseline_results: HashMap::new(),
            threshold_percent,
        }
    }

    /// Load baseline from previous run
    pub fn load_baseline(&mut self, results: HashMap<String, BenchmarkResult>) {
        self.baseline_results = results;
    }

    /// Check for regressions
    pub fn check(&self, current: &HashMap<String, BenchmarkResult>) -> Vec<Regression> {
        let mut regressions = Vec::new();

        for (name, current_result) in current {
            if let Some(baseline) = self.baseline_results.get(name) {
                let diff_percent = ((current_result.mean.as_nanos() as f64
                    - baseline.mean.as_nanos() as f64)
                    / baseline.mean.as_nanos() as f64)
                    * 100.0;

                if diff_percent > self.threshold_percent {
                    regressions.push(Regression {
                        benchmark_name: name.clone(),
                        baseline_mean: baseline.mean,
                        current_mean: current_result.mean,
                        diff_percent,
                    });
                }
            }
        }

        regressions
    }
}

#[derive(Debug, Clone)]
pub struct Regression {
    pub benchmark_name: String,
    pub baseline_mean: Duration,
    pub current_mean: Duration,
    pub diff_percent: f64,
}

// Helper functions

fn format_duration(d: Duration) -> String {
    let nanos = d.as_nanos();
    if nanos >= 1_000_000_000 {
        format!("{:.2} s", d.as_secs_f64())
    } else if nanos >= 1_000_000 {
        format!("{:.2} ms", nanos as f64 / 1_000_000.0)
    } else if nanos >= 1_000 {
        format!("{:.2} µs", nanos as f64 / 1_000.0)
    } else {
        format!("{} ns", nanos)
    }
}

fn main() {
    println!("=== Benchmark Suite ===\n");

    // Create benchmark configuration
    let config = BenchmarkConfig {
        warmup_iterations: 3,
        measurement_iterations: 100,
        sample_size: 50,
        ..Default::default()
    };

    // Create benchmark group
    let mut group = BenchmarkGroup::new("String Operations")
        .with_config(config)
        .baseline("vec_push");

    // Add benchmarks
    group.bench("vec_push", || {
        let mut v = Vec::new();
        for i in 0..1000 {
            v.push(i);
        }
    });

    group.bench("vec_with_capacity", || {
        let mut v = Vec::with_capacity(1000);
        for i in 0..1000 {
            v.push(i);
        }
    });

    group.bench("vec_collect", || {
        let _v: Vec<_> = (0..1000).collect();
    });

    // Run benchmarks
    println!("--- Running Benchmarks ---");
    let report = group.run();

    // Print results
    println!("{}", report.format_table());

    // Print detailed statistics
    println!("--- Detailed Statistics ---");
    for (name, result) in &report.results {
        println!("\n{}:", name);
        println!("  Iterations: {}", result.iterations);
        println!("  Mean: {}", format_duration(result.mean));
        println!("  Median: {}", format_duration(result.median));
        println!("  Min: {}", format_duration(result.min));
        println!("  Max: {}", format_duration(result.max));
        println!("  Std Dev: {}", format_duration(result.std_dev));
        println!("  CV: {:.2}%", result.coefficient_of_variation());
        println!("  P50: {}", format_duration(result.percentile(50.0)));
        println!("  P90: {}", format_duration(result.percentile(90.0)));
        println!("  P99: {}", format_duration(result.percentile(99.0)));
    }

    // Throughput example
    println!("\n--- Throughput Benchmark ---");
    let data_size = 1024 * 1024; // 1MB
    let start = Instant::now();
    let data: Vec<u8> = (0..data_size).map(|i| i as u8).collect();
    let _ = data.iter().map(|b| b.wrapping_add(1)).collect::<Vec<_>>();
    let elapsed = start.elapsed();
    let throughput = Throughput::bytes_per_sec(data_size as u64, elapsed);
    println!("Data processing: {}", throughput.format());

    // Regression detection
    println!("\n--- Regression Detection ---");
    let mut detector = RegressionDetector::new(10.0); // 10% threshold

    // Simulate baseline
    let mut baseline = HashMap::new();
    baseline.insert(
        "vec_push".to_string(),
        BenchmarkResult::from_samples("vec_push", vec![Duration::from_micros(100)]),
    );

    detector.load_baseline(baseline);

    // Check current results
    let regressions = detector.check(&report.results);
    if regressions.is_empty() {
        println!("No regressions detected!");
    } else {
        for reg in &regressions {
            println!(
                "REGRESSION: {} ({:+.1}%)",
                reg.benchmark_name, reg.diff_percent
            );
        }
    }

    // JSON export
    println!("\n--- JSON Export ---");
    let json = report.to_json();
    println!("{}", &json[..json.len().min(500)]);

    println!("\n=== Benchmark Suite Complete ===");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_benchmark_result_statistics() {
        let samples = vec![
            Duration::from_micros(100),
            Duration::from_micros(110),
            Duration::from_micros(90),
            Duration::from_micros(105),
            Duration::from_micros(95),
        ];

        let result = BenchmarkResult::from_samples("test", samples);

        assert_eq!(result.iterations, 5);
        assert_eq!(result.min, Duration::from_micros(90));
        assert_eq!(result.max, Duration::from_micros(110));
        assert_eq!(result.median, Duration::from_micros(100));
    }

    #[test]
    fn test_percentile() {
        let samples: Vec<Duration> = (1..=100).map(|i| Duration::from_micros(i)).collect();
        let result = BenchmarkResult::from_samples("test", samples);

        assert_eq!(result.percentile(50.0), Duration::from_micros(50));
        assert!(result.percentile(90.0) >= Duration::from_micros(89));
    }

    #[test]
    fn test_throughput_formatting() {
        let t1 = Throughput::bytes_per_sec(1_000_000_000, Duration::from_secs(1));
        assert!(t1.format().contains("GB/s"));

        let t2 = Throughput::bytes_per_sec(1_000_000, Duration::from_secs(1));
        assert!(t2.format().contains("MB/s"));

        let t3 = Throughput::ops_per_sec(1_000_000, Duration::from_secs(1));
        assert!(t3.format().contains("M ops/s"));
    }

    #[test]
    fn test_coefficient_of_variation() {
        let samples = vec![Duration::from_micros(100); 10]; // All same = 0 CV
        let result = BenchmarkResult::from_samples("test", samples);
        assert_eq!(result.coefficient_of_variation(), 0.0);
    }

    #[test]
    fn test_benchmark_group() {
        let mut group = BenchmarkGroup::new("Test Group");
        group.bench("bench1", || {
            let _ = 1 + 1;
        });

        assert_eq!(group.benchmarks.len(), 1);
    }

    #[test]
    fn test_comparison_detection() {
        let baseline = BenchmarkResult::from_samples("baseline", vec![Duration::from_micros(100)]);
        let faster = BenchmarkResult::from_samples("faster", vec![Duration::from_micros(80)]);
        let slower = BenchmarkResult::from_samples("slower", vec![Duration::from_micros(120)]);

        let speedup_faster = baseline.mean.as_nanos() as f64 / faster.mean.as_nanos() as f64;
        let speedup_slower = baseline.mean.as_nanos() as f64 / slower.mean.as_nanos() as f64;

        assert!(speedup_faster > 1.0); // faster is improvement
        assert!(speedup_slower < 1.0); // slower is regression
    }

    #[test]
    fn test_regression_detector() {
        let mut detector = RegressionDetector::new(10.0);

        let mut baseline = HashMap::new();
        baseline.insert(
            "test".to_string(),
            BenchmarkResult::from_samples("test", vec![Duration::from_micros(100)]),
        );
        detector.load_baseline(baseline);

        // 20% slower - should be detected
        let mut current = HashMap::new();
        current.insert(
            "test".to_string(),
            BenchmarkResult::from_samples("test", vec![Duration::from_micros(120)]),
        );

        let regressions = detector.check(&current);
        assert!(!regressions.is_empty());
    }

    #[test]
    fn test_format_duration() {
        assert!(format_duration(Duration::from_secs(1)).contains("s"));
        assert!(format_duration(Duration::from_millis(1)).contains("ms"));
        assert!(format_duration(Duration::from_micros(1)).contains("µs"));
        assert!(format_duration(Duration::from_nanos(1)).contains("ns"));
    }

    #[test]
    fn test_benchmark_config_defaults() {
        let config = BenchmarkConfig::default();
        assert_eq!(config.warmup_iterations, 3);
        assert_eq!(config.confidence_level, 0.95);
    }

    #[test]
    fn test_json_export() {
        let mut results = HashMap::new();
        results.insert(
            "test".to_string(),
            BenchmarkResult::from_samples("test", vec![Duration::from_micros(100)]),
        );

        let report = GroupReport {
            name: "Test".to_string(),
            results,
            comparisons: Vec::new(),
            baseline: None,
        };

        let json = report.to_json();
        assert!(json.contains("\"name\": \"Test\""));
        assert!(json.contains("\"test\""));
    }
}
