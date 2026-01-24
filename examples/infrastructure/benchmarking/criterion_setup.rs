//! Benchmarking with Criterion.rs Patterns
//!
//! Implements performance benchmarking patterns for Rust projects
//! using criterion-style approaches.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Benchmark configuration
#[derive(Debug, Clone)]
pub struct BenchmarkConfig {
    /// Number of warmup iterations
    pub warmup_iterations: u32,
    /// Minimum measurement time
    pub measurement_time: Duration,
    /// Sample size
    pub sample_size: u32,
    /// Confidence level (e.g., 0.95 for 95%)
    pub confidence_level: f64,
    /// Noise threshold for regression detection
    pub noise_threshold: f64,
    /// Enable outlier detection
    pub outlier_detection: bool,
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        Self {
            warmup_iterations: 10,
            measurement_time: Duration::from_secs(5),
            sample_size: 100,
            confidence_level: 0.95,
            noise_threshold: 0.02,
            outlier_detection: true,
        }
    }
}

/// Benchmark measurement
#[derive(Debug, Clone)]
pub struct Measurement {
    /// Sample times (nanoseconds)
    pub samples: Vec<u64>,
    /// Mean time
    pub mean: f64,
    /// Standard deviation
    pub std_dev: f64,
    /// Median time
    pub median: f64,
    /// Minimum time
    pub min: u64,
    /// Maximum time
    pub max: u64,
    /// Throughput (if applicable)
    pub throughput: Option<Throughput>,
    /// Number of iterations
    pub iterations: u64,
}

#[derive(Debug, Clone)]
pub struct Throughput {
    /// Elements per second
    pub elements_per_sec: f64,
    /// Bytes per second
    pub bytes_per_sec: Option<f64>,
}

/// Benchmark result
#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    /// Benchmark name
    pub name: String,
    /// Function group
    pub group: Option<String>,
    /// Measurement data
    pub measurement: Measurement,
    /// Comparison with baseline (if available)
    pub comparison: Option<Comparison>,
    /// Outliers detected
    pub outliers: OutlierStats,
}

#[derive(Debug, Clone)]
pub struct Comparison {
    /// Baseline measurement
    pub baseline: Measurement,
    /// Percent change
    pub percent_change: f64,
    /// Change direction
    pub direction: ChangeDirection,
    /// Statistical significance
    pub significant: bool,
    /// P-value
    pub p_value: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ChangeDirection {
    Improvement,
    Regression,
    NoChange,
}

#[derive(Debug, Clone, Default)]
pub struct OutlierStats {
    pub low_severe: u32,
    pub low_mild: u32,
    pub high_mild: u32,
    pub high_severe: u32,
}

/// Benchmark group for comparing multiple implementations
pub struct BenchmarkGroup {
    name: String,
    config: BenchmarkConfig,
    benchmarks: Vec<Box<dyn BenchmarkFn>>,
    results: Vec<BenchmarkResult>,
}

trait BenchmarkFn {
    fn name(&self) -> &str;
    fn run(&self, iterations: u64) -> Duration;
}

struct FnBenchmark<F> {
    name: String,
    func: F,
}

impl<F: Fn() + 'static> BenchmarkFn for FnBenchmark<F> {
    fn name(&self) -> &str {
        &self.name
    }

    fn run(&self, iterations: u64) -> Duration {
        let start = Instant::now();
        for _ in 0..iterations {
            (self.func)();
            std::hint::black_box(());
        }
        start.elapsed()
    }
}

impl BenchmarkGroup {
    /// Create new benchmark group
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            config: BenchmarkConfig::default(),
            benchmarks: Vec::new(),
            results: Vec::new(),
        }
    }

    /// Set configuration
    pub fn config(mut self, config: BenchmarkConfig) -> Self {
        self.config = config;
        self
    }

    /// Add a benchmark function
    pub fn bench_function<F>(mut self, name: &str, f: F) -> Self
    where
        F: Fn() + 'static,
    {
        self.benchmarks.push(Box::new(FnBenchmark {
            name: name.to_string(),
            func: f,
        }));
        self
    }

    /// Run all benchmarks in the group
    pub fn run(&mut self) -> &[BenchmarkResult] {
        for bench in &self.benchmarks {
            let result = self.run_single(bench.as_ref());
            self.results.push(result);
        }
        &self.results
    }

    fn run_single(&self, bench: &dyn BenchmarkFn) -> BenchmarkResult {
        // Warmup
        for _ in 0..self.config.warmup_iterations {
            bench.run(1);
        }

        // Determine iteration count
        let test_duration = bench.run(1);
        let iterations_per_sample = if test_duration.as_nanos() > 0 {
            (Duration::from_millis(10).as_nanos() / test_duration.as_nanos()).max(1) as u64
        } else {
            1000
        };

        // Collect samples
        let mut samples = Vec::with_capacity(self.config.sample_size as usize);

        for _ in 0..self.config.sample_size {
            let duration = bench.run(iterations_per_sample);
            let ns_per_iter = duration.as_nanos() as u64 / iterations_per_sample;
            samples.push(ns_per_iter);
        }

        // Calculate statistics
        let measurement = self.calculate_measurement(&samples, iterations_per_sample);
        let outliers = self.detect_outliers(&samples);

        BenchmarkResult {
            name: bench.name().to_string(),
            group: Some(self.name.clone()),
            measurement,
            comparison: None,
            outliers,
        }
    }

    fn calculate_measurement(&self, samples: &[u64], iterations: u64) -> Measurement {
        let n = samples.len() as f64;

        // Mean
        let sum: u64 = samples.iter().sum();
        let mean = sum as f64 / n;

        // Standard deviation
        let variance: f64 = samples
            .iter()
            .map(|&x| {
                let diff = x as f64 - mean;
                diff * diff
            })
            .sum::<f64>()
            / n;
        let std_dev = variance.sqrt();

        // Median
        let mut sorted = samples.to_vec();
        sorted.sort();
        let median = if sorted.len() % 2 == 0 {
            (sorted[sorted.len() / 2 - 1] + sorted[sorted.len() / 2]) as f64 / 2.0
        } else {
            sorted[sorted.len() / 2] as f64
        };

        // Min/Max
        let min = *samples.iter().min().unwrap_or(&0);
        let max = *samples.iter().max().unwrap_or(&0);

        // Throughput
        let throughput = if mean > 0.0 {
            Some(Throughput {
                elements_per_sec: 1_000_000_000.0 / mean,
                bytes_per_sec: None,
            })
        } else {
            None
        };

        Measurement {
            samples: samples.to_vec(),
            mean,
            std_dev,
            median,
            min,
            max,
            throughput,
            iterations,
        }
    }

    fn detect_outliers(&self, samples: &[u64]) -> OutlierStats {
        if samples.len() < 4 {
            return OutlierStats::default();
        }

        let mut sorted = samples.to_vec();
        sorted.sort();

        let q1_idx = sorted.len() / 4;
        let q3_idx = 3 * sorted.len() / 4;

        let q1 = sorted[q1_idx] as f64;
        let q3 = sorted[q3_idx] as f64;
        let iqr = q3 - q1;

        let low_mild = q1 - 1.5 * iqr;
        let low_severe = q1 - 3.0 * iqr;
        let high_mild = q3 + 1.5 * iqr;
        let high_severe = q3 + 3.0 * iqr;

        let mut stats = OutlierStats::default();

        for &sample in samples {
            let s = sample as f64;
            if s < low_severe {
                stats.low_severe += 1;
            } else if s < low_mild {
                stats.low_mild += 1;
            } else if s > high_severe {
                stats.high_severe += 1;
            } else if s > high_mild {
                stats.high_mild += 1;
            }
        }

        stats
    }

    /// Get results
    pub fn results(&self) -> &[BenchmarkResult] {
        &self.results
    }
}

/// Benchmark report generator
pub struct BenchmarkReport {
    results: Vec<BenchmarkResult>,
    baselines: HashMap<String, Measurement>,
}

impl BenchmarkReport {
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
            baselines: HashMap::new(),
        }
    }

    /// Add results
    pub fn add_results(&mut self, results: Vec<BenchmarkResult>) {
        self.results.extend(results);
    }

    /// Set baseline for comparison
    pub fn set_baseline(&mut self, name: &str, measurement: Measurement) {
        self.baselines.insert(name.to_string(), measurement);
    }

    /// Generate text report
    pub fn generate_text(&self) -> String {
        let mut report = String::new();
        report.push_str("=== Benchmark Report ===\n\n");

        // Group results by group name
        let mut groups: HashMap<String, Vec<&BenchmarkResult>> = HashMap::new();
        for result in &self.results {
            let group = result
                .group
                .clone()
                .unwrap_or_else(|| "default".to_string());
            groups.entry(group).or_default().push(result);
        }

        for (group_name, results) in &groups {
            report.push_str(&format!("Group: {}\n", group_name));
            report.push_str(&"-".repeat(60));
            report.push('\n');

            for result in results {
                report.push_str(&format!("  {}\n", result.name));
                report.push_str(&format!(
                    "    Mean:   {:>12.3} ns (± {:.3} ns)\n",
                    result.measurement.mean, result.measurement.std_dev
                ));
                report.push_str(&format!(
                    "    Median: {:>12.3} ns\n",
                    result.measurement.median
                ));
                report.push_str(&format!(
                    "    Range:  [{}, {}] ns\n",
                    result.measurement.min, result.measurement.max
                ));

                if let Some(ref throughput) = result.measurement.throughput {
                    report.push_str(&format!(
                        "    Throughput: {:.2} elem/s\n",
                        throughput.elements_per_sec
                    ));
                }

                let outliers = &result.outliers;
                let total_outliers = outliers.low_severe
                    + outliers.low_mild
                    + outliers.high_mild
                    + outliers.high_severe;
                if total_outliers > 0 {
                    report.push_str(&format!(
                        "    Outliers: {} ({} severe)\n",
                        total_outliers,
                        outliers.low_severe + outliers.high_severe
                    ));
                }

                if let Some(ref comparison) = result.comparison {
                    let direction = match comparison.direction {
                        ChangeDirection::Improvement => "faster",
                        ChangeDirection::Regression => "slower",
                        ChangeDirection::NoChange => "no change",
                    };
                    report.push_str(&format!(
                        "    Change: {:.2}% {} (p={:.4}{})\n",
                        comparison.percent_change.abs(),
                        direction,
                        comparison.p_value,
                        if comparison.significant { " *" } else { "" }
                    ));
                }

                report.push('\n');
            }
        }

        report
    }

    /// Generate JSON report
    pub fn generate_json(&self) -> String {
        let mut json = String::from("{\n  \"benchmarks\": [\n");

        for (i, result) in self.results.iter().enumerate() {
            if i > 0 {
                json.push_str(",\n");
            }
            json.push_str(&format!(
                r#"    {{
      "name": "{}",
      "group": {},
      "mean_ns": {:.3},
      "std_dev_ns": {:.3},
      "median_ns": {:.3},
      "min_ns": {},
      "max_ns": {},
      "samples": {}
    }}"#,
                result.name,
                result
                    .group
                    .as_ref()
                    .map(|g| format!("\"{}\"", g))
                    .unwrap_or_else(|| "null".to_string()),
                result.measurement.mean,
                result.measurement.std_dev,
                result.measurement.median,
                result.measurement.min,
                result.measurement.max,
                result.measurement.samples.len()
            ));
        }

        json.push_str("\n  ]\n}");
        json
    }
}

/// Simple benchmark runner for quick measurements
pub fn bench<F>(name: &str, iterations: u64, mut f: F) -> Duration
where
    F: FnMut(),
{
    // Warmup
    for _ in 0..10 {
        f();
    }

    // Measure
    let start = Instant::now();
    for _ in 0..iterations {
        f();
        std::hint::black_box(());
    }
    let total = start.elapsed();

    let per_iter = total / iterations as u32;
    println!(
        "{}: {:?} per iteration ({} iterations in {:?})",
        name, per_iter, iterations, total
    );

    per_iter
}

/// Black box to prevent optimization
#[inline(never)]
pub fn black_box<T>(x: T) -> T {
    std::hint::black_box(x)
}

fn main() {
    println!("=== Criterion-Style Benchmarking Demo ===\n");

    // Simple benchmark
    println!("Quick benchmarks:\n");

    bench("Vec push", 10_000, || {
        let mut v = Vec::new();
        for i in 0..100 {
            v.push(i);
        }
        black_box(v);
    });

    bench("Vec with_capacity push", 10_000, || {
        let mut v = Vec::with_capacity(100);
        for i in 0..100 {
            v.push(i);
        }
        black_box(v);
    });

    bench("String concatenation", 10_000, || {
        let mut s = String::new();
        for i in 0..100 {
            s.push_str(&i.to_string());
        }
        black_box(s);
    });

    bench("String with_capacity", 10_000, || {
        let mut s = String::with_capacity(500);
        for i in 0..100 {
            s.push_str(&i.to_string());
        }
        black_box(s);
    });

    // Benchmark group
    println!("\n=== Benchmark Group: Sorting Algorithms ===\n");

    let mut group = BenchmarkGroup::new("sorting")
        .config(BenchmarkConfig {
            sample_size: 50,
            warmup_iterations: 5,
            ..Default::default()
        })
        .bench_function("std_sort", || {
            let mut data: Vec<u32> = (0..1000).rev().collect();
            data.sort();
            black_box(data);
        })
        .bench_function("std_sort_unstable", || {
            let mut data: Vec<u32> = (0..1000).rev().collect();
            data.sort_unstable();
            black_box(data);
        })
        .bench_function("std_sort_by", || {
            let mut data: Vec<u32> = (0..1000).rev().collect();
            data.sort_by(|a, b| a.cmp(b));
            black_box(data);
        });

    let results = group.run();

    // Generate report
    let mut report = BenchmarkReport::new();
    report.add_results(results.to_vec());

    println!("{}", report.generate_text());

    // Show JSON output
    println!("=== JSON Report ===");
    println!("{}", report.generate_json());

    // Compare results
    println!("\n=== Comparison ===");
    let sorted_results: Vec<_> = results
        .iter()
        .map(|r| (&r.name, r.measurement.mean))
        .collect();

    if sorted_results.len() >= 2 {
        let (fastest_name, fastest_time) = sorted_results
            .iter()
            .min_by(|a, b| a.1.partial_cmp(&b.1).unwrap())
            .unwrap();

        println!("Fastest: {} ({:.2} ns)", fastest_name, fastest_time);

        for (name, time) in &sorted_results {
            if *name != *fastest_name {
                let slowdown = time / fastest_time;
                println!("  {} is {:.2}x slower", name, slowdown);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_measurement_calculation() {
        let config = BenchmarkConfig::default();
        let group = BenchmarkGroup::new("test");

        let samples = vec![100, 110, 105, 108, 102, 107, 103, 109, 104, 106];
        let measurement = group.calculate_measurement(&samples, 1);

        // Mean should be around 105.4
        assert!((measurement.mean - 105.4).abs() < 0.1);

        // Min/Max
        assert_eq!(measurement.min, 100);
        assert_eq!(measurement.max, 110);
    }

    #[test]
    fn test_outlier_detection() {
        let group = BenchmarkGroup::new("test");

        // Create data with outliers
        let mut samples: Vec<u64> = (100..200).collect();
        samples.push(10); // Low outlier
        samples.push(500); // High outlier

        let outliers = group.detect_outliers(&samples);

        assert!(outliers.low_severe + outliers.low_mild > 0);
        assert!(outliers.high_severe + outliers.high_mild > 0);
    }

    #[test]
    fn test_benchmark_group_creation() {
        let group = BenchmarkGroup::new("test_group").config(BenchmarkConfig {
            sample_size: 10,
            ..Default::default()
        });

        assert_eq!(group.name, "test_group");
        assert_eq!(group.config.sample_size, 10);
    }

    #[test]
    fn test_report_generation() {
        let mut report = BenchmarkReport::new();

        let result = BenchmarkResult {
            name: "test_bench".to_string(),
            group: Some("test".to_string()),
            measurement: Measurement {
                samples: vec![100, 110, 105],
                mean: 105.0,
                std_dev: 4.08,
                median: 105.0,
                min: 100,
                max: 110,
                throughput: None,
                iterations: 1000,
            },
            comparison: None,
            outliers: OutlierStats::default(),
        };

        report.add_results(vec![result]);

        let text = report.generate_text();
        assert!(text.contains("test_bench"));
        assert!(text.contains("105.0"));

        let json = report.generate_json();
        assert!(json.contains("test_bench"));
        assert!(json.contains("105.0"));
    }

    #[test]
    fn test_black_box() {
        let value = black_box(42);
        assert_eq!(value, 42);

        let string = black_box(String::from("test"));
        assert_eq!(string, "test");
    }

    #[test]
    fn test_change_direction() {
        assert_ne!(ChangeDirection::Improvement, ChangeDirection::Regression);
        assert_ne!(ChangeDirection::NoChange, ChangeDirection::Improvement);
    }
}
