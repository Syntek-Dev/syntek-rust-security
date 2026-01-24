//! Performance Profiler and Benchmarking
//!
//! This example demonstrates comprehensive performance profiling
//! and benchmarking for Rust applications, including CPU profiling,
//! memory tracking, flamegraph generation, and criterion-style
//! statistical analysis.

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

// ============================================================================
// Benchmark Types
// ============================================================================

/// Benchmark configuration
#[derive(Clone)]
pub struct BenchConfig {
    /// Number of warmup iterations
    pub warmup_iters: u32,
    /// Minimum number of samples
    pub min_samples: u32,
    /// Maximum number of samples
    pub max_samples: u32,
    /// Minimum benchmark time
    pub min_time: Duration,
    /// Maximum benchmark time
    pub max_time: Duration,
    /// Confidence level (0.0 - 1.0)
    pub confidence_level: f64,
    /// Noise threshold for significance
    pub noise_threshold: f64,
    /// Number of resamples for bootstrap
    pub resamples: u32,
}

impl Default for BenchConfig {
    fn default() -> Self {
        Self {
            warmup_iters: 3,
            min_samples: 10,
            max_samples: 100,
            min_time: Duration::from_secs(1),
            max_time: Duration::from_secs(5),
            confidence_level: 0.95,
            noise_threshold: 0.05,
            resamples: 1000,
        }
    }
}

impl BenchConfig {
    pub fn quick() -> Self {
        Self {
            warmup_iters: 1,
            min_samples: 5,
            max_samples: 20,
            min_time: Duration::from_millis(500),
            max_time: Duration::from_secs(2),
            ..Default::default()
        }
    }

    pub fn thorough() -> Self {
        Self {
            warmup_iters: 10,
            min_samples: 50,
            max_samples: 500,
            min_time: Duration::from_secs(5),
            max_time: Duration::from_secs(30),
            resamples: 10000,
            ..Default::default()
        }
    }
}

/// Benchmark measurement
#[derive(Debug, Clone)]
pub struct Measurement {
    /// Individual timing samples (nanoseconds)
    pub samples: Vec<u64>,
    /// Number of iterations per sample
    pub iters_per_sample: u64,
    /// Total benchmark time
    pub total_time: Duration,
}

/// Statistical analysis of measurements
#[derive(Debug, Clone)]
pub struct Statistics {
    /// Mean time (nanoseconds)
    pub mean: f64,
    /// Median time (nanoseconds)
    pub median: f64,
    /// Standard deviation
    pub std_dev: f64,
    /// Minimum time
    pub min: u64,
    /// Maximum time
    pub max: u64,
    /// Mean absolute deviation
    pub mad: f64,
    /// Confidence interval (lower, upper)
    pub confidence_interval: (f64, f64),
    /// Throughput (iterations per second)
    pub throughput: f64,
}

impl Statistics {
    pub fn from_samples(samples: &[u64], confidence_level: f64) -> Self {
        if samples.is_empty() {
            return Self::zero();
        }

        let mut sorted = samples.to_vec();
        sorted.sort_unstable();

        let n = samples.len();
        let mean = samples.iter().sum::<u64>() as f64 / n as f64;

        let median = if n % 2 == 0 {
            (sorted[n / 2 - 1] + sorted[n / 2]) as f64 / 2.0
        } else {
            sorted[n / 2] as f64
        };

        let variance = samples
            .iter()
            .map(|&x| {
                let diff = x as f64 - mean;
                diff * diff
            })
            .sum::<f64>()
            / n as f64;

        let std_dev = variance.sqrt();

        let mad = samples
            .iter()
            .map(|&x| (x as f64 - median).abs())
            .sum::<f64>()
            / n as f64;

        // Confidence interval using normal approximation
        let z = match confidence_level {
            l if l >= 0.99 => 2.576,
            l if l >= 0.95 => 1.96,
            l if l >= 0.90 => 1.645,
            _ => 1.0,
        };

        let margin = z * std_dev / (n as f64).sqrt();
        let confidence_interval = (mean - margin, mean + margin);

        let throughput = if mean > 0.0 {
            1_000_000_000.0 / mean
        } else {
            0.0
        };

        Self {
            mean,
            median,
            std_dev,
            min: sorted[0],
            max: sorted[n - 1],
            mad,
            confidence_interval,
            throughput,
        }
    }

    fn zero() -> Self {
        Self {
            mean: 0.0,
            median: 0.0,
            std_dev: 0.0,
            min: 0,
            max: 0,
            mad: 0.0,
            confidence_interval: (0.0, 0.0),
            throughput: 0.0,
        }
    }

    /// Format as human-readable string
    pub fn to_string(&self) -> String {
        format!(
            "mean: {}, median: {}, std_dev: ±{} ({:.1}%)",
            format_duration(self.mean as u64),
            format_duration(self.median as u64),
            format_duration(self.std_dev as u64),
            (self.std_dev / self.mean) * 100.0
        )
    }
}

/// Comparison result between two benchmarks
#[derive(Debug, Clone)]
pub struct Comparison {
    /// Baseline statistics
    pub baseline: Statistics,
    /// New statistics
    pub new: Statistics,
    /// Relative change (positive = slower, negative = faster)
    pub change: f64,
    /// Is the change statistically significant
    pub significant: bool,
    /// P-value for the test
    pub p_value: f64,
}

impl Comparison {
    pub fn compare(baseline: &Statistics, new: &Statistics, noise_threshold: f64) -> Self {
        let change = (new.mean - baseline.mean) / baseline.mean;
        let significant = change.abs() > noise_threshold;

        // Simplified p-value calculation (would use proper t-test in production)
        let p_value = if significant { 0.01 } else { 0.5 };

        Self {
            baseline: baseline.clone(),
            new: new.clone(),
            change,
            significant,
            p_value,
        }
    }

    pub fn description(&self) -> String {
        let direction = if self.change > 0.0 {
            "slower"
        } else {
            "faster"
        };
        let pct = (self.change.abs() * 100.0).round();

        if self.significant {
            format!("{:.0}% {} (significant)", pct, direction)
        } else {
            format!("{:.0}% {} (within noise)", pct, direction)
        }
    }
}

// ============================================================================
// Benchmark Runner
// ============================================================================

/// Benchmark runner
pub struct Bencher {
    config: BenchConfig,
    groups: HashMap<String, BenchGroup>,
    current_group: Option<String>,
}

/// Benchmark group
#[derive(Default)]
pub struct BenchGroup {
    benchmarks: Vec<BenchResult>,
}

/// Result of a single benchmark
#[derive(Debug, Clone)]
pub struct BenchResult {
    pub name: String,
    pub measurement: Measurement,
    pub statistics: Statistics,
    pub throughput_unit: Option<ThroughputUnit>,
}

/// Throughput unit
#[derive(Debug, Clone)]
pub struct ThroughputUnit {
    pub value: f64,
    pub unit: String,
}

impl Bencher {
    pub fn new(config: BenchConfig) -> Self {
        Self {
            config,
            groups: HashMap::new(),
            current_group: None,
        }
    }

    /// Start a benchmark group
    pub fn group(&mut self, name: &str) -> &mut Self {
        self.current_group = Some(name.to_string());
        self.groups.entry(name.to_string()).or_default();
        self
    }

    /// Run a benchmark function
    pub fn bench<F>(&mut self, name: &str, mut f: F) -> BenchResult
    where
        F: FnMut() -> (),
    {
        // Warmup
        for _ in 0..self.config.warmup_iters {
            f();
        }

        // Determine iterations per sample
        let iters = self.calibrate_iterations(&mut f);

        // Collect samples
        let mut samples = Vec::new();
        let start = Instant::now();

        while samples.len() < self.config.min_samples as usize
            || (start.elapsed() < self.config.min_time
                && samples.len() < self.config.max_samples as usize)
        {
            if start.elapsed() >= self.config.max_time {
                break;
            }

            let sample_start = Instant::now();
            for _ in 0..iters {
                f();
            }
            let sample_time = sample_start.elapsed().as_nanos() as u64 / iters;
            samples.push(sample_time);
        }

        let total_time = start.elapsed();
        let measurement = Measurement {
            samples: samples.clone(),
            iters_per_sample: iters,
            total_time,
        };

        let statistics = Statistics::from_samples(&samples, self.config.confidence_level);

        let result = BenchResult {
            name: name.to_string(),
            measurement,
            statistics,
            throughput_unit: None,
        };

        // Add to current group
        if let Some(group_name) = &self.current_group {
            if let Some(group) = self.groups.get_mut(group_name) {
                group.benchmarks.push(result.clone());
            }
        }

        result
    }

    /// Run a benchmark with throughput measurement
    pub fn bench_throughput<F>(
        &mut self,
        name: &str,
        elements: u64,
        unit: &str,
        f: F,
    ) -> BenchResult
    where
        F: FnMut() -> (),
    {
        let mut result = self.bench(name, f);

        let throughput_per_sec = (elements as f64 * 1_000_000_000.0) / result.statistics.mean;
        result.throughput_unit = Some(ThroughputUnit {
            value: throughput_per_sec,
            unit: unit.to_string(),
        });

        result
    }

    fn calibrate_iterations<F>(&self, f: &mut F) -> u64
    where
        F: FnMut() -> (),
    {
        let mut iters = 1u64;
        let target_time = Duration::from_micros(100);

        loop {
            let start = Instant::now();
            for _ in 0..iters {
                f();
            }
            let elapsed = start.elapsed();

            if elapsed >= target_time {
                return iters;
            }

            iters = (iters * 2).min(1_000_000);

            if iters >= 1_000_000 {
                return iters;
            }
        }
    }

    /// Print a summary of all benchmarks
    pub fn summarize(&self) {
        for (group_name, group) in &self.groups {
            println!("\n{}", group_name);
            println!("{}", "=".repeat(group_name.len()));

            for bench in &group.benchmarks {
                let stats = &bench.statistics;
                let time_str = format_duration(stats.mean as u64);

                print!("  {} ... {} ", bench.name, time_str);

                if let Some(throughput) = &bench.throughput_unit {
                    print!("({:.2} {}/s) ", throughput.value, throughput.unit);
                }

                println!("(± {:.1}%)", (stats.std_dev / stats.mean) * 100.0);
            }
        }
    }
}

// ============================================================================
// Memory Profiler
// ============================================================================

/// Memory profiler
pub struct MemoryProfiler {
    allocations: Vec<AllocationRecord>,
    baseline_used: usize,
}

/// Allocation record
#[derive(Debug, Clone)]
pub struct AllocationRecord {
    pub size: usize,
    pub timestamp: Instant,
    pub location: Option<String>,
}

/// Memory statistics
#[derive(Debug, Clone)]
pub struct MemoryStats {
    pub peak_usage: usize,
    pub total_allocated: usize,
    pub total_deallocated: usize,
    pub allocation_count: usize,
    pub average_allocation_size: usize,
    pub current_usage: usize,
}

impl MemoryProfiler {
    pub fn new() -> Self {
        Self {
            allocations: Vec::new(),
            baseline_used: Self::current_memory(),
        }
    }

    /// Record an allocation
    pub fn record_allocation(&mut self, size: usize, location: Option<&str>) {
        self.allocations.push(AllocationRecord {
            size,
            timestamp: Instant::now(),
            location: location.map(String::from),
        });
    }

    /// Get current memory usage (platform-specific)
    pub fn current_memory() -> usize {
        // Would use platform-specific APIs in real implementation
        // On Linux: read /proc/self/statm
        // On macOS: use mach_task_self()
        // On Windows: use GetProcessMemoryInfo()

        // Placeholder that returns a simulated value
        1024 * 1024 // 1 MB
    }

    /// Calculate memory statistics
    pub fn stats(&self) -> MemoryStats {
        let total_allocated: usize = self.allocations.iter().map(|a| a.size).sum();
        let allocation_count = self.allocations.len();
        let average = if allocation_count > 0 {
            total_allocated / allocation_count
        } else {
            0
        };

        let current = Self::current_memory();
        let peak = current.max(total_allocated);

        MemoryStats {
            peak_usage: peak,
            total_allocated,
            total_deallocated: 0, // Would track deallocations in real impl
            allocation_count,
            average_allocation_size: average,
            current_usage: current,
        }
    }

    /// Reset profiler
    pub fn reset(&mut self) {
        self.allocations.clear();
        self.baseline_used = Self::current_memory();
    }

    /// Get allocation timeline
    pub fn timeline(&self) -> Vec<(Duration, usize)> {
        if self.allocations.is_empty() {
            return vec![];
        }

        let start = self.allocations[0].timestamp;
        let mut cumulative = 0;
        let mut timeline = vec![];

        for alloc in &self.allocations {
            cumulative += alloc.size;
            timeline.push((alloc.timestamp - start, cumulative));
        }

        timeline
    }
}

impl Default for MemoryProfiler {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// CPU Profiler
// ============================================================================

/// CPU profiler with call stack sampling
pub struct CpuProfiler {
    samples: Vec<CpuSample>,
    sampling_interval: Duration,
    is_running: bool,
    start_time: Option<Instant>,
}

/// CPU sample
#[derive(Debug, Clone)]
pub struct CpuSample {
    pub timestamp: Duration,
    pub call_stack: Vec<String>,
    pub cpu_time: Duration,
}

/// Flamegraph node
#[derive(Debug, Clone)]
pub struct FlamegraphNode {
    pub name: String,
    pub self_time: u64,
    pub total_time: u64,
    pub children: HashMap<String, FlamegraphNode>,
}

impl FlamegraphNode {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            self_time: 0,
            total_time: 0,
            children: HashMap::new(),
        }
    }

    /// Add a sample to the flamegraph
    pub fn add_sample(&mut self, stack: &[String], time: u64) {
        self.total_time += time;

        if stack.is_empty() {
            self.self_time += time;
            return;
        }

        let frame = &stack[0];
        let child = self
            .children
            .entry(frame.clone())
            .or_insert_with(|| FlamegraphNode::new(frame));

        child.add_sample(&stack[1..], time);
    }

    /// Generate flamegraph lines (folded format)
    pub fn to_folded(&self, prefix: &str) -> Vec<String> {
        let mut lines = vec![];
        let current_path = if prefix.is_empty() {
            self.name.clone()
        } else {
            format!("{};{}", prefix, self.name)
        };

        if self.self_time > 0 {
            lines.push(format!("{} {}", current_path, self.self_time));
        }

        for child in self.children.values() {
            lines.extend(child.to_folded(&current_path));
        }

        lines
    }
}

impl CpuProfiler {
    pub fn new(sampling_interval: Duration) -> Self {
        Self {
            samples: Vec::new(),
            sampling_interval,
            is_running: false,
            start_time: None,
        }
    }

    pub fn start(&mut self) {
        self.is_running = true;
        self.start_time = Some(Instant::now());
        self.samples.clear();
    }

    pub fn stop(&mut self) {
        self.is_running = false;
    }

    /// Record a sample manually (for demonstration)
    pub fn record_sample(&mut self, call_stack: Vec<String>, cpu_time: Duration) {
        if let Some(start) = self.start_time {
            self.samples.push(CpuSample {
                timestamp: start.elapsed(),
                call_stack,
                cpu_time,
            });
        }
    }

    /// Generate flamegraph from samples
    pub fn generate_flamegraph(&self) -> FlamegraphNode {
        let mut root = FlamegraphNode::new("root");

        for sample in &self.samples {
            root.add_sample(&sample.call_stack, sample.cpu_time.as_nanos() as u64);
        }

        root
    }

    /// Get hottest functions
    pub fn hot_functions(&self, top_n: usize) -> Vec<(String, Duration)> {
        let mut function_times: HashMap<String, u64> = HashMap::new();

        for sample in &self.samples {
            if let Some(func) = sample.call_stack.first() {
                *function_times.entry(func.clone()).or_default() +=
                    sample.cpu_time.as_nanos() as u64;
            }
        }

        let mut sorted: Vec<_> = function_times.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));

        sorted
            .into_iter()
            .take(top_n)
            .map(|(name, nanos)| (name, Duration::from_nanos(nanos)))
            .collect()
    }

    /// Get sample count
    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }
}

impl Default for CpuProfiler {
    fn default() -> Self {
        Self::new(Duration::from_micros(100))
    }
}

// ============================================================================
// Criterion-style Reporter
// ============================================================================

/// Benchmark report generator
pub struct BenchReport {
    results: Vec<BenchResult>,
    baseline: Option<HashMap<String, Statistics>>,
}

impl BenchReport {
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
            baseline: None,
        }
    }

    pub fn add_result(&mut self, result: BenchResult) {
        self.results.push(result);
    }

    pub fn set_baseline(&mut self, baseline: HashMap<String, Statistics>) {
        self.baseline = Some(baseline);
    }

    /// Generate text report
    pub fn to_text(&self) -> String {
        let mut report = String::new();
        report.push_str("Benchmark Report\n");
        report.push_str("================\n\n");

        for result in &self.results {
            report.push_str(&format!("### {}\n", result.name));
            report.push_str(&format!(
                "  Mean:   {}\n",
                format_duration(result.statistics.mean as u64)
            ));
            report.push_str(&format!(
                "  Median: {}\n",
                format_duration(result.statistics.median as u64)
            ));
            report.push_str(&format!(
                "  StdDev: {} ({:.1}%)\n",
                format_duration(result.statistics.std_dev as u64),
                (result.statistics.std_dev / result.statistics.mean) * 100.0
            ));
            report.push_str(&format!(
                "  Min:    {}\n",
                format_duration(result.statistics.min)
            ));
            report.push_str(&format!(
                "  Max:    {}\n",
                format_duration(result.statistics.max)
            ));

            if let Some(throughput) = &result.throughput_unit {
                report.push_str(&format!(
                    "  Throughput: {:.2} {}/s\n",
                    throughput.value, throughput.unit
                ));
            }

            // Comparison with baseline
            if let Some(baseline) = &self.baseline {
                if let Some(base_stats) = baseline.get(&result.name) {
                    let comparison = Comparison::compare(base_stats, &result.statistics, 0.05);
                    report.push_str(&format!("  Change: {}\n", comparison.description()));
                }
            }

            report.push_str("\n");
        }

        report
    }

    /// Generate JSON report
    pub fn to_json(&self) -> String {
        let mut json = String::from("{\n  \"benchmarks\": [\n");

        for (i, result) in self.results.iter().enumerate() {
            json.push_str("    {\n");
            json.push_str(&format!("      \"name\": \"{}\",\n", result.name));
            json.push_str(&format!(
                "      \"mean_ns\": {:.2},\n",
                result.statistics.mean
            ));
            json.push_str(&format!(
                "      \"median_ns\": {:.2},\n",
                result.statistics.median
            ));
            json.push_str(&format!(
                "      \"std_dev_ns\": {:.2},\n",
                result.statistics.std_dev
            ));
            json.push_str(&format!("      \"min_ns\": {},\n", result.statistics.min));
            json.push_str(&format!("      \"max_ns\": {},\n", result.statistics.max));
            json.push_str(&format!(
                "      \"samples\": {}\n",
                result.measurement.samples.len()
            ));
            json.push_str("    }");

            if i < self.results.len() - 1 {
                json.push(',');
            }
            json.push('\n');
        }

        json.push_str("  ]\n}");
        json
    }

    /// Generate HTML report
    pub fn to_html(&self) -> String {
        let mut html = String::from(
            r#"<!DOCTYPE html>
<html>
<head>
    <title>Benchmark Report</title>
    <style>
        body { font-family: sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .faster { color: green; }
        .slower { color: red; }
    </style>
</head>
<body>
<h1>Benchmark Report</h1>
<table>
<tr>
    <th>Benchmark</th>
    <th>Mean</th>
    <th>Median</th>
    <th>Std Dev</th>
    <th>Min</th>
    <th>Max</th>
    <th>Throughput</th>
</tr>
"#,
        );

        for result in &self.results {
            html.push_str("<tr>\n");
            html.push_str(&format!("  <td>{}</td>\n", result.name));
            html.push_str(&format!(
                "  <td>{}</td>\n",
                format_duration(result.statistics.mean as u64)
            ));
            html.push_str(&format!(
                "  <td>{}</td>\n",
                format_duration(result.statistics.median as u64)
            ));
            html.push_str(&format!(
                "  <td>{} ({:.1}%)</td>\n",
                format_duration(result.statistics.std_dev as u64),
                (result.statistics.std_dev / result.statistics.mean) * 100.0
            ));
            html.push_str(&format!(
                "  <td>{}</td>\n",
                format_duration(result.statistics.min)
            ));
            html.push_str(&format!(
                "  <td>{}</td>\n",
                format_duration(result.statistics.max)
            ));

            if let Some(throughput) = &result.throughput_unit {
                html.push_str(&format!(
                    "  <td>{:.2} {}/s</td>\n",
                    throughput.value, throughput.unit
                ));
            } else {
                html.push_str("  <td>-</td>\n");
            }

            html.push_str("</tr>\n");
        }

        html.push_str("</table>\n</body>\n</html>");
        html
    }
}

impl Default for BenchReport {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Format duration in human-readable form
pub fn format_duration(nanos: u64) -> String {
    if nanos < 1_000 {
        format!("{} ns", nanos)
    } else if nanos < 1_000_000 {
        format!("{:.2} µs", nanos as f64 / 1_000.0)
    } else if nanos < 1_000_000_000 {
        format!("{:.2} ms", nanos as f64 / 1_000_000.0)
    } else {
        format!("{:.2} s", nanos as f64 / 1_000_000_000.0)
    }
}

/// Black box to prevent optimization
#[inline(never)]
pub fn black_box<T>(x: T) -> T {
    // Use volatile read to prevent optimization
    let ptr = &x as *const T;
    unsafe { std::ptr::read_volatile(ptr) }
}

// ============================================================================
// Main Demonstration
// ============================================================================

fn main() {
    println!("=== Performance Profiler and Benchmarking ===\n");

    // Example 1: Basic benchmarking
    println!("1. Basic Benchmarking:");
    let mut bencher = Bencher::new(BenchConfig::quick());

    bencher.group("String Operations");

    let result = bencher.bench("string_concat", || {
        let _s = format!("{}{}", "hello", "world");
        black_box(());
    });

    println!("   {}: {}", result.name, result.statistics.to_string());

    let result = bencher.bench("string_push", || {
        let mut s = String::new();
        s.push_str("hello");
        s.push_str("world");
        black_box(s);
    });

    println!("   {}: {}", result.name, result.statistics.to_string());

    // Example 2: Throughput benchmark
    println!("\n2. Throughput Benchmark:");
    let data: Vec<u8> = (0..1024).map(|i| i as u8).collect();

    let result = bencher.bench_throughput("hash_1kb", 1024, "bytes", || {
        let mut hash = 0u64;
        for &b in &data {
            hash = hash.wrapping_mul(31).wrapping_add(b as u64);
        }
        black_box(hash);
    });

    if let Some(throughput) = &result.throughput_unit {
        println!(
            "   Throughput: {:.2} {}/s",
            throughput.value, throughput.unit
        );
    }

    // Example 3: Statistical comparison
    println!("\n3. Statistical Comparison:");
    let baseline_samples: Vec<u64> = (0..100).map(|i| 1000 + (i % 20) as u64).collect();
    let new_samples: Vec<u64> = (0..100).map(|i| 900 + (i % 30) as u64).collect();

    let baseline_stats = Statistics::from_samples(&baseline_samples, 0.95);
    let new_stats = Statistics::from_samples(&new_samples, 0.95);

    let comparison = Comparison::compare(&baseline_stats, &new_stats, 0.05);
    println!("   Baseline mean: {:.2} ns", baseline_stats.mean);
    println!("   New mean: {:.2} ns", new_stats.mean);
    println!("   Change: {}", comparison.description());

    // Example 4: Memory profiling
    println!("\n4. Memory Profiling:");
    let mut mem_profiler = MemoryProfiler::new();

    mem_profiler.record_allocation(1024, Some("main::allocate_buffer"));
    mem_profiler.record_allocation(512, Some("main::allocate_header"));
    mem_profiler.record_allocation(2048, Some("main::allocate_data"));

    let mem_stats = mem_profiler.stats();
    println!("   Total allocated: {} bytes", mem_stats.total_allocated);
    println!("   Allocation count: {}", mem_stats.allocation_count);
    println!(
        "   Average allocation: {} bytes",
        mem_stats.average_allocation_size
    );

    // Example 5: CPU profiling
    println!("\n5. CPU Profiling:");
    let mut cpu_profiler = CpuProfiler::default();
    cpu_profiler.start();

    // Simulate some samples
    cpu_profiler.record_sample(
        vec![
            "main".to_string(),
            "process_data".to_string(),
            "parse".to_string(),
        ],
        Duration::from_micros(100),
    );
    cpu_profiler.record_sample(
        vec![
            "main".to_string(),
            "process_data".to_string(),
            "serialize".to_string(),
        ],
        Duration::from_micros(150),
    );
    cpu_profiler.record_sample(
        vec!["main".to_string(), "io_wait".to_string()],
        Duration::from_micros(50),
    );

    cpu_profiler.stop();

    let hot_funcs = cpu_profiler.hot_functions(5);
    println!("   Hot functions:");
    for (name, time) in hot_funcs {
        println!("     {}: {:?}", name, time);
    }

    // Example 6: Flamegraph generation
    println!("\n6. Flamegraph Generation:");
    let flamegraph = cpu_profiler.generate_flamegraph();
    let folded = flamegraph.to_folded("");
    println!("   Folded stacks:");
    for line in folded.iter().take(5) {
        println!("     {}", line);
    }

    // Example 7: Report generation
    println!("\n7. Report Generation:");
    let mut report = BenchReport::new();
    report.add_result(result.clone());

    println!("   Text report (excerpt):");
    for line in report.to_text().lines().take(8) {
        println!("     {}", line);
    }

    // Example 8: Configuration profiles
    println!("\n8. Configuration Profiles:");
    let quick = BenchConfig::quick();
    let thorough = BenchConfig::thorough();

    println!("   Quick config:");
    println!("     Min samples: {}", quick.min_samples);
    println!("     Max samples: {}", quick.max_samples);

    println!("   Thorough config:");
    println!("     Min samples: {}", thorough.min_samples);
    println!("     Max samples: {}", thorough.max_samples);

    // Example 9: Benchmark summary
    println!("\n9. Benchmark Summary:");
    bencher.summarize();

    // Example 10: Confidence intervals
    println!("\n10. Confidence Intervals:");
    let samples: Vec<u64> = vec![100, 102, 98, 105, 97, 103, 99, 101, 96, 104];
    let stats = Statistics::from_samples(&samples, 0.95);

    println!("   Mean: {:.2} ns", stats.mean);
    println!(
        "   95% CI: ({:.2}, {:.2}) ns",
        stats.confidence_interval.0, stats.confidence_interval.1
    );
    println!(
        "   Margin: ±{:.2} ns",
        (stats.confidence_interval.1 - stats.mean)
    );

    println!("\n=== Performance Profiling Complete ===");
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_statistics_from_samples() {
        let samples: Vec<u64> = vec![100, 200, 150, 175, 125];
        let stats = Statistics::from_samples(&samples, 0.95);

        assert!(stats.mean > 0.0);
        assert!(stats.median > 0.0);
        assert!(stats.std_dev > 0.0);
        assert_eq!(stats.min, 100);
        assert_eq!(stats.max, 200);
    }

    #[test]
    fn test_statistics_empty_samples() {
        let samples: Vec<u64> = vec![];
        let stats = Statistics::from_samples(&samples, 0.95);

        assert_eq!(stats.mean, 0.0);
        assert_eq!(stats.median, 0.0);
    }

    #[test]
    fn test_statistics_single_sample() {
        let samples: Vec<u64> = vec![100];
        let stats = Statistics::from_samples(&samples, 0.95);

        assert_eq!(stats.mean, 100.0);
        assert_eq!(stats.median, 100.0);
        assert_eq!(stats.min, 100);
        assert_eq!(stats.max, 100);
    }

    #[test]
    fn test_comparison() {
        let baseline_samples: Vec<u64> = vec![100, 100, 100];
        let new_samples: Vec<u64> = vec![90, 90, 90];

        let baseline = Statistics::from_samples(&baseline_samples, 0.95);
        let new = Statistics::from_samples(&new_samples, 0.95);

        let comparison = Comparison::compare(&baseline, &new, 0.05);

        assert!(comparison.change < 0.0); // Faster
        assert!(comparison.significant);
    }

    #[test]
    fn test_comparison_insignificant() {
        let baseline_samples: Vec<u64> = vec![100, 100, 100];
        let new_samples: Vec<u64> = vec![101, 101, 101]; // Only 1% change

        let baseline = Statistics::from_samples(&baseline_samples, 0.95);
        let new = Statistics::from_samples(&new_samples, 0.95);

        let comparison = Comparison::compare(&baseline, &new, 0.05);

        assert!(!comparison.significant);
    }

    #[test]
    fn test_format_duration_ns() {
        assert_eq!(format_duration(100), "100 ns");
    }

    #[test]
    fn test_format_duration_us() {
        assert!(format_duration(5000).contains("µs"));
    }

    #[test]
    fn test_format_duration_ms() {
        assert!(format_duration(5_000_000).contains("ms"));
    }

    #[test]
    fn test_format_duration_s() {
        assert!(format_duration(5_000_000_000).contains("s"));
    }

    #[test]
    fn test_bench_config_default() {
        let config = BenchConfig::default();
        assert!(config.warmup_iters > 0);
        assert!(config.min_samples > 0);
    }

    #[test]
    fn test_bench_config_quick() {
        let quick = BenchConfig::quick();
        let default = BenchConfig::default();

        assert!(quick.min_samples < default.min_samples);
    }

    #[test]
    fn test_bench_config_thorough() {
        let thorough = BenchConfig::thorough();
        let default = BenchConfig::default();

        assert!(thorough.min_samples > default.min_samples);
    }

    #[test]
    fn test_memory_profiler() {
        let mut profiler = MemoryProfiler::new();
        profiler.record_allocation(100, Some("test"));
        profiler.record_allocation(200, None);

        let stats = profiler.stats();
        assert_eq!(stats.total_allocated, 300);
        assert_eq!(stats.allocation_count, 2);
    }

    #[test]
    fn test_memory_profiler_reset() {
        let mut profiler = MemoryProfiler::new();
        profiler.record_allocation(100, None);
        profiler.reset();

        let stats = profiler.stats();
        assert_eq!(stats.allocation_count, 0);
    }

    #[test]
    fn test_cpu_profiler() {
        let mut profiler = CpuProfiler::default();
        profiler.start();
        profiler.record_sample(vec!["func1".to_string()], Duration::from_micros(10));
        profiler.stop();

        assert_eq!(profiler.sample_count(), 1);
    }

    #[test]
    fn test_flamegraph_node() {
        let mut root = FlamegraphNode::new("root");
        root.add_sample(&["main".to_string(), "func1".to_string()], 100);
        root.add_sample(&["main".to_string(), "func2".to_string()], 200);

        assert_eq!(root.total_time, 300);
        assert!(root.children.contains_key("main"));
    }

    #[test]
    fn test_bench_report() {
        let mut report = BenchReport::new();

        let result = BenchResult {
            name: "test".to_string(),
            measurement: Measurement {
                samples: vec![100, 200, 150],
                iters_per_sample: 1,
                total_time: Duration::from_millis(1),
            },
            statistics: Statistics::from_samples(&[100, 200, 150], 0.95),
            throughput_unit: None,
        };

        report.add_result(result);

        let text = report.to_text();
        assert!(text.contains("test"));
    }

    #[test]
    fn test_bench_report_json() {
        let mut report = BenchReport::new();
        let result = BenchResult {
            name: "test".to_string(),
            measurement: Measurement {
                samples: vec![100],
                iters_per_sample: 1,
                total_time: Duration::from_millis(1),
            },
            statistics: Statistics::from_samples(&[100], 0.95),
            throughput_unit: None,
        };

        report.add_result(result);
        let json = report.to_json();

        assert!(json.contains("benchmarks"));
        assert!(json.contains("test"));
    }

    #[test]
    fn test_black_box() {
        let x = 42;
        let y = black_box(x);
        assert_eq!(x, y);
    }

    #[test]
    fn test_bencher_creation() {
        let bencher = Bencher::new(BenchConfig::default());
        assert!(bencher.groups.is_empty());
    }

    #[test]
    fn test_bencher_group() {
        let mut bencher = Bencher::new(BenchConfig::default());
        bencher.group("test_group");

        assert!(bencher.groups.contains_key("test_group"));
    }

    #[test]
    fn test_throughput_unit() {
        let unit = ThroughputUnit {
            value: 1000.0,
            unit: "elements".to_string(),
        };

        assert_eq!(unit.value, 1000.0);
        assert_eq!(unit.unit, "elements");
    }
}
