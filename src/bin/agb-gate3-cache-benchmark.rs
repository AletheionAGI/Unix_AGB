use serde::Serialize;
use std::time::Instant;
use unix_agb::policy::{CompiledDecision, CompiledDecisionCache};

#[derive(Serialize)]
struct Latency {
    p50_ns: u128,
    p95_ns: u128,
    p99_ns: u128,
}

#[derive(Serialize)]
struct Report {
    benchmark: &'static str,
    iterations: usize,
    cache_entries: usize,
    effect: &'static str,
    latency: Latency,
}

fn percentile(samples: &[u128], quantile: f64) -> u128 {
    let index = ((samples.len() - 1) as f64 * quantile).round() as usize;
    samples[index]
}

fn main() -> Result<(), String> {
    let iterations = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "100000".into())
        .parse::<usize>()
        .map_err(|_| "iterations must be a positive integer".to_string())?;
    if iterations == 0 {
        return Err("iterations must be positive".into());
    }
    let entry = CompiledDecision {
        cache_key: "process:benchmark:1:1|file.open|resource".into(),
        decision_id: "dec:benchmark".into(),
        namespace_id: "process:benchmark:1:1".into(),
        operation: "file.open".into(),
        resource_sha256: "0".repeat(64),
        effect: "DENY".into(),
        policy_revision: "policy:gate3-benchmark".into(),
        state_revision: 1,
        evidence_sha256: "1".repeat(64),
        expires_epoch: u64::MAX,
    };
    let key = entry.cache_key.clone();
    let mut cache = CompiledDecisionCache::default();
    cache.put(entry, "policy:gate3-benchmark")?;
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let started = Instant::now();
        let result = cache.lookup(&key, "policy:gate3-benchmark", 1, 1);
        samples.push(started.elapsed().as_nanos());
        if result.effect != "DENY" {
            return Err("cache lookup changed effect".into());
        }
    }
    samples.sort_unstable();
    let report = Report {
        benchmark: "unix-agb-gate3-cache-lookup-v1",
        iterations,
        cache_entries: cache.len(),
        effect: "DENY",
        latency: Latency {
            p50_ns: percentile(&samples, 0.50),
            p95_ns: percentile(&samples, 0.95),
            p99_ns: percentile(&samples, 0.99),
        },
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?
    );
    Ok(())
}
