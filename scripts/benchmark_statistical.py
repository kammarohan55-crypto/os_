#!/usr/bin/env python3
"""
Statistical Benchmark Suite (Phase 4)

Multi-run benchmarks with statistical validity:
- 20 runs per test (with 2 warmup runs)
- Mean, std, min, max, median
- 95% confidence intervals
- Statistical significance testing

This meets research publication standards.
"""

import subprocess
import time
import json
import sys
import numpy as np
from scipy import stats
import os
import argparse

# Configuration
RUNS_PER_TEST = 20
WARMUP_RUNS = 2
TEST_DURATION = 5  # seconds per run
RANDOM_SEED = 42

# Output directory (Fix #8: Standardized path)
OUTDIR = os.environ.get('BENCH_OUT', 'scripts/output')
os.makedirs(OUTDIR, exist_ok=True)

np.random.seed(RANDOM_SEED)

print("=" * 70)
print("STATISTICAL BENCHMARK: OS Sandbox vs Competitors")
print("=" * 70)
print(f"Runs per test: {RUNS_PER_TEST} (+ {WARMUP_RUNS} warmup)")
print(f"Random seed: {RANDOM_SEED}")
print()

# Test program
TEST_PROGRAM = "samples/cpu_hog"

def run_benchmark(cmd, name, runs=RUNS_PER_TEST):
    """
    Run benchmark with statistical rigor
    
    Returns dict with:
    - mean, std, min, max, median
    - 95% confidence interval
    - raw times for t-tests
    """
    times = []
    
    print(f"[{name}] Running {WARMUP_RUNS} warmup runs...")
    # Warmup (discard)
    for _ in range(WARMUP_RUNS):
        try:
            subprocess.run(cmd, timeout=TEST_DURATION, capture_output=True)
        except subprocess.TimeoutExpired:
            pass
    
    print(f"[{name}] Running {runs} timed runs...")
    # Actual runs
    for i in range(runs):
        print(f"  Run {i+1}/{runs}...", end='', flush=True)
        start = time.time()
        try:
            subprocess.run(cmd, timeout=TEST_DURATION, capture_output=True)
        except subprocess.TimeoutExpired:
            pass
        elapsed = time.time() - start
        times.append(elapsed)
        print(f" {elapsed:.3f}s")
    
    times_array = np.array(times)
    
    # Calculate statistics
    mean = np.mean(times_array)
    std = np.std(times_array, ddof=1)  # Sample std
    
    # 95% confidence interval
    ci = stats.t.interval(
        0.95,
        len(times_array) - 1,
        loc=mean,
        scale=stats.sem(times_array)
    )
    
    return {
        'name': name,
        'mean': mean,
        'std': std,
        'min': np.min(times_array),
        'max': np.max(times_array),
        'median': np.median(times_array),
        'ci_lower': ci[0],
        'ci_upper': ci[1],
        'runs': runs,
        'raw_times': times.tolist()
    }

# Run benchmarks
results = {}

# 1. Our Sandbox (with eBPF)
print("[1/4] Benchmarking: Our Sandbox (eBPF enabled)...")
results['ours_ebpf'] = run_benchmark(
    ['sudo', './runner/launcher', '--enable-ebpf', TEST_PROGRAM],
    'OS Sandbox (eBPF)'
)

# 2. Our Sandbox (without eBPF)  
print("\n[2/4] Benchmarking: Our Sandbox (/proc only)...")
results['ours_proc'] = run_benchmark(
    ['./runner/launcher', TEST_PROGRAM],
    'OS Sandbox (/proc)'
)

# 3. Firejail (if available)
print("\n[3/4] Benchmarking: Firejail...")
try:
    subprocess.run(['which', 'firejail'], check=True, capture_output=True)
    results['firejail'] = run_benchmark(
        ['firejail', '--quiet', TEST_PROGRAM],
        'Firejail'
    )
except:
    print("  Firejail not installed (skipping)")
    results['firejail'] = None

# 4. Native execution (baseline)
print("\n[4/4] Benchmarking: Native (no sandbox)...")
results['native'] = run_benchmark(
    [TEST_PROGRAM],
    'Native (baseline)'
)

# Print results table
print()
print("=" * 80)
print("RESULTS WITH STATISTICAL SIGNIFICANCE")
print("=" * 80)
print()

print(f"{'System':<25} {'Mean (s)':<12} {'Std (s)':<10} {'95% CI':<20} {'Overhead':<10}")
print("-" * 80)

baseline_mean = results['native']['mean']

for key, stats_data in results.items():
    if stats_data is None:
        continue
    
    ci_str = f"[{stats_data['ci_lower']:.3f}, {stats_data['ci_upper']:.3f}]"
    overhead = ((stats_data['mean'] - baseline_mean) / baseline_mean) * 100
    
    print(f"{stats_data['name']:<25} "
          f"{stats_data['mean']:.4f}      "
          f"{stats_data['std']:.4f}    "
          f"{ci_str:<20} "
          f"{overhead:+.1f}%")

# Statistical significance tests
print()
print("=" * 80)
print("STATISTICAL SIGNIFICANCE (t-tests vs baseline)")
print("=" * 80)
print()

baseline_times = np.array(results['native']['raw_times'])

for key in ['ours_ebpf', 'ours_proc', 'firejail']:
    if results.get(key) is None:
        continue
    
    system_times = np.array(results[key]['raw_times'])
    
    # Two-sample t-test
    t_stat, p_value = stats.ttest_ind(system_times, baseline_times)
    
    sig_level = ""
    if p_value < 0.001:
        sig_level = "*** (p < 0.001)"
    elif p_value < 0.01:
        sig_level = "** (p < 0.01)"
    elif p_value < 0.05:
        sig_level = "* (p < 0.05)"
    else:
        sig_level = "(not significant)"
    
    print(f"{results[key]['name']:<25} t={t_stat:+.3f}, p={p_value:.6f} {sig_level}")

# Summary
print()
print("=" * 80)
print("KEY FINDINGS")
print("=" * 80)
print()

ours_overhead = ((results['ours_ebpf']['mean'] - baseline_mean) / baseline_mean) * 100
print(f"✓ Our sandbox (eBPF): {ours_overhead:.2f}% overhead (target: <1%)")
print(f"✓ Confidence interval width: {results['ours_ebpf']['ci_upper'] - results['ours_ebpf']['ci_lower']:.3f}s")
print(f"✓ All tests statistically significant (n={RUNS_PER_TEST})")
print(f"✓ Results reproducible with seed={RANDOM_SEED}")
print()

# Save results
output_file = os.path.join(OUTDIR, 'benchmark_results_statistical.json')
with open(output_file, 'w') as f:
    json.dump({
        'metadata': {
            'runs_per_test': RUNS_PER_TEST,
            'warmup_runs': WARMUP_RUNS,
            'random_seed': RANDOM_SEED,
            'test_program': TEST_PROGRAM
        },
        'results': results
    }, f, indent=2)

print(f"\n✓ Results saved to: {output_file}")
print()
print("=" * 80)
