"""
Compute Aggregates (Critical Fix for Zero CPU/MEM Metrics)

This module computes per-process aggregate statistics from raw telemetry samples.

CRITICAL: Fixes the root cause of zero CPU/MEM metrics by properly computing:
- CPU usage from /proc/[pid]/stat jiffies deltas
- Memory usage from RSS samples
- Peak values across lifetime

Called by merge_telemetry.py to produce final aggregates.
"""

import os
import ctypes

# Get system clock ticks per second (usually 100 on Linux)
try:
    CLK_TCK = os.sysconf(os.sysconf_names['SC_CLK_TCK'])
except:
    CLK_TCK = 100  # Fallback

def compute_cpu_from_stat_samples(stat_samples):
    """
    Compute CPU metrics from /proc/[pid]/stat samples
    
    Args:
        stat_samples: List of dicts with {'utime': int, 'stime': int, 'ts': float}
    
    Returns:
        Dict with cpu_used_seconds, cpu_percent, peak_cpu_percent
    """
    if not stat_samples or len(stat_samples) < 2:
        return {
            "cpu_used_seconds": 0.0,
            "cpu_percent": 0.0,
            "peak_cpu_percent": 0.0
        }
    
    # Total CPU time used (jiffies delta)
    start_jiffies = stat_samples[0]['utime'] + stat_samples[0]['stime']
    end_jiffies = stat_samples[-1]['utime'] + stat_samples[-1]['stime']
    delta_jiffies = max(0, end_jiffies - start_jiffies)
    
    # Convert jiffies to seconds
    delta_seconds = delta_jiffies / CLK_TCK
    
    # Wall time elapsed
    wall_time = stat_samples[-1]['ts'] - stat_samples[0]['ts']
    
    # Average CPU percent
    cpu_percent = (delta_seconds / max(1e-6, wall_time)) * 100.0
    
    # Compute per-sample percent to find peak
    peak_percent = 0.0
    for i in range(1, len(stat_samples)):
        curr_jiffies = stat_samples[i]['utime'] + stat_samples[i]['stime']
        prev_jiffies = stat_samples[i-1]['utime'] + stat_samples[i-1]['stime']
        
        delta_j = curr_jiffies - prev_jiffies
        delta_t = stat_samples[i]['ts'] - stat_samples[i-1]['ts']
        
        if delta_t <= 0:
            continue
        
        sample_percent = (delta_j / CLK_TCK) / delta_t * 100.0
        if sample_percent > peak_percent:
            peak_percent = sample_percent
    
    return {
        "cpu_used_seconds": round(delta_seconds, 3),
        "cpu_percent": round(cpu_percent, 2),
        "peak_cpu_percent": round(peak_percent, 2),
        "avg_cpu_percent": round(cpu_percent, 2)  # For backward compatibility
    }

def compute_mem_from_samples(mem_samples):
    """
    Compute memory metrics from RSS samples
    
    Args:
        mem_samples: List of dicts with {'rss_kb': int, 'ts': float}
    
    Returns:
        Dict with peak_memory_kb, avg_memory_kb
    """
    if not mem_samples:
        return {
            "peak_memory_kb": 0,
            "avg_memory_kb": 0,
            "peak_mem_kb": 0,  # Legacy name
            "avg_mem_kb": 0    # Legacy name
        }
    
    rss_values = [s['rss_kb'] for s in mem_samples]
    peak_kb = int(max(rss_values))
    avg_kb = int(sum(rss_values) / len(rss_values))
    
    return {
        "peak_memory_kb": peak_kb,
        "avg_memory_kb": avg_kb,
        "peak_mem_kb": peak_kb,  # Legacy name
        "avg_mem_kb": avg_kb     # Legacy name
    }

def compute_runtime(log):
    """
    Compute runtime in milliseconds
    
    Args:
        log: Dict with 'start_ts', 'end_ts', or 'stat_samples'
    
    Returns:
        runtime_ms: int
    """
    # Try explicit timestamps first
    start_ts = log.get('start_ts')
    end_ts = log.get('end_ts')
    
    # Fallback to stat_samples
    if not start_ts and log.get('stat_samples'):
        start_ts = log['stat_samples'][0].get('ts')
    if not end_ts and log.get('stat_samples'):
        end_ts = log['stat_samples'][-1].get('ts')
    
    if start_ts and end_ts:
        return int((end_ts - start_ts) * 1000)
    
    # Fallback to existing field
    return int(log.get('runtime_ms', 0))

def compute_aggregates_for_log(log):
    """
    Compute all aggregate statistics for a telemetry log
    
    CRITICAL FUNCTION: This fixes zero CPU/MEM metrics!
    
    Args:
        log: Dict with raw telemetry including:
            - 'stat_samples': List of /proc/[pid]/stat readings
            - 'mem_samples': List of RSS readings
            - Other metadata
    
    Returns:
        Dict with all computed aggregates
    """
    result = {}
    
    # Compute CPU metrics
    cpu_metrics = compute_cpu_from_stat_samples(log.get('stat_samples', []))
    result.update(cpu_metrics)
    
    # Compute memory metrics
    mem_metrics = compute_mem_from_samples(log.get('mem_samples', []))
    result.update(mem_metrics)
    
    # Compute runtime
    result['runtime_ms'] = compute_runtime(log)
    
    # Add metadata for reproducibility
    result['clock_ticks_per_sec'] = CLK_TCK
    result['aggregation_version'] = '1.0'
    
    return result

def normalize_for_api(run):
    """
    Normalize run data for API backward compatibility
    
    Ensures both old and new field names exist
    """
    # CPU normalization
    if 'peak_cpu_percent' in run:
        run['cpu_avg'] = run.get('cpu_percent', run.get('avg_cpu_percent', run.get('peak_cpu_percent', 0)))
        run['cpu_peak'] = run.get('peak_cpu_percent', 0)
    
    # Memory normalization
    if 'peak_memory_kb' in run:
        run['mem_avg'] = run.get('avg_memory_kb', run.get('peak_memory_kb', 0))
        run['mem_peak'] = run.get('peak_memory_kb', 0)
    
    # Series normalization
    if 'risk_series' not in run and 'risk_samples' in run:
        run['risk_series'] = run['risk_samples']
    
    if 'cpu_series' not in run and 'cpu_samples' in run:
        run['cpu_series'] = run['cpu_samples']
    
    return run

# Test function
if __name__ == '__main__':
    # Test with mock data
    import time
    
    mock_log = {
        'stat_samples': [
            {'utime': 100, 'stime': 50, 'ts': 0.0},
            {'utime': 500, 'stime': 200, 'ts': 1.0},
            {'utime': 1000, 'stime': 400, 'ts': 2.0}
        ],
        'mem_samples': [
            {'rss_kb': 1024, 'ts': 0.0},
            {'rss_kb': 2048, 'ts': 1.0},
            {'rss_kb': 1536, 'ts': 2.0}
        ]
    }
    
    result = compute_aggregates_for_log(mock_log)
    print("Test Results:")
    print(f"  CPU used: {result['cpu_used_seconds']}s")
    print(f"  CPU percent: {result['cpu_percent']}%")
    print(f"  Peak CPU: {result['peak_cpu_percent']}%")
    print(f"  Peak Memory: {result['peak_memory_kb']} KB")
    print(f"  Avg Memory: {result['avg_memory_kb']} KB")
    print(f"  Runtime: {result['runtime_ms']} ms")
    
    # Verify non-zero
    assert result['cpu_percent'] > 0, "CPU percent should be > 0"
    assert result['peak_memory_kb'] > 0, "Peak memory should be > 0"
    print("\n✓ All tests passed!")
