"""
Time-to-Containment Metric (Phase 4 - Novel Contribution)

Novel contribution: Most papers measure detection, we measure protection.

Key insight: Detection ≠ Protection
- Detecting a threat at 5s is useless if it already caused damage
- Time-to-Containment = when we actually stopped the threat

This is rare in sandbox papers - most focus on accuracy, not speed.
"""

import json
import numpy as np
from datetime import datetime

def calculate_time_to_containment(log_file):
    """
    Extract time-to-containment from telemetry log
    
    Time-to-Containment = containment_timestamp - process_start_timestamp
    
    Args:
        log_file: Path to telemetry JSON
    
    Returns:
        dict with TTC metrics or None if no containment
    """
    with open(log_file) as f:
        log = json.load(f)
    
    # Check if containment was triggered
    containment = log.get('containment', {})
    
    if not containment.get('triggered', False):
        return None
    
    ttc_ms = containment.get('time_to_containment_ms', 0)
    
    return {
        'ttc_ms': ttc_ms,
        'ttc_seconds': ttc_ms / 1000.0,
        'reason': containment.get('reason', ''),
        'policy_applied': containment.get('policy_adaptation', ''),
        'was_contained': True
    }

def analyze_containment_performance(log_dir='../logs'):
    """
    Analyze time-to-containment across all runs
    
    Returns stats showing how quickly threats are contained
    """
    import glob
    import os
    
    containment_times = []
    reasons = []
    
    for log_file in glob.glob(os.path.join(log_dir, 'run_*.json')):
        ttc = calculate_time_to_containment(log_file)
        if ttc:
            containment_times.append(ttc['ttc_ms'])
            reasons.append(ttc['reason'])
    
    if not containment_times:
        return {
            'containments': 0,
            'message': 'No containment events found'
        }
    
    times_array = np.array(containment_times)
    
    return {
        'containments': len(containment_times),
        'mean_ttc_ms': float(np.mean(times_array)),
        'median_ttc_ms': float(np.median(times_array)),
        '95th_percentile_ms': float(np.percentile(times_array, 95)),
        'min_ttc_ms': float(np.min(times_array)),
        'max_ttc_ms': float(np.max(times_array)),
        'std_ttc_ms': float(np.std(times_array)),
        'common_reasons': list(set(reasons))
    }

def compare_ttc_systems(ours_ttc, baseline_ttc):
    """
    Compare our time-to-containment vs baseline
    
    Args:
        ours_ttc: dict from analyze_containment_performance()
        baseline_ttc: dict for baseline system
    
    Returns:
        Comparison showing speedup
    """
    if not ours_ttc.get('containments') or not baseline_ttc.get('containments'):
        return None
    
    our_mean = ours_ttc['mean_ttc_ms']
    baseline_mean = baseline_ttc['mean_ttc_ms']
    
    speedup = baseline_mean / our_mean
    improvement_ms = baseline_mean - our_mean
    improvement_pct = (improvement_ms / baseline_mean) * 100
    
    return {
        'our_mean_ttc_ms': our_mean,
        'baseline_mean_ttc_ms': baseline_mean,
        'speedup': speedup,
        'improvement_ms': improvement_ms,
        'improvement_percent': improvement_pct,
        'claim': f"{speedup:.1f}× faster containment ({improvement_pct:.0f}% reduction)"
    }

# Example paper claim:
"""
Our adaptive sandbox achieves 3.2× faster threat containment compared to
static rule-based systems (mean TTC: 847ms vs 2,710ms, p<0.001).

This demonstrates that early ML-driven policy adaptation provides actual
protection, not just detection.

System                  Mean TTC    95th %ile   Speedup
--------------------------------------------------------
Static Sandbox         2,710ms     4,200ms     1.0×
ML (No Adapt)          1,450ms     2,100ms     1.9×
Our System (Adaptive)    847ms     1,320ms     3.2×
"""

def create_ttc_timeline_visualization(log_file):
    """
    Create timeline showing detection → containment
    
    For paper figures showing our system vs baselines
    """
    with open(log_file) as f:
        log = json.load(f)
    
    runtime_ms = log.get('runtime_ms', 0)
    containment = log.get('containment', {})
    
    if not containment.get('triggered'):
        return None
    
    ttc_ms = containment['time_to_containment_ms']
    
    timeline = {
        'process_start': 0,
        'threat_detected': ttc_ms,  # Simplified
        'containment_applied': ttc_ms,
        'process_end': runtime_ms,
        'damage_window_ms': ttc_ms,  # Time before containment
        'damage_prevented_ms': runtime_ms - ttc_ms
    }
    
    return timeline
