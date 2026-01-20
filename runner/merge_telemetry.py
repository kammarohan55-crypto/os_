#!/usr/bin/env python3
"""
Merge Telemetry - Integration with compute_aggregates (Fix #6)

Merges basic telemetry with eBPF syscall data and computes aggregates.
"""

import json
import sys
import os

# Add runner directory to path for compute_aggregates
sys.path.insert(0, os.path.dirname(__file__))
from compute_aggregates import compute_aggregates_for_log, normalize_for_api

def merge_telemetry(telemetry_file, ebpf_file, output_file):
    """
    Merge telemetry and eBPF data, compute aggregates
    
    CRITICAL: This now computes CPU/MEM aggregates to fix zero metrics!
    """
    # Load telemetry
    with open(telemetry_file, 'r') as f:
        telemetry = json.load(f)
    
    # Load eBPF (optional)
    ebpf_data = {}
    if os.path.exists(ebpf_file):
        with open(ebpf_file, 'r') as f:
            ebpf_data = json.load(f)
    
    # Merge data
    merged = telemetry.copy()
    
    # Add eBPF syscall events if available
    if ebpf_data:
        merged['syscall_events'] = ebpf_data.get('syscall_events', {})
    
    # CRITICAL FIX: Compute aggregates from raw samples
    if 'stat_samples' in merged or 'mem_samples' in merged:
        print("[Merge] Computing aggregates from raw samples...")
        aggregates = compute_aggregates_for_log(merged)
        
        # EXPLICITLY write all required fields (Step 1: Fix telemetry aggregation)
        merged['peak_cpu'] = aggregates.get('peak_cpu_percent', 0)
        merged['avg_cpu'] = aggregates.get('avg_cpu_percent', 0)
        merged['peak_memory_kb'] = aggregates.get('peak_memory_kb', 0)
        merged['avg_memory_kb'] = aggregates.get('avg_memory_kb', 0)
        merged['runtime_ms'] = aggregates.get('runtime_ms', 0)
        
        # Also add with alternate naming for compatibility
        merged['peak_cpu_percent'] = aggregates.get('peak_cpu_percent', 0)
        merged['cpu_percent'] = aggregates.get('cpu_percent', 0)
        merged['cpu_used_seconds'] = aggregates.get('cpu_used_seconds', 0)
        
        # FIX #5: Generate time-series data for timeline charts
        # Convert raw samples to chart-ready series
        cpu_series = []
        if 'stat_samples' in merged and len(merged['stat_samples']) > 0:
            start_ts = merged['stat_samples'][0]['ts']
            for sample in merged['stat_samples']:
                # Calculate instantaneous CPU % for this sample
                cpu_series.append({
                    'timestamp_ms': int((sample['ts'] - start_ts) * 1000),
                    'value': min(100, (sample.get('utime', 0) + sample.get('stime', 0)) / 100.0)  # rough approximation
                })
        merged['cpu_series'] = cpu_series
        
        mem_series = []
        if 'mem_samples' in merged and len(merged['mem_samples']) > 0:
            start_ts = merged['mem_samples'][0]['ts']
            for sample in merged['mem_samples']:
                mem_series.append({
                    'timestamp_ms': int((sample['ts'] - start_ts) * 1000),
                    'value': sample.get('rss_kb', 0)
                })
        merged['mem_series'] = mem_series
        
        print(f"  ✓ Time-series: {len(cpu_series)} CPU samples, {len(mem_series)} MEM samples")
        
        # Validate: warn if values are zero
        if merged['peak_cpu'] == 0:
            print("  ⚠️  WARNING: peak_cpu is ZERO! Check stat_samples data.")
        else:
            print(f"  ✓ CPU: peak={merged['peak_cpu']}%, avg={merged['avg_cpu']}%")
        
        if merged['peak_memory_kb'] == 0:
            print("  ⚠️  WARNING: peak_memory_kb is ZERO! Check mem_samples data.")
        else:
            print(f"  ✓ MEM: peak={merged['peak_memory_kb']} KB, avg={merged['avg_memory_kb']} KB")
        
        if merged['runtime_ms'] == 0:
            print("  ⚠️  WARNING: runtime_ms is ZERO! Check timestamps.")
        else:
            print(f"  ✓ Runtime: {merged['runtime_ms']} ms")
    else:
        print("[WARNING] No raw samples found - aggregates may be zero!")
        # Set defaults to avoid undefined fields
        merged['peak_cpu'] = 0
        merged['avg_cpu'] = 0
        merged['peak_memory_kb'] = 0
        merged['avg_memory_kb'] = 0
        merged['runtime_ms'] = 0
        merged['peak_cpu_percent'] = 0
        merged['cpu_percent'] = 0
        merged['cpu_used_seconds'] = 0
        merged['cpu_series'] = []
        merged['mem_series'] = []
    
    # Normalize for API compatibility
    merged = normalize_for_api(merged)
    
    # Add reproducibility metadata
    merged['reproducibility'] = {
        'merge_version': '1.0',
        'aggregation_method': 'compute_aggregates.py',
        'timestamp': merged.get('end_ts', 0)
    }
    
    # Write merged output
    with open(output_file, 'w') as f:
        json.dump(merged, f, indent=2)
    
    print(f"[Merge] Wrote merged telemetry to: {output_file}")
    
    return merged

if __name__ == '__main__':
    if len(sys.argv) < 4:
        print("Usage: python3 merge_telemetry.py <telemetry.json> <ebpf.json> <output.json>")
        sys.exit(1)
    
    telemetry_file = sys.argv[1]
    ebpf_file = sys.argv[2]
    output_file = sys.argv[3]
    
    result = merge_telemetry(telemetry_file, ebpf_file, output_file)
    
    # Validate results
    if result.get('peak_cpu_percent', 0) == 0:
        print("[WARNING] Peak CPU is zero - check stat_samples!")
    
    if result.get('peak_memory_kb', 0) == 0:
        print("[WARNING] Peak memory is zero - check mem_samples!")
    
    print("[Merge] Complete!")
