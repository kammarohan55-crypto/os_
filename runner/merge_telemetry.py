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
        merged.update(aggregates)
        
        print(f"  ✓ CPU: {aggregates.get('peak_cpu_percent', 0)}%")
        print(f"  ✓ MEM: {aggregates.get('peak_memory_kb', 0)} KB")
        print(f"  ✓ Runtime: {aggregates.get('runtime_ms', 0)} ms")
    else:
        print("[WARNING] No raw samples found - aggregates may be zero!")
    
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
