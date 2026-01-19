#!/usr/bin/env python3
"""
Merge telemetry JSON and eBPF JSON into single unified log
"""

import sys
import json

def merge_telemetry(telemetry_file, ebpf_file, output_file=None):
    """Merge telemetry and eBPF data"""
    
    # Load telemetry
    with open(telemetry_file, 'r') as f:
        telemetry = json.load(f)
    
    # Load eBPF data
    try:
        with open(ebpf_file, 'r') as f:
            ebpf_data = json.load(f)
    except FileNotFoundError:
        print(f"Warning: eBPF file {ebpf_file} not found, using telemetry only")
        ebpf_data = {}
    
    # Merge
    telemetry.update(ebpf_data)
    
    # Write back to telemetry file (in-place merge)
    output = output_file if output_file else telemetry_file
    with open(output, 'w') as f:
        json.dump(telemetry, f, indent=2)
    
    print(f"Merged: {output}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: merge_telemetry.py <telemetry.json> <ebpf.json> [output.json]")
        sys.exit(1)
    
    telemetry_file = sys.argv[1]
    ebpf_file = sys.argv[2]
    output_file = sys.argv[3] if len(sys.argv) > 3 else None
    
    merge_telemetry(telemetry_file, ebpf_file, output_file)
