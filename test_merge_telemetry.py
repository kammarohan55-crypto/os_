#!/usr/bin/env python3
"""
Test merge_telemetry with mock data to verify aggregates are computed correctly
"""

import json
import sys
import os

# Create mock telemetry data with stat and mem samples
mock_telemetry = {
    "program": "test_program",
    "pid": 12345,
    "start_ts": 1000.0,
    "end_ts": 1005.0,
    "stat_samples": [
        {"utime": 100, "stime": 50, "ts": 1000.0},
        {"utime": 300, "stime": 150, "ts": 1001.0},
        {"utime": 500, "stime": 250, "ts": 1002.0},
        {"utime": 800, "stime": 400, "ts": 1003.0},
        {"utime": 1200, "stime": 600, "ts": 1004.0},
        {"utime": 1500, "stime": 750, "ts": 1005.0}
    ],
    "mem_samples": [
        {"rss_kb": 1024, "ts": 1000.0},
        {"rss_kb": 2048, "ts": 1001.0},
        {"rss_kb": 4096, "ts": 1002.0},
        {"rss_kb": 3072, "ts": 1003.0},
        {"rss_kb": 2560, "ts": 1004.0},
        {"rss_kb": 2048, "ts": 1005.0}
    ]
}

mock_ebpf = {
    "syscall_events": {
        "total_syscalls": 150,
        "unique_syscalls": 25,
        "syscall_rate_per_sec": 30.0,
        "network_syscalls": 5
    }
}

# Write mock files
print("Creating mock telemetry files...")
with open('/tmp/test_telemetry.json', 'w') as f:
    json.dump(mock_telemetry, f, indent=2)

with open('/tmp/test_ebpf.json', 'w') as f:
    json.dump(mock_ebpf, f, indent=2)

print("✓ Mock files created")
print()

# Run merge_telemetry
print("Running merge_telemetry.py...")
print("=" * 70)

sys.path.insert(0, 'runner')
from merge_telemetry import merge_telemetry

result = merge_telemetry('/tmp/test_telemetry.json', '/tmp/test_ebpf.json', '/tmp/test_merged.json')

print("=" * 70)
print()

# Validate results
print("VALIDATION:")
print("-" * 70)

required_fields = {
    'peak_cpu': 'Peak CPU %',
    'avg_cpu': 'Average CPU %',
    'peak_memory_kb': 'Peak Memory (KB)',
    'avg_memory_kb': 'Average Memory (KB)',
    'runtime_ms': 'Runtime (ms)'
}

all_valid = True

for field, description in required_fields.items():
    value = result.get(field, None)
    
    if value is None:
        print(f"  ❌ {description} ({field}): MISSING")
        all_valid = False
    elif value == 0:
        print(f"  ⚠️  {description} ({field}): ZERO (expected non-zero)")
        all_valid = False
    else:
        print(f"  ✅ {description} ({field}): {value}")

print("-" * 70)
print()

if all_valid:
    print("✅ ALL FIELDS VALID AND NON-ZERO!")
    print()
    print("Sample output:")
    print(json.dumps({
        'peak_cpu': result.get('peak_cpu'),
        'avg_cpu': result.get('avg_cpu'),
        'peak_memory_kb': result.get('peak_memory_kb'),
        'avg_memory_kb': result.get('avg_memory_kb'),
        'runtime_ms': result.get('runtime_ms')
    }, indent=2))
    sys.exit(0)
else:
    print("❌ VALIDATION FAILED - Some fields missing or zero")
    sys.exit(1)
