#!/usr/bin/env python3
"""
Complete Test Suite for OS Sandbox
Shows CPU usage and all metrics clearly
"""

import subprocess
import json
import os
import time
from pathlib import Path

PROJECT_ROOT = "/mnt/c/Users/Rohan/Desktop/os_el/sandbox-project"
os.chdir(PROJECT_ROOT)

print("=" * 60)
print("OS SANDBOX - COMPLETE TEST SUITE")
print("=" * 60)
print()

# Clean old logs
print("🧹 Cleaning old logs...")
for log in Path("logs").glob("*.json"):
    log.unlink()
print()

# Test cases
tests = [
    {
        "name": "Normal Execution (STRICT)",
        "profile": "STRICT",
        "binary": "/bin/echo",
        "args": ["test"],
        "expected": "Quick execution, low CPU"
    },
    {
        "name": "List Files (LEARNING)",
        "profile": "LEARNING",
        "binary": "/bin/ls",
        "args": ["-la"],
        "expected": "Normal CPU usage"
    },
    {
        "name": "Short Sleep (STRICT)",
        "profile": "STRICT",
        "binary": "/bin/sleep",
        "args": ["0.3"],
        "expected": "Very low CPU (sleeping)"
    },
    {
        "name": "CPU Hog (LEARNING)",
        "profile": "LEARNING",
        "binary": "samples/cpu_hog",
        "args": [],
        "expected": "High CPU, will be killed"
    },
    {
        "name": "Fork Bomb (STRICT)",
        "profile": "STRICT",
        "binary": "samples/fork_bomb",
        "args": [],
        "expected": "Blocked by seccomp"
    },
]

print("🧪 Running Tests...")
print()

for i, test in enumerate(tests, 1):
    print(f"[{i}/{len(tests)}] {test['name']}")
    print(f"    Expected: {test['expected']}")
    
    cmd = [
        "./runner/launcher",
        f"--profile={test['profile']}",
        test['binary']
    ] + test['args']
    
    try:
        subprocess.run(cmd, timeout=5, capture_output=True)
    except subprocess.TimeoutExpired:
        print("    ⚠️  Timeout (expected for CPU hog)")
    except Exception as e:
        print(f"    ⚠️  {e}")
    
    time.sleep(0.5)
    print()

# Analyze results
print("=" * 60)
print("RESULTS SUMMARY")
print("=" * 60)
print()

logs = sorted(Path("logs").glob("*.json"), key=lambda x: x.stat().st_mtime)
print(f"📊 Total Logs Created: {len(logs)}")
print()

if logs:
    print("📈 CPU Usage Per Test:")
    print("-" * 80)
    print(f"{'Program':<20} | {'Profile':<12} | {'CPU %':>6} | {'Runtime':>8} | {'Exit Reason':<20}")
    print("-" * 80)
    
    for log_file in logs:
        with open(log_file) as f:
            data = json.load(f)
        
        program = Path(data.get('program', 'unknown')).name
        profile = data.get('profile', 'UNKNOWN')
        summary = data.get('summary', {})
        peak_cpu = summary.get('peak_cpu', 0)
        runtime = summary.get('runtime_ms', 0)
        exit_reason = summary.get('exit_reason', 'UNKNOWN')[:20]
        
        print(f"{program:<20} | {profile:<12} | {peak_cpu:>5}% | {runtime:>6}ms | {exit_reason:<20}")
    
    print()
    
    # Show detailed view of latest
    print("=" * 60)
    print("DETAILED VIEW: Latest Run with Timeline")
    print("=" * 60)
    print()
    
    with open(logs[-1]) as f:
        latest = json.load(f)
    
    print(f"Program: {latest.get('program')}")
    print(f"Profile: {latest.get('profile')}")
    print(f"PID: {latest.get('pid')}")
    print()
    
    timeline = latest.get('timeline', {})
    samples = len(timeline.get('time_ms', []))
    print(f"Timeline Samples: {samples}")
    
    if samples > 0:
        print()
        print("CPU % Over Time:")
        cpu_timeline = timeline.get('cpu_percent', [])[:10]  # First 10 samples
        time_timeline = timeline.get('time_ms', [])[:10]
        
        for t, cpu in zip(time_timeline, cpu_timeline):
            bar = '█' * (cpu // 5)  # Visual bar
            print(f"  {t:>4}ms: {cpu:>3}% {bar}")
        
        if samples > 10:
            print(f"  ... ({samples - 10} more samples)")
    
    print()
    print("Summary:")
    summary = latest.get('summary', {})
    print(f"  Runtime: {summary.get('runtime_ms')}ms")
    print(f"  Peak CPU: {summary.get('peak_cpu')}%")
    print(f"  Peak Memory: {summary.get('peak_memory_kb')}KB")
    print(f"  Page Faults (minor): {summary.get('page_faults_minor')}")
    print(f"  Page Faults (major): {summary.get('page_faults_major')}")
    print(f"  Exit Reason: {summary.get('exit_reason')}")
    print()

print("=" * 60)
print("NEXT STEPS")
print("=" * 60)
print()
print("1. Start Dashboard:")
print("   cd dashboard && python3 app.py")
print()
print("2. Open Browser:")
print("   http://localhost:5000")
print()
print("3. Test API:")
print("   curl -s http://localhost:5000/api/stats | python3 -m json.tool")
print()
print("✅ All tests complete!")
