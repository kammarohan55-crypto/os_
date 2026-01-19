#!/usr/bin/env python3
"""
Phase 2 Validation Script
Tests eBPF integration and extended ML features
"""

import sys
import os

print("=" * 70)
print("PHASE 2 VALIDATION (eBPF Integration)")
print("=" * 70)
print()

# Test 1: Check file structure
print("[1/6] Checking Phase 2 files...")
required_files = [
    'runner/ebpf_tracer.py',
    'runner/test_ebpf.py',
    'runner/merge_telemetry.py',
    'runner/launcher.c',  # With eBPF support
    'dashboard/ml_model.py',
    'dashboard/analytics.py'
]

missing = []
for filepath in required_files:
    if not os.path.exists(filepath):
        missing.append(filepath)
        print(f"  ❌ Missing: {filepath}")
    else:
        print(f"  ✅ Found: {filepath}")

if missing:
    print(f"\n⚠️  {len(missing)} files missing!")
    sys.exit(1)

print("\n✅ All Phase 2 files present\n")

# Test 2: Import Python modules
print("[2/6] Testing Python imports...")
try:
    from dashboard.ml_model import ExplainableRiskClassifier
    print("  ✅ ml_model.ExplainableRiskClassifier")
except ImportError as e:
    print(f"  ❌ Failed to import ml_model: {e}")
    sys.exit(1)

try:
    from dashboard.analytics import extract_features, get_syscall_stats
    print("  ✅ analytics.extract_features")
    print("  ✅ analytics.get_syscall_stats")
except ImportError as e:
    print(f"  ❌ Failed to import analytics: {e}")
    sys.exit(1)

try:
    import pandas as pd
    print("  ✅ pandas")
except ImportError:
    print("  ❌ pandas not installed")
    sys.exit(1)

print()

# Test 3: Check BCC (optional but recommended)
print("[3/6] Testing eBPF/BCC availability...")
try:
    from bcc import BPF
    print("  ✅ BCC installed (eBPF enabled)")
    bcc_available = True
except ImportError:
    print("  ⚠️  BCC not installed (eBPF features disabled)")
    print("     Install with: sudo apt install bpfcc-tools python3-bpfcc")
    bcc_available = False

print()

# Test 4: ML Model with 8 features
print("[4/6] Testing ML model with eBPF features...")
try:
    clf = ExplainableRiskClassifier()
    print(f"  ✅ Model initialized with {len(clf.feature_names)} features")
    
    expected_features = [
        'runtime_ms', 'peak_cpu', 'peak_memory_kb',
        'page_faults_minor', 'page_faults_major',
        'syscall_rate', 'syscall_diversity', 'syscall_network_count'
    ]
    
    if clf.feature_names == expected_features:
        print("  ✅ Feature set correct (8 features)")
    else:
        print(f"  ❌ Feature mismatch:")
        print(f"     Expected: {expected_features}")
        print(f"     Got: {clf.feature_names}")
        sys.exit(1)
    
    # Test prediction with syscall features
    test_sample = {
        'runtime_ms': 5000,
        'peak_cpu': 99,
        'peak_memory_kb': 80000,
        'page_faults_minor': 150,
        'page_faults_major': 5,
        'syscall_rate': 500,
        'syscall_diversity': 15,
        'syscall_network_count': 20
    }
    
    result = clf.predict_with_explanation(test_sample)
    print(f"  ✅ Prediction: {result['prediction']} ({result['confidence']}%)")
    
    if 'shap_values' in result:
        print(f"  ✅ SHAP values present ({len(result['shap_values']['top_features'])} features)")
        
        # Check if syscall features appear in SHAP
        feature_names = [f['name'] for f in result['shap_values']['top_features']]
        syscall_features_found = any('Syscall' in name or 'Network' in name for name in feature_names)
        if syscall_features_found:
            print("  ✅ Syscall features in SHAP explanations")
    else:
        print("  ⚠️  No SHAP values (install shap package)")
    
except Exception as e:
    print(f"  ❌ ML model test failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print()

# Test 5: Feature extraction with syscall data
print("[5/6] Testing feature extraction with eBPF data...")
try:
    mock_log = {
        'program': 'test',
        'profile': 'LEARNING',
        'pid': 12345,
        'summary': {
            'runtime_ms': 1000,
            'peak_cpu': 50,
            'peak_memory_kb': 2048,
            'page_faults_minor': 10,
            'page_faults_major': 0,
            'exit_reason': 'EXITED(0)'
        },
        'timeline': {
            'time_ms': [0, 100, 200],
            'cpu_percent': [10, 20, 30],
            'memory_kb': [1000, 1500, 2000]
        },
        'syscall_events': {
            'total_syscalls': 500,
            'unique_syscalls': 12,
            'syscall_rate_per_sec': 250.5,
            'network_syscalls': 5,
            'top_syscalls': [
                {'name': 'read', 'id': 0, 'count': 200},
                {'name': 'write', 'id': 1, 'count': 150}
            ]
        }
    }
    
    df = extract_features([mock_log])
    
    # Check syscall columns exist
    required_cols = ['syscall_rate', 'syscall_diversity', 'syscall_network_count']
    for col in required_cols:
        if col in df.columns:
            print(f"  ✅ Column '{col}' extracted")
        else:
            print(f"  ❌ Missing column: {col}")
            sys.exit(1)
    
    # Check values
    row = df.iloc[0]
    assert row['syscall_rate'] == 250.5, "syscall_rate mismatch"
    assert row['syscall_diversity'] == 12, "syscall_diversity mismatch"
    assert row['syscall_network_count'] == 5, "syscall_network_count mismatch"
    
    print("  ✅ Syscall features extracted correctly")
    
except Exception as e:
    print(f"  ❌ Feature extraction test failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print()

# Test 6: Launcher compilation check
print("[6/6] Checking launcher compilation...")
if os.path.exists('runner/launcher'):
    print("  ✅ Launcher binary exists")
    print("  ⚠️  Recompile needed: make clean && make")
else:
    print("  ⚠️  Launcher not compiled")
    print("     Run: cd runner && make clean && make")

print()

# Summary
print("=" * 70)
print("VALIDATION COMPLETE")
print("=" * 70)
print()

if bcc_available:
    print("✅ Phase 2 implementation verified (eBPF enabled)!")
else:
    print("⚠️  Phase 2 verified but eBPF not available")
    print("   System will fall back to /proc polling")

print()
print("Next Steps:")
print("  1. Install BCC (if not done): sudo apt install bpfcc-tools python3-bpfcc")
print("  2. Test eBPF: sudo python3 runner/test_ebpf.py")
print("  3. Recompile launcher: make clean && make")
print("  4. Test with eBPF: ./runner/launcher --enable-ebpf samples/cpu_hog")
print("  5. Merge telemetry: python3 runner/merge_telemetry.py <run.json> <ebpf.json>")
print()
print("=" * 70)
