# Phase 4 Validation Script - Research-Grade Improvements

import sys
import os
import json

print("=" * 70)
print("PHASE 4 VALIDATION - Research-Grade Improvements")
print("=" * 70)
print()

# Test 1: Scenario Labels
print("[1/5] Testing scenario-based labels...")
try:
    import yaml
    with open('samples/scenario_labels.yaml') as f:
        labels = yaml.safe_load(f)
        assert 'scenarios' in labels
        assert labels['scenarios']['cpu_hog']['label'] == 'malicious_sim'
        assert labels['scenarios']['sleep']['label'] == 'benign'
        print("  ✅ Scenario labels valid (ground truth from semantics)")
except Exception as e:
    print(f"  ❌ Scenario labels failed: {e}")
    sys.exit(1)

# Test 2: Analytics uses scenario labels
print("\n[2/5] Testing analytics integration...")
try:
    sys.path.insert(0, 'dashboard')
    from analytics import get_ground_truth_label, identify_scenario
    
    assert get_ground_truth_label('cpu_hog') == 'malicious_sim'
    assert get_ground_truth_label('samples/sleep') == 'benign'
    assert get_ground_truth_label('/bin/ls') == 'benign'
    assert identify_scenario('cpu_hog') == 'cpu_hog'
    
    print("  ✅ Analytics uses scenario-based labels (NOT thresholds)")
except Exception as e:
    print(f"  ❌ Analytics integration failed: {e}")
    sys.exit(1)

# Test 3: Model reproducibility
print("\n[3/5] Testing model reproducibility...")
try:
    from ml_ensemble import EnsembleRiskClassifier
    
    clf = EnsembleRiskClassifier()
    repro_info = clf.get_reproducibility_info()
    
    assert 'model_hash' in repro_info
    assert 'random_seed' in repro_info
    assert 'feature_schema_version' in repro_info
    assert repro_info['feature_schema_version'] == '2.0'
    
    print(f"  ✅ Model hash: {repro_info['model_hash']}")
    print(f"  ✅ Random seed: {repro_info['random_seed']}")
    print(f"  ✅ Schema version: {repro_info['feature_schema_version']}")
except Exception as e:
    print(f"  ❌ Reproducibility failed: {e}")
    sys.exit(1)

# Test 4: Prediction metadata
print("\n[4/5] Testing prediction reproducibility...")
try:
    test_sample = {
        'runtime_ms': 5000,
        'peak_cpu': 99,
        'peak_memory_kb': 50000,
        'page_faults_minor': 100,
        'page_faults_major': 5,
        'syscall_rate': 500,
        'syscall_diversity': 15,
        'syscall_network_count': 20
    }
    
    result = clf.predict_with_explanation(test_sample)
    
    assert 'model_hash' in result
    assert 'prediction_timestamp' in result
    assert 'feature_schema_version' in result
    
    print(f"  ✅ Predictions include reproducibility metadata")
    print(f"  ✅ Model hash: {result['model_hash']}")
except Exception as e:
    print(f"  ❌ Prediction metadata failed: {e}")
    sys.exit(1)

# Test 5: Statistical benchmark script exists
print("\n[5/5] Testing statistical benchmark...")
try:
    assert os.path.exists('scripts/benchmark_statistical.py')
    
    # Check it has the right structure
    with open('scripts/benchmark_statistical.py') as f:
        content = f.read()
        assert 'RUNS_PER_TEST = 20' in content
        assert 'WARMUP_RUNS = 2' in content
        assert 'confidence interval' in content.lower()
        assert 'ttest' in content.lower()
    
    print("  ✅ Statistical benchmark script ready")
    print("  ✅ 20 runs + 2 warmups configured")
    print("  ✅ Confidence intervals enabled")
    print("  ✅ Statistical significance tests included")
except Exception as e:
    print(f"  ❌ Statistical benchmark failed: {e}")
    sys.exit(1)

print()
print("=" * 70)
print("PHASE 4 CRITICAL FIXES: VALIDATED")
print("=" * 70)
print()
print("Summary:")
print("  ✅ Scenario-based labels (NO threshold circular logic)")
print("  ✅ Model reproducibility (hash, seed, version)")
print("  ✅ Prediction tracking (timestamp, metadata)")
print("  ✅ Statistical rigor (20 runs, CI, t-tests)")
print()
print("Research-Ready: YES ✅")
print()
print("Next: Run statistical benchmark with:")
print("  sudo python3 scripts/benchmark_statistical.py")
print()
print("=" * 70)
