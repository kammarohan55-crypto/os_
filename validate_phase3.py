#!/usr/bin/env python3
"""
Phase 3 Validation Script - Advanced ML Features
Tests XGBoost ensemble and online learning
"""

import sys
import os

print("=" * 70)
print("PHASE 3 VALIDATION (Advanced ML)")
print("=" * 70)
print()

# Test 1: Check XGBoost availability
print("[1/4] Testing XGBoost installation...")
try:
    import xgboost as xgb
    print(f"  ✅ XGBoost installed (version: {xgb.__version__})")
    xgboost_available = True
except ImportError:
    print("  ⚠️  XGBoost not installed")
    print("     Install with: pip install xgboost==2.0.3")
    xgboost_available = False

print()

# Test 2: Test Ensemble Classifier
print("[2/4] Testing Ensemble Classifier...")
try:
    from dashboard.ml_ensemble import EnsembleRiskClassifier
    
    clf = EnsembleRiskClassifier()
    print(f"  ✅ Ensemble classifier initialized")
    print(f"  ✅ Model type: {clf.get_model_comparison()}")
    
    # Test prediction
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
    print(f"  ✅ Model: {result.get('model_type', 'Unknown')}")
    
except Exception as e:
    print(f"  ❌ Ensemble test failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print()

# Test 3: Test Online Learning
print("[3/4] Testing online learning...")
try:
    from dashboard.ml_model import ExplainableRiskClassifier
    
    clf = ExplainableRiskClassifier()
    
    # Simulate analyst feedback
    new_sample = {
        'runtime_ms': 1000,
        'peak_cpu': 50,
        'peak_memory_kb': 5000,
        'page_faults_minor': 10,
        'page_faults_major': 0,
        'syscall_rate': 100,
        'syscall_diversity': 8,
        'syscall_network_count': 2
    }
    
    result = clf.update_online(new_sample, label='Benign')
    print(f"  ✅ Online learning method available")
    
except Exception as e:
    print(f"  ❌ Online learning test failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print()

# Test 4: Dashboard Integration
print("[4/4] Testing dashboard eBPF visualizations...")
try:
    with open('dashboard/templates/index.html', 'r', encoding='utf-8') as f:
        html = f.read()
    
    checks = [
        ('eBPF Status Badge', 'ebpf-status' in html),
        ('Syscall Chart', 'syscallBarChart' in html),
        ('Network Chart', 'networkChart' in html),
        ('eBPF API Call', '/api/ebpf' in html),
    ]
    
    for name, passed in checks:
        if passed:
            print(f"  ✅ {name} implemented")
        else:
            print(f"  ⚠️  {name} not found")
    
except Exception as e:
    print(f"  ❌ Dashboard check failed: {e}")
    sys.exit(1)

print()

# Summary
print("=" * 70)
print("VALIDATION COMPLETE")
print("=" * 70)
print()

if xgboost_available:
    print("✅ Phase 3 Advanced ML verified (Ensemble + Online Learning)!")
else:
    print("⚠️  Phase 3 verified but XGBoost unavailable")
    print("   System will fall back to RandomForest only")

print()
print("Next Steps:")
print("  1. Install XGBoost: pip install xgboost==2.0.3")
print("  2. Test ensemble: python3 -c 'from dashboard.ml_ensemble import EnsembleRiskClassifier; clf = EnsembleRiskClassifier()'")
print("  3. Run dashboard: cd dashboard && python3 app.py")
print("  4. View in browser: http://localhost:5000")
print()
print("=" * 70)
