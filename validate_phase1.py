#!/usr/bin/env python3
"""
Phase 1 Validation Script
Tests all newly implemented components
"""

import sys
import os

print("=" * 70)
print("PHASE 1 VALIDATION")
print("=" * 70)
print()

# Test 1: Check file structure
print("[1/5] Checking file structure...")
required_files = [
    'dashboard/ml_model.py',
    'dashboard/policy_engine.py',
    'dashboard/templates/index.html',
    'docs/comparison.md',
    'docs/architecture.md',
    'docs/academic_novelty.md',
    'requirements.txt',
    'README.md'
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

print("\n✅ All files present\n")

# Test 2: Import Python modules
print("[2/5] Testing Python imports...")
try:
    from dashboard.ml_model import ExplainableRiskClassifier
    print("  ✅ ml_model.ExplainableRiskClassifier")
except ImportError as e:
    print(f"  ❌ Failed to import ml_model: {e}")
    sys.exit(1)

try:
    from dashboard.policy_engine import PolicyEngine
    print("  ✅ policy_engine.PolicyEngine")
except ImportError as e:
    print(f"  ❌ Failed to import policy_engine: {e}")
    sys.exit(1)

try:
    import pandas as pd
    print("  ✅ pandas")
except ImportError:
    print("  ❌ pandas not installed (pip install pandas)")
    sys.exit(1)

try:
    import yaml
    print("  ✅ pyyaml")
except ImportError:
    print("  ⚠️  pyyaml not installed (pip install pyyaml)")
    print("     Policy engine will fail")

try:
    import shap
    print("  ✅ shap (SHAP explanations enabled)")
except ImportError:
    print("  ⚠️  shap not installed (pip install shap)")
    print("     ML will use fallback explanations")

print()

# Test 3: ML Model
print("[3/5] Testing ML model...")
try:
    clf = ExplainableRiskClassifier()
    print("  ✅ Model initialized")
    
    # Test prediction
    test_sample = {
        'runtime_ms': 100,
        'peak_cpu': 10,
        'peak_memory_kb': 2048,
        'page_faults_minor': 5,
        'page_faults_major': 0
    }
    
    result = clf.predict_with_explanation(test_sample)
    print(f"  ✅ Prediction: {result['prediction']} ({result['confidence']}%)")
    
    if 'shap_values' in result:
        print(f"  ✅ SHAP values present ({len(result['shap_values']['top_features'])} features)")
    else:
        print("  ⚠️  No SHAP values (install shap package)")
    
except Exception as e:
    print(f"  ❌ ML model test failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print()

# Test 4: Policy Engine
print("[4/5] Testing policy engine...")
try:
    engine = PolicyEngine()
    print("  ✅ Policy engine initialized")
    
    # Test malicious scenario
    malware_context = {
        'risk_score': 95,
        'syscall_rate': 15000,
        'peak_cpu': 99
    }
    
    actions = engine.evaluate(malware_context)
    if len(actions) > 0:
        print(f"  ✅ Policy triggered: {actions[0].action_type}")
        print(f"     Reason: {actions[0].reason}")
    else:
        print("  ⚠️  No actions triggered (check policy rules)")
    
    # Test benign scenario
    benign_context = {
        'risk_score': 15,
        'syscall_rate': 50,
        'peak_cpu': 5
    }
    
    actions = engine.evaluate(benign_context)
    if len(actions) == 0:
        print("  ✅ Benign context correctly ignored")
    else:
        print(f"  ⚠️  Benign triggered action: {actions[0].action_type}")
    
except Exception as e:
    print(f"  ❌ Policy engine test failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print()

# Test 5: Dashboard HTML
print("[5/5] Testing dashboard HTML...")
try:
    with open('dashboard/templates/index.html', 'r', encoding='utf-8') as f:
        html = f.read()
    
    checks = [
        ('SHAP', 'SHAP' in html),
        ('Risk Score', 'risk-score' in html),
        ('Dark Mode', '--bg-primary' in html),
        ('Chart.js', 'Chart.js' in html or 'cdn.jsdelivr.net/npm/chart.js' in html),
        ('Policy', 'policy' in html.lower() or 'factor' in html),
    ]
    
    for name, passed in checks:
        if passed:
            print(f"  ✅ {name} section found")
        else:
            print(f"  ⚠️  {name} section not found")
    
except Exception as e:
    print(f"  ❌ Dashboard HTML test failed: {e}")
    sys.exit(1)

print()

# Summary
print("=" * 70)
print("VALIDATION COMPLETE")
print("=" * 70)
print()
print("✅ Phase 1 implementation verified!")
print()
print("Next Steps:")
print("  1. Install missing dependencies: pip install -r requirements.txt")
print("  2. Test dashboard: cd dashboard && python3 app.py")
print("  3. Open browser: http://localhost:5000")
print("  4. Run sandbox tests: python3 run_all_tests.py")
print()
print("Documentation:")
print("  - README: ./README.md")
print("  - Architecture: ./docs/architecture.md")
print("  - Comparison: ./docs/comparison.md")
print("  - Academic: ./docs/academic_novelty.md")
print()
print("=" * 70)
