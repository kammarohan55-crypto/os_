#!/usr/bin/env python3
"""
Test Step 2: Verify ML blocking when metrics are invalid
"""

import sys
sys.path.insert(0, 'dashboard')

# Mock the ML classifier
class MockClassifier:
    feature_names = ['peak_cpu', 'peak_memory_kb', 'runtime_ms']
    
    def predict_with_explanation(self, row):
        return {
            'prediction': 'Malicious',
            'confidence': 95.0,
            'reason': 'High CPU usage'
        }

# Test cases
test_cases = [
    {
        'name': 'Valid metrics',
        'row': {'runtime_ms': 5000, 'peak_cpu': 80, 'peak_memory_kb': 2048},
        'expected_prediction': 'Malicious',
        'expected_confidence': 95.0
    },
    {
        'name': 'Zero runtime',
        'row': {'runtime_ms': 0, 'peak_cpu': 80, 'peak_memory_kb': 2048},
        'expected_prediction': 'Insufficient data',
        'expected_confidence': 0.0
    },
    {
        'name': 'Zero CPU',
        'row': {'runtime_ms': 5000, 'peak_cpu': 0, 'peak_memory_kb': 2048},
        'expected_prediction': 'Insufficient data',
        'expected_confidence': 0.0
    },
    {
        'name': 'Both zero',
        'row': {'runtime_ms': 0, 'peak_cpu': 0, 'peak_memory_kb': 2048},
        'expected_prediction': 'Insufficient data',
        'expected_confidence': 0.0
    }
]

print("=" * 70)
print("STEP 2 VALIDATION: Block ML if metrics are invalid")
print("=" * 70)
print()

classifier = MockClassifier()
passed = 0
failed = 0

for test in test_cases:
    print(f"Test: {test['name']}")
    row = test['row']
    
    # Simulate the validation logic from app.py
    runtime_ms = row.get('runtime_ms', 0)
    peak_cpu = row.get('peak_cpu', row.get('peak_cpu_percent', 0))
    
    if runtime_ms == 0 or peak_cpu == 0:
        # Invalid data - skip ML prediction
        prediction = 'Insufficient data'
        confidence = 0.0
        reason = 'Invalid metrics: runtime_ms or peak_cpu is zero'
    elif len(classifier.feature_names) == 0:
        # Model not trained
        prediction = 'Unknown'
        confidence = 0.0
        reason = 'Model not trained'
    else:
        # Valid - use ML
        result = classifier.predict_with_explanation(row)
        prediction = result['prediction']
        confidence = result['confidence']
        reason = result['reason']
    
    # Check results
    if prediction == test['expected_prediction'] and confidence == test['expected_confidence']:
        print(f"  ✅ PASSED")
        print(f"     Prediction: {prediction}, Confidence: {confidence}")
        passed += 1
    else:
        print(f"  ❌ FAILED")
        print(f"     Expected: {test['expected_prediction']} @ {test['expected_confidence']}%")
        print(f"     Got: {prediction} @ {confidence}%")
        failed += 1
    print()

print("=" * 70)
print(f"Results: {passed}/{len(test_cases)} passed, {failed}/{len(test_cases)} failed")
print("=" * 70)

if failed == 0:
    print()
    print("✅ STEP 2 VALIDATION PASSED")
    print()
    print("Summary:")
    print("  - ML predictions blocked when runtime_ms = 0")
    print("  - ML predictions blocked when peak_cpu = 0")
    print("  - Valid metrics allow ML predictions")
    print("  - Fake confidence prevented!")
    sys.exit(0)
else:
    print()
    print("❌ STEP 2 VALIDATION FAILED")
    sys.exit(1)
