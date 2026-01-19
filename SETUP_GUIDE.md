# Phase 1 Setup & Testing Guide

## Quick Setup (5 minutes)

### Step 1: Install Dependencies

```bash
cd c:\Users\Rohan\Desktop\os_el\sandbox-project

# Install Python packages
pip install -r requirements.txt
```

**Expected packages:**
- `shap==0.44.0` - ML explainability
- `pyyaml==6.0.1` - Policy engine
- Flask, pandas, numpy, scikit-learn (existing)

### Step 2: Validate Installation

```bash
python validate_phase1.py
```

**Expected output:**
```
✅ All files present
✅ ml_model.ExplainableRiskClassifier
✅ policy_engine.PolicyEngine
✅ pandas
✅ pyyaml
✅ shap (SHAP explanations enabled)
✅ Model initialized
✅ Prediction: Benign (95.2%)
✅ SHAP values present (5 features)
✅ Policy triggered: KILL
```

### Step 3: Test Dashboard

```bash
cd dashboard
python app.py
```

**Open browser:** http://localhost:5000

**You should see:**
- Dark mode dashboard with purple/blue theme
- Risk score hero section (if logs exist)
- Real-time updating charts
- Execution table with ML predictions

### Step 4: Run Sandbox Tests

```bash
# From project root
python run_all_tests.py
```

**This will:**
1. Clean old logs
2. Run 5 test scenarios
3. Generate telemetry JSON files
4. Show CPU usage and metrics

### Step 5: View Results in Dashboard

Keep dashboard running and refresh browser. You should now see:
- Populated risk score
- Timeline charts with data
- ML predictions with SHAP values
- Policy recommendations

---

## Testing Individual Components

### Test ML Model with SHAP

```bash
cd dashboard
python -c "
from ml_model import ExplainableRiskClassifier

clf = ExplainableRiskClassifier()
result = clf.predict_with_explanation({
    'runtime_ms': 5000,
    'peak_cpu': 98,
    'peak_memory_kb': 80000,
    'page_faults_minor': 150,
    'page_faults_major': 5
})

print('Prediction:', result['prediction'])
print('Confidence:', result['confidence'], '%')
print('Reason:', result['reason'])

if 'shap_values' in result:
    print('\\nTop SHAP Features:')
    for feat in result['shap_values']['top_features']:
        print(f\"  - {feat['name']}: {feat['contribution']:+.3f} (value: {feat['value']})\")
"
```

**Expected:**
```
Prediction: Malicious
Confidence: 92.3 %
Reason: High CPU (98%) + Long Runtime (5000ms)

Top SHAP Features:
  - CPU Usage: +0.310 (value: 98)
  - Runtime: +0.245 (value: 5000)
  - Memory Usage: +0.182 (value: 80000)
```

### Test Policy Engine

```bash
cd dashboard
python policy_engine.py
```

**Expected:**
```
[Policy] Loaded policy: Default Adaptive Policy
[Test] Malware scenario triggered 1 action(s):
  - KILL: Critical risk: excessive malicious activity
[Test] Benign scenario triggered 0 action(s)
[Policy] Exported policy to policies/default_policy.yaml
```

### Test REST API

```bash
# Keep dashboard running (python app.py)
# In another terminal:

curl http://localhost:5000/api/stats | python -m json.tool
curl http://localhost:5000/api/analytics | python -m json.tool
curl http://localhost:5000/api/ml | python -m json.tool
```

---

## Troubleshooting

### Issue: "No module named 'numpy'"

**Solution:**
```bash
pip install numpy pandas scikit-learn
```

### Issue: "No module named 'shap'"

**Solution:**
```bash
pip install shap
```

**Note:** SHAP installation may take 2-3 minutes and requires ~500MB disk space.

### Issue: Dashboard shows "No execution data"

**Solution:** Run tests first to generate logs:
```bash
python run_all_tests.py
```

### Issue: Charts not rendering

**Solution:** Check browser console (F12). Ensure Chart.js CDN is accessible.

### Issue: Policy engine errors

**Solution:** Install PyYAML:
```bash
pip install pyyaml
```

---

## Verification Checklist

- [ ] All dependencies installed (`pip list | grep -E "shap|pyyaml"`)
- [ ] Validation script passes (`python validate_phase1.py`)
- [ ] Dashboard loads at http://localhost:5000
- [ ] Tests run successfully (`python run_all_tests.py`)
- [ ] Dashboard shows populated data after tests
- [ ] ML predictions include SHAP values
- [ ] Policy engine runs without errors

---

## What to Look For

### Dashboard Features

1. **Header**
   - Dark background
   - Live indicator pulsing
   - Professional typography

2. **Stats Cards**
   - Total executions count
   - Violations count
   - Average CPU %
   - Average memory

3. **Risk Hero** (appears after running tests)
   - Large risk score number
   - Color-coded verdict (green/yellow/red)
   - Top 3 risk factors with icons

4. **Charts**
   - CPU timeline (blue gradient)
   - Memory timeline (yellow gradient)
   - Exit reason pie chart
   - Policy effectiveness bar chart

5. **Table**
   - Recent executions
   - ML prediction badges
   - Confidence percentages
   - Explanation text

### ML Model Features

- Random Forest with 100 estimators
- SHAP TreeExplainer initialized
- Per-prediction feature attributions
- Human-readable explanations

### Policy Engine Features

- YAML-based rules
- 5 default rules (critical → low risk)
- JSONL audit log at `logs/policy_audit.jsonl`
- Test scenarios for malware/benign

---

## Demo Script (for Presentation)

### Scenario 1: Benign Program (2 minutes)

```bash
./runner/launcher --profile=STRICT /bin/echo "test"
```

**Show in dashboard:**
- Risk score: ~15%
- Verdict: BENIGN (green)
- SHAP: "Short runtime contributed -0.2"

### Scenario 2: CPU Hog (2 minutes)

```bash
./runner/launcher --profile=LEARNING samples/cpu_hog
```

**Show in dashboard:**
- Risk score: ~90%
- Verdict: MALICIOUS (red, pulsing)
- SHAP: "High CPU +0.31, Long Runtime +0.24"
- Process killed by policy adaptation

### Scenario 3: Policy Engine (1 minute)

```bash
cd dashboard
python policy_engine.py
```

**Explain:**
- YAML rules evaluated
- Conditions matched for malware scenario
- KILL action triggered
- Audit logged to JSONL

---

## Next Steps After Phase 1

Once everything is working:

### Option A: Prepare for Demo/Presentation
- Record screen captures
- Create slide deck
- Practice demo script

### Option B: Start Phase 2 (eBPF Integration)
- Install BCC: `apt install bpfcc-tools python3-bpfcc`
- Write eBPF syscall tracer
- Reduce overhead to <1%

### Option C: Write Academic Paper
- Use documentation as foundation
- Add evaluation section
- Submit to USENIX Security or IEEE S&P

---

## Contact & Help

If you encounter issues:
1. Check this guide first
2. Review `docs/architecture.md` for system design
3. Check `logs/` directory for error messages
4. Verify WSL2 has internet access (for CDN resources)

---

**Setup Guide Created:** January 19, 2026  
**Phase:** 1 Complete ✅  
**Status:** Ready for Testing 🚀
