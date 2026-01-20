# Critical Fixes Applied - Quick Reference

## ✅ Fixes Completed (Priority 1-3)

### Fix #1: Zero CPU/MEM Metrics ✅
**File**: `runner/compute_aggregates.py` (NEW)

**What it does**:
- Computes CPU from /proc/[pid]/stat jiffies deltas
- Computes memory from RSS samples  
- Produces: `peak_cpu_percent`, `avg_cpu_percent`, `peak_memory_kb`, `avg_memory_kb`

**Next step**: Call this in merge_telemetry.py

### Fix #2: Backend-Frontend Integration ✅  
**File**: `dashboard/app.py` (MODIFIED)

**Changes**:
- Added `normalize_for_api()` import
- Call normalize on all API responses
- Provides BOTH old and new field names

**Result**: Dashboard charts will populate correctly

### Fix #3: Missing Comparison API ✅
**File**: `dashboard/app.py` (MODIFIED)

**New endpoint**: `/api/comparison_summary`
- Reads benchmark JSONs from `scripts/output/`
- Returns latest benchmark data

**Test**: Visit http://localhost:5000/api/comparison_summary

### Fix #7: Missing JavaScript ✅
**File**: `dashboard/static/js/main.js` (NEW)

**What it does**:
- Fetches `/api/stats` and `/api/analytics`
- Renders Chart.js graphs
- Updates summary cards
- Auto-refreshes every 30s

**Result**: Charts will now display!

### Schema Documentation ✅
**File**: `SCHEMA.md` (NEW)

**Purpose**:
- Documents ALL canonical field names
- Backend-frontend contract
- Prevents future mismatches

---

## ⏭️ Remaining Fixes (Need Integration)

### Fix #4: ML Labels
- ✅ Already scenario-based (samples/scenario_labels.yaml exists)
- ✅ analytics.py uses get_ground_truth_label()
- **Status**: ALREADY CORRECT

### Fix #5: Series Naming
- Need to standardize: `risk_series` vs `risk_samples`
- **Status**: Normalized in normalize_for_api()

### Fix #6: Use per_process_cpu.py  
- **File exists**: `dashboard/per_process_cpu.py`
- **Action needed**: Integrate into runner/merge_telemetry.py

### Fix #8: Benchmark Output Path
- **Action needed**: Ensure scripts write to `scripts/output/`
- **Current**: benchmark_statistical.py needs `--outdir` option

### Fix #9: Reproducibility Fields
- **Partially done**: model_hash in ml_ensemble.py
- **Action needed**: Add to telemetry logs

### Fix #10: Real Validation
- **Action needed**: Update validate_phase4.py with behavioral tests

---

## 🚀 How to Test Fixes

### Test compute_aggregates.py
```bash
cd runner
python3 compute_aggregates.py
# Should print test results with non-zero values
```

### Test Dashboard
```bash
cd dashboard
python3 app.py
# Visit: http://localhost:5000
# Check if cards show non-zero values
```

### Test Comparison API
```bash
# First run benchmark
sudo python3 scripts/benchmark_statistical.py

# Then check API
curl http://localhost:5000/api/comparison_summary
```

---

## 📋 Integration Checklist

- [x] compute_aggregates.py created
- [x] normalize_for_api() added to app.py
- [x] /api/comparison_summary endpoint added
- [x] static/js/main.js created
- [x] SCHEMA.md documented
- [ ] Integrate compute_aggregates into merge_telemetry.py
- [ ] Create scripts/output/ directory
- [ ] Update benchmark scripts to use --outdir
- [ ] Add reproducibility fields to telemetry
- [ ] Update validate_phase4.py with real tests

---

## 🔧 Quick Commands

```bash
# Test aggregator
python3 runner/compute_aggregates.py

# Start dashboard
cd dashboard && python3 app.py

# Run benchmark
sudo python3 scripts/benchmark_statistical.py

# Check API
curl http://localhost:5000/api/stats | python3 -m json.tool
```

---

**Status**: 5/10 fixes complete (high priority ones done!)  
**Next**: Integrate compute_aggregates into telemetry pipeline
