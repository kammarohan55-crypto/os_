# Data Schema Reference

## Canonical Field Names and Types

This document defines the **single source of truth** for all data structures used in the OS Sandbox project.

**Purpose**: Prevent backend-frontend mismatches and ensure consistent data contracts.

---

## 1. Telemetry Log (Raw)

**File**: `logs/run_XXX.json`

```json
{
  "program": "string",           // Program path
  "pid": "integer",               // Process ID
  "start_ts": "float",            // Unix timestamp (seconds)
  "end_ts": "float",              // Unix timestamp (seconds)
  "runtime_ms": "integer",        // Computed: (end_ts - start_ts) * 1000
  
  // Raw samples (from runner/telemetry.c)
  "stat_samples": [
    {
      "utime": "integer",         // User mode jiffies
      "stime": "integer",         // Kernel mode jiffies
      "ts": "float"               // Sample timestamp
    }
  ],
  
  "mem_samples": [
    {
      "rss_kb": "integer",        // Resident set size in KB
      "ts": "float"               // Sample timestamp
    }
  ],
  
  // Computed aggregates (from runner/compute_aggregates.py)
  "cpu_used_seconds": "float",    // Total CPU time
  "cpu_percent": "float",         // Average CPU %
  "peak_cpu_percent": "float",    // Peak CPU %
  "avg_cpu_percent": "float",     // Alias for cpu_percent
  
  "peak_memory_kb": "integer",    // Peak RSS
  "avg_memory_kb": "integer",     // Average RSS
  "peak_mem_kb": "integer",       // Legacy alias
  "avg_mem_kb": "integer",        // Legacy alias
  
  // eBPF syscall telemetry
  "syscall_events": {
    "total_syscalls": "integer",
    "unique_syscalls": "integer",
    "syscall_rate_per_sec": "float",
    "network_syscalls": "integer",
    "blocked_syscalls": "integer"
  },
  
  // ML prediction
  "prediction": "string",         // "Benign" | "Malicious" | "Suspicious"
  "confidence": "float",          // 0-100
  "reason": "string",             // Explanation
  "model_hash": "string",         // Reproducibility
  "feature_schema_version": "string"
}
```

---

## 2. API Response Format

### `/api/stats`

```json
{
  "total_runs": "integer",
  "avg_cpu": "float",             // Average across all runs
  "avg_mem": "integer",           // Average memory (KB)
  
  "runs": [
    {
      // All fields from Telemetry Log above
      // PLUS normalized fields for backward compatibility:
      
      "cpu_avg": "float",         // = cpu_percent
      "cpu_peak": "float",        // = peak_cpu_percent
      "mem_avg": "integer",       // = avg_memory_kb
      "mem_peak": "integer",      // = peak_memory_kb
      
      // Series data
      "risk_series": "array",     // Timeline of risk scores
      "cpu_series": "array",      // Timeline of CPU %
      "risk_samples": "array"     // Alias for risk_series
    }
  ]
}
```

### `/api/analytics`

```json
{
  "benign_count": "integer",
  "malicious_count": "integer",
  "suspicious_count": "integer",
  "total_samples": "integer",
  
  "avg_cpu_by_label": {
    "Benign": "float",
    "Malicious": "float"
  },
  
  "avg_mem_by_label": {
    "Benign": "integer",
    "Malicious": "integer"
  }
}
```

### `/api/ebpf`

```json
{
  "ebpf_enabled": "boolean",
  "total_syscalls": "integer",
  "unique_syscalls": "integer",
  "blocked_syscalls": "integer",
  
  "syscall_stats": {
    "avg_rate": "float",
    "avg_diversity": "float",
    "total_network_calls": "integer"
  },
  
  "top_syscalls": [
    {
      "name": "string",
      "count": "integer"
    }
  ]
}
```

### `/api/comparison_summary`

```json
{
  "metadata": {
    "runs_per_test": "integer",
    "random_seed": "integer"
  },
  
  "results": {
    "ours_ebpf": {
      "mean": "float",
      "std": "float",
      "ci_lower": "float",
      "ci_upper": "float"
    },
    "native": { /* same structure */ },
    "firejail": { /* same structure */ }
  }
}
```

---

## 3. Feature DataFrame (ML Input)

**Used by**: `dashboard/analytics.py`, `dashboard/ml_model.py`

```python
{
  "program": str,
  "scenario": str,               # From scenario_labels.yaml
  "runtime_ms": int,
  "peak_cpu": float,             # peak_cpu_percent
  "peak_memory_kb": int,
  "page_faults_minor": int,
  "page_faults_major": int,
  "exit_reason": str,
  
  # eBPF features
  "syscall_rate": float,
  "syscall_diversity": int,
  "syscall_network_count": int,
  "total_syscalls": int,
  
  # Ground truth
  "true_label": str              # From YAML, NOT from thresholds!
}
```

---

## 4. Scenario Labels (Ground Truth)

**File**: `samples/scenario_labels.yaml`

```yaml
scenarios:
  cpu_hog:
    label: malicious_sim
    description: "CPU exhaustion attack"
    threat_type: resource_exhaustion
    
  sleep:
    label: benign
    description: "Benign sleep syscall"
    threat_type: null
```

**Critical**: Labels must be scenario-based, NOT threshold-based!

---

## 5. Reproducibility Metadata

All ML predictions must include:

```json
{
  "model_hash": "string",         // SHA-256 of model params
  "random_seed": "integer",       // 42
  "feature_schema_version": "string",  // "2.0"
  "prediction_timestamp": "string",    // ISO 8601 UTC
  "clock_ticks_per_sec": "integer"     // sysconf(_SC_CLK_TCK)
}
```

---

## 6. Backward Compatibility Rules

**Always provide BOTH old and new names**:

| New Name | Legacy Aliases |
|----------|---------------|
| `peak_cpu_percent` | `cpu_peak`, `cpu_avg` |
| `peak_memory_kb` | `mem_peak`, `peak_mem_kb` |
| `avg_memory_kb` | `mem_avg`, `avg_mem_kb` |
| `risk_series` | `risk_samples` |
| `cpu_series` | `cpu_samples` |

**Normalization**: Use `compute_aggregates.normalize_for_api()` before returning JSON.

---

## 7. Common Mistakes to Avoid

❌ **DON'T**:
- Mix up `peak_cpu` (legacy) vs `peak_cpu_percent` (canonical)
- Assign labels from feature thresholds (circular logic!)
- Return only new names without legacy aliases
- Forget to compute aggregates from raw samples

✅ **DO**:
- Always call `compute_aggregates_for_log()` before saving JSON
- Use `normalize_for_api()` in all API responses
- Get labels from `scenario_labels.yaml`
- Include reproducibility metadata

---

## 8. Testing Data Contract

```bash
# Test that aggregates are computed
python3 -c "
import json
with open('logs/run_001.json') as f:
    log = json.load(f)
    assert 'peak_cpu_percent' in log, 'Missing peak_cpu_percent'
    assert log['peak_cpu_percent'] > 0, 'CPU metrics are zero!'
    assert 'peak_memory_kb' in log, 'Missing peak_memory_kb'
    print('✓ Schema valid')
"
```

---

**Version**: 2.0  
**Last Updated**: Phase 4 Critical Fixes  
**Maintained By**: Integration Team
