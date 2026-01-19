# System Architecture - Research-Grade OS Sandbox

## Overview

This document describes the architecture of a research-grade behavioral malware analysis sandbox that combines OS-level isolation, explainable machine learning, and dynamic policy adaptation.

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        USER INTERFACE LAYER                      │
│  ┌──────────────────┐  ┌──────────────────┐  ┌───────────────┐ │
│  │ Premium Dashboard│  │  REST API        │  │  CLI Tools    │ │
│  │ (React + D3.js)  │  │  (Flask)         │  │               │ │
│  └──────────────────┘  └──────────────────┘  └───────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      ANALYTICS LAYER                             │
│  ┌──────────────────┐  ┌──────────────────┐  ┌───────────────┐ │
│  │ ML Risk Scoring  │  │ SHAP Explainer   │  │ Policy Engine │ │
│  │ (Random Forest)  │  │ (Feature Attr.)  │  │ (YAML Rules)  │ │
│  └──────────────────┘  └──────────────────┘  └───────────────┘ │
│  ┌──────────────────┐  ┌──────────────────┐  ┌───────────────┐ │
│  │ Feature Extract. │  │ Active Learning  │  │ Audit Logger  │ │
│  │ (Pandas)         │  │ (Uncertainty)    │  │ (JSONL)       │ │
│  └──────────────────┘  └──────────────────┘  └───────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      TELEMETRY LAYER                             │
│  ┌──────────────────┐  ┌──────────────────┐  ┌───────────────┐ │
│  │ Telemetry Coll.  │  │ Time-Series DB   │  │ Log Parser    │ │
│  │ (/proc polling)  │  │ (JSON files)     │  │               │ │
│  └──────────────────┘  └──────────────────┘  └───────────────┘ │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ FUTURE: eBPF Programs (syscall, sched, network tracing)  │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      ISOLATION LAYER                             │
│  ┌──────────────────┐  ┌──────────────────┐  ┌───────────────┐ │
│  │ Namespace Isol.  │  │ Seccomp Filters  │  │ Cgroups v2    │ │
│  │ (PID, NET, MNT)  │  │ (Syscall Block)  │  │ (CPU, Mem)    │ │
│  └──────────────────┘  └──────────────────┘  └───────────────┘ │
│  ┌──────────────────┐  ┌──────────────────┐  ┌───────────────┐ │
│  │ Read-Only Root   │  │ Resource Limits  │  │ Process Mon.  │ │
│  │ (mount --bind)   │  │ (rlimit)         │  │ (waitpid)     │ │
│  └──────────────────┘  └──────────────────┘  └───────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                  ┌───────────────────────┐
                  │  UNTRUSTED BINARY     │
                  │  (sandboxed process)  │
                  └───────────────────────┘
```

---

## Component Descriptions

### 1. Isolation Layer (C)

**Files:** `runner/launcher.c`, `runner/telemetry.c`, `policies/seccomp_rules.h`

**Responsibilities:**
- Create isolated execution environment using `clone()` with namespaces
- Apply seccomp BPF filters to block dangerous syscalls
- Set resource limits via `cgroups` and `rlimit`
- Mount read-only root filesystem
- Monitor child process with `waitpid(WNOHANG)`

**OS Concepts Demonstrated:**
1. **Process Management:** `clone()`, `fork()`, `exec()`, process states
2. **Memory Management:** Virtual memory, address space limits, OOM handling
3. **CPU Scheduling:** cgroups CPU quotas, nice values
4. **System Calls:** seccomp BPF filtering, audit logging
5. **File System:** Mount namespaces, read-only bind mounts, overlayfs
6. **IPC:** IPC namespace isolation

**Key Algorithms:**
- **Polling Loop:** 100ms sampling with `waitpid(WNOHANG)` for non-blocking wait
- **Metrics Collection:** Parse `/proc/[pid]/stat` for CPU ticks, memory, page faults
- **Dynamic Adaptation:** Kill process if CPU ticks > threshold (LEARNING mode)

---

### 2. Telemetry Layer (C + Python)

**Files:** `runner/telemetry.c`, `dashboard/analytics.py`

**Current Implementation:**
- C program collects metrics every 100ms:
  - CPU usage (calculated from ticks and wall time)
  - Memory usage (VmHWM from `/proc/[pid]/status`)
  - Page faults (minor/major from `/proc/[pid]/stat`)
  - Exit reason (signal, exit code, seccomp violation)
- Writes JSON timeline to `logs/run_<pid>_<timestamp>.json`

**Planned eBPF Enhancement (Phase 2):**
```c
// BPF program attached to tracepoint:raw_syscalls:sys_enter
int trace_syscall(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    if (!is_sandboxed_pid(pid)) return 0;
    
    struct syscall_event evt = {
        .pid = pid,
        .syscall_nr = ctx->orig_ax,
        .timestamp_ns = bpf_ktime_get_ns()
    };
    
    events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}
```

**Benefits of eBPF:**
- <1% overhead (vs. 5% for /proc polling)
- Sub-millisecond granularity
- Kernel-space filtering (no context switches)

---

### 3. Analytics Layer (Python)

**Files:** `dashboard/analytics.py`, `dashboard/ml_model.py`, `dashboard/policy_engine.py`

#### Feature Engineering

**Raw logs → Flat DataFrame:**

| program | profile | pid | runtime_ms | peak_cpu | peak_memory_kb | page_faults_minor | page_faults_major | exit_reason | sample_count | avg_cpu | cpu_variance | memory_growth_rate |
|---------|---------|-----|------------|----------|----------------|-------------------|-------------------|-------------|--------------|---------|--------------|-------------------|
| /bin/echo | STRICT | 1234 | 45 | 2 | 184 | 0 | 0 | EXITED(0) | 1 | 2 | 0.0 | 0.0 |
| cpu_hog | LEARNING | 1235 | 5100 | 99 | 892 | 150 | 0 | POLICY_ADAPTATION_KILL | 51 | 98 | 1.2 | 5.2 |

**Features Extracted:**
- `runtime_ms`: Total execution time
- `peak_cpu`: Max CPU% observed
- `peak_memory_kb`: Max memory footprint
- `avg_cpu`: Mean CPU over timeline
- `cpu_variance`: Variance in CPU usage (detects spikes)
- `memory_growth_rate`: KB/sample (detects memory leaks)
- `sample_count`: Number of telemetry samples

#### ML Model (Random Forest + SHAP)

**Training:**
- Seed data (8 samples) provides cold start
- Real execution logs auto-labeled based on exit_reason:
  - `VIOLATION` → Malicious
  - `KILL` / `ADAPTATION` → Malicious
  - `EXITED(0)` → Benign
  - High CPU + Long Runtime → Malicious
  - Others → Suspicious

**Prediction with Explainability:**
```json
{
  "prediction": "Malicious",
  "confidence": 87.2,
  "reason": "High CPU + Long Runtime + Network Connections",
  "shap_values": {
    "top_features": [
      {"name": "CPU Usage", "contribution": 0.31, "value": 98},
      {"name": "Runtime", "contribution": 0.24, "value": 5100},
      {"name": "Memory Usage", "contribution": 0.18, "value": 512000}
    ],
    "base_value": 0.12
  }
}
```

**SHAP Integration:**
- `TreeExplainer` for fast computation on RandomForest
- Waterfall plot shows cumulative feature contributions
- Force plot shows push toward benign/malicious

#### Policy Engine

**Rule Format (YAML):**
```yaml
rules:
  - name: "Critical Risk - Kill"
    condition:
      risk_score: {gte: 90}
      or:
        - syscall_rate: {gte: 10000}
        - peak_cpu: {gte: 95}
    actions:
      - type: KILL
        reason: "Critical risk detected"
```

**Actions Supported:**
1. **KILL:** Send SIGKILL to process
2. **THROTTLE_CPU:** Update `cgroup.cpu.max`
3. **RESTRICT_NETWORK:** iptables DROP rules
4. **TIGHTEN_SECCOMP:** Switch to stricter filter (requires restart)
5. **ALERT:** Log to audit trail

---

### 4. User Interface Layer

#### Dashboard (HTML + Chart.js)

**Components:**
- **Risk Score Hero:** Large circular gauge with verdict
- **Top Risk Factors:** SHAP top-3 contributions
- **Timeline Charts:** CPU and Memory over time (Chart.js line charts)
- **Distribution Charts:** Exit reasons (doughnut), Policy effectiveness (bar)
- **Execution Table:** Paginated list with ML predictions

**Design Principles:**
- Dark mode for security analysts
- Glassmorphism for modern aesthetic
- Inter font for readability
- Real-time updates every 2 seconds

#### REST API (Flask)

**Endpoints:**
- `GET /api/stats` → Summary + enriched runs with ML predictions
- `GET /api/analytics` → Detailed statistics by profile, exit reason
- `GET /api/ml` → Model info + recent predictions

**Future Endpoints (Phase 2):**
- `POST /api/label` → Submit analyst label for active learning
- `GET /api/shap/<run_id>` → Full SHAP explanation with plots
- `GET /api/policy/audit` → Policy enforcement history

---

## Data Flow Example

### Scenario: CPU-Intensive Malware

**Step 1: Execution**
```bash
./runner/launcher --profile=LEARNING samples/cpu_hog
```

**Step 2: Isolation**
- `clone()` creates new PID/IPC/MNT/UTS/USER namespaces
- Seccomp filter blocks fork/clone (configured in LEARNING mode)
- cgroups limit CPU to 100% of 1 core, memory to 128MB
- Root filesystem remounted read-only

**Step 3: Telemetry**
- Parent process polls every 100ms:
  - Reads `/proc/[pid]/stat` → CPU ticks
  - Reads `/proc/[pid]/status` → VmHWM
  - Calculates CPU% = (ticks / wall_time) * 100
- Samples stored in timeline array:
  ```json
  {
    "timeline": {
      "time_ms": [0, 100, 200, ..., 5000],
      "cpu_percent": [0, 45, 89, 98, 99, ...],
      "memory_kb": [180, 200, 220, ..., 892]
    }
  }
  ```

**Step 4: Dynamic Adaptation**
- At t=2000ms, CPU ticks > threshold
- Launcher detects risk, sends SIGKILL
- Sets `exit_reason = "POLICY_ADAPTATION_KILL"`

**Step 5: Log Export**
```json
{
  "program": "samples/cpu_hog",
  "profile": "LEARNING",
  "pid": 1235,
  "summary": {
    "runtime_ms": 5100,
    "peak_cpu": 99,
    "peak_memory_kb": 892,
    "exit_reason": "POLICY_ADAPTATION_KILL"
  },
  "timeline": { ... }
}
```

**Step 6: Feature Extraction (Python)**
- `analytics.py` reads all logs in `logs/` directory
- Extracts features:
  ```python
  {
    'runtime_ms': 5100,
    'peak_cpu': 99,
    'avg_cpu': 98,
    'cpu_variance': 1.2,
    'memory_growth_rate': 5.2
  }
  ```

**Step 7: ML Prediction**
- RandomForest predicts: **Malicious** (confidence: 92%)
- SHAP attributes: `peak_cpu: +0.41`, `runtime_ms: +0.28`

**Step 8: Policy Evaluation**
- Policy engine evaluates: `risk_score=92, peak_cpu=99`
- Matches rule: "Critical Risk - Kill"
- Action logged to audit trail

**Step 9: Dashboard Display**
- API endpoint `/api/stats` returns enriched data
- Dashboard shows:
  - Risk score: 92
  - Verdict: ⚠️ MALICIOUS
  - Top factor: "High CPU (99%) contributed +0.41 to risk"
  - Timeline chart with spike at t=200ms

---

## Key Design Decisions

### Why Namespaces Over VMs?

**Trade-off:** Security vs. Performance

- **VMs (Cuckoo):** Full isolation but 20-30% overhead, slow startup
- **Namespaces (Us):** Process-level isolation, <2% overhead, instant startup
- **Decision:** For research and short-lived malware analysis, namespaces suffice. For production, can add gVisor backend (Phase 3 plugin).

### Why Random Forest + SHAP?

**Alternatives:** Neural Networks, XGBoost, SVM

- **Random Forest:** Naturally interpretable, fast training, works with small datasets
- **SHAP:** Optimal for tree-based models (TreeExplainer is O(TLD²) vs. O(2^M) for KernelSHAP)
- **Trade-off:** Neural nets might achieve higher accuracy but lose explainability

### Why YAML Policies?

**Alternatives:** Python code, Rego (OPA), custom DSL

- **YAML:** Human-readable, version-controllable, no code execution risk
- **Simple Evaluator:** Only supports comparison operators (gte, lt, etc.)
- **Security:** Safer than `eval()` or embedded Python

---

## Performance Characteristics

| Metric | Current | With eBPF (Phase 2) | Target |
|--------|---------|---------------------|--------|
| **Overhead** | 2-5% | <1% | <1% |
| **Sampling Rate** | 100ms | Sub-ms | 10ms |
| **Memory Footprint** | ~50MB | ~60MB | <100MB |
| **ML Prediction** | <10ms | <10ms | <5ms |
| **Dashboard Latency** | 50-200ms | 50-200ms | <100ms |

---

## Future Extensions

### Phase 2: eBPF Telemetry
- Replace `/proc` polling with BPF programs
- Capture syscalls, scheduling events, network packets
- Add syscall diversity and rate features

### Phase 3: Forensics
- CRIU checkpointing for replay
- PDF report generation with embedded charts
- Deterministic replay with `rr`

### Phase 4: Advanced ML
- XGBoost ensemble
- Online learning (incremental updates)
- Autoencoder for anomaly detection on syscall sequences

---

## Academic Contributions

**Novel aspects suitable for publication:**

1. **Architecture:** First to combine NS isolation + SHAP + dynamic policies
2. **Algorithm:** Active learning for sample-efficient labeling
3. **System:** Complete end-to-end platform (not just a component)
4. **Evaluation:** Can benchmark against Cuckoo, Firejail in real-world tests

---

**Last Updated:** January 2026  
**Version:** 1.0 (Phase 1 Complete)
