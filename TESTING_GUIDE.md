# Testing Guide: Which Files Run in the Sandbox

## Test Programs (samples/)

These are the programs that **RUN INSIDE** the sandbox:

### 1. **samples/cpu_hog.c** → `samples/cpu_hog`
**Purpose**: Tests CPU resource limits and detection  
**Behavior**: Infinite loop consuming 100% CPU  
**Expected**: Detected as "Malicious" (high CPU + long runtime)  
**Seccomp**: Allowed (no dangerous syscalls)  
**Command**: `./runner/launcher samples/cpu_hog`

### 2. **samples/fork_bomb.c** → `samples/fork_bomb`
**Purpose**: Tests process limit enforcement (pids.max)  
**Behavior**: Recursively forks to create process bomb  
**Expected**: Blocked by seccomp (SIGSYS) or cgroup limit  
**Seccomp**: **BLOCKED** (clone syscall filtered in STRICT mode)  
**Command**: `./runner/launcher --profile=STRICT samples/fork_bomb`

### 3. **samples/fs_attack.c** → `samples/fs_attack`
**Purpose**: Tests filesystem isolation (read-only root)  
**Behavior**: Attempts to write to /etc/passwd  
**Expected**: Fails (EROFS - Read-only file system)  
**Seccomp**: Allowed  
**Command**: `./runner/launcher samples/fs_attack`

### 4. **samples/sleep.c** → `samples/sleep`
**Purpose**: Benign baseline test  
**Behavior**: Sleeps for specified seconds then exits  
**Expected**: Detected as "Benign" (low resource usage)  
**Seccomp**: Allowed  
**Command**: `./runner/launcher samples/sleep 2`

### 5. **System Binaries** (also tested)
- `/bin/echo` - Benign, quick exit
- `/bin/ls` - Benign, filesystem read
- `/bin/date` - Benign, system call

---

## Runner/Launcher (NOT sandboxed)

These files **RUN ON THE HOST** (outside sandbox):

### 1. **runner/launcher.c** → `runner/launcher`
**Compiled binary** that creates the sandbox  
**NOT SANDBOXED** - Runs with full privileges  
**Purpose**: Creates namespaces, sets limits, launches child  

### 2. **runner/ebpf_tracer.py**
**Runs as root on host** (forked by launcher)  
**NOT SANDBOXED** - Needs kernel access for eBPF  
**Purpose**: Attaches to kernel tracepoints, monitors syscalls  

### 3. **runner/merge_telemetry.py**
**Runs on host** (post-processing)  
**Purpose**: Merges JSON files from launcher + eBPF tracer  

---

## Dashboard Components (NOT sandboxed)

### 1. **dashboard/app.py**
**Flask web server** running on host  
**Port**: 5000  
**Purpose**: REST API and web interface  

### 2. **dashboard/ml_model.py** & **dashboard/ml_ensemble.py**
**ML inference** on host  
**Purpose**: Risk prediction on telemetry data  

### 3. **dashboard/analytics.py**
**Feature extraction** on host  
**Purpose**: Process logs into ML features  

---

## Validation Scripts (NOT sandboxed)

These test the system:

### 1. **validate_phase1.py**
Tests basic sandbox (namespaces, seccomp, telemetry)

### 2. **validate_phase2.py**
Tests eBPF integration (BCC, syscall tracing)

### 3. **validate_phase3.py**
Tests advanced ML (ensemble, online learning)

### 4. **run_all_tests.py**
Runs all samples and collects results

---

## Testing Flow

```
┌─────────────────────────────────────────┐
│ HOST SYSTEM (WSL2)                      │
│                                         │
│  runner/launcher                        │  ← Runs on host
│    │                                    │
│    ├─> Creates namespaces              │
│    ├─> Forks child process             │
│    │                                    │
│    v                                    │
│  ┌──────────────────────────┐          │
│  │ SANDBOX (Isolated)       │          │
│  │                          │          │
│  │  samples/cpu_hog         │  ← Runs inside sandbox
│  │  samples/fork_bomb       │  ← Runs inside sandbox
│  │  /bin/echo               │  ← Runs inside sandbox
│  │                          │          │
│  └──────────────────────────┘          │
│    │                                    │
│    v                                    │
│  Telemetry logged to logs/             │
│    │                                    │
│    v                                    │
│  runner/ebpf_tracer.py                 │  ← Runs on host
│    │                                    │
│    v                                    │
│  dashboard/app.py                      │  ← Runs on host
│  (ML analysis + visualization)          │
│                                         │
└─────────────────────────────────────────┘
```

---

## Quick Test Commands

### Test 1: Benign Program
```bash
./runner/launcher samples/sleep 1
# Should detect: Benign, low CPU, fast exit
```

### Test 2: CPU Hog (Malicious)
```bash
./runner/launcher samples/cpu_hog
# Should detect: Malicious, high CPU, long runtime
# Kill with Ctrl+C after a few seconds
```

### Test 3: Fork Bomb (Blocked)
```bash
./runner/launcher --profile=STRICT samples/fork_bomb
# Should: Get SIGSYS (seccomp blocked)
# Or: Hit pids.max limit
```

### Test 4: Filesystem Attack
```bash
./runner/launcher samples/fs_attack
# Should: Fail with EROFS (read-only)
```

### Test 5: With eBPF
```bash
sudo ./runner/launcher --enable-ebpf samples/cpu_hog
# Generates: logs/run_XXX.json + logs/ebpf_XXX.json
# Then: python3 runner/merge_telemetry.py logs/run_XXX.json logs/ebpf_XXX.json
```

---

## What Each Test File Contains

| File | Sandboxed? | Purpose |
|------|-----------|---------|
| `samples/cpu_hog` | ✅ YES | Tests CPU limits |
| `samples/fork_bomb` | ✅ YES | Tests process limits |
| `samples/fs_attack` | ✅ YES | Tests filesystem isolation |
| `samples/sleep` | ✅ YES | Benign baseline |
| `runner/launcher` | ❌ NO | Creates sandbox |
| `runner/ebpf_tracer.py` | ❌ NO | Kernel monitoring |
| `dashboard/app.py` | ❌ NO | Web dashboard |
| `validate_*.py` | ❌ NO | System validation |

---

**Key Point**: Only files in `samples/` and system binaries (like `/bin/echo`) run **INSIDE** the sandbox. Everything else runs on the host.
