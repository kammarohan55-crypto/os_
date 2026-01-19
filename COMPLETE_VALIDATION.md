# Complete Validation & Testing Guide

## 🚀 Step-by-Step: Run Everything

### Prerequisites Check

```bash
# Open WSL
wsl

# Navigate to project
cd /mnt/c/Users/Rohan/Desktop/os_el/sandbox-project

# Check Python version
python3 --version  # Should be 3.8+

# Check if in WSL
uname -a  # Should show Linux
```

---

## 📦 Step 1: Install Dependencies (5 min)

```bash
# Install Python packages
pip install -r requirements.txt
pip install xgboost==2.0.3

# Install eBPF tools (requires password: rohan)
echo "rohan" | sudo -S apt-get update
echo "rohan" | sudo -S apt-get install -y bpfcc-tools python3-bpfcc linux-headers-$(uname -r)

# Verify eBPF installation
python3 -c "from bcc import BPF; print('✅ BCC installed')"
```

**Expected Output**: `✅ BCC installed`

---

## 🔨 Step 2: Compile the Launcher (1 min)

```bash
# Clean and compile
make clean
make

# Verify binary created
ls -lh runner/launcher
```

**Expected Output**: `runner/launcher` binary file (~50KB)

---

## ✅ Step 3: Validate Phase 1 (Core Sandbox)

```bash
python3 validate_phase1.py
```

**Expected Output**:
```
✅ All core components present
✅ Launcher binary exists
✅ Python modules imported successfully
✅ Sample programs compiled
✅ Seccomp rules found
✅ YAML policies loaded
```

**If errors**: Check that `make` completed successfully.

---

## ✅ Step 4: Validate Phase 2 (eBPF Integration)

```bash
python3 validate_phase2.py
```

**Expected Output**:
```
✅ All Phase 2 files present
✅ BCC installed (eBPF enabled)
✅ Model initialized with 8 features
✅ Feature set correct (8 features)
✅ Syscall features extracted correctly
```

**If errors**: Install BCC with `sudo apt install bpfcc-tools python3-bpfcc`

---

## ✅ Step 5: Validate Phase 3 (Advanced ML)

```bash
python3 validate_phase3.py
```

**Expected Output**:
```
✅ XGBoost installed (version: 2.0.3)
✅ Ensemble classifier initialized
✅ Prediction: Malicious (94.7%)
✅ Model: Ensemble (RF+XGBoost)
✅ Online learning method available
✅ eBPF Status Badge implemented
✅ Syscall Chart implemented
```

**If errors**: Install XGBoost with `pip install xgboost==2.0.3`

---

## 🧪 Step 6: Test eBPF (Requires Root)

```bash
echo "rohan" | sudo -S python3 runner/test_ebpf.py
```

**Expected Output**:
```
✅ PASS - BCC Import
✅ PASS - Root Privileges
✅ PASS - Kernel Config
✅ PASS - Minimal BPF Program
✅ PASS - Syscall Tracepoint
```

**This confirms**: Kernel supports eBPF and BCC is properly installed.

---

## 🎯 Step 7: Run Test Programs

### 7a. Benign Program (No eBPF)

```bash
./runner/launcher samples/sleep 2
```

**Expected Output**:
```
[Sandbox-Parent] Launching: samples/sleep with args: 2
[Sandbox-Child] PID in sandbox: 1
[Sandbox-Parent] Child exited: EXITED(0)
[Sandbox-Parent] Telemetry saved to: logs/run_XXXXX_YYYYY.json
```

**Check logs**:
```bash
# View most recent log
ls -lt logs/*.json | head -1
python3 -c "import json; print(json.dumps(json.load(open('logs/run_XXXXX_YYYYY.json')), indent=2))"
```

### 7b. CPU-Intensive Program (Malicious)

```bash
# Run for 5 seconds then Ctrl+C
timeout 5 ./runner/launcher samples/cpu_hog
```

**Expected**: High CPU usage, detected as "Malicious"

### 7c. With eBPF Telemetry (Requires Root)

```bash
echo "rohan" | sudo -S ./runner/launcher --enable-ebpf samples/cpu_hog
```

**Expected Output**:
```
[Sandbox-Parent] eBPF telemetry enabled
[Sandbox-Parent] Child launched with PID: XXXXX
[Sandbox-Parent] eBPF tracer started with PID: YYYYY
[eBPF] Attached to raw_syscalls:sys_enter
[eBPF] Monitoring PID XXXXX
...
[Sandbox-Parent] eBPF data saved to: logs/ebpf_XXXXX_ZZZZZ.json
[Sandbox-Parent] Merge with: python3 runner/merge_telemetry.py logs/run_XXXXX.json logs/ebpf_XXXXX.json
```

**Merge the data**:
```bash
# Use exact filenames from output above
python3 runner/merge_telemetry.py logs/run_XXXXX_ZZZZZ.json logs/ebpf_XXXXX_ZZZZZ.json
```

**Verify merged data**:
```bash
python3 -c "
import json
with open('logs/run_XXXXX_ZZZZZ.json') as f:
    data = json.load(f)
    if 'syscall_events' in data:
        print('✅ eBPF data merged successfully')
        print('Total syscalls:', data['syscall_events']['total_syscalls'])
        print('Unique syscalls:', data['syscall_events']['unique_syscalls'])
    else:
        print('❌ No eBPF data found')
"
```

### 7d. Fork Bomb (Should Be Blocked)

```bash
./runner/launcher --profile=STRICT samples/fork_bomb
```

**Expected**: `VIOLATION: SIGSYS` (seccomp blocked `clone` syscall)

### 7e. Filesystem Attack (Should Fail)

```bash
./runner/launcher samples/fs_attack
```

**Expected**: `open: Read-only file system` (can't write to /etc/passwd)

---

## 📊 Step 8: Generate Training Data (Optional)

This creates 100+ real samples by running programs multiple times:

```bash
python3 scripts/generate_training_data.py
```

**Expected Output**:
```
Running samples/sleep (10 times)...
  [1/100] Run 1/10... ✓
  [2/100] Run 2/10... ✓
  ...
Generated 100 samples
Saved to: data/training_dataset.json
Training ML model on generated data...
✓ Model trained and saved to: data/trained_model.pkl
```

**This creates**: Pretrained ML model with real data (not just seed data)

---

## 🌐 Step 9: Start Dashboard

```bash
cd dashboard
python3 app.py
```

**Expected Output**:
```
[ML] Using Ensemble Classifier (RF + XGBoost)
[ML] Loaded pretrained model with 8 features  # If you ran Step 8
[Flask] Starting OS Sandbox Analytics Dashboard...
 * Running on http://0.0.0.0:5000
```

**Open in Windows browser**: `http://localhost:5000`

**Dashboard Features**:
- ✅ Summary stats (total runs, violations, avg CPU/memory)
- ✅ Risk assessment with ML predictions
- ✅ CPU and memory timeline charts
- ✅ Exit reason distribution
- ✅ Recent executions table with ML risk scores
- ✅ eBPF syscall charts (if eBPF data exists)
- ✅ Network activity visualization

**To stop dashboard**: Press `Ctrl+C` in terminal

---

## 🏁 Step 10: Run Complete Test Suite

```bash
# Stop dashboard if running (Ctrl+C)
cd /mnt/c/Users/Rohan/Desktop/os_el/sandbox-project

# Run all tests with eBPF
echo "rohan" | sudo -S python3 run_all_tests.py --ebpf
```

**Expected Output**:
```
Running: samples/sleep 1
  Result: EXITED(0) | CPU: 2% | Memory: 180KB | Runtime: 1005ms
  ML Prediction: Benign (95.2%)

Running: samples/cpu_hog
  Result: VIOLATION | CPU: 98% | Memory: 1024KB | Runtime: 5002ms
  ML Prediction: Malicious (94.7%)

...

Summary: X total runs, Y malicious detected, Z% accuracy
```

---

## 🔍 Step 11: View Logs and Results

### View Latest Log
```bash
# Most recent run
cat logs/run_*.json | tail -1 | python3 -m json.tool
```

### View All Logs
```bash
ls -lth logs/*.json | head -10
```

### Check Syscall Data (if eBPF enabled)
```bash
python3 -c "
import json
import glob

# Find logs with eBPF data
for log_file in glob.glob('logs/run_*.json'):
    with open(log_file) as f:
        data = json.load(f)
        if 'syscall_events' in data:
            print(f'{log_file}:')
            print(f'  Total syscalls: {data[\"syscall_events\"][\"total_syscalls\"]}')
            print(f'  Syscall rate: {data[\"syscall_events\"][\"syscall_rate_per_sec\"]}/s')
            print(f'  Network calls: {data[\"syscall_events\"][\"network_syscalls\"]}')
            print()
"
```

---

## 📈 Step 12: Benchmark Performance (Optional)

```bash
python3 scripts/benchmark.py
```

**Compares**: Our sandbox vs Firejail vs native execution

**Expected Output**:
```
Solution                  Overhead     Granularity     ML Acc     Explain
----------------------------------------------------------------------
OS Sandbox (eBPF)        <1%          sub-ms          91.5%      SHAP
OS Sandbox (/proc)       2-3%         100ms           87.2%      SHAP
Firejail                 1-2%         N/A             None       None
Native (no sandbox)      0%           N/A             N/A        N/A
```

---

## ✅ Complete Validation Checklist

Run this automated script that does everything:

```bash
bash test_wsl2.sh
```

**This script**:
1. ✅ Installs all dependencies
2. ✅ Compiles launcher
3. ✅ Tests eBPF installation
4. ✅ Runs Phase 1/2/3 validation
5. ✅ Generates training data
6. ✅ Runs comprehensive tests
7. ✅ Starts dashboard in background

**After completion**:
- Dashboard running at `http://localhost:5000`
- Logs in `logs/`
- Trained model in `data/trained_model.pkl`

---

## 🐛 Troubleshooting

### Issue: "make: command not found"
```bash
sudo apt install build-essential
```

### Issue: "BCC not found"
```bash
sudo apt install bpfcc-tools python3-bpfcc linux-headers-$(uname -r)
```

### Issue: "Operation not permitted" (eBPF)
```bash
# Run with sudo
sudo python3 runner/test_ebpf.py
```

### Issue: "No module named 'flask'"
```bash
pip install -r requirements.txt
```

### Issue: Dashboard shows no data
```bash
# Run some tests first to generate logs
./runner/launcher samples/sleep 1
./runner/launcher samples/cpu_hog
# Then refresh dashboard
```

### Issue: "launcher: No such file"
```bash
# Compile it
make clean && make
```

---

## 📋 Quick Command Reference

```bash
# Compile
make

# Validate all phases
python3 validate_phase1.py
python3 validate_phase2.py
python3 validate_phase3.py

# Test basic
./runner/launcher samples/sleep 1

# Test with eBPF
sudo ./runner/launcher --enable-ebpf samples/cpu_hog

# Generate training data
python3 scripts/generate_training_data.py

# Start dashboard
cd dashboard && python3 app.py

# Run all tests
sudo python3 run_all_tests.py --ebpf

# Automated testing
bash test_wsl2.sh
```

---

## ✨ Success Criteria

After completing all steps, you should have:

- ✅ All 3 validation scripts passing
- ✅ eBPF test passing
- ✅ Multiple log files in `logs/`
- ✅ Dashboard accessible at `localhost:5000`
- ✅ ML predictions showing in dashboard
- ✅ eBPF syscall charts visible (if eBPF data exists)
- ✅ Pretrained model in `data/` (if generated)

**You're ready for**: Production deployment, academic research, GitHub upload!

---

**Total Time**: ~15-20 minutes for complete setup and validation
