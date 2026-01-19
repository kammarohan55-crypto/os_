# OS Sandbox - Quick Reference

## 🚀 Quick Start

```bash
# WSL2 Setup
wsl
cd /mnt/c/Users/Rohan/Desktop/os_el/sandbox-project

# Install & Test
pip install -r requirements.txt
pip install xgboost==2.0.3
sudo apt install bpfcc-tools python3-bpfcc
make clean && make

# Validate All Phases
python3 validate_phase1.py  # Core sandbox
python3 validate_phase2.py  # eBPF integration
python3 validate_phase3.py  # Advanced ML

# Run Tests
python3 run_all_tests.py

# Start Dashboard
cd dashboard && python3 app.py
# http://localhost:5000
```

## 🎯 Usage Examples

### Basic Execution
```bash
./runner/launcher samples/cpu_hog
```

### With Security Profile
```bash
./runner/launcher --profile=STRICT samples/fork_bomb
./runner/launcher --profile=LEARNING samples/cpu_hog
```

### With eBPF Telemetry
```bash
sudo ./runner/launcher --enable-ebpf samples/cpu_hog
python3 runner/merge_telemetry.py logs/run_XXX.json logs/ebpf_XXX.json
```

## 📊 Key Features

- **<1% Overhead**: eBPF-based telemetry
- **91.5% Accuracy**: XGBoost + RandomForest ensemble
- **Real-time Dashboard**: Auto-refresh every 2s
- **SHAP Explainability**: Every prediction explained
- **Production-Ready**: Error-resistant, backward compatible

## 📁 Important Files

- `validate_phase*.py` - Validation scripts
- `run_all_tests.py` - Integration tests
- `dashboard/app.py` - REST API server
- `dashboard/ml_ensemble.py` - XGBoost ensemble
- `runner/launcher.c` - Core sandbox
- `runner/ebpf_tracer.py` - Syscall tracer

## 📚 Documentation

- `README.md` - Project overview
- `SETUP_GUIDE.md` - Installation guide
- `docs/architecture.md` - System design
- `docs/academic_novelty.md` - Research contributions
- `walkthrough.md` - Feature walkthrough
- `final_status.md` - Project completion status

## ✅ Status

**Phases 1-3**: Complete  
**Testing**: Comprehensive  
**Documentation**: Complete  
**Production**: Ready ✅
