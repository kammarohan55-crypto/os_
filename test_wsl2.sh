#!/bin/bash
# Automated WSL2 Testing Script
# Password: rohan

set -e  # Exit on error

echo "=========================================="
echo "OS SANDBOX - AUTOMATED WSL2 TESTING"
echo "=========================================="
echo ""

# Change to project directory
cd /mnt/c/Users/Rohan/Desktop/os_el/sandbox-project

echo "[1/10] Installing Python dependencies..."
pip install -q -r requirements.txt 2>/dev/null || echo "Some packages already installed"
pip install -q xgboost==2.0.3 2>/dev/null || echo "XGBoost already installed"

echo "[2/10] Installing eBPF tools (requires sudo)..."
echo "rohan" | sudo -S apt-get update -qq 2>/dev/null
echo "rohan" | sudo -S apt-get install -y -qq bpfcc-tools python3-bpfcc linux-headers-$(uname -r) 2>/dev/null || echo "eBPF tools already installed"

echo "[3/10] Compiling launcher..."
make clean 2>/dev/null
make 2>/dev/null

echo "[4/10] Testing eBPF installation..."
echo "rohan" | sudo -S python3 runner/test_ebpf.py

echo "[5/10] Running Phase 1 validation..."
python3 validate_phase1.py

echo "[6/10] Running Phase 2 validation..."
python3 validate_phase2.py

echo "[7/10] Running Phase 3 validation..."
python3 validate_phase3.py

echo "[8/10] Generating training data (100 samples)..."
python3 scripts/generate_training_data.py

echo "[9/10] Running comprehensive tests..."
echo "rohan" | sudo -S python3 run_all_tests.py --ebpf

echo "[10/10] Starting dashboard (background)..."
cd dashboard
nohup python3 app.py > ../logs/dashboard.log 2>&1 &
DASHBOARD_PID=$!
echo "Dashboard started with PID: $DASHBOARD_PID"
echo "Access at: http://localhost:5000"

cd ..
echo ""
echo "=========================================="
echo "TESTING COMPLETE!"
echo "=========================================="
echo ""
echo "Summary saved to: logs/test_results.txt"
echo "Dashboard PID: $DASHBOARD_PID"
echo ""
echo "To stop dashboard: kill $DASHBOARD_PID"
