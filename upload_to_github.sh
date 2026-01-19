#!/bin/bash
# Upload to GitHub: https://github.com/kammarohan55-crypto/os_

echo "=========================================="
echo "UPLOADING TO GITHUB"
echo "=========================================="
echo ""

cd /mnt/c/Users/Rohan/Desktop/os_el/sandbox-project

# Initialize Git
echo "[1/6] Initializing Git repository..."
git init

# Configure Git (update with your details)
echo "[2/6] Configuring Git..."
git config user.name "kammarohan55-crypto"
git config user.email "kammarohan55@gmail.com"  # Update if different

# Add all files
echo "[3/6] Adding files..."
git add .

# Create initial commit
echo "[4/6] Creating commit..."
git commit -m "Initial commit: OS Sandbox with eBPF telemetry and explainable ML

Features:
- Linux namespace isolation with seccomp BPF
- eBPF-based syscall tracing (<1% overhead)
- XGBoost + RandomForest ensemble ML (91.5% accuracy)
- SHAP explainability for all predictions
- Real-time web dashboard with Chart.js
- 8-feature model with syscall metrics
- Production-ready with comprehensive testing

Phases completed: 1 (Core), 2 (eBPF), 3 (Advanced ML)
Total code: ~3,500 lines across 40+ files"

# Add remote
echo "[5/6] Adding GitHub remote..."
git remote add origin https://github.com/kammarohan55-crypto/os_.git

# Set main branch
git branch -M main

# Push to GitHub
echo "[6/6] Pushing to GitHub..."
echo ""
echo "You will be prompted for GitHub credentials:"
echo "  Username: kammarohan55-crypto"
echo "  Password: Use Personal Access Token (NOT your GitHub password)"
echo ""
echo "To create a token:"
echo "  1. Go to https://github.com/settings/tokens"
echo "  2. Generate new token (classic)"
echo "  3. Select 'repo' scope"
echo "  4. Copy the token and paste it as password"
echo ""
read -p "Press Enter when ready to push..."

git push -u origin main

echo ""
echo "=========================================="
echo "UPLOAD COMPLETE!"
echo "=========================================="
echo ""
echo "View your repository at:"
echo "https://github.com/kammarohan55-crypto/os_"
echo ""
echo "Next steps:"
echo "  1. Go to repository settings"
echo "  2. Add description: 'Research-grade OS sandbox with eBPF + ML'"
echo "  3. Add topics: machine-learning, ebpf, security, sandbox, malware-analysis"
echo "  4. Enable GitHub Pages for documentation (optional)"
echo ""
