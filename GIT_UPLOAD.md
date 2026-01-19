# Git Commands for GitHub Upload

## Step 1: Initialize Git (in WSL)

```bash
cd /mnt/c/Users/Rohan/Desktop/os_el/sandbox-project

# Initialize repository
git init

# Add all files
git add .

# Create initial commit
git commit -m "Initial commit: OS Sandbox with eBPF + ML"
```

## Step 2: Create GitHub Repository

1. Go to https://github.com/new
2. Repository name: `os-sandbox` (or your choice)
3. Description: "Research-grade OS-level malware analysis sandbox with eBPF telemetry and explainable ML"
4. Make it **Public** or **Private**
5. **DO NOT** initialize with README, .gitignore, or license (we already have them)
6. Click "Create repository"

## Step 3: Connect and Push

Replace `yourusername` and `os-sandbox` with your actual GitHub username and repo name:

```bash
# Add remote
git remote add origin https://github.com/yourusername/os-sandbox.git

# Push to GitHub
git push -u origin main
```

If you get an error about "master" vs "main":
```bash
git branch -M main
git push -u origin main
```

## Step 4: GitHub Authentication

When prompted for credentials:

**Option 1: Personal Access Token (Recommended)**
1. Go to GitHub → Settings → Developer settings → Personal access tokens → Tokens (classic)
2. Generate new token with `repo` scope
3. Use token as password

**Option 2: SSH Key**
```bash
# Generate SSH key
ssh-keygen -t ed25519 -C "your_email@example.com"

# Copy public key
cat ~/.ssh/id_ed25519.pub

# Add to GitHub → Settings → SSH keys
# Then change remote URL:
git remote set-url origin git@github.com:yourusername/os-sandbox.git
```

## Step 5: Verify Upload

Visit: `https://github.com/yourusername/os-sandbox`

You should see:
- README.md with badges and documentation
- All source files
- Proper .gitignore (no logs or build artifacts)

## Future Updates

```bash
# Make changes
git add .
git commit -m "Description of changes"
git push
```

## Tips

- **Don't commit**: logs/, data/, *.pkl (already in .gitignore)
- **Do commit**: Source code, documentation, samples
- **Branch for features**: `git checkout -b feature-name`
- **Tag releases**: `git tag -a v1.0 -m "Phase 3 Complete"`

---

**Repository is ready for upload!** 🚀
