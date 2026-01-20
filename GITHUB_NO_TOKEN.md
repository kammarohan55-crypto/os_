# GitHub Upload Without Personal Access Token

## Method 1: SSH Keys (Recommended Alternative)

SSH keys allow password-free authentication. One-time setup, then it works forever!

### Step 1: Generate SSH Key (in WSL)
```bash
wsl
cd ~
ssh-keygen -t ed25519 -C "kammarohan55@gmail.com"
```

**Press Enter 3 times** (accept default location, no passphrase)

### Step 2: Copy Your Public Key
```bash
cat ~/.ssh/id_ed25519.pub
```

**Copy the entire output** (starts with `ssh-ed25519 AAAA...`)

### Step 3: Add to GitHub
1. Go to: https://github.com/settings/keys
2. Click **"New SSH key"**
3. Title: `WSL2 OS Sandbox`
4. Key type: `Authentication Key`
5. **Paste** your copied key
6. Click **"Add SSH key"**
7. Confirm with your GitHub password (just this once)

### Step 4: Change Git Remote to SSH
```bash
cd /mnt/c/Users/Rohan/Desktop/os_el/sandbox-project

# Change from HTTPS to SSH
git remote set-url origin git@github.com:kammarohan55-crypto/os_.git

# Now push (NO PASSWORD NEEDED!)
git push -u origin main
```

**Done!** Future pushes won't ask for credentials.

---

## Method 2: GitHub CLI (gh)

### Install GitHub CLI
```bash
# In WSL
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
sudo chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
sudo apt update
sudo apt install gh
```

### Authenticate
```bash
gh auth login
# Choose: GitHub.com
# Choose: HTTPS
# Choose: Login with a web browser
# Copy the code shown
# Press Enter
# Browser will open - paste code and authorize
```

### Push
```bash
cd /mnt/c/Users/Rohan/Desktop/os_el/sandbox-project
git push -u origin main
# Works automatically!
```

---

## Method 3: GitHub Desktop (GUI)

1. Download: https://desktop.github.com/
2. Install and sign in with GitHub
3. File → Add Local Repository → Browse to `C:\Users\Rohan\Desktop\os_el\sandbox-project`
4. Click **"Publish repository"**
5. Repository name: `os_`
6. Click **"Publish"**

---

## Quick Comparison

| Method | Setup Time | Future Use |
|--------|-----------|------------|
| **SSH Key** | 2 min | Instant (no password) |
| **GitHub CLI** | 5 min | Instant (no password) |
| **GitHub Desktop** | 5 min | GUI clicks |
| Personal Token | 1 min | Need to re-enter |

---

## Recommended: SSH Key Method

**Fastest and most secure!** Here's the complete commands:

```bash
# 1. Generate key
wsl
ssh-keygen -t ed25519 -C "kammarohan55@gmail.com"
# Press Enter 3 times

# 2. Copy key
cat ~/.ssh/id_ed25519.pub
# Copy the output

# 3. Add to GitHub (browser)
# https://github.com/settings/keys → New SSH key → Paste

# 4. Update remote and push
cd /mnt/c/Users/Rohan/Desktop/os_el/sandbox-project
git remote set-url origin git@github.com:kammarohan55-crypto/os_.git
git push -u origin main
# NO PASSWORD NEEDED!
```

**That's it!** SSH is the standard way developers use Git.
