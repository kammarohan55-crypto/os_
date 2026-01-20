# GET YOUR GITHUB CREDENTIALS - EXACT STEPS

## 🔑 Option 1: Get Personal Access Token (FASTEST - 1 MINUTE)

### Step-by-Step with Screenshots

#### 1. Open This Link
**Click here**: https://github.com/settings/tokens

(Make sure you're logged into GitHub first!)

#### 2. Click "Generate new token"
Look for the button in the top-right corner that says:
```
[Generate new token ▼]
```
Click it, then select **"Generate new token (classic)"**

#### 3. Fill in the Form

**Note (name your token)**: Type `os-sandbox-upload`

**Expiration**: Select `90 days` (or whatever you prefer)

**Select scopes**: 
- ✅ Check the box next to **`repo`** (this will auto-check all sub-boxes)
  - That's the ONLY box you need!

#### 4. Scroll Down and Click
Look for the green button at the bottom:
```
[Generate token]
```
Click it!

#### 5. COPY YOUR TOKEN
You'll see a token that looks like:
```
ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

**CRITICAL**: Click the copy icon 📋 or select and copy this token!
**YOU WILL NEVER SEE IT AGAIN!**

Save it somewhere (Notepad, etc.)

---

## 🚀 Now Use the Token

### Open a NEW Terminal
```powershell
wsl
cd /mnt/c/Users/Rohan/Desktop/os_el/sandbox-project
git push -u origin main
```

**When it asks:**
```
Username for 'https://github.com': 
```
Type: `kammarohan55-crypto` and press Enter

**When it asks:**
```
Password for 'https://kammarohan55-crypto@github.com':
```
**PASTE YOUR TOKEN** (right-click to paste in terminal) and press Enter

**DONE!** Your code uploads to GitHub! 🎉

---

## 🔑 Option 2: Use Your GitHub Password (NOT RECOMMENDED)

GitHub doesn't accept passwords anymore! You MUST use a token or SSH key.

---

## ❓ I Can't Access GitHub Settings

**Are you logged into GitHub?**
1. Go to https://github.com
2. Click "Sign in" (top right)
3. Enter your GitHub username/email and password
4. Then go to: https://github.com/settings/tokens

**Don't have a GitHub account?**
1. Go to https://github.com/signup
2. Create an account (free)
3. Then follow the token steps above

---

## 🎯 SUMMARY - What You Need

To upload to GitHub, you need **ONE** of these:

1. **Personal Access Token** ← Get from https://github.com/settings/tokens
2. **SSH Key** ← More complex, but one-time setup
3. **GitHub Desktop App** ← GUI, no commands needed

**I recommend #1 (Token)** - takes 1 minute to get!

---

## 🆘 Still Stuck?

**Can't find settings?**
- Make sure you're logged into GitHub.com
- Direct link: https://github.com/settings/tokens

**Don't want to use terminal?**
- Use GitHub website: Go to your repo → "Add file" → "Upload files" → Drag and drop

**Really stuck?**
- Install GitHub Desktop: https://desktop.github.com/
- Sign in, add your folder, click "Publish"

---

**The token is YOUR GitHub credential - I cannot create it for you!**
Only YOU can access your GitHub settings to generate it.
