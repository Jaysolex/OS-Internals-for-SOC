# Transferring the Project from Windows to Ubuntu via SSH

> Complete workflow — SSH setup, file transfer, repo cleanup, and pushing clean to GitHub.

---

## Overview

```
Windows (your files)
       │
       │  SCP over SSH
       ▼
Ubuntu (your Linux machine)
       │
       │  git push
       ▼
GitHub (Jaysolex/OS-Internals-for-SOC)
```

---

## Step 1 — Verify SSH is Running on Ubuntu

On your **Ubuntu machine**, run:

```bash
# Check if SSH daemon is running
sudo systemctl status ssh

# If not running, install and start it
sudo apt update
sudo apt install openssh-server -y
sudo systemctl enable ssh
sudo systemctl start ssh

# Get your Ubuntu IP address
ip addr show | grep "inet " | grep -v 127.0.0.1
# Look for something like: inet 192.168.1.105/24
# That 192.168.1.105 is the IP you need
```

---

## Step 2 — Verify SSH Works from Windows

On your **Windows machine**, open **PowerShell** or **Windows Terminal**:

```powershell
# Test SSH connection to Ubuntu
ssh your_ubuntu_username@192.168.1.105

# Example:
ssh solomon@192.168.1.105

# It will ask for your Ubuntu password — enter it
# Type 'exit' when done to close the connection
```

If it connects, SSH is working. Move to Step 3.

**If it fails:**
```powershell
# Make sure Ubuntu firewall allows SSH
# Run this on Ubuntu:
sudo ufw allow ssh
sudo ufw status

# Or check if Ubuntu is on the same network as Windows
# Windows: run this to see your Windows IP
ipconfig
# Look for IPv4 Address under your active adapter
```

---

## Step 3 — Know Your File Location on Windows

You have the project files. Find where they are.

On **Windows**, right-click any folder → Properties to see the full path, or:

```powershell
# In PowerShell — find where the project folder is
Get-ChildItem C:\Users\$env:USERNAME\Desktop
Get-ChildItem C:\Users\$env:USERNAME\Downloads

# Example path structures:
# C:\Users\Solomon\Desktop\OS-Internals-for-SOC
# C:\Users\Solomon\Downloads\OS-Internals-for-SOC
```

---

## Step 4 — Transfer Files from Windows to Ubuntu

You have **three options** depending on what tools you have.

---

### Option A — SCP (Simplest — built into Windows 10/11)

Open **PowerShell** on Windows:

```powershell
# Syntax:
# scp -r "C:\path\to\folder" username@ubuntu_ip:/destination/path

# Example — transfer the project to your Ubuntu home directory:
scp -r "C:\Users\Solomon\Desktop\OS-Internals-for-SOC" solomon@192.168.1.105:~/

# What this does:
# -r          = recursive (copies entire folder and all subfolders)
# "C:\..."    = source folder on Windows (use quotes if spaces in path)
# solomon@... = your Ubuntu username and IP
# :~/         = destination = your home directory on Ubuntu (/home/solomon/)

# You'll be prompted for your Ubuntu password
```

After transfer, on Ubuntu:
```bash
ls ~/OS-Internals-for-SOC
# You should see all your files and folders
```

---

### Option B — rsync over SSH (Best for large projects or re-syncing)

```powershell
# rsync must be installed on Windows first
# Install via: winget install --id=Cygwin.Cygwin
# Or use WSL (Windows Subsystem for Linux)

# If using WSL (Windows Subsystem for Linux):
wsl
rsync -avz --progress "/mnt/c/Users/Solomon/Desktop/OS-Internals-for-SOC/" \
  solomon@192.168.1.105:~/OS-Internals-for-SOC/

# Flags:
# -a = archive mode (preserves permissions, timestamps)
# -v = verbose output
# -z = compress during transfer
# --progress = show transfer progress
```

---

### Option C — WinSCP (GUI — easiest if you prefer visual)

1. Download WinSCP: https://winscp.net
2. Open WinSCP
3. Protocol: **SFTP**
4. Host name: `192.168.1.105` (your Ubuntu IP)
5. Username: your Ubuntu username
6. Password: your Ubuntu password
7. Click **Login**
8. Left panel = Windows files, Right panel = Ubuntu files
9. Drag `OS-Internals-for-SOC` folder from left to right
10. Done

---

## Step 5 — Clean Up the Project on Ubuntu

Once the files are on Ubuntu, clean before pushing to GitHub.

```bash
# Navigate to the project
cd ~/OS-Internals-for-SOC

# See what's there
ls -la

# Remove any Windows-specific junk files
find . -name "Thumbs.db" -delete
find . -name "desktop.ini" -delete
find . -name "*.DS_Store" -delete
find . -name "Zone.Identifier" -delete

# Fix Windows line endings (CRLF → LF) on all shell scripts
# Install dos2unix if not present
sudo apt install dos2unix -y

# Convert all .sh scripts
find . -name "*.sh" -exec dos2unix {} \;

# Convert all .md files
find . -name "*.md" -exec dos2unix {} \;

# Make shell scripts executable
chmod +x Scripts/Linux/*.sh

# Verify the structure looks correct
find . -type f | sort
```

---

## Step 6 — Set Up Git on Ubuntu

```bash
# Install git if not already installed
sudo apt install git -y

# Configure git identity (required for commits)
git config --global user.name "Solomon James"
git config --global user.email "your_email@example.com"

# Verify config
git config --list
```

---

## Step 7 — Initialize the Repository

```bash
cd ~/OS-Internals-for-SOC

# Initialize git repository
git init

# Check current state
git status
```

---

## Step 8 — Create .gitignore

```bash
cat > .gitignore << 'EOF'
# OS artifacts
.DS_Store
Thumbs.db
desktop.ini

# Windows metadata
*:Zone.Identifier

# Editor temp files
*.swp
*.swo
*~
.vscode/
.idea/

# Script output files (don't push case output to GitHub)
/tmp/
triage_*/
*.tar.gz

# Python cache
__pycache__/
*.pyc

# Credentials (never commit these)
*.pem
*.key
id_rsa
credentials
.env
EOF

echo ".gitignore created"
cat .gitignore
```

---

## Step 9 — Create the GitHub Repository

On **GitHub.com**:
1. Go to https://github.com/Jaysolex
2. Click the **+** → **New repository**
3. Repository name: `OS-Internals-for-SOC`
4. Description: `Operating system internals through the lens of detection, investigation, and response — Linux & Windows`
5. Set to **Public**
6. **Do NOT** check "Add README" (you already have one)
7. **Do NOT** add .gitignore (you already have one)
8. Click **Create repository**
9. Copy the repository URL shown — it will look like:
   `https://github.com/Jaysolex/OS-Internals-for-SOC.git`

---

## Step 10 — Set Up GitHub Authentication (SSH Key)

GitHub no longer accepts password authentication for pushes. Set up an SSH key.

```bash
# Generate SSH key (on Ubuntu)
ssh-keygen -t ed25519 -C "your_email@example.com"
# Press Enter for all prompts (default location, no passphrase)

# Display your public key
cat ~/.ssh/id_ed25519.pub
# Copy the entire output — it starts with ssh-ed25519
```

Now add it to GitHub:
1. Go to https://github.com/settings/keys
2. Click **New SSH key**
3. Title: `Ubuntu Machine`
4. Key type: **Authentication Key**
5. Paste the key you copied
6. Click **Add SSH key**

Test it works:
```bash
ssh -T git@github.com
# Should say: Hi Jaysolex! You've successfully authenticated...
```

---

## Step 11 — Stage, Commit, and Push

```bash
cd ~/OS-Internals-for-SOC

# Stage all files
git add .

# Review what you're about to commit
git status
git diff --stat --cached

# Commit with a professional message
git commit -m "feat: initial release — Linux & Windows OS internals for security engineers

- Linux filesystem hierarchy — full root directory dissection with security context
- Windows filesystem hierarchy — System32, registry hives, forensic artifacts
- Security reference — artifact locations, event IDs, LOLBins, investigation commands
- Detection engineering — Sigma rules, Splunk SPL, Wazuh, Sysmon config
- Incident response — evidence preservation, memory acquisition procedures
- Threat hunting — hypothesis packages mapped to OS mechanisms
- Scripts — live triage, log parser, persistence hunter
- MITRE ATT&CK coverage across 14 Linux and 14 Windows modules"

# Set the remote to your GitHub repository (use SSH URL)
git remote add origin git@github.com:Jaysolex/OS-Internals-for-SOC.git

# Set branch to main
git branch -M main

# Push to GitHub
git push -u origin main
```

You'll see output showing each file being pushed. When it finishes:

```bash
# Confirm it's live
echo "Live at: https://github.com/Jaysolex/OS-Internals-for-SOC"
```

---

## Ongoing Workflow — Adding New Modules

Every time you write a new module and want to update GitHub:

```bash
cd ~/OS-Internals-for-SOC

# See what changed
git status
git diff

# Stage specific file or all changes
git add Linux/02-Logging-System/README.md
# or
git add .

# Commit
git commit -m "feat(linux): add logging system module — rsyslog, journald, auditd, detection rules"

# Push
git push
```

---

## Troubleshooting

**Permission denied (publickey) when pushing:**
```bash
# Make sure your SSH key is added to ssh-agent
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519

# Re-test GitHub connection
ssh -T git@github.com
```

**SCP fails with "Connection refused":**
```bash
# On Ubuntu — check SSH service
sudo systemctl status ssh
sudo systemctl restart ssh

# Check firewall
sudo ufw status
sudo ufw allow 22
```

**Files transferred but scripts won't run (permission error):**
```bash
chmod +x ~/OS-Internals-for-SOC/Scripts/Linux/*.sh
```

**Wrong line endings on scripts (Windows → Linux):**
```bash
sudo apt install dos2unix -y
find ~/OS-Internals-for-SOC -name "*.sh" -exec dos2unix {} \;
```

**git push says "remote origin already exists":**
```bash
git remote set-url origin git@github.com:Jaysolex/OS-Internals-for-SOC.git
```

---

## Quick Reference Card

```
Windows → Ubuntu:     scp -r "C:\path\to\folder" user@ubuntu_ip:~/
Ubuntu → GitHub:      git add . && git commit -m "msg" && git push
Check Ubuntu IP:      ip addr show
Check SSH on Ubuntu:  sudo systemctl status ssh
Fix line endings:     find . -name "*.sh" -exec dos2unix {} \;
Make scripts exec:    chmod +x Scripts/Linux/*.sh
Test GitHub SSH:      ssh -T git@github.com
```
