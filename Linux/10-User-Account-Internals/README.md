# Linux/10 — User Account Internals

> User accounts are the identity layer of Linux. Every process runs as a user, every file has an owner, every privilege decision references a UID. Attackers create accounts, modify existing ones, abuse authentication, and manipulate the credential stack. Understanding how Linux manages identity is foundational to detecting all of it.

![MITRE](https://img.shields.io/badge/MITRE-T1078%20|%20T1136%20|%20T1098%20|%20T1110-red)
![Platform](https://img.shields.io/badge/Platform-Linux-orange)

---

## Identity Architecture

```
User logs in
    |
    v
PAM (Pluggable Authentication Modules)
    |   authenticates via password, key, MFA
    v
Login process sets:
    - Real UID / GID (who you are)
    - Supplementary groups
    - loginuid (audit trail — never changes)
    - Session environment
    |
    v
Shell spawned with user identity
    |
    v
All child processes inherit identity
```

---

## /etc/passwd

World-readable. One line per account.

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
ghostop:x:1000:1000::/home/ghostop:/bin/bash
```

Fields: `username:password:UID:GID:GECOS:home:shell`

- `x` in password field = hash is in /etc/shadow
- UID 0 = root (any account with UID 0 has full root access)
- Shell `/usr/sbin/nologin` or `/bin/false` = service account, no interactive login

### Security Checks

```bash
# Accounts with UID 0 besides root
awk -F: '$3==0 {print}' /etc/passwd

# Accounts with login shells (interactive users)
grep -v "nologin\|false\|sync\|halt\|shutdown" /etc/passwd | awk -F: '{print $1, $3, $7}'

# Recently modified passwd file
stat /etc/passwd
find /etc -name passwd -newer /etc/shadow 2>/dev/null

# Accounts with no password (empty hash field)
awk -F: '$2=="" {print $1, "HAS NO PASSWORD"}' /etc/passwd
```

---

## /etc/shadow

Root-readable only. Contains password hashes and aging policy.

```
root:$6$salt$hash...:19000:0:99999:7:::
ghostop:$6$salt$hash...:19372:0:99999:7:::
locked_user:!$6$salt$hash...:19000:0:99999:7:::
disabled_user:*:19000:0:99999:7:::
```

Fields: `username:hash:last_changed:min_days:max_days:warn_days:inactive_days:expire_date:reserved`

| Hash Prefix | Algorithm | Status |
|------------|-----------|--------|
| `$1$` | MD5 | Weak — deprecated |
| `$5$` | SHA-256 | Acceptable |
| `$6$` | SHA-512 | Current standard |
| `$y$` | yescrypt | Modern, strongest |
| `!hash` | Locked | Account locked, hash preserved |
| `*` | Disabled | No valid hash, cannot authenticate |
| `` (empty) | No password | Dangerous — anyone can login |

```bash
# Check shadow file permissions (must be root-only)
stat /etc/shadow
ls -la /etc/shadow
# Should be: -rw-r----- root shadow

# Find accounts with weak hash types
awk -F: '$2 ~ /^\$1\$/ {print $1, "uses MD5"}' /etc/shadow
awk -F: '$2 ~ /^\$5\$/ {print $1, "uses SHA-256"}' /etc/shadow

# Find accounts with no password
awk -F: '$2=="" {print $1, "NO PASSWORD"}' /etc/shadow

# Find locked vs active accounts
awk -F: '$2~/^!/ {print $1, "LOCKED"}' /etc/shadow
awk -F: '$2~/^\*/ {print $1, "DISABLED"}' /etc/shadow
```

---

## /etc/group

Group membership definitions.

```
root:x:0:
sudo:x:27:ghostop
docker:x:999:ghostop
```

Fields: `group_name:password:GID:member_list`

```bash
# Find users in privileged groups
grep -E "^(sudo|wheel|admin|docker|disk|shadow):" /etc/group

# Docker group = effective root (can mount host filesystem)
grep "^docker:" /etc/group

# Shadow group = can read /etc/shadow
grep "^shadow:" /etc/group
```

**Docker group privilege:** Members of the docker group can run `docker run -v /:/host --privileged ubuntu chroot /host` — mounting the entire host filesystem and effectively becoming root. Treat docker group membership as equivalent to sudo.

---

## PAM — Pluggable Authentication Modules

PAM is the authentication framework between the login process and the actual credential verification. It is modular — you can stack multiple authentication methods.

### PAM Configuration

```
/etc/pam.d/          directory of per-service PAM configs
/etc/pam.d/sshd      SSH daemon authentication
/etc/pam.d/sudo      sudo authentication
/etc/pam.d/login     console login
/etc/pam.d/common-auth  shared auth stack (included by others)
```

### PAM Stack Format

```
# /etc/pam.d/common-auth
auth    required    pam_unix.so    # check /etc/shadow
auth    optional    pam_google_authenticator.so  # TOTP MFA
auth    sufficient  pam_permit.so  # always succeed (DANGEROUS if misused)
```

Control flags:
- `required` — must succeed; failure continues but auth ultimately fails
- `requisite` — must succeed; immediate failure on error
- `sufficient` — if succeeds and no prior failure, auth succeeds immediately
- `optional` — result doesn't affect overall auth (unless only module)

### PAM Backdoor Detection

```bash
# Look for pam_exec (execute arbitrary script during auth)
grep -r "pam_exec" /etc/pam.d/

# Look for pam_permit (always succeeds — bypasses auth)
grep -r "pam_permit" /etc/pam.d/

# Look for unexpected modules
ls /lib/x86_64-linux-gnu/security/
ls /usr/lib/x86_64-linux-gnu/security/
# Compare against known-good package list
dpkg -l | grep libpam

# Review complete PAM stack for SSH
cat /etc/pam.d/sshd
cat /etc/pam.d/common-auth
```

---

## SSH Authentication

SSH supports multiple authentication methods, configured in `/etc/ssh/sshd_config`.

### Key-Based Authentication

```bash
# User's authorized keys
~/.ssh/authorized_keys

# System-wide authorized keys location (if configured)
# /etc/ssh/sshd_config: AuthorizedKeysFile
grep AuthorizedKeysFile /etc/ssh/sshd_config

# Key format
ssh-ed25519 AAAA... comment@hostname
ssh-rsa AAAA... comment

# Dangerous options in authorized_keys
# command="..." — restrict to specific command only
# no-pty — no terminal allocation
# from="192.168.1.0/24" — restrict source IP
# An attacker adds a key with no restrictions
```

### sshd_config Security Settings

```bash
cat /etc/ssh/sshd_config | grep -v "^#\|^$"
```

Critical settings:

| Setting | Secure Value | Risk if Wrong |
|---------|-------------|---------------|
| `PermitRootLogin` | `no` or `prohibit-password` | Direct root SSH access |
| `PasswordAuthentication` | `no` | Password brute force |
| `PubkeyAuthentication` | `yes` | Key-based auth |
| `AuthorizedKeysFile` | `.ssh/authorized_keys` | Non-standard key location |
| `AllowUsers` / `DenyUsers` | Restrict to named users | Unrestricted SSH |
| `MaxAuthTries` | `3` | Unlimited brute force attempts |
| `LoginGraceTime` | `60` | Long window for attacks |
| `X11Forwarding` | `no` | X11 forwarding pivot |
| `AllowTcpForwarding` | `no` | Tunnel creation |

```bash
# Check for dangerous sshd settings
grep -iE "PermitRootLogin yes|PasswordAuthentication yes|X11Forwarding yes" /etc/ssh/sshd_config
```

---

## Account Manipulation Techniques

### Creating a Backdoor Account

```bash
# Add root-equivalent account to /etc/passwd directly
echo "support:x:0:0::/root:/bin/bash" >> /etc/passwd
echo "support:$(openssl passwd -6 'backdoor123')" >> /etc/shadow

# Standard useradd
useradd -m -s /bin/bash -u 1337 svc-monitor
echo "svc-monitor:P@ssw0rd" | chpasswd

# Add to sudo group
usermod -aG sudo svc-monitor

# Detection: /etc/passwd and /etc/shadow modification times
stat /etc/passwd /etc/shadow
```

### SSH Key Implantation

```bash
# Add attacker public key to root
mkdir -p /root/.ssh
echo "ssh-ed25519 AAAA...attacker_key" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# Add to all users
for home in /home/* /root; do
  mkdir -p "$home/.ssh"
  echo "ssh-ed25519 AAAA...attacker_key" >> "$home/.ssh/authorized_keys"
done
```

### /etc/sudoers Modification

```bash
# Grant full root without password
echo "attacker ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Via sudoers.d (less obvious)
echo "www-data ALL=(ALL) NOPASSWD: /bin/bash" > /etc/sudoers.d/www-data
chmod 440 /etc/sudoers.d/www-data
```

---

## Investigation Commands

```bash
# Full account audit
echo "=== UID 0 ACCOUNTS ==="
awk -F: '$3==0' /etc/passwd

echo "=== LOGIN SHELL ACCOUNTS ==="
grep -v "nologin\|false" /etc/passwd | awk -F: '{print $1, $3, $6, $7}'

echo "=== PRIVILEGED GROUP MEMBERS ==="
for g in sudo wheel admin docker shadow disk; do
  members=$(getent group $g 2>/dev/null | cut -d: -f4)
  [ -n "$members" ] && echo "$g: $members"
done

echo "=== SUDO RIGHTS ==="
cat /etc/sudoers | grep -v "^#\|^$"
ls /etc/sudoers.d/ && cat /etc/sudoers.d/* 2>/dev/null

echo "=== ALL SSH AUTHORIZED KEYS ==="
find / -name "authorized_keys" 2>/dev/null | while read f; do
  echo "=== $f ==="
  cat "$f"
done

echo "=== RECENTLY MODIFIED ACCOUNT FILES ==="
stat /etc/passwd /etc/shadow /etc/group /etc/sudoers

echo "=== LOGIN HISTORY ==="
last -F | head -30
lastb | head -20
lastlog | grep -v "Never"

echo "=== FAILED AUTH PATTERNS ==="
grep "Failed password\|Invalid user" /var/log/auth.log 2>/dev/null | \
  awk '{print $11}' | sort | uniq -c | sort -rn | head -10

echo "=== PAM BACKDOOR CHECK ==="
grep -r "pam_exec\|pam_permit" /etc/pam.d/ 2>/dev/null

echo "=== SSHD CONFIG RISKS ==="
grep -iE "PermitRootLogin yes|PasswordAuthentication yes" /etc/ssh/sshd_config
```

---

## MITRE ATT&CK Mapping

| Technique | ID |
|-----------|-----|
| Valid Accounts | T1078 |
| Create Account: Local Account | T1136.001 |
| Account Manipulation: SSH Authorized Keys | T1098.004 |
| Brute Force: Password Guessing | T1110.001 |
| Brute Force: Password Spraying | T1110.003 |
| Modify Authentication Process: PAM | T1556.003 |
| Unsecured Credentials | T1552 |

---

## Sigma Rule — New Account Created

```yaml
title: New Local User Account Created on Linux
id: f2a3b4c5-d6e7-8901-fabc-012345678901
status: stable
description: >
  Detects creation of new local user accounts on Linux.
  Attackers create backdoor accounts for persistent access.
author: Solomon James (@Jaysolex)
tags:
  - attack.persistence
  - attack.t1136.001
logsource:
  product: linux
  service: auditd
detection:
  selection:
    type: ADD_USER
  condition: selection
falsepositives:
  - Legitimate user provisioning during deployment
  - Admin creating service accounts
level: medium
```

---

## Practitioner Notes

**On the docker group as root equivalent:** This is frequently misunderstood by administrators who add developers to the docker group for convenience. `docker run -v /:/host -it ubuntu chroot /host` mounts the entire host filesystem and gives a root shell within the container that maps to host root. Any member of the docker group effectively has root. Audit docker group membership the same way you audit sudo.

**On PAM sufficient and backdoors:** A `pam_exec.so sufficient` entry that runs an attacker-controlled script means any authentication request executes that script. If the script exits 0, authentication succeeds regardless of password. This is completely invisible to users logging in. The only detection is reviewing the PAM configuration files and checking the modification timestamps.

**On authorized_keys and key rotation:** Adding a key to authorized_keys grants persistent access that survives password changes, account lockouts (unless key-based auth is disabled in sshd_config), and reboots. During IR, removing the malicious key, rotating the account password, and reviewing sshd_config are all necessary — any one alone is insufficient.

---

## Knowledge Validation

**A user account has shell /usr/sbin/nologin but you find successful SSH logins for it in auth.log. How is this possible?**
SSH can be configured to allow a specific command via the authorized_keys `command=` option — the nologin shell is bypassed because SSH executes the specified command directly without spawning a login shell. Alternatively, if the account's shell was recently changed to nologin after the attacker already established SSH key access, the attacker may have added a ForceCommand workaround. Check the account's authorized_keys for command= options and check sshd_config for ForceCommand overrides.

**What is the forensic significance of /proc/pid/loginuid versus checking the current UID?**
loginuid is set once at the time of initial login by the PAM login module and cannot be changed by the process or by su/sudo operations. It persists throughout the entire session. A root shell spawned via sudo still shows the original login user's UID in loginuid. This enables attribution — determining who was originally logged in regardless of what privilege changes occurred — which is essential during IR when attackers use sudo or su to escalate.

**During IR you find /etc/pam.d/sshd contains `auth sufficient pam_exec.so /tmp/.auth`. What has happened and what do you do?**
An attacker inserted a PAM backdoor — any SSH authentication attempt executes /tmp/.auth, and if that script exits 0, authentication succeeds regardless of the actual password or key. The attacker has a universal backdoor into every account on the system. Steps: immediately disable the pam_exec line, analyze /tmp/.auth for what it does and whether it called home, check auth.log for all logins since the PAM file was modified, audit all accounts for new keys or password changes, and investigate how the attacker got write access to /etc/pam.d/.

---

*Linux/10-User-Account-Internals | OS-Internals-for-SOC | Solomon James (@Jaysolex)*
