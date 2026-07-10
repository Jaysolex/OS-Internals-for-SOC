# L08 — Permissions & Privilege Escalation

**Module:** Linux/07-Permissions-Capabilities  
**Time:** 40 minutes  
**Objective:** Find privilege escalation vectors — misconfigured SUID binaries, dangerous capabilities, sudo misconfigurations, and world-writable files in PATH.

---

## Exercise 1 — SUID Binary Audit

```bash
# Find all SUID binaries
find / -type f -perm -4000 2>/dev/null | sort > /tmp/suid_found.txt
cat /tmp/suid_found.txt

# Cross-reference against known-good list
known_suid=(
  "/usr/bin/sudo" "/usr/bin/su" "/usr/bin/passwd" "/usr/bin/chsh"
  "/usr/bin/chfn" "/usr/bin/newgrp" "/usr/bin/gpasswd" "/usr/bin/mount"
  "/usr/bin/umount" "/usr/bin/ping" "/usr/bin/pkexec"
)

echo "=== UNEXPECTED SUID BINARIES ==="
while IFS= read -r suid; do
  known=false
  for k in "${known_suid[@]}"; do [ "$suid" = "$k" ] && known=true; done
  $known || echo "UNEXPECTED: $suid"
done < /tmp/suid_found.txt

rm /tmp/suid_found.txt
```

---

## Exercise 2 — Linux Capabilities Audit

```bash
# Find all binaries with capabilities set
getcap -r / 2>/dev/null

# Common dangerous capabilities:
echo ""
echo "Dangerous capabilities to watch for:"
echo "  cap_setuid     = can become any user (equivalent to SUID root)"
echo "  cap_dac_override = bypass file permission checks (read any file)"
echo "  cap_sys_admin  = near-equivalent to root"
echo "  cap_net_raw    = raw socket access (packet capture, ICMP tunnel)"
echo "  cap_sys_module = load kernel modules (rootkit insertion)"

# Check capabilities on your Python binary
getcap /usr/bin/python3 2>/dev/null || echo "No capabilities on python3"
```

---

## Exercise 3 — Sudo Configuration Analysis

```bash
# What can the current user run with sudo?
sudo -l

# Check sudoers for dangerous patterns
sudo cat /etc/sudoers | grep -v "^#\|^$"
sudo ls /etc/sudoers.d/ 2>/dev/null
sudo cat /etc/sudoers.d/* 2>/dev/null

# Dangerous patterns to flag:
echo ""
echo "=== Dangerous sudoers patterns ==="
echo "NOPASSWD: ALL     — full root without password"
echo "NOPASSWD: /bin/bash — root shell without password"
echo "(ALL) ALL         — run anything as any user"
echo "!authenticate     — never require password"
```

---

## Exercise 4 — PATH Hijacking Simulation

```bash
# Check if any writable directory is in PATH
echo "Current PATH: $PATH"
echo ""
echo "=== Checking PATH directories for writability ==="
IFS=: read -ra path_dirs <<< "$PATH"
for dir in "${path_dirs[@]}"; do
  if [ -w "$dir" ] 2>/dev/null; then
    echo "WRITABLE: $dir"
  else
    echo "Safe: $dir"
  fi
done

# ~/.local/bin is often in PATH on Ubuntu and writable by user
# An attacker plants a script named 'ls' or 'sudo' there
# Every time the victim runs that command, the malicious version executes
```

---

## Exercise 5 — /etc/passwd Direct Write Check

```bash
# Check permissions on critical auth files
ls -la /etc/passwd /etc/shadow /etc/group /etc/sudoers

# Verify passwd is world-readable but NOT world-writable
stat /etc/passwd | grep "Access:"

# If /etc/passwd were world-writable, an attacker could add:
# backdoor::0:0::/root:/bin/bash
# (UID 0 = root, no password)
# This is a critical misconfiguration to check in any assessment
```

---

## Validation

```bash
# Run the persistence hunter to verify SUID findings
sudo bash ~/OS-Internals-for-SOC/Scripts/Linux/persistence-hunter.sh 2>/dev/null | \
  grep -A5 "SUID"

# Run log parser for privilege escalation events
sudo bash ~/OS-Internals-for-SOC/Scripts/Linux/log-parser.sh privesc
```
