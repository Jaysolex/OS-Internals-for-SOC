# L11 — User Account Internals & Forensics

**Module:** Linux/10-User-Account-Internals  
**Time:** 35 minutes  
**Objective:** Audit user accounts, analyse PAM configuration for backdoors, review SSH configuration, and investigate authentication logs.

---

## Exercise 1 — Account Enumeration

```bash
# Users with login shells (can log in interactively)
echo "=== Interactive users ==="
grep -v "nologin\|false\|sync\|halt\|shutdown" /etc/passwd | \
  awk -F: '{printf "User: %-20s UID: %-6s Shell: %s\n", $1, $3, $7}'

# Users with UID 0 (root-equivalent)
echo "=== UID 0 accounts (should only be root) ==="
awk -F: '$3==0 {print}' /etc/passwd

# Recently modified account files
echo "=== Account file modification times ==="
stat /etc/passwd /etc/shadow /etc/group 2>/dev/null | grep -E "File:|Modify:"

# Check for accounts with no password
echo "=== Accounts with no password hash ==="
sudo awk -F: '$2=="" {print $1,"HAS NO PASSWORD"}' /etc/shadow 2>/dev/null
```

---

## Exercise 2 — Privileged Group Membership

```bash
# Check who is in sensitive groups
for group in sudo wheel admin docker shadow disk; do
  members=$(getent group $group 2>/dev/null | cut -d: -f4)
  if [ -n "$members" ]; then
    echo "$group: $members"
    # Docker group = effective root
    [ "$group" = "docker" ] && echo "  WARNING: Docker group = root equivalent"
  fi
done
```

---

## Exercise 3 — PAM Configuration Review

```bash
# Review SSH PAM stack
echo "=== /etc/pam.d/sshd ==="
cat /etc/pam.d/sshd

echo "=== /etc/pam.d/common-auth ==="
cat /etc/pam.d/common-auth

# Look for dangerous PAM modules
echo "=== Checking for dangerous PAM entries ==="
grep -r "pam_exec\|pam_permit\|sufficient.*exec" /etc/pam.d/ 2>/dev/null && \
  echo "REVIEW: pam_exec or pam_permit found" || echo "Clean: no dangerous PAM modules"

# List PAM modules directory
echo "=== Available PAM modules ==="
ls /lib/x86_64-linux-gnu/security/ 2>/dev/null || ls /lib/security/ 2>/dev/null
```

---

## Exercise 4 — SSH Configuration Audit

```bash
# Check sshd config for security issues
echo "=== Critical sshd_config settings ==="
grep -E "PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|\
AuthorizedKeysFile|MaxAuthTries|AllowTcpForwarding|X11Forwarding|\
AllowUsers|DenyUsers" /etc/ssh/sshd_config

echo ""
echo "=== Security assessment ==="
root_login=$(grep "^PermitRootLogin" /etc/ssh/sshd_config | awk '{print $2}')
pass_auth=$(grep "^PasswordAuthentication" /etc/ssh/sshd_config | awk '{print $2}')
[ "$root_login" = "yes" ] && echo "RISK: Root login permitted" || echo "OK: Root login restricted"
[ "$pass_auth" = "yes" ] && echo "RISK: Password auth enabled (brute force possible)" || \
  echo "OK: Password auth disabled"

# Find all authorized_keys files
echo "=== All authorized_keys files ==="
find / -name "authorized_keys" -type f 2>/dev/null | while read f; do
  echo "--- $f ---"
  cat "$f"
  echo ""
done
```

---

## Exercise 5 — Login History Analysis

```bash
# Full login history
last -F | head -30

# Failed logins
lastb 2>/dev/null | head -20 || echo "btmp not readable without sudo"
sudo lastb 2>/dev/null | head -20

# Last login per user
lastlog | grep -v "Never logged"

# Check for logins at unusual hours (2am-5am)
last -F | awk '{print $5, $6, $7, $8, $1}' | \
  grep -E " 0[2-5]:" | head -20
```

---

## Validation

```bash
# Run full triage and check user artifacts
sudo bash ~/OS-Internals-for-SOC/Scripts/Linux/linux-triage.sh /tmp/lab11
cat /tmp/lab11/02_passwd.txt
cat /tmp/lab11/02_ssh_auth_keys.txt 2>/dev/null
```
