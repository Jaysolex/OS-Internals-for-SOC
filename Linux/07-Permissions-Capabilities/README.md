# Linux/07 — Permissions & Capabilities

> Linux permissions are the first line of defence between a standard user and root. Every privilege escalation technique on Linux either exploits a misconfigured permission, abuses a capability, or bypasses the permission model entirely. Understanding this model at the kernel level is what allows you to identify misconfigurations before attackers do.

![MITRE](https://img.shields.io/badge/MITRE-T1548.001%20|%20T1548.003%20|%20T1068-red)
![Platform](https://img.shields.io/badge/Platform-Linux-orange)

---

## Discretionary Access Control (DAC)

Linux DAC is based on three identities and three permission sets applied to every file and directory.

### Identities

Every file has an owner (UID) and a group (GID). Every process has a real UID/GID (who it is) and effective UID/GID (what permissions it has).

### Permission Bits

```
-rwxr-xr--  1  root  admin  4096  Jan 1  /usr/bin/example
 |||||||||||
 |---------- file type (- = regular file, d = directory, l = symlink)
  |||        owner permissions (rwx = read/write/execute)
     |||     group permissions (r-x = read/execute)
        |||  other permissions (r-- = read only)
```

### Permission Values

| Permission | File | Directory |
|-----------|------|-----------|
| Read (4) | View file content | List directory contents |
| Write (2) | Modify file content | Create/delete files within |
| Execute (1) | Run as program | Enter directory (cd) |

### Octal Notation

```bash
chmod 755 file    # rwxr-xr-x
chmod 644 file    # rw-r--r--
chmod 700 file    # rwx------
chmod 400 file    # r--------  (read-only, even for owner)
```

---

## Special Permission Bits

Beyond rwx, three special bits control elevated behaviour.

### SUID (Set User ID) — Bit 4000

When a SUID binary executes, the process effective UID becomes the file owner's UID — not the calling user's UID. Most commonly used to give non-root users access to privileged operations.

```bash
# Legitimate SUID example
ls -la /usr/bin/passwd
-rwsr-xr-x 1 root root 59976 /usr/bin/passwd
# 's' in owner execute position = SUID set
# passwd runs as root so it can modify /etc/shadow

# Finding all SUID binaries
find / -perm -4000 -type f 2>/dev/null
```

**SUID exploitation:** Any SUID root binary that can be made to execute arbitrary code elevates the attacker to root. Classic examples:

```bash
# If vim is SUID root (misconfiguration)
vim -c ':!/bin/bash'
# Shell spawns with euid=0

# If find is SUID root
find . -exec /bin/sh \; -quit

# If python is SUID root
python3 -c 'import os; os.execl("/bin/sh", "sh")'
```

### SGID (Set Group ID) — Bit 2000

When a SGID binary executes, the process effective GID becomes the file's group. On directories, new files inherit the directory's group instead of the creator's primary group.

```bash
ls -la /usr/bin/wall
-rwxr-sr-x 1 root tty 18912 /usr/bin/wall
# 's' in group execute position = SGID set

# Finding SGID binaries
find / -perm -2000 -type f 2>/dev/null
```

### Sticky Bit — Bit 1000

On directories, prevents users from deleting files owned by other users even if they have write permission to the directory. Used on /tmp.

```bash
ls -la /tmp
drwxrwxrwt  ... /tmp
# 't' in other execute position = sticky bit

# Without sticky bit, any user could delete others' files in /tmp
```

---

## Linux Capabilities

Traditional Unix permissions are binary — a process either has root (full privileges) or it doesn't. Linux capabilities divide root's privileges into ~40 distinct units that can be granted independently.

### Why Capabilities Matter

Instead of running a service as root just because it needs to bind to port 80, you can grant only `CAP_NET_BIND_SERVICE`. If that service is compromised, the attacker gets network binding ability — not full root.

### Key Capabilities

| Capability | What It Allows | Abuse Potential |
|-----------|---------------|-----------------|
| `CAP_SYS_ADMIN` | Mount, namespace, device ops | Near-equivalent to root |
| `CAP_NET_ADMIN` | Network config, firewall rules | Modify iptables, sniff traffic |
| `CAP_NET_BIND_SERVICE` | Bind to ports below 1024 | Required for web servers |
| `CAP_SYS_PTRACE` | ptrace any process | Read memory of any process |
| `CAP_DAC_OVERRIDE` | Bypass file permission checks | Read any file |
| `CAP_DAC_READ_SEARCH` | Bypass read/search permissions | Read any file |
| `CAP_SETUID` | Arbitrary UID changes | Become any user |
| `CAP_SETGID` | Arbitrary GID changes | Join any group |
| `CAP_SYS_MODULE` | Load/unload kernel modules | Rootkit insertion |
| `CAP_SYS_RAWIO` | Raw I/O port access | Hardware manipulation |
| `CAP_CHOWN` | Change file ownership | Take ownership of any file |
| `CAP_KILL` | Send signals to any process | Kill any process including auditd |
| `CAP_SYS_CHROOT` | chroot to any directory | Container escape |
| `CAP_NET_RAW` | Raw sockets, packet capture | Network sniffing |
| `CAP_AUDIT_WRITE` | Write to audit log | Log manipulation |
| `CAP_AUDIT_CONTROL` | Configure audit system | Disable auditing |

### Capability Sets

Each process has three capability sets:
- **Permitted** — maximum capabilities the process may have
- **Effective** — currently active capabilities
- **Inheritable** — capabilities passed to child processes via exec

```bash
# View capabilities of current process
cat /proc/self/status | grep Cap
# CapInh, CapPrm, CapEff, CapBnd, CapAmb

# Decode capability bitmask
capsh --decode=0000000000000000

# View capabilities of running process
cat /proc/<pid>/status | grep Cap
getpcaps <pid>

# View capabilities set on a file
getcap /usr/bin/ping
# /usr/bin/ping cap_net_raw=ep
```

### Setting Capabilities on Files

```bash
# Grant capability to binary (instead of SUID)
setcap cap_net_bind_service=ep /usr/local/bin/myserver

# Remove all capabilities from binary
setcap -r /usr/local/bin/myserver

# Find all files with capabilities set
getcap -r / 2>/dev/null
```

### Capability Exploitation

```bash
# If python3 has cap_setuid set
getcap /usr/bin/python3
# /usr/bin/python3 = cap_setuid+ep

python3 -c "import os; os.setuid(0); os.system('/bin/bash')"
# Shell as root

# If perl has cap_dac_override (bypass file permissions)
perl -e 'open(my $f, "<", "/etc/shadow"); print <$f>'

# If tar has cap_dac_read_search
tar -czf /tmp/shadow.tar.gz /etc/shadow
```

---

## sudo — Delegated Privilege

sudo allows specific users to run specific commands as root (or another user) after password authentication.

### /etc/sudoers Format

```
# User privilege specification
root    ALL=(ALL:ALL) ALL

# Allow user 'deploy' to restart nginx as root without password
deploy  ALL=(root) NOPASSWD: /bin/systemctl restart nginx

# Allow group 'devops' to run any command
%devops ALL=(ALL) ALL

# Dangerous: allow running bash as root
baduser ALL=(ALL) NOPASSWD: /bin/bash
```

### sudo Privilege Escalation

```bash
# Check what sudo allows current user
sudo -l

# If sudo allows running vim
sudo vim -c ':!/bin/bash'

# If sudo allows running find
sudo find / -exec /bin/bash \; -quit

# If sudo allows running less/man (shell escape)
sudo less /etc/shadow
!/bin/bash      # inside less

# If sudo allows LD_PRELOAD (rare but critical misconfiguration)
# /etc/sudoers: Defaults env_keep += "LD_PRELOAD"
sudo LD_PRELOAD=/tmp/evil.so /usr/bin/something
```

### GTFOBins

GTFOBins (https://gtfobins.github.io) documents sudo/SUID/capability escape techniques for hundreds of binaries. Any binary listed there should never be in sudoers or SUID without justification.

---

## /etc/passwd and /etc/shadow

```
/etc/passwd  — world-readable, contains account info
/etc/shadow  — root-readable only, contains password hashes
```

### /etc/passwd Format

```
username:x:UID:GID:GECOS:home:shell
root:x:0:0:root:/root:/bin/bash
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
```

The `x` in the password field means the hash is in /etc/shadow. If /etc/passwd contains an actual hash (from a legacy system), it is readable by all users and can be cracked offline.

### /etc/shadow Format

```
username:$hash_type$salt$hash:last_changed:min:max:warn:inactive:expire
root:$6$salt$hash...:19000:0:99999:7:::
```

Hash types:
- `$1$` = MD5 (weak, deprecated)
- `$5$` = SHA-256
- `$6$` = SHA-512 (current standard)
- `$y$` = yescrypt (modern, strongest)

### World-Writable /etc/passwd (Critical Misconfiguration)

```bash
# If /etc/passwd is world-writable (attacker can add root user)
echo "backdoor::0:0::/root:/bin/bash" >> /etc/passwd
# Now: su backdoor (no password, UID 0)
```

---

## Namespace-Based Privilege Isolation

User namespaces allow mapping user IDs inside a namespace — a process can appear as root inside a container but is an unprivileged user outside.

```bash
# Create user namespace where we appear as root
unshare --user --map-root-user /bin/bash
# Inside: id shows uid=0 gid=0
# Outside: still unprivileged

# Container escape via namespace misconfiguration
# If container runs with --privileged flag or with CAP_SYS_ADMIN:
nsenter --target 1 --mount --uts --ipc --net --pid
# Enters host namespaces — effective escape
```

---

## Detection and Hardening

### Find Privilege Escalation Vectors

```bash
# SUID binaries not in default installation
find / -perm -4000 -type f 2>/dev/null | \
  grep -vE "^(/usr/bin|/usr/sbin|/bin|/sbin)" 

# SGID binaries
find / -perm -2000 -type f 2>/dev/null

# Files with capabilities
getcap -r / 2>/dev/null

# World-writable files in sensitive locations
find /etc /usr/bin /usr/sbin /bin /sbin -perm -002 -type f 2>/dev/null

# World-writable directories
find / -type d -perm -002 -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null

# Check sudoers for dangerous entries
grep -E "NOPASSWD|ALL.*ALL|!authenticate" /etc/sudoers /etc/sudoers.d/* 2>/dev/null

# Files owned by root but writable by others
find / -user root -perm -002 -not -path "/proc/*" -type f 2>/dev/null
```

### auditd Rules for Privilege Monitoring

```bash
# Monitor SUID execution
auditctl -a always,exit -F arch=b64 -S execve -F euid=0 -F auid!=0 -k suid_execution

# Monitor capability changes
auditctl -a always,exit -F arch=b64 -S setuid -S setgid -k privilege_change

# Monitor sudoers modification
auditctl -w /etc/sudoers -p wa -k sudoers_change
auditctl -w /etc/sudoers.d -p wa -k sudoers_change

# Monitor /etc/passwd and /etc/shadow
auditctl -w /etc/passwd -p wa -k identity
auditctl -w /etc/shadow -p wa -k identity
```

---

## MITRE ATT&CK Mapping

| Technique | ID |
|-----------|-----|
| Abuse Elevation: SUID/SGID | T1548.001 |
| Abuse Elevation: Sudo and Sudo Caching | T1548.003 |
| Exploitation for Privilege Escalation | T1068 |
| Valid Accounts | T1078 |

---

## Sigma Rule — SUID Binary Executed by Non-Root

```yaml
title: Unexpected SUID Binary Execution
id: d0e1f2a3-b4c5-6789-defa-890123456789
status: stable
description: >
  Detects execution of a SUID binary by a non-root user
  where the process effective UID becomes 0. May indicate
  privilege escalation via a misconfigured SUID binary.
author: Solomon James (@Jaysolex)
tags:
  - attack.privilege_escalation
  - attack.t1548.001
logsource:
  product: linux
  service: auditd
detection:
  selection:
    type: SYSCALL
    syscall: execve
    euid: 0
    auid|gt: 999
  condition: selection
falsepositives:
  - Legitimate use of passwd, sudo, ping (baseline these)
level: medium
```

---

## Practitioner Notes

**On CAP_SYS_ADMIN:** This single capability is nearly equivalent to full root. It allows mounting filesystems, managing namespaces, loading kernel modules (on some kernels), and much more. Any process with CAP_SYS_ADMIN in a container can typically escape to the host. Treat it as root for threat modelling purposes.

**On GTFOBins in sudoers:** The presence of any binary from the GTFOBins list in sudoers with NOPASSWD is a critical finding regardless of intent. Administrators often add `sudo vim` for convenience without realizing `sudo vim -c ':!/bin/bash'` trivially grants a root shell. Document and remediate during any security assessment.

**On capabilities vs SUID:** Capabilities are the modern, more granular replacement for SUID. A binary that only needs to bind to port 80 should have `cap_net_bind_service` instead of SUID root. However, misconfigured capabilities can be just as dangerous as SUID — `cap_setuid` on a Python binary is effectively SUID root with extra steps.

---

## Knowledge Validation

**What is the difference between real UID and effective UID and why does it matter for SUID exploitation?**
Real UID (ruid) is who actually launched the process — set at login and unchanged. Effective UID (euid) is what permissions the process currently has — used for all permission checks. When a SUID root binary executes, the kernel sets euid to 0 (root) while ruid remains the original user. If the binary allows executing arbitrary code (shell escape, command injection), that code runs with euid=0 — full root privileges — even though the original user is unprivileged.

**A user has `sudo python3 /opt/scripts/backup.py` in sudoers. Why might this still be exploitable?**
If the script imports modules from a path the user can write to (e.g., current directory, PYTHONPATH), the user can create a malicious module with the same name that executes arbitrary code when imported — with root privileges. Additionally, if the script takes a filename argument that is passed to shell commands without sanitisation, it may allow command injection. sudo restrictions on specific scripts only work when the script itself has no execution path for privilege escalation.

**During an IR you find getcap output showing /usr/bin/python3 = cap_setuid+ep. What is the impact and what do you do?**
This means any user can call os.setuid(0) in Python and become root — functionally identical to SUID root on Python. Impact: any user on the system can trivially escalate to root. Immediate remediation: `setcap -r /usr/bin/python3`. Investigate how this capability was set — check auditd records for `setcap` execution, identify who set it and when, determine if any backdoors were planted using the elevated access.

---

*Linux/07-Permissions-Capabilities | OS-Internals-for-SOC | Solomon James (@Jaysolex)*
