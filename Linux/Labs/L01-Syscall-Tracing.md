# L01 — Syscall Tracing

**Module:** Linux/00-Architecture  
**Time:** 20 minutes  
**Objective:** Understand the syscall interface by tracing real system calls and configuring auditd to capture them.

---

## Exercise 1 — Trace syscalls with strace

```bash
# Trace all syscalls made by ls
strace ls /tmp 2>&1 | head -30

# Count syscalls by type
strace -c ls /tmp 2>&1

# Trace only specific syscalls (execve and openat)
strace -e trace=execve,openat ls /tmp 2>&1
```

**Questions:**
- Which syscall does ls use to open the directory?
- How many execve calls does a simple `ls` make?
- What is the first syscall in any process execution?

---

## Exercise 2 — Monitor execve with auditd

```bash
# Add an audit rule to monitor all process execution
sudo auditctl -a always,exit -F arch=b64 -S execve -k lab_exec

# Run a few commands
ls /tmp
whoami
id

# Read the audit log
sudo ausearch -k lab_exec | tail -30

# Remove the rule when done
sudo auditctl -d always,exit -F arch=b64 -S execve -k lab_exec
```

**Questions:**
- What fields does the auditd EXECVE record contain?
- What is the `auid` field and why is it different from `uid`?

---

## Exercise 3 — Check kernel security settings

```bash
# Check ASLR
cat /proc/sys/kernel/randomize_va_space

# Check kernel taint
cat /proc/sys/kernel/tainted

# Check LSM modules loaded
cat /sys/kernel/security/lsm 2>/dev/null || cat /sys/kernel/security/lsm

# Check dmesg for security messages
dmesg | grep -i "security\|selinux\|apparmor\|audit" | head -20
```

**Expected results:** ASLR = 2, tainted = 0 on clean system.

---

## Validation

Run the triage script and verify it captures execve events:

```bash
sudo bash ~/OS-Internals-for-SOC/Scripts/Linux/linux-triage.sh /tmp/lab01
cat /tmp/lab01/04_processes.txt | head -20
```
