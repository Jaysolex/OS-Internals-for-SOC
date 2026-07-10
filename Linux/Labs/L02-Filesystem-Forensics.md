# L02 — Filesystem Forensics

**Module:** Linux/01-Filesystem-Hierarchy  
**Time:** 40 minutes  
**Objective:** Explore every critical root directory from a security perspective. Find SUID binaries, world-writable directories, hidden files, and recent filesystem modifications.

---

## Exercise 1 — Directory Security Audit

```bash
# Find all SUID binaries on the system
find / -type f -perm -4000 2>/dev/null | sort

# Compare against expected baseline (common legitimate SUID binaries)
expected=("sudo" "su" "passwd" "chsh" "chfn" "ping" "mount" "umount" "newgrp" "gpasswd")
find / -type f -perm -4000 2>/dev/null | while read bin; do
  name=$(basename "$bin")
  known=false
  for e in "${expected[@]}"; do [ "$name" = "$e" ] && known=true; done
  $known || echo "UNEXPECTED SUID: $bin"
done
```

**Question:** Which SUID binaries on your system are outside /bin, /sbin, /usr/bin, /usr/sbin?

---

## Exercise 2 — World-Writable Directories

```bash
# Find world-writable directories (everyone can write)
find / -type d -perm -0002 \
  -not -path "/proc/*" -not -path "/sys/*" \
  -not -path "/dev/*" -not -path "/tmp" \
  -not -path "/var/tmp" 2>/dev/null

# Find world-writable files in sensitive locations
find /etc /usr/bin /usr/sbin /bin /sbin \
  -perm -002 -type f 2>/dev/null
```

**Expected result:** No world-writable files in /etc, /bin, /sbin. Only /tmp and /var/tmp should appear.

---

## Exercise 3 — /dev/shm Analysis

```bash
# Check current /dev/shm contents
ls -la /dev/shm/

# Create a test file in /dev/shm (simulate attacker staging)
echo "test payload" > /dev/shm/.hidden_payload
ls -la /dev/shm/

# Check if it shows up in df (it won't — RAM backed)
df -h /dev/shm

# Verify it never touches disk
# This is what makes /dev/shm attractive to attackers
lsof +D /dev/shm/

# Cleanup
rm /dev/shm/.hidden_payload
```

---

## Exercise 4 — Recent Filesystem Changes

```bash
# Files modified in the last 24 hours (excluding /proc /sys /dev)
find / \( -path /proc -o -path /sys -o -path /dev \) -prune -o \
  -type f -mtime -1 -printf "%TY-%Tm-%Td %TH:%TM  %p\n" 2>/dev/null | sort | tail -50

# Files with no owner (orphaned — may indicate deleted attacker account)
find / -nouser -nogroup \
  -not -path "/proc/*" -not -path "/sys/*" -ls 2>/dev/null

# Hidden files in non-home locations
find /tmp /var/tmp /opt /srv -name ".*" -ls 2>/dev/null
```

---

## Exercise 5 — /proc/self Exploration

```bash
# Explore your own process via /proc/self
cat /proc/self/cmdline | tr '\0' ' '
cat /proc/self/status | head -20
ls -la /proc/self/fd/
cat /proc/self/maps | head -20

# Find the PID of your current bash session
echo "My PID: $$"
ls -la /proc/$$/exe
```

---

## Exercise 6 — Timestamp Analysis

```bash
# Create a test file and examine all timestamps
echo "test" > /tmp/timestamp_test.txt
stat /tmp/timestamp_test.txt

# Modify content — watch mtime change but not ctime from the kernel
sleep 1
echo "modified" >> /tmp/timestamp_test.txt
stat /tmp/timestamp_test.txt

# Try to fake the mtime (timestomping)
touch -t 202001010000 /tmp/timestamp_test.txt
stat /tmp/timestamp_test.txt
# Note: mtime changed but ctime reflects actual time of change

# Cleanup
rm /tmp/timestamp_test.txt
```

**Key observation:** mtime can be faked. ctime cannot be modified by normal userspace tools.

---

## Validation

Run the triage script and verify filesystem artifacts are collected:

```bash
sudo bash ~/OS-Internals-for-SOC/Scripts/Linux/linux-triage.sh /tmp/lab02
ls /tmp/lab02/
cat /tmp/lab02/06_suid_sgid.txt | head -20
```
