# Linux/12 — Forensics Artifacts

> Every action on a Linux system leaves a mark somewhere. The attacker who knows which marks they leave can clean them up. The investigator who knows where to look finds what was missed. This module maps every forensic artifact on Linux — what it contains, where it lives, how long it survives, and what attackers do to destroy it.

![MITRE](https://img.shields.io/badge/MITRE-T1070%20|%20T1564%20|%20T1003-red)
![Platform](https://img.shields.io/badge/Platform-Linux-orange)

---

## Artifact Survival Matrix

| Artifact | Survives Reboot | Survives Log Clear | Survives Disk Wipe |
|----------|----------------|-------------------|-------------------|
| /var/log/auth.log | ✅ | ❌ | ❌ |
| journald journal | ✅ | Partial | ❌ |
| auditd logs | ✅ | ❌ | ❌ |
| wtmp / btmp | ✅ | ❌ | ❌ |
| bash_history | ✅ | ❌ | ❌ |
| /proc entries | ❌ (volatile) | ✅ | ✅ (while live) |
| Filesystem timestamps | ✅ | ✅ | ❌ |
| Inode data | ✅ | ✅ | ❌ |
| Memory | ❌ | ✅ | ✅ (while live) |
| Swap | ✅ (if unencrypted) | ✅ | ❌ |

---

## Log Artifacts

### /var/log/auth.log

SSH logins, sudo usage, PAM authentication, su commands. First target for attackers to clear.

```bash
# Parse failed logins
grep "Failed password" /var/log/auth.log | \
  awk '{print $1,$2,$3,$11}' | sort | uniq -c | sort -rn

# Parse successful logins
grep "Accepted" /var/log/auth.log | \
  awk '{print $1,$2,$3,"user:"$9,"from:"$11}'

# Parse sudo usage
grep "sudo.*COMMAND" /var/log/auth.log | \
  awk -F: '{print $1, $NF}'

# Check for gaps (tampering indicator)
awk '{print $1,$2,$3}' /var/log/auth.log | head -5
awk '{print $1,$2,$3}' /var/log/auth.log | tail -5
```

### wtmp and btmp — Binary Login Records

wtmp records every login, logout, and system reboot. btmp records failed login attempts. Written by the kernel login accounting system — independent of rsyslog.

```bash
# Login history (wtmp)
last -F              # full timestamps
last -F -w           # wide format
last -F -x           # include system events (reboots, runlevel changes)

# Failed logins (btmp)
lastb               # all failed attempts
lastb -F | head -50

# Last login per user (lastlog binary file)
lastlog
lastlog -u username

# Raw wtmp analysis
strings /var/log/wtmp | head -50

# Detect wtmp tampering (size should grow continuously)
stat /var/log/wtmp
ls -la /var/log/wtmp*
```

### journald — Binary Journal

systemd journal stores structured binary log entries that survive rsyslog being stopped.

```bash
# Retrieve SSH events from journal (survives auth.log clearing)
journalctl _COMM=sshd --no-pager

# Events from specific time window
journalctl --since "2024-01-01 00:00:00" --until "2024-01-02 00:00:00"

# Previous boot logs (if attacker rebooted)
journalctl -b -1 --no-pager

# Export for offline analysis
journalctl --output=json > journal_export.json
journalctl --output=export > journal_export.bin
```

---

## Shell History

### bash_history

Records every command typed interactively. Location: `~/.bash_history`. Written when shell exits normally — attackers kill the shell or clear the file to evade.

```bash
# Read history for all users
for home in /home/* /root; do
  user=$(stat -c %U "$home" 2>/dev/null)
  hist="$home/.bash_history"
  if [ -f "$hist" ]; then
    echo "=== $user ($hist) ==="
    cat "$hist"
  fi
done

# History with timestamps (if HISTTIMEFORMAT was set)
# Each timestamp entry: #1234567890
grep -A1 "^#[0-9]\{10\}" ~/.bash_history | head -50

# Find cleared history (file exists but empty)
find /home /root -name ".bash_history" -empty 2>/dev/null

# Find timestomped history (mtime older than last login)
for home in /home/* /root; do
  hist="$home/.bash_history"
  [ -f "$hist" ] || continue
  hist_mtime=$(stat -c %Y "$hist")
  last_login=$(last -F $(basename $home) 2>/dev/null | head -1 | awk '{print $5,$6,$7,$8}')
  echo "$hist: mtime=$(date -d @$hist_mtime) | last_login=$last_login"
done
```

### Other Shell Histories

```bash
# zsh
~/.zsh_history

# fish
~/.local/share/fish/fish_history

# Python REPL
~/.python_history

# MySQL client
~/.mysql_history

# psql
~/.psql_history
```

---

## Filesystem Timestamps — MAC Times

Every file and directory on Linux has three timestamps:

| Timestamp | Meaning | Modified By |
|-----------|---------|------------|
| mtime | Last content modification | Writing to file |
| atime | Last access | Reading file |
| ctime | Last metadata change | chmod, chown, rename, write |

```bash
# View all three timestamps
stat /path/to/file

# Find files modified in last 24 hours
find / -mtime -1 -not \( -path /proc -o -path /sys \) 2>/dev/null

# Find files accessed recently
find /home /etc -atime -1 2>/dev/null

# Timeline — all changes in order
find / -not \( -path /proc -o -path /sys -o -path /dev \) \
  -printf "%T@ %Tc %p\n" 2>/dev/null | sort -n | tail -100
```

### Timestomping Detection

Attackers modify mtime to hide when a file was created or modified. The `touch -t` command changes mtime and atime but ctime always reflects the last metadata change — it cannot be changed by normal userspace tools.

```bash
# Detect timestomping: mtime older than ctime
# Normal: mtime <= ctime
# Suspicious: mtime much older than ctime (file was timestomped)
stat /suspected/file
# If mtime is from years ago but ctime is recent = timestomped

# Script to find timestomped files
find /tmp /var/tmp /dev/shm /opt -type f 2>/dev/null | while read f; do
  mtime=$(stat -c %Y "$f" 2>/dev/null)
  ctime=$(stat -c %Z "$f" 2>/dev/null)
  diff=$((ctime - mtime))
  # If ctime is more than 1 hour newer than mtime
  if [ $diff -gt 3600 ]; then
    echo "POSSIBLE TIMESTOMP: $f (mtime=$(date -d @$mtime), ctime=$(date -d @$ctime))"
  fi
done
```

---

## Deleted File Recovery

When a file is deleted on Linux:
1. The directory entry is removed
2. The inode reference count is decremented
3. If count reaches 0, inode is marked free
4. Data blocks are marked available but NOT overwritten

Until those blocks are overwritten, the data is recoverable.

```bash
# Recover deleted files with The Sleuth Kit
# List deleted inodes
ils /dev/sda1 | head -20

# Recover specific inode
icat /dev/sda1 <inode_number> > recovered_file

# Search for deleted files by content
grep -a "password\|secret\|token" /dev/sda1 2>/dev/null | strings

# extundelete (ext filesystem)
extundelete /dev/sda1 --restore-all --output-dir /tmp/recovered/

# PhotoRec (filesystem-agnostic)
photorec /dev/sda1
```

---

## Memory Forensics Artifacts

### /proc as Live Memory Source

```bash
# Dump process memory
cat /proc/<pid>/maps      # identify regions
# Then use dd or python to read /proc/<pid>/mem

# Find credentials in process memory
strings /proc/<pid>/mem 2>/dev/null | grep -iE "password|token|BEGIN.*KEY"

# Deleted binary still running
ls -la /proc/*/exe 2>/dev/null | grep deleted
cp /proc/<pid>/exe /tmp/recovered_binary
```

### Swap Space

```bash
# Check swap
cat /proc/swaps
swapon --show

# Search swap for artifacts
strings /dev/dm-1 2>/dev/null | grep -iE "password|token|bash"

# Acquire swap for analysis
dd if=/dev/sda2 of=/media/external/swap.img bs=4M
```

---

## Network Forensics Artifacts

```bash
# ARP cache — who communicated recently
ip neigh show
arp -a

# Connection tracking (netfilter conntrack)
conntrack -L 2>/dev/null
cat /proc/net/nf_conntrack 2>/dev/null | head -20

# DNS cache
systemd-resolve --statistics
nscd --invalidate=hosts 2>/dev/null

# Recent TCP connections in logs
grep "DPT=\|SPT=" /var/log/syslog 2>/dev/null | tail -50

# Check for hosts file modification
stat /etc/hosts
cat /etc/hosts | grep -v "^#\|localhost\|^$"
```

---

## Package and Binary Integrity

```bash
# Debian/Ubuntu — verify installed packages
debsums -c 2>/dev/null | grep -v OK

# RPM systems — verify package files
rpm -Va 2>/dev/null | grep -v "^........."

# Check binary hashes against known-good
sha256sum /bin/ls /bin/ps /bin/bash /usr/bin/ssh
# Compare against reference hashes from clean system

# Find recently installed packages
grep " install " /var/log/dpkg.log | tail -20   # Debian
rpm -qa --last | head -20                        # RPM

# Check for world-writable binaries
find /bin /sbin /usr/bin /usr/sbin -perm -002 -type f 2>/dev/null
```

---

## Attacker Anti-Forensics Techniques

| Technique | What It Targets | Detection |
|-----------|---------------|-----------|
| `shred /var/log/auth.log` | Log file content | auditd shred execve, file size zero |
| `history -c` | bash_history | File emptied but ctime updated |
| `touch -t` | File mtime | ctime still shows real time |
| `rm binary` after exec | File on disk | /proc/pid/exe shows (deleted) |
| Kill rsyslog | New log entries | journald and auditd continue |
| Kill auditd | Audit records | dmesg, journal may preserve events |
| Reboot | Volatile memory, /proc | journald persists; previous boot logs |
| Wipe swap | Swap artifacts | Encrypted swap prevents this entirely |
| Overwrite wtmp | Login history | File size change, stat timestamps |

---

## Full Forensic Collection Script

```bash
#!/usr/bin/env bash
# Rapid artifact collection for Linux IR
CASE="/tmp/artifacts_$(hostname)_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$CASE"

echo "[*] Collecting system info..."
uname -a > "$CASE/system_info.txt"
date >> "$CASE/system_info.txt"
uptime >> "$CASE/system_info.txt"

echo "[*] Collecting user artifacts..."
last -F > "$CASE/wtmp.txt"
lastb > "$CASE/btmp.txt" 2>/dev/null
lastlog > "$CASE/lastlog.txt"

echo "[*] Collecting logs..."
cp /var/log/auth.log* "$CASE/" 2>/dev/null
journalctl --no-pager > "$CASE/journal.txt" 2>/dev/null
journalctl -b -1 --no-pager > "$CASE/journal_prev_boot.txt" 2>/dev/null

echo "[*] Collecting shell histories..."
mkdir -p "$CASE/histories"
find /home /root -name ".*history" 2>/dev/null | while read f; do
  cp "$f" "$CASE/histories/$(echo $f | tr '/' '_')" 2>/dev/null
done

echo "[*] Collecting persistence artifacts..."
cat /etc/crontab > "$CASE/crontab.txt"
cat /etc/cron.d/* >> "$CASE/crontab.txt" 2>/dev/null
systemctl list-unit-files --state=enabled > "$CASE/systemd_enabled.txt"
cat /etc/passwd > "$CASE/passwd.txt"
cat /etc/shadow > "$CASE/shadow.txt" 2>/dev/null
cat /etc/sudoers > "$CASE/sudoers.txt"
cat /etc/sudoers.d/* >> "$CASE/sudoers.txt" 2>/dev/null

echo "[*] Collecting network state..."
ss -tnap > "$CASE/connections.txt"
cat /proc/net/tcp > "$CASE/proc_net_tcp.txt"
ip route show > "$CASE/routes.txt"
arp -a > "$CASE/arp.txt"
cat /etc/hosts > "$CASE/hosts.txt"

echo "[*] Collecting process state..."
ps auxef > "$CASE/processes.txt"
ls -la /proc/*/exe 2>/dev/null | grep deleted > "$CASE/deleted_binaries.txt"

echo "[*] Hashing artifacts..."
find "$CASE" -type f | xargs sha256sum > "$CASE/checksums.sha256"

echo "[+] Collection complete: $CASE"
echo "[+] Archive: tar czf ${CASE}.tar.gz $CASE"
```

---

## MITRE ATT&CK Mapping

| Technique | ID |
|-----------|-----|
| Indicator Removal: Clear Linux Logs | T1070.002 |
| Indicator Removal: Timestomp | T1070.006 |
| Indicator Removal: File Deletion | T1070.004 |
| Hide Artifacts | T1564 |
| Hide Artifacts: Hidden Files | T1564.001 |

---

## Practitioner Notes

**On evidence acquisition order:** Memory first — it is the most volatile and contains the most attacker activity. Then network state (connections drop quickly). Then running processes. Then disk image. Never shut down before memory acquisition unless absolutely necessary — you lose all volatile evidence permanently.

**On journald as auth.log backup:** Attackers who clear /var/log/auth.log frequently miss the systemd journal which stores the same events in binary format at /var/log/journal/. Run `journalctl _COMM=sshd` after any auth.log clearing incident — the SSH events are almost certainly still in the journal.

**On ctime and timestomping:** The ctime (inode change time) cannot be modified by normal userspace tools — only by mounting the filesystem with noatime and directly patching the inode. When you find a file whose mtime is from 2019 but ctime is from yesterday, it has been timestomped. The ctime tells you when the attacker actually placed the file.

---

## Knowledge Validation

**An attacker ran `history -c && rm ~/.bash_history`. What forensic evidence survives?**
The bash_history file is deleted or emptied — content is gone. However: ctime on the home directory is updated (directory entry changed), the deletion is recorded in auditd if rules cover ~/.bash_history, commands may exist in /var/log/auth.log if they used sudo, commands executed during the session may appear in auditd execve records, and if the attacker used SSH the session may be in journald. The key forensic gap is that the specific commands the attacker ran in that shell session are likely unrecoverable from file-based sources alone.

**Why is ctime more forensically reliable than mtime for detecting timestomping?**
mtime (content modification time) can be changed by any user with write permission using `touch -t` — setting it to any arbitrary date. ctime (inode change time) is set by the kernel whenever any metadata changes (permissions, ownership, link count, content) and cannot be modified by userspace tools without special kernel access or direct inode patching. An attacker who timestomps a file's mtime to hide when it was created leaves ctime unchanged — revealing the actual time of modification.

**A process is running but its /proc/pid/exe shows (deleted). What does this tell you and what do you do?**
The binary was deleted from disk after execution — a technique to eliminate the file-based IOC while the process continues running in memory. The binary is still fully recoverable: `cp /proc/<pid>/exe /tmp/recovered` copies the in-memory binary to disk for analysis. Do this immediately before the process exits. Then analyze with `file`, `strings`, and a disassembler. Check /proc/<pid>/cmdline for arguments, /proc/<pid>/environ for credentials, /proc/<pid>/net/tcp for C2 connections, and /proc/<pid>/maps for injected libraries.

---

*Linux/12-Forensics-Artifacts | OS-Internals-for-SOC | Solomon James (@Jaysolex)*
