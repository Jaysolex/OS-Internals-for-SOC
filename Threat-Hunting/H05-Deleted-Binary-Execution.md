# H05 — Deleted Binary Execution Hunt

**Hypothesis:** An attacker executed a malware binary then deleted it from disk to eliminate file-based IOCs while the process continues running in memory.

**OS Mechanism:** Linux maintains process file descriptors and /proc/pid/exe symlinks even after the binary is deleted from disk. The process continues running; the binary is recoverable from /proc.

**MITRE:** T1036 — Masquerading, T1070.004 — Indicator Removal: File Deletion

---

## Baseline

Legitimate processes occasionally show as deleted if a package update replaces a binary while the old version is still running. This is transient and resolves when the process restarts.

## Anomaly Indicators

- Process with `/proc/pid/exe` showing `(deleted)`
- Executable path in non-standard location (not /usr/bin, /usr/sbin, etc.)
- Process running from /tmp, /dev/shm, or home directories — now deleted
- High network activity from a process with no binary on disk

---

## Hunt Queries

### Bash — Live System

```bash
# Find all processes with deleted binaries
echo "=== PROCESSES WITH DELETED BINARIES ==="
for pid in $(ls /proc | grep '^[0-9]'); do
    exe=$(readlink /proc/$pid/exe 2>/dev/null)
    if echo "$exe" | grep -q "(deleted)"; then
        cmdline=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')
        user=$(stat -c %U /proc/$pid 2>/dev/null)
        echo "PID: $pid | User: $user | Exe: $exe | CMD: $cmdline"
    fi
done

# Recover deleted binary (do this immediately)
# cp /proc/<pid>/exe /tmp/recovered_binary
# file /tmp/recovered_binary
# sha256sum /tmp/recovered_binary  # check against threat intel
```

### osquery

```sql
SELECT pid, name, path, cmdline, uid, parent
FROM processes
WHERE path LIKE '%(deleted)%'
   OR path = '';
```

### Splunk SPL (if auditd captures this)

```spl
index=linux_auditd exe="*(deleted)*"
| table _time, host, pid, uid, exe, comm
| sort -_time
```

---

## Validation

1. Copy the binary: `cp /proc/<pid>/exe /tmp/recovered`
2. Hash it: `sha256sum /tmp/recovered` — submit to VirusTotal
3. Check network connections: `cat /proc/<pid>/net/tcp`
4. Check open files: `ls -la /proc/<pid>/fd/`
5. Check environment for credentials: `cat /proc/<pid>/environ | tr '\0' '\n'`

## Response

1. Recover the binary BEFORE killing the process
2. Document all connections from the process
3. Kill the process after recovery: `kill -9 <pid>`
4. Hunt for persistence mechanisms the attacker may have established
5. Check for other deleted-binary processes on the same host
