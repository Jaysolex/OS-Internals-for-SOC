# H04 — Linux Persistence Hunt

**Hypothesis:** An attacker has established persistence on Linux systems via cron, systemd, or shell profile modifications.

**OS Mechanism:** Linux persistence uses OS scheduling (cron, systemd timers), init system (systemd services), and shell initialization (bashrc, profile.d) to execute code at boot or user logon.

**MITRE:** T1053.003, T1053.006, T1543.002, T1546.004

---

## Baseline

On a managed Linux system:
- Cron jobs in `/etc/cron.d/` are installed by packages — track with package manager
- Systemd units in `/etc/systemd/system/` are created during software installation
- `/etc/profile.d/` scripts are small environment setup scripts
- `/etc/ld.so.preload` does not exist or is empty

## Anomaly Indicators

- Cron jobs containing curl, wget, nc, bash -i, or /tmp/ paths
- Systemd service units with ExecStart pointing to non-package paths
- `/etc/ld.so.preload` containing any entries
- Shell profiles modified outside maintenance windows
- SSH authorized_keys modified after initial provisioning

---

## Hunt Queries

### Bash — Live System Enumeration

```bash
#!/usr/bin/env bash
echo "=== CRON JOBS WITH NETWORK COMMANDS ==="
grep -r "curl\|wget\|nc \|bash.*tcp\|python.*socket" \
    /etc/crontab /etc/cron.d/ /var/spool/cron/ 2>/dev/null

echo "=== NON-PACKAGE SYSTEMD UNITS ==="
for unit in /etc/systemd/system/*.service; do
    [ -f "$unit" ] || continue
    dpkg -S "$unit" 2>/dev/null || echo "NOT PACKAGED: $unit"
done

echo "=== LD_PRELOAD CHECK ==="
cat /etc/ld.so.preload 2>/dev/null && echo "WARNING: /etc/ld.so.preload has content" || echo "CLEAN"

echo "=== RECENTLY MODIFIED PERSISTENCE FILES ==="
find /etc/cron.d /etc/systemd/system /etc/profile.d \
    ~/.ssh /root/.ssh -newer /etc/passwd -ls 2>/dev/null
```

### Splunk SPL

```spl
index=linux_auditd type=PATH
name IN ("/etc/cron.d/*", "/etc/systemd/system/*.service",
         "/etc/profile.d/*", "/etc/ld.so.preload")
nametype IN ("CREATE", "NORMAL")
| table _time, host, auid, uid, name, nametype
| sort -_time
```

### osquery

```sql
SELECT path, mtime, size
FROM file
WHERE path LIKE '/etc/cron.d/%'
   OR path LIKE '/etc/systemd/system/%.service'
   OR path = '/etc/ld.so.preload'
ORDER BY mtime DESC;
```

---

## Validation

1. Read the content of any flagged files
2. Decode any base64 or obfuscated content
3. Check if the binary referenced in the persistence mechanism exists and is signed
4. Cross-reference modification time with known maintenance windows and auditd records

## Response

1. Remove malicious cron entries or unit files
2. Run `systemctl daemon-reload` after removing unit files
3. Check `/etc/ld.so.preload` — remove entries and analyze the library
4. Rotate SSH keys if authorized_keys was modified
5. Hunt for other persistence mechanisms on the same host
