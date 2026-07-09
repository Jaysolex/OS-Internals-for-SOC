# H07 — Log Tampering Hunt

**Hypothesis:** An attacker has cleared, modified, or disabled logging to destroy forensic evidence.

**OS Mechanism:** Both Linux (rsyslog, auditd, journald) and Windows (Event Log service, Sysmon) maintain logs. Attackers disable services, clear log files, or modify logging configuration.

**MITRE:** T1070.001 (Windows), T1070.002 (Linux), T1562.001, T1562.002

---

## Baseline

- Event logs grow continuously — size should always increase
- Log service status should be Running
- auditd should be active and generating records
- Log record numbers should be sequential with no gaps

## Anomaly Indicators

**Windows:**
- Event ID 1102 (Security log cleared) or 104 (System log cleared)
- Event ID 4719 (Audit policy changed)
- EventLog service stopped/disabled
- Sudden decrease in log file size

**Linux:**
- rsyslog service stopped
- /var/log/auth.log emptied or size suddenly reduced
- shred command executed against /var/log/*
- auditd stopped or rules flushed

---

## Hunt Queries

### Windows — Splunk SPL

```spl
| Log clearing events
index=wineventlog EventCode IN (1102, 104)
| eval cleared_by=coalesce(SubjectUserName, "unknown")
| table _time, host, EventCode, cleared_by, Channel
| sort -_time
```

```spl
| Audit policy changes
index=wineventlog EventCode=4719
| table _time, host, SubjectUserName, CategoryId, SubcategoryId, AuditPolicyChanges
| sort -_time
```

```spl
| Log gaps — hosts that stopped sending events
| tstats latest(_time) AS last_event WHERE index=wineventlog BY host
| eval hours_since=round((now()-last_event)/3600,1)
| where hours_since > 2
| sort -hours_since
```

### Linux — Splunk SPL

```spl
index=linux_auditd
(exe="/usr/bin/shred" AND key="log_tampering")
OR (syscall="truncate" AND name="/var/log/*")
| table _time, host, auid, uid, exe, a0, a1
```

```spl
| rsyslog stopped
index=linux_syslog message="rsyslog*stop*" OR message="rsyslog*terminat*"
| table _time, host, message
```

### Linux — Bash Check

```bash
# Check for log gaps
for logfile in /var/log/auth.log /var/log/syslog; do
    size=$(stat -c%s "$logfile" 2>/dev/null)
    mtime=$(stat -c%y "$logfile" 2>/dev/null)
    lines=$(wc -l < "$logfile" 2>/dev/null)
    echo "$logfile: ${size}B | $lines lines | Modified: $mtime"
    [ "$size" -lt 1024 ] && echo "  WARNING: Suspiciously small"
done

# Check journald for events during log gap
journalctl --since "2024-01-01 00:00" --until "2024-01-01 06:00" --no-pager | wc -l
```

---

## Validation

1. Confirm the log clearing timestamp — correlate with other activity
2. Check journald (Linux) or Sysmon (Windows) for events during the gap
3. Check WEF / SIEM for any forwarded events from before the clear
4. Look for attacker activity immediately before the clearing event

## Response

1. The log clearing timestamp is your IR start anchor — work backward from there
2. Recover pre-clear events from: WEF, journald, VSS (Windows), network logs
3. Treat the clearing event as confirmation of active attacker — escalate immediately
