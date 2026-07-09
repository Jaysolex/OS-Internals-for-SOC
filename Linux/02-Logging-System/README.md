# Linux/02 — The Logging System

> Logs are the memory of the operating system. Every meaningful event — authentication, process execution, kernel panic, service crash — gets written somewhere. Understanding the logging architecture tells you where to look, what survives tampering, and what an attacker must destroy to go dark.

![MITRE](https://img.shields.io/badge/MITRE-T1070.002%20|%20T1562.001%20|%20T1070.004-red)
![Platform](https://img.shields.io/badge/Platform-Linux-orange)

---

## Logging Architecture

Linux logging is not a single system. It is a pipeline with multiple components operating in parallel:

```
Kernel / Applications
        |
        v
  rsyslog daemon       <- userspace, writes flat text to /var/log/*
        |
  journald             <- systemd binary journal, persists across reboots
        |
  auditd               <- kernel-level syscall auditing, independent of both
        |
        v
  /var/log/*           <- flat text files
  /var/log/journal/    <- binary journal
  /var/log/audit/      <- audit records
```

The critical point for defenders: **auditd operates at the kernel level**. It captures events regardless of whether rsyslog is running. An attacker who stops rsyslog goes dark in `/var/log/syslog` but not in `/var/log/audit/audit.log`.

---

## rsyslog

rsyslog is the default logging daemon on Debian and Ubuntu systems. It collects events from the kernel and applications via the Unix socket `/dev/log` and writes them to flat text files under `/var/log/`.

### Configuration Files

```
/etc/rsyslog.conf       main configuration
/etc/rsyslog.d/         modular drop-in configs
```

### Rule Format

Every rule follows this structure:

```
facility.priority    action
```

### Facility Codes

| Code | Source |
|------|--------|
| `auth` / `authpriv` | Authentication and authorization |
| `kern` | Linux kernel |
| `daemon` | Background services |
| `cron` | Scheduled jobs |
| `mail` | Mail system |
| `user` | User-space applications |
| `*` | All facilities |

### Priority Levels (lowest to highest)

| Level | Meaning |
|-------|---------|
| `debug` | Debug output |
| `info` | Informational |
| `notice` | Normal but significant |
| `warning` | Warning condition |
| `err` | Error condition |
| `crit` | Critical condition |
| `alert` | Immediate action required |
| `emerg` | System unusable |
| `*` | All priorities |

Setting a priority logs that level **and everything above it**.

### Action

```bash
/var/log/auth.log     # synchronous write to file
-/var/log/syslog      # async write (buffered, faster)
:omusmsg:*            # send to all logged-in users
```

### Default Logging Rules

```bash
auth,authpriv.*              /var/log/auth.log
*.*;auth,authpriv.none      -/var/log/syslog
kern.*                      -/var/log/kern.log
daemon.*                    -/var/log/daemon.log
cron.*                       /var/log/cron.log
mail.*                      -/var/log/mail.log
user.*                      -/var/log/user.log
mail.info                   -/var/log/mail.info
mail.warn                   -/var/log/mail.warn
mail.err                     /var/log/mail.err
```

### Rule Examples

```bash
# All mail events at all priorities
mail.*  /var/log/mail

# Kernel critical and above only
kern.crit  /var/log/kernel

# All emergency events to all logged-in users
*.emerg  :omusmsg:*
```

### Service Management

```bash
systemctl status rsyslog
systemctl stop rsyslog
systemctl start rsyslog
systemctl restart rsyslog
```

---

## journald

journald is systemd's logging component. It runs parallel to rsyslog and stores logs in a binary structured format under `/var/log/journal/`. Unlike rsyslog flat files, journal entries cannot be tampered with by simply editing a text file — the binary format detects corruption.

### Key Commands

```bash
# View all logs
journalctl

# Follow live
journalctl -f

# Since last boot
journalctl -b

# Specific unit
journalctl -u ssh.service

# Specific time window
journalctl --since "2024-01-01 00:00:00" --until "2024-01-01 06:00:00"

# Specific process
journalctl _COMM=sshd

# Kernel messages only
journalctl -k

# Last 100 lines
journalctl -n 100 --no-pager

# All auth-related since 24h ago
journalctl _COMM=sshd --since "24 hours ago" --no-pager
```

---

## auditd

auditd is the Linux kernel audit framework. Unlike rsyslog and journald which operate in userspace, auditd hooks directly into the kernel via the netlink socket. It captures syscall-level events — file access, process execution, network connections, privilege changes — regardless of what userspace logging daemons are doing.

### Configuration Files

```
/etc/audit/auditd.conf        daemon configuration
/etc/audit/rules.d/           audit rules directory
/var/log/audit/audit.log      output log
```

### Adding Rules

```bash
# Monitor file for writes and attribute changes
auditctl -w /etc/passwd -p wa -k identity

# Monitor SSH directory
auditctl -w /etc/ssh -p rwxa -k ssh_config

# Monitor all process execution
auditctl -a always,exit -F arch=b64 -S execve -k process_exec

# Monitor privilege escalation
auditctl -a always,exit -F arch=b64 -S setuid -k privilege_abuse

# List active rules
auditctl -l

# Make rules persistent — add to:
# /etc/audit/rules.d/security.rules
```

### Reading Audit Logs

```bash
# Search by key
ausearch -k identity
ausearch -k log_tampering

# Search by file
ausearch -f /var/log/auth.log

# Search by PID
ausearch -p 1234

# Search by user ID
ausearch -ua 1000

# Time range
ausearch --start 01/01/2024 00:00:00 --end 01/01/2024 06:00:00

# Summary report
aureport --summary

# Executable summary
aureport -x --summary

# Failed events only
aureport --failed
```

---

## Log Rotation — logrotate

Log files grow indefinitely. logrotate runs via cron and manages archiving automatically.

```bash
/etc/logrotate.conf       main config
/etc/logrotate.d/         per-application configs
```

### Default Configuration

```bash
weekly          # rotate every week
rotate 4        # keep 4 weeks of archives
create          # create fresh log after rotation
#compress       # optionally compress old logs
include /etc/logrotate.d
```

### Rotation Chain

```
auth.log        <- current (active writes)
auth.log.1      <- last week
auth.log.2      <- 2 weeks ago
auth.log.3      <- 3 weeks ago
auth.log.4      <- 4 weeks ago (oldest kept)
                   auth.log.5 would be deleted
```

**DFIR significance:** Attackers typically only clear the current log file. Rotated archives `.1` `.2` `.3` `.4` frequently preserve evidence of the intrusion. Always check them before concluding logs are clean.

### Useful logrotate Settings

| Setting | Meaning |
|---------|---------|
| `rotate 4` | Keep 4 archives (~1 month) |
| `rotate 52` | Keep 52 archives (~1 year, forensic) |
| `daily` | Rotate every day |
| `compress` | Compress archives with gzip |
| `missingok` | Do not error if log file missing |
| `notifempty` | Do not rotate empty files |

---

## Critical Log Files Reference

| File | Contains | Security Value |
|------|----------|----------------|
| `/var/log/auth.log` | SSH, sudo, PAM, su | Who authenticated, from where, how |
| `/var/log/syslog` | General system events | Service activity, application events |
| `/var/log/kern.log` | Kernel messages | Driver errors, module loading, crashes |
| `/var/log/cron.log` | Cron execution | Scheduled job runs — validates persistence |
| `/var/log/audit/audit.log` | Syscall-level events | File access, exec, network, privilege |
| `/var/log/wtmp` | All login sessions | Binary — read with `last -F` |
| `/var/log/btmp` | Failed login attempts | Binary — read with `lastb` |
| `/var/log/lastlog` | Last login per user | Binary — read with `lastlog` |
| `/var/log/journal/` | systemd journal | Binary — read with `journalctl` |

---

## Attacker Tradecraft

### Technique 1 — Manual Log Editing

Open auth.log and remove incriminating lines manually. Leaves time gaps in the log timeline — detected by SIEM timechart gap analysis. Deleted content is recoverable by forensic tools until disk blocks are overwritten.

### Technique 2 — Shredding Log Files

```bash
# Shred current log and all rotated archives
shred -f -n 10 /var/log/auth.log.*
```

Overwrites file content multiple times with random data. File inode remains but content is unrecoverable even with forensic hardware. The `-f` forces permission override, `-n` sets overwrite passes, `.*` catches all rotated copies.

### Technique 3 — Stopping rsyslog

```bash
systemctl stop rsyslog
# or legacy:
service rsyslog stop
```

No new log entries written to `/var/log/*` while stopped. Requires root. journald and auditd continue independently — they are the forensic fallback.

### Technique 4 — Redirect to /dev/null

```bash
# Modify /etc/rsyslog.conf rule:
*.* /dev/null
```

All events discarded. Detected by file integrity monitoring on `/etc/rsyslog.conf` and by auditd capturing the write syscall.

---

## Detection Opportunities

| Attacker Action | Detection Source | Indicator |
|----------------|-----------------|-----------|
| rsyslog stopped | auditd, journald | `systemctl stop rsyslog` execve |
| Log file shredded | auditd | shred execve against `/var/log/*` |
| Log file truncated | auditd, FIM | truncate syscall on log paths |
| rsyslog.conf modified | auditd, FIM | write to `/etc/rsyslog.conf` |
| Log time gap | SIEM timechart | Zero log volume for unexpected period |
| auth.log size drop | Wazuh FIM | File size suddenly zero or near-zero |

---

## Investigation Commands

```bash
# Authentication events
tail -200 /var/log/auth.log
grep "Failed password" /var/log/auth.log | tail -50
grep "Accepted password\|Accepted publickey" /var/log/auth.log
grep "sudo" /var/log/auth.log | grep COMMAND

# Brute force — count failures by source IP
grep "Failed password" /var/log/auth.log | \
  grep -oE "from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | \
  sort | uniq -c | sort -rn | head -20

# Login history
last -F | head -30
lastb | head -20
lastlog | grep -v "Never"

# Check log file integrity
stat /var/log/auth.log
ls -la /var/log/auth.log*

# Check rsyslog service state
systemctl status rsyslog

# journald — survives rsyslog being stopped
journalctl _COMM=sshd --since "24 hours ago" --no-pager
journalctl -n 500 --no-pager

# auditd — kernel level evidence
ausearch -k log_tampering
ausearch -f /var/log/auth.log
aureport -x --summary
aureport --failed

# Check for LD_PRELOAD (rootkit indicator)
cat /etc/ld.so.preload 2>/dev/null || echo "Clean"
```

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|-----|-------------|
| Indicator Removal: Clear Linux Logs | T1070.002 | Clearing or shredding log files |
| Impair Defenses: Disable or Modify Tools | T1562.001 | Stopping rsyslog or auditd daemon |
| Indicator Removal: File Deletion | T1070.004 | Deleting log files from disk |
| Brute Force | T1110 | Multiple failed authentication attempts |
| Valid Accounts | T1078 | Successful login following brute force |

---

## Sigma Rules

### rsyslog Stopped

```yaml
title: Linux Logging Daemon Stopped
id: b2c3d4e5-f6a7-8901-bcde-f12345678901
status: stable
description: >
  Detects the rsyslog logging daemon being stopped.
  Attackers disable logging to prevent activity
  from being recorded in log files.
author: Solomon James (@Jaysolex)
date: 2024/01/01
tags:
  - attack.defense_evasion
  - attack.t1562.001
logsource:
  product: linux
  service: auditd
detection:
  selection:
    type: EXECVE
    a0|contains:
      - systemctl
      - service
    a1|contains:
      - rsyslog
      - syslog
    a2: stop
  condition: selection
falsepositives:
  - Legitimate maintenance with approved change ticket
level: high
```

### Log File Shredded

```yaml
title: Linux Log File Cleared or Shredded
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: stable
description: >
  Detects use of shred or truncate against Linux log files.
  Destroys log content in a way that is unrecoverable
  even with forensic hardware.
author: Solomon James (@Jaysolex)
date: 2024/01/01
tags:
  - attack.defense_evasion
  - attack.t1070.002
  - attack.t1070.004
logsource:
  product: linux
  service: auditd
detection:
  selection_shred:
    type: EXECVE
    a0: shred
    a1|contains: '/var/log/'
  selection_truncate:
    type: SYSCALL
    syscall: truncate
    a0|startswith: '/var/log/'
  condition: selection_shred OR selection_truncate
falsepositives:
  - Legitimate log management outside normal rotation window
level: high
```

---

## Wazuh Rules

```xml
<group name="linux,log_tampering,">

  <rule id="100001" level="12">
    <if_group>syscheck</if_group>
    <field name="file">/var/log/auth.log</field>
    <description>Auth log file modified or truncated</description>
    <mitre><id>T1070.002</id></mitre>
  </rule>

  <rule id="100002" level="14">
    <if_group>audit</if_group>
    <match>shred</match>
    <field name="audit.directory.name">/var/log</field>
    <description>Shred executed against log files — evidence destruction</description>
    <mitre><id>T1070.004</id></mitre>
  </rule>

  <rule id="100003" level="13">
    <if_group>syslog</if_group>
    <match>rsyslog.*stopped</match>
    <description>rsyslog daemon stopped — logging disabled</description>
    <mitre><id>T1562.001</id></mitre>
  </rule>

</group>
```

---

## Splunk SPL

```spl
| SSH Brute Force
index=linux_logs sourcetype=syslog "Failed password"
| rex field=_raw "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count AS failures by src_ip
| where failures > 10
| sort -failures

| Log Gap Detection
index=linux_logs sourcetype=syslog host=*
| timechart span=5m count by host
| where count=0
| eval gap="DETECTED"

| Brute Force to Successful Login Correlation
index=linux_logs sourcetype=syslog "Failed password"
| rex field=_raw "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count AS failures by src_ip
| where failures > 10
| join src_ip [
    search index=linux_logs sourcetype=syslog "Accepted"
    | rex field=_raw "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
    | stats count AS successes by src_ip
  ]
| where successes > 0
| eval severity="CRITICAL"
| table src_ip, failures, successes, severity
```

---

## Practitioner Notes

**On rotated logs during IR:** Always check `.1` `.2` `.3` `.4` archives. Attackers clear `auth.log` but frequently forget the rotated copies. Run `ls -la /var/log/auth.log*` before concluding logs are clean.

**On auditd as fallback:** If rsyslog was stopped during an incident window, journald and auditd are your evidence sources. `journalctl --since "timestamp"` retrieves events from the binary journal independent of rsyslog state. auditd captures at kernel level and cannot be bypassed from userspace without root.

**On log gaps in SIEM:** A gap in syslog timestamps is itself evidence. Production Linux systems generate continuous log volume. A true zero-volume gap of more than a few minutes indicates logging was stopped or logs were deleted after the fact.

**On shred forensics:** After shred executes, the file inode and name still exist but content is overwritten with random data. The auditd record of the shred execve syscall persists in `/var/log/audit/audit.log` because auditd writes to a separate path the attacker may not have targeted.

---

## Knowledge Validation

**An attacker stops rsyslog and shreds auth.log. What evidence survives?**
journald retains an independent binary journal — query with `journalctl` for the time window. auditd captures the shred execve and the rsyslog stop at kernel level in `/var/log/audit/audit.log`. The wtmp and btmp binary files are written by kernel login accounting not rsyslog — read with `last` and `lastb`. Rotated log archives the attacker may have missed preserve earlier activity.

**Why is a log gap in SIEM a high-confidence indicator rather than just a quiet period?**
Production Linux systems generate continuous log volume from cron jobs, service heartbeats, kernel messages, and authentication events. A true zero-volume gap of more than a few minutes indicates either logging was stopped or logs were deleted after the fact. Correlate the gap window with auditd records of rsyslog stop events to confirm evasion.

**What is the forensic difference between rm and shred on a log file?**
rm removes the directory entry and marks the inode available but data blocks remain on disk until overwritten — recoverable with forensic tools. shred overwrites file content multiple times with random data before deletion — original content is unrecoverable even with hardware forensic analysis.

**You find /etc/ld.so.preload exists and is non-empty. What is the security implication?**
Every dynamically linked process loads that library before all others. This is an LD_PRELOAD injection technique — the malicious library intercepts libc calls to hide files, processes, or network connections from userspace tools. Verify with `cat /etc/ld.so.preload`, check the library with `file` and `strings`, compare `/proc/net/tcp` with `ss` output for hidden connections.

---

*Linux/02-Logging-System | OS-Internals-for-SOC | Solomon James (@Jaysolex)*
