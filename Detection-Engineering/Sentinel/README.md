# Microsoft Sentinel — KQL Detection & Hunting

> Production-ready KQL queries for Microsoft Sentinel.
> Each query includes a plain-English explanation of what it detects,
> why that matters, and how to tune it for your environment.

---

## How to Use These Queries

1. Open Microsoft Sentinel → Logs
2. Paste the query into the query editor
3. Adjust table names to match your data connectors
4. Save as Analytics Rule for alerting or use in Hunting for investigation

**Common data sources referenced:**
- `SecurityEvent` — Windows Security event log (via MMA or AMA agent)
- `Syslog` — Linux syslog (via MMA or AMA agent)
- `DeviceProcessEvents` — Microsoft Defender for Endpoint process events
- `DeviceNetworkEvents` — MDE network events
- `DeviceRegistryEvents` — MDE registry events
- `DeviceFileEvents` — MDE file events
- `AuditLogs` — Azure AD audit logs

---

## Linux Detections

### SSH Brute Force

Detects repeated SSH authentication failures from a single source.
High failure counts indicate automated brute force or password spray attacks.
Correlate with successful logons from the same source to identify breaches.

```kql
Syslog
| where Facility == "auth"
| where SyslogMessage contains "Failed password"
| extend src_ip = extract(@"from (\d+\.\d+\.\d+\.\d+)", 1, SyslogMessage)
| extend username = extract(@"for (?:invalid user )?(\S+) from", 1, SyslogMessage)
| where isnotempty(src_ip)
| summarize failures=count(), users=dcount(username), first_seen=min(TimeGenerated),
    last_seen=max(TimeGenerated) by src_ip, Computer
| where failures > 10
| extend severity = case(failures > 100, "Critical", failures > 50, "High", "Medium")
| extend MitreTechnique = "T1110.001 - Brute Force: Password Guessing"
| project src_ip, Computer, failures, users, first_seen, last_seen, severity, MitreTechnique
| sort by failures desc
```

---

### Brute Force Succeeded

Correlates failed logins with subsequent successful login from the same IP.
This is the highest-priority SSH alert — a breach confirmation.

```kql
let failures = Syslog
| where Facility == "auth" and SyslogMessage contains "Failed password"
| extend src_ip = extract(@"from (\d+\.\d+\.\d+\.\d+)", 1, SyslogMessage)
| summarize fail_count=count() by src_ip, Computer;
let successes = Syslog
| where Facility == "auth" and SyslogMessage contains "Accepted"
| extend src_ip = extract(@"from (\d+\.\d+\.\d+\.\d+)", 1, SyslogMessage)
| extend username = extract(@"for (\S+) from", 1, SyslogMessage)
| project TimeGenerated, src_ip, Computer, username;
failures
| where fail_count > 5
| join kind=inner successes on src_ip, Computer
| extend severity = "Critical"
| extend MitreTechnique = "T1110.001 - Brute Force succeeded"
| project TimeGenerated, src_ip, Computer, username, fail_count, severity, MitreTechnique
| sort by TimeGenerated desc
```

---

### rsyslog Daemon Stopped

Detects the Linux logging daemon being stopped.
When rsyslog stops, no new log entries are written to /var/log/*.
The absence of logs after this event is itself forensic evidence.

```kql
Syslog
| where SyslogMessage has_all ("rsyslog", "stop")
    or SyslogMessage has_all ("rsyslog", "terminated")
| extend MitreTechnique = "T1562.001 - Impair Defenses: Disable or Modify Tools"
| extend severity = "High"
| project TimeGenerated, Computer, HostName, SyslogMessage, severity, MitreTechnique
| sort by TimeGenerated desc
```

---

### Execution from Temporary Directories

Detects processes launched from /tmp, /var/tmp, or /dev/shm on Linux endpoints
monitored by Microsoft Defender for Endpoint.

```kql
DeviceProcessEvents
| where FolderPath startswith "/tmp/"
    or FolderPath startswith "/var/tmp/"
    or FolderPath startswith "/dev/shm/"
| extend location = case(
    FolderPath startswith "/dev/shm/", "Shared Memory — no disk artifact",
    FolderPath startswith "/var/tmp/", "Persistent Temp — survives reboot",
    "Temp — cleared on reboot")
| extend MitreTechnique = "T1059 - Command and Scripting Interpreter"
| project TimeGenerated, DeviceName, AccountName, FileName, FolderPath,
    ProcessCommandLine, location, MitreTechnique
| sort by TimeGenerated desc
```

---

## Windows Detections

### Event Log Cleared

Detects Security or System event log clearing.
Event ID 1102 means Security log was cleared. Event ID 104 means System log was cleared.
These events are logged before the clear happens and cannot be suppressed.

```kql
SecurityEvent
| where EventID in (1102, 4719)
| extend action = case(EventID == 1102, "Security Log Cleared",
    EventID == 4719, "Audit Policy Changed", "Unknown")
| extend MitreTechnique = "T1070.001 - Indicator Removal: Clear Windows Event Logs"
| extend severity = "High"
| project TimeGenerated, Computer, Account, EventID, action, severity, MitreTechnique
| sort by TimeGenerated desc
```

---

### LSASS Memory Access

Detects processes opening LSASS with credential-dumping access masks.
Filters out known system processes. Any remaining hits should be investigated immediately.

```kql
DeviceEvents
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where AdditionalFields has_any ("0x1010", "0x1410", "0x1438", "0x143a")
| where InitiatingProcessFolderPath !startswith @"C:\Windows\System32"
| where InitiatingProcessFolderPath !startswith @"C:\Windows\SysWOW64"
| extend MitreTechnique = "T1003.001 - OS Credential Dumping: LSASS Memory"
| extend severity = "High"
| project TimeGenerated, DeviceName, AccountName,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    InitiatingProcessFolderPath, AdditionalFields, severity, MitreTechnique
| sort by TimeGenerated desc
```

---

### WMI Event Subscription Created

Detects WMI permanent event subscription creation — fileless persistence.
WMI subscriptions survive reboots and leave no files on disk.
Any subscription outside known monitoring tools is suspicious.

```kql
DeviceEvents
| where ActionType in ("WmiBindEventFilterToConsumer",
    "WmiAddEventConsumer", "WmiAddEventFilter")
| extend MitreTechnique = "T1546.003 - WMI Event Subscription"
| extend severity = "High"
| project TimeGenerated, DeviceName, AccountName, ActionType,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    AdditionalFields, severity, MitreTechnique
| sort by TimeGenerated desc
```

---

### Office Spawning Shell Process

Detects Microsoft Office applications spawning command interpreters.
This is the signature of malicious macro execution — primary initial access technique.

```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe",
    "powerpnt.exe", "outlook.exe", "onenote.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "wscript.exe",
    "cscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe")
| extend MitreTechnique = "T1566.001 - Phishing: Spearphishing Attachment"
| extend severity = "High"
| project TimeGenerated, DeviceName, AccountName,
    InitiatingProcessFileName, FileName, ProcessCommandLine, severity, MitreTechnique
| sort by TimeGenerated desc
```

---

### Encoded PowerShell Execution

Detects PowerShell launched with base64-encoded command arguments.
Encoding is used to bypass script content inspection and logging filters.

```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc ", "-EncodedCommand ", "-ec ")
| extend encoded_cmd = extract(@"(?:-enc|-EncodedCommand|-ec)\s+([A-Za-z0-9+/=]+)",
    1, ProcessCommandLine)
| extend MitreTechnique = "T1059.001 - PowerShell"
| extend note = "Check Sysmon Event 4104 for decoded script block content"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine,
    encoded_cmd, note, MitreTechnique
| sort by TimeGenerated desc
```

---

### Volume Shadow Copy Deletion

Detects shadow copy deletion — the ransomware pre-cursor.
Ransomware deletes shadow copies before encrypting to prevent recovery.
Any hit on this query should be treated as a potential ransomware incident.

```kql
DeviceProcessEvents
| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has_any ("delete shadows", "delete shadow"))
    or (FileName =~ "wmic.exe" and ProcessCommandLine has "shadowcopy" and ProcessCommandLine has "delete")
    or (FileName =~ "wbadmin.exe" and ProcessCommandLine has "delete catalog")
    or (FileName in~ ("powershell.exe", "pwsh.exe") and ProcessCommandLine has "ShadowCopy" and ProcessCommandLine has "Delete")
| extend MitreTechnique = "T1490 - Inhibit System Recovery"
| extend severity = "Critical"
| extend action = "Treat as ransomware incident — check for mass file rename"
| project TimeGenerated, DeviceName, AccountName, FileName,
    ProcessCommandLine, severity, action, MitreTechnique
| sort by TimeGenerated desc
```

---

### New Service with Suspicious Path

Detects Windows service installation with non-standard executable paths.
Legitimate services install to Windows or Program Files directories.

```kql
SecurityEvent
| where EventID == 7045
| extend ServiceName = tostring(EventData.ServiceName)
| extend ServicePath = tostring(EventData.ImagePath)
| where ServicePath !startswith @"C:\Windows\"
    and ServicePath !startswith @"""C:\Windows\"
    and ServicePath !startswith @"C:\Program Files\"
    and ServicePath !startswith @"""C:\Program Files"
| extend MitreTechnique = "T1543.003 - Windows Service"
| project TimeGenerated, Computer, Account, ServiceName, ServicePath, MitreTechnique
| sort by TimeGenerated desc
```

---

### Registry Run Key Persistence

Detects new values in Windows autorun registry keys from non-system processes.

```kql
DeviceRegistryEvents
| where RegistryKey has_any (
    @"CurrentVersion\Run",
    @"CurrentVersion\RunOnce",
    @"CurrentVersion\RunServices")
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| where InitiatingProcessFolderPath !startswith @"C:\Windows\"
| where InitiatingProcessFolderPath !startswith @"C:\Program Files\"
| extend MitreTechnique = "T1547.001 - Registry Run Keys"
| project TimeGenerated, DeviceName, AccountName, RegistryKey,
    RegistryValueName, RegistryValueData,
    InitiatingProcessFileName, InitiatingProcessCommandLine, MitreTechnique
| sort by TimeGenerated desc
```

---

### LOLBin External Network Connection

Detects Living-Off-the-Land binaries connecting to public IP addresses.

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("certutil.exe", "bitsadmin.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "wscript.exe",
    "cscript.exe", "msiexec.exe")
| where RemoteIPType == "Public"
| extend MitreTechnique = "T1218 - System Binary Proxy Execution"
| extend severity = "High"
| project TimeGenerated, DeviceName, AccountName,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    RemoteIP, RemotePort, RemoteUrl, severity, MitreTechnique
| sort by TimeGenerated desc
```

---

### Kerberoasting Detection

Detects RC4-encrypted Kerberos service ticket requests — the Kerberoasting signature.

```kql
SecurityEvent
| where EventID == 4769
| extend TicketEncryptionType = tostring(EventData.TicketEncryptionType)
| extend ServiceName = tostring(EventData.ServiceName)
| extend AccountName = tostring(EventData.TargetUserName)
| extend ClientIP = tostring(EventData.IpAddress)
| where TicketEncryptionType == "0x17"
| where ServiceName !endswith "$"
| summarize RequestCount=count(), Services=make_set(ServiceName)
    by AccountName, ClientIP, bin(TimeGenerated, 5m)
| where RequestCount > 2
| extend MitreTechnique = "T1558.003 - Kerberoasting"
| extend severity = case(RequestCount > 20, "Critical", RequestCount > 5, "High", "Medium")
| project TimeGenerated, AccountName, ClientIP, RequestCount,
    Services, severity, MitreTechnique
| sort by RequestCount desc
```

---

### IFEO Debugger Entry

Detects Image File Execution Options Debugger registry entries — lock screen backdoor technique.

```kql
DeviceRegistryEvents
| where RegistryKey has "Image File Execution Options"
| where RegistryValueName =~ "Debugger"
| extend target_process = extract(@"Options\\([^\\]+)\\Debugger", 1, RegistryKey)
| extend is_accessibility = target_process in~ ("sethc.exe", "utilman.exe",
    "osk.exe", "magnify.exe", "narrator.exe")
| extend severity = iif(is_accessibility, "Critical", "High")
| extend MitreTechnique = "T1546.012 - IFEO Injection"
| extend note = iif(is_accessibility,
    "Lock screen backdoor — provides SYSTEM shell without authentication", "")
| project TimeGenerated, DeviceName, AccountName, target_process,
    RegistryValueData, severity, note, MitreTechnique
| sort by TimeGenerated desc
```

---

### Known Vulnerable Driver Loaded (BYOVD)

Detects loading of kernel drivers known to be exploited in BYOVD attacks.

```kql
DeviceEvents
| where ActionType == "DriverLoad"
| where AdditionalFields has_any ("RTCore64.sys", "gdrv.sys", "WinRing0.sys",
    "WinRing0x64.sys", "dbutil_2_3.sys", "AsrDrv104.sys",
    "iqvw64e.sys", "mhyprot2.sys", "HW64.sys")
| extend MitreTechnique = "T1068 - Exploitation for Privilege Escalation"
| extend severity = "Critical"
| extend action = "Isolate immediately — kernel-level compromise likely"
| project TimeGenerated, DeviceName, AccountName,
    AdditionalFields, severity, action, MitreTechnique
| sort by TimeGenerated desc
```

---

### Hosts File Modified

Detects modifications to the Windows hosts file — used for C2 redirection and defense evasion.

```kql
DeviceFileEvents
| where FolderPath endswith @"\drivers\etc"
| where FileName =~ "hosts"
| where ActionType in ("FileModified", "FileCreated")
| extend MitreTechnique = "T1565.001 - Stored Data Manipulation"
| extend severity = "High"
| project TimeGenerated, DeviceName, AccountName,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    FileName, FolderPath, severity, MitreTechnique
| sort by TimeGenerated desc
```

---

## Threat Hunting Queries

### Find Hosts That Stopped Sending Logs

Identifies endpoints that have gone silent — possible logging disruption or isolation.

```kql
let expected_hosts = DeviceProcessEvents
| where TimeGenerated > ago(7d)
| summarize by DeviceName;
let recent_hosts = DeviceProcessEvents
| where TimeGenerated > ago(2h)
| summarize by DeviceName;
expected_hosts
| join kind=leftanti recent_hosts on DeviceName
| extend note = "Host was active in last 7 days but no events in last 2 hours"
| extend severity = "Medium"
| project DeviceName, note, severity
```

### Lateral Movement — Same Credential Multiple Hosts

```kql
SecurityEvent
| where EventID == 4624
| where LogonType == 3
| summarize host_count=dcount(Computer), hosts=make_set(Computer)
    by Account, IpAddress, bin(TimeGenerated, 1h)
| where host_count > 3
| extend MitreTechnique = "T1021.002 - SMB Lateral Movement"
| sort by host_count desc
```
