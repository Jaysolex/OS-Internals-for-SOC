# Windows/07 — Event Log System

> Windows Event Logs are the primary evidence source for every Windows investigation. Understanding the EVTX format, the critical event IDs, log tampering techniques, and how to extract maximum forensic value from event data is not optional for a security engineer — it is the job.

![MITRE](https://img.shields.io/badge/MITRE-T1070.001%20|%20T1562%20|%20T1003-red)
![Platform](https://img.shields.io/badge/Platform-Windows-blue)

---

## Event Log Architecture

```
Applications / OS components
        |
        v
Event Log API (EvtWriteLog, ReportEvent)
        |
        v
Windows Event Log Service (EventLog / wevsvc)
        |
        v
Event Log Files (.evtx) in C:\Windows\System32\winevt\Logs\
        |
        v
SIEM / WEF (Windows Event Forwarding) -> centralised collection
```

The Event Log Service buffers events in memory and writes to EVTX files. Logs are circular by default — old events are overwritten when size limit is reached.

---

## EVTX File Format

EVTX (Event Log XML) is a binary format replacing the older EVT format. Each record contains:
- Event metadata (timestamp, provider, computer, channel)
- Event data (XML-structured, provider-specific fields)
- Record number and event ID

```powershell
# EVTX file locations
Get-ChildItem C:\Windows\System32\winevt\Logs\ | Sort-Object Length -Descending

# Parse with PowerShell
Get-WinEvent -Path "C:\Windows\System32\winevt\Logs\Security.evtx" -MaxEvents 10

# Parse with Chainsaw (fast, field extraction)
# chainsaw hunt C:\Windows\System32\winevt\Logs\ --rules sigma_rules/

# Parse with EvtxECmd (Eric Zimmerman)
# EvtxECmd.exe -d C:\Windows\System32\winevt\Logs\ --csv C:\output\
```

---

## Critical Log Channels

```
Security.evtx                    Authentication, privilege, object access, policy
System.evtx                      Hardware, drivers, services, system events
Application.evtx                 Application-level events
Microsoft-Windows-Sysmon%4Operational.evtx       Sysmon telemetry
Microsoft-Windows-PowerShell%4Operational.evtx   PowerShell script blocks
Microsoft-Windows-WMI-Activity%4Operational.evtx WMI execution
Microsoft-Windows-TaskScheduler%4Operational.evtx Scheduled tasks
Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx  RDP
Microsoft-Windows-DNS-Client%4Operational.evtx   DNS queries (requires enabling)
Microsoft-Windows-Bits-Client%4Operational.evtx  BITS transfers
```

---

## Security Event IDs — Complete Reference

### Authentication

| Event ID | Description | Key Fields | Attack Scenario |
|----------|-------------|-----------|----------------|
| 4624 | Successful logon | LogonType, AuthPackage, SourceIP | Baseline all logons |
| 4625 | Failed logon | FailureReason, TargetUser, SourceIP | Brute force |
| 4627 | Group membership on logon | MemberSid list | Admin group usage |
| 4634 | Logoff | LogonId | Session duration |
| 4647 | User-initiated logoff | — | — |
| 4648 | Logon with explicit credentials | TargetUser, TargetServer | PtH, RunAs, lateral move |
| 4672 | Special privileges on logon | PrivilegeList | Admin/SYSTEM logon |
| 4768 | Kerberos TGT requested | AccountName, ClientAddress | AS-REP roasting |
| 4769 | Kerberos service ticket | ServiceName, TicketEncType | Kerberoasting (RC4 = 0x17) |
| 4771 | Kerberos pre-auth failed | AccountName, ClientAddress | Brute force, roasting |
| 4776 | NTLM credential validation | AccountName, Workstation | NTLM auth, PtH |

### Logon Types

| Type | Name | Scenario |
|------|------|---------|
| 2 | Interactive | Physical keyboard logon |
| 3 | Network | SMB, net use, WMI |
| 4 | Batch | Scheduled task |
| 5 | Service | Service startup |
| 7 | Unlock | Workstation unlock |
| 8 | NetworkCleartext | Basic auth cleartext |
| 9 | NewCredentials | RunAs /netonly |
| 10 | RemoteInteractive | RDP |
| 11 | CachedInteractive | Cached domain creds |

### Account Management

| Event ID | Description | Attack Scenario |
|----------|-------------|----------------|
| 4720 | User account created | Backdoor account |
| 4722 | User account enabled | Activating disabled backdoor |
| 4724 | Password reset attempt | Credential manipulation |
| 4725 | User account disabled | Attacker cleanup |
| 4726 | User account deleted | Attacker cleanup |
| 4728 | Member added to global security group | Domain privilege escalation |
| 4732 | Member added to local security group | Local admin group add |
| 4738 | User account changed | Account manipulation |
| 4740 | Account locked out | Brute force side effect |
| 4756 | Member added to universal group | Domain-wide escalation |

### Process and Execution

| Event ID | Log | Description | Notes |
|----------|-----|-------------|-------|
| 4688 | Security | Process created | Requires audit policy; includes cmdline if configured |
| 4689 | Security | Process exited | Process lifetime |
| 1 | Sysmon | Process created | Full cmdline, hash, parent |
| 3 | Sysmon | Network connection | C2, lateral movement |
| 7 | Sysmon | Image loaded (DLL) | DLL injection |
| 8 | Sysmon | CreateRemoteThread | Process injection |
| 10 | Sysmon | ProcessAccess | LSASS dumping |
| 11 | Sysmon | FileCreate | Payload dropped |
| 12/13/14 | Sysmon | Registry events | Persistence |
| 15 | Sysmon | FileCreateStreamHash | ADS creation |
| 17/18 | Sysmon | Pipe events | Named pipe C2 |
| 19/20/21 | Sysmon | WMI events | WMI persistence |
| 22 | Sysmon | DNS query | C2 domain resolution |
| 23 | Sysmon | FileDelete | Evidence deletion |
| 25 | Sysmon | ProcessTampering | Hollowing detection |
| 4104 | PowerShell | Script block logged | Script content |
| 4103 | PowerShell | Module logging | Cmdlet invocations |

### Service and Persistence

| Event ID | Log | Description |
|----------|-----|-------------|
| 4697 | Security | Service installed |
| 7045 | System | New service installed |
| 7034 | System | Service crashed |
| 7036 | System | Service started/stopped |
| 4698 | Security | Scheduled task created |
| 4699 | Security | Scheduled task deleted |
| 4700 | Security | Scheduled task enabled |
| 4702 | Security | Scheduled task updated |

### Defense Evasion

| Event ID | Log | Description |
|----------|-----|-------------|
| 1102 | Security | Audit log cleared |
| 104 | System | System log cleared |
| 4719 | Security | Audit policy changed |
| 4906 | Security | CrashOnAuditFail changed |

---

## Enabling Critical Audit Policies

Windows does not log everything by default. These must be explicitly enabled.

```powershell
# Enable via Group Policy or auditpol
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Account Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable

# Enable command line in process creation (4688)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1

# Check current policy
auditpol /get /category:*
```

---

## Log Tampering Techniques

### Clearing Event Logs

```powershell
# Clear Security log (generates Event ID 1102)
Clear-EventLog -LogName Security
wevtutil cl Security

# Clear System log (generates Event ID 104)
wevtutil cl System

# Clear all logs
wevtutil el | ForEach-Object { wevtutil cl "$_" }
```

### Disabling Event Log Service

```powershell
# Stop event log service (requires SYSTEM or admin)
Stop-Service EventLog -Force
sc stop EventLog

# Disable permanently
Set-Service EventLog -StartupType Disabled
```

### Modifying Audit Policy

```powershell
# Disable all auditing
auditpol /clear

# Disable specific subcategory
auditpol /set /subcategory:"Logon" /success:disable /failure:disable
```

---

## Detection — Log Tampering

```powershell
# Detect log clearing (always check these first in any IR)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} |
  Select-Object TimeCreated, Message

Get-WinEvent -FilterHashtable @{LogName='System'; Id=104} |
  Select-Object TimeCreated, Message

# Detect audit policy changes
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4719} |
  Select-Object TimeCreated, Message

# Check current log sizes (sudden shrink = clearing)
Get-WinEvent -ListLog * | Sort-Object RecordCount -Descending |
  Select-Object LogName, RecordCount, FileSize, LastWriteTime

# Check event log gaps (missing record numbers)
$log = Get-WinEvent -LogName Security -MaxEvents 1000
$records = $log | Select-Object -ExpandProperty RecordId | Sort-Object
for ($i = 0; $i -lt $records.Count - 1; $i++) {
    if ($records[$i+1] - $records[$i] -gt 1) {
        "GAP: Records $($records[$i]) to $($records[$i+1]) missing"
    }
}
```

---

## Windows Event Forwarding (WEF)

WEF forwards events from endpoints to a central Windows Event Collector — preventing log clearing on endpoints from destroying evidence.

```powershell
# Check if WEF is configured
Get-WinEvent -ListLog ForwardedEvents -ErrorAction SilentlyContinue

# Configure subscription (on collector)
wecutil cs subscription.xml

# Check WEF status (on source)
winrm get winrm/config
```

---

## Investigation Queries

```powershell
# Recent failed logons with source IP
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 100 |
  ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
      Time       = $_.TimeCreated
      User       = $xml.Event.EventData.Data[5].'#text'
      Domain     = $xml.Event.EventData.Data[6].'#text'
      LogonType  = $xml.Event.EventData.Data[10].'#text'
      SourceIP   = $xml.Event.EventData.Data[19].'#text'
      Reason     = $xml.Event.EventData.Data[8].'#text'
    }
  } | Sort-Object Time -Descending

# Successful logons in last 24 hours
Get-WinEvent -FilterHashtable @{
  LogName='Security'; Id=4624
  StartTime=(Get-Date).AddHours(-24)
} | ForEach-Object {
  $xml = [xml]$_.ToXml()
  [PSCustomObject]@{
    Time      = $_.TimeCreated
    User      = $xml.Event.EventData.Data[5].'#text'
    LogonType = $xml.Event.EventData.Data[8].'#text'
    SourceIP  = $xml.Event.EventData.Data[18].'#text'
    AuthPkg   = $xml.Event.EventData.Data[14].'#text'
  }
}

# New services in last 7 days
Get-WinEvent -FilterHashtable @{
  LogName='System'; Id=7045
  StartTime=(Get-Date).AddDays(-7)
} | ForEach-Object {
  $xml = [xml]$_.ToXml()
  [PSCustomObject]@{
    Time    = $_.TimeCreated
    Name    = $xml.Event.EventData.Data[0].'#text'
    Path    = $xml.Event.EventData.Data[1].'#text'
    Account = $xml.Event.EventData.Data[4].'#text'
  }
}

# PowerShell script block content
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104
} | Where-Object { $_.Message -match 'Invoke-|DownloadString|IEX|EncodedCommand' } |
  Select-Object TimeCreated, Message | Format-List

# Kerberoasting detection (RC4 service ticket requests)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769} |
  Where-Object {
    $xml = [xml]$_.ToXml()
    $xml.Event.EventData.Data[5].'#text' -eq '0x17'  # RC4 encryption type
  } | ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
      Time        = $_.TimeCreated
      Account     = $xml.Event.EventData.Data[0].'#text'
      ServiceName = $xml.Event.EventData.Data[2].'#text'
      EncType     = $xml.Event.EventData.Data[5].'#text'
      ClientIP    = $xml.Event.EventData.Data[6].'#text'
    }
  }
```

---

## MITRE ATT&CK Mapping

| Technique | ID |
|-----------|-----|
| Indicator Removal: Clear Windows Event Logs | T1070.001 |
| Impair Defenses: Disable Windows Event Logging | T1562.002 |
| Impair Defenses: Modify Audit Policy | T1562.002 |

---

## Practitioner Notes

**On log clearing as a timeline anchor:** Event ID 1102 (Security log cleared) and 104 (System log cleared) are themselves logged and cannot be silently suppressed. Even after clearing, these events appear in the log — giving you the exact timestamp the attacker cleared logs. This becomes your investigation start time: reconstruct what happened before that timestamp from other sources (Sysmon, WEF, network logs).

**On record number gaps:** EVTX records are sequentially numbered. If records jump from 10000 to 12000, records 10001-11999 were deleted. This is detectable even without WEF. EvtxECmd and Chainsaw both flag record number gaps during parsing. Always check for gaps before concluding a log is clean.

**On PowerShell logging completeness:** Script block logging (Event ID 4104) captures PowerShell content after deobfuscation — the actual commands that will execute, not the encoded blob. It is the most valuable PS logging level. Module logging (4103) captures cmdlet invocations. Transcription logs write a text file per session. All three should be enabled. Script block logging alone catches most attacker PS activity.

---

## Knowledge Validation

**Event ID 1102 appears at 03:15 AM. The Security log now contains only events from 03:15 AM onward. How do you recover the pre-03:15 timeline?**
The log clearing is confirmed by Event ID 1102. Pre-clearing evidence: (1) Windows Event Forwarding — if configured, events were forwarded before clearing; (2) Sysmon log — separate channel not cleared by wevtutil cl Security; (3) PowerShell Operational log; (4) VSS shadow copies may contain the pre-cleared Security.evtx; (5) network-level evidence — firewall logs, proxy logs, SIEM if events were forwarded; (6) endpoint forensics — Prefetch, Amcache, Shimcache, LNK files that don't rely on event logs.

**What is the forensic significance of Event ID 4648 versus 4624?**
Event ID 4624 is a standard successful logon. Event ID 4648 is a logon using explicitly supplied credentials — the requesting process supplied a username and password different from its current identity. This is the signature of RunAs, Pass-the-Hash, and lateral movement tools that authenticate to remote systems. 4648 includes both the requesting process and the target credentials, making it significantly more informative for lateral movement investigation.

**Kerberoasting generates a specific Event ID pattern on the domain controller. What is it and how do you detect it?**
Kerberoasting requests service tickets using RC4 encryption (type 0x17) even in environments that default to AES — because the offline cracking is easier against RC4. On the DC, Event ID 4769 is generated for each service ticket request. Detection: filter 4769 for TicketEncryptionType = 0x17 combined with ServiceName not ending in $ (machine accounts). A single user requesting multiple RC4 service tickets in a short window is a Kerberoasting indicator.

---

*Windows/07-Event-Log-System | OS-Internals-for-SOC | Solomon James (@Jaysolex)*
