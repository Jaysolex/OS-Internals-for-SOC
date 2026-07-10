# PB02 — Windows Event Log Cleared Response Playbook

**Trigger:** Security Event ID 1102 or System Event ID 104  
**Severity:** High  
**Platform:** Windows  
**MITRE:** T1070.001 — Indicator Removal: Clear Windows Event Logs  

---

## What This Playbook Does

Responds to Windows event log clearing — a strong indicator of active attacker presence. The log clearing timestamp becomes the IR anchor point. This playbook recovers pre-clearing evidence from alternative sources and drives a full investigation.

---

## Why This Matters

Event log clearing means:
1. An attacker is actively covering their tracks
2. They have admin or SYSTEM privileges on this host
3. Evidence from before the clear may still exist in other sources
4. The host should be treated as compromised until proven otherwise

---

## Playbook Flow

```
EVENT 1102 / 104 DETECTED
        |
        v
STEP 1: IMMEDIATE TRIAGE
  Record the exact clearing timestamp
  Identify who cleared the log (SubjectUserName from Event 1102)
        |
        v
STEP 2: RECOVER PRE-CLEARING EVIDENCE
  Check Sysmon log (separate channel — not cleared by wevtutil)
  Check WEF forwarded events (if configured)
  Check VSS shadow copies for pre-clear Security.evtx
  Check PowerShell Operational log
        |
        v
STEP 3: ENRICH
  Who cleared it? Account context, last logon, group membership
  From where? Source IP if remote logon preceded the clear
        |
        v
STEP 4: HUNT FOR ATTACKER ACTIVITY
  What happened in the 1-4 hours BEFORE the clear?
  New services, scheduled tasks, accounts, registry keys?
        |
        v
STEP 5: CONTAIN
  Isolate host if active compromise confirmed
  Disable account that performed clearing if not legitimate
        |
        v
STEP 6: REPORT
```

---

## Step 1 — Immediate Triage

```powershell
# Get the exact clearing event details
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} |
    Select-Object TimeCreated, Message | Format-List

# Note: SubjectUserName = who cleared it
# If SYSTEM cleared it = automated tool or malware
# If a user account cleared it = investigate that account

# Check if System log was also cleared
Get-WinEvent -FilterHashtable @{LogName='System'; Id=104} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Message | Format-List

# Record clearing timestamp — this is your IR anchor
$clearTime = (Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} |
    Select-Object -First 1).TimeCreated
Write-Host "LOG CLEARED AT: $clearTime"
Write-Host "All pre-clearing events MUST be recovered from alternative sources"
```

---

## Step 2 — Recover Pre-Clearing Evidence

```powershell
$clearTime = (Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} |
    Select-Object -First 1).TimeCreated
$huntStart = $clearTime.AddHours(-4)

# Source 1: Sysmon log (NOT cleared by standard log clearing)
Write-Host "=== SYSMON EVENTS BEFORE CLEAR ===" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational'
    StartTime=$huntStart
    EndTime=$clearTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message | Format-Table -AutoSize

# Source 2: PowerShell log
Write-Host "=== POWERSHELL EVENTS BEFORE CLEAR ===" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    Id=4104
    StartTime=$huntStart
    EndTime=$clearTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Message | Format-List

# Source 3: VSS shadow copy (if exists)
vssadmin list shadows
Write-Host "If shadow copies exist — mount and copy pre-clear Security.evtx:"
Write-Host "  mklink /d C:\shadowmount <DeviceObject>"
Write-Host "  copy C:\shadowmount\Windows\System32\winevt\Logs\Security.evtx C:\IR\"

# Source 4: TaskScheduler log
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-TaskScheduler/Operational'
    StartTime=$huntStart
} -ErrorAction SilentlyContinue | Select-Object TimeCreated, Message | Format-List
```

---

## Step 3 — Enrichment

```powershell
# Who cleared the log?
$clearEvent = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} |
    Select-Object -First 1
$xml = [xml]$clearEvent.ToXml()
$clearingUser = $xml.Event.UserData.LogFileCleared.SubjectUserName
$clearingDomain = $xml.Event.UserData.LogFileCleared.SubjectDomainName

Write-Host "Cleared by: $clearingDomain\$clearingUser"

# What was this account doing before?
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=@(4624, 4648)
} -MaxEvents 20 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match $clearingUser } |
    Select-Object TimeCreated, Id, Message | Format-List

# Is this account in admin groups?
Get-LocalGroupMember -Group "Administrators" | Where-Object { $_.Name -match $clearingUser }
```

---

## Step 4 — Hunt for Attacker Activity

```powershell
$clearTime = (Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} |
    Select-Object -First 1).TimeCreated
$huntStart = $clearTime.AddHours(-4)

# New services installed before clear
Write-Host "=== NEW SERVICES BEFORE CLEAR ===" -ForegroundColor Red
Get-WinEvent -FilterHashtable @{
    LogName='System'; Id=7045
    StartTime=$huntStart; EndTime=$clearTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml = [xml]$_.ToXml()
    "[$($_.TimeCreated)] $($xml.Event.EventData.Data[0].'#text') -> $($xml.Event.EventData.Data[1].'#text')"
}

# New scheduled tasks
Write-Host "=== NEW TASKS BEFORE CLEAR ===" -ForegroundColor Red
Get-WinEvent -FilterHashtable @{
    LogName='Security'; Id=4698
    StartTime=$huntStart; EndTime=$clearTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Message | Format-List

# New accounts
Write-Host "=== ACCOUNT CHANGES BEFORE CLEAR ===" -ForegroundColor Red
Get-WinEvent -FilterHashtable @{
    LogName='Security'; Id=@(4720,4728,4732)
    StartTime=$huntStart; EndTime=$clearTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message | Format-List

# Check current persistence state
Write-Host "=== CURRENT PERSISTENCE STATE ===" -ForegroundColor Yellow
# Run Keys
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
# WMI
Get-WMIObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue
```

---

## Step 5 — Containment

```powershell
# If active compromise confirmed:

# Isolate host (network isolation via Windows Firewall)
# Block all inbound/outbound except management
New-NetFirewallRule -DisplayName "IR-ISOLATE-IN" -Direction Inbound -Action Block -Profile Any
New-NetFirewallRule -DisplayName "IR-ISOLATE-OUT" -Direction Outbound -Action Block -Profile Any

# Re-allow only management IP
New-NetFirewallRule -DisplayName "IR-MGMT-IN" -Direction Inbound `
    -RemoteAddress <MANAGEMENT_IP> -Action Allow -Profile Any

Write-Host "Host isolated — only management access allowed"
Write-Host "Do NOT reboot — preserve volatile evidence"
```

---

## Step 6 — Report Template

```
INCIDENT REPORT — LOG CLEARING
================================
Incident ID:   INC-XXXX
Date:          
Host:          
Severity:      HIGH

LOG CLEARING DETAILS
--------------------
Time cleared:
Cleared by:
Logs cleared:    [ ] Security  [ ] System  [ ] Other

ALTERNATIVE EVIDENCE RECOVERED
--------------------------------
Sysmon events before clear:  YES / NO
WEF forwarded events:        YES / NO
VSS shadow copy available:   YES / NO
PowerShell log intact:       YES / NO

PRE-CLEARING ACTIVITY (if recovered)
--------------------------------------
New services:
New accounts:
New tasks:
Network connections:

CURRENT PERSISTENCE STATE
--------------------------
Run keys:
WMI subscriptions:
Scheduled tasks:
Services:
Startup folder:

ASSESSMENT
----------
[ ] Log clearing appears deliberate — active attacker
[ ] Attacker had admin/SYSTEM privileges
[ ] Pre-clearing activity recovered
[ ] Additional persistence found
[ ] Lateral movement evidence

RECOMMENDED ACTIONS
-------------------
1. Treat host as compromised
2. Reset all local account passwords
3. Remove discovered persistence
4. Enable Windows Event Forwarding to prevent future clearing
5. Deploy Sysmon if not present (cannot be silently cleared)
```

---

*PB02 — Windows Log Cleared Response | OS-Internals-for-SOC | Solomon James (@Jaysolex)*
