# Windows/08 — Scheduled Tasks

> Scheduled tasks are one of the most abused persistence mechanisms on Windows. They run silently, survive reboots, execute as any user including SYSTEM, and can be triggered by dozens of conditions beyond simple time schedules. Understanding the Task Scheduler architecture is what separates finding malicious tasks from missing them.

![MITRE](https://img.shields.io/badge/MITRE-T1053.005%20|%20T1574%20|%20T1547-red)
![Platform](https://img.shields.io/badge/Platform-Windows-blue)

---

## Task Scheduler Architecture

```
Task Scheduler Service (Schedule service)
        |
        +-- reads task definitions from:
        |       C:\Windows\System32\Tasks\       <- XML task files
        |       HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\
        |
        +-- evaluates triggers (time, event, logon, idle, boot...)
        |
        +-- executes actions (run executable, send email, show message)
        |
        +-- logs to:
                Microsoft-Windows-TaskScheduler/Operational.evtx
```

---

## Task Storage Locations

```
C:\Windows\System32\Tasks\       authoritative task XML files
C:\Windows\SysWOW64\Tasks\       32-bit task mirror (older systems)
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\
```

**Important:** The registry cache and the XML files should match. Discrepancies indicate tampering — a task may exist in the registry but not as an XML file (or vice versa), making it invisible to tools that only check one source.

---

## Task XML Structure

```xml
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2024-01-01T00:00:00</Date>
    <Author>SYSTEM</Author>
    <Description>Windows Update Task</Description>
  </RegistrationInfo>

  <Triggers>
    <TimeTrigger>
      <Repetition>
        <Interval>PT5M</Interval>   <!-- every 5 minutes -->
      </Repetition>
      <StartBoundary>2024-01-01T00:00:00</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>

  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>   <!-- SYSTEM SID -->
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>

  <Settings>
    <Hidden>true</Hidden>          <!-- hidden from Task Scheduler UI -->
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
  </Settings>

  <Actions>
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-enc JABjAG0AZAA...</Arguments>
    </Exec>
  </Actions>
</Task>
```

---

## Trigger Types

| Trigger | Description | Attacker Use |
|---------|-------------|--------------|
| Time | Specific time or interval | Regular beaconing |
| Boot | On system boot | Persistence |
| Logon | On user logon | User-context persistence |
| SessionStateChange | On lock/unlock/connect/disconnect | Triggered by activity |
| Event | On Windows event ID match | Trigger on specific log entry |
| Registration | When task is created | Immediate execution |
| Idle | When system becomes idle | Stealthy execution |
| WnfStateChange | Windows Notification Framework state | Advanced evasion |

**Event-triggered tasks** are particularly stealthy — a task that fires when Event ID 4624 (successful logon) is generated will execute every time anyone logs in, without a time-based pattern to detect.

---

## Malicious Task Creation

### Via schtasks.exe

```cmd
schtasks /create /tn "\Microsoft\Windows\Update\SystemUpdate" ^
  /tr "powershell.exe -WindowStyle Hidden -enc <base64>" ^
  /sc minute /mo 5 ^
  /ru SYSTEM ^
  /f

schtasks /run /tn "\Microsoft\Windows\Update\SystemUpdate"
```

### Via PowerShell

```powershell
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-WindowStyle Hidden -enc JABjAG0AZAAuAGUAeABlAA=="

$trigger = New-ScheduledTaskTrigger -AtStartup

$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" `
    -LogonType ServiceAccount -RunLevel Highest

$settings = New-ScheduledTaskSettingsSet -Hidden

Register-ScheduledTask -TaskName "\Microsoft\Windows\Update\SystemUpdate" `
    -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force
```

### Via COM Object (T1053.005 — fileless)

```powershell
$scheduler = New-Object -ComObject "Schedule.Service"
$scheduler.Connect()
$folder = $scheduler.GetFolder("\")
$taskDef = $scheduler.NewTask(0)
# ... configure taskDef ...
$folder.RegisterTaskDefinition("UpdateTask", $taskDef, 6, "SYSTEM", $null, 5)
```

---

## COM Hijacking via Tasks

Certain built-in Windows tasks load COM objects by CLSID. If the CLSID is registered in HKCU (user-level), an attacker can override it with a malicious DLL — no admin required, no new task created.

```powershell
# Find tasks that load COM objects (potential hijack targets)
Get-ScheduledTask | Where-Object { $_.Actions.ClassId -ne $null } |
  Select-Object TaskName, TaskPath

# Plant malicious COM registration (no admin needed)
$clsid = "{GUID-FROM-TASK}"
New-Item -Path "HKCU:\Software\Classes\CLSID\$clsid\InprocServer32" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\$clsid\InprocServer32" `
    -Name "(default)" -Value "C:\Users\user\AppData\Roaming\evil.dll"
```

---

## Investigation Commands

```powershell
# List all scheduled tasks
Get-ScheduledTask | Select-Object TaskName, TaskPath, State | Sort-Object TaskPath

# Non-disabled tasks with their actions
Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } |
  ForEach-Object {
    [PSCustomObject]@{
      Name    = $_.TaskName
      Path    = $_.TaskPath
      Execute = $_.Actions.Execute
      Args    = $_.Actions.Arguments
      User    = $_.Principal.UserId
      Trigger = $_.Triggers.GetType().Name
    }
  } | Where-Object { $_.Execute } |
  Sort-Object Path

# Find tasks executing from suspicious locations
Get-ScheduledTask | ForEach-Object {
  $task = $_
  $_.Actions | ForEach-Object {
    if ($_.Execute -match 'Temp|AppData|ProgramData|Users\\Public|%TEMP%') {
      [PSCustomObject]@{
        TaskName = $task.TaskName
        Execute  = $_.Execute
        Args     = $_.Arguments
        User     = $task.Principal.UserId
      }
    }
  }
}

# Find tasks running as SYSTEM with non-Microsoft actions
Get-ScheduledTask | Where-Object {
  $_.Principal.UserId -match 'S-1-5-18|SYSTEM'
} | ForEach-Object {
  $task = $_
  $_.Actions | Where-Object {
    $_.Execute -and $_.Execute -notmatch 'C:\\Windows\\System32|C:\\Windows\\SysWOW64'
  } | ForEach-Object {
    [PSCustomObject]@{
      TaskName = $task.TaskName
      Execute  = $_.Execute
      Args     = $_.Arguments
    }
  }
}

# Read task XML directly
Get-Content "C:\Windows\System32\Tasks\Microsoft\Windows\Update\SystemUpdate" |
  Select-String "Command|Arguments|UserId|Author"

# Find recently modified task files
Get-ChildItem "C:\Windows\System32\Tasks" -Recurse |
  Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } |
  Sort-Object LastWriteTime -Descending |
  Select-Object FullName, LastWriteTime

# Task execution history from event log
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-TaskScheduler/Operational'
  Id=200  # Task executed
} -MaxEvents 50 | ForEach-Object {
  $xml = [xml]$_.ToXml()
  [PSCustomObject]@{
    Time     = $_.TimeCreated
    TaskName = $xml.Event.EventData.Data[0].'#text'
    Action   = $xml.Event.EventData.Data[1].'#text'
  }
}

# Check registry vs filesystem for discrepancies
$regTasks = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks" |
  ForEach-Object { Get-ItemProperty $_.PSPath | Select-Object Path }
$fsTasks = Get-ChildItem "C:\Windows\System32\Tasks" -Recurse -File |
  ForEach-Object { $_.FullName -replace 'C:\\Windows\\System32\\Tasks','' -replace '\\','/' }
Compare-Object ($regTasks.Path) ($fsTasks) | Where-Object { $_.SideIndicator -eq '<=' }
```

---

## Task Scheduler Event IDs

| Event ID | Description |
|----------|-------------|
| 106 | Task registered |
| 140 | Task updated |
| 141 | Task deleted |
| 200 | Task action started |
| 201 | Task action completed |
| 202 | Task completed |
| 4698 | Security: Scheduled task created |
| 4699 | Security: Scheduled task deleted |
| 4700 | Security: Scheduled task enabled |
| 4701 | Security: Scheduled task disabled |
| 4702 | Security: Scheduled task updated |

```powershell
# All task creation events
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4698} |
  Select-Object TimeCreated, Message | Format-List

# Task execution timeline
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-TaskScheduler/Operational'
  Id=@(200, 201)
} -MaxEvents 100 | Sort-Object TimeCreated
```

---

## MITRE ATT&CK Mapping

| Technique | ID |
|-----------|-----|
| Scheduled Task/Job: Scheduled Task | T1053.005 |
| Boot/Logon Autostart | T1547 |
| Hijack Execution Flow: COM Hijacking | T1546.015 |

---

## Sigma Rule — Scheduled Task Created by Non-Standard Process

```yaml
title: Scheduled Task Created by Suspicious Process
id: c5d6e7f8-a9b0-1234-cdef-567890123456
status: stable
description: >
  Detects scheduled task creation by processes outside
  of expected management tools. Attackers create tasks
  via PowerShell, cmd, or direct COM for persistence.
author: Solomon James (@Jaysolex)
tags:
  - attack.persistence
  - attack.t1053.005
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4698
  filter_legitimate:
    SubjectUserName|endswith: '$'    # machine accounts creating tasks
  condition: selection and not filter_legitimate
falsepositives:
  - Software installers creating scheduled tasks
  - Admin scripts deploying tasks
level: medium
```

---

## Practitioner Notes

**On hidden tasks:** Task definitions can set `<Hidden>true</Hidden>` — this hides the task from the Task Scheduler GUI and from `Get-ScheduledTask` by default. Always read task XML files directly from `C:\Windows\System32\Tasks\` rather than relying solely on PowerShell cmdlets. The `-Force` parameter on `Get-ScheduledTask` is not sufficient to reveal all hidden tasks.

**On registry vs filesystem discrepancy:** A task that exists in the registry cache but has no corresponding XML file in `C:\Windows\System32\Tasks\` is a red flag — it may be a "ghost task" created by some rootkits or may indicate filesystem tampering. The scheduler reads from the XML files — the registry is a cache. Always compare both.

**On COM hijacking via tasks:** This technique requires no admin privileges, creates no new tasks, and leaves minimal traditional IOCs. The attacker relies on a legitimate built-in task that loads a COM object, overrides that COM registration in HKCU, and waits for the task to execute. Detection requires monitoring HKCU COM registrations with Sysmon registry events (Event ID 13) and comparing HKCU CLSID registrations against those in HKLM.

---

## Knowledge Validation

**A scheduled task runs as SYSTEM but the XML file shows the Author as a standard user account. What does this indicate?**
The Author field shows who created or registered the task — a standard user. The Principal UserId shows who it runs as — SYSTEM. A standard user cannot normally create tasks that run as SYSTEM through the standard API. This combination indicates the task was created through privilege escalation or via direct registry/XML manipulation rather than standard API calls. It warrants investigation of how the task was created and what the standard user account did leading up to task creation.

**How do event-triggered tasks differ from time-triggered tasks from a detection perspective?**
Time-triggered tasks create predictable patterns — beaconing at fixed intervals shows up in timechart analysis. Event-triggered tasks fire based on Windows event log entries — they have no fixed time pattern and may only execute once per logon or under specific conditions. Detection requires monitoring the TaskScheduler Operational log for Event ID 200 (task started) and correlating with the triggering event rather than looking for time-based patterns.

**During IR you find a scheduled task in the registry cache with no corresponding XML file in System32\Tasks. What are your next steps?**
This is a significant anomaly — the XML file is the authoritative task definition. Steps: (1) read the registry cache entry directly to understand what the task does; (2) check TaskScheduler Operational log for Event ID 200 to see if and when the task executed; (3) check Security log Event ID 4698 for when the task was created; (4) check if the task executable path still exists on disk; (5) look for similar anomalies — missing XML files for multiple registry tasks suggests systematic tampering. The registry path is `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{GUID}`.

---

*Windows/08-Scheduled-Tasks | OS-Internals-for-SOC | Solomon James (@Jaysolex)*
