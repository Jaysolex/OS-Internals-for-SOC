# Windows/10 — Persistence Mechanisms

> Windows has dozens of persistence mechanisms — from registry run keys that have existed since Windows 95 to WMI subscriptions introduced in Windows Vista. Every one abuses a legitimate OS feature. A complete persistence hunt requires checking every location, every time.

![MITRE](https://img.shields.io/badge/MITRE-T1547%20|%20T1546%20|%20T1543%20|%20T1053-red)
![Platform](https://img.shields.io/badge/Platform-Windows-blue)

---

## Windows Persistence Map

```
Windows Persistence
    |
    +-- Registry Autorun
    |       Run / RunOnce keys (HKLM + HKCU)
    |       Winlogon helper DLLs
    |       AppInit_DLLs
    |       Image File Execution Options
    |       Browser Helper Objects
    |
    +-- Scheduled Tasks
    |       Time-based, event-based, logon-based
    |       COM-object tasks
    |
    +-- Services
    |       New service creation
    |       Existing service DLL replacement
    |       Service failure actions
    |
    +-- Boot/Logon Init
    |       Startup folder (user + all users)
    |       Logon scripts (Group Policy)
    |       Userinit / Shell replacement
    |
    +-- DLL Hijacking
    |       DLL search order
    |       DLL side-loading
    |       COM object hijacking
    |
    +-- WMI Subscriptions
    |       Permanent event subscriptions
    |       Fileless — no disk artifact
    |
    +-- Kernel/Driver Level
    |       Malicious driver (.sys)
    |       Boot execute
    |
    +-- Account-Based
            Backdoor account
            SSH authorized keys equivalent (OpenSSH on Windows)
            Golden Ticket (Kerberos)
```

---

## 1. Registry Run Keys (T1547.001)

The most common and oldest Windows persistence mechanism.

```
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
```

HKLM runs for all users (requires admin). HKCU runs for the current user only (no admin needed).

```powershell
# Add persistence
Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
    -Name "WindowsDefenderUpdate" `
    -Value "C:\Users\Public\update.exe"

# Enumerate all run keys
$keys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
)
foreach ($key in $keys) {
    Write-Host "=== $key ===" -ForegroundColor Cyan
    Get-ItemProperty $key -ErrorAction SilentlyContinue |
        Select-Object * -ExcludeProperty PS* | Format-List
}
```

---

## 2. Winlogon Helper (T1547.004)

Winlogon (winlogon.exe) loads helper DLLs and executables at user logon.

```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
    Userinit    = C:\Windows\system32\userinit.exe,   <- add payload after comma
    Shell       = explorer.exe                          <- replace with malicious shell
    Notify      = (DLL path)
```

```powershell
# Check Winlogon settings
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" |
    Select-Object Userinit, Shell, Notify

# Normal values:
# Userinit = C:\Windows\system32\userinit.exe,
# Shell = explorer.exe
# Anything else = investigate
```

---

## 3. AppInit_DLLs (T1546.010)

DLLs listed here are loaded by every process that loads User32.dll — which is almost every GUI application.

```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows
    AppInit_DLLs     = (path to malicious DLL)
    LoadAppInit_DLLs = 1

HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows
    AppInit_DLLs     = (32-bit DLL path)
```

```powershell
# Check AppInit
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" |
    Select-Object AppInit_DLLs, LoadAppInit_DLLs

# Should be empty or LoadAppInit_DLLs = 0
```

---

## 4. Image File Execution Options (T1546.012)

Allows a debugger to be specified per executable. Replaced by attacker with their payload.

```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<target.exe>
    Debugger = C:\evil\payload.exe
```

Now every launch of `<target.exe>` runs the payload instead.

**Classic abuse:** Replace sethc.exe (Sticky Keys), osk.exe (On-Screen Keyboard), or utilman.exe — accessible from the Windows lock screen as SYSTEM.

```powershell
# Check IFEO for debugger entries
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" |
  ForEach-Object {
    $dbg = (Get-ItemProperty $_.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger
    if ($dbg) {
      [PSCustomObject]@{ Process=$_.PSChildName; Debugger=$dbg }
    }
  }
```

---

## 5. Startup Folders (T1547.001)

Files in startup folders execute at user logon automatically.

```
# All users (requires admin)
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\

# Current user (no admin needed)
C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\
```

```powershell
# Check both startup folders
Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\" -Force
Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\" -Force -ErrorAction SilentlyContinue
```

---

## 6. Scheduled Tasks (T1053.005)

Covered in detail in Windows/08. Key persistence indicators:

```powershell
# Tasks running from suspicious locations
Get-ScheduledTask | ForEach-Object {
  $task = $_
  $_.Actions | Where-Object {
    $_.Execute -match 'Temp|AppData|Public|ProgramData'
  } | ForEach-Object {
    [PSCustomObject]@{
      Name    = $task.TaskName
      Execute = $_.Execute
      Args    = $_.Arguments
      User    = $task.Principal.UserId
    }
  }
}
```

---

## 7. Windows Services (T1543.003)

Services run at boot as SYSTEM (or other accounts). Covered in Windows/05.

```powershell
# Non-standard service paths
Get-WmiObject Win32_Service |
  Where-Object { $_.PathName -notmatch 'C:\\Windows' -and $_.StartMode -eq 'Auto' } |
  Select-Object Name, PathName, StartName
```

---

## 8. WMI Permanent Event Subscriptions (T1546.003)

The most stealthy Windows persistence mechanism. Fileless — stored in the WMI repository, not as files on disk.

Three components:

```
EventFilter    — what event triggers the subscription
EventConsumer  — what action to take when triggered
FilterToConsumerBinding — links filter to consumer
```

```powershell
# Create WMI persistence (no admin required for user-level)
$FilterName = "WindowsEventFilter"
$ConsumerName = "WindowsEventConsumer"

# Create filter (trigger on system uptime > 200 seconds)
$FilterArgs = @{
    Name = $FilterName
    EventNameSpace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 200"
}
$Filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments $FilterArgs

# Create consumer (execute command)
$ConsumerArgs = @{
    Name = $ConsumerName
    CommandLineTemplate = "powershell.exe -enc JABjAG0AZAAuAGUAeABlAA=="
}
$Consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments $ConsumerArgs

# Bind filter to consumer
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter = $Filter
    Consumer = $Consumer
}
```

```powershell
# Detection — enumerate WMI subscriptions
Get-WMIObject -Namespace root\subscription -Class __EventFilter |
    Select-Object Name, Query

Get-WMIObject -Namespace root\subscription -Class __EventConsumer |
    Select-Object Name, CommandLineTemplate, ScriptText

Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding

# Sysmon Event IDs 19, 20, 21 capture WMI subscription creation
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational'
    Id=@(19,20,21)
} | Select-Object TimeCreated, Message
```

---

## 9. DLL Hijacking (T1574)

Detailed in Windows/05 (Services). Key locations for persistence:

```powershell
# Known DLL hijack locations
# C:\Windows\System32\ (requires admin)
# Application directories (requires write to app dir)
# PATH directories
# Current directory at time of execution

# Find writable directories in PATH
$env:PATH -split ';' | ForEach-Object {
    if (Test-Path $_) {
        $acl = Get-Acl $_ -ErrorAction SilentlyContinue
        $acl.Access | Where-Object {
            $_.FileSystemRights -match 'Write|FullControl' -and
            $_.IdentityReference -notmatch 'Administrators|SYSTEM|TrustedInstaller'
        } | ForEach-Object { "WRITABLE PATH: $_ ($($_.IdentityReference))" }
    }
}
```

---

## 10. Boot Execute (T1547.012)

Programs listed in BootExecute run before Windows fully initialises — before user logon, before most security tools start.

```
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager
    BootExecute = autocheck autochk *   <- normal value
```

An attacker adds their binary here to execute at the very start of the boot process.

```powershell
# Check BootExecute
(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager").BootExecute
# Normal: autocheck autochk *
# Anything additional = investigate
```

---

## Full Persistence Audit Script

```powershell
# Windows Persistence Hunter
Write-Host "=== REGISTRY RUN KEYS ===" -ForegroundColor Cyan
$runKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
)
foreach ($key in $runKeys) {
    $vals = Get-ItemProperty $key -ErrorAction SilentlyContinue
    if ($vals) { Write-Host "$key"; $vals | Format-List }
}

Write-Host "=== WINLOGON ===" -ForegroundColor Cyan
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" |
    Select-Object Userinit, Shell, Notify

Write-Host "=== APPINIT DLLS ===" -ForegroundColor Cyan
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" |
    Select-Object AppInit_DLLs, LoadAppInit_DLLs

Write-Host "=== IFEO DEBUGGER ENTRIES ===" -ForegroundColor Cyan
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" |
  ForEach-Object {
    $dbg = (Get-ItemProperty $_.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger
    if ($dbg) { "$($_.PSChildName) -> $dbg" }
  }

Write-Host "=== STARTUP FOLDERS ===" -ForegroundColor Cyan
Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\" -Force -ErrorAction SilentlyContinue
Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\" -Force -ErrorAction SilentlyContinue

Write-Host "=== SCHEDULED TASKS (non-Microsoft) ===" -ForegroundColor Cyan
Get-ScheduledTask | Where-Object { $_.TaskPath -notmatch '\\Microsoft\\' } |
    Select-Object TaskName, TaskPath, State

Write-Host "=== SERVICES (non-standard paths) ===" -ForegroundColor Cyan
Get-WmiObject Win32_Service |
    Where-Object { $_.PathName -notmatch 'C:\\Windows' -and $_.StartMode -ne 'Disabled' } |
    Select-Object Name, PathName, StartName

Write-Host "=== WMI SUBSCRIPTIONS ===" -ForegroundColor Cyan
Get-WMIObject -Namespace root\subscription -Class __EventFilter | Select-Object Name, Query
Get-WMIObject -Namespace root\subscription -Class __EventConsumer | Select-Object Name, CommandLineTemplate

Write-Host "=== BOOT EXECUTE ===" -ForegroundColor Cyan
(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager").BootExecute
```

---

## MITRE ATT&CK Mapping

| Technique | ID |
|-----------|-----|
| Boot/Logon Autostart: Registry Run Keys | T1547.001 |
| Boot/Logon Autostart: Winlogon Helper | T1547.004 |
| Boot/Logon Autostart: AppInit DLLs | T1546.010 |
| Event Triggered: IFEO Injection | T1546.012 |
| Event Triggered: WMI Subscriptions | T1546.003 |
| Scheduled Task | T1053.005 |
| Windows Service | T1543.003 |
| Boot/Logon Autostart: Boot Execute | T1547.012 |
| Hijack Execution: DLL Side-Loading | T1574.002 |

---

## Practitioner Notes

**On WMI persistence detection gaps:** Standard file monitoring, registry monitoring, and process monitoring all miss WMI subscriptions — they are stored in the WMI repository binary files. Detection requires: Sysmon Events 19/20/21, querying the WMI namespace directly, or monitoring writes to `C:\Windows\System32\wbem\Repository\`. During any IR, WMI subscription enumeration is mandatory regardless of what other persistence was found.

**On IFEO and accessibility feature backdoors:** sethc.exe (Sticky Keys — Shift x5), utilman.exe (Ease of Access — Win+U), osk.exe (On-Screen Keyboard), and magnify.exe are all accessible from the Windows lock screen before authentication. An IFEO debugger entry replacing any of these with cmd.exe provides SYSTEM shell access from the lock screen — one of the oldest Windows backdoor techniques still used today. Check IFEO for all four.

**On RunOnce and cleanup detection:** RunOnce entries execute once at logon then are deleted. An attacker may use RunOnce to execute a payload on next logon and then clean up — the key is gone by the time you investigate. Detection relies on Sysmon registry monitoring (Event ID 13) capturing the RunOnce write before it executes, or Security Event ID 4657 if object access auditing is enabled.

---

## Knowledge Validation

**Why is WMI subscription persistence considered fileless and why does this matter for detection?**
WMI subscriptions are stored in the WMI CIM repository database (`C:\Windows\System32\wbem\Repository\`) as objects in the WMI namespace — not as standalone executable files or registry values. File-based monitoring, signature scanning, and most registry-based persistence checks do not detect them. The malicious code executes as a child process of WMI (WmiPrvSE.exe), which is a legitimate system process. Detection requires querying the WMI subscription namespace directly or Sysmon Events 19-21 at creation time.

**An attacker adds a path after the comma in Userinit. What happens and how do you detect it?**
The Userinit registry value lists programs to run immediately after logon, separated by commas. `userinit.exe,` is normal — the trailing comma is intentional (no additional program). Adding `userinit.exe,C:\evil\payload.exe,` causes both userinit.exe and payload.exe to execute at every logon for any user. Detection: Sysmon Event ID 13 captures the registry write. Baseline detection compares the value against the known-good `C:\Windows\system32\userinit.exe,` and alerts on any deviation.

**During persistence hunting you find an IFEO entry for sethc.exe with Debugger = cmd.exe. What are the implications?**
This is the classic accessibility feature backdoor. Pressing Shift five times at the Windows lock screen now launches cmd.exe as SYSTEM instead of Sticky Keys — providing an unauthenticated SYSTEM shell without any credentials. The attacker can create new accounts, dump credentials, or do anything that requires SYSTEM access without logging in. Immediate remediation: remove the IFEO entry. Investigation: determine when it was created (Sysmon Event ID 13), what account created it (requires admin), and what other persistence exists — this is almost never the only mechanism an attacker establishes.

---

*Windows/10-Persistence-Mechanisms | OS-Internals-for-SOC | Solomon James (@Jaysolex)*
