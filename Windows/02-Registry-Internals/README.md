# Windows/02 — Registry Internals

> The Windows Registry is not a database of settings. It is the central nervous system of the OS — every service, every driver, every autorun, every COM object, every security policy lives here. Attackers know this. The registry is the most abused persistence and configuration mechanism on Windows.

![MITRE](https://img.shields.io/badge/MITRE-T1112%20|%20T1547.001%20|%20T1546%20|%20T1574-red)
![Platform](https://img.shields.io/badge/Platform-Windows-blue)

---

## Registry Architecture

The registry is organized as a hierarchical key-value store. On disk it is stored in binary files called hives. In memory the kernel maps these hives and exposes them through the registry API.

```
Registry (in-memory, kernel-managed)
    |
    +-- HKEY_LOCAL_MACHINE (HKLM)     <- system-wide settings
    |       |
    |       +-- SAM         <- local accounts (maps to SAM hive file)
    |       +-- SECURITY    <- security policy, LSA secrets
    |       +-- SYSTEM      <- hardware config, services, boot
    |       +-- SOFTWARE    <- installed applications, OS config
    |       +-- HARDWARE    <- detected hardware (volatile, rebuilt at boot)
    |
    +-- HKEY_CURRENT_USER (HKCU)      <- current user settings (maps to NTUSER.DAT)
    |
    +-- HKEY_USERS (HKU)              <- all loaded user hives
    |
    +-- HKEY_CLASSES_ROOT (HKCR)      <- COM registrations, file associations
    |                                    (merge of HKLM\SOFTWARE\Classes + HKCU\SOFTWARE\Classes)
    |
    +-- HKEY_CURRENT_CONFIG (HKCC)    <- current hardware profile (volatile)
```

---

## Hive Files on Disk

Hives are the physical files that store registry data. The OS locks them while running.

| Hive | File Path | Contains |
|------|-----------|---------|
| HKLM\SAM | `C:\Windows\System32\config\SAM` | Local user accounts and NTLM hashes |
| HKLM\SECURITY | `C:\Windows\System32\config\SECURITY` | LSA secrets, cached credentials, policy |
| HKLM\SYSTEM | `C:\Windows\System32\config\SYSTEM` | Services, drivers, boot config, timezone |
| HKLM\SOFTWARE | `C:\Windows\System32\config\SOFTWARE` | Installed apps, run keys, OS settings |
| HKCU | `C:\Users\<user>\NTUSER.DAT` | User-specific settings, loaded at logon |
| HKCU\Classes | `C:\Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat` | User COM registrations, shellbags |

### Hive Transaction Logs

Every hive has a transaction log (`.LOG`, `.LOG1`, `.LOG2`) that records uncommitted changes. These are forensically valuable — they may contain registry modifications that were not yet flushed to the main hive.

```
C:\Windows\System32\config\SYSTEM.LOG
C:\Windows\System32\config\SYSTEM.LOG1
C:\Windows\System32\config\SYSTEM.LOG2
```

---

## Registry Data Types

| Type | Name | Description |
|------|------|-------------|
| REG_SZ | String | Null-terminated Unicode string |
| REG_EXPAND_SZ | Expandable String | String with environment variable references |
| REG_BINARY | Binary | Raw binary data |
| REG_DWORD | 32-bit integer | 4-byte value |
| REG_QWORD | 64-bit integer | 8-byte value |
| REG_MULTI_SZ | Multi-string | Multiple null-terminated strings |

---

## Critical Registry Keys — Security Reference

### Autorun and Persistence

```
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
  Userinit     (runs after logon)
  Shell        (usually explorer.exe — replace for persistence)
HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
  Shell        (user-level shell replacement)
```

### Service Configuration

```
HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>
  ImagePath    <- path to service binary (T1543.003)
  Start        <- 0=Boot, 1=System, 2=Auto, 3=Manual, 4=Disabled
  Type         <- 1=Kernel driver, 16=Own process, 32=Share process
  ObjectName   <- account service runs as
```

New service = new subkey here. Detection: monitor for new keys created under Services.

### DLL Injection via Registry

```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows
  AppInit_DLLs     <- loaded by every process that loads User32.dll (T1546.010)
  LoadAppInit_DLLs <- must be 1 for AppInit_DLLs to work

HKLM\SYSTEM\CurrentControlSet\Control\Session Manager
  BootExecute      <- runs before Windows fully loads (T1547.012)

HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<process.exe>
  Debugger         <- replaces process with specified binary (T1546.012)
                      attacker sets: Debugger=cmd.exe
                      now every launch of process.exe runs cmd.exe instead
```

### COM Hijacking

```
HKCU\Software\Classes\CLSID\{GUID}\InprocServer32
  (default)    <- path to DLL implementing this COM object

HKLM\SOFTWARE\Classes\CLSID\{GUID}\InprocServer32
  (default)    <- system-wide COM registration
```

HKCU takes precedence over HKLM for COM resolution. An attacker creates a CLSID key in HKCU pointing to a malicious DLL — when any application instantiates that COM object, the malicious DLL loads instead. No admin required.

### Credential Storage

```
HKLM\SECURITY\Policy\Secrets                     <- LSA secrets (requires SYSTEM)
HKLM\SECURITY\Cache                              <- cached domain credentials (DCC2)
HKCU\Software\Microsoft\Internet Explorer\IntelliForms  <- IE saved credentials
HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest
  UseLogonCredential                             <- 1 = cleartext in LSASS memory
```

### Security Policy

```
HKLM\SYSTEM\CurrentControlSet\Control\Lsa
  LmCompatibilityLevel     <- NTLM version (6 = NTLMv2 only, most secure)
  RunAsPPL                 <- 1 = LSASS runs as Protected Process Light
  RestrictAnonymous        <- anonymous access to SAM
  NoLMHash                 <- disable LM hash storage

HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
  EnableLUA                <- UAC enabled (0 = UAC disabled)
  ConsentPromptBehaviorAdmin  <- UAC prompt level
```

### Network and DNS

```
HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters
  Hostname
  Domain
  NameServer               <- DNS servers configured

HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\<GUID>
  DhcpIPAddress
  DhcpNameServer
```

---

## Registry as Forensic Artifact

### ShimCache (AppCompatCache)

Records application execution — file path, last modified time, and whether the file was executed. Persists across reboots.

```
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
```

Parsing: AppCompatCacheParser.exe (Eric Zimmerman) or volatility shimcache plugin.

Forensic value: Proves a binary existed at a path and was executed — even if the binary has since been deleted.

### Amcache

Stores detailed application information including SHA1 hash.

```
C:\Windows\AppCompat\Programs\Amcache.hve
```

Forensic value: SHA1 hash of executed binary survives binary deletion. Cross-reference hash with threat intelligence.

### UserAssist

Tracks GUI application execution per user. ROT13 encoded.

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count
```

Forensic value: Proves a user interactively launched a specific application with run count and last execution time.

### MuiCache

Tracks application display names.

```
HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache
```

### RecentDocs

Tracks recently opened files per extension.

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
```

### TypedPaths / TypedURLs

User typed paths in Explorer and IE address bars.

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
HKCU\Software\Microsoft\Internet Explorer\TypedURLs
```

---

## Registry Modification — Attacker Techniques

### Disabling Security Features

```powershell
# Disable Windows Defender (T1562.001)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1

# Disable UAC (T1548.002)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0

# Enable WDigest cleartext (T1003.001)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 1

# Disable Windows Firewall
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v EnableFirewall /t REG_DWORD /d 0
```

### Persistence via Run Keys

```powershell
# Add persistence (T1547.001)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /t REG_SZ /d "C:\Users\Public\payload.exe"

# Verify
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
```

### Image File Execution Options Hijacking (Debugger)

```powershell
# Replace sethc.exe (sticky keys) with cmd.exe — classic backdoor (T1546.012)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\Windows\System32\cmd.exe"
# Now pressing Shift 5 times at lock screen opens cmd.exe as SYSTEM
```

---

## Registry Forensics — Investigation Commands

```powershell
# Query all autorun keys
$keys = @(
  "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
  "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
  "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
  "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)
foreach ($key in $keys) {
  Write-Host "=== $key ===" -ForegroundColor Cyan
  Get-ItemProperty $key -ErrorAction SilentlyContinue |
    Select-Object * -ExcludeProperty PS*
}

# Check Winlogon for shell replacement
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" |
  Select-Object Userinit, Shell

# Check AppInit_DLLs
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" |
  Select-Object AppInit_DLLs, LoadAppInit_DLLs

# Check IFEO for debugger hijacking
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" |
  ForEach-Object {
    $debugger = (Get-ItemProperty $_.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger
    if ($debugger) {
      [PSCustomObject]@{ Process=$_.PSChildName; Debugger=$debugger }
    }
  }

# Check WDigest
(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -ErrorAction SilentlyContinue).UseLogonCredential

# Check UAC settings
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" |
  Select-Object EnableLUA, ConsentPromptBehaviorAdmin

# Check LSASS PPL
(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa").RunAsPPL

# Find recently modified registry keys (requires baseline)
# Use reg export + diff approach
reg export HKLM\SOFTWARE C:\baseline_software.reg
# Compare later

# Services — find non-standard service binaries
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\*" |
  Where-Object { $_.ImagePath -and $_.ImagePath -notmatch "^C:\\Windows" } |
  Select-Object PSChildName, ImagePath, ObjectName

# WMI persistence check
Get-WMIObject -Namespace root\subscription -Class __EventFilter
Get-WMIObject -Namespace root\subscription -Class __EventConsumer
Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding
```

---

## Sysmon Registry Events

| Event ID | Description |
|----------|-------------|
| 12 | Registry key or value created/deleted |
| 13 | Registry value set |
| 14 | Registry key or value renamed |

```powershell
# Query for run key modifications
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=13} |
  Where-Object { $_.Message -match 'CurrentVersion\\Run' } |
  Select-Object TimeCreated, Message
```

---

## MITRE ATT&CK Mapping

| Technique | ID |
|-----------|-----|
| Modify Registry | T1112 |
| Boot/Logon Autostart: Registry Run Keys | T1547.001 |
| Boot/Logon Autostart: Winlogon Helper | T1547.004 |
| Boot/Logon Autostart: AppInit DLLs | T1546.010 |
| Event Triggered Execution: IFEO Injection | T1546.012 |
| Hijack Execution: DLL Search Order | T1574.001 |
| OS Credential Dumping: SAM | T1003.002 |
| Impair Defenses: Disable Security Tools | T1562.001 |

---

## Sigma Rule — Suspicious Run Key Created

```yaml
title: Suspicious Entry Added to Registry Run Key
id: f6a7b8c9-d0e1-2345-fabc-456789012345
status: stable
description: >
  Detects new values added to autorun registry keys.
  Attackers use run keys for user and system-level persistence.
author: Solomon James (@Jaysolex)
tags:
  - attack.persistence
  - attack.t1547.001
logsource:
  product: windows
  category: registry_set
detection:
  selection:
    TargetObject|contains:
      - '\CurrentVersion\Run\'
      - '\CurrentVersion\RunOnce\'
  filter_legitimate:
    Image|startswith:
      - 'C:\Windows\'
      - 'C:\Program Files\'
  condition: selection and not filter_legitimate
falsepositives:
  - Software installation from non-standard paths
  - Admin tools writing run keys
level: medium
```

---

## Practitioner Notes

**On offline hive analysis:** The registry hive files are locked while Windows runs. To read SAM, SECURITY, or SYSTEM on a live system use `reg save` or Volume Shadow Copies. Offline analysis (post-imaging) uses tools like Registry Explorer (Eric Zimmerman), regripper, or volatility. Always parse transaction logs alongside the main hive — they may contain changes not yet flushed.

**On COM hijacking detection:** User-level COM hijacking creates keys under `HKCU\Software\Classes\CLSID` — no admin required, no file system writes to protected directories. Standard file monitoring misses this. Detection requires monitoring `HKCU\Software\Classes\CLSID` for new InprocServer32 keys and validating the DLL path points to a legitimate signed binary.

**On IFEO debugger persistence:** The sticky keys (sethc.exe) and on-screen keyboard (osk.exe) IFEO backdoor predates modern security tools. It provides SYSTEM-level command access from the Windows lock screen. Detection: enumerate all IFEO keys with a Debugger value — any entry outside of legitimate debugger tools is suspicious.

---

## Knowledge Validation

**Why does HKCU take precedence over HKLM for COM object resolution and why does this matter for attackers?**
The Windows COM infrastructure checks HKCU before HKLM when resolving CLSIDs. HKCU is writable by the current user without admin privileges. An attacker creates a CLSID key in HKCU pointing to a malicious DLL — when any application running as that user instantiates the COM object, the malicious DLL loads. No UAC prompt, no admin required, no file system writes to protected directories.

**What is the forensic value of ShimCache versus Amcache?**
ShimCache (AppCompatCache) records file path and last modified time of executed binaries — proves a file existed at a path even after deletion, but does not contain a hash. Amcache records the SHA1 hash of the executed binary — allows identification even if the file is renamed or moved, and enables threat intelligence correlation against known-malicious hashes.

**An attacker adds a value to HKLM\Run pointing to a malicious binary then deletes the binary. What survives forensically?**
The registry key entry survives until explicitly deleted — readable in the live registry or in the SOFTWARE hive file. ShimCache may record the binary's execution. Prefetch may record execution history. Amcache may record the hash. Windows Event ID 4657 records registry value changes if object access auditing is enabled. Sysmon Event ID 13 records the registry write if Sysmon was running at the time.

---

*Windows/02-Registry-Internals | OS-Internals-for-SOC | Solomon James (@Jaysolex)*
