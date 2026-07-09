# Windows/05 — Windows Services

> Windows services are background processes managed by the Service Control Manager. They run at boot, often as SYSTEM, and persist across logons. Every major attacker capability — lateral movement, persistence, privilege escalation — has a service-based implementation. Understanding how SCM works is what allows you to find malicious services that look legitimate.

![MITRE](https://img.shields.io/badge/MITRE-T1543.003%20|%20T1574%20|%20T1569-red)
![Platform](https://img.shields.io/badge/Platform-Windows-blue)

---

## Service Control Manager (SCM)

The SCM (services.exe) is the Windows component that manages all services. It starts at boot, reads service configuration from the registry, and starts services in dependency order.

```
Boot
  |
  v
services.exe (SCM)
  |
  +-- reads HKLM\SYSTEM\CurrentControlSet\Services\
  |
  +-- starts Auto services in dependency order
  |       |
  |       +-- svchost.exe -k NetworkService  (group of network services)
  |       +-- svchost.exe -k LocalService    (group of local services)
  |       +-- svchost.exe -k netsvcs         (group of system services)
  |       +-- standalone service executables
  |
  +-- listens for service control requests
        (start, stop, pause, query via sc.exe or PowerShell)
```

---

## Service Registry Configuration

Every service has a registry key:

```
HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>
```

Key values:

| Value | Type | Description |
|-------|------|-------------|
| `ImagePath` | REG_EXPAND_SZ | Path to the service executable |
| `Start` | REG_DWORD | 0=Boot, 1=System, 2=Auto, 3=Manual, 4=Disabled |
| `Type` | REG_DWORD | 1=Kernel driver, 16=Own process, 32=Share process |
| `ObjectName` | REG_SZ | Account the service runs as |
| `Description` | REG_SZ | Human-readable description |
| `DependOnService` | REG_MULTI_SZ | Services that must start first |
| `FailureActions` | REG_BINARY | What to do on crash (restart, run command) |

### Start Types

| Value | Name | Behaviour |
|-------|------|-----------|
| 0 | Boot | Loaded by OS loader before kernel init |
| 1 | System | Loaded by kernel during init |
| 2 | Auto | Started by SCM at boot |
| 3 | Manual | Started on demand |
| 4 | Disabled | Not started |

### Service Account Types

| Account | Privileges | Use |
|---------|-----------|-----|
| LocalSystem (SYSTEM) | Highest — full local admin | Legacy services |
| LocalService | Reduced — no network creds | Simple services |
| NetworkService | Reduced — can use computer account on network | Network services |
| Custom account | Defined by admin | Least-privilege services |

**SYSTEM services:** Services running as LocalSystem have full local administrator privileges — equivalent to running as the local Administrator account. Compromising a SYSTEM service = full local compromise.

---

## Service Types

| Type Value | Name | Description |
|-----------|------|-------------|
| 1 | Kernel Driver | Kernel-mode driver (.sys) |
| 2 | File System Driver | Kernel filesystem driver |
| 16 | Own Process | Runs in its own svchost or dedicated process |
| 32 | Share Process | Shares svchost.exe with other services |
| 256 | Interactive | Can interact with desktop (legacy) |

---

## svchost.exe — Service Hosting

Most Windows services share svchost.exe instances. Each svchost instance runs with a `-k <group>` parameter specifying which service group it hosts.

```powershell
# List svchost processes and their hosted services
Get-WmiObject Win32_Process | Where-Object { $_.Name -eq 'svchost.exe' } |
  ForEach-Object {
    $pid = $_.ProcessId
    $cmd = $_.CommandLine
    $services = Get-WmiObject Win32_Service |
      Where-Object { $_.ProcessId -eq $pid } |
      Select-Object -ExpandProperty Name
    [PSCustomObject]@{
      PID = $pid
      CommandLine = $cmd
      Services = $services -join ', '
    }
  }
```

**Detection note:** Legitimate svchost.exe always:
- Runs from `C:\Windows\System32\svchost.exe`
- Has `services.exe` as parent
- Has `-k <group>` in command line

Any svchost without these properties is malicious.

---

## Malicious Service Creation

### Via sc.exe

```cmd
sc create MaliciousSvc binPath= "C:\Windows\Temp\payload.exe" start= auto obj= LocalSystem
sc description MaliciousSvc "Windows Update Helper"
sc start MaliciousSvc
```

### Via PowerShell

```powershell
New-Service -Name "WindowsDefenderUpdate" `
            -BinaryPathName "C:\ProgramData\update.exe" `
            -StartupType Automatic `
            -Description "Windows Defender Update Service"
Start-Service "WindowsDefenderUpdate"
```

### Via Registry

```powershell
$path = "HKLM:\SYSTEM\CurrentControlSet\Services\MalService"
New-Item -Path $path
New-ItemProperty -Path $path -Name "ImagePath" -Value "C:\temp\evil.exe" -PropertyType ExpandString
New-ItemProperty -Path $path -Name "Start" -Value 2 -PropertyType DWord
New-ItemProperty -Path $path -Name "Type" -Value 16 -PropertyType DWord
New-ItemProperty -Path $path -Name "ObjectName" -Value "LocalSystem" -PropertyType String
```

---

## DLL Hijacking via Services

### Unquoted Service Path (T1574.009)

If a service ImagePath contains spaces and is not quoted, Windows tries each space-separated component as a possible executable.

```
ImagePath: C:\Program Files\My Service\service.exe

Windows tries:
  C:\Program.exe                   <- if attacker can create this
  C:\Program Files\My.exe          <- if attacker can create this
  C:\Program Files\My Service\service.exe  <- actual service
```

```powershell
# Find services with unquoted paths containing spaces
Get-WmiObject Win32_Service |
  Where-Object {
    $_.PathName -notmatch '^"' -and
    $_.PathName -match ' ' -and
    $_.PathName -notmatch '^C:\\Windows'
  } |
  Select-Object Name, PathName, StartMode
```

### DLL Search Order Hijacking

Services that load DLLs by name without full path are vulnerable. The DLL search order on Windows:

```
1. Application directory (service binary location)
2. C:\Windows\System32
3. C:\Windows\System
4. C:\Windows
5. Current directory
6. PATH directories
```

If the service directory is writable, planting a malicious DLL with the right name causes it to load when the service starts.

```powershell
# Find service directories writable by non-admins
Get-WmiObject Win32_Service | ForEach-Object {
  $path = $_.PathName -replace '"','' -replace ' .*',''
  $dir = Split-Path $path -Parent
  if (Test-Path $dir) {
    $acl = Get-Acl $dir -ErrorAction SilentlyContinue
    $acl.Access | Where-Object {
      $_.FileSystemRights -match 'Write|FullControl' -and
      $_.IdentityReference -notmatch 'Administrators|SYSTEM|TrustedInstaller'
    } | ForEach-Object {
      "WRITABLE: $dir ($($_.IdentityReference))"
    }
  }
}
```

---

## Failure Actions — Service Recovery as Persistence

Services can be configured to execute a command on failure:

```powershell
# Configure failure action to run payload on crash
sc failure MalService reset= 0 actions= run/5000 command= "C:\temp\payload.exe"

# View failure actions
sc qfailure <ServiceName>
```

**Attacker technique:** Create a service that intentionally crashes, with a failure action that executes a payload. The payload runs as SYSTEM when the service fails — a persistence mechanism that's triggered by the service failing rather than starting normally.

---

## Service-Based Lateral Movement

### PsExec-Style

```bash
# PsExec creates a service on the remote host to execute commands
# Detectable via Event ID 7045 (new service installed) on target
psexec.exe \\target -u admin -p password cmd.exe

# Impacket equivalent
python smbexec.py domain/user:password@target
```

Detection: Event ID 7045 (new service) + Event ID 7036 (service started) on target host, combined with Event ID 4624 Type 3 (network logon) from source.

---

## Investigation Commands

```powershell
# All services and their state
Get-Service | Sort-Object Status -Descending

# Running services with executable paths
Get-WmiObject Win32_Service |
  Where-Object { $_.State -eq 'Running' } |
  Select-Object Name, DisplayName, PathName, StartName |
  Sort-Object Name

# Non-standard service paths (not in C:\Windows)
Get-WmiObject Win32_Service |
  Where-Object { $_.PathName -notmatch 'C:\\Windows' -and $_.PathName } |
  Select-Object Name, PathName, StartName, State

# Services running as SYSTEM with unusual paths
Get-WmiObject Win32_Service |
  Where-Object {
    $_.StartName -match 'LocalSystem|SYSTEM' -and
    $_.PathName -notmatch 'C:\\Windows'
  } |
  Select-Object Name, PathName, State

# Recently installed services (Event ID 7045)
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 50 |
  ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
      Time        = $_.TimeCreated
      ServiceName = $xml.Event.EventData.Data[0].'#text'
      ImagePath   = $xml.Event.EventData.Data[1].'#text'
      StartType   = $xml.Event.EventData.Data[2].'#text'
      Account     = $xml.Event.EventData.Data[4].'#text'
    }
  }

# Services with unquoted paths
Get-WmiObject Win32_Service |
  Where-Object {
    $_.PathName -notmatch '^"' -and
    $_.PathName -match ' ' -and
    $_.PathName -notmatch '^C:\\Windows'
  } |
  Select-Object Name, PathName

# Disabled services (may be attacker cleanup)
Get-WmiObject Win32_Service |
  Where-Object { $_.StartMode -eq 'Disabled' } |
  Select-Object Name, PathName
```

---

## Critical Event IDs

| Event ID | Log | Description |
|----------|-----|-------------|
| 4697 | Security | Service installed |
| 7045 | System | New service installed |
| 7034 | System | Service crashed unexpectedly |
| 7035 | System | Service sent start/stop control |
| 7036 | System | Service started or stopped |
| 7040 | System | Service start type changed |

---

## MITRE ATT&CK Mapping

| Technique | ID |
|-----------|-----|
| Create or Modify System Process: Windows Service | T1543.003 |
| Hijack Execution Flow: DLL Search Order | T1574.001 |
| Hijack Execution Flow: Unquoted Service Path | T1574.009 |
| System Services: Service Execution | T1569.002 |
| Lateral Tool Transfer | T1570 |

---

## Sigma Rule — New Service With Suspicious Path

```yaml
title: New Windows Service Created with Non-Standard Path
id: b4c5d6e7-f8a9-0123-bcde-456789012345
status: stable
description: >
  Detects creation of Windows services with executable
  paths outside expected system directories. Attackers
  create services from temp, user, or ProgramData paths.
author: Solomon James (@Jaysolex)
tags:
  - attack.persistence
  - attack.t1543.003
logsource:
  product: windows
  service: system
  definition: Event ID 7045
detection:
  selection:
    EventID: 7045
  filter_windows:
    ServiceFileName|startswith:
      - 'C:\Windows\'
      - '"C:\Windows\'
  filter_program_files:
    ServiceFileName|startswith:
      - 'C:\Program Files\'
      - 'C:\Program Files (x86)\'
  condition: selection and not filter_windows and not filter_program_files
falsepositives:
  - Third-party software installing services from non-standard paths
  - Admin tools and monitoring agents
level: medium
```

---

## Practitioner Notes

**On svchost child process detection:** Legitimate services hosted in svchost never spawn cmd.exe, powershell.exe, or other shells as direct children. If you see svchost.exe spawning a shell, it is either a malicious service executing a payload or a legitimate service being exploited. Check the specific svchost PID's hosted services to identify the culprit service.

**On service failure actions as evasion:** A service configured with a run-command failure action that crashes immediately after starting is a stealth persistence technique — the service appears to fail (normal behavior) but its failure action executes the real payload as SYSTEM. Detection: audit failure action configurations with `sc qfailure` for all services and alert on any with a command action pointing to unusual paths.

**On unquoted paths in practice:** This vulnerability has existed for decades and persists in third-party software. The key question during assessment is not just whether the path is unquoted but whether the intermediate directories are writable by non-admins. An unquoted path in `C:\Program Files\` is usually not exploitable because standard users cannot write there. The dangerous cases are unquoted paths in directories writable by the service account or standard users.

---

## Knowledge Validation

**Why is LocalSystem the most dangerous service account from a security perspective?**
LocalSystem has the highest local privileges on Windows — equivalent to the built-in Administrator but with no restrictions. It can read any file, write any registry key, access any process memory, and authenticate to network resources using the computer account. A service running as LocalSystem that is compromised gives the attacker complete local control. The principle of least privilege means services should run as NetworkService or LocalService unless they specifically need higher privileges.

**How does unquoted service path exploitation work and what determines exploitability?**
When a service ImagePath contains spaces and is not quoted, Windows tokenises the path at each space and tries each prefix as a possible executable. For `C:\Program Files\My App\service.exe`, Windows first tries `C:\Program.exe`, then `C:\Program Files\My.exe`. An attacker who can write to the root of C:\ can plant `C:\Program.exe` and have it execute as SYSTEM when the service starts. Exploitability depends on write permission to the intermediate directories — the vulnerability is theoretical if those directories are only writable by administrators.

**Event ID 7045 appears on a domain controller at 3 AM with ServiceFileName pointing to C:\Windows\Temp\update.exe. What is your response?**
This is a critical indicator — services are almost never installed at 3 AM pointing to temp directories. Steps: (1) immediately check if the service is running and stop it if so; (2) preserve the binary at C:\Windows\Temp\update.exe before it is deleted; (3) check Event ID 4624 for network logons to the DC around the same time to identify the source; (4) check Event ID 4697 in Security log for additional detail; (5) check for other new services, scheduled tasks, or registry autorun keys created around the same time; (6) escalate to full IR — a new service on a DC at 3 AM is a presumed compromise.

---

*Windows/05-Windows-Services | OS-Internals-for-SOC | Solomon James (@Jaysolex)*
