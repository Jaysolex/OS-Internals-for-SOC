# Windows/01 — Filesystem Hierarchy

> Windows directory structure is not arbitrary. It reflects the NT architecture — the separation between kernel space and user space, between system-managed and user-managed, between volatile and persistent. Every directory exists because the OS needs it to function. Understanding that need is what allows you to recognize when something is wrong.

![MITRE](https://img.shields.io/badge/MITRE-T1005%20|%20T1083%20|%20T1552%20|%20T1036%20|%20T1564-red)
![OS](https://img.shields.io/badge/Platform-Windows-blue)

---

## Windows Filesystem Architecture

The Windows NT filesystem is built on NTFS (New Technology File System). Unlike FAT32, NTFS supports:
- Access Control Lists (ACLs) on every file and directory
- Alternate Data Streams (ADS) — hidden data attached to files
- Transactional file operations
- Journaling via the `$LogFile` and `$UsnJrnl`
- Hard links and symbolic links
- Sparse files and compression

The Master File Table (MFT) is the heart of NTFS — a structured database where every file and directory on the volume has a record. The MFT itself is a file: `$MFT`. Even deleted files leave residual MFT records until overwritten. This is the foundation of Windows forensics.

```
C:\
│
├── Windows\          OS core — kernel, drivers, system32
├── Program Files\    64-bit applications
├── Program Files (x86)\  32-bit applications on 64-bit OS
├── ProgramData\      Application data (all users, hidden)
├── Users\            User profiles
├── System Volume Information\  VSS shadow copies, restore points
└── $Recycle.Bin\     Deleted files staging
```

---

## Full Directory Dissection

### `C:\Windows\` — The OS Core

The root of the Windows installation. Contains the kernel, system libraries, device drivers, system executables, and configuration data that define the operating environment.

**Never trust the presence of a file in `C:\Windows\` as evidence of legitimacy.** Attackers place malicious files here specifically because defenders assume it is clean.

---

### `C:\Windows\System32\` — 64-bit System Components

The most important directory in Windows. Contains 64-bit system DLLs, executables, drivers, and configuration files that the OS, services, and applications depend on.

**Key executables security practitioners must know:**

```
cmd.exe             Command interpreter
powershell.exe      PowerShell host
wscript.exe         Windows Script Host (VBScript/JScript)
cscript.exe         Console Script Host
mshta.exe           HTML Application host (MITRE: T1218.005)
regsvr32.exe        COM DLL registration (living-off-the-land)
rundll32.exe        DLL execution host (living-off-the-land)
msiexec.exe         Windows Installer
certutil.exe        Certificate utility (used for file download/decode)
bitsadmin.exe       Background Intelligent Transfer Service CLI
wmic.exe            WMI command-line interface
schtasks.exe        Scheduled task management
at.exe              Legacy task scheduler
net.exe             Network/user management
netsh.exe           Network configuration
sc.exe              Service Control CLI
reg.exe             Registry CLI
tasklist.exe        Process enumeration
taskkill.exe        Process termination
whoami.exe          Current user context
hostname.exe        System hostname
ipconfig.exe        Network configuration query
nltest.exe          Domain enumeration
dsquery.exe         Active Directory query tool
PsExec.exe          [Sysinternals] Remote execution (common attacker tool)
```

**Key DLLs security practitioners must know:**

```
ntdll.dll           NT layer — syscall interface between user and kernel mode
kernel32.dll        Core Windows API (process, memory, file, I/O)
kernelbase.dll      Refactored kernel32 (modern Windows)
advapi32.dll        Security, registry, service APIs
user32.dll          User interface, window management
ws2_32.dll          Winsock — network socket API
wininet.dll         HTTP/FTP client API (used by malware C2)
urlmon.dll          URL handling
shell32.dll         Shell integration
shlwapi.dll         Shell lightweight utility
ole32.dll           COM/OLE base
oleaut32.dll        Automation COM interfaces
secur32.dll         Security support provider interface
lsasrv.dll          LSA server — credential storage engine
samlib.dll          SAM database access
netapi32.dll        Network API
crypt32.dll         Cryptographic functions
bcrypt.dll          Modern crypto primitives
amsi.dll            Antimalware Scan Interface
clr.dll             .NET Common Language Runtime
```

**Critical subdirectories:**

```
C:\Windows\System32\drivers\         Kernel-mode device drivers (.sys files)
C:\Windows\System32\drivers\etc\     hosts, networks, protocol files (static DNS override)
C:\Windows\System32\config\          Registry hive files (SAM, SYSTEM, SECURITY, SOFTWARE, DEFAULT)
C:\Windows\System32\spool\           Print spooler (PrintNightmare vulnerability location)
C:\Windows\System32\Tasks\           Scheduled task XML definitions
C:\Windows\System32\winevt\Logs\     Windows Event Log files (.evtx)
C:\Windows\System32\wbem\            WMI repository
C:\Windows\System32\wbem\Repository\ WMI persistent subscription storage
C:\Windows\System32\WindowsPowerShell\  PowerShell installations
C:\Windows\System32\inetsrv\         IIS web server components
C:\Windows\System32\catroot\         Driver signing catalog
C:\Windows\System32\LogFiles\        IIS logs, ETW logs
C:\Windows\System32\SMI\             System Management Infrastructure
```

**Security investigation commands:**

```powershell
# Find recently created/modified files in System32
Get-ChildItem C:\Windows\System32 -File |
  Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } |
  Sort-Object LastWriteTime -Descending

# Find DLLs that are not Microsoft-signed
Get-ChildItem C:\Windows\System32 -Filter *.dll |
  ForEach-Object {
    $sig = Get-AuthenticodeSignature $_.FullName
    if ($sig.SignerCertificate.Subject -notmatch "Microsoft") {
      $_
    }
  }

# Check for masquerading — files named like system files but wrong hash
Get-FileHash C:\Windows\System32\svchost.exe
# Compare against known-good hash from Microsoft
```

---

### `C:\Windows\SysWOW64\` — 32-bit System Components on 64-bit Windows

The WOW64 (Windows 32-bit on Windows 64-bit) subsystem allows 32-bit applications to run on 64-bit Windows. `SysWOW64` contains the 32-bit versions of system DLLs.

**Security significance — the redirection trap:**

When a 32-bit process calls `C:\Windows\System32\`, Windows transparently redirects it to `C:\Windows\SysWOW64\`. This means:
- A 32-bit malware accessing `System32` is actually reading `SysWOW64`
- A 32-bit process can access the real `System32` via the alias `C:\Windows\Sysnative\`

This redirection is invisible in process logs unless you understand WOW64. Security tools that don't account for this miss the actual files being accessed.

```powershell
# Check if a process is 32-bit or 64-bit
Get-Process | ForEach-Object {
    $is32 = [System.Diagnostics.Process]::GetProcessById($_.Id) |
            Select-Object -ExpandProperty Handle |
            ForEach-Object { 
                $ptr = [IntPtr]::Zero
                [bool](Get-Variable -Name IsWow64Process -ErrorAction SilentlyContinue)
            }
    "$($_.Name) PID:$($_.Id)"
}
```

---

### `C:\Windows\Temp\` — System Temporary Files

The system-level temporary directory. Used by installers, update processes, and system services.

**Attacker use:** High-value staging area. System processes legitimately write here, making it harder to baseline. Malware frequently unpacks and executes from `C:\Windows\Temp\`.

```powershell
# List files in Windows\Temp sorted by creation time
Get-ChildItem C:\Windows\Temp -Force -Recurse |
  Sort-Object CreationTime -Descending |
  Select-Object FullName, CreationTime, LastWriteTime, Length

# Find executables in Windows\Temp
Get-ChildItem C:\Windows\Temp -Recurse -Include *.exe,*.dll,*.ps1,*.bat,*.vbs,*.js |
  Select-Object FullName, CreationTime
```

---

### `C:\Windows\Prefetch\` — Application Prefetch Cache

Windows prefetch files (`.pf`) record evidence of program execution — what executable ran, when it last ran, how many times, and what files it accessed during the first 10 seconds of execution.

**This directory is gold for DFIR.** Even if a binary is deleted, its prefetch file may remain for up to 128 entries (Windows 8+: 1024 entries), preserving evidence of execution.

```
C:\Windows\Prefetch\CMD.EXE-<hash>.pf
C:\Windows\Prefetch\POWERSHELL.EXE-<hash>.pf
C:\Windows\Prefetch\MIMIKATZ.EXE-<hash>.pf   ← attacker tool evidence
```

**Parsing prefetch with Eric Zimmerman Tools:**

```powershell
# PECmd.exe (PrefetchECmd — Eric Zimmerman)
PECmd.exe -d C:\Windows\Prefetch --csv C:\output\prefetch.csv

# Built-in: list prefetch files sorted by last run time
Get-ChildItem C:\Windows\Prefetch -Filter *.pf |
  Sort-Object LastWriteTime -Descending |
  Select-Object Name, LastWriteTime |
  Format-Table -AutoSize
```

**Note:** Prefetch is disabled on Windows Server editions by default. Enable it: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters` → `EnablePrefetcher = 3`

---

### `C:\Windows\System32\winevt\Logs\` — Windows Event Logs

Every Windows Event Log file in EVTX format. This is one of the primary artifact sources for SOC and DFIR.

```
Security.evtx         Authentication, privilege use, object access, policy change
System.evtx           Hardware, driver, service events
Application.evtx      Application-level events
Microsoft-Windows-Sysmon%4Operational.evtx    Sysmon telemetry
Microsoft-Windows-PowerShell%4Operational.evtx    PowerShell command logging
Microsoft-Windows-WMI-Activity%4Operational.evtx  WMI events
Microsoft-Windows-TaskScheduler%4Operational.evtx Scheduled task events
Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx  RDP
Microsoft-Windows-DNS-Client%4Operational.evtx    DNS queries
```

**Critical Security Event IDs:**

| Event ID | Description | Security Significance |
|----------|-------------|----------------------|
| 4624 | Logon Success | Who logged in, how (logon type), from where |
| 4625 | Logon Failure | Brute force detection |
| 4627 | Group membership on logon | Privilege context |
| 4648 | Logon with explicit credentials | Pass-the-hash, lateral movement |
| 4663 | Object access | File/registry access (requires SACL) |
| 4672 | Special privileges assigned | Admin-level logon |
| 4688 | Process creation | Command execution (requires audit policy) |
| 4697 | Service installed | Malicious service creation |
| 4698 | Scheduled task created | Persistence |
| 4699 | Scheduled task deleted | Attacker cleanup |
| 4700/4701 | Scheduled task enabled/disabled | Persistence manipulation |
| 4702 | Scheduled task updated | Persistence modification |
| 4719 | Audit policy changed | Attacker disabling logging |
| 4720 | User account created | Backdoor account |
| 4726 | User account deleted | Attacker cleanup |
| 4728/4732/4756 | Member added to security group | Privilege escalation |
| 4738 | User account changed | Account manipulation |
| 4756 | Member added to universal group | Domain privilege escalation |
| 4771 | Kerberos pre-auth failure | Kerberoasting / AS-REP roasting |
| 4776 | NTLM authentication | Lateral movement via NTLM |
| 4798 | User's local group membership queried | Recon |
| 4799 | Security-enabled local group queried | Recon |
| 1102 | Audit log cleared | Log tampering — T1070.001 |
| 4104 | PowerShell script block logged | Script execution content |
| 7045 | New service installed (System log) | Persistence / lateral movement |
| 7036 | Service started/stopped | Service state change |

```powershell
# Query Security log for failed logons (4625)
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4625
    StartTime = (Get-Date).AddHours(-24)
} | Select-Object TimeCreated, Message | Format-List

# Query for new services (7045)
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} |
  ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
      Time        = $_.TimeCreated
      ServiceName = $xml.Event.EventData.Data[0].'#text'
      ImagePath   = $xml.Event.EventData.Data[1].'#text'
      StartType   = $xml.Event.EventData.Data[2].'#text'
    }
  }

# Query for log clearing (1102)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102}

# Export all Security events to CSV for SIEM ingestion
Get-WinEvent -LogName Security -MaxEvents 5000 |
  Export-Csv C:\IR\security_events.csv -NoTypeInformation
```

---

### `C:\Windows\System32\config\` — Registry Hive Files

The physical files that store the Windows Registry on disk. These are memory-mapped by the OS at boot — what you see in `regedit` is the in-memory representation of these files.

```
SAM         Security Accounts Manager — local user accounts and password hashes
SECURITY    Security policy, LSA secrets, cached domain credentials
SYSTEM      Hardware configuration, services, boot configuration
SOFTWARE    Installed applications, OS configuration, run keys
DEFAULT     Default user profile settings
```

**These files are locked by the OS while Windows is running.** To read them on a live system, use volume shadow copies, registry export, or tools that use the Volume Shadow Copy Service API.

```powershell
# Export specific registry hives (live system)
reg save HKLM\SAM C:\IR\SAM.hiv
reg save HKLM\SECURITY C:\IR\SECURITY.hiv
reg save HKLM\SYSTEM C:\IR\SYSTEM.hiv
reg save HKLM\SOFTWARE C:\IR\SOFTWARE.hiv

# Read from shadow copy (without VSS API tools)
# List shadow copies
vssadmin list shadows

# Access shadow copy
$shadowPath = "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\"
Get-ChildItem "${shadowPath}Windows\System32\config\"
```

---

### `C:\Windows\System32\drivers\etc\` — Static Network Configuration

A small but forensically important directory containing files that pre-date DNS and are still consulted before DNS resolution on Windows.

```
hosts           Static hostname-to-IP mapping (DNS override)
networks        Network names and addresses
protocol        Protocol names and numbers
services        Service names and port numbers
```

**`hosts` file — critical attacker target:** By adding entries to the hosts file, an attacker can redirect specific domain lookups to attacker-controlled IPs — intercepting traffic intended for security tools, update servers, or authentication endpoints. This is a C2 resilience and defense evasion technique.

```powershell
# Read hosts file
Get-Content C:\Windows\System32\drivers\etc\hosts

# Check for modification (any non-comment, non-localhost entry is suspicious on workstations)
Get-Content C:\Windows\System32\drivers\etc\hosts |
  Where-Object { $_ -notmatch "^#" -and $_ -notmatch "localhost" -and $_ -notmatch "^$" }

# Check modification time
(Get-Item C:\Windows\System32\drivers\etc\hosts).LastWriteTime
```

---

### `C:\Windows\System32\wbem\Repository\` — WMI Repository

The WMI (Windows Management Instrumentation) repository stores the WMI schema, class definitions, and — critically — **permanent event subscriptions**. This is where fileless WMI persistence lives.

A WMI permanent event subscription consists of three components stored in this repository:
- `EventFilter` — what event triggers the subscription
- `EventConsumer` — what action to take
- `FilterToConsumerBinding` — links the two

```powershell
# Enumerate WMI permanent event subscriptions
Get-WMIObject -Namespace root\subscription -Class __EventFilter |
  Select-Object Name, Query

Get-WMIObject -Namespace root\subscription -Class __EventConsumer |
  Select-Object Name, CommandLineTemplate, ScriptText

Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding

# Delete a malicious subscription
$filter = Get-WMIObject -Namespace root\subscription -Class __EventFilter -Filter "Name='MaliciousFilter'"
$filter.Delete()
```

---

### `C:\Program Files\` and `C:\Program Files (x86)\` — Installed Applications

Standard installation locations for 64-bit and 32-bit applications respectively.

**Security significance:** Legitimate software installs here. Malware typically does not — it prefers `AppData`, `Temp`, or `ProgramData`. Finding a suspicious executable in `Program Files` usually means an attacker attempted to blend in, or a legitimate application was hijacked.

**DLL search order hijacking:** Many applications in `Program Files` load DLLs by name without a full path. If an attacker can write a malicious DLL to the application's directory (or a location earlier in the DLL search order), it loads instead of the legitimate DLL.

```
DLL Search Order (default, SafeDLLSearchMode enabled):
1. The directory from which the application loaded
2. C:\Windows\System32
3. C:\Windows\System
4. C:\Windows
5. Current directory
6. Directories in %PATH%
```

```powershell
# Find applications in Program Files that have writable DLL directories
Get-ChildItem "C:\Program Files" -Directory |
  ForEach-Object {
    $acl = Get-Acl $_.FullName
    $acl.Access |
      Where-Object { 
        $_.FileSystemRights -match "Write|FullControl" -and
        $_.IdentityReference -notmatch "Administrators|SYSTEM|TrustedInstaller"
      } |
      ForEach-Object { "$($_.IdentityReference) can write to $($_.Path)" }
  }
```

---

### `C:\ProgramData\` — All-User Application Data (Hidden)

Application data shared across all users. Hidden by default in Explorer. Contains application configuration, databases, license files, and — in security contexts — EDR telemetry databases, AV definitions, and log agent state.

**Attacker use:** Persistence mechanisms frequently target `ProgramData`. It is writable by standard users (unlike `Program Files`), persists across reboots, and is hidden from casual inspection.

```powershell
# List contents (hidden by default)
Get-ChildItem C:\ProgramData -Force -Recurse -Depth 2 |
  Sort-Object LastWriteTime -Descending |
  Select-Object FullName, LastWriteTime

# Find executables in ProgramData (suspicious on workstations)
Get-ChildItem C:\ProgramData -Recurse -Include *.exe,*.dll,*.ps1 -Force |
  Select-Object FullName, CreationTime
```

---

### `C:\Users\` — User Profiles

The equivalent of Linux's `/home`. Each user has a profile directory containing their personal files, application data, and configuration.

```
C:\Users\<username>\
├── Desktop\
├── Documents\
├── Downloads\
├── AppData\                          Hidden
│   ├── Roaming\                      Synced across domain-joined machines
│   │   ├── Microsoft\Windows\Start Menu\Programs\Startup\   ← persistence
│   │   ├── Microsoft\Windows\Recent\                         ← LNK artifacts
│   │   └── <application data>\
│   ├── Local\                        Machine-specific, not synced
│   │   ├── Temp\                     ← attacker staging
│   │   ├── Microsoft\Windows\
│   │   │   ├── PowerShell\           ← PSReadLine history
│   │   │   └── Explorer\             ← shellbag artifacts
│   │   └── <application data>\
│   └── LocalLow\                     Low-integrity process data (sandboxed apps)
├── NTUSER.DAT                        User-specific registry hive (loaded at logon)
└── ntuser.dat.LOG                    Transaction log for NTUSER.DAT
```

#### `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`

Files placed here execute automatically when the user logs on. One of the oldest and most reliable persistence mechanisms in Windows.

```powershell
# Check all users' Startup folders
$users = Get-ChildItem C:\Users -Directory
foreach ($user in $users) {
    $startup = "$($user.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
    if (Test-Path $startup) {
        Get-ChildItem $startup -Force | Select-Object FullName, CreationTime
    }
}

# Also check the system-wide startup
Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" -Force
```

#### `C:\Users\<user>\AppData\Local\Temp\`

User-level temp directory. Legitimate installers write here. Malware frequently stages payloads, unpacks archives, and executes from here.

```powershell
# Find recently created executables in user Temp
$users = Get-ChildItem C:\Users -Directory
foreach ($user in $users) {
    $temp = "$($user.FullName)\AppData\Local\Temp"
    if (Test-Path $temp) {
        Get-ChildItem $temp -Recurse -Include *.exe,*.dll,*.ps1,*.bat,*.vbs -Force |
          Where-Object { $_.CreationTime -gt (Get-Date).AddDays(-7) } |
          Select-Object FullName, CreationTime
    }
}
```

#### `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\`

LNK (shortcut) files are automatically created by the Windows Shell when a user opens a file. These persist even after the original file is deleted and contain:
- Original file path (including network paths)
- File timestamps (created, modified, accessed)
- Volume serial number
- MAC address (for network paths)
- File size at time of access

**DFIR significance:** LNK files prove a user interacted with a specific file at a specific time — even if the file has since been deleted or the drive unmounted.

```powershell
# Parse LNK files for all users
$users = Get-ChildItem C:\Users -Directory
foreach ($user in $users) {
    $recent = "$($user.FullName)\AppData\Roaming\Microsoft\Windows\Recent"
    if (Test-Path $recent) {
        Get-ChildItem $recent -Filter *.lnk |
          Sort-Object LastWriteTime -Descending |
          Select-Object Name, LastWriteTime
    }
}
# Use LECmd.exe (Eric Zimmerman) for full LNK parsing
# LECmd.exe -d "C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent" --csv C:\output\
```

#### `C:\Users\<user>\AppData\Local\Microsoft\Windows\PowerShell\`

Contains PSReadLine history — a record of every PowerShell command typed interactively by the user. This is separate from PowerShell script block logging.

```powershell
# Read PowerShell command history for all users
$users = Get-ChildItem C:\Users -Directory
foreach ($user in $users) {
    $histPath = "$($user.FullName)\AppData\Local\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $histPath) {
        Write-Host "=== $($user.Name) ==="
        Get-Content $histPath
    }
}
```

#### `C:\Users\<user>\NTUSER.DAT` — User Registry Hive

Loaded into `HKEY_CURRENT_USER` when the user logs on. Contains user-specific settings, application configurations, and — critically — user-specific persistence keys.

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run          User-level autorun
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce      One-time user autorun
HKCU\Environment                                             User environment variables
HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon  User winlogon settings
HKCU\Software\Classes\                                       User COM registrations
```

---

### `C:\Windows\Tasks\` and `C:\Windows\System32\Tasks\` — Scheduled Tasks

Scheduled task XML definitions are stored here. `System32\Tasks\` is the authoritative location on modern Windows.

```powershell
# List all scheduled tasks
Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } |
  Select-Object TaskName, TaskPath, State |
  Sort-Object TaskPath

# Get full details including action (what runs)
Get-ScheduledTask | ForEach-Object {
    $task = $_
    $actions = $task.Actions
    [PSCustomObject]@{
        Name    = $task.TaskName
        Path    = $task.TaskPath
        Execute = $actions.Execute
        Args    = $actions.Arguments
        UserId  = $task.Principal.UserId
        State   = $task.State
    }
} | Where-Object { $_.Execute -match "powershell|cmd|wscript|cscript|mshta|regsvr32" }
```

---

### `C:\System Volume Information\` — VSS and Restore Points

Contains Volume Shadow Copy Service (VSS) data — point-in-time snapshots of the volume. Only accessible by SYSTEM.

**DFIR use:** Shadow copies may contain earlier versions of files that have since been encrypted (ransomware) or deleted. They are a forensic gold mine.

**Attacker use:** Ransomware deletes shadow copies as part of its execution to prevent recovery. Detection of `vssadmin delete shadows` or `wmic shadowcopy delete` is a ransomware indicator.

```powershell
# List shadow copies
vssadmin list shadows
Get-WmiObject Win32_ShadowCopy | Select-Object ID, InstallDate, VolumeName

# Access a shadow copy
$shadow = Get-WmiObject Win32_ShadowCopy | Select-Object -First 1
$shadowPath = $shadow.DeviceObject + "\"
cmd /c mklink /d C:\shadowmount "$shadowPath"

# Detect shadow copy deletion (Event ID 524 in Application log, or process creation audit)
Get-WinEvent -FilterHashtable @{LogName='Application'; Id=524} -ErrorAction SilentlyContinue
```

---

### `C:\$Recycle.Bin\` — Deleted Files Staging

When a file is deleted in Explorer (not Shift+Delete), it is moved here. The original path and deletion timestamp are preserved in metadata files (`$I` files).

```
C:\$Recycle.Bin\<SID>\
    $IXXX...   Metadata: original path, deletion time, original size
    $RXXX...   The actual deleted file content
```

```powershell
# List recycle bin contents for all users
Get-ChildItem 'C:\$Recycle.Bin' -Force -Recurse |
  Where-Object { $_.Name -like '$I*' } |
  ForEach-Object {
    # Read metadata from $I file to get original path
    $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
    $originalSize = [BitConverter]::ToInt64($bytes, 8)
    $deletionTime = [DateTime]::FromFileTime([BitConverter]::ToInt64($bytes, 16))
    $originalPath = [System.Text.Encoding]::Unicode.GetString($bytes, 28, $bytes.Length - 28).TrimEnd([char]0)
    [PSCustomObject]@{
      DeletionTime = $deletionTime
      OriginalPath = $originalPath
      Size         = $originalSize
      MetaFile     = $_.FullName
    }
  } | Sort-Object DeletionTime -Descending
```

---

## Alternate Data Streams — The Hidden Layer

NTFS supports Alternate Data Streams (ADS) — additional data attached to any file or directory, invisible to standard `dir` commands and Windows Explorer. The primary stream is the visible file. Additional named streams are hidden.

**Attacker use:** ADS can hide executable content, configuration data, or exfiltrated data inside innocent-looking files. The Zone.Identifier stream is a legitimate Windows security feature that marks downloaded files — attackers remove it to prevent SmartScreen from flagging their payloads.

```
legitfile.txt:hidden_payload.exe    ← ADS named "hidden_payload.exe"
file.txt:Zone.Identifier            ← Marks file as downloaded from internet
```

```powershell
# Find files with ADS (beyond Zone.Identifier)
Get-ChildItem C:\ -Recurse -Force -ErrorAction SilentlyContinue |
  ForEach-Object { Get-Item $_.FullName -Stream * -ErrorAction SilentlyContinue } |
  Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' } |
  Select-Object FileName, Stream, Length

# Read an ADS
Get-Content "file.txt:hidden_stream"

# Execute from ADS
wmic process call create "C:\legitimate.txt:payload.exe"

# Check Zone.Identifier (download source)
Get-Content "suspicious.exe:Zone.Identifier"
# ZoneId=3 means downloaded from internet
```

---

## Windows Filesystem Forensic Artifacts Summary

| Artifact | Location | What It Proves |
|----------|----------|----------------|
| MFT | `$MFT` (root of volume) | Every file ever created — timestamps, size, attributes |
| USN Journal | `$Extend\$UsnJrnl` | File system change log — create, modify, delete, rename |
| Prefetch | `C:\Windows\Prefetch\` | Program executed, when, how often, what it accessed |
| LNK files | `%AppData%\...\Recent\` | User opened a file — path, timestamps, volume serial |
| Shellbags | `NTUSER.DAT`, `UsrClass.dat` | User navigated to a folder — proves awareness of content |
| Jump Lists | `%AppData%\...\Recent\AutomaticDestinations\` | Recently opened files per application |
| Amcache | `C:\Windows\AppCompat\Programs\Amcache.hve` | Application execution — hash, publisher, install path |
| Shimcache | `SYSTEM` hive | Application execution — file path, size, last modified |
| SRUM | `C:\Windows\System32\sru\SRUDB.dat` | Network usage, CPU, memory per app — 30-60 day history |
| Event Logs | `C:\Windows\System32\winevt\Logs\` | Authentication, process creation, service events |
| WMI Repository | `C:\Windows\System32\wbem\Repository\` | Persistent WMI subscriptions — fileless persistence |
| Registry | `C:\Windows\System32\config\` | System config, installed software, autorun keys |
| VSS | `C:\System Volume Information\` | Point-in-time volume snapshots |
| $Recycle.Bin | `C:\$Recycle.Bin\` | Deleted files with original path and deletion time |
| Scheduled Tasks | `C:\Windows\System32\Tasks\` | Task definitions — what runs, when, as whom |
| Hiberfil.sys | `C:\hiberfil.sys` | Hibernation file — compressed memory snapshot |
| Pagefile.sys | `C:\pagefile.sys` | Virtual memory — may contain fragments of malware |

---

## MITRE ATT&CK Mapping

| Technique | ID | Directory/Artifact |
|-----------|----|--------------------|
| Masquerading | T1036 | `C:\Windows\System32\`, `C:\Windows\` |
| DLL Side-Loading | T1574.002 | `C:\Program Files\`, `C:\ProgramData\` |
| DLL Search Order Hijacking | T1574.001 | Application directories |
| Boot/Logon Autostart — Registry Run Keys | T1547.001 | `NTUSER.DAT`, `SOFTWARE` hive |
| Boot/Logon Autostart — Startup Folder | T1547.001 | `AppData\Roaming\...\Startup\` |
| Scheduled Task | T1053.005 | `C:\Windows\System32\Tasks\` |
| WMI Event Subscription | T1546.003 | `C:\Windows\System32\wbem\Repository\` |
| Indicator Removal — Clear Windows Log | T1070.001 | `C:\Windows\System32\winevt\Logs\` |
| Inhibit System Recovery | T1490 | `C:\System Volume Information\` |
| Unsecured Credentials | T1552 | `C:\Users\`, `C:\Windows\System32\config\` |
| Hide Artifacts — ADS | T1564.004 | Any NTFS file |
| Modify Hosts File | T1565.001 | `C:\Windows\System32\drivers\etc\hosts` |
| Credential Dumping — SAM | T1003.002 | `C:\Windows\System32\config\SAM` |

---

## Practitioner Notes

**On `System32` vs `SysWOW64`:** When analyzing process behavior in a 32-bit context on 64-bit Windows, remember the WOW64 redirection. Always verify actual file paths against what the process monitor shows. A 32-bit process saying it loaded `System32\evil.dll` actually loaded `SysWOW64\evil.dll`.

**On NTFS timestamps:** Windows NTFS has four timestamps per file (MACE: Modified, Accessed, Changed, Entry Modified). Tools that manipulate timestamps (`timestomp`) typically only affect three of them, leaving the `$STANDARD_INFORMATION` and `$FILE_NAME` attribute timestamps potentially inconsistent — a forensic indicator of anti-forensics.

**On VSS and ransomware:** Ransomware deletes shadow copies before encrypting. Detection of this is high-confidence evidence of ransomware execution. Correlate: process creation audit for `vssadmin` + `wbadmin` + `wmic shadowcopy` → volume of file renames with unusual extensions.

**On the Recycle Bin SID:** The `$Recycle.Bin` directory contains per-SID subdirectories. Mapping SIDs to usernames from the registry (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`) links deleted files to specific user accounts.

---

## Knowledge Validation

**What is the WOW64 redirection and why does it matter for security analysis?**  
32-bit processes on 64-bit Windows have their `System32` references transparently redirected to `SysWOW64`. A 32-bit malware accessing `System32\cmd.exe` is actually accessing `SysWOW64\cmd.exe`. Security tools not accounting for this may log the wrong path. The real `System32` is accessible from 32-bit processes via the `Sysnative` alias.

**A threat actor deleted their malicious binary. Identify three artifacts that can still prove it executed.**  
Prefetch file in `C:\Windows\Prefetch\` (executable name, run count, last run time), Amcache.hve (executable hash, file path, publisher), Shimcache in the SYSTEM registry hive (file path, last modified time), Windows Event ID 4688 (process creation, if enabled), and Sysmon Event ID 1 (process creation with command line and hash).

**What is the forensic value of the `$I` files in `C:\$Recycle.Bin\`?**  
`$I` files store metadata for deleted files: the original full path, the deletion timestamp, and the original file size. This metadata persists even after the corresponding `$R` (content) file is permanently deleted, and can prove a specific file existed at a specific path at a specific time.

**Why is WMI subscription persistence considered fileless, and how do you detect it?**  
WMI subscriptions are stored in the WMI repository (`C:\Windows\System32\wbem\Repository\`) as objects in the WMI CIM database — not as standalone files on disk. Standard file monitoring does not see them. Detection requires querying the WMI repository directly: `Get-WMIObject -Namespace root\subscription -Class __EventFilter` and correlating with `__EventConsumer` and `__FilterToConsumerBinding`. Sysmon Event ID 19, 20, 21 logs WMI subscription events in real time.

**An analyst finds `C:\Windows\System32\svchost.exe` has a last write time of yesterday. Is this necessarily malicious?**  
Not necessarily — Windows updates can legitimately update `svchost.exe`. The investigation should: (1) verify the file hash against Microsoft's known-good hash, (2) check the Authenticode signature, (3) review Windows Update logs for a patch that ran yesterday, (4) compare the file size with known-good values. If the hash doesn't match Microsoft's and no legitimate update explains it, the file is suspect.

---

*Windows/01-Filesystem-Hierarchy | OS-Internals-for-SOC | Solomon James (@Jaysolex)*
