# Windows/01 — Filesystem Hierarchy

> The Windows directory structure reflects the NT architecture — system components, user data, application data, and volatile runtime state each have designated locations. Attackers know these locations as well as administrators do. What separates a security engineer is knowing not just where things live, but why — and what their presence or absence means during an investigation.

![MITRE](https://img.shields.io/badge/MITRE-T1005%20|%20T1083%20|%20T1552%20|%20T1036-red)
![Platform](https://img.shields.io/badge/Platform-Windows-blue)

---

## Root Drive Structure

```
C:\
├── Windows\                  OS core — kernel, drivers, system components
├── Program Files\            64-bit installed applications
├── Program Files (x86)\      32-bit applications on 64-bit Windows
├── ProgramData\              All-user application data (hidden)
├── Users\                    User profiles
├── System Volume Information\ VSS shadow copies (SYSTEM only)
├── $Recycle.Bin\             Deleted files staging
└── pagefile.sys / hiberfil.sys  Virtual memory and hibernation
```

---

## C:\Windows\ — OS Core

The Windows installation root. Contains everything required to run the operating system.

### C:\Windows\System32\ — 64-bit System Components

The most critical directory on Windows. Contains 64-bit system DLLs, executables, drivers, and configuration files.

**Key executables:**

```
cmd.exe             command interpreter
powershell.exe      PowerShell host
wscript.exe         Windows Script Host (VBScript/JScript)
cscript.exe         Console Script Host
mshta.exe           HTML Application host
regsvr32.exe        COM DLL registration (LOLBin)
rundll32.exe        DLL execution host (LOLBin)
msiexec.exe         Windows Installer
certutil.exe        Certificate utility — abused for file download/decode
bitsadmin.exe       BITS service CLI — abused for download
wmic.exe            WMI command line
schtasks.exe        Scheduled task management
sc.exe              Service control CLI
reg.exe             Registry CLI
net.exe             Network/user management
nltest.exe          Domain enumeration
ntdsutil.exe        AD database management — abused for NTDS dump
```

**Key DLLs:**

```
ntdll.dll           NT layer — syscall interface, always loaded
kernel32.dll        Core Windows API
kernelbase.dll      Refactored kernel32 (modern Windows)
advapi32.dll        Security, registry, service APIs
ws2_32.dll          Winsock — network socket API
wininet.dll         HTTP/FTP client — C2 communication
lsasrv.dll          LSA server — credential storage engine
amsi.dll            Antimalware Scan Interface
```

**Key subdirectories:**

```
System32\drivers\         Kernel-mode drivers (.sys files)
System32\drivers\etc\     hosts, services, protocol files
System32\config\          Registry hive files (SAM, SYSTEM, SECURITY, SOFTWARE)
System32\winevt\Logs\     Windows Event Log files (.evtx)
System32\Tasks\           Scheduled task XML definitions
System32\wbem\            WMI components
System32\wbem\Repository\ WMI persistent subscription database
System32\spool\           Print spooler (PrintNightmare location)
System32\WindowsPowerShell\ PowerShell installations
System32\LogFiles\        IIS and ETW logs
```

```powershell
# Find recently modified files in System32
Get-ChildItem C:\Windows\System32 -File |
  Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } |
  Sort-Object LastWriteTime -Descending |
  Select-Object FullName, LastWriteTime

# Find unsigned DLLs in System32
Get-ChildItem C:\Windows\System32 -Filter *.dll | ForEach-Object {
  $sig = Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue
  if ($sig.Status -ne 'Valid') {
    [PSCustomObject]@{ File=$_.Name; Status=$sig.Status }
  }
}
```

### C:\Windows\SysWOW64\ — 32-bit Components on 64-bit Windows

Contains 32-bit system DLLs. When a 32-bit process accesses `C:\Windows\System32\`, the WOW64 subsystem transparently redirects it to `SysWOW64\`.

**Security implication:** A 32-bit malware that claims to access `System32\cmd.exe` is actually accessing `SysWOW64\cmd.exe`. Security tools that do not account for WOW64 redirection log the wrong path.

### C:\Windows\Temp\ — System Temporary Files

Used by installers, updates, and system services. Attacker staging area — system processes legitimately write here.

```powershell
# Find executables in Windows\Temp
Get-ChildItem C:\Windows\Temp -Recurse -Include *.exe,*.dll,*.ps1,*.bat -ErrorAction SilentlyContinue |
  Sort-Object CreationTime -Descending |
  Select-Object FullName, CreationTime, Length
```

### C:\Windows\Prefetch\ — Application Execution Cache

Prefetch files (.pf) record evidence of program execution — what ran, when, how many times, what files it accessed in the first 10 seconds.

```powershell
# List prefetch files sorted by last run
Get-ChildItem C:\Windows\Prefetch -Filter *.pf |
  Sort-Object LastWriteTime -Descending |
  Select-Object Name, LastWriteTime |
  Format-Table -AutoSize

# Parse with PECmd (Eric Zimmerman)
# PECmd.exe -d C:\Windows\Prefetch --csv C:\output\
```

**DFIR value:** Even if a binary is deleted, its prefetch file may remain — proving it executed, when it last ran, and what files it accessed.

### C:\Windows\System32\winevt\Logs\ — Event Logs

All Windows Event Log files in EVTX format.

```
Security.evtx                                          Auth, privilege, object access
System.evtx                                            Hardware, drivers, services
Application.evtx                                       Application events
Microsoft-Windows-Sysmon%4Operational.evtx             Sysmon telemetry
Microsoft-Windows-PowerShell%4Operational.evtx         PowerShell script blocks
Microsoft-Windows-WMI-Activity%4Operational.evtx       WMI execution
Microsoft-Windows-TaskScheduler%4Operational.evtx      Task events
Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx  RDP
```

### C:\Windows\System32\config\ — Registry Hives

Physical registry hive files — locked while Windows runs.

```
SAM         local user accounts and NTLM hashes
SECURITY    LSA secrets, cached credentials, security policy
SYSTEM      services, boot config, hardware
SOFTWARE    installed applications, run keys
```

### C:\Windows\System32\drivers\etc\ — Static Network Config

```
hosts       static DNS override — attacker target for C2 redirection
services    port/service name mapping
protocol    protocol numbers
```

```powershell
# Check hosts file for malicious entries
Get-Content C:\Windows\System32\drivers\etc\hosts |
  Where-Object { $_ -notmatch '^#' -and $_ -notmatch 'localhost' -and $_ -match '\S' }

# Check modification time
(Get-Item C:\Windows\System32\drivers\etc\hosts).LastWriteTime
```

---

## C:\Program Files\ and C:\Program Files (x86)\ — Installed Applications

Standard locations for 64-bit and 32-bit installed software. Require admin privileges to write.

**DLL search order hijacking:** Applications in Program Files frequently load DLLs by name without full path. If an attacker can write a malicious DLL to the application directory or a directory earlier in the search order, it loads first.

```powershell
# Find application directories writable by non-admins
Get-ChildItem "C:\Program Files" -Directory | ForEach-Object {
  $acl = Get-Acl $_.FullName
  $acl.Access | Where-Object {
    $_.FileSystemRights -match 'Write|FullControl' -and
    $_.IdentityReference -notmatch 'Administrators|SYSTEM|TrustedInstaller'
  } | ForEach-Object {
    "$($_.IdentityReference) can write to $($_.Path)"
  }
}
```

---

## C:\ProgramData\ — All-User Application Data (Hidden)

Hidden by default. Writable by standard users. Application config, databases, security tool state.

**Attacker use:** Persistence mechanisms frequently target ProgramData — writable without admin, persistent across reboots, hidden from casual inspection.

```powershell
# Find executables in ProgramData
Get-ChildItem C:\ProgramData -Recurse -Include *.exe,*.dll,*.ps1 -Force -ErrorAction SilentlyContinue |
  Where-Object { $_.CreationTime -gt (Get-Date).AddDays(-7) } |
  Select-Object FullName, CreationTime
```

---

## C:\Users\ — User Profiles

```
C:\Users\<username>\
├── Desktop\
├── Documents\
├── Downloads\
├── AppData\                              (hidden)
│   ├── Roaming\                          synced across domain machines
│   │   ├── Microsoft\Windows\Start Menu\Programs\Startup\  ← persistence
│   │   └── Microsoft\Windows\Recent\                       ← LNK files
│   ├── Local\
│   │   ├── Temp\                         ← attacker staging
│   │   └── Microsoft\Windows\PowerShell\ ← PSReadLine history
│   └── LocalLow\                         sandboxed app data
├── NTUSER.DAT                            user registry hive
└── ntuser.dat.LOG                        transaction log
```

### Startup Folder — Persistence

```
C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\
```

Anything here executes automatically at user logon.

```powershell
# Check all user startup folders
Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*" -Force -ErrorAction SilentlyContinue
Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\*" -Force -ErrorAction SilentlyContinue
```

### PSReadLine History — PowerShell Command History

```
C:\Users\<user>\AppData\Local\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

Records every PowerShell command typed interactively. Separate from script block logging.

```powershell
# Read PowerShell history for all users
Get-ChildItem "C:\Users\*\AppData\Local\Microsoft\Windows\PowerShell\PSReadLine\*.txt" -Force |
  ForEach-Object { Write-Host "=== $($_.DirectoryName) ==="; Get-Content $_ }
```

### LNK Files — File Access Evidence

Automatically created when a user opens a file. Contain original path, timestamps, and volume serial number — survive after the original file is deleted.

```powershell
# List recent LNK files
Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\*.lnk" |
  Sort-Object LastWriteTime -Descending |
  Select-Object Name, LastWriteTime
# Parse with LECmd (Eric Zimmerman) for full details
```

---

## C:\System Volume Information\ — VSS Shadow Copies

Volume Shadow Copy data. SYSTEM access only. Contains point-in-time snapshots.

**DFIR use:** Earlier versions of encrypted or deleted files. Ransomware deletes shadow copies first.

```powershell
# List shadow copies
vssadmin list shadows
Get-WmiObject Win32_ShadowCopy | Select-Object ID, InstallDate, VolumeName

# Detect shadow copy deletion (ransomware indicator)
Get-WinEvent -FilterHashtable @{LogName='System'} |
  Where-Object { $_.Message -match 'shadow' -and $_.Message -match 'delet' }
```

---

## C:\$Recycle.Bin\ — Deleted Files

Per-SID subdirectories. `$I` files contain metadata: original path, deletion time, size. `$R` files contain actual content.

```powershell
# List recycle bin with original paths
Get-ChildItem 'C:\$Recycle.Bin' -Force -Recurse |
  Where-Object { $_.Name -like '$I*' } | ForEach-Object {
    $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
    $deletionTime = [DateTime]::FromFileTime([BitConverter]::ToInt64($bytes, 16))
    $originalPath = [System.Text.Encoding]::Unicode.GetString($bytes, 28, $bytes.Length-28).TrimEnd([char]0)
    [PSCustomObject]@{ Deleted=$deletionTime; OriginalPath=$originalPath }
  } | Sort-Object Deleted -Descending
```

---

## NTFS Alternate Data Streams (ADS)

Hidden data attached to any NTFS file. The primary stream is visible; named streams are hidden from standard dir listing.

```powershell
# Find files with ADS (beyond Zone.Identifier)
Get-ChildItem C:\ -Recurse -Force -ErrorAction SilentlyContinue |
  ForEach-Object { Get-Item $_.FullName -Stream * -ErrorAction SilentlyContinue } |
  Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' } |
  Select-Object FileName, Stream, Length

# Read ADS content
Get-Content "file.txt:hidden_stream"

# Zone.Identifier — download source evidence
Get-Content "suspicious.exe:Zone.Identifier"
# ZoneId=3 = downloaded from internet
```

---

## Windows Forensic Artifact Quick Reference

| Artifact | Path | Forensic Value |
|----------|------|----------------|
| Prefetch | `C:\Windows\Prefetch\` | Execution history, file access |
| Amcache | `C:\Windows\AppCompat\Programs\Amcache.hve` | SHA1 hash of executed binaries |
| Shimcache | SYSTEM hive — AppCompatCache | Execution path and timestamp |
| SRUM | `C:\Windows\System32\sru\SRUDB.dat` | 30-60 day app network/CPU usage |
| LNK files | `%AppData%\...\Recent\` | File access — proves user awareness |
| Jump Lists | `%AppData%\...\AutomaticDestinations\` | Recent files per application |
| Shellbags | NTUSER.DAT + UsrClass.dat | Folder navigation history |
| MFT | `C:\$MFT` | Every file, deleted records |
| USN Journal | `C:\$Extend\$UsnJrnl` | File system change log |
| Event Logs | `C:\Windows\System32\winevt\Logs\` | Auth, execution, service events |
| WMI Repository | `C:\Windows\System32\wbem\Repository\` | Persistent WMI subscriptions |
| $Recycle.Bin | `C:\$Recycle.Bin\<SID>\` | Deleted files with original path |
| VSS | `C:\System Volume Information\` | Point-in-time snapshots |
| PSReadLine | `%AppData%\Local\...\PSReadLine\` | Interactive PS command history |
| Pagefile | `C:\pagefile.sys` | Virtual memory — process fragments |
| Hiberfil | `C:\hiberfil.sys` | Hibernation — RAM snapshot |

---

## MITRE ATT&CK Mapping

| Technique | ID | Location |
|-----------|-----|---------|
| Data from Local System | T1005 | Users\, ProgramData\ |
| File and Directory Discovery | T1083 | All |
| Unsecured Credentials | T1552 | Users\, System32\config\ |
| Masquerading | T1036 | Windows\, Temp\ |
| Hide Artifacts: ADS | T1564.004 | Any NTFS file |
| Modify Hosts File | T1565.001 | System32\drivers\etc\hosts |
| Startup Folder Persistence | T1547.001 | AppData\Roaming\...\Startup\ |
| Inhibit System Recovery | T1490 | System Volume Information\ |

---

## Practitioner Notes

**On WOW64 redirection in investigations:** When analysing 32-bit process behaviour, remember that System32 references are redirected to SysWOW64. A 32-bit malware accessing System32\cmd.exe is actually loading SysWOW64\cmd.exe. Tools that read process memory directly (Sysmon, ETW) see the real path — tools that read the PEB command line may not.

**On Zone.Identifier as download evidence:** The Zone.Identifier ADS is automatically added to files downloaded from the internet (ZoneId=3) or email (ZoneId=2). Malware that removes its Zone.Identifier before execution (using `Unblock-File` or direct ADS deletion) is performing anti-forensics. Detection: Sysmon Event ID 15 (FileCreateStreamHash) records ADS creation and content hash.

**On Amcache vs Shimcache:** Amcache stores the SHA1 hash of executed binaries — this hash survives even if the binary is renamed or moved. Shimcache stores file path and last modified time but no hash. Use Amcache for malware identification (hash lookup against threat intel), use Shimcache for timeline reconstruction and path evidence.

---

## Knowledge Validation

**A binary named svchost.exe is running from C:\Users\Public\svchost.exe. How do you confirm this is malicious?**
The legitimate svchost.exe always runs from `C:\Windows\System32\svchost.exe` with `services.exe` as parent and always includes `-k <group>` in its arguments. Check: (1) the full path — C:\Users\Public is not System32; (2) the parent process — should be services.exe not explorer or cmd; (3) the command line — legitimate svchost always has `-k`; (4) the file signature — legitimate svchost is Microsoft-signed; (5) Prefetch — compare against known-good execution patterns.

**What does a Zone.Identifier ADS with ZoneId=3 tell you forensically?**
The file was downloaded from the internet (Zone 3 = Internet Zone). Windows automatically attaches this ADS when files are saved from browsers, email clients, or download managers. It can also contain the source URL and referrer. It proves the file originated from an external source rather than being created locally or copied from internal systems — relevant for establishing initial access vector in an IR.

**Why is the Recycle Bin forensically valuable even when an attacker empties it?**
Emptying the Recycle Bin removes the $I metadata files and marks the $R content files for overwriting — but the data blocks are not immediately zeroed. Until overwritten, the content is recoverable via filesystem forensics (deleted inode analysis, MFT record examination). The $I file's deletion timestamp and original path may also persist in the USN Journal ($UsnJrnl) even after the file is gone from the Recycle Bin directory.

---

*Windows/01-Filesystem-Hierarchy | OS-Internals-for-SOC | Solomon James (@Jaysolex)*
