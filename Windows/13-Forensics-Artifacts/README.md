# Windows/13 — Forensics Artifacts

> Windows leaves more forensic artifacts than any other OS. The MFT, prefetch files, shellbags, SRUM, Amcache, LNK files, jump lists — each one records a different dimension of user and system activity. Understanding what each artifact proves, how long it persists, and what attackers do to destroy it is what separates a competent DFIR analyst from one who misses half the evidence.

![MITRE](https://img.shields.io/badge/MITRE-T1070%20|%20T1564%20|%20T1003-red)
![Platform](https://img.shields.io/badge/Platform-Windows-blue)

---

## Artifact Survival Matrix

| Artifact | Survives Reboot | Survives Log Clear | Survives Binary Delete | Requires Admin to Read |
|----------|----------------|-------------------|----------------------|----------------------|
| MFT | ✅ | ✅ | ✅ (record remains) | No |
| USN Journal | ✅ | ✅ | ✅ | No |
| Prefetch | ✅ | ✅ | ✅ (pf file) | No |
| Amcache | ✅ | ✅ | ✅ (hash stored) | No |
| Shimcache | ✅ | ✅ | ✅ | Yes (SYSTEM hive) |
| SRUM | ✅ (30-60 days) | ✅ | ✅ | Yes |
| Event Logs | ✅ | ❌ (unless WEF) | ✅ | No |
| LNK files | ✅ | ✅ | ✅ (original gone, LNK remains) | No |
| Shellbags | ✅ | ✅ | ✅ | No (NTUSER.DAT) |
| Pagefile | ✅ (until reboot) | ✅ | ✅ | Yes |
| Hiberfil | ✅ | ✅ | ✅ | Yes |
| $Recycle.Bin | ✅ (until emptied) | ✅ | Partial | No |

---

## NTFS Artifacts

### MFT — Master File Table

Every file and directory on an NTFS volume has a record in the MFT. The MFT is itself a file: `$MFT` in the root of the volume.

Each MFT record contains:
- File name and path
- File size
- MACB timestamps (Modified, Accessed, Changed, Born)
- Data attribute (file content or pointer to data runs)
- Security descriptor
- Parent directory reference

**Critical forensic property:** When a file is deleted, its MFT record is marked as available — but the record is not immediately overwritten. Deleted file records persist in the MFT until that record slot is reused, which may be weeks or months later.

```powershell
# Parse MFT with MFTECmd (Eric Zimmerman)
# MFTECmd.exe -f C:\$MFT --csv C:\output\ --csvf mft.csv

# Access $MFT (requires volume shadow copy or raw disk access)
# Cannot be opened normally while Windows is running

# Alternative: extract via VSS
$shadow = Get-WmiObject Win32_ShadowCopy | Select-Object -First 1
$shadowPath = $shadow.DeviceObject + "\"
Copy-Item "${shadowPath}`$MFT" C:\IR\mft_copy
```

### USN Journal — $UsnJrnl

The Update Sequence Number (USN) Change Journal records every file system change — creates, renames, deletes, attribute modifications. Rolling buffer, configurable size.

```
C:\$Extend\$UsnJrnl
```

```powershell
# Parse USN journal with MFTECmd
# MFTECmd.exe -f C:\$Extend\$UsnJrnl --csv C:\output\

# Check USN journal status
fsutil usn queryjournal C:

# View recent entries (live system)
fsutil usn readjournal C: csv > C:\IR\usn.csv
```

**Forensic value:** The USN journal records file operations that may not appear in event logs. A file that was created, used, and deleted may leave no other trace — but the USN journal records each operation with a timestamp.

### NTFS Timestamps — MACB

Each file has timestamps in two attributes:
- `$STANDARD_INFORMATION` — visible in Windows Explorer, modified by normal file operations and timestomping tools
- `$FILE_NAME` — updated by the NTFS driver on move/rename, harder to modify via userspace tools

```
M — Modified (last content write)
A — Accessed (last read)
C — Changed (metadata change — chmod, rename)
B — Born (file creation time)
```

**Timestomping detection:** Timestomping tools modify `$STANDARD_INFORMATION` timestamps. `$FILE_NAME` timestamps are less accessible and often not modified. If `$STANDARD_INFORMATION` timestamps predate `$FILE_NAME` timestamps, the file was likely timestomped.

```powershell
# Parse timestamps from both attributes
# Use MFTECmd or Autopsy for $FILE_NAME access
# Comparing $STANDARD_INFORMATION vs $FILE_NAME is the timestomp detection
```

---

## Execution Artifacts

### Prefetch

Windows prefetch files (.pf) record evidence of program execution.

```
Location: C:\Windows\Prefetch\
Format:   PROGRAMNAME-HASH.pf
```

Each prefetch file contains:
- Executable name
- Run count (how many times executed)
- Last run timestamp (up to 8 timestamps on Windows 8+)
- Files and directories accessed during first 10 seconds of execution

```powershell
# Quick prefetch listing
Get-ChildItem C:\Windows\Prefetch -Filter *.pf |
    Sort-Object LastWriteTime -Descending |
    Select-Object Name, LastWriteTime | Format-Table

# Full parse with PECmd (Eric Zimmerman)
# PECmd.exe -d C:\Windows\Prefetch --csv C:\output\ --csvf prefetch.csv

# Prefetch for a specific executable
Get-ChildItem C:\Windows\Prefetch -Filter "MIMIKATZ*" -ErrorAction SilentlyContinue
Get-ChildItem C:\Windows\Prefetch -Filter "PSEXEC*" -ErrorAction SilentlyContinue
Get-ChildItem C:\Windows\Prefetch -Filter "POWERSHELL*" | Sort-Object LastWriteTime -Descending
```

**DFIR value:** Even if the binary is deleted, the prefetch file proves it executed — with timestamps of up to the last 8 runs and what files it accessed.

**Note:** Prefetch is disabled on Windows Server by default. Enable: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters` → `EnablePrefetcher = 3`

### Amcache

Stores information about executed applications including SHA1 hash.

```
Location: C:\Windows\AppCompat\Programs\Amcache.hve
Format:   Registry hive
```

Contains:
- Full path of executed binary
- SHA1 hash (survives binary deletion and renaming)
- File size, compile time, publisher
- First execution timestamp

```powershell
# Parse Amcache with AmcacheParser (Eric Zimmerman)
# AmcacheParser.exe -f C:\Windows\AppCompat\Programs\Amcache.hve --csv C:\output\

# Cannot be read live — use VSS or offline
$shadow = Get-WmiObject Win32_ShadowCopy | Select-Object -First 1
$shadowPath = $shadow.DeviceObject + "\"
Copy-Item "${shadowPath}Windows\AppCompat\Programs\Amcache.hve" C:\IR\
```

**DFIR value:** The SHA1 hash persists even if the binary is renamed, moved, or deleted. Hash can be cross-referenced against threat intelligence and VirusTotal.

### Shimcache (AppCompatCache)

Records application execution for compatibility purposes. Stored in the SYSTEM registry hive.

```
Registry: HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
```

Contains:
- File path
- File size
- Last modified timestamp of the binary
- Execution flag (indicates whether the binary was actually executed — varies by Windows version)

```powershell
# Parse with AppCompatCacheParser (Eric Zimmerman)
# AppCompatCacheParser.exe -f C:\Windows\System32\config\SYSTEM --csv C:\output\

# Or access live (requires admin)
$reg = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', 'Default')
$key = $reg.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache')
```

### SRUM — System Resource Usage Monitor

Tracks application resource usage over 30-60 days. Includes network usage, CPU time, and memory per application.

```
Location: C:\Windows\System32\sru\SRUDB.dat
Format:   ESE database
```

Tables of interest:
- `{973F5D5C-1D90-11D3-8...}` — Application Resource Usage (CPU, memory per app)
- `{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}` — Network Data Usage (bytes sent/received per app)
- `{DD6636C4-8929-4683-974E-22C046A43763}` — Network Connectivity Usage

```powershell
# Parse with SrumECmd (Eric Zimmerman)
# SrumECmd.exe -f C:\Windows\System32\sru\SRUDB.dat --csv C:\output\

# Cannot be read live — copy offline
Copy-Item C:\Windows\System32\sru\SRUDB.dat C:\IR\ -ErrorAction SilentlyContinue
```

**DFIR value:** SRUM proves an application ran and used network resources — even if no other execution evidence remains. Particularly valuable for proving C2 communication (bytes sent/received from a process at specific times).

---

## User Activity Artifacts

### LNK Files — Shell Link Files

Automatically created by Windows Shell when a user opens a file via Explorer.

```
Location: C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\
Format:   Binary .lnk file
```

Each LNK file contains:
- Original file path (including network paths)
- File timestamps at time of access (Created, Modified, Accessed)
- Volume serial number of the source drive
- MAC address if the source was a network share
- Target file size

```powershell
# List recent LNK files
Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\*.lnk" |
    Sort-Object LastWriteTime -Descending |
    Select-Object Name, LastWriteTime

# Parse with LECmd (Eric Zimmerman)
# LECmd.exe -d "C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent" --csv C:\output\
```

**DFIR value:** LNK files prove a user interacted with a specific file at a specific time — even if the file has since been deleted, the drive unmounted, or the file moved. The MAC address in network LNK files can identify attacker infrastructure.

### Jump Lists

Per-application recent file lists stored by the Windows shell.

```
Location: C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\
          C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\
Format:   AppID.automaticDestinations-ms
```

```powershell
# List jump list files
Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\" |
    Sort-Object LastWriteTime -Descending | Select-Object Name, LastWriteTime

# Parse with JLECmd (Eric Zimmerman)
# JLECmd.exe -d "C:\Users\<user>\AppData\...\AutomaticDestinations" --csv C:\output\
```

### Shellbags

Registry-based artifact recording folder navigation history — every folder a user browsed in Windows Explorer.

```
Registry:
  NTUSER.DAT:  HKCU\Software\Microsoft\Windows\Shell\BagMRU
                HKCU\Software\Microsoft\Windows\Shell\Bags
  UsrClass.dat: HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\
```

```powershell
# Parse with ShellBagsExplorer or SBECmd (Eric Zimmerman)
# SBECmd.exe -d C:\Users\<user>\ --csv C:\output\
```

**DFIR value:** Shellbags record that a user navigated to a folder — even if the folder and its contents have been deleted. Proves user awareness of files/folders on removable media, network shares, or deleted directories.

### UserAssist

Records GUI application launches per user. Values are ROT13 encoded.

```
Registry: HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count
```

```powershell
# Read UserAssist (values are ROT13 encoded)
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count" |
    Get-Member -MemberType NoteProperty | ForEach-Object {
        $name = $_.Name
        $decoded = -join ($name.ToCharArray() | ForEach-Object {
            if ([char]::IsLetter($_)) {
                [char](([byte][char]$_ - [byte][char]'A' + 13) % 26 + [byte][char]'A')
            } else { $_ }
        })
        Write-Host "$decoded"
    }
```

### TypedPaths and TypedURLs

Records paths typed directly into the Explorer address bar and IE/Edge URL bar.

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
HKCU\Software\Microsoft\Internet Explorer\TypedURLs
```

```powershell
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" |
    Select-Object * -ExcludeProperty PS*

Get-ItemProperty "HKCU:\Software\Microsoft\Internet Explorer\TypedURLs" |
    Select-Object * -ExcludeProperty PS*
```

---

## PSReadLine — PowerShell Command History

Every PowerShell command typed interactively is logged here regardless of PowerShell logging policy.

```
C:\Users\<user>\AppData\Local\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

```powershell
# Read for all users
Get-ChildItem "C:\Users\*\AppData\Local\Microsoft\Windows\PowerShell\PSReadLine\*.txt" -Force |
    ForEach-Object {
        Write-Host "=== $($_.DirectoryName) ===" -ForegroundColor Cyan
        Get-Content $_
    }
```

---

## Memory Artifacts

### Pagefile.sys

Virtual memory — physical RAM pages swapped to disk.

```
C:\pagefile.sys   (locked while Windows runs)
```

May contain fragments of: credentials from LSASS, decrypted content, C2 communication strings, process memory from terminated processes.

```powershell
# Check pagefile configuration
Get-WmiObject Win32_PageFileSetting
(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management").PagingFiles
```

Acquire via VSS or offline disk imaging.

### Hiberfil.sys

Full RAM snapshot at hibernate. Voltility processes it directly.

```
C:\hiberfil.sys
```

```powershell
# Check if hibernation is enabled
powercfg /query SCHEME_CURRENT | Select-String "hibernate"
powercfg /availablesleepstates
```

---

## $Recycle.Bin

```
C:\$Recycle.Bin\<SID>\$I<hash>   metadata file
C:\$Recycle.Bin\<SID>\$R<hash>   content file
```

$I metadata contains: original path, deletion timestamp, original size.

```powershell
# Parse Recycle Bin with RBCmd (Eric Zimmerman)
# RBCmd.exe -d C:\$Recycle.Bin --csv C:\output\

# Quick PowerShell parse
Get-ChildItem 'C:\$Recycle.Bin' -Force -Recurse |
    Where-Object { $_.Name -like '$I*' } | ForEach-Object {
        $bytes = [IO.File]::ReadAllBytes($_.FullName)
        $time = [DateTime]::FromFileTime([BitConverter]::ToInt64($bytes, 16))
        $path = [Text.Encoding]::Unicode.GetString($bytes, 28, $bytes.Length - 28).TrimEnd([char]0)
        [PSCustomObject]@{ Deleted=$time; OriginalPath=$path }
    } | Sort-Object Deleted -Descending
```

---

## Eric Zimmerman Tools Reference

| Tool | Artifact | Output |
|------|----------|--------|
| MFTECmd | $MFT, $UsnJrnl | CSV |
| PECmd | Prefetch | CSV |
| AmcacheParser | Amcache.hve | CSV |
| AppCompatCacheParser | Shimcache (SYSTEM hive) | CSV |
| SrumECmd | SRUDB.dat | CSV |
| LECmd | LNK files | CSV |
| JLECmd | Jump Lists | CSV |
| SBECmd | Shellbags | CSV |
| RBCmd | $Recycle.Bin | CSV |
| RECmd | Registry hives | CSV |
| EvtxECmd | EVTX event logs | CSV/JSON |

All tools output to CSV for SIEM ingestion or timeline analysis with Timeline Explorer.

---

## KAPE — Triage Collection

KAPE (Kroll Artifact Parser and Extractor) automates artifact collection and parsing.

```powershell
# Collect all forensic artifacts to USB
# kape.exe --tsource C: --tdest E:\KAPE_Output --target !SANS_Triage

# Parse collected artifacts
# kape.exe --msource E:\KAPE_Output --mdest E:\Parsed --module !EZParser
```

---

## Full Artifact Collection Script

```powershell
$IR = "C:\IR_$(hostname)_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $IR -Force

# Volatile — collect first
netstat -anob > "$IR\connections.txt"
Get-Process > "$IR\processes.txt"
arp -a > "$IR\arp.txt"
ipconfig /displaydns > "$IR\dns_cache.txt"
Get-ScheduledTask > "$IR\scheduled_tasks.txt"

# Registry persistence
$keys = @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
          "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run")
foreach ($k in $keys) {
    Get-ItemProperty $k -ErrorAction SilentlyContinue >> "$IR\autoruns.txt"
}

# WMI subscriptions
Get-WMIObject -Namespace root\subscription -Class __EventFilter >> "$IR\wmi_filters.txt"
Get-WMIObject -Namespace root\subscription -Class __EventConsumer >> "$IR\wmi_consumers.txt"

# Recent execution
Get-ChildItem C:\Windows\Prefetch -Filter *.pf |
    Sort-Object LastWriteTime -Descending |
    Select-Object Name, LastWriteTime > "$IR\prefetch.txt"

# User artifacts
Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\*.lnk" |
    Sort-Object LastWriteTime -Descending |
    Select-Object FullName, LastWriteTime > "$IR\lnk_files.txt"

Get-ChildItem "C:\Users\*\AppData\Local\Microsoft\Windows\PowerShell\PSReadLine\*.txt" -Force |
    ForEach-Object { Get-Content $_ >> "$IR\ps_history.txt" }

# Event logs (copy EVTX files)
$evtxDest = "$IR\EventLogs"
New-Item -ItemType Directory -Path $evtxDest -Force
Copy-Item "C:\Windows\System32\winevt\Logs\Security.evtx" $evtxDest
Copy-Item "C:\Windows\System32\winevt\Logs\System.evtx" $evtxDest
Copy-Item "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx" $evtxDest -ErrorAction SilentlyContinue

Write-Host "[+] Collection complete: $IR"
```

---

## MITRE ATT&CK Mapping

| Technique | ID |
|-----------|-----|
| Indicator Removal: Clear Windows Event Logs | T1070.001 |
| Indicator Removal: Timestomp | T1070.006 |
| Indicator Removal: File Deletion | T1070.004 |
| Hide Artifacts: Alternate Data Streams | T1564.004 |
| Hide Artifacts: NTFS File Attributes | T1564.002 |

---

## Practitioner Notes

**On artifact acquisition order:** Volatile artifacts first — DNS cache, network connections, running processes, clipboard. These disappear on reboot or process exit. Then non-volatile but time-sensitive artifacts — event logs (may be cleared), prefetch (may be overwritten). Then disk artifacts that persist — MFT, Amcache, Shellbags. Always document collection timestamps — artifact timestamps without collection metadata are less defensible in legal proceedings.

**On Amcache as malware identification:** Amcache stores SHA1 hashes of executed binaries. When an attacker deletes their tools after execution, the hash remains in Amcache. Submitting these hashes to VirusTotal or cross-referencing against threat intelligence frequently identifies the specific malware family — even when the binary is gone. This is one of the highest-value artifacts for attribution and scope assessment.

**On SRUM for C2 detection:** SRUM tracks network bytes sent and received per application over 30-60 days. If you identify a suspicious process but lack network logs, SRUM can prove it communicated externally and quantify the data volume — supporting exfiltration assessment. The timestamps in SRUM correlate with other artifacts to build timeline confidence.

---

## Knowledge Validation

**A binary was executed, then deleted. Name four artifact sources that can still prove the execution and what each one preserves.**
Prefetch (C:\Windows\Prefetch\BINARY-HASH.pf) — execution timestamp, run count, files accessed. Amcache (Amcache.hve) — SHA1 hash, file path, first execution time. Shimcache (SYSTEM hive AppCompatCache) — file path, last modified timestamp of the binary. SRUM (SRUDB.dat) — network bytes sent/received by the process with timestamps. Event logs (Security 4688 or Sysmon 1) — command line, parent process, user — if logging was enabled.

**What does a $FILE_NAME timestamp older than its $STANDARD_INFORMATION timestamp indicate?**
Under normal circumstances $FILE_NAME timestamps are updated when a file is moved or renamed, which is less frequent than content modifications. If $STANDARD_INFORMATION shows an earlier date than $FILE_NAME, the $STANDARD_INFORMATION timestamps were modified backward using a timestomping tool (touch, timestomp). The $FILE_NAME attribute is less accessible from userspace and often retains the true creation/modification time. This discrepancy is forensic evidence of anti-forensics.

**During IR you find shellbag entries for a folder path on a removable drive that is no longer present. What does this prove?**
Shellbags record folder navigation via Windows Explorer regardless of whether the navigated location is currently accessible. The presence of shellbag entries for a removable drive path proves: (1) a user navigated to that specific folder on that drive while it was connected, (2) the drive with that volume serial number was connected to this system, and (3) the user was aware of the folder's contents. This is evidence of data access even when the drive itself has been removed and the files are gone.

---

*Windows/13-Forensics-Artifacts | OS-Internals-for-SOC | Solomon James (@Jaysolex)*
