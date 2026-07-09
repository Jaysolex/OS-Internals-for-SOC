# Windows/03 — Process Internals

> Every attack on Windows eventually becomes a process. Understanding how the Windows process model works at the kernel level — how processes are created, what structures describe them, how memory is laid out — is what separates a detection engineer who writes rules from one who understands what they are detecting.

![MITRE](https://img.shields.io/badge/MITRE-T1055%20|%20T1036%20|%20T1134%20|%20T1106-red)
![Platform](https://img.shields.io/badge/Platform-Windows-blue)

---

## Windows Process Architecture

A Windows process is a container — it holds virtual address space, handles, threads, and loaded modules. It does not execute code directly. Threads execute code within a process context.

```
Process (EPROCESS kernel object)
    |
    +-- Virtual Address Space (0x00000000 - 0x7FFFFFFF user, kernel above)
    |
    +-- Handle Table (open files, registry keys, mutexes, other processes)
    |
    +-- PEB (Process Environment Block) -- userspace process metadata
    |       |
    |       +-- ImageBaseAddress    (where the EXE loaded)
    |       +-- Ldr (loader data)   (loaded DLLs list)
    |       +-- ProcessParameters   (command line, environment)
    |       +-- HeapList            (process heaps)
    |
    +-- Threads (at least one -- the main thread)
    |       |
    |       +-- TEB (Thread Environment Block)
    |               +-- Stack
    |               +-- Thread-local storage
    |
    +-- Loaded Modules (EXE + DLLs mapped into address space)
```

---

## Key Data Structures

### EPROCESS (Kernel)

The kernel-mode object representing a process. Lives in kernel address space. Security tools and EDRs access this directly.

Critical fields:
```
UniqueProcessId       PID
InheritedFromUniqueProcessId    Parent PID (PPID)
ImageFileName         Process name (15 chars, truncated)
ActiveProcessLinks    Doubly-linked list of all processes
Token                 Security token (privileges)
VadRoot               Virtual Address Descriptor tree
ObjectTable           Handle table
```

Rootkits manipulate `ActiveProcessLinks` to hide processes from tools that walk this list — but the process still exists in memory and can be found by scanning for EPROCESS structures directly.

### PEB (Process Environment Block)

Userspace structure at a fixed offset from the process base. Readable without kernel access.

```
fs:[0x30] (32-bit) or gs:[0x60] (64-bit) -> PEB address

PEB fields of security interest:
  +0x000 InheritedAddressSpace
  +0x002 BeingDebugged           <- anti-debug check target
  +0x00c Ldr                     <- pointer to PEB_LDR_DATA (loaded modules)
  +0x010 ProcessParameters       <- command line, image path, environment
  +0x018 SubSystemData
  +0x068 NtGlobalFlag            <- heap flags, debug detection
```

Attackers check `BeingDebugged` and `NtGlobalFlag` for sandbox/debugger detection. Process hollowing manipulates `ImageBaseAddress` and the Ldr list to hide the real payload.

### VAD Tree (Virtual Address Descriptors)

The kernel maintains a balanced binary tree (VAD) describing every memory region in a process — what is mapped, permissions, backing file. Volatility's `vaddump` and `vadinfo` plugins enumerate this.

Security significance: Shellcode injected into a process typically appears as a `VAD_SHORT` node with `EXECUTE_READWRITE` permissions and no backing file — a strong anomaly indicator.

---

## Process Creation Flow

```
CreateProcess() called
        |
        v
kernel32.dll -> NtCreateProcess() syscall
        |
        v
NT kernel creates EPROCESS object
        |
        v
Initial thread created (NtCreateThread)
        |
        v
NTDLL.dll loaded (first DLL, always)
        |
        v
LdrInitializeThunk() called
        |
        v
Import Address Table (IAT) resolved
        |
        v
DLL_PROCESS_ATTACH notifications sent
        |
        v
Entry point (WinMain/main) executed
```

### Parent-Child Relationships

Every process has a Parent PID (PPID). Legitimate software has predictable parent-child relationships. Deviations are high-confidence indicators.

Expected relationships:
```
explorer.exe         -> chrome.exe, notepad.exe, cmd.exe (user launches)
services.exe         -> svchost.exe (service hosting)
winlogon.exe         -> userinit.exe -> explorer.exe (logon flow)
cmd.exe              -> child processes (scripts, tools)
```

Suspicious relationships:
```
word.exe             -> cmd.exe, powershell.exe (macro execution)
excel.exe            -> wscript.exe, mshta.exe
svchost.exe          -> cmd.exe, powershell.exe
explorer.exe         -> regsvr32.exe with URL argument
```

---

## Process Injection Techniques

### DLL Injection (T1055.001)

Classic technique. Force a target process to load a malicious DLL.

```
1. OpenProcess(PROCESS_ALL_ACCESS, target_pid)
2. VirtualAllocEx() -- allocate memory in target
3. WriteProcessMemory() -- write DLL path into target
4. CreateRemoteThread(LoadLibraryA, dll_path_addr)
   -> target process loads the DLL
```

Detection: Sysmon Event ID 8 (CreateRemoteThread) + Event ID 7 (ImageLoad) of unsigned DLL.

### Process Hollowing (T1055.012)

Create a legitimate process in suspended state, replace its memory with malicious code, resume execution. The process appears legitimate in task list.

```
1. CreateProcess("svchost.exe", SUSPENDED)
2. NtUnmapViewOfSection() -- hollow out the memory
3. VirtualAllocEx() -- allocate new memory at preferred base
4. WriteProcessMemory() -- write malicious image
5. SetThreadContext() -- redirect entry point
6. ResumeThread() -- execute malicious code as svchost.exe
```

Detection: Sysmon Event ID 25 (ProcessTampering). The PEB ImageBaseAddress does not match the file on disk. Memory region is executable but has no file backing.

### Process Doppelganging (T1055.013)

Uses NTFS transactions to create a transacted file write that is never committed to disk. The malicious image is mapped from a transaction that gets rolled back.

```
1. CreateTransaction()
2. CreateFileTransacted() -- write malicious EXE in transaction
3. CreateProcessWithTransaction() -- map from transacted file
4. RollbackTransaction() -- file never hits disk
```

The process memory contains malicious code but no corresponding file exists on disk. File-based AV cannot scan it.

### Reflective DLL Injection

DLL contains its own loader. Injected as shellcode into target process memory — loads itself without using LoadLibrary. Never touches disk.

### Thread Hijacking (T1055.003)

Suspend an existing thread in target process, modify its context (instruction pointer), inject shellcode, resume thread.

```
1. OpenThread(THREAD_ALL_ACCESS, target_tid)
2. SuspendThread()
3. GetThreadContext() -- save original registers
4. VirtualAllocEx() + WriteProcessMemory() -- inject shellcode
5. SetThreadContext() -- redirect RIP/EIP to shellcode
6. ResumeThread()
```

---

## Token Manipulation (T1134)

Every process has a security token defining its identity and privileges. Token manipulation allows privilege escalation and impersonation.

### Token Impersonation

```powershell
# Duplicate token from SYSTEM process
# Then assign to current thread -> running as SYSTEM

# Incognito (Meterpreter) / TokenKidnapping
getsystem   <- attempts multiple token impersonation techniques
```

### Token Duplication

```c
OpenProcessToken(target_process, TOKEN_DUPLICATE, &token)
DuplicateTokenEx(token, ..., SecurityImpersonation, &dup_token)
ImpersonateLoggedOnUser(dup_token)
// Now running with target's identity
```

Detection: Event ID 4624 Logon Type 9 (NewCredentials) or Event ID 4648 (explicit credential logon).

---

## PPID Spoofing (T1134.004)

The CreateProcess API accepts a parent process handle via PROC_THREAD_ATTRIBUTE_PARENT_PROCESS. An attacker spawns a malicious process claiming a legitimate parent — bypassing parent-child detection rules.

```c
// Spawn cmd.exe claiming explorer.exe (PID 1234) as parent
InitializeProcThreadAttributeList(...)
UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, explorer_handle)
CreateProcess("cmd.exe", ..., lpAttributeList)
// cmd.exe shows explorer.exe as parent in process tree
```

Detection: The reported PPID does not match the actual creating process. Sysmon logs both the reported PPID and can be correlated with the actual creating process via correlation of thread creation events.

---

## Masquerading (T1036)

### Binary Name Masquerading

Place malicious binary with a legitimate name in an unexpected location.

```
C:\Windows\System32\svchost.exe   <- legitimate
C:\Users\Public\svchost.exe       <- malicious (wrong path)
C:\Temp\explorer.exe              <- malicious (wrong path)
```

Detection: Process image path does not match known-good location for that process name.

### Process Argument Spoofing

Modify process arguments after creation to hide true command line. The process creates with malicious arguments, immediately overwrites its own PEB command line field with benign content.

```
Actual execution: powershell.exe -enc <base64 payload>
PEB CommandLine after spoof: powershell.exe -version
```

Detection: ETW (Event Tracing for Windows) captures arguments at creation time before the PEB can be modified. Sysmon reads from ETW, not PEB, making this spoof ineffective against Sysmon.

---

## Detection

### Sysmon Events for Process Activity

| Event ID | Description | Key Fields |
|----------|-------------|------------|
| 1 | Process created | Image, CommandLine, ParentImage, Hashes |
| 5 | Process terminated | Image, PID |
| 8 | CreateRemoteThread | SourceImage, TargetImage, StartAddress |
| 10 | ProcessAccess | SourceImage, TargetImage, GrantedAccess |
| 25 | ProcessTampering | Image, Type (hollowing/herpaderping) |

### Detection Queries

```powershell
# Suspicious parent-child: Office spawning shell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object {
    $xml = [xml]$_.ToXml()
    $parent = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ParentImage'}
    $image  = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'}
    ($parent.'#text' -match 'winword|excel|powerpnt') -and
    ($image.'#text'  -match 'cmd|powershell|wscript|mshta')
  } | Select-Object TimeCreated, Message

# Encoded PowerShell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match '-enc|-encodedcommand' } |
  Select-Object TimeCreated, Message

# Processes running from temp locations
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match '\\Temp\\|\\AppData\\|\\Public\\' } |
  Where-Object { $_.Message -match '\.exe' } |
  Select-Object TimeCreated, Message
```

---

## Investigation Commands

```powershell
# Full process list with parent
Get-WmiObject Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CommandLine |
  Sort-Object ProcessId

# Find process by name with path
Get-Process -Name svchost | Select-Object Id, Path, StartTime

# Check process signature
Get-Process | ForEach-Object {
  if ($_.Path) {
    $sig = Get-AuthenticodeSignature $_.Path
    [PSCustomObject]@{
      Name    = $_.Name
      PID     = $_.Id
      Path    = $_.Path
      Signed  = $sig.Status
      Signer  = $sig.SignerCertificate.Subject
    }
  }
}

# Find unsigned processes
Get-Process | ForEach-Object {
  if ($_.Path) {
    $sig = Get-AuthenticodeSignature $_.Path -ErrorAction SilentlyContinue
    if ($sig.Status -ne 'Valid') { $_ | Select-Object Name, Id, Path }
  }
}

# Processes with no file on disk (hollowing indicator)
Get-Process | ForEach-Object {
  if ($_.Path -and -not (Test-Path $_.Path)) {
    "$($_.Name) PID:$($_.Id) Path:$($_.Path) -- FILE NOT FOUND"
  }
}

# Handles opened to other processes (injection indicator)
Get-Process | ForEach-Object {
  $handles = $_.Handles
  if ($handles -gt 500) {
    "$($_.Name) PID:$($_.Id) Handles:$handles"
  }
}
```

---

## MITRE ATT&CK Mapping

| Technique | ID |
|-----------|-----|
| Process Injection: DLL Injection | T1055.001 |
| Process Injection: Process Hollowing | T1055.012 |
| Process Injection: Thread Hijacking | T1055.003 |
| Process Injection: Process Doppelganging | T1055.013 |
| Access Token Manipulation | T1134 |
| PPID Spoofing | T1134.004 |
| Masquerading | T1036 |
| Native API | T1106 |

---

## Sigma Rule — Suspicious Parent-Child

```yaml
title: Office Application Spawning Shell Process
id: d4e5f6a7-b8c9-0123-defa-234567890123
status: stable
description: >
  Detects Office applications spawning command interpreters
  or scripting hosts — indicator of malicious macro execution.
author: Solomon James (@Jaysolex)
tags:
  - attack.execution
  - attack.t1059
  - attack.initial_access
  - attack.t1566.001
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
      - '\winword.exe'
      - '\excel.exe'
      - '\powerpnt.exe'
      - '\outlook.exe'
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
      - '\regsvr32.exe'
      - '\rundll32.exe'
  condition: selection
falsepositives:
  - Legitimate macro-based automation (whitelist by hash)
level: high
```

---

## Practitioner Notes

**On process hollowing detection:** The strongest indicator is a process whose PEB ImageBaseAddress does not correspond to the file path shown in the process list. Volatility's `malfind` plugin detects VAD regions with execute permissions and no file backing — classic hollowing artifact.

**On PPID spoofing and detection rules:** Many detection rules check parent-child relationships using the reported PPID. PPID spoofing defeats these rules. Counter: correlate Sysmon Event ID 1 (process creation) with the actual creating process using thread and process tracking across multiple events rather than relying solely on reported PPID.

**On ETW and argument spoofing:** ETW captures process arguments at creation time from the kernel — before the process can modify its own PEB. Sysmon reads from ETW. This makes PEB-based argument spoofing ineffective against Sysmon but effective against tools that read the PEB directly.

---

## Knowledge Validation

**What is the difference between the EPROCESS structure and the PEB?**
EPROCESS is a kernel-mode object maintained by the NT kernel — it contains the authoritative process state including security token, handle table, and VAD tree. PEB is a userspace structure mapped into the process address space — it contains loader data, command line, and environment variables. Rootkits manipulate EPROCESS to hide processes; malware manipulates PEB for sandbox evasion and argument spoofing.

**Why does process hollowing survive hash-based detection?**
The legitimate process binary is what spawns — svchost.exe is created from the real svchost.exe on disk. The hash matches. After creation in suspended state, the memory is hollowed and replaced with malicious content. By execution time the on-disk hash is irrelevant — the in-memory content is the payload. Detection requires memory scanning, not file scanning.

**What makes PPID spoofing effective against parent-child detection rules?**
CreateProcess accepts an explicit parent process handle via PROC_THREAD_ATTRIBUTE_PARENT_PROCESS. The kernel records this as the parent in the EPROCESS structure. Detection tools reading the process tree see the spoofed parent. Counter-detection requires correlating the actual creating thread with the new process — the creating thread's process is the real parent regardless of what PPID is reported.

---

*Windows/03-Process-Internals | OS-Internals-for-SOC | Solomon James (@Jaysolex)*
