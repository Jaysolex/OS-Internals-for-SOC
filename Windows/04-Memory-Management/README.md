# Windows/04 — Memory Management

> Windows memory management is where process injection, credential theft, and fileless malware live. The Virtual Address Descriptor tree, page table structure, and memory-mapped file system are not abstract concepts — they are the attack surface. Understanding them is what allows you to find shellcode that has no file on disk, detect injection, and know what artifacts survive after a process exits.

![MITRE](https://img.shields.io/badge/MITRE-T1055%20|%20T1620%20|%20T1003-red)
![Platform](https://img.shields.io/badge/Platform-Windows-blue)

---

## Virtual Memory Architecture

Every Windows process has a private virtual address space. On 64-bit Windows this is 128TB for user space and 128TB for kernel space — far more than any physical RAM.

```
0xFFFFFFFFFFFFFFFF  kernel space (inaccessible from user mode)
0xFFFF080000000000
        .
0x00007FFFFFFFFFFF  top of user space
        |
        +-- Stack (grows downward, ASLR randomized)
        +-- Memory-mapped files and shared libraries
        +-- Heap (grows upward, managed by HeapAlloc)
        +-- PE image (executable loaded at base address)
        +-- NTDLL (always mapped, lowest DLL)
0x0000000000000000  NULL page (reserved, access causes exception)
```

The kernel's Memory Manager translates virtual addresses to physical RAM via page tables. Processes share physical RAM but have isolated virtual views.

---

## Virtual Address Descriptors (VAD)

The NT kernel maintains a balanced binary tree of VAD nodes for each process — one node per contiguous memory region describing its purpose, permissions, and backing.

```
VAD Tree (per process)
    |
    +-- VAD node: 0x400000-0x401000  r-x  backed by notepad.exe
    +-- VAD node: 0x7ff00000-0x7ffff000  r--  backed by ntdll.dll
    +-- VAD node: 0x1000000-0x1001000  rwx  anonymous (SHELLCODE INDICATOR)
    +-- VAD node: 0x2000000-0x3000000  rw-  heap
```

**Security significance:** Shellcode and injected payloads typically appear as VAD nodes with execute permissions and no file backing. Volatility's `vaddump` and `malfind` plugins scan the VAD tree looking for these anomalous executable anonymous regions.

---

## Page Protection Flags

Every memory page has protection flags controlling allowed access:

| Flag | Value | Description |
|------|-------|-------------|
| PAGE_NOACCESS | 0x01 | No access — access violation on touch |
| PAGE_READONLY | 0x02 | Read only |
| PAGE_READWRITE | 0x04 | Read and write |
| PAGE_EXECUTE | 0x10 | Execute only |
| PAGE_EXECUTE_READ | 0x20 | Execute and read |
| PAGE_EXECUTE_READWRITE | 0x40 | Execute, read, write — shellcode staging |
| PAGE_EXECUTE_WRITECOPY | 0x80 | Execute, write-on-copy |

**DEP (Data Execution Prevention):** Hardware-enforced NX bit prevents executing code in non-executable pages. Classic buffer overflow shellcode fails because stack/heap pages are PAGE_READWRITE without execute. Attackers bypass with ROP or by calling VirtualProtect to change page permissions.

---

## Key Memory Management APIs

| API | Purpose | Attack Use |
|-----|---------|-----------|
| `VirtualAlloc` | Allocate virtual memory | Stage shellcode |
| `VirtualProtect` | Change page permissions | Make shellcode executable |
| `VirtualAllocEx` | Allocate in remote process | Process injection staging |
| `WriteProcessMemory` | Write to remote process | Inject shellcode/DLL path |
| `ReadProcessMemory` | Read from remote process | Credential theft, reconnaissance |
| `CreateRemoteThread` | Create thread in remote process | Trigger injected code |
| `NtMapViewOfSection` | Map section into process | Section-based injection |
| `NtUnmapViewOfSection` | Unmap a section | Process hollowing step 2 |

### Injection Sequence (Classic DLL Injection)

```
1. OpenProcess(PROCESS_ALL_ACCESS, target_pid)
2. VirtualAllocEx(target, NULL, path_length, MEM_COMMIT, PAGE_READWRITE)
3. WriteProcessMemory(target, alloc_addr, dll_path, path_length)
4. GetProcAddress(kernel32, "LoadLibraryA")
5. CreateRemoteThread(target, NULL, 0, LoadLibraryA, alloc_addr, 0)
```

Detection: Sysmon Event ID 8 (CreateRemoteThread) + Event ID 7 (ImageLoad) for the injected DLL.

---

## Section Objects and Memory-Mapped Files

Windows uses section objects (file mappings) to share memory between processes and to map files into address space. Every DLL loaded by multiple processes is backed by a single section object — the physical pages are shared.

```
ntdll.dll on disk
    |
    v
Section object (kernel)
    |
    +-- mapped into Process A at 0x7ffb00000000
    +-- mapped into Process B at 0x7ffa00000000
    +-- mapped into Process C at 0x7ff900000000
```

### Section-Based Injection

More sophisticated than CreateRemoteThread — uses shared sections to map executable code into a target process.

```
1. NtCreateSection(SEC_COMMIT | SEC_NO_CHANGE)
2. NtMapViewOfSection(section, current_process, ...)  <- map in our process
3. Write shellcode to the mapped view
4. NtMapViewOfSection(section, target_process, ...)   <- map same section in target
5. NtCreateThreadEx(target_process, shellcode_address) <- execute
```

This technique does not call WriteProcessMemory — evades detections based on that API.

---

## ASLR — Address Space Layout Randomization

Windows randomizes the base addresses of the stack, heap, PEB, and loaded modules at each process launch. This prevents hardcoded address exploits.

```powershell
# Check ASLR status
# Registry: HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management
(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management").MoveImages
# 0 = ASLR disabled, non-zero = enabled

# Check if a specific binary has ASLR (DYNAMICBASE flag in PE header)
dumpbin /headers C:\Windows\System32\notepad.exe | Select-String "DYNAMIC BASE"
```

### ASLR Bypass Techniques

- **Information leak** — read a pointer from a known location to discover actual base addresses
- **Heap spray** — fill large memory regions with NOP sled + shellcode so any jump hits it
- **Return-to-known** — use non-ASLR modules as ROP gadget sources (older applications)

---

## Page File and Virtual Memory

When physical RAM fills, the Memory Manager pages out inactive pages to the page file on disk.

```
C:\pagefile.sys     primary page file
C:\swapfile.sys     used by UWP apps (Windows 8+)
```

**Forensic significance:** Credentials, decrypted content, and process memory fragments may be written to the page file. Sensitive data processed in RAM can survive in pagefile.sys after the process exits.

```powershell
# Check page file configuration
Get-WmiObject Win32_PageFileSetting
Get-WmiObject Win32_PageFileUsage

# Page file location
(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management").PagingFiles
```

---

## Hibernation File

`C:\hiberfil.sys` contains a compressed snapshot of physical RAM at the time of hibernation. This is a full memory image — contains process memory, credentials, encryption keys, and all running program state.

```powershell
# Check hibernation status
powercfg /query SCHEME_CURRENT SUB_SLEEP HYBRIDSLEEP
powercfg /availablesleepstates

# Hibernate now
shutdown /h
```

**Forensic use:** Acquiring hiberfil.sys from a hibernated system provides a full memory image without needing to run a memory acquisition tool. Volatility can directly process hiberfil.sys.

---

## Memory Forensics — Live Investigation

```powershell
# List all memory regions in a process
# Use Sysinternals VMMap or Process Explorer

# Via PowerShell — basic working set info
Get-Process -Id <pid> | Select-Object Name, Id, WorkingSet64, VirtualMemorySize64

# Find processes with unusual memory patterns
Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 20 |
  Select-Object Name, Id, WorkingSet64, Path

# Check for processes with no path (hollowing indicator)
Get-Process | Where-Object { -not $_.Path } | Select-Object Name, Id

# Dump process memory with procdump (Sysinternals)
# procdump.exe -ma <pid> C:\output\process.dmp

# Acquire full memory image
# WinPmem: winpmem_mini.exe memory.raw
# DumpIt: DumpIt.exe /O memory.raw
```

---

## Detection — Memory-Based Attacks

### Sysmon Events

| Event ID | Description | Memory Attack Indicator |
|----------|-------------|------------------------|
| 8 | CreateRemoteThread | Thread created in another process |
| 10 | ProcessAccess | Handle to process with VM_READ/WRITE |
| 17/18 | Pipe created/connected | Named pipe C2 |
| 25 | ProcessTampering | Hollowing or herp-a-derping detected |

### PowerShell Detection Queries

```powershell
# Detect process access with memory read/write permissions
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; Id=10
} | Where-Object {
  $_.Message -match '0x1010|0x1410|0x1438'  # memory read access masks
} | Select-Object TimeCreated, Message | Format-List

# Detect CreateRemoteThread
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; Id=8
} | Select-Object TimeCreated, Message | Format-List

# Detect process tampering (hollowing)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; Id=25
} | Select-Object TimeCreated, Message
```

---

## MITRE ATT&CK Mapping

| Technique | ID |
|-----------|-----|
| Process Injection: DLL Injection | T1055.001 |
| Process Injection: Process Hollowing | T1055.012 |
| Process Injection: Thread Execution Hijacking | T1055.003 |
| Process Injection: Process Doppelganging | T1055.013 |
| Reflective Code Loading | T1620 |
| OS Credential Dumping: LSASS Memory | T1003.001 |

---

## Practitioner Notes

**On PAGE_EXECUTE_READWRITE as IOC:** Legitimate code almost never needs a page that is simultaneously executable and writable at runtime. The presence of RWX pages in a process's working set is a strong injection indicator — JIT compilers (Chrome V8, .NET CLR) are the main exception. Baseline known JIT users and alert on all others.

**On VAD tree analysis:** Volatility's `malfind` plugin walks the VAD tree looking for private, executable memory regions that do not correspond to a mapped file on disk. This detects reflectively-loaded DLLs, shellcode, and process hollowing payloads without relying on signature scanning — it finds the anomaly by its structural properties.

**On page file and credential persistence:** If a system processes credentials or encryption keys in memory and the page file is unencrypted, that data may persist in pagefile.sys after the process exits and even after reboot (pagefile.sys is cleared at startup only if configured). Enable encrypted page file in secure environments: `fsutil behavior set encryptpagingfile 1`.

---

## Knowledge Validation

**What makes section-based injection harder to detect than classic CreateRemoteThread injection?**
Classic injection calls WriteProcessMemory (detected by Sysmon Event ID 10) and CreateRemoteThread (Event ID 8) — both are well-monitored APIs. Section-based injection uses NtCreateSection and NtMapViewOfSection to create shared memory between processes, then NtCreateThreadEx to start execution. It bypasses WriteProcessMemory entirely — the data is written to the local mapping and appears in the target via the shared section. Detection requires monitoring NtMapViewOfSection and NtCreateThreadEx at the NT API level rather than Win32 API level.

**Why does process hollowing survive hash-based detection?**
The process is created from the legitimate binary on disk — the hash matches. After creation in SUSPENDED state, the memory is unmapped with NtUnmapViewOfSection and replaced with malicious content. By the time execution starts, the hash of the binary on disk is irrelevant — the in-memory content is the attacker's payload. Detection requires memory scanning (VAD anomaly analysis) or Sysmon Event ID 25 (ProcessTampering), not file hash comparison.

**During IR you find hiberfil.sys on a seized system. What can you extract from it?**
hiberfil.sys contains a compressed snapshot of physical RAM at hibernation time — equivalent to a full memory dump. Using Volatility with a Windows profile, you can extract: running processes and their command lines, network connections active at hibernation time, loaded DLLs and their base addresses, registry hives cached in memory, clipboard content, browser session data, credentials cached in LSASS, and encryption keys held in process memory. It is forensically equivalent to a live memory acquisition.

---

*Windows/04-Memory-Management | OS-Internals-for-SOC | Solomon James (@Jaysolex)*
