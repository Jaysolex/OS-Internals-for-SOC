# Windows/00 — Architecture

> Windows NT architecture defines the boundaries between user and kernel space, the object model that governs every resource, and the security model that every privilege escalation attempts to bypass. Understanding the NT architecture is what separates a Windows security engineer from someone who reads event logs without knowing why they say what they say.

![Platform](https://img.shields.io/badge/Platform-Windows-blue)

---

## NT Architecture Overview

```
+--------------------------------------------------+
|                  USER SPACE                      |
|                                                  |
|  Win32 Applications    .NET Applications         |
|  cmd.exe  powershell   chrome  office            |
|                                                  |
|  Win32 Subsystem (csrss.exe)                     |
|  POSIX Subsystem (optional)                      |
|                                                  |
|  NTDLL.DLL  (gateway to kernel — always loaded) |
+--------------------------------------------------+
           |  syscall (NTAPI)
           v
+--------------------------------------------------+
|                 KERNEL SPACE                     |
|                                                  |
|  Executive (ntoskrnl.exe)                        |
|    Object Manager    Security Reference Monitor  |
|    Process Manager   Memory Manager              |
|    I/O Manager       Cache Manager               |
|    PnP Manager       Power Manager               |
|                                                  |
|  Kernel (ntoskrnl.exe lower half)                |
|    Scheduler  Interrupt Dispatcher  Sync         |
|                                                  |
|  HAL (hal.dll) — Hardware Abstraction Layer      |
|                                                  |
|  Device Drivers (kernel-mode .sys files)         |
+--------------------------------------------------+
|                  HARDWARE                        |
+--------------------------------------------------+
```

---

## CPU Privilege Rings

Windows uses two of the four x86/x64 privilege rings:

| Ring | Mode | Used By |
|------|------|---------|
| 0 | Kernel mode | NT kernel, HAL, drivers |
| 3 | User mode | All applications |

Rings 1 and 2 are unused. The transition from Ring 3 to Ring 0 happens only via syscall — the controlled entry point the kernel exposes. Every exploit that achieves kernel code execution is making this transition illegitimately.

---

## The NT Executive

The NT Executive is the upper layer of the kernel (ntoskrnl.exe). It provides the core OS services via a documented API (NTAPI) and internal subsystems.

### Executive Components

**Object Manager**
Every resource in Windows is represented as a kernel object — files, processes, threads, registry keys, events, mutexes, semaphores. The Object Manager maintains the namespace, reference counts, and security descriptors for all objects.

```
\                           root of object namespace
├── Device\                 device objects
├── Driver\                 driver objects
├── KnownDlls\             pre-loaded DLL objects
├── ObjectTypes\           type objects for each object class
├── Sessions\              per-session namespaces
├── Windows\               window station objects
└── BaseNamedObjects\      mutexes, events, semaphores (user created)
```

**Security Reference Monitor (SRM)**
Enforces access control. Every time a process attempts to open an object, the SRM compares the process's access token against the object's security descriptor. This is the kernel-level enforcement of Windows ACLs.

**Process Manager**
Creates and terminates processes and threads. Maintains the EPROCESS and ETHREAD kernel structures.

**Memory Manager**
Manages virtual address spaces, page tables, working sets, paging, and the page file. Handles memory-mapped files, shared memory, and large page support.

**I/O Manager**
Manages all I/O requests through the driver stack. Implements the IRP (I/O Request Packet) model — a structured request passed down through layered drivers.

**Cache Manager**
Unified file system cache shared across all file system drivers.

---

## The Windows Kernel (Lower Half)

The lower half of ntoskrnl.exe handles the most fundamental operations:

- **Scheduler** — thread scheduling across CPU cores using priority levels 0-31
- **Interrupt Dispatcher** — handles hardware interrupts and software exceptions
- **Synchronization** — spinlocks, mutexes, events used by the Executive
- **IRQL** — Interrupt Request Level system controlling what code can run at each level

### IRQL — Interrupt Request Level

Windows uses IRQLs to serialize access to shared data structures and control execution context.

| IRQL | Name | Description |
|------|------|-------------|
| 0 | PASSIVE_LEVEL | Normal thread execution, user mode |
| 1 | APC_LEVEL | Asynchronous Procedure Calls |
| 2 | DISPATCH_LEVEL | Scheduler and DPCs — no page faults allowed |
| 3-26 | DIRQL | Device interrupt levels |
| 27 | PROFILE_LEVEL | Timer profiling |
| 28 | CLOCK_LEVEL | Clock interrupts |
| 29 | IPI_LEVEL | Inter-processor interrupts |
| 30 | POWER_LEVEL | Power failure |
| 31 | HIGH_LEVEL | Machine check / NMI |

**Security significance:** Drivers running at DISPATCH_LEVEL or above cannot be paged out, cannot take page faults, and must complete quickly. Rootkits that run their malicious code at high IRQL are harder to detect and can cause system instability.

---

## HAL — Hardware Abstraction Layer

hal.dll abstracts hardware differences from the kernel. The kernel calls HAL functions rather than touching hardware directly — enabling the same kernel binary to run on different hardware configurations.

```
Kernel → HAL → Hardware
```

From a security perspective, HAL is a very low-level component that boots before most security controls. UEFI firmware attacks that compromise the boot process can manipulate what HAL presents to the kernel.

---

## Device Drivers

Kernel-mode drivers (.sys files) load into Ring 0 and have full kernel access. They are the most common rootkit vehicle on Windows.

### Driver Types

| Type | Description | Example |
|------|-------------|---------|
| Kernel-mode driver | Full kernel access | Hardware drivers |
| Minifilter driver | File system filter | AV file scanning |
| NDIS filter | Network filter | Firewall, VPN |
| WDM driver | Plug and Play | USB devices |
| Legacy driver | Non-PnP | Some rootkits |

### Driver Loading

```powershell
# List all loaded drivers
driverquery /v

# List via WMI
Get-WmiObject Win32_SystemDriver | Select-Object Name, State, PathName

# Check driver signatures
Get-WmiObject Win32_SystemDriver | ForEach-Object {
    $sig = Get-AuthenticodeSignature $_.PathName -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        Name    = $_.Name
        Path    = $_.PathName
        Signed  = $sig.Status
        Signer  = $sig.SignerCertificate.Subject
    }
}

# Services that are kernel drivers
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\*" |
  Where-Object { $_.Type -eq 1 } |
  Select-Object PSChildName, ImagePath
```

### Driver Signing Enforcement

Windows enforces driver signing in 64-bit mode — unsigned drivers cannot load. BYOVD (Bring Your Own Vulnerable Driver) bypasses this by loading a legitimate signed driver that has a known vulnerability, then exploiting it to execute unsigned attacker code in kernel space.

```powershell
# Check if Driver Signature Enforcement is enabled
bcdedit /enum | grep -i "nointegritychecks\|testsigning"
# If testsigning=Yes = signing disabled (development mode or bypass)
```

---

## Windows Object Model

Every resource in Windows is a kernel object with:
- A type (Process, Thread, File, Key, Event...)
- A security descriptor (ACL controlling who can access it)
- A reference count (object destroyed when count reaches 0)
- A handle table entry when opened by a process

### Object Handles

A handle is a process-specific reference to a kernel object. When a process opens a file, registry key, or another process, it receives a handle number that indexes into the process's handle table.

```powershell
# View handles for a process (Sysinternals Handle)
handle.exe -p <pid>

# View via PowerShell
$proc = Get-Process -Id <pid>
$proc.Handles

# Process handle to another process = injection vector
# OpenProcess() returns a handle that allows memory read/write
```

**Security significance:** To inject into or dump memory of another process, an attacker must call OpenProcess() with appropriate access rights — this creates a handle entry detectable via Sysmon Event ID 10.

---

## Access Tokens

Every process and thread has an access token — a kernel object that defines its security identity.

```
Access Token contains:
    User SID             (who this process runs as)
    Group SIDs           (group memberships)
    Privileges           (SeDebugPrivilege, SeTcbPrivilege...)
    Integrity Level      (Low, Medium, High, System)
    Logon Session ID
    Default DACL         (for objects created by this process)
```

### Privilege Escalation via Token

```powershell
# Check current process token
whoami /all

# Check privileges
whoami /priv

# Key privileges for attackers:
# SeDebugPrivilege    - debug (read/write memory of) any process
# SeTcbPrivilege      - act as part of OS (generate arbitrary tokens)
# SeImpersonatePrivilege - impersonate other users (Potato attacks)
# SeLoadDriverPrivilege - load kernel drivers
# SeBackupPrivilege   - bypass ACLs for backup (read any file)
# SeRestorePrivilege  - bypass ACLs for restore (write any file)
# SeTakeOwnershipPrivilege - take ownership of any object
```

### Integrity Levels

Mandatory Integrity Control (MIC) assigns integrity levels to processes and objects:

| Level | Value | Who Runs Here |
|-------|-------|--------------|
| Untrusted | 0x0000 | Heavily sandboxed processes |
| Low | 0x1000 | IE Protected Mode, sandboxed apps |
| Medium | 0x2000 | Normal user processes |
| High | 0x3000 | Elevated (admin) processes |
| System | 0x4000 | SYSTEM services |
| Protected | 0x5000 | PPL processes (LSASS with PPL) |

A process cannot write to objects with a higher integrity level — medium processes cannot write to high-integrity locations. UAC elevation creates a high-integrity token from a medium-integrity process.

---

## Windows Subsystems

### Win32 Subsystem (csrss.exe)

The Win32 subsystem server — handles console windows, process/thread creation notifications, and Win32 API. csrss.exe runs as SYSTEM and is a critical system process.

**Forensic note:** csrss.exe should always run from `C:\Windows\System32\csrss.exe`. Any csrss.exe from another path or with a parent other than smss.exe is malicious.

### NTDLL.DLL

The lowest-level user-mode library. Every Win32 API call eventually passes through NTDLL, which translates it into the corresponding NT syscall. Always present in every process.

**Security significance:** Attackers who hook NTDLL functions intercept all API calls before they reach the kernel. Security tools that detect this (unhooking NTDLL) restore original function bytes to bypass attacker hooks.

---

## Boot Process

```
Power on
    |
    v
UEFI firmware     <- POST, hardware init, Secure Boot validation
    |
    v
Windows Boot Manager (bootmgr)    <- from EFI partition
    |
    v
Windows OS Loader (winload.efi)   <- loads kernel, HAL, boot drivers
    |
    v
NT Kernel init (ntoskrnl.exe)     <- initializes executive subsystems
    |
    v
Session Manager (smss.exe)        <- PID 4 parent, creates sessions
    |
    v
WinLogon (winlogon.exe)           <- handles user logon UI
    |
    v
LSASS (lsass.exe)                 <- authentication
    |
    v
Services (services.exe)           <- starts Windows services
    |
    v
Explorer (explorer.exe)           <- user shell
```

### Secure Boot

UEFI Secure Boot validates digital signatures on the boot manager, OS loader, and drivers before executing them. Prevents bootkits from loading unsigned code before the OS starts.

```powershell
# Check Secure Boot status
Confirm-SecureBootUEFI

# Check via WMI
Get-WmiObject -Namespace "root\cimv2\security\microsofttpm" -Class Win32_Tpm
```

---

## Key System Processes

| Process | PID | Parent | Purpose | Anomaly Indicator |
|---------|-----|--------|---------|-------------------|
| System | 4 | 0 | Kernel thread host | Wrong PID or parent |
| smss.exe | varies | 4 | Session Manager | Multiple instances (only one per session) |
| csrss.exe | varies | smss | Win32 subsystem | Wrong path or parent |
| wininit.exe | varies | smss | Windows Init (session 0) | Multiple instances |
| winlogon.exe | varies | smss | Logon (session 1+) | Wrong parent or path |
| lsass.exe | varies | wininit | Authentication | Multiple instances or wrong parent |
| services.exe | varies | wininit | SCM | Multiple instances |
| svchost.exe | varies | services | Service host | Wrong parent or unusual path |
| explorer.exe | varies | userinit | User shell | Running as SYSTEM |

```powershell
# Validate critical process parent-child relationships
Get-WmiObject Win32_Process | Select-Object ProcessId, ParentProcessId, Name, ExecutablePath |
  Where-Object { $_.Name -match "csrss|lsass|winlogon|svchost|services|smss" } |
  Format-Table -AutoSize
```

---

## Investigation Commands

```powershell
# Kernel and system info
[System.Environment]::OSVersion
Get-WmiObject Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber

# Loaded drivers
driverquery /v /fo csv | ConvertFrom-Csv | Where-Object { $_.State -eq "Running" }

# Unsigned drivers
Get-WmiObject Win32_SystemDriver | ForEach-Object {
  $path = $_.PathName -replace '"',''
  $sig = Get-AuthenticodeSignature $path -ErrorAction SilentlyContinue
  if ($sig.Status -ne 'Valid') {
    [PSCustomObject]@{ Name=$_.Name; Path=$path; Status=$sig.Status }
  }
}

# Check Driver Signing Enforcement
bcdedit /enum | Select-String "nointegritychecks|testsigning"

# Integrity level of running processes
Get-WmiObject Win32_Process | ForEach-Object {
  try {
    $handle = [System.Diagnostics.Process]::GetProcessById($_.ProcessId)
    Write-Host "$($_.Name) PID:$($_.ProcessId)"
  } catch {}
}

# Secure Boot status
try { Confirm-SecureBootUEFI } catch { "Cannot determine Secure Boot status" }

# Token privileges for current session
whoami /all
whoami /priv

# Check for SeDebugPrivilege (allows credential dumping)
whoami /priv | Select-String "SeDebugPrivilege"
```

---

## Practitioner Notes

**On NTDLL hooking detection:** Security products and attacker tools both hook NTDLL. EDRs hook it to monitor API calls. Attackers hook it to hide activity. Some malware "unhoooks" NTDLL by reading a fresh copy from disk and restoring original function bytes — bypassing EDR hooks. Detection: monitor for processes reading ntdll.dll from disk at runtime (unusual for normal applications).

**On svchost.exe and detection:** svchost.exe is the most common legitimate process name for process injection and masquerading. Legitimate svchost.exe always has `services.exe` as parent and loads from `C:\Windows\System32\svchost.exe`. Any svchost with a different parent, different path, or running without `-k` parameter is suspicious.

**On integrity levels and UAC bypass:** UAC bypass techniques elevate from Medium to High integrity without a UAC prompt. They work by exploiting auto-elevation (certain trusted binaries automatically elevate) or COM object hijacking that executes as a high-integrity process. Detection: monitor for processes with High integrity level spawned without a corresponding UAC prompt (consent.exe execution).

---

## Knowledge Validation

**What is the role of the Security Reference Monitor and when does it run?**
The SRM is the kernel component that enforces access control decisions. Every time a process calls OpenProcess, CreateFile, RegOpenKey, or any function that accesses a kernel object, the Object Manager calls the SRM to compare the requesting process's access token (its privileges and group SIDs) against the object's security descriptor (its DACL). If access is denied, the syscall returns ACCESS_DENIED without the object ever being opened. It runs in kernel space on every object access attempt.

**Why is NTDLL.DLL significant from both an attack and defense perspective?**
NTDLL is the lowest-level user-mode library — every API call from every process eventually passes through NTDLL functions which translate them to NT syscalls. EDRs hook NTDLL to intercept and monitor API calls. Attackers hook NTDLL to hide activity from security tools, or "unhook" it by loading a clean copy from disk to bypass EDR hooks. Understanding NTDLL is the foundation of understanding both security product architecture and API-level evasion.

**A process shows High integrity level but was not launched via UAC prompt. What does this indicate?**
This indicates a UAC bypass — the process elevated from Medium to High integrity without triggering the standard UAC consent prompt. Common techniques: auto-elevation abuse (certain Microsoft-signed binaries auto-elevate; attackers exploit them), COM object hijacking targeting auto-elevating COM servers, DLL hijacking in trusted auto-elevating processes, or token manipulation. Investigation: check the process parent chain, the binary path and signature, and correlate with Sysmon process creation logs to find the elevation mechanism.

---

*Windows/00-Architecture | OS-Internals-for-SOC | Solomon James (@Jaysolex)*
