# Windows/12 — Kernel Drivers

> A Windows kernel driver runs in Ring 0 with the same privilege as the NT kernel. It can intercept any system call, hook any kernel function, read any process memory, and make itself completely invisible to userspace tools. Understanding the driver model is what allows you to detect BYOVD attacks, kernel rootkits, and driver-based defense evasion.

![MITRE](https://img.shields.io/badge/MITRE-T1014%20|%20T1068%20|%20T1543.003-red)
![Platform](https://img.shields.io/badge/Platform-Windows-blue)

---

## Windows Driver Model

```
User Space (Ring 3)
    Application calls CreateFile, ReadFile, DeviceIoControl
        |
        v
I/O Manager (kernel)
    creates IRP (I/O Request Packet)
        |
        v
Driver Stack (Ring 0)
    Upper filter driver  (optional — security tools, AV)
    Function driver      (actual device implementation)
    Lower filter driver  (optional)
        |
        v
HAL / Hardware
```

Every I/O request in Windows is packaged as an IRP and dispatched down a driver stack. Filter drivers sit above or below the function driver and can inspect, modify, or block every request.

---

## Driver Types

| Type | Description | Security Use |
|------|-------------|-------------|
| Kernel-mode driver (.sys) | Full Ring 0 access | Hardware, rootkits, EDRs |
| Minifilter (fltmgr.sys) | Filesystem filter | AV file scanning, FIM |
| NDIS filter | Network filter | Firewall, VPN, packet capture |
| WDM driver | Plug and Play | USB, disk, input devices |
| WDF (KMDF/UMDF) | Modern framework | Modern hardware drivers |

---

## Driver Loading

### Normal Loading

```powershell
# Load via Service Control Manager
sc create MyDriver type= kernel binPath= C:\driver.sys
sc start MyDriver

# Via NtLoadDriver (requires SeLoadDriverPrivilege)
# Used by some tools and rootkits directly

# Check loaded drivers
driverquery /v
Get-WmiObject Win32_SystemDriver | Select-Object Name, State, PathName
```

### Boot-Load Drivers

Drivers with Start = 0 (Boot) or Start = 1 (System) load before most of Windows initialises — before user logon, before security tools, before many protections are active.

```
HKLM\SYSTEM\CurrentControlSet\Services\<DriverName>
    Type     = 1     (kernel driver)
    Start    = 0     (boot) or 1 (system)
    ImagePath = \SystemRoot\System32\Drivers\driver.sys
```

---

## Driver Signing Enforcement

64-bit Windows enforces driver signing — unsigned drivers cannot load in normal mode.

```powershell
# Check if signing enforcement is disabled
bcdedit /enum | Select-String "nointegritychecks|testsigning"
# If testsigning=Yes or nointegritychecks=Yes = signing disabled

# Check Secure Boot (prevents bypassing at firmware level)
Confirm-SecureBootUEFI -ErrorAction SilentlyContinue

# Check Windows Code Integrity policy
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
    Select-Object CodeIntegrityPolicyEnforcementStatus
```

---

## BYOVD — Bring Your Own Vulnerable Driver

The most common kernel-level attack technique on modern Windows. Load a legitimate, Microsoft-signed driver that has a known vulnerability — exploit it to achieve unsigned kernel code execution.

### Attack Flow

```
1. Attacker has a malicious unsigned driver/rootkit
2. Load a signed but vulnerable driver (e.g., RTCore64.sys, gdrv.sys, WinRing0.sys)
   - Signed = passes driver signing enforcement
   - Kernel loads it without issue
3. Exploit the vulnerability in the signed driver
   - Common: arbitrary memory read/write, arbitrary kernel function call
4. Use the exploit to:
   - Disable EDR kernel callbacks
   - Load unsigned malicious driver
   - Kill security processes by manipulating EPROCESS
5. Signed vulnerable driver unloaded (cleanup)
```

### Known Vulnerable Drivers (EDR Killers)

Common BYOVD drivers used in the wild:
- `RTCore64.sys` (MSI Afterburner) — arbitrary read/write
- `gdrv.sys` (GIGABYTE) — arbitrary read/write
- `WinRing0.sys` / `WinRing0x64.sys` — I/O port and MSR access
- `dbutil_2_3.sys` (Dell) — CVE-2021-21551
- `AsrDrv104.sys` (ASRock) — arbitrary R/W
- `iqvw64e.sys` (Intel) — arbitrary R/W

```powershell
# Check for known vulnerable drivers
$vulnerable = @('RTCore64.sys', 'gdrv.sys', 'WinRing0.sys', 'WinRing0x64.sys',
                'dbutil_2_3.sys', 'AsrDrv104.sys', 'iqvw64e.sys', 'mhyprot2.sys')

Get-WmiObject Win32_SystemDriver | ForEach-Object {
    $name = $_.Name + '.sys'
    if ($vulnerable -contains $name) {
        Write-Host "VULNERABLE DRIVER LOADED: $($_.Name) -> $($_.PathName)" -ForegroundColor Red
    }
}

# Check driver files on disk
foreach ($drv in $vulnerable) {
    $found = Get-ChildItem C:\ -Recurse -Filter $drv -ErrorAction SilentlyContinue
    if ($found) { "FOUND ON DISK: $($found.FullName)" }
}
```

---

## Kernel Callbacks — EDR Mechanism and BYOVD Target

EDRs use kernel callbacks to monitor system activity:

| Callback | Purpose | Registered By |
|----------|---------|---------------|
| PsSetCreateProcessNotifyRoutine | Process creation notification | EDR process monitoring |
| PsSetCreateThreadNotifyRoutine | Thread creation notification | EDR thread monitoring |
| PsSetLoadImageNotifyRoutine | Image (DLL) load notification | EDR DLL monitoring |
| CmRegisterCallback | Registry operation notification | EDR registry monitoring |
| ObRegisterCallbacks | Object (handle) access notification | EDR LSASS protection |
| MiniFilter registration | File I/O interception | AV file scanning |

**BYOVD target:** A vulnerable driver with arbitrary memory write allows overwriting the callback arrays — removing EDR entries and effectively disabling monitoring without touching any EDR process or file.

---

## Rootkit Techniques at Kernel Level

### DKOM — Direct Kernel Object Manipulation

Manipulate kernel data structures directly to hide processes, drivers, and registry keys.

```
EPROCESS.ActiveProcessLinks is a doubly-linked list of all processes.
A rootkit unlinks its process from this list.
ps.exe walks ActiveProcessLinks to enumerate processes.
Result: hidden process invisible to ps, Task Manager, Process Explorer.

But: /proc equivalent (scanning EPROCESS pool tags) can still find it.
And: Volatility's linux_pslist / pslist plugin detects unlinked processes.
```

### Kernel Patch — SSDT Hooking

The System Service Descriptor Table (SSDT) maps syscall numbers to kernel function addresses. Replacing entries redirects syscalls through the rootkit.

```
Kernel: NtQuerySystemInformation at 0xfffff800`12345678
Rootkit patches SSDT: NtQuerySystemInformation -> 0xfffff800`deadbeef (rootkit function)
Now: every call to NtQuerySystemInformation is filtered by rootkit
```

Modern Windows: PatchGuard (KPP — Kernel Patch Protection) detects and BSODs on SSDT modification. Sophisticated rootkits bypass PatchGuard.

---

## Detection

### Live Detection

```powershell
# All loaded drivers
driverquery /v /fo csv | ConvertFrom-Csv | Where-Object { $_.'State' -eq 'Running' }

# Unsigned drivers
Get-WmiObject Win32_SystemDriver | ForEach-Object {
    $path = $_.PathName -replace '"',''
    $sig = Get-AuthenticodeSignature $path -ErrorAction SilentlyContinue
    if ($sig.Status -ne 'Valid') {
        [PSCustomObject]@{ Name=$_.Name; Path=$path; Status=$sig.Status }
    }
}

# Recently loaded drivers (Event ID 7045 for new services + Type=kernel)
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        $type = $xml.Event.EventData.Data[2].'#text'
        if ($type -eq 'kernel mode driver') {
            [PSCustomObject]@{
                Time = $_.TimeCreated
                Name = $xml.Event.EventData.Data[0].'#text'
                Path = $xml.Event.EventData.Data[1].'#text'
            }
        }
    }

# Check for testsigning / nointegritychecks
bcdedit /enum all | Select-String "testsigning|nointegritychecks"

# Driver files in non-standard locations
Get-ChildItem C:\Windows\System32\Drivers -Filter *.sys |
    ForEach-Object {
        $sig = Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue
        if ($sig.Status -ne 'Valid') {
            [PSCustomObject]@{ File=$_.Name; Status=$sig.Status; Path=$_.FullName }
        }
    }

# Kernel integrity (PatchGuard violations would cause BSOD, check minidumps)
Get-ChildItem C:\Windows\Minidump -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 5
```

### Sysmon — Driver Load

```powershell
# Sysmon Event ID 6 — Driver loaded
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational'; Id=6
} | Where-Object { $_.Message -match 'Signed: false' } |
    Select-Object TimeCreated, Message | Format-List
```

---

## MITRE ATT&CK Mapping

| Technique | ID |
|-----------|-----|
| Rootkit | T1014 |
| Exploitation for Privilege Escalation | T1068 |
| Create or Modify System Process: Windows Service | T1543.003 |
| Impair Defenses: Disable or Modify Tools | T1562.001 |

---

## Sigma Rule — Vulnerable Driver Loaded

```yaml
title: Known Vulnerable Kernel Driver Loaded
id: e7f8a9b0-c1d2-3456-efab-789012345678
status: stable
description: >
  Detects loading of kernel drivers known to be vulnerable
  and used in BYOVD attacks to disable security software
  or achieve kernel code execution.
author: Solomon James (@Jaysolex)
tags:
  - attack.defense_evasion
  - attack.t1562.001
  - attack.privilege_escalation
  - attack.t1068
logsource:
  product: windows
  category: driver_load
  service: sysmon
detection:
  selection:
    EventID: 6
    ImageLoaded|endswith:
      - '\RTCore64.sys'
      - '\gdrv.sys'
      - '\WinRing0.sys'
      - '\WinRing0x64.sys'
      - '\dbutil_2_3.sys'
      - '\AsrDrv104.sys'
      - '\iqvw64e.sys'
      - '\mhyprot2.sys'
  condition: selection
falsepositives:
  - Legitimate use of hardware monitoring tools (verify context)
level: critical
```

---

## Practitioner Notes

**On BYOVD and EDR evasion:** BYOVD has become the standard technique for bypassing kernel-level EDR protections in targeted attacks. The attacker does not touch the EDR binary, does not disable the EDR service, and does not inject into any security process — they simply remove the kernel callbacks that the EDR registered. From the EDR's perspective, it is still running. From the kernel's perspective, its visibility hooks have been removed. Detection requires monitoring for known-vulnerable driver loads (Sysmon Event ID 6) and maintaining a blocklist of vulnerable driver hashes.

**On PatchGuard and its limitations:** PatchGuard (Kernel Patch Protection) prevents modification of SSDT, IDT, GDT, and EPROCESS.ActiveProcessLinks by periodically checking their integrity and BSODing on violation. It does not prevent DKOM on less-monitored structures, does not prevent callback removal (legitimate operation), and sophisticated attackers have bypassed it by exploiting the PatchGuard mechanism itself. PatchGuard is a defence in depth measure, not a complete rootkit prevention solution.

**On driver acquisition during IR:** When you find a suspicious driver, acquire the .sys file immediately before remediation — the binary itself is the primary IOC and should be submitted for analysis. Check its PE metadata (compile time, version info), its import table (what kernel APIs it uses), and whether it is signed and by whom. A legitimately signed driver with a compilation date from yesterday is a BYOVD indicator.

---

## Knowledge Validation

**What is BYOVD and why does it succeed against signed driver enforcement?**
BYOVD loads a legitimate, cryptographically signed driver that has a known exploitable vulnerability. Because it is signed by a trusted certificate authority, driver signing enforcement allows it to load without issue. The attacker then exploits the vulnerability to achieve arbitrary kernel read/write or code execution — running their unsigned malicious code in Ring 0 via the signed driver as a proxy. Detection requires blocking known-vulnerable drivers by hash before they load, not just checking signatures.

**How do EDRs use kernel callbacks and how does BYOVD disable them?**
EDRs register kernel callbacks (PsSetCreateProcessNotifyRoutine, ObRegisterCallbacks, etc.) to receive notifications of process creation, handle access, and DLL loads. These registrations are stored in kernel arrays. A BYOVD attack uses arbitrary memory write (from the vulnerable driver) to zero out or replace the EDR's function pointer in these arrays — the notification is never sent to the EDR when processes create or LSASS is accessed. The EDR is still running but is effectively blind.

**You find testsigning=Yes in bcdedit output on a production server. What does this mean and what do you do?**
Test signing mode disables driver signature enforcement — any unsigned driver can load. This is a development setting that should never appear on production systems. On a production server it strongly indicates: (1) an attacker disabled signing to load a malicious unsigned driver/rootkit, or (2) a compromised build process. Steps: check recent driver loads (Sysmon Event ID 6, Event ID 7045), look for unsigned .sys files in non-standard locations, acquire memory for rootkit analysis (Volatility), check for DKOM artifacts (process list discrepancies), and treat this as a confirmed kernel-level compromise until proven otherwise.

---

*Windows/12-Kernel-Drivers | OS-Internals-for-SOC | Solomon James (@Jaysolex)*
