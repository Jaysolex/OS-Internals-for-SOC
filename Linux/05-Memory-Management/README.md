# Linux/05 — Memory Management

> Memory is where attacks live. Shellcode, injected payloads, credential material, decrypted strings — all of it exists in memory. Understanding how Linux manages memory is what allows a security engineer to find things that have no file on disk, detect injection, and know what survives a reboot versus what dies with the process.

![MITRE](https://img.shields.io/badge/MITRE-T1055%20|%20T1620%20|%20T1003-red)
![Platform](https://img.shields.io/badge/Platform-Linux-orange)

---

## Virtual Memory

Every Linux process operates in its own virtual address space. The process believes it has exclusive access to a large flat memory range. The kernel's memory manager (MM subsystem) translates virtual addresses to physical RAM using page tables.

```
Process A virtual space      Process B virtual space
0x0000 - 0x7FFF...           0x0000 - 0x7FFF...
        |                            |
        v    (page table translation)
        Physical RAM (shared, managed by kernel)
```

Benefits for security:
- Process isolation — process A cannot read process B's memory without kernel permission
- Overcommit — the kernel can allocate more virtual memory than physical RAM exists
- Memory protection — pages can be marked read-only, no-execute, etc.

---

## Page Tables and TLB

The CPU's Memory Management Unit (MMU) walks page tables to translate virtual to physical addresses. Linux uses a 5-level page table on x86_64 for large address spaces.

Each page (4KB default) has protection flags:
- **Present** — page is in physical RAM
- **Writable** — page can be written
- **User/Supervisor** — accessible from Ring 3 or Ring 0 only
- **NX (No-Execute)** — page cannot be executed (DEP/NX bit)

**NX bit and shellcode:** The NX bit prevents executing code in data pages. Classic buffer overflow shellcode fails because the stack is marked NX. Attackers bypass this with ROP (Return Oriented Programming) — chaining existing executable code fragments.

```bash
# Check if NX is enabled for a process stack
cat /proc/<pid>/maps | grep "\[stack\]"
# Should show rw-p (not rwx) on modern systems
```

---

## Memory Layout Per Process

```
Virtual Address Space (x86_64 process)

0xFFFFFFFFFFFFFFFF  <-- kernel space (inaccessible from user space)
0xFFFF800000000000
        .
        .
0x00007FFFFFFFFFFF  <-- top of user space
        |
        +-- Stack          grows downward, rw-p, ASLR randomized
        |   [stack]
        |
        +-- mmap region    shared libraries, anonymous mappings
        |   [heap]         grows upward from brk()
        |
        +-- BSS segment    uninitialized globals (zero-filled)
        +-- Data segment   initialized globals
        +-- Text segment   executable code (r-xp, read-only)
        |
0x00400000          <-- typical ELF load address (no PIE)
0x0000000000000000  <-- NULL page (unmapped)
```

---

## Memory Types Security Engineers Care About

### Anonymous Mappings

Memory not backed by any file on disk. Created by malloc, mmap(MAP_ANONYMOUS), or stack growth. Shellcode and injected payloads live here.

```bash
# Find anonymous executable mappings in a process
cat /proc/<pid>/maps | awk '$2~/x/ && $6=="" {print "EXEC ANON:", $0}'
```

### File-Backed Mappings

Memory mapped from a file — shared libraries, executable code, memory-mapped files. The file path appears in the maps output.

```bash
# List all file-backed mappings
cat /proc/<pid>/maps | awk '$6!="" {print $6}' | sort -u
```

### Shared Memory (SHM/mmap)

Memory shared between processes. `/dev/shm` provides POSIX shared memory — RAM-backed, never touches disk.

```bash
ls -la /dev/shm/
ipcs -m          # System V shared memory segments
```

---

## Key Memory Syscalls — Attacker Perspective

| Syscall | Purpose | Attack Use |
|---------|---------|------------|
| `mmap` | Map memory region | Allocate executable memory for shellcode |
| `mprotect` | Change page permissions | Mark shellcode region executable after writing |
| `brk` | Extend heap | Heap-based payload staging |
| `munmap` | Unmap memory | Clean up after payload execution |
| `ptrace` | Read/write another process memory | Process injection |
| `process_vm_writev` | Write to another process memory | Injection without ptrace |
| `memfd_create` | Create anonymous file in RAM | Fileless execution |

### memfd_create — Fileless Execution

Creates a file descriptor backed only by RAM — no filesystem path, invisible to tools scanning disk. Used for fileless malware execution.

```c
int fd = memfd_create("", MFD_CLOEXEC);
write(fd, payload, payload_len);
fexecve(fd, args, env);  // execute directly from memory
```

```bash
# Detect memfd usage
# Process exe symlink points to /memfd:name (deleted)
ls -la /proc/*/exe 2>/dev/null | grep memfd

# Also visible in /proc/pid/maps as
# 7f... r-xp ... /memfd:name (deleted)
cat /proc/<pid>/maps | grep memfd
```

---

## The OOM Killer

When the system runs out of memory, the kernel's Out-of-Memory (OOM) killer selects a process to terminate based on an OOM score.

```bash
# View OOM score for a process (higher = more likely to be killed)
cat /proc/<pid>/oom_score

# View OOM score adjustment
cat /proc/<pid>/oom_score_adj
# -1000 = never kill this process
# +1000 = kill this first

# Attacker use: protect malicious process from OOM killer
echo -1000 > /proc/<malicious_pid>/oom_score_adj
```

Detection: Writing to /proc/pid/oom_score_adj by a non-root process or for unexpected processes — monitor via auditd.

---

## Swap Space

When physical RAM is full, the kernel moves inactive pages to swap (disk). This has forensic implications:

- Sensitive data (credentials, keys, decrypted content) may be written to swap
- Swap survives reboots if not encrypted
- Analysing swap can reveal memory artifacts from completed processes

```bash
# Check swap usage
cat /proc/swaps
swapon --show
free -h

# Disable swap (prevent sensitive data hitting disk)
swapoff -a

# Check if swap is encrypted
dmsetup ls | grep swap
cat /proc/swaps | awk '{print $1}' | while read dev; do
  cryptsetup status $dev 2>/dev/null
done
```

---

## ASLR — Address Space Layout Randomization

The kernel randomizes base addresses of stack, heap, mmap, and VDSO regions at each program launch. Makes exploitation harder by preventing hardcoded addresses.

```bash
# ASLR setting
cat /proc/sys/kernel/randomize_va_space
# 0 = disabled
# 1 = randomize stack, mmap, VDSO
# 2 = also randomize heap (default)

# Verify ASLR is working — run twice, addresses should differ
cat /proc/self/maps | head -5
cat /proc/self/maps | head -5
```

**Defeating ASLR:**
- Information leak vulnerabilities reveal actual addresses
- Brute force on 32-bit systems (small address space)
- Heap spraying — fill memory with payload so any jump hits it

---

## Memory Forensics — Live Investigation

```bash
# Full memory map of suspect process
cat /proc/<pid>/maps

# Dump specific memory region
# From maps: 7f8b4c000000-7f8b4c021000 rwxp
dd if=/proc/<pid>/mem bs=1 skip=$((16#7f8b4c000000)) count=$((16#21000)) \
  of=/tmp/region_dump 2>/dev/null

# Alternative with Python
python3 -c "
import sys
pid = int(sys.argv[1])
start = int(sys.argv[2], 16)
end = int(sys.argv[3], 16)
with open(f'/proc/{pid}/mem', 'rb') as mem:
    mem.seek(start)
    data = mem.read(end - start)
    sys.stdout.buffer.write(data)
" <pid> <start_addr> <end_addr> > /tmp/dump.bin

# Search for strings in process memory
strings /proc/<pid>/mem 2>/dev/null | grep -iE "password|token|BEGIN.*KEY"

# Full memory acquisition with LiME (kernel module)
insmod lime.ko "path=/media/usb/memory.lime format=lime"
```

---

## /proc/meminfo — System Memory Overview

```bash
cat /proc/meminfo
```

Key fields:
```
MemTotal:       16384000 kB    total physical RAM
MemFree:         2048000 kB    unused RAM
MemAvailable:    8192000 kB    available without swapping
Buffers:          512000 kB    kernel buffer cache
Cached:          4096000 kB    page cache
SwapTotal:       2097152 kB    total swap space
SwapFree:        2097152 kB    unused swap
```

---

## MITRE ATT&CK Mapping

| Technique | ID | Memory Relevance |
|-----------|-----|-----------------|
| Process Injection | T1055 | Writing shellcode into process memory |
| Reflective Code Loading | T1620 | Loading code from memory without disk |
| OS Credential Dumping | T1003 | Reading credentials from process memory |
| Hide Artifacts: Process Argument Spoofing | T1564.011 | Modifying in-memory cmdline |

---

## Sigma Rule — Suspicious mprotect Call

```yaml
title: Process Making Memory Region Executable
id: b8c9d0e1-f2a3-4567-bcde-678901234567
status: stable
description: >
  Detects processes calling mprotect to add execute permission
  to a memory region. Legitimate software rarely does this
  at runtime — shellcode staging and JIT engines are the
  primary use cases.
author: Solomon James (@Jaysolex)
tags:
  - attack.defense_evasion
  - attack.t1055
logsource:
  product: linux
  service: auditd
detection:
  selection:
    type: SYSCALL
    syscall: mprotect
    a2|contains: '0x7'    # PROT_READ|PROT_WRITE|PROT_EXEC = 7
  filter_known_jit:
    exe|contains:
      - 'java'
      - 'node'
      - 'python'
  condition: selection and not filter_known_jit
falsepositives:
  - JIT compilers (Java, V8, LuaJIT)
  - Some legitimate cryptographic libraries
level: medium
```

---

## Practitioner Notes

**On memfd_create and fileless detection:** Processes executing payloads via memfd_create show their exe symlink as `/memfd:name (deleted)` — the file never existed on disk. Standard file scanning misses these entirely. Detection requires monitoring the memfd_create syscall via auditd or eBPF and correlating with subsequent fexecve calls.

**On swap and sensitive data:** If a system processes credentials, private keys, or other sensitive material in memory and swap is unencrypted, that data may persist on disk in the swap partition after the process exits. IR on systems with sensitive workloads should include swap analysis. Enable encrypted swap (dm-crypt) in production.

**On anonymous RWX regions:** A legitimate process almost never has a region that is simultaneously writable and executable. The presence of rwx pages in /proc/pid/maps is a strong injection indicator. JIT compilers (Java, JavaScript engines) are the main legitimate exception — filter by process name.

---

## Knowledge Validation

**Why does the NX bit not fully prevent code execution attacks and what technique bypasses it?**
The NX bit marks data pages as non-executable — injected shellcode on the stack or heap cannot run directly. Return Oriented Programming (ROP) bypasses this by chaining short sequences of existing executable code (gadgets) ending in `ret` instructions. The attacker never executes new code — only redirects execution through existing code already mapped as executable, which the NX bit cannot prevent.

**What is memfd_create and why is it significant for detection?**
memfd_create creates a file descriptor backed by RAM with no filesystem path. Malware uses it to load and execute payloads entirely in memory — no file is written to disk, evading file-based detection and many EDR hooks. Detection requires monitoring the memfd_create syscall via auditd or eBPF, and identifying processes whose /proc/pid/exe shows `/memfd:` as the path.

**During an IR, you find /proc/1234/maps shows an rwx anonymous region at 0x7f000000. The process name is sshd. What is your assessment and next steps?**
Legitimate sshd has no reason for an anonymous executable-writable memory region. This is a strong indicator of process injection — shellcode or a reflectively-loaded payload staged in sshd's memory. Steps: dump the memory region using /proc/1234/mem, run strings and file against the dump, check /proc/1234/fd for unusual open files, review auditd records for ptrace or process_vm_writev syscalls targeting PID 1234, check network connections from sshd's perspective via /proc/1234/net/tcp.

---

*Linux/05-Memory-Management | OS-Internals-for-SOC | Solomon James (@Jaysolex)*
