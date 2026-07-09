# Linux/00 — Architecture

> Before you can detect an attack, you need to understand what normal looks like at the OS level. Linux architecture defines the boundaries between user and kernel space, the interface through which all software interacts with hardware, and the security model that every privilege escalation technique attempts to bypass.

![Platform](https://img.shields.io/badge/Platform-Linux-orange)

---

## The Fundamental Split — User Space vs Kernel Space

Linux divides memory and execution into two domains:

```
+----------------------------------+
|         USER SPACE               |
|  Applications, shells, daemons   |
|  /bin, /usr, /home, /tmp         |
|  Runs in CPU Ring 3              |
+----------------------------------+
           |  syscall interface
           |  (only crossing point)
+----------------------------------+
|         KERNEL SPACE             |
|  Scheduler, memory manager       |
|  Device drivers, VFS, network    |
|  Runs in CPU Ring 0              |
+----------------------------------+
|         HARDWARE                 |
|  CPU, RAM, disk, NIC             |
+----------------------------------+
```

User space code cannot directly access hardware or kernel memory. It must cross the boundary via the **syscall interface** — a controlled gate the kernel manages. This is the security model. Every privilege escalation, every kernel exploit, every rootkit is an attempt to either cross this boundary illegitimately or abuse something that already has kernel access.

---

## CPU Privilege Rings

x86/x64 CPUs implement four privilege rings (0-3). Linux uses only two:

| Ring | Name | Who Uses It | Can Do |
|------|------|-------------|--------|
| 0 | Kernel mode | Linux kernel, drivers | Full hardware access, all instructions |
| 3 | User mode | All userspace processes | Restricted instruction set, no direct hardware |

Rings 1 and 2 exist in the architecture but are unused by Linux. The kernel runs in Ring 0. Everything else — bash, sshd, Apache, your Python script — runs in Ring 3.

**Security significance:** A process running in Ring 3 cannot execute privileged CPU instructions (like `in`, `out`, `lgdt`, `lidt`). If it tries, the CPU raises a General Protection Fault — the kernel kills the process. Kernel exploits work by finding paths to execute attacker-controlled code in Ring 0.

---

## The Syscall Interface

The only legitimate way for user space to request kernel services. Every file read, network connection, process creation, and memory allocation goes through here.

```
Application calls: open("/etc/passwd", O_RDONLY)
        |
        v
C library (glibc) translates to syscall:
  mov rax, 2        ; syscall number for open()
  syscall           ; CPU traps to kernel
        |
        v
Kernel validates arguments, checks permissions
        |
        v
Kernel performs the operation
        |
        v
Returns result to user space (file descriptor or error)
```

### Syscall Table

Every syscall has a number. Key ones for security:

| Number | Syscall | Security Significance |
|--------|---------|----------------------|
| 0 | read | File/socket reads |
| 1 | write | File/socket writes |
| 2 | open | File access |
| 3 | close | File descriptor management |
| 9 | mmap | Memory mapping — shellcode injection |
| 10 | mprotect | Change memory permissions — making shellcode executable |
| 11 | munmap | Unmap memory |
| 39 | getpid | Process enumeration |
| 56 | clone | Thread/process creation |
| 57 | fork | Process duplication |
| 59 | execve | Execute binary — most monitored syscall |
| 62 | kill | Send signal to process |
| 105 | setuid | Change user identity |
| 110 | getuid | Get current UID |
| 165 | mount | Filesystem mounting |
| 175 | init_module | Load kernel module — rootkit vector |
| 176 | delete_module | Unload kernel module |
| 317 | seccomp | Apply syscall filter |

### auditd and Syscall Monitoring

auditd hooks into the kernel audit framework to capture syscall events. This is how you detect `execve` (process execution), `open` on sensitive files, and `init_module` (kernel module loading) at the kernel level — before any userspace tool can manipulate the view.

```bash
# Monitor all execve syscalls
auditctl -a always,exit -F arch=b64 -S execve -k exec_monitor

# Monitor mprotect (shellcode making memory executable)
auditctl -a always,exit -F arch=b64 -S mprotect -k mprotect_monitor

# Monitor kernel module loading
auditctl -a always,exit -F arch=b64 -S init_module -S delete_module -k kernel_module
```

---

## Kernel Subsystems

The Linux kernel is monolithic — all subsystems run in kernel space as a single binary image.

```
Linux Kernel
    |
    +-- Process Scheduler      (CFS — Completely Fair Scheduler)
    |   Decides which thread runs on which CPU core and when
    |
    +-- Memory Manager         (MM subsystem)
    |   Virtual memory, page tables, demand paging, OOM killer
    |
    +-- Virtual Filesystem     (VFS)
    |   Abstraction layer over ext4, xfs, btrfs, tmpfs, procfs, sysfs
    |
    +-- Network Stack          (net/)
    |   TCP/IP, sockets, netfilter, routing
    |
    +-- Device Drivers         (drivers/)
    |   Block devices, character devices, network interfaces
    |
    +-- Security Subsystem     (security/)
    |   LSM (Linux Security Modules) — SELinux, AppArmor, seccomp
    |
    +-- System Call Interface  (arch/x86/entry/)
        Entry/exit points for syscalls
```

---

## Virtual Filesystem (VFS)

VFS is the abstraction that makes "everything is a file" work. It defines a common interface (open, read, write, close, stat) that all filesystem implementations must provide.

```
Application: open("/proc/1234/maps")
        |
        v
VFS: find inode, determine filesystem type (procfs)
        |
        v
procfs implementation: generate data from kernel process structures
        |
        v
Data returned to application
```

This is why `/proc`, `/sys`, and `/dev` contain no actual disk data — they are VFS implementations backed by kernel data structures, generated on demand.

**Security significance:** A rootkit that hooks VFS function pointers can intercept file operations system-wide — making files invisible to all userspace tools without modifying the files themselves.

---

## Linux Security Modules (LSM)

LSM provides hooks throughout the kernel that security modules use to enforce mandatory access control (MAC).

```
Process calls open("/etc/shadow")
        |
        v
Kernel checks DAC (discretionary access control)
  - file permissions, UID/GID
        |
        v (if DAC passes)
Kernel calls LSM hooks
  - SELinux: does this process type have read permission on shadow_t?
  - AppArmor: is /etc/shadow in this profile's allowed paths?
        |
        v (if LSM passes)
Access granted
```

### SELinux

Labels every process and file with a security context. Access requires both DAC permission and a matching SELinux policy rule.

```bash
# Check SELinux status
getenforce          # Enforcing / Permissive / Disabled
sestatus

# View process context
ps -eZ | grep sshd

# View file context
ls -Z /etc/shadow

# Check SELinux denials
ausearch -m avc -ts recent
grep "denied" /var/log/audit/audit.log
```

### AppArmor

Profile-based MAC. Each confined application has a profile listing what paths, capabilities, and networks it can access.

```bash
# Check AppArmor status
aa-status

# View loaded profiles
cat /sys/kernel/security/apparmor/profiles

# Check AppArmor denials
dmesg | grep -i apparmor
grep "apparmor" /var/log/syslog
```

### seccomp

Filters syscalls available to a process. Used by browsers, containers, and sandboxes to restrict what syscalls a process can make — limiting the kernel attack surface.

```bash
# Check if a process uses seccomp
grep Seccomp /proc/<pid>/status
# 0 = no filter, 1 = strict, 2 = filter mode
```

---

## Memory Layout

Every Linux process sees a virtual address space. The kernel maps this to physical memory using page tables.

```
High addresses (kernel space — not accessible from user space)
0xFFFFFFFFFFFFFFFF
        |
        +-- Kernel code, data, page tables
        |
0xFFFF800000000000 (kernel/user boundary on x86_64)

Low addresses (user space)
0x0000000000000000
        |
        +-- NULL (unmapped, catches null pointer dereferences)
        +-- Text segment (executable code, read-only)
        +-- Data segment (initialized globals)
        +-- BSS (uninitialized globals)
        +-- Heap (grows upward from brk)
        +-- ...
        +-- Memory-mapped regions (mmap — shared libs, anonymous)
        +-- Stack (grows downward)
        +-- vDSO / vsyscall (kernel-provided fast syscall page)
0x00007FFFFFFFFFFF (top of user space)
```

**ASLR (Address Space Layout Randomization):** The kernel randomizes the base addresses of the stack, heap, and mmap regions at each program launch. This makes exploit development harder — the attacker cannot hardcode addresses.

```bash
# Check ASLR status
cat /proc/sys/kernel/randomize_va_space
# 0 = disabled, 1 = partial, 2 = full (default)

# View a process memory layout
cat /proc/<pid>/maps
```

---

## Boot Process

Understanding boot is understanding what runs before your security tools start.

```
Power on
    |
    v
UEFI/BIOS         <- firmware, hardware init, Secure Boot validation
    |
    v
Bootloader (GRUB) <- loads kernel image from /boot/
    |
    v
Kernel init       <- decompresses, initializes subsystems
    |
    v
initramfs         <- temporary root filesystem in RAM
    |               contains drivers needed to mount real root
    v
Real root mounted <- /dev/sda1 or equivalent
    |
    v
PID 1: systemd    <- first userspace process, starts everything else
    |
    v
Targets/services  <- network, logging, SSH, cron...
```

**Persistence at boot level:** Attackers can persist at the bootloader level (GRUB config modification), initramfs level (inject malicious binary into initramfs), or kernel module level (auto-load rootkit via /etc/modules). These techniques survive OS reinstallation if the bootloader/firmware is not also wiped.

```bash
# Check GRUB config
cat /boot/grub/grub.cfg

# Check initramfs contents
lsinitramfs /boot/initrd.img-$(uname -r) | head -50

# Check auto-loaded modules
cat /etc/modules
ls /etc/modprobe.d/
```

---

## Investigation Commands

```bash
# Kernel version and build info
uname -a
cat /proc/version

# Kernel parameters (security settings)
sysctl kernel.randomize_va_space    # ASLR
sysctl kernel.dmesg_restrict        # dmesg access
sysctl kernel.kptr_restrict         # kernel pointer exposure
sysctl net.ipv4.ip_forward          # routing/forwarding
sysctl kernel.perf_event_paranoid   # perf subsystem access

# Check LSM status
cat /sys/kernel/security/lsm        # which LSMs are loaded
getenforce 2>/dev/null              # SELinux
aa-status 2>/dev/null               # AppArmor

# Active syscall filters on processes
for pid in $(ls /proc | grep '^[0-9]'); do
  sec=$(grep Seccomp /proc/$pid/status 2>/dev/null | awk '{print $2}')
  [ "$sec" = "2" ] && echo "PID $pid has seccomp filter"
done

# Kernel ring buffer (boot messages, driver errors, module loading)
dmesg --time-format=iso | tail -100
dmesg | grep -iE "error|warn|module|rootkit|taint"

# Kernel taint flags (indicates non-standard kernel state)
cat /proc/sys/kernel/tainted
# 0 = clean kernel
# Non-zero = something modified the kernel (unsigned module, etc.)
```

---

## Practitioner Notes

**On kernel tainting:** `/proc/sys/kernel/tainted` is a bitmask. A non-zero value means the kernel has been modified in some way — unsigned module loaded, proprietary driver, forced module load. During IR, a tainted kernel on a server that should have no custom modules is a rootkit indicator.

**On ASLR and exploitation:** ASLR makes exploitation harder but not impossible. Information leaks (reading a pointer from /proc or via a bug) defeat ASLR by revealing actual addresses. Kernel exploits often combine an info leak with a write primitive to bypass ASLR.

**On seccomp and containers:** Docker and other container runtimes apply seccomp profiles to restrict what syscalls containers can make. A container breakout often involves finding a syscall that the seccomp profile permits but that allows escaping the namespace isolation.

---

## Knowledge Validation

**What is the security purpose of the user/kernel space split?**
User space processes run in CPU Ring 3 with restricted instruction access and cannot directly touch hardware or kernel memory. The only way to cross into kernel space is via the syscall interface — a controlled gate the kernel manages. This means all hardware access, memory management, and process control is mediated by the kernel, which can enforce permission checks before granting access.

**Why is execve the most monitored syscall from a security perspective?**
execve replaces the current process image with a new program. Every shell command, every script execution, every malware launch goes through execve. Monitoring execve via auditd or eBPF gives visibility into every program that runs on the system — command line arguments, environment, calling process. It is the foundation of process execution monitoring in EDRs and SIEMs.

**What does a non-zero value in /proc/sys/kernel/tainted indicate during an IR investigation?**
The kernel has been modified outside of normal operation — an unsigned module was loaded, a module was force-loaded despite errors, or a proprietary driver is running. On a server that should have no custom kernel modules, a tainted kernel is a strong rootkit indicator. Cross-reference with lsmod, /proc/modules, and /sys/module/ to identify the tainting module.

---

*Linux/00-Architecture | OS-Internals-for-SOC | Solomon James (@Jaysolex)*
