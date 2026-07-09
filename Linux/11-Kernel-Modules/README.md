# Linux/11 — Kernel Modules

> A kernel module runs in Ring 0 — the same privilege level as the kernel itself. There is no permission model above it, no process isolation containing it, no userspace tool that can reliably detect it once it is active. Understanding how modules work is the foundation of rootkit detection and the reason kernel integrity matters.

![MITRE](https://img.shields.io/badge/MITRE-T1014%20|%20T1547.006%20|%20T1068-red)
![Platform](https://img.shields.io/badge/Platform-Linux-orange)

---

## What Kernel Modules Are

Loadable Kernel Modules (LKMs) are chunks of code that can be inserted into the running kernel without rebooting. They extend kernel functionality — device drivers, filesystem support, network protocols, security modules.

```
User Space
    |
    | insmod / modprobe
    v
Kernel Space (Ring 0)
    |
    +-- Module loaded into kernel address space
    +-- Module registers hooks with kernel subsystems
    +-- Module runs with full kernel privileges
    +-- No memory isolation, no permission checks
```

Once loaded, a module can:
- Hook any kernel function
- Read and write any memory address
- Hide processes, files, and network connections
- Intercept syscalls
- Create kernel-level backdoors

---

## Module Lifecycle

```bash
# Load a module
insmod module.ko              # direct load from file
modprobe module_name          # load by name (searches /lib/modules/)

# Unload a module
rmmod module_name
modprobe -r module_name

# List loaded modules
lsmod

# Get module information
modinfo module_name
modinfo /path/to/module.ko

# Auto-load at boot — add to /etc/modules
echo "module_name" >> /etc/modules

# Module parameters
modprobe module_name param=value
```

---

## Module File Structure

A kernel module is an ELF (Executable and Linkable Format) object file with the `.ko` extension.

```
/lib/modules/<kernel-version>/
    kernel/
        drivers/          hardware drivers
        net/              network protocol modules
        fs/               filesystem modules
        security/         LSM modules (SELinux, AppArmor)
    modules.dep           dependency map
    modules.alias         alias to module name mapping
    modules.builtin       modules compiled into kernel
```

```bash
# Find module location
modinfo snd_hda_intel | grep filename

# List all available modules
find /lib/modules/$(uname -r) -name "*.ko" | wc -l

# Check module dependencies
cat /lib/modules/$(uname -r)/modules.dep | grep module_name
```

---

## Kernel Module Signing

Modern kernels support module signature verification. The kernel checks a cryptographic signature on every module before loading.

```bash
# Check if kernel enforces module signing
cat /proc/sys/kernel/modules_disabled    # 1 = no new modules allowed
grep "CONFIG_MODULE_SIG_FORCE" /boot/config-$(uname -r)
# CONFIG_MODULE_SIG_FORCE=y = only signed modules allowed

# Check module signature
modinfo module_name | grep sig
# sig_id, signer, sig_key, sig_hashalgo

# Check kernel taint from unsigned module
cat /proc/sys/kernel/tainted
# Bit 12 (4096) set = unsigned module loaded
```

---

## Rootkit Architecture

A kernel rootkit uses LKM capability to hide attacker presence. Core techniques:

### Syscall Table Hooking

The kernel maintains a table of function pointers — one per syscall. A rootkit replaces entries with its own functions.

```c
// Original: getdents64 lists directory entries
// Rootkit version: lists all entries EXCEPT those starting with ".rootkit_"

asmlinkage long hooked_getdents64(unsigned int fd,
    struct linux_dirent64 __user *dirent, unsigned int count) {
    // call original
    long ret = original_getdents64(fd, dirent, count);
    // remove hidden entries from result
    // ...
    return modified_ret;
}
```

Result: `ls`, `find`, `ps` — all libc-based tools — cannot see hidden files/processes.

### VFS Hook

Hook Virtual Filesystem function pointers (file_operations, inode_operations) to intercept at filesystem level rather than syscall level — harder to detect.

### Netfilter Hook

Register a Netfilter hook to intercept and drop packets — hiding network connections from packet capture and /proc/net.

### /proc Manipulation

Override the proc_ops for /proc/net/tcp, /proc/<pid>/, etc. to filter out hidden entries.

---

## Rootkit Detection Strategy

The fundamental approach: compare multiple sources that should agree. A rootkit that manipulates one source may miss another.

### Source Comparison

```bash
# Three module list sources — any discrepancy is suspicious
lsmod | awk 'NR>1{print $1}' | sort > /tmp/s1.txt
cat /proc/modules | awk '{print $1}' | sort > /tmp/s2.txt
ls /sys/module/ | sort > /tmp/s3.txt

diff /tmp/s1.txt /tmp/s2.txt && echo "lsmod vs /proc/modules: MATCH" || echo "DISCREPANCY"
diff /tmp/s1.txt /tmp/s3.txt && echo "lsmod vs /sys/module: MATCH" || echo "DISCREPANCY"
```

### Process List Comparison

```bash
# Compare ps (userspace) with /proc (kernel virtual fs)
ps -eo pid | sort > /tmp/ps_pids.txt
ls /proc | grep '^[0-9]' | sort > /tmp/proc_pids.txt

diff /tmp/ps_pids.txt /tmp/proc_pids.txt
# PIDs in /proc but not in ps = rootkit hiding processes
```

### Network Connection Comparison

```bash
# ss uses kernel netlink socket (may be hooked)
# /proc/net/tcp is VFS (may also be hooked by sophisticated rootkit)
# Compare counts as sanity check
ss_count=$(ss -tn | wc -l)
proc_count=$(wc -l < /proc/net/tcp)
echo "ss: $ss_count | /proc/net/tcp: $proc_count"
```

### Kernel Taint Check

```bash
cat /proc/sys/kernel/tainted
# 0 = clean kernel
# Decode bits:
# 1   = proprietary module loaded
# 2   = module force-loaded
# 4   = kernel oops occurred
# 8   = module unloaded
# 16  = taint on warning
# 32  = bad page reference
# 64  = taint on user-space-initiated oops
# 4096 = unsigned module loaded
# 8192 = soft lockup
```

### Check for Hidden Modules via Memory Scan

```bash
# Volatility (offline analysis of memory image)
# vol.py -f memory.lime --profile=LinuxUbuntu_x64 linux_lsmod
# vol.py -f memory.lime --profile=LinuxUbuntu_x64 linux_hidden_modules

# Compare loaded module addresses with kernel symbol table
cat /proc/kallsyms | grep -v "^0000000000000000" | head -20
```

---

## Module Auto-Load Persistence

```bash
# Permanent module loading via /etc/modules
cat /etc/modules
echo "rootkit" >> /etc/modules

# Module configuration (load with parameters)
cat /etc/modprobe.d/
# Attacker creates: /etc/modprobe.d/rootkit.conf
# Contents: install rootkit /sbin/insmod /lib/modules/rootkit.ko

# Alias-based loading (trigger module on device event)
echo "alias net-pf-10 rootkit" > /etc/modprobe.d/alias.conf
```

---

## Investigation Commands

```bash
# Full module audit
echo "=== LOADED MODULES ==="
lsmod

echo "=== UNSIGNED MODULES ==="
for mod in $(lsmod | awk 'NR>1{print $1}'); do
  signer=$(modinfo $mod 2>/dev/null | grep "^signer:" | awk '{print $2}')
  filename=$(modinfo $mod 2>/dev/null | grep "^filename:" | awk '{print $2}')
  [ -z "$signer" ] && echo "UNSIGNED: $mod -> $filename"
done

echo "=== OUT-OF-TREE MODULES ==="
for mod in $(lsmod | awk 'NR>1{print $1}'); do
  filename=$(modinfo $mod 2>/dev/null | grep "^filename:" | awk '{print $2}')
  echo "$filename" | grep -qv "^/lib/modules" && echo "OUT-OF-TREE: $mod -> $filename"
done

echo "=== KERNEL TAINT STATUS ==="
cat /proc/sys/kernel/tainted

echo "=== MODULE SOURCE COMPARISON ==="
diff <(lsmod | awk 'NR>1{print $1}' | sort) <(ls /sys/module/ | sort)

echo "=== AUTO-LOAD CONFIGURATION ==="
cat /etc/modules 2>/dev/null
ls /etc/modprobe.d/ && cat /etc/modprobe.d/*.conf 2>/dev/null

echo "=== RECENT MODULE LOADS (dmesg) ==="
dmesg | grep -iE "module|insmod|modprobe|loaded" | tail -30

echo "=== PROCESS VS /proc COMPARISON ==="
diff <(ps -eo pid | grep -v PID | sort) <(ls /proc | grep '^[0-9]' | sort)
```

---

## Acquiring Memory for Rootkit Analysis

```bash
# LiME (Linux Memory Extractor) — most reliable
# Compile for target kernel version
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules

# Load and dump to file
insmod lime.ko "path=/media/external/memory.lime format=lime"

# Load and dump over network (doesn't touch disk)
insmod lime.ko "path=tcp:4444 format=lime"
# On analyst machine:
nc -l 4444 > memory.lime

# Analyse with Volatility3
vol -f memory.lime linux.lsmod
vol -f memory.lime linux.hidden_modules
vol -f memory.lime linux.pslist
vol -f memory.lime linux.pstree
```

---

## MITRE ATT&CK Mapping

| Technique | ID |
|-----------|-----|
| Rootkit | T1014 |
| Boot/Logon Autostart: Kernel Modules | T1547.006 |
| Exploitation for Privilege Escalation | T1068 |
| Impair Defenses: Disable or Modify Tools | T1562.001 |

---

## Sigma Rule — Kernel Module Loaded

```yaml
title: Kernel Module Loaded Outside Expected Window
id: a3b4c5d6-e7f8-9012-abcd-234567890123
status: stable
description: >
  Detects kernel module loading via insmod or modprobe.
  Legitimate module loads occur during boot or hardware
  changes. Runtime loading by user processes is suspicious.
author: Solomon James (@Jaysolex)
tags:
  - attack.persistence
  - attack.t1547.006
  - attack.defense_evasion
  - attack.t1014
logsource:
  product: linux
  service: auditd
detection:
  selection:
    type: SYSCALL
    syscall:
      - init_module
      - finit_module
  filter_boot:
    auid: 4294967295    # unset auid = system/boot context
  condition: selection and not filter_boot
falsepositives:
  - Admin loading hardware drivers
  - Security tools with kernel components
level: high
```

---

## Practitioner Notes

**On rootkit persistence vs detection:** A well-written kernel rootkit that hooks getdents64 and the process list makes itself invisible to every tool that relies on those interfaces — ls, find, ps, top, netstat. The only reliable detection from a live system uses sources the rootkit hasn't hooked: comparing /proc with ps output, comparing lsmod with /sys/module/, reading /proc/net/tcp directly, and examining kernel taint flags. Memory acquisition with LiME and offline Volatility analysis is the definitive detection method.

**On module signing enforcement:** Secure Boot with module signing enforcement (CONFIG_MODULE_SIG_FORCE) prevents unsigned modules from loading — the kernel rejects them at the insmod/modprobe level. Attackers bypass this with BYOVD (Bring Your Own Vulnerable Driver) — loading a legitimate, signed but vulnerable driver, then exploiting it to execute unsigned code in kernel space. Detection: monitor for loading of known-vulnerable driver hashes.

**On memory acquisition before shutdown:** On a suspected rootkitted system, shutting down before memory acquisition loses all volatile evidence — the rootkit code, hidden process data, and kernel hook table modifications. Acquire memory with LiME first, then image the disk, then power off. The order matters.

---

## Knowledge Validation

**Why is a kernel rootkit fundamentally more powerful than a userspace rootkit?**
A kernel rootkit runs in Ring 0 with the same privilege as the kernel itself. It can modify any kernel data structure, hook any function pointer, and intercept any syscall. Every userspace security tool — ps, ls, netstat, auditd — must go through the kernel to do its work. A kernel rootkit that hooks the right functions makes itself and its artifacts invisible to all of them simultaneously. A userspace rootkit runs in Ring 3 and can only manipulate its own memory and the files it has permission to modify — it cannot intercept kernel functions.

**Three sources report different module lists on a production server. What is your investigation sequence?**
First, note which sources agree and which differ — if lsmod and /sys/module/ match but /proc/modules differs, the rootkit is hooking /proc but missed /sys. If all three differ, the rootkit is more comprehensive. Acquire memory immediately with LiME before the system state changes. Analyse offline with Volatility's linux_lsmod and linux_hidden_modules plugins which scan memory directly rather than using kernel interfaces. Cross-reference kernel taint flags, dmesg for module load messages, and auditd for init_module syscall records.

**What is BYOVD and why does it bypass module signing enforcement?**
Bring Your Own Vulnerable Driver loads a legitimate, cryptographically signed kernel driver that has a known vulnerability. Because it is signed, module signing enforcement allows it to load. The attacker then exploits the vulnerability in the signed driver to achieve arbitrary kernel code execution — running unsigned attacker code in Ring 0 without ever loading an unsigned module. Detection requires maintaining a blocklist of known-vulnerable driver hashes and alerting when they are loaded.

---

*Linux/11-Kernel-Modules | OS-Internals-for-SOC | Solomon James (@Jaysolex)*
