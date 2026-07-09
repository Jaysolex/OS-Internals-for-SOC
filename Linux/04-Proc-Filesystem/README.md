# Linux/04 — The /proc Filesystem

> /proc is not a filesystem in the traditional sense. Nothing in it exists on disk. It is a window the kernel opens into its own internal state — every running process, every network connection, every kernel parameter exposed as a readable file. For security engineers, /proc is the most powerful live forensic tool on the system.

![MITRE](https://img.shields.io/badge/MITRE-T1057%20|%20T1083%20|%20T1070%20|%20T1036-red)
![Platform](https://img.shields.io/badge/Platform-Linux-orange)

---

## What /proc Is

/proc is a virtual filesystem (procfs) maintained entirely by the kernel in memory. Reading a file in /proc triggers a kernel function that generates the content on demand from live kernel data structures. Writing to certain files changes kernel behavior in real time.

```
/proc
  |
  +-- /proc/<pid>/       one directory per running process
  +-- /proc/net/         network state (kernel perspective)
  +-- /proc/sys/         kernel tunables (read/write)
  +-- /proc/modules      loaded kernel modules
  +-- /proc/mounts       mounted filesystems
  +-- /proc/meminfo      memory usage
  +-- /proc/cpuinfo      CPU details
  +-- /proc/version      kernel version string
  +-- /proc/uptime       system uptime
  +-- /proc/loadavg      load averages
  +-- /proc/self/        shortcut — refers to reading process
```

---

## Per-Process Directory /proc/pid

Every running process has a directory named by its PID. This directory disappears when the process exits.

```
/proc/<pid>/
  exe         symlink to the executable binary on disk
  cmdline     full command line, null-delimited
  maps        memory map — every region mapped into the process
  mem         raw process memory (readable with ptrace permission)
  fd/         directory of open file descriptors (symlinks)
  fdinfo/     additional info per file descriptor
  environ     environment variables at launch (null-delimited)
  status      human-readable process state
  stat        machine-readable process statistics
  statm       memory usage in pages
  cwd         symlink to current working directory
  root        symlink to process root directory (chroot detection)
  ns/         namespace memberships (symlinks to namespace inodes)
  net/        network state as seen by this process namespace
  task/       one subdirectory per thread
  oom_score   OOM killer score
  loginuid    audit login UID (set at login, survives privilege changes)
  attr/       LSM security attributes (SELinux context etc.)
```

---

## /proc/pid/exe — The Binary Link

Symlink pointing to the actual executable that launched this process. The kernel maintains this link even if the binary is deleted from disk after launch.

```bash
# View all process binaries
ls -la /proc/*/exe 2>/dev/null

# CRITICAL: find processes running from deleted binaries
ls -la /proc/*/exe 2>/dev/null | grep "(deleted)"

# Recover a deleted binary while process still runs
pid=1234
cp /proc/$pid/exe /tmp/recovered_binary
file /tmp/recovered_binary
strings /tmp/recovered_binary | grep -iE "http|exec|bash|connect"
```

**Why this matters:** Malware frequently deletes its binary from disk after execution to eliminate the file-based IOC. The process continues running in memory. /proc/pid/exe preserves the link — and the binary is still recoverable by copying the symlink target while the process lives.

---

## /proc/pid/cmdline — Full Command Line

The complete command line used to launch the process, with arguments separated by null bytes.

```bash
# Read command line cleanly
cat /proc/<pid>/cmdline | tr '\0' ' '

# Check all process command lines
for pid in $(ls /proc | grep '^[0-9]'); do
  cmdline=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')
  [ -n "$cmdline" ] && echo "PID $pid: $cmdline"
done

# Find encoded payloads
for pid in $(ls /proc | grep '^[0-9]'); do
  cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ' | \
    grep -iE "base64|enc|encoded|-e [A-Za-z0-9+/]{20}" && echo "PID: $pid"
done
```

**Argv[0] spoofing:** A process can overwrite its own cmdline in memory to hide its true arguments. /proc/pid/cmdline reflects the current in-memory state — potentially spoofed. Cross-reference with auditd execve records which capture arguments at kernel level before the process can modify them.

---

## /proc/pid/maps — Memory Map

Shows every memory region mapped into the process address space — executable code, shared libraries, anonymous mappings, file-backed mappings.

```bash
cat /proc/<pid>/maps
```

Output format:
```
address           perms offset  dev   inode   pathname
7f8b4c000000-7f8b4c021000 r--p 00000000 fd:01 1234567  /usr/lib/x86_64-linux-gnu/libc.so.6
7f8b4c021000-7f8b4c176000 r-xp 00021000 fd:01 1234567  /usr/lib/x86_64-linux-gnu/libc.so.6
7fff12340000-7fff12361000 rw-p 00000000 00:00 0        [stack]
7fff1238f000-7fff12393000 r--p 00000000 00:00 0        [vvar]
```

**Security analysis of maps:**

```bash
# Find executable anonymous mappings (shellcode indicator)
# Legitimate code is always file-backed
cat /proc/<pid>/maps | awk '{
  if ($2 ~ /x/ && $6 == "") print "EXEC ANON: " $0
}'

# Find rwx regions (writable AND executable — dangerous)
cat /proc/<pid>/maps | grep "rwx"

# List all loaded libraries for a process
cat /proc/<pid>/maps | grep "\.so" | awk '{print $6}' | sort -u

# Find regions with no file backing (anonymous)
cat /proc/<pid>/maps | awk '$6=="" {print}'
```

---

## /proc/pid/fd — Open File Descriptors

Directory containing symlinks — one per open file descriptor. Shows every file, socket, pipe, and device the process has open.

```bash
# List open files for a process
ls -la /proc/<pid>/fd/

# Find processes with open network sockets
ls -la /proc/<pid>/fd/ | grep socket

# Find deleted files still open (common in log clearing)
ls -la /proc/<pid>/fd/ | grep "(deleted)"

# Recover data from deleted file still held open
# If a process deleted a log file but still has it open:
cat /proc/<pid>/fd/<fd_number> > /tmp/recovered_log
```

**Deleted file recovery:** When a process opens a file then the file is deleted, the inode remains allocated as long as the process holds the file descriptor. The data is accessible via /proc/pid/fd/. This is how you recover log files that were deleted while a logging daemon still had them open.

---

## /proc/pid/environ — Environment Variables

The environment variables present when the process was launched. May contain credentials, tokens, API keys, or configuration secrets.

```bash
# Read environment cleanly
cat /proc/<pid>/environ | tr '\0' '\n'

# Scan all processes for credential patterns
for pid in $(ls /proc | grep '^[0-9]'); do
  env=$(cat /proc/$pid/environ 2>/dev/null | tr '\0' '\n')
  if echo "$env" | grep -qiE "password|token|secret|api_key|aws_secret|private_key"; then
    echo "=== PID $pid ==="
    echo "$env" | grep -iE "password|token|secret|api_key|aws_secret|private_key"
  fi
done
```

---

## /proc/pid/status — Process State

Human-readable summary of process state including credential information.

```bash
cat /proc/<pid>/status
```

Key fields:
```
Name:     sshd                  process name
State:    S (sleeping)
Pid:      1234
PPid:     1                     parent PID
TracerPid: 0                    0=not traced, non-zero=being debugged
Uid:      0  0  0  0           real, effective, saved, filesystem UID
Gid:      0  0  0  0           real, effective, saved, filesystem GID
VmRSS:    4096 kB              resident memory
Seccomp:  2                     0=none, 1=strict, 2=filter
```

```bash
# Find processes being traced (ptrace injection indicator)
grep -l "TracerPid:" /proc/*/status 2>/dev/null | while read f; do
  pid=$(echo $f | awk -F/ '{print $3}')
  tracer=$(grep TracerPid $f | awk '{print $2}')
  [ "$tracer" != "0" ] && echo "PID $pid is being traced by PID $tracer"
done

# Find processes with elevated effective UID
grep -l "^Uid:" /proc/*/status 2>/dev/null | while read f; do
  uid_line=$(grep "^Uid:" $f)
  euid=$(echo $uid_line | awk '{print $3}')
  ruid=$(echo $uid_line | awk '{print $2}')
  [ "$euid" = "0" ] && [ "$ruid" != "0" ] && echo "SUID escalation: $f"
done
```

---

## /proc/net — Network State from the Kernel

Network state as maintained by the kernel — bypasses userspace tools that a rootkit might manipulate.

```
/proc/net/tcp       IPv4 TCP connections (hex encoded)
/proc/net/tcp6      IPv6 TCP connections
/proc/net/udp       UDP sockets
/proc/net/udp6      IPv6 UDP sockets
/proc/net/unix      Unix domain sockets
/proc/net/if_inet6  IPv6 interface addresses
/proc/net/route     routing table
/proc/net/arp       ARP cache
/proc/net/dev       network interface statistics
```

**Rootkit detection via /proc/net:**

```bash
# Get connection count from kernel
kernel_conns=$(wc -l < /proc/net/tcp)

# Get connection count from userspace tool
ss_conns=$(ss -tn | wc -l)

echo "Kernel sees: $kernel_conns TCP entries"
echo "ss sees: $ss_conns TCP connections"
# Significant difference = rootkit hiding connections

# Parse /proc/net/tcp manually (hex to decimal)
awk 'NR>1 {
  split($2, local, ":");
  split($3, remote, ":");
  printf "Local: %d.%d.%d.%d:%d Remote: %d.%d.%d.%d:%d State: %s\n",
    strtonum("0x"substr(local[1],7,2)),
    strtonum("0x"substr(local[1],5,2)),
    strtonum("0x"substr(local[1],3,2)),
    strtonum("0x"substr(local[1],1,2)),
    strtonum("0x"local[2]),
    strtonum("0x"substr(remote[1],7,2)),
    strtonum("0x"substr(remote[1],5,2)),
    strtonum("0x"substr(remote[1],3,2)),
    strtonum("0x"substr(remote[1],1,2)),
    strtonum("0x"remote[2]),
    $4
}' /proc/net/tcp
```

---

## /proc/sys — Kernel Tunables

Kernel parameters readable and writable via /proc/sys. Equivalent to sysctl.

```
/proc/sys/kernel/
  randomize_va_space    ASLR (0=off, 1=partial, 2=full)
  dmesg_restrict        restrict dmesg to root (0/1)
  kptr_restrict         hide kernel pointers (0/1/2)
  perf_event_paranoid   perf subsystem access level
  tainted               kernel taint flags
  hostname              system hostname
  pid_max               maximum PID value

/proc/sys/net/ipv4/
  ip_forward            packet forwarding (0/1) — pivot indicator
  tcp_syncookies        SYN flood protection
  conf/all/accept_redirects   ICMP redirect acceptance

/proc/sys/fs/
  file-max              maximum open files system-wide
```

```bash
# Security-relevant kernel parameters
cat /proc/sys/kernel/randomize_va_space
cat /proc/sys/kernel/dmesg_restrict
cat /proc/sys/kernel/kptr_restrict
cat /proc/sys/kernel/tainted
cat /proc/sys/net/ipv4/ip_forward

# Attacker disabling ASLR
echo 0 > /proc/sys/kernel/randomize_va_space

# Attacker enabling IP forwarding (pivot setup)
echo 1 > /proc/sys/net/ipv4/ip_forward
```

**Detection:** Monitor /proc/sys writes via auditd. Changes to randomize_va_space, ip_forward, or dmesg_restrict outside maintenance windows are suspicious.

---

## /proc/modules — Loaded Kernel Modules

```bash
cat /proc/modules
```

Format:
```
module_name  size  refcount  used_by  state  address
nf_conntrack 172032 3 xt_conntrack,nf_nat,iptable_nat - Live 0xffffffffc0a12000
```

**Rootkit detection:**

```bash
# Three sources — a rootkit may manipulate one but not all
lsmod | awk 'NR>1{print $1}' | sort > /tmp/lsmod.txt
cat /proc/modules | awk '{print $1}' | sort > /tmp/proc_modules.txt
ls /sys/module/ | sort > /tmp/sys_modules.txt

diff /tmp/lsmod.txt /tmp/proc_modules.txt && echo "lsmod vs /proc/modules: MATCH"
diff /tmp/lsmod.txt /tmp/sys_modules.txt && echo "lsmod vs /sys/module: MATCH"
# Any difference = investigate
```

---

## /proc/self — The Self-Referential Shortcut

/proc/self is a symlink to /proc/<pid-of-reading-process>. Any process reading /proc/self/maps sees its own memory map, /proc/self/fd sees its own file descriptors, etc.

Useful for scripts that need to inspect their own state without knowing their PID.

---

## Full /proc Forensic Workflow

```bash
#!/usr/bin/env bash
# Quick /proc triage for live investigation

echo "=== PROCESSES WITH DELETED BINARIES ==="
ls -la /proc/*/exe 2>/dev/null | grep "(deleted)"

echo "=== PROCESSES BEING TRACED (ptrace) ==="
grep -r "TracerPid" /proc/*/status 2>/dev/null | grep -v "TracerPid:	0"

echo "=== ANONYMOUS EXECUTABLE MEMORY REGIONS ==="
for pid in $(ls /proc | grep '^[0-9]'); do
  maps=/proc/$pid/maps
  [ -r "$maps" ] && awk -v pid=$pid '
    $2~/x/ && $6=="" {print "PID " pid ": " $0}
  ' $maps
done

echo "=== CREDENTIAL PATTERNS IN PROCESS ENVIRONMENTS ==="
for pid in $(ls /proc | grep '^[0-9]'); do
  cat /proc/$pid/environ 2>/dev/null | tr '\0' '\n' | \
    grep -iE "password|token|secret|key" | \
    while read line; do echo "PID $pid: $line"; done
done

echo "=== IP FORWARDING STATUS ==="
cat /proc/sys/net/ipv4/ip_forward

echo "=== KERNEL TAINT STATUS ==="
taint=$(cat /proc/sys/kernel/tainted)
[ "$taint" = "0" ] && echo "Clean" || echo "TAINTED: $taint"

echo "=== NETWORK CONNECTION COMPARISON ==="
echo "Kernel /proc/net/tcp entries: $(wc -l < /proc/net/tcp)"
echo "ss -tn entries: $(ss -tn | wc -l)"
```

---

## MITRE ATT&CK Mapping

| Technique | ID | /proc Relevance |
|-----------|-----|----------------|
| Process Discovery | T1057 | /proc/pid/status, /proc/pid/cmdline |
| File and Directory Discovery | T1083 | /proc/pid/fd, /proc/pid/maps |
| Hide Artifacts | T1564 | Rootkits manipulate /proc visibility |
| Masquerading | T1036 | /proc/pid/exe vs cmdline discrepancy |
| Credential from Process Memory | T1003 | /proc/pid/mem, /proc/pid/environ |
| Network Connection Discovery | T1049 | /proc/net/tcp bypasses rootkit tools |

---

## Practitioner Notes

**On /proc/net as a rootkit bypass:** A rootkit that hooks the `getdents` syscall can hide entries from `ls` and `ps` — but /proc/net/tcp is generated by the kernel's network subsystem independently. A rootkit that hides a network connection from `ss` or `netstat` but cannot modify /proc/net will still expose the connection there. Always check /proc/net directly during IR.

**On /proc/pid/loginuid:** The loginuid in /proc/pid/loginuid is set at the time of initial login and is not changed by su, sudo, or any other privilege change. It records the original login UID throughout a session. This is how auditd's auid field identifies who was originally logged in even when acting as root — critical for attribution during IR.

**On /proc/pid/mem access:** Reading /proc/pid/mem requires either being the process itself, having ptrace permission over the process, or being root. A process that opens /proc/other_pid/mem and reads from it is performing memory introspection — legitimate for debuggers, suspicious for arbitrary processes. Monitor with auditd.

---

## Knowledge Validation

**A security tool shows no suspicious network connections but you suspect a rootkit. How do you use /proc to verify?**
Read /proc/net/tcp directly — this is generated by the kernel network subsystem and is not affected by userspace rootkit hooks on getdents or readdir. Compare the number of entries in /proc/net/tcp against the output of ss or netstat. Parse the hex-encoded addresses manually or with awk. Any connection visible in /proc/net/tcp but absent from ss indicates active connection hiding.

**Why is /proc/pid/loginuid forensically more reliable than checking the current UID during an investigation?**
loginuid is set once at initial login by the PAM login module and written to /proc/pid/loginuid. It cannot be changed by the process itself — only the kernel audit system manages it. Subsequent su, sudo, or privilege changes do not alter it. This means even a process running as root can be traced back to the original login account via loginuid, providing reliable attribution that current UID checks cannot.

**A process shows cmdline as [kworker/0:1] but /proc/pid/exe points to /tmp/.x. What is this and what do you do?**
This is argv[0] masquerading — the process overwrote its own command line in memory to impersonate a kernel worker thread. Kernel threads have no userspace exe path. The presence of a path in /proc/pid/exe combined with a kernel thread name in cmdline is definitive. Copy the binary via /proc/pid/exe for analysis, kill the process, check /tmp for related files, review auditd execve records for when /tmp/.x was launched and what launched it.

---

*Linux/04-Proc-Filesystem | OS-Internals-for-SOC | Solomon James (@Jaysolex)*
