# Linux/03 — Process Internals

> On Linux, everything is a file and every execution is a process. The process model — how the kernel creates, tracks, and destroys processes — is the foundation of both attacker tradecraft and defender detection. Injection, evasion, persistence, and privilege escalation all operate within this model.

![MITRE](https://img.shields.io/badge/MITRE-T1055%20|%20T1057%20|%20T1036%20|%20T1106-red)
![Platform](https://img.shields.io/badge/Platform-Linux-orange)

---

## Process Model Architecture

```
Kernel
  |
  +-- task_struct (kernel process descriptor)
  |       |
  |       +-- PID, PPID, UID, GID
  |       +-- credentials (real/effective/saved UIDs)
  |       +-- file descriptor table
  |       +-- memory descriptor (mm_struct)
  |       +-- signal handlers
  |       +-- namespace memberships
  |
  +-- Virtual address space (mm_struct)
          |
          +-- text segment    (executable code)
          +-- data segment    (initialized globals)
          +-- BSS segment     (uninitialized globals)
          +-- heap            (malloc, grows up)
          +-- mmap regions    (shared libs, anonymous maps)
          +-- stack           (grows down)
          +-- vDSO/vsyscall   (kernel-provided fast syscall page)
```

---

## Process Creation — fork and exec

Linux creates processes through two syscalls used in sequence.

### fork()

Creates an exact copy of the calling process. Copy-on-write (COW) — memory pages are shared until either process writes, at which point a private copy is made.

```c
pid_t pid = fork();
if (pid == 0) {
    // child process
} else {
    // parent process, pid = child's PID
}
```

After fork, child inherits: open file descriptors, signal handlers, environment variables, memory mappings, credentials.

### exec()

Replaces the current process image with a new program. Does not create a new process — transforms the existing one.

```c
execve("/bin/bash", args, env);
// process image is now bash
// PID remains the same
// open FDs remain (unless O_CLOEXEC set)
```

Security significance: File descriptors not marked O_CLOEXEC survive exec — a common credential leakage vector.

### clone()

The underlying syscall for both threads and processes. Allows fine-grained control over what is shared between parent and child.

```c
clone(fn, stack, CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_THREAD, arg)
// CLONE_VM = share address space (thread)
// without CLONE_VM = separate address space (process)
```

---

## /proc — The Live Process Interface

Every running process has a directory under `/proc/<pid>/`. This is not on disk — it is a virtual filesystem maintained by the kernel exposing live process state.

```
/proc/<pid>/
  exe         symlink to the executable on disk
  cmdline     full command line (null-delimited)
  maps        memory map — all mapped regions
  mem         process memory (readable with ptrace)
  fd/         open file descriptors
  environ     environment variables at launch
  status      process state, UID, GID, memory
  stat        process statistics
  net/        network state as seen by this process
  cwd         symlink to current working directory
  root        symlink to process root (chroot)
  ns/         namespace memberships
  task/       threads within this process
```

### Forensic Use of /proc

```bash
# Find process running from deleted binary
ls -la /proc/*/exe 2>/dev/null | grep deleted

# Recover deleted binary from memory
cp /proc/<pid>/exe /tmp/recovered

# Read full command line
cat /proc/<pid>/cmdline | tr '\0' ' '

# Check environment for credentials
cat /proc/<pid>/environ | tr '\0' '\n' | grep -iE "pass|token|key|secret"

# See all open files
ls -la /proc/<pid>/fd/

# Read memory map
cat /proc/<pid>/maps

# Check namespace memberships
ls -la /proc/<pid>/ns/
```

---

## Credentials and UIDs

Every Linux process has four credential sets:

| Type | Purpose |
|------|---------|
| Real UID (ruid) | Who launched the process |
| Effective UID (euid) | What permissions the process has now |
| Saved UID (suid) | Allows dropping and regaining euid |
| Filesystem UID (fsuid) | Used for filesystem access checks |

### SUID Mechanism

When a SUID binary executes, the kernel sets euid to the file owner's UID (often root). The process gains elevated privileges temporarily.

```bash
# Find SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Classic SUID privilege escalation
# If /usr/bin/vim is SUID root:
vim -c ':!/bin/bash'
# bash spawns with euid=0
```

Detection: Execution of unusual SUID binaries — any SUID file not in the known-good baseline.

---

## Namespaces

Linux namespaces isolate process views of system resources. Each namespace type controls what a process can see.

| Namespace | Isolates | Security Use |
|-----------|---------|--------------|
| `mnt` | Filesystem mounts | Container filesystem isolation |
| `pid` | Process IDs | Containers have their own PID 1 |
| `net` | Network interfaces, routing | Container network isolation |
| `uts` | Hostname, domain name | Per-container hostname |
| `ipc` | System V IPC, POSIX message queues | IPC isolation |
| `user` | UIDs and GIDs | Unprivileged containers |
| `cgroup` | cgroup root | Resource limit isolation |

### Namespace Security Significance

An attacker who escapes a container namespace gains access to the host namespace. Namespace escape is a container breakout technique.

```bash
# Check what namespaces a process is in
ls -la /proc/<pid>/ns/

# Check if current process is in a container
# (different ns from PID 1 = containerized)
ls -la /proc/1/ns/pid
ls -la /proc/$$/ns/pid
# If different inodes = we are in a container

# Escape via nsenter (requires capabilities)
nsenter --target 1 --mount --uts --ipc --net --pid
```

---

## Signals

Signals are asynchronous notifications sent to processes. Used legitimately for process control — also abused for evasion.

| Signal | Number | Default Action | Common Use |
|--------|--------|---------------|------------|
| SIGHUP | 1 | Terminate | Reload config (daemons) |
| SIGINT | 2 | Terminate | Ctrl+C |
| SIGKILL | 9 | Terminate | Cannot be caught or ignored |
| SIGSEGV | 11 | Core dump | Segmentation fault |
| SIGTERM | 15 | Terminate | Graceful shutdown |
| SIGSTOP | 19 | Stop | Cannot be caught or ignored |
| SIGCONT | 18 | Continue | Resume stopped process |

```bash
# Send signal to process
kill -SIGTERM <pid>
kill -9 <pid>

# Attacker use: SIGKILL audit daemon
kill -9 $(pgrep auditd)    # kills auditd — requires root
```

Detection: SIGKILL sent to security-critical processes (auditd, wazuh, osquery).

---

## Process Injection on Linux

### ptrace Injection

ptrace is the system call used by debuggers. It allows one process to read/write another's memory and registers.

```c
ptrace(PTRACE_ATTACH, target_pid, NULL, NULL);
// now can read/write target memory
ptrace(PTRACE_POKEDATA, target_pid, addr, shellcode);
ptrace(PTRACE_SETREGS, target_pid, NULL, &regs);  // redirect RIP
ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
```

Detection: auditd rule on ptrace syscall from unexpected processes. Process being ptrace'd shows `TracerPid` in `/proc/<pid>/status`.

```bash
# Check if a process is being debugged/traced
grep TracerPid /proc/<pid>/status
# TracerPid: 0 = not traced
# TracerPid: <pid> = being traced by this PID
```

### /proc/mem Injection

Write directly to process memory via `/proc/<pid>/mem` — no ptrace required if you own the process.

```bash
# Check if process mem is writable
ls -la /proc/<pid>/mem
```

### LD_PRELOAD Injection

Force a shared library to load before all others — intercepts libc function calls.

```bash
# Per-process injection
LD_PRELOAD=/path/to/evil.so /bin/ls

# System-wide injection
echo "/path/to/evil.so" > /etc/ld.so.preload
```

Detection: `/etc/ld.so.preload` should be empty. Any entry is a critical finding.

### Shared Library Injection via ldconfig

Plant a malicious `.so` in a library search path, run `ldconfig` to register it. Subsequent programs that link against the spoofed library load the malicious version.

---

## Process Masquerading

### Binary Name Masquerading

Place malicious binary with legitimate name in unexpected path.

```bash
# Legitimate
/bin/bash

# Malicious
/tmp/bash
/dev/shm/sshd
/var/tmp/.bash
```

Detection: Process name matches known system binary but path does not match expected location.

### Argv[0] Manipulation

A process can change its own argv[0] — what appears in `ps` output.

```c
// Attacker renames process in ps output
strcpy(argv[0], "[kworker/0:1]");
// now appears as a kernel worker thread in ps
```

Detection: Cross-reference `/proc/<pid>/exe` (real binary) against `cmdline` argv[0]. Kernel workers don't have a userspace exe path — if `/proc/<pid>/exe` points to a user binary but cmdline shows a kernel thread name, it is masquerading.

```bash
# Find masquerading processes
for pid in $(ls /proc | grep '^[0-9]'); do
  exe=$(readlink /proc/$pid/exe 2>/dev/null)
  cmdline=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')
  if [ -n "$exe" ]; then
    echo "PID:$pid EXE:$exe CMD:$cmdline"
  fi
done | grep -E "kworker|kthread|migration" | grep -v "^\[k"
```

---

## Investigation Commands

```bash
# Full process list with parent
ps auxef

# Process tree
pstree -ap

# Find processes running from deleted binaries
ls -la /proc/*/exe 2>/dev/null | grep "(deleted)"

# Check all process executables
for pid in $(ls /proc | grep '^[0-9]$'); do
  exe=$(readlink /proc/$pid/exe 2>/dev/null)
  [ -n "$exe" ] && echo "PID $pid: $exe"
done

# Find processes with unusual parent (PPID 1 = orphaned)
ps -eo pid,ppid,user,cmd | awk '$2==1 && $3!="root"'

# Check for ptrace on any process
grep -r "TracerPid" /proc/*/status 2>/dev/null | grep -v "TracerPid:	0"

# Open network connections per process
ss -tnap
cat /proc/net/tcp

# Memory map of suspicious process
cat /proc/<pid>/maps

# Find executable anonymous mappings (shellcode indicator)
cat /proc/<pid>/maps | grep -E "rwx|r-x" | grep -v "\.so\|\.bin\|exe"

# Environment variables (credential hunting)
strings /proc/<pid>/environ

# Check for LD_PRELOAD
cat /etc/ld.so.preload 2>/dev/null || echo "Clean"
grep LD_PRELOAD /proc/*/environ 2>/dev/null

# Recover binary from running process
cp /proc/<pid>/exe /tmp/recovered_$(date +%s)
file /tmp/recovered_*
strings /tmp/recovered_* | head -100
```

---

## MITRE ATT&CK Mapping

| Technique | ID |
|-----------|-----|
| Process Injection: ptrace | T1055.008 |
| Process Injection: LD_PRELOAD | T1574.006 |
| Process Discovery | T1057 |
| Masquerading: Match Legitimate Name | T1036.005 |
| Native API | T1106 |
| Exploitation for Privilege Escalation | T1068 |
| SUID/GUID Abuse | T1548.001 |

---

## Sigma Rule — Suspicious Process from /tmp

```yaml
title: Process Execution from Temporary Directory
id: e5f6a7b8-c9d0-1234-efab-345678901234
status: stable
description: >
  Detects process execution originating from /tmp, /var/tmp,
  or /dev/shm. Legitimate software does not execute from these
  directories. Common attacker staging and execution locations.
author: Solomon James (@Jaysolex)
tags:
  - attack.execution
  - attack.t1059
  - attack.defense_evasion
  - attack.t1036
logsource:
  product: linux
  service: auditd
detection:
  selection:
    type: EXECVE
    a0|startswith:
      - '/tmp/'
      - '/var/tmp/'
      - '/dev/shm/'
  condition: selection
falsepositives:
  - Some package installers extract to /tmp during installation
level: high
```

---

## Practitioner Notes

**On deleted binary processes:** A process whose binary was deleted after launch is a common attacker technique — execute payload, delete binary from disk, process runs in memory. The binary path in `/proc/<pid>/exe` shows `(deleted)`. The binary is still recoverable by copying from `/proc/<pid>/exe` while the process runs.

**On anonymous executable mappings:** Legitimate processes map code from files — shared libraries, executables. A memory region that is executable but has no file backing (`maps` shows no filename in the last column) is shellcode or a reflectively-loaded payload. This is detectable without AV by scanning `/proc/<pid>/maps`.

**On ptrace detection:** When a process is being traced via ptrace, its `/proc/<pid>/status` shows `TracerPid` as non-zero. During live IR, checking this across all processes quickly identifies any process under active debugging or injection.

---

## Knowledge Validation

**What is the difference between fork() and exec() and why does the sequence matter for security?**
fork() creates a child process as a copy of the parent — same memory, same open file descriptors, same environment. exec() replaces the current process image with a new program. File descriptors survive exec unless marked O_CLOEXEC. This matters because credentials, tokens, or socket connections in the parent survive into the child unless explicitly closed — a credential leakage vector.

**How does ptrace-based injection work and what kernel-level artifact does it leave?**
ptrace attaches to a running process, uses PTRACE_POKEDATA to write shellcode into its memory, redirects the instruction pointer via PTRACE_SETREGS, then detaches. The kernel records the tracing relationship — detectable via TracerPid in `/proc/<pid>/status` while the injection is in progress, and via auditd ptrace syscall records after the fact.

**A process shows as kworker/0:1 in ps but /proc/pid/exe points to /tmp/.x. What is happening?**
The process manipulated its own argv[0] to masquerade as a kernel worker thread. Kernel threads do not have a userspace exe path — they show nothing in `/proc/<pid>/exe`. The presence of a userspace path combined with a kernel thread name in cmdline is definitive evidence of argv[0] masquerading.

---

*Linux/03-Process-Internals | OS-Internals-for-SOC | Solomon James (@Jaysolex)*
