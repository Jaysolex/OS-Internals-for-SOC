# Linux Labs

> Hands-on exercises for every Linux module. Each lab validates understanding through practical application on a live system. All exercises are safe to run on a dedicated lab machine or VM.

**Prerequisites:** Ubuntu/Debian or Kali Linux VM with sudo access.

---

## Lab Index

| Lab | Module | Skill Validated |
|-----|--------|----------------|
| [L01 — Syscall Tracing](./L01-Syscall-Tracing.md) | 00-Architecture | strace, auditd syscall monitoring |
| [L02 — Filesystem Forensics](./L02-Filesystem-Forensics.md) | 01-Filesystem-Hierarchy | Timeline analysis, hidden files, SUID |
| [L03 — Log Analysis](./L03-Log-Analysis.md) | 02-Logging-System | rsyslog, auditd, log gap detection |
| [L04 — Process Investigation](./L04-Process-Investigation.md) | 03-Process-Internals | /proc analysis, deleted binary recovery |
| [L05 — /proc Forensics](./L05-Proc-Forensics.md) | 04-Proc-Filesystem | Live process forensics, memory maps |
| [L06 — Memory Analysis](./L06-Memory-Analysis.md) | 05-Memory-Management | memfd detection, anonymous mappings |
| [L07 — Systemd Persistence](./L07-Systemd-Persistence.md) | 06-Systemd-Init | Unit file analysis, timer detection |
| [L08 — Privilege Escalation](./L08-Privilege-Escalation.md) | 07-Permissions-Capabilities | SUID, capabilities, sudo misconfig |
| [L09 — Network Investigation](./L09-Network-Investigation.md) | 08-Networking-Stack | Reverse shell detection, /proc/net |
| [L10 — Persistence Hunt](./L10-Persistence-Hunt.md) | 09-Persistence-Mechanisms | Full persistence enumeration |
| [L11 — Account Forensics](./L11-Account-Forensics.md) | 10-User-Account-Internals | PAM, sudoers, SSH key analysis |
| [L12 — Rootkit Detection](./L12-Rootkit-Detection.md) | 11-Kernel-Modules | Module comparison, taint detection |
| [L13 — Full IR Simulation](./L13-Full-IR-Simulation.md) | 12-Forensics-Artifacts | End-to-end incident response |
