# OS Internals for Security Engineers

> A field reference on operating system internals through the lens of detection, investigation, and response.  
> Built for practitioners — not students.

![Maintained](https://img.shields.io/badge/Maintained-Active-brightgreen)
![Coverage](https://img.shields.io/badge/Coverage-Linux%20%7C%20Windows-blue)
![Frameworks](https://img.shields.io/badge/Frameworks-MITRE%20ATT%26CK%20%7C%20D3FEND-red)
![Detection](https://img.shields.io/badge/Detection-Sigma%20%7C%20SPL%20%7C%20KQL%20%7C%20Wazuh-purple)
![Author](https://img.shields.io/badge/Author-Solomon%20James-black)

---

## What This Is

Most security tooling sits on top of the OS.  
Most practitioners only know the tooling.

When a detection fires, the analyst who understands *why* the OS generated that event works faster, writes better rules, builds better playbooks, and escalates with precision.

This repository is a dissection of Linux and Windows internals — every subsystem, every directory, every kernel mechanism — mapped to attacker technique, defender detection, and operational response.

Every module answers the same four questions:

```
What is the OS actually doing here?
How does an attacker weaponize it?
What artifacts does abuse leave behind?
How do you detect, hunt, and respond?
```

This is not a hacking guide. It is an engineering reference for security professionals who operate on both sides of a compromised system.

---

## Repository Architecture

```
OS-Internals-for-SOC/
│
├── Linux/
│   ├── 00-Architecture              OS design, ring model, syscall interface
│   ├── 01-Filesystem-Hierarchy      Every root directory — purpose, artifacts, abuse
│   ├── 02-Logging-System            rsyslog, journald, auditd, wtmp, btmp
│   ├── 03-Process-Internals         fork/exec, namespaces, signals, /proc/<pid>
│   ├── 04-Proc-Filesystem           /proc as a forensic artifact source
│   ├── 05-Memory-Management         virtual memory, mmap, swap, heap abuse
│   ├── 06-Systemd-Init              units, timers, socket activation, persistence
│   ├── 07-Permissions-Capabilities  DAC, MAC, SUID, capabilities, namespace abuse
│   ├── 08-Networking-Stack          sockets, netfilter, routing, raw socket abuse
│   ├── 09-Persistence-Mechanisms    Full persistence map — every technique
│   ├── 10-User-Account-Internals    passwd, shadow, PAM, sudoers, SSH keys
│   ├── 11-Kernel-Modules            LKM loading, rootkit insertion, detection
│   ├── 12-Forensics-Artifacts       What survives, what doesn't, where to look
│   └── Labs/                        Hands-on exercises with detection validation
│
├── Windows/
│   ├── 00-Architecture              NT architecture, rings, HAL, kernel objects
│   ├── 01-Filesystem-Hierarchy      Every system directory — purpose, artifacts, abuse
│   ├── 02-Registry-Internals        Hive structure, keys, persistence, forensics
│   ├── 03-Process-Internals         PEB, TEB, handles, parent spoofing, hollowing
│   ├── 04-Memory-Management         VAD, page tables, injection techniques
│   ├── 05-Windows-Services          SCM, service types, DLL hijacking
│   ├── 06-Authentication-LSASS      SAM, NTLM, Kerberos, credential dumping
│   ├── 07-Event-Log-System          EVTX structure, critical event IDs, tampering
│   ├── 08-Scheduled-Tasks           Task XML, COM hijack, AT command legacy
│   ├── 09-Networking-Stack          Winsock, raw sockets, DNS, named pipes
│   ├── 10-Persistence-Mechanisms    Full persistence map — every technique
│   ├── 11-WMI-COM-Internals         WMI subscriptions, DCOM abuse, lateral movement
│   ├── 12-Kernel-Drivers            Driver loading, BYOVD, kernel callbacks
│   ├── 13-Forensics-Artifacts       MFT, prefetch, shellbags, LNK, SRUM, AmCache
│   └── Labs/                        Hands-on exercises with detection validation
│
├── Detection-Engineering/
│   ├── Sigma/                       Platform-agnostic detection rules
│   ├── Splunk/                      SPL queries — detection + hunting
│   ├── Sentinel/                    KQL — detection + hunting
│   └── Wazuh/                       Rules, decoders, active response
│
├── Threat-Hunting/                  Hypothesis-driven hunt packages
├── SOAR/
│   ├── Playbooks/                   Response automation by technique
│   └── Workflows/                   Integration diagrams
├── Incident-Response/               IR process anchored to OS artifacts
└── Security-Reference/              MITRE mapping, artifact cheat sheets
```

---

## Module Standard

Every module in this repository is structured identically:

| Section | Content |
|---------|---------|
| **Internals** | What the OS is doing at the kernel/system level |
| **Security Significance** | Why this component matters to defenders |
| **Artifact Map** | What gets written, where, in what format |
| **Attacker Tradecraft** | Real techniques threat actors use against this component |
| **Detection Logic** | What to look for and why it works |
| **Investigation Runbook** | Commands and queries for active investigations |
| **MITRE ATT&CK Mapping** | Technique-level tagging |
| **Detection Rules** | Sigma, SPL, KQL, Wazuh — ready to deploy |
| **Threat Hunt Package** | Hypothesis + queries + expected findings |
| **SOAR Integration** | Trigger → enrich → contain → remediate |
| **Practitioner Notes** | Field-level nuance — edge cases, blind spots, caveats |
| **Knowledge Validation** | Technical questions used to verify depth of understanding |

---

## Coverage Index

### Linux Modules

| Module | Core Topic | MITRE Techniques | Status |
|--------|-----------|-----------------|--------|
| [00 — Architecture](./Linux/00-Architecture/) | Kernel rings, syscall interface, memory layout | — | ✅ |
| [01 — Filesystem Hierarchy](./Linux/01-Filesystem-Hierarchy/) | Every root directory dissected | T1005, T1083, T1552 | ✅ |
| [02 — Logging System](./Linux/02-Logging-System/) | rsyslog, journald, auditd, wtmp | T1070.002, T1562.001 | ✅ |
| [03 — Process Internals](./Linux/03-Process-Internals/) | fork/exec, namespaces, signals | T1055, T1057, T1036 | ✅ |
| [04 — /proc Filesystem](./Linux/04-Proc-Filesystem/) | Live OS state as forensic source | T1057, T1083 | ✅ |
| [05 — Memory Management](./Linux/05-Memory-Management/) | Virtual memory, mmap, heap, swap | T1055, T1620 | ✅ |
| [06 — Systemd & Init](./Linux/06-Systemd-Init/) | Units, timers, socket activation | T1543.002, T1053.006 | ✅ |
| [07 — Permissions & Capabilities](./Linux/07-Permissions-Capabilities/) | DAC, MAC, SUID, Linux capabilities | T1548.001, T1548.003 | ✅ |
| [08 — Networking Stack](./Linux/08-Networking-Stack/) | Sockets, netfilter, routing table | T1049, T1090, T1571 | ✅ |
| [09 — Persistence Mechanisms](./Linux/09-Persistence-Mechanisms/) | Complete Linux persistence map | T1546, T1547, T1053 | ✅ |
| [10 — User Account Internals](./Linux/10-User-Account-Internals/) | passwd, shadow, PAM, sudoers | T1078, T1136, T1098 | ✅ |
| [11 — Kernel Modules](./Linux/11-Kernel-Modules/) | LKM loading, rootkit detection | T1014, T1547.006 | ✅ |
| [12 — Forensics Artifacts](./Linux/12-Forensics-Artifacts/) | What survives and where | T1070, T1564 | ✅ |

### Windows Modules

| Module | Core Topic | MITRE Techniques | Status |
|--------|-----------|-----------------|--------|
| [00 — Architecture](./Windows/00-Architecture/) | NT kernel, HAL, kernel objects, rings | — | ✅ |
| [01 — Filesystem Hierarchy](./Windows/01-Filesystem-Hierarchy/) | Every system directory dissected | T1005, T1083, T1552 | ✅ |
| [02 — Registry Internals](./Windows/02-Registry-Internals/) | Hive structure, persistence keys | T1112, T1547.001 | ✅ |
| [03 — Process Internals](./Windows/03-Process-Internals/) | PEB, TEB, handles, injection | T1055, T1036, T1134 | ✅ |
| [04 — Memory Management](./Windows/04-Memory-Management/) | VAD, page tables, memory injection | T1055, T1620 | ✅ |
| [05 — Windows Services](./Windows/05-Windows-Services/) | SCM, service types, DLL hijacking | T1543.003, T1574 | ✅ |
| [06 — Authentication & LSASS](./Windows/06-Authentication-LSASS/) | SAM, NTLM, Kerberos, LSA secrets | T1003, T1110, T1558 | ✅ |
| [07 — Event Log System](./Windows/07-Event-Log-System/) | EVTX, critical event IDs, tampering | T1070.001, T1562 | ✅ |
| [08 — Scheduled Tasks](./Windows/08-Scheduled-Tasks/) | Task XML, COM hijack, persistence | T1053.005, T1574 | ✅ |
| [09 — Networking Stack](./Windows/09-Networking-Stack/) | Winsock, named pipes, DNS, C2 | T1071, T1090, T1572 | ✅ |
| [10 — Persistence Mechanisms](./Windows/10-Persistence-Mechanisms/) | Complete Windows persistence map | T1547, T1546, T1543 | ✅ |
| [11 — WMI & COM Internals](./Windows/11-WMI-COM-Internals/) | WMI subscriptions, DCOM abuse | T1047, T1546.003 | ✅ |
| [12 — Kernel Drivers](./Windows/12-Kernel-Drivers/) | Driver loading, BYOVD, callbacks | T1014, T1068, T1543 | ✅ |
| [13 — Forensics Artifacts](./Windows/13-Forensics-Artifacts/) | MFT, prefetch, shellbags, SRUM | T1070, T1564 | ✅ |

---

## The Operational Chain

Everything in this repository connects. A module is never an isolated topic.

```
OS Internals
     │
     ▼
Understand normal behavior
     │
     ▼
Identify what attacker abuse looks like by contrast
     │
     ▼
Map the artifacts abuse generates
     │
     ▼
Write detection logic grounded in artifact reality
     │
     ▼
Build hunt hypotheses from attacker tradecraft
     │
     ▼
Automate response via SOAR
     │
     ▼
Reconstruct timelines during IR using the same artifact knowledge
```

The analyst who skips the top of this chain writes brittle detections and misses attacker tradecraft that doesn't match a signature.

---

## MITRE ATT&CK Coverage

```
Reconnaissance       Initial Access      Execution           Persistence
─────────────        ─────────────       ─────────           ───────────
T1592 (host info)    T1078 (accounts)    T1059 (CLI)         T1543 (services)
T1590 (network)      T1190 (exploit)     T1053 (scheduled)   T1547 (boot/logon)
                     T1133 (remote svc)  T1047 (WMI)         T1546 (event trigger)

Privilege Escalation  Defense Evasion     Credential Access   Discovery
────────────────────  ───────────────     ─────────────────   ─────────
T1548 (SUID/sudo)     T1070 (log clear)   T1003 (dumping)     T1057 (process)
T1055 (injection)     T1562 (disable def) T1110 (brute force) T1083 (file/dir)
T1068 (kernel vuln)   T1036 (masquerade)  T1558 (Kerberos)    T1049 (net conns)
T1134 (token manip)   T1014 (rootkit)     T1552 (cred files)  T1018 (remote sys)

Lateral Movement      Collection          C2                  Exfiltration
────────────────      ──────────          ──                  ────────────
T1021 (remote svc)    T1005 (local data)  T1071 (app layer)   T1048 (exfil)
T1570 (tool transfer) T1560 (archive)     T1090 (proxy)       T1041 (C2 channel)
T1550 (pass-the-hash) T1056 (input cap)   T1572 (tunneling)   T1567 (web service)
```

---

## Tools Referenced

| Category | Tools |
|----------|-------|
| SIEM | Splunk Enterprise, Microsoft Sentinel, Elastic SIEM |
| Host-Based Detection | Wazuh, Sysmon, auditd, osquery |
| Detection Language | Sigma, SPL, KQL, Yara |
| Forensics — Linux | Volatility3, LiME, dd, strings, The Sleuth Kit |
| Forensics — Windows | Volatility3, Autopsy, KAPE, Eric Zimmerman Tools, Chainsaw |
| Threat Intel | MISP, OpenCTI, VirusTotal, AbuseIPDB |
| SOAR | Shuffle, TheHive + Cortex |
| Emulation | Atomic Red Team, Caldera |

---

## Author

**Solomon James**  
Security Engineer — Detection, DFIR, OS Internals  
`Splunk` · `Microsoft Sentinel` · `Sigma` · `Wazuh` · `YARA` · `Volatility`

[![GitHub](https://img.shields.io/badge/GitHub-Jaysolex-181717?logo=github)](https://github.com/Jaysolex)

---

*Engineered for security practitioners. Updated continuously.*
