# OS Internals for Security Engineers

> A field reference on operating system internals through the lens of detection, investigation, and response.  
> Built for practitioners — not students.

![Maintained](https://img.shields.io/badge/Maintained-Active-brightgreen)
![Modules](https://img.shields.io/badge/Modules-27%20Complete-blue)
![Coverage](https://img.shields.io/badge/Coverage-Linux%20%7C%20Windows-orange)
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

---

## Repository Architecture

```
OS-Internals-for-SOC/
│
├── Linux/                           13 modules — complete
│   ├── 00-Architecture              OS design, ring model, syscall interface
│   ├── 01-Filesystem-Hierarchy      Every root directory — purpose, artifacts, abuse
│   ├── 02-Logging-System            rsyslog, journald, auditd, wtmp, btmp
│   ├── 03-Process-Internals         fork/exec, namespaces, signals, /proc/<pid>
│   ├── 04-Proc-Filesystem           /proc as a live forensic artifact source
│   ├── 05-Memory-Management         virtual memory, mmap, swap, memfd, heap abuse
│   ├── 06-Systemd-Init              units, timers, socket activation, persistence
│   ├── 07-Permissions-Capabilities  DAC, MAC, SUID, Linux capabilities
│   ├── 08-Networking-Stack          sockets, netfilter, routing, reverse shells
│   ├── 09-Persistence-Mechanisms    Complete Linux persistence map
│   ├── 10-User-Account-Internals    passwd, shadow, PAM, sudoers, SSH keys
│   ├── 11-Kernel-Modules            LKM loading, rootkit detection, BYOVD
│   ├── 12-Forensics-Artifacts       What survives, what doesn't, where to look
│   └── Labs/
│
├── Windows/                         14 modules — complete
│   ├── 00-Architecture              NT kernel, HAL, kernel objects, rings
│   ├── 01-Filesystem-Hierarchy      Every system directory — artifacts, abuse
│   ├── 02-Registry-Internals        Hive structure, persistence keys, forensics
│   ├── 03-Process-Internals         PEB, TEB, handles, injection, hollowing
│   ├── 04-Memory-Management         VAD, page tables, injection, pagefile
│   ├── 05-Windows-Services          SCM, service types, DLL hijacking
│   ├── 06-Authentication-LSASS      SAM, NTLM, Kerberos, credential dumping
│   ├── 07-Event-Log-System          EVTX, critical event IDs, log tampering
│   ├── 08-Scheduled-Tasks           Task XML, COM hijack, persistence
│   ├── 09-Networking-Stack          Winsock, named pipes, DNS, C2 channels
│   ├── 10-Persistence-Mechanisms    Complete Windows persistence map
│   ├── 11-WMI-COM-Internals         WMI subscriptions, DCOM, COM hijacking
│   ├── 12-Kernel-Drivers            Driver loading, BYOVD, kernel callbacks
│   ├── 13-Forensics-Artifacts       MFT, prefetch, shellbags, SRUM, Amcache
│   └── Labs/
│
├── Detection-Engineering/
│   ├── Sigma/                       Platform-agnostic detection rules
│   ├── Splunk/                      SPL queries
│   ├── Sentinel/                    KQL queries
│   └── Wazuh/                       Rules and decoders
│
├── Scripts/
│   └── Linux/
│       ├── linux-triage.sh          Full live response collection
│       ├── log-parser.sh            Modular log analysis engine
│       └── persistence-hunter.sh    Enumerate all persistence mechanisms
│
├── Security-Reference/              Artifact cheat sheets, event IDs, LOLBins
├── Threat-Hunting/                  Hypothesis-driven hunt packages
├── SOAR/                            Response playbooks
└── Incident-Response/               IR procedures anchored to OS artifacts
```

---

## Module Standard

Every module follows the same structure:

| Section | Content |
|---------|---------|
| **Internals** | What the OS is doing at kernel/system level |
| **Security Significance** | Why this component matters to defenders |
| **Artifact Map** | What gets written, where, in what format |
| **Attacker Tradecraft** | Real techniques threat actors use |
| **Detection Logic** | What to look for and why it works |
| **Investigation Runbook** | Commands and queries for active investigations |
| **MITRE ATT&CK Mapping** | Technique-level tagging |
| **Detection Rules** | Sigma, SPL, KQL, Wazuh — ready to deploy |
| **Practitioner Notes** | Field-level nuance — edge cases, blind spots |
| **Knowledge Validation** | Technical questions to verify depth of understanding |

---

## Coverage Index

### Linux Modules

| Module | Core Topic | Key MITRE Techniques |
|--------|-----------|---------------------|
| [00 — Architecture](./Linux/00-Architecture/) | Kernel rings, syscall interface, LSM | — |
| [01 — Filesystem Hierarchy](./Linux/01-Filesystem-Hierarchy/) | Every root directory dissected | T1005, T1083, T1552 |
| [02 — Logging System](./Linux/02-Logging-System/) | rsyslog, journald, auditd, wtmp | T1070.002, T1562.001 |
| [03 — Process Internals](./Linux/03-Process-Internals/) | fork/exec, namespaces, injection | T1055, T1057, T1036 |
| [04 — /proc Filesystem](./Linux/04-Proc-Filesystem/) | Live OS state as forensic source | T1057, T1083 |
| [05 — Memory Management](./Linux/05-Memory-Management/) | Virtual memory, mmap, memfd, swap | T1055, T1620 |
| [06 — Systemd & Init](./Linux/06-Systemd-Init/) | Units, timers, socket activation | T1543.002, T1053.006 |
| [07 — Permissions & Capabilities](./Linux/07-Permissions-Capabilities/) | DAC, SUID, Linux capabilities | T1548.001, T1548.003 |
| [08 — Networking Stack](./Linux/08-Networking-Stack/) | Sockets, netfilter, reverse shells | T1049, T1090, T1571 |
| [09 — Persistence Mechanisms](./Linux/09-Persistence-Mechanisms/) | Complete Linux persistence map | T1546, T1547, T1053 |
| [10 — User Account Internals](./Linux/10-User-Account-Internals/) | passwd, shadow, PAM, sudoers | T1078, T1136, T1098 |
| [11 — Kernel Modules](./Linux/11-Kernel-Modules/) | LKM loading, rootkit detection, BYOVD | T1014, T1547.006 |
| [12 — Forensics Artifacts](./Linux/12-Forensics-Artifacts/) | What survives and where to look | T1070, T1564 |

### Windows Modules

| Module | Core Topic | Key MITRE Techniques |
|--------|-----------|---------------------|
| [00 — Architecture](./Windows/00-Architecture/) | NT kernel, HAL, kernel objects | — |
| [01 — Filesystem Hierarchy](./Windows/01-Filesystem-Hierarchy/) | Every system directory dissected | T1005, T1083, T1552 |
| [02 — Registry Internals](./Windows/02-Registry-Internals/) | Hive structure, persistence keys | T1112, T1547.001 |
| [03 — Process Internals](./Windows/03-Process-Internals/) | PEB, handles, injection, hollowing | T1055, T1036, T1134 |
| [04 — Memory Management](./Windows/04-Memory-Management/) | VAD, page tables, injection types | T1055, T1620 |
| [05 — Windows Services](./Windows/05-Windows-Services/) | SCM, service types, DLL hijacking | T1543.003, T1574 |
| [06 — Authentication & LSASS](./Windows/06-Authentication-LSASS/) | SAM, NTLM, Kerberos, credential dumping | T1003, T1110, T1558 |
| [07 — Event Log System](./Windows/07-Event-Log-System/) | EVTX, critical event IDs, tampering | T1070.001, T1562 |
| [08 — Scheduled Tasks](./Windows/08-Scheduled-Tasks/) | Task XML, COM hijack, persistence | T1053.005, T1574 |
| [09 — Networking Stack](./Windows/09-Networking-Stack/) | Winsock, named pipes, DNS, C2 | T1071, T1090, T1572 |
| [10 — Persistence Mechanisms](./Windows/10-Persistence-Mechanisms/) | Complete Windows persistence map | T1547, T1546, T1543 |
| [11 — WMI & COM Internals](./Windows/11-WMI-COM-Internals/) | WMI subscriptions, DCOM, COM hijacking | T1047, T1546.003 |
| [12 — Kernel Drivers](./Windows/12-Kernel-Drivers/) | Driver loading, BYOVD, kernel callbacks | T1014, T1068, T1543 |
| [13 — Forensics Artifacts](./Windows/13-Forensics-Artifacts/) | MFT, prefetch, shellbags, SRUM, Amcache | T1070, T1564 |

---

## Scripts

Three operational scripts for live response and investigation:

| Script | Purpose |
|--------|---------|
| [linux-triage.sh](./Scripts/Linux/linux-triage.sh) | Full live response — 11 artifact categories, chain of custody hashing |
| [log-parser.sh](./Scripts/Linux/log-parser.sh) | Modular analysis — brute force, privesc, persistence, evasion, exfil, user/IP investigation |
| [persistence-hunter.sh](./Scripts/Linux/persistence-hunter.sh) | Enumerate every Linux persistence mechanism on a live system |

```bash
sudo bash linux-triage.sh /tmp/case_001
sudo bash log-parser.sh full
sudo bash log-parser.sh ip 192.168.1.100
sudo bash persistence-hunter.sh
```

---

## The Operational Chain

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

---

## MITRE ATT&CK Coverage

This project covers techniques across all 14 MITRE ATT&CK tactics with particular depth in:

- **Defense Evasion** — T1014, T1036, T1055, T1070, T1562, T1564, T1574
- **Persistence** — T1037, T1053, T1543, T1546, T1547
- **Privilege Escalation** — T1055, T1068, T1134, T1548
- **Credential Access** — T1003, T1110, T1552, T1558
- **Discovery** — T1049, T1057, T1083
- **Lateral Movement** — T1021, T1047, T1550
- **Command & Control** — T1071, T1090, T1095, T1572

---

## Tools Referenced

| Category | Tools |
|----------|-------|
| SIEM | Splunk Enterprise, Microsoft Sentinel, Elastic SIEM |
| Host-Based Detection | Wazuh, Sysmon, auditd, osquery |
| Detection Language | Sigma, SPL, KQL, YARA |
| Forensics — Linux | Volatility3, LiME, The Sleuth Kit |
| Forensics — Windows | Volatility3, KAPE, Eric Zimmerman Tools, Chainsaw |
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

*27 modules. Linux and Windows internals. Built for security engineers.*
