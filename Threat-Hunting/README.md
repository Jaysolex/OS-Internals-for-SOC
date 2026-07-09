# Threat Hunting

> Hypothesis-driven hunting anchored to OS internals. Every hypothesis starts from a specific OS mechanism — because attackers abuse mechanisms, not signatures. Each package contains everything needed to execute the hunt from start to finish.

---

## Hunt Package Format

Every hunt package contains:
1. **Hypothesis** — what attacker behavior is being hunted
2. **OS Mechanism** — the underlying system component being abused
3. **Baseline** — what normal looks like
4. **Anomaly Indicators** — deviation from baseline
5. **Hunt Queries** — SPL, KQL, osquery
6. **Validation** — confirming true positive
7. **MITRE Mapping** — technique and tactic

---

## Hunt Index

| Hunt | OS Mechanism | MITRE | Platform |
|------|-------------|-------|----------|
| [H01 — LSASS Access](./H01-LSASS-Memory-Access.md) | Windows LSASS | T1003.001 | Windows |
| [H02 — WMI Persistence](./H02-WMI-Persistence.md) | Windows WMI | T1546.003 | Windows |
| [H03 — LOLBin Network](./H03-LOLBin-Network-Connections.md) | Windows process execution | T1218 | Windows |
| [H04 — Linux Persistence](./H04-Linux-Persistence-Hunt.md) | Linux cron/systemd | T1053, T1543 | Linux |
| [H05 — Deleted Binary Execution](./H05-Deleted-Binary-Execution.md) | Linux /proc | T1036 | Linux |
| [H06 — Kerberoasting](./H06-Kerberoasting.md) | Kerberos | T1558.003 | Windows |
| [H07 — Log Tampering](./H07-Log-Tampering.md) | Logging subsystems | T1070 | Both |
| [H08 — Shadow Copy Deletion](./H08-Shadow-Copy-Deletion.md) | Windows VSS | T1490 | Windows |
| [H09 — DNS Tunneling](./H09-DNS-Tunneling.md) | DNS resolver | T1071.004 | Both |
| [H10 — Lateral Movement SMB](./H10-Lateral-Movement-SMB.md) | SMB/authentication | T1021.002 | Windows |
