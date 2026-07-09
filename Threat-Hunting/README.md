# Threat Hunting

> Hypothesis-driven hunting anchored to OS internals. Every hypothesis here starts from a specific OS mechanism — because attackers abuse mechanisms, not signatures.

## Hunt Packages

| Hypothesis | OS Mechanism | MITRE | Platform |
|------------|-------------|-------|----------|
| Attacker established persistence via systemd unit | Linux systemd | T1543.002 | Linux |
| Process running from deleted binary on disk | Linux /proc | T1036 | Linux |
| LD_PRELOAD used to intercept syscalls | Linux dynamic linker | T1574.006 | Linux |
| WMI permanent event subscription active | Windows WMI | T1546.003 | Windows |
| LOLBin spawned unusual child process | Windows process tree | T1218 | Windows |
| LSASS accessed by non-system process | Windows LSASS | T1003.001 | Windows |
| Encoded PowerShell with network activity | Windows PS engine | T1059.001 | Windows |
| Shadow copies deleted before ransomware | Windows VSS | T1490 | Windows |
| DNS queries with long subdomain strings | OS DNS resolver | T1071.004 | Both |
| Lateral movement via SMB Type 3 logon | OS authentication | T1021.002 | Windows |

## Hunt Format

Each hunt package contains:
1. **Hypothesis** — what attacker behavior is being hunted
2. **OS Mechanism** — the underlying system component being abused
3. **Baseline** — what normal looks like
4. **Anomaly Indicators** — what deviation from baseline looks like
5. **Queries** — SPL/KQL/osquery to find the anomaly
6. **Validation** — how to confirm a true positive
7. **MITRE mapping** — technique and tactic
