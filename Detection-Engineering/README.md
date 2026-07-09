# Detection Engineering

> Every rule in this directory is grounded in OS internals. Detection logic exists because the OS behavior exists.

## Contents

| Folder | Description |
|--------|-------------|
| [Sigma/](./Sigma/) | 27 platform-agnostic detection rules — Linux and Windows |
| [Splunk/](./Splunk/) | SPL queries for detection and threat hunting |
| [Sentinel/](./Sentinel/) | KQL queries for Microsoft Sentinel |
| [Wazuh/](./Wazuh/) | Custom rules, decoders, and active response |

## Sigma Rules Index

| Rule | Platform | MITRE |
|------|----------|-------|
| linux-log-file-cleared | Linux | T1070.002 |
| linux-rsyslog-stopped | Linux | T1562.001 |
| linux-ssh-brute-force | Linux | T1110.001 |
| linux-devshm-execution | Linux | T1564 |
| linux-tmp-execution | Linux | T1059 |
| linux-kernel-module-load | Linux | T1547.006 |
| linux-ldpreload-modified | Linux | T1574.006 |
| linux-cron-persistence | Linux | T1053.003 |
| linux-systemd-persistence | Linux | T1543.002 |
| linux-suid-execution | Linux | T1548.001 |
| linux-reverse-shell-bash | Linux | T1059.004 |
| linux-new-user-created | Linux | T1136.001 |
| linux-process-deleted-binary | Linux | T1036 |
| windows-event-log-cleared | Windows | T1070.001 |
| windows-lsass-memory-access | Windows | T1003.001 |
| windows-wmi-subscription-created | Windows | T1546.003 |
| windows-scheduled-task-suspicious-path | Windows | T1053.005 |
| windows-new-service-suspicious-path | Windows | T1543.003 |
| windows-office-spawns-shell | Windows | T1059 |
| windows-encoded-powershell | Windows | T1059.001 |
| windows-shadow-copy-deletion | Windows | T1490 |
| windows-hosts-file-modified | Windows | T1565.001 |
| windows-registry-run-key-added | Windows | T1547.001 |
| windows-lolbin-network-connection | Windows | T1218 |
| windows-ifeo-debugger | Windows | T1546.012 |
| windows-vulnerable-driver-loaded | Windows | T1068 |
| windows-kerberoasting | Windows | T1558.003 |
