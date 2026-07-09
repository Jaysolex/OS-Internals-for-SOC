# Detection Engineering

> Every rule in this directory is grounded in OS internals. The detection logic exists because the OS behavior exists. Rules written without understanding the underlying system are brittle — they match strings, not behavior.

## Rule Index

### Sigma (Platform-Agnostic)
| Rule | MITRE | Status |
|------|-------|--------|
| [Linux Log File Cleared](./Sigma/linux-log-cleared.yml) | T1070.002 | ✅ |
| [rsyslog Daemon Stopped](./Sigma/linux-rsyslog-stopped.yml) | T1562.001 | ✅ |
| [SSH Brute Force](./Sigma/linux-ssh-brute-force.yml) | T1110.001 | ✅ |
| [File Written to /dev/shm](./Sigma/linux-devshm-write.yml) | T1564 | ✅ |
| [Executable in /tmp](./Sigma/linux-tmp-execution.yml) | T1059 | ✅ |
| [Kernel Module Loaded](./Sigma/linux-kernel-module-load.yml) | T1547.006 | ✅ |
| [LD_PRELOAD Modified](./Sigma/linux-ldpreload.yml) | T1574.006 | ✅ |
| [Cron Persistence Added](./Sigma/linux-cron-persistence.yml) | T1053.003 | ✅ |
| [Windows Event Log Cleared](./Sigma/windows-event-log-cleared.yml) | T1070.001 | ✅ |
| [LSASS Memory Access](./Sigma/windows-lsass-access.yml) | T1003.001 | ✅ |
| [WMI Subscription Created](./Sigma/windows-wmi-subscription.yml) | T1546.003 | ✅ |
| [Scheduled Task by LOLBin](./Sigma/windows-schtask-lolbin.yml) | T1053.005 | ✅ |
| [Shadow Copy Deletion](./Sigma/windows-shadow-delete.yml) | T1490 | ✅ |
| [Hosts File Modified](./Sigma/windows-hosts-modified.yml) | T1565.001 | ✅ |

### Splunk SPL
See [Splunk/](./Splunk/) for production-ready SPL queries with field extractions.

### Microsoft Sentinel KQL
See [Sentinel/](./Sentinel/) for KQL detection and hunting queries.

### Wazuh
See [Wazuh/](./Wazuh/) for custom rules, decoders, and active response scripts.
