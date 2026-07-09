# Incident Response

> IR procedures anchored to OS artifacts. The quality of an IR engagement is determined by the investigator's knowledge of where the OS leaves evidence — and what disappears when the system is powered off.

## Response Procedures

| Scenario | OS Artifacts | Platform |
|----------|-------------|----------|
| [Linux Intrusion — Initial Triage](./linux-intrusion-triage.md) | auth.log, /proc, auditd | Linux |
| [Windows Intrusion — Initial Triage](./windows-intrusion-triage.md) | Security.evtx, Sysmon, MFT | Windows |
| [Ransomware Response](./ransomware-response.md) | VSS, MFT, Security.evtx | Windows |
| [Credential Theft Response](./credential-theft-response.md) | LSASS, SAM, Sysmon EID 10 | Windows |
| [Linux Rootkit Investigation](./linux-rootkit-investigation.md) | /proc, /sys, lsmod | Linux |
| [Log Tampering Investigation](./log-tampering-investigation.md) | auditd, journal, wtmp | Linux/Windows |

## Memory Acquisition

**Linux:**
```bash
# LiME kernel module
insmod lime.ko "path=/media/usb/memory.lime format=lime"

# Recover running process binary (deleted from disk)
cp /proc/<pid>/exe /media/usb/recovered_binary

# Capture /proc for offline analysis
tar czf /media/usb/proc_snapshot.tar.gz /proc/[0-9]*/
```

**Windows:**
```powershell
# WinPmem
winpmem_mini.exe memory.raw

# Via Task Manager (limited)
# Right-click process → Create dump file

# Magnet RAM Capture (GUI)
# RAMMap (Sysinternals) for analysis
```

## Evidence Preservation Order

```
1. Memory (most volatile — lost on power off)
2. Network state (connections, ARP, DNS cache)
3. Running processes
4. Open files and handles
5. System time and timezone
6. Disk image
7. Log files
8. Configuration files
```
