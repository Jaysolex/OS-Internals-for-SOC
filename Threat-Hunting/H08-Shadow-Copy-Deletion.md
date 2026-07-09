# H08 — Shadow Copy Deletion Hunt

**Hypothesis:** An attacker (likely ransomware) has deleted Volume Shadow Copies to prevent recovery.

**OS Mechanism:** VSS maintains point-in-time snapshots of volumes. Ransomware deletes them before encryption to prevent file recovery without paying ransom.

**MITRE:** T1490 — Inhibit System Recovery

---

## Baseline

- Shadow copies are created by Windows Backup and System Restore — managed automatically
- Legitimate deletion uses Windows Backup interfaces, not command-line tools
- vssadmin, wbadmin, and wmic are not used to delete shadows in normal operations

## Anomaly Indicators

- vssadmin.exe with "delete shadows" argument
- wmic.exe with "shadowcopy delete" argument
- wbadmin.exe with "delete catalog" argument
- bcdedit.exe modifying recovery options
- Large volume of file renames with unusual extensions (encryption phase)

---

## Hunt Queries

### Splunk SPL

```spl
index=sysmon EventCode=1
(Image="*\\vssadmin.exe" AND CommandLine="*delete*shadow*")
OR (Image="*\\wmic.exe" AND CommandLine="*shadowcopy*delete*")
OR (Image="*\\wbadmin.exe" AND CommandLine="*delete*catalog*")
OR (Image="*\\bcdedit.exe" AND CommandLine="*recoveryenabled*No*")
| table _time, host, Image, CommandLine, User, ParentImage
| sort -_time
```

```spl
| Ransomware file extension pattern (encryption phase)
index=sysmon EventCode=11
| rex field=TargetFilename "\.(?<ext>[^\.]+)$"
| stats count by ext, host
| where count > 100
| sort -count
```

### KQL

```kql
DeviceProcessEvents
| where FileName in~ ("vssadmin.exe", "wmic.exe", "wbadmin.exe", "bcdedit.exe")
| where ProcessCommandLine has_any ("delete shadows", "shadowcopy delete",
    "delete catalog", "recoveryenabled")
| project TimeGenerated, DeviceName, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessFileName
| sort by TimeGenerated desc
```

### PowerShell — Current VSS Status

```powershell
# Check remaining shadow copies
vssadmin list shadows
Get-WmiObject Win32_ShadowCopy | Select-Object ID, InstallDate, VolumeName

# Check event log for deletion events
Get-WinEvent -FilterHashtable @{LogName='Application'; Id=8228} -ErrorAction SilentlyContinue
```

---

## Validation

1. Confirm no shadow copies remain: `vssadmin list shadows`
2. Check if encryption has started — file extension changes in large volumes
3. Look for the initial access vector — phishing, exploit, RDP brute force
4. Determine scope — how many hosts are affected

## Response

**THIS IS A RANSOMWARE INCIDENT — ESCALATE IMMEDIATELY**
1. Isolate all affected hosts from the network
2. Do not reboot — preserves memory evidence
3. Check offline backups — are they intact and not accessible from the network?
4. Engage IR team and legal counsel
5. Preserve forensic evidence before any remediation
6. Document ransom note content and file extension pattern for threat intel
