# H01 — LSASS Memory Access Hunt

**Hypothesis:** An attacker on this network has accessed LSASS memory to dump credentials.

**OS Mechanism:** LSASS (lsass.exe) holds all active credentials in memory. Accessing it with PROCESS_VM_READ permission enables credential extraction.

**MITRE:** T1003.001 — OS Credential Dumping: LSASS Memory

---

## Baseline

On a healthy system:
- Only SYSTEM and a small set of trusted security processes open handles to LSASS
- Access masks are restricted — security products use specific, bounded access rights
- No user-initiated process should read LSASS memory

## Anomaly Indicators

- Non-system process opening LSASS with access mask 0x1010, 0x1410, or 0x1438
- procdump.exe, taskmgr.exe, or unknown binaries accessing LSASS
- LSASS dump file (.dmp) created in any directory
- WDigest enabled (UseLogonCredential = 1) — preparation for cleartext harvest

---

## Hunt Queries

### Splunk SPL

```spl
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
| where GrantedAccess IN ("0x1010", "0x1410", "0x1438", "0x143a", "0x1418")
| eval is_system=if(match(SourceImage, "(?i)C:\\\\Windows\\\\(system32|SysWOW64)\\\\"), "yes", "no")
| where is_system="no"
| table _time, Computer, SourceImage, SourceProcessId, GrantedAccess, TargetImage
| sort -_time
```

### KQL (Microsoft Sentinel)

```kql
DeviceEvents
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where AdditionalFields has_any ("0x1010", "0x1410", "0x1438")
| where InitiatingProcessFolderPath !startswith "C:\\Windows\\System32"
| project TimeGenerated, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, AdditionalFields
| sort by TimeGenerated desc
```

### osquery

```sql
SELECT p.name, p.pid, p.path, p.cmdline, p.parent,
       pp.name AS parent_name
FROM processes p
JOIN processes pp ON p.parent = pp.pid
WHERE p.name = 'lsass.exe'
  AND pp.name NOT IN ('wininit.exe', 'services.exe');
```

---

## Validation

Confirm true positive by:
1. Verify SourceImage is not a known security tool (EDR, AV)
2. Check if a dump file was created after the access
3. Look for credential use from the target host to other systems post-access
4. Check for 4624 Type 3 logons from the host using new accounts

---

## Response

If confirmed:
1. Isolate the host immediately
2. Reset all credentials for users logged in at time of dump
3. Rotate service account passwords
4. Check for lateral movement — 4624/4648 from the host to other systems
5. Acquire memory image for forensic analysis
