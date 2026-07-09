# H10 — Lateral Movement via SMB Hunt

**Hypothesis:** An attacker with stolen credentials is moving laterally through the network using SMB authentication.

**OS Mechanism:** SMB (Server Message Block) allows file sharing and remote execution. Type 3 network logons over SMB are the signature of lateral movement tools like PsExec, Impacket, and credential-based access.

**MITRE:** T1021.002 — Remote Services: SMB/Windows Admin Shares

---

## Baseline

Normal SMB activity:
- Mapped network drives for file access
- Group Policy processing (SYSVOL access)
- Printer access
- Backup software accessing shares

Lateral movement indicators differ:
- Type 3 logons followed immediately by service creation (PsExec)
- Admin share access (C$, ADMIN$, IPC$) from non-admin workstations
- NTLM authentication to multiple hosts in sequence
- Same credential accessing many systems in a short window

---

## Hunt Queries

### Splunk SPL

```spl
| Type 3 logons to admin shares (PsExec pattern)
index=wineventlog EventCode=4624 LogonType=3
| join LogonId [search index=wineventlog EventCode=4697]
| table _time, host, TargetUserName, IpAddress, ServiceName, ServiceFileName
| sort -_time
```

```spl
| Credential used to access many hosts
index=wineventlog EventCode=4624 LogonType=3
| stats dc(host) AS unique_hosts count BY TargetUserName, IpAddress
| where unique_hosts > 3
| sort -unique_hosts
```

```spl
| Admin share access pattern
index=wineventlog EventCode=5140
ShareName IN ("\\*\\C$", "\\*\\ADMIN$", "\\*\\IPC$")
| stats count dc(host) AS targets BY SubjectUserName, IpAddress
| where targets > 2
| sort -targets
```

### KQL

```kql
SecurityEvent
| where EventID == 4624
| where LogonType == 3
| where AuthenticationPackageName == "NTLM"
| summarize TargetCount=dcount(Computer), Targets=make_set(Computer)
    by AccountName, IpAddress, bin(TimeGenerated, 1h)
| where TargetCount > 3
| sort by TargetCount desc
```

```kql
| PsExec detection pattern
let type3_logons = SecurityEvent
    | where EventID == 4624 and LogonType == 3;
let service_installs = SecurityEvent
    | where EventID == 7045;
type3_logons
| join kind=inner (service_installs) on Computer
| where abs(datetime_diff('minute', TimeGenerated, TimeGenerated1)) < 5
| project TimeGenerated, Computer, AccountName, IpAddress,
          ServiceName=ServiceName1, ServicePath=ServiceFileName1
```

### osquery — Live Hunt

```sql
-- Recent network logon sessions
SELECT user, host, tty, time
FROM logged_in_users
WHERE tty = 'pts/0' OR host != '';

-- Active SMB connections
SELECT pid, family, protocol, local_address, local_port,
       remote_address, remote_port, state
FROM process_open_sockets
WHERE remote_port = 445 AND state = 'ESTABLISHED';
```

---

## Validation

1. Map the source IP to a hostname — is it a workstation or server?
2. Check if the authenticating account normally accesses the target
3. Look for service creation (7045) or scheduled task creation (4698) immediately after logon
4. Check for process creation on the target in the same timeframe

## Response

1. Identify all systems accessed — build the lateral movement map
2. Reset the compromised credential immediately
3. Check each accessed system for persistence mechanisms
4. Determine the original compromise point — work backward from first lateral move
5. Assess whether the attacker reached high-value targets (DCs, file servers, backups)
