# H03 — LOLBin Network Connections Hunt

**Hypothesis:** An attacker is using Living-Off-the-Land binaries to download payloads or communicate with C2 infrastructure.

**OS Mechanism:** Legitimate Windows binaries (certutil, bitsadmin, mshta, regsvr32) have network capabilities that bypass application whitelisting and blend with legitimate traffic.

**MITRE:** T1218 — System Binary Proxy Execution

---

## Baseline

LOLBins rarely make outbound internet connections in normal environments:
- `certutil.exe` connects to certificate authorities for revocation checks only
- `bitsadmin.exe` transfers are initiated by Windows Update and SCCM
- `mshta.exe`, `regsvr32.exe`, `wscript.exe` should never initiate internet connections

## Anomaly Indicators

- Any LOLBin connecting to non-Microsoft external IPs
- certutil.exe with `-urlcache`, `-decode`, or `-encode` in command line
- bitsadmin.exe creating new transfer jobs to external URLs
- mshta.exe connecting to any external address
- regsvr32.exe with `/s /n /u /i:http://` — Squiblydoo pattern

---

## Hunt Queries

### Splunk SPL

```spl
index=sysmon EventCode=3
Image IN ("*\\certutil.exe", "*\\bitsadmin.exe", "*\\mshta.exe",
          "*\\regsvr32.exe", "*\\rundll32.exe", "*\\wscript.exe",
          "*\\cscript.exe", "*\\msiexec.exe")
Initiated=true
| where NOT match(DestinationIp, "^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|0\.0\.0\.0)")
| stats count by Image, DestinationIp, DestinationPort, Computer
| sort -count
```

```spl
| certutil download/decode patterns
index=sysmon EventCode=1 Image="*\\certutil.exe"
CommandLine IN ("*-urlcache*", "*-decode*", "*-encode*", "*http*")
| table _time, Computer, CommandLine, User, ParentImage
```

### KQL

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("certutil.exe", "bitsadmin.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "wscript.exe", "msiexec.exe")
| where RemoteIPType == "Public"
| project TimeGenerated, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| sort by TimeGenerated desc
```

---

## Validation

1. Resolve the destination IP — is it known infrastructure?
2. Check process command line for download URLs or encoded content
3. Look for files created by the LOLBin process immediately after the connection
4. Check for child processes spawned after the network activity

## Response

1. Block the destination IP at perimeter
2. Identify and quarantine any downloaded payloads
3. Hunt for the same destination IP across all endpoints
4. Check for persistence mechanisms established after LOLBin execution
