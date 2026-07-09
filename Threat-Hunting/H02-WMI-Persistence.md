# H02 — WMI Permanent Event Subscription Hunt

**Hypothesis:** An attacker has established fileless persistence via WMI permanent event subscriptions.

**OS Mechanism:** WMI stores event subscriptions in the CIM repository — no files on disk, survives reboots, executes as SYSTEM.

**MITRE:** T1546.003 — Event Triggered Execution: Windows Management Instrumentation Event Subscription

---

## Baseline

On a healthy system:
- Very few or no permanent event subscriptions exist
- Legitimate monitoring products (SCCM, monitoring agents) create known subscriptions
- WmiPrvSE.exe does not spawn cmd.exe or powershell.exe

## Anomaly Indicators

- Any CommandLineEventConsumer with encoded PowerShell or paths to temp directories
- ActiveScriptEventConsumer with embedded script content
- WmiPrvSE.exe spawning shell processes
- New entries in root\subscription namespace

---

## Hunt Queries

### PowerShell (Live System)

```powershell
# Enumerate all WMI subscriptions
$filters = Get-WMIObject -Namespace root\subscription -Class __EventFilter
$consumers = Get-WMIObject -Namespace root\subscription -Class __EventConsumer
$bindings = Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding

Write-Host "=== FILTERS ===" -ForegroundColor Cyan
$filters | Select-Object Name, Query | Format-Table -AutoSize

Write-Host "=== CONSUMERS ===" -ForegroundColor Cyan
$consumers | Select-Object Name, CommandLineTemplate, ScriptText | Format-Table -AutoSize

Write-Host "=== BINDINGS ===" -ForegroundColor Cyan
$bindings | Format-Table -AutoSize
```

### Splunk SPL

```spl
index=sysmon EventCode IN (19, 20, 21)
| eval event_type=case(EventCode=19, "Filter Created",
                        EventCode=20, "Consumer Created",
                        EventCode=21, "Binding Created")
| table _time, Computer, event_type, Name, Type, Query, Destination
| sort -_time
```

```spl
| WmiPrvSE spawning shells
index=sysmon EventCode=1 ParentImage="*\\WmiPrvSE.exe"
Image IN ("*\\cmd.exe", "*\\powershell.exe", "*\\wscript.exe", "*\\cscript.exe")
| table _time, Computer, Image, CommandLine, ParentImage
```

### KQL (Microsoft Sentinel)

```kql
DeviceProcessEvents
| where InitiatingProcessFileName =~ "WmiPrvSE.exe"
| where FileName in~ ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by TimeGenerated desc
```

---

## Validation

1. Query root\subscription namespace directly on the suspected host
2. Decode any base64 in CommandLineTemplate
3. Check WMI Activity event log for subscription execution history
4. Acquire WMI repository (`C:\Windows\System32\wbem\Repository\`) for offline analysis

## Response

1. Delete subscription components:
```powershell
Get-WMIObject -Namespace root\subscription -Class __EventFilter -Filter "Name='<name>'" | Remove-WmiObject
Get-WMIObject -Namespace root\subscription -Class __EventConsumer -Filter "Name='<name>'" | Remove-WmiObject
Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding | Remove-WmiObject
```
2. Investigate what the payload executed during its run
3. Hunt for additional persistence on the same host
