# W03 — Windows Event Log Analysis

**Module:** Windows/07-Event-Log-System  
**Time:** 40 minutes  
**Objective:** Query critical Security event IDs, detect log clearing, analyse authentication patterns, and understand what Sysmon adds beyond native Windows logging.

---

## Exercise 1 — Enable Critical Audit Policies

```powershell
# Check current audit policy
auditpol /get /category:* | Select-String "Logon|Process|Object"

# Enable process creation auditing with command line
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1

# Enable logon auditing
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable

Write-Host "Audit policies configured"
```

---

## Exercise 2 — Query Authentication Events

```powershell
# Recent successful logons
Write-Host "=== SUCCESSFUL LOGONS (4624) ===" -ForegroundColor Green
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 20 `
    -ErrorAction SilentlyContinue | ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time      = $_.TimeCreated
        User      = $xml.Event.EventData.Data[5].'#text'
        LogonType = $xml.Event.EventData.Data[8].'#text'
        SourceIP  = $xml.Event.EventData.Data[18].'#text'
        AuthPkg   = $xml.Event.EventData.Data[14].'#text'
    }
} | Format-Table -AutoSize

# Recent failed logons
Write-Host "=== FAILED LOGONS (4625) ===" -ForegroundColor Red
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 20 `
    -ErrorAction SilentlyContinue | ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time     = $_.TimeCreated
        User     = $xml.Event.EventData.Data[5].'#text'
        SourceIP = $xml.Event.EventData.Data[19].'#text'
        Reason   = $xml.Event.EventData.Data[8].'#text'
    }
} | Format-Table -AutoSize
```

---

## Exercise 3 — Detect Log Gap (Missing Record Numbers)

```powershell
# Check for gaps in Security log record numbers
$events = Get-WinEvent -LogName Security -MaxEvents 500 -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty RecordId | Sort-Object

$gaps = for ($i = 0; $i -lt $events.Count - 1; $i++) {
    $diff = $events[$i+1] - $events[$i]
    if ($diff -gt 1) {
        [PSCustomObject]@{
            Before = $events[$i]
            After  = $events[$i+1]
            Missing = $diff - 1
        }
    }
}

if ($gaps) {
    Write-Host "LOG GAPS DETECTED:" -ForegroundColor Red
    $gaps | Format-Table
} else {
    Write-Host "No gaps found in last 500 records" -ForegroundColor Green
}
```

---

## Exercise 4 — Check Log Clearing Events

```powershell
# Check for Security log clearing (1102)
$clears = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} `
    -ErrorAction SilentlyContinue
if ($clears) {
    Write-Host "SECURITY LOG WAS CLEARED:" -ForegroundColor Red
    $clears | Select-Object TimeCreated, Message | Format-List
} else {
    Write-Host "No log clearing events found" -ForegroundColor Green
}

# Check System log clearing (104)
$sysClears = Get-WinEvent -FilterHashtable @{LogName='System'; Id=104} `
    -ErrorAction SilentlyContinue
if ($sysClears) {
    Write-Host "SYSTEM LOG WAS CLEARED:" -ForegroundColor Red
    $sysClears | Select-Object TimeCreated | Format-Table
}
```

---

## Exercise 5 — Sysmon vs Native Logging Comparison

```powershell
# Count process creation events from both sources
$native = (Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} `
    -MaxEvents 100 -ErrorAction SilentlyContinue).Count

$sysmon = (Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} `
    -MaxEvents 100 -ErrorAction SilentlyContinue).Count

Write-Host "Native 4688 events: $native"
Write-Host "Sysmon Event 1 events: $sysmon"
Write-Host ""
Write-Host "Sysmon Event 1 includes: ParentImage, Hashes, CurrentDirectory"
Write-Host "Native 4688 includes: CommandLine (if configured)"
Write-Host ""
Write-Host "Sysmon provides significantly richer process creation context"

# Show a Sysmon event in full detail
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} `
    -MaxEvents 1 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Message
```

---

## Validation

```powershell
# Copy event logs for offline analysis
New-Item -ItemType Directory -Path C:\IR\lab_w03 -Force | Out-Null
Copy-Item C:\Windows\System32\winevt\Logs\Security.evtx C:\IR\lab_w03\
Write-Host "Security.evtx saved to C:\IR\lab_w03\"
Write-Host "Parse with: EvtxECmd.exe -f C:\IR\lab_w03\Security.evtx --csv C:\IR\lab_w03\"
```
