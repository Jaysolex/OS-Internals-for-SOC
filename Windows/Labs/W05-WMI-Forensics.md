# W05 — WMI & COM Forensics

**Module:** Windows/11-WMI-COM-Internals  
**Time:** 35 minutes  
**Objective:** Enumerate WMI subscriptions, understand the WMI repository, detect COM hijacking opportunities, and use WMI for lateral movement detection.

---

## Exercise 1 — WMI Namespace Exploration

```powershell
# List all WMI namespaces
Get-WmiObject -Namespace root -Class __Namespace | Select-Object Name | Sort-Object Name

# Explore the subscription namespace
Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue
Get-WmiObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue

Write-Host "If all three return empty — no WMI persistence installed" -ForegroundColor Green
```

---

## Exercise 2 — Create and Detect WMI Subscription (Lab Only)

```powershell
# Create a harmless WMI subscription
$filterQuery = "SELECT * FROM __InstanceModificationEvent WITHIN 60 " +
    "WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' " +
    "AND TargetInstance.SystemUpTime >= 120"

$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
    Name = "LabWMIFilter"
    EventNameSpace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = $filterQuery
}

$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
    Name = "LabWMIConsumer"
    CommandLineTemplate = "cmd.exe /c echo WMI_LAB >> C:\Temp\wmi_lab.txt"
}

Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter = $filter; Consumer = $consumer
}

Write-Host "WMI subscription created" -ForegroundColor Yellow

# Detect it immediately
Write-Host "`n=== Enumerating WMI subscriptions ===" -ForegroundColor Cyan
Get-WmiObject -Namespace root\subscription -Class __EventFilter | Select-Object Name, Query
Get-WmiObject -Namespace root\subscription -Class __EventConsumer | Select-Object Name, CommandLineTemplate

# CLEANUP
Get-WmiObject -Namespace root\subscription -Class __EventFilter `
    -Filter "Name='LabWMIFilter'" | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer `
    -Filter "Name='LabWMIConsumer'" | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding |
    Remove-WmiObject
Write-Host "Subscription removed" -ForegroundColor Green
```

---

## Exercise 3 — COM Hijacking Opportunities

```powershell
# Find CLSIDs registered in HKLM but not HKCU
# These are potential COM hijack targets
$hklm_clsids = Get-ChildItem "HKLM:\SOFTWARE\Classes\CLSID" -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty PSChildName

$hkcu_clsids = Get-ChildItem "HKCU:\Software\Classes\CLSID" -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty PSChildName

$hijackable = $hklm_clsids | Where-Object { $_ -notin $hkcu_clsids } |
    ForEach-Object {
        $clsid = $_
        $inproc = "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32"
        if (Test-Path $inproc) {
            $dll = (Get-ItemProperty $inproc -ErrorAction SilentlyContinue).'(default)'
            if ($dll -and -not (Test-Path $dll -ErrorAction SilentlyContinue)) {
                [PSCustomObject]@{ CLSID=$clsid; MissingDLL=$dll }
            }
        }
    }

Write-Host "Potentially hijackable CLSIDs (missing DLL):"
$hijackable | Select-Object -First 10 | Format-Table -AutoSize
```

---

## Exercise 4 — Check HKCU COM Registrations

```powershell
# List any user-level COM registrations (potential hijacks)
$userCOM = Get-ChildItem "HKCU:\Software\Classes\CLSID" -ErrorAction SilentlyContinue |
    ForEach-Object {
        $inproc = Get-ItemProperty "$($_.PSPath)\InprocServer32" -ErrorAction SilentlyContinue
        if ($inproc) {
            [PSCustomObject]@{
                CLSID = $_.PSChildName
                DLL   = $inproc.'(default)'
            }
        }
    }

if ($userCOM) {
    Write-Host "USER-LEVEL COM REGISTRATIONS FOUND:" -ForegroundColor Yellow
    $userCOM | Format-Table -AutoSize
} else {
    Write-Host "No user-level COM registrations found" -ForegroundColor Green
}
```

---

## Exercise 5 — WMI Execution Detection via Event Log

```powershell
# Check WMI Activity log for recent WMI execution
Get-WinEvent -LogName "Microsoft-Windows-WMI-Activity/Operational" `
    -MaxEvents 20 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'execute|query|invoke' } |
    Select-Object TimeCreated, Message | Format-List

# Check Sysmon for WMI subscription events
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational'
    Id=@(19,20,21)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message | Format-List
```

---

## Validation

```powershell
# Full WMI audit via triage script
powershell.exe -ExecutionPolicy Bypass -File `
    "$HOME\OS-Internals-for-SOC\Scripts\Windows\windows-triage.ps1" `
    -OutputPath C:\IR\lab_w05

Get-Content C:\IR\lab_w05\05_wmi_filters.csv
Get-Content C:\IR\lab_w05\05_wmi_consumers.csv
```
