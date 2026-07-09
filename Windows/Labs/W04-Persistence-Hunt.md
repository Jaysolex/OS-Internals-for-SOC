# W04 — Windows Persistence Hunt

**Module:** Windows/10-Persistence-Mechanisms  
**Time:** 45 minutes  
**Objective:** Enumerate every Windows persistence location and understand what malicious entries look like versus legitimate ones.

---

## Exercise 1 — Full Persistence Enumeration

```powershell
# Run the complete persistence audit
# Registry run keys
$keys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
)
foreach ($k in $keys) {
    $vals = Get-ItemProperty $k -ErrorAction SilentlyContinue
    if ($vals) { Write-Host "=== $k ==="; $vals | Select-Object * -ExcludeProperty PS* | Format-List }
}

# Scheduled tasks (non-Microsoft)
Get-ScheduledTask | Where-Object { $_.TaskPath -notmatch '\\Microsoft\\' } |
    Select-Object TaskName, TaskPath, State | Format-Table -AutoSize

# Services with non-standard paths
Get-WmiObject Win32_Service |
    Where-Object { $_.PathName -notmatch 'C:\\Windows' -and $_.StartMode -ne 'Disabled' } |
    Select-Object Name, PathName, StartName | Format-Table -AutoSize

# WMI subscriptions
Get-WMIObject -Namespace root\subscription -Class __EventFilter |
    Select-Object Name, Query
Get-WMIObject -Namespace root\subscription -Class __EventConsumer |
    Select-Object Name, CommandLineTemplate

# Startup folders
Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\" -Force
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\" -Force
```

---

## Exercise 2 — Scheduled Task Deep Dive

```powershell
# List all non-disabled tasks with their actions
Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } |
    ForEach-Object {
        [PSCustomObject]@{
            Name    = $_.TaskName
            Path    = $_.TaskPath
            Execute = $_.Actions.Execute
            Args    = $_.Actions.Arguments
            User    = $_.Principal.UserId
        }
    } | Where-Object { $_.Execute } |
    Where-Object { $_.Execute -match 'powershell|cmd|wscript|mshta|regsvr32' } |
    Format-Table -AutoSize

# Read a task XML directly
$taskPath = "C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Schedule Scan"
if (Test-Path $taskPath) { Get-Content $taskPath | Select-String "Command|Arguments|UserId" }
```

---

## Exercise 3 — Plant and Detect WMI Subscription (Lab Only)

```powershell
# Create a harmless WMI subscription that writes to a log file
$filterQuery = "SELECT * FROM __InstanceModificationEvent WITHIN 60 " +
    "WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' " +
    "AND TargetInstance.SystemUpTime >= 60"

$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
    Name = "LabTestFilter"
    EventNameSpace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = $filterQuery
}

$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
    Name = "LabTestConsumer"
    CommandLineTemplate = "cmd.exe /c echo WMI triggered >> C:\Temp\wmi_lab.txt"
}

Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter = $filter
    Consumer = $consumer
}

# Verify subscription exists
Get-WMIObject -Namespace root\subscription -Class __EventFilter | Where-Object { $_.Name -eq "LabTestFilter" }

# CLEANUP
Get-WMIObject -Namespace root\subscription -Class __EventFilter -Filter "Name='LabTestFilter'" | Remove-WmiObject
Get-WMIObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='LabTestConsumer'" | Remove-WmiObject
Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding | Remove-WmiObject
```

---

## Validation

```powershell
# Verify all cleanup was successful
Get-WMIObject -Namespace root\subscription -Class __EventFilter
Get-WMIObject -Namespace root\subscription -Class __EventConsumer
# Both should return nothing

# Run full triage and check persistence output
powershell.exe -ExecutionPolicy Bypass -File ".\Scripts\Windows\windows-triage.ps1"
```
