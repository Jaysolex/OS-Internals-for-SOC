# W07 — Full Windows IR Simulation

**Module:** Windows/13-Forensics-Artifacts  
**Time:** 60 minutes  
**Objective:** Conduct a complete Windows IR engagement — triage, persistence hunt, artifact collection, evidence preservation, and timeline reconstruction.

---

## Scenario

You receive an alert: a Windows endpoint made an unusual outbound connection at 3 AM and a new service was installed. Conduct live response.

---

## Phase 1 — Immediate Triage

```powershell
# Establish timeline anchor
Get-Date
(Get-WmiObject Win32_OperatingSystem).ConvertToDateTime(
    (Get-WmiObject Win32_OperatingSystem).LastBootUpTime)

# Who is logged in
query user

# Check active network connections
Get-NetTCPConnection -State Established | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    "$($proc.Name):$($_.LocalPort) -> $($_.RemoteAddress):$($_.RemotePort)"
}

# Quick process check
Get-WmiObject Win32_Process |
    Select-Object ProcessId, ParentProcessId, Name, CommandLine |
    Sort-Object ProcessId | Format-Table -AutoSize
```

---

## Phase 2 — Run Full Triage Script

```powershell
# Execute automated triage
$caseDir = "C:\IR\case_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
powershell.exe -ExecutionPolicy Bypass -File `
    "$HOME\OS-Internals-for-SOC\Scripts\Windows\windows-triage.ps1" `
    -OutputPath $caseDir

# Review what was collected
Get-ChildItem $caseDir | Format-Table Name, Length, LastWriteTime
```

---

## Phase 3 — Persistence Hunt

```powershell
# Registry run keys
$keys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
)
foreach ($key in $keys) {
    Write-Host "=== $key ===" -ForegroundColor Cyan
    Get-ItemProperty $key -ErrorAction SilentlyContinue |
        Select-Object * -ExcludeProperty PS* | Format-List
}

# Scheduled tasks (non-Microsoft)
Get-ScheduledTask | Where-Object { $_.TaskPath -notmatch '\\Microsoft\\' } |
    ForEach-Object {
        [PSCustomObject]@{
            Name    = $_.TaskName
            Execute = $_.Actions.Execute
            User    = $_.Principal.UserId
            State   = $_.State
        }
    } | Format-Table -AutoSize

# WMI subscriptions
Get-WMIObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue
Get-WMIObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue

# Startup folders
Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\" -Force -ErrorAction SilentlyContinue
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\" -Force -ErrorAction SilentlyContinue
```

---

## Phase 4 — Forensic Artifact Collection

```powershell
$caseDir = "C:\IR\case_$(Get-Date -Format 'yyyyMMdd')"
New-Item -ItemType Directory -Path $caseDir -Force | Out-Null

# Prefetch — execution evidence
New-Item -ItemType Directory -Path "$caseDir\Prefetch" -Force | Out-Null
Get-ChildItem C:\Windows\Prefetch -Filter *.pf |
    Sort-Object LastWriteTime -Descending |
    Select-Object Name, LastWriteTime |
    Export-Csv "$caseDir\Prefetch\prefetch_list.csv" -NoTypeInformation

# PSReadLine history
Get-ChildItem "C:\Users\*\AppData\Local\Microsoft\Windows\PowerShell\PSReadLine\*.txt" `
    -Force -ErrorAction SilentlyContinue | ForEach-Object {
    $user = ($_.FullName -split '\\')[2]
    Copy-Item $_.FullName "$caseDir\ps_history_$user.txt"
}

# LNK files
Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\*.lnk" |
    Sort-Object LastWriteTime -Descending |
    Select-Object FullName, LastWriteTime |
    Export-Csv "$caseDir\lnk_files.csv" -NoTypeInformation

# DNS cache
Get-DnsClientCache | Export-Csv "$caseDir\dns_cache.csv" -NoTypeInformation

# Copy event logs
New-Item -ItemType Directory -Path "$caseDir\EventLogs" -Force | Out-Null
@('Security', 'System', 'Application') | ForEach-Object {
    $src = "C:\Windows\System32\winevt\Logs\$_.evtx"
    if (Test-Path $src) { Copy-Item $src "$caseDir\EventLogs\" }
}

Write-Host "Artifacts collected in $caseDir"
```

---

## Phase 5 — Timeline Reconstruction

```powershell
# Build a timeline of recent events
Write-Host "=== EVENT TIMELINE (last 24 hours) ===" -ForegroundColor Cyan

# New services
Get-WinEvent -FilterHashtable @{
    LogName='System'; Id=7045
    StartTime=(Get-Date).AddHours(-24)
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml = [xml]$_.ToXml()
    "[$($_.TimeCreated)] NEW SERVICE: $($xml.Event.EventData.Data[0].'#text') -> $($xml.Event.EventData.Data[1].'#text')"
}

# Log clearing
Get-WinEvent -FilterHashtable @{
    LogName='Security'; Id=1102
    StartTime=(Get-Date).AddHours(-24)
} -ErrorAction SilentlyContinue | ForEach-Object {
    "[$($_.TimeCreated)] LOG CLEARED by $($_.UserId)"
}

# Account changes
Get-WinEvent -FilterHashtable @{
    LogName='Security'; Id=@(4720,4726,4728,4732)
    StartTime=(Get-Date).AddHours(-24)
} -ErrorAction SilentlyContinue | ForEach-Object {
    "[$($_.TimeCreated)] ACCOUNT EVENT: $($_.Id) - $($_.Message.Substring(0,[math]::Min(100,$_.Message.Length)))"
}
```

---

## Phase 6 — Evidence Preservation

```powershell
$caseDir = "C:\IR\case_$(Get-Date -Format 'yyyyMMdd')"

# Hash all collected files
Get-ChildItem $caseDir -Recurse -File |
    Where-Object { $_.Name -ne 'checksums.sha256' } |
    ForEach-Object {
        $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
        "$hash  $($_.FullName)"
    } | Out-File "$caseDir\checksums.sha256"

# Create archive
Compress-Archive -Path $caseDir -DestinationPath "$caseDir.zip"

$fileCount = (Get-ChildItem $caseDir -Recurse -File).Count
Write-Host "Evidence preserved: $fileCount files"
Write-Host "Archive: $caseDir.zip"
Write-Host "Checksums: $caseDir\checksums.sha256"
```

---

## Phase 7 — IR Report Template

```
WINDOWS INCIDENT RESPONSE REPORT
==================================
Date:          
Host:          
Investigator:  Solomon James

TIMELINE
--------
Alert time:
IR start:
Triage complete:

FINDINGS
--------
Authentication:
  New accounts created:
  Accounts modified:
  Unusual logon types (Type 3 NTLM):

Persistence:
  Run keys added:
  Services installed:
  Scheduled tasks created:
  WMI subscriptions:
  Startup folder items:

Execution:
  Encoded PowerShell:
  LOLBins with network connections:
  Office spawning shells:

Defense Evasion:
  Event logs cleared:
  Shadow copies deleted:
  Hosts file modified:

FORENSIC ARTIFACTS REVIEWED
-----------------------------
[ ] Prefetch
[ ] PSReadLine history
[ ] LNK files
[ ] Event logs (Security, System, Sysmon)
[ ] Registry persistence keys
[ ] WMI subscriptions
[ ] Scheduled tasks (XML files)

MITRE ATT&CK TECHNIQUES
------------------------

IOCs
----
IPs:
Hashes:
File paths:
Registry keys:

RECOMMENDATIONS
---------------
1.
2.
3.
```

---

## Validation

```powershell
# Verify evidence archive exists and has content
$archive = "C:\IR\case_$(Get-Date -Format 'yyyyMMdd').zip"
if (Test-Path $archive) {
    $zip = [System.IO.Compression.ZipFile]::OpenRead($archive)
    Write-Host "Archive contains $($zip.Entries.Count) files"
    $zip.Dispose()
}
```
