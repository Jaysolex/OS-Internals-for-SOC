# =============================================================================
# windows-triage.ps1
# Live Response & Triage Script for Windows Systems
# Author: Solomon James (@Jaysolex)
# Usage: Run as Administrator in PowerShell
# powershell.exe -ExecutionPolicy Bypass -File windows-triage.ps1 [output_path]
# =============================================================================

#Requires -RunAsAdministrator

param(
    [string]$OutputPath = "C:\IR\triage_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
)

# ── Colours ───────────────────────────────────────────────────────────────────
function Write-Header  { Write-Host "`n$('='*50)" -ForegroundColor Cyan; Write-Host "  $args" -ForegroundColor Cyan; Write-Host $('='*50) -ForegroundColor Cyan }
function Write-Item    { Write-Host "  [*] $args" -ForegroundColor White }
function Write-Finding { Write-Host "  [!] $args" -ForegroundColor Red }
function Write-OK      { Write-Host "  [+] $args" -ForegroundColor Green }

# ── Setup ─────────────────────────────────────────────────────────────────────
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
$LogFile = "$OutputPath\triage.log"
Start-Transcript -Path $LogFile -Append | Out-Null

Write-Host @"
  ___  ___  _  _   _____ ___ ___ _   _  ___  ___
 / __|/ _ \| \| | |_   _| _ \_ _/_\ / _|/ __|| __|
 \__ \ (_) | .` |   | | |   /| |/ _ \ (_| (_ || _|
 |___/\___/|_|\_|   |_| |_|_\___/_/ \_\__|\___||___|

     Windows Live Response Triage
"@ -ForegroundColor Cyan

Write-OK "Output: $OutputPath"
Write-OK "Host: $env:COMPUTERNAME | User: $env:USERNAME | Time: $(Get-Date)"

# =============================================================================
Write-Header "1. SYSTEM IDENTITY"
# =============================================================================
Write-Item "Collecting system information..."

$sysInfo = @{
    Hostname    = $env:COMPUTERNAME
    Domain      = (Get-WmiObject Win32_ComputerSystem).Domain
    OS          = (Get-WmiObject Win32_OperatingSystem).Caption
    OSVersion   = (Get-WmiObject Win32_OperatingSystem).Version
    Uptime      = (Get-Date) - (Get-WmiObject Win32_OperatingSystem).ConvertToDateTime((Get-WmiObject Win32_OperatingSystem).LastBootUpTime)
    CurrentUser = $env:USERNAME
    DateTime    = Get-Date
}
$sysInfo | ConvertTo-Json | Out-File "$OutputPath\01_system_info.json"

# Installed hotfixes
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object HotFixID, Description, InstalledOn |
    Export-Csv "$OutputPath\01_hotfixes.csv" -NoTypeInformation

Write-OK "System identity collected"

# =============================================================================
Write-Header "2. USER & AUTHENTICATION"
# =============================================================================
Write-Item "Collecting user and authentication data..."

# Local users
Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, Description |
    Export-Csv "$OutputPath\02_local_users.csv" -NoTypeInformation

# Local groups
Get-LocalGroup | ForEach-Object {
    $group = $_.Name
    Get-LocalGroupMember -Group $_ -ErrorAction SilentlyContinue |
        Select-Object @{N='Group';E={$group}}, Name, ObjectClass, PrincipalSource
} | Export-Csv "$OutputPath\02_local_groups.csv" -NoTypeInformation

# Administrators
Write-Item "Local Administrators:"
Get-LocalGroupMember -Group "Administrators" | ForEach-Object {
    Write-Finding "  ADMIN: $($_.Name)"
}

# Recent logon events
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 100 -ErrorAction SilentlyContinue |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        [PSCustomObject]@{
            Time      = $_.TimeCreated
            User      = $xml.Event.EventData.Data[5].'#text'
            Domain    = $xml.Event.EventData.Data[6].'#text'
            LogonType = $xml.Event.EventData.Data[8].'#text'
            SourceIP  = $xml.Event.EventData.Data[18].'#text'
            AuthPkg   = $xml.Event.EventData.Data[14].'#text'
        }
    } | Export-Csv "$OutputPath\02_logon_events.csv" -NoTypeInformation

# Failed logons
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 100 -ErrorAction SilentlyContinue |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        [PSCustomObject]@{
            Time      = $_.TimeCreated
            User      = $xml.Event.EventData.Data[5].'#text'
            SourceIP  = $xml.Event.EventData.Data[19].'#text'
            Reason    = $xml.Event.EventData.Data[8].'#text'
        }
    } | Export-Csv "$OutputPath\02_failed_logons.csv" -NoTypeInformation

Write-OK "User and authentication data collected"

# =============================================================================
Write-Header "3. NETWORK STATE"
# =============================================================================
Write-Item "Collecting network state..."

# TCP connections with process
Get-NetTCPConnection | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        LocalAddr  = $_.LocalAddress
        LocalPort  = $_.LocalPort
        RemoteAddr = $_.RemoteAddress
        RemotePort = $_.RemotePort
        State      = $_.State
        PID        = $_.OwningProcess
        Process    = $proc.Name
        Path       = $proc.Path
    }
} | Export-Csv "$OutputPath\03_tcp_connections.csv" -NoTypeInformation

# Flag established connections to non-private IPs
Write-Item "Checking for external connections..."
Get-NetTCPConnection -State Established | ForEach-Object {
    $ip = $_.RemoteAddress
    if ($ip -notmatch '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|::1|0\.0\.0\.0)') {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        Write-Finding "External: $ip:$($_.RemotePort) <- $($proc.Name) (PID:$($_.OwningProcess))"
    }
}

# ARP cache
Get-NetNeighbor | Export-Csv "$OutputPath\03_arp_cache.csv" -NoTypeInformation

# DNS cache
Get-DnsClientCache | Export-Csv "$OutputPath\03_dns_cache.csv" -NoTypeInformation

# Routing table
Get-NetRoute | Export-Csv "$OutputPath\03_routes.csv" -NoTypeInformation

# Hosts file
Get-Content C:\Windows\System32\drivers\etc\hosts | Out-File "$OutputPath\03_hosts_file.txt"
$hostsAnomalies = Get-Content C:\Windows\System32\drivers\etc\hosts |
    Where-Object { $_ -notmatch '^#' -and $_ -notmatch 'localhost' -and $_ -match '\S' }
if ($hostsAnomalies) {
    Write-Finding "Hosts file has custom entries:"
    $hostsAnomalies | ForEach-Object { Write-Finding "  $_" }
}

# Named pipes
[System.IO.Directory]::GetFiles("\\.\pipe\") | Out-File "$OutputPath\03_named_pipes.txt"

Write-OK "Network state collected"

# =============================================================================
Write-Header "4. PROCESS STATE"
# =============================================================================
Write-Item "Collecting process state..."

# All processes with path and signature
Get-WmiObject Win32_Process | ForEach-Object {
    $proc = Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue
    $sig = if ($proc.Path) { (Get-AuthenticodeSignature $proc.Path -ErrorAction SilentlyContinue).Status } else { 'NoPath' }
    [PSCustomObject]@{
        PID         = $_.ProcessId
        PPID        = $_.ParentProcessId
        Name        = $_.Name
        CommandLine = $_.CommandLine
        Path        = $proc.Path
        Signature   = $sig
        StartTime   = $proc.StartTime
    }
} | Export-Csv "$OutputPath\04_processes.csv" -NoTypeInformation

# Unsigned processes
Write-Item "Checking for unsigned process binaries..."
Get-WmiObject Win32_Process | ForEach-Object {
    $proc = Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue
    if ($proc.Path) {
        $sig = Get-AuthenticodeSignature $proc.Path -ErrorAction SilentlyContinue
        if ($sig.Status -ne 'Valid') {
            Write-Finding "Unsigned: $($_.Name) (PID:$($_.ProcessId)) -> $($proc.Path)"
        }
    }
}

# Processes with no path
Write-Item "Checking for processes with no disk path..."
Get-Process | Where-Object { -not $_.Path } |
    Select-Object Name, Id | ForEach-Object {
        Write-Finding "No path: $($_.Name) (PID:$($_.Id))"
    }

Write-OK "Process state collected"

# =============================================================================
Write-Header "5. PERSISTENCE MECHANISMS"
# =============================================================================
Write-Item "Enumerating persistence mechanisms..."

# Registry run keys
$runKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
)
$runEntries = foreach ($key in $runKeys) {
    $props = Get-ItemProperty $key -ErrorAction SilentlyContinue
    if ($props) {
        $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } |
            ForEach-Object {
                Write-Finding "Run Key: [$key] $($_.Name) = $($_.Value)"
                [PSCustomObject]@{ Key=$key; Name=$_.Name; Value=$_.Value }
            }
    }
}
$runEntries | Export-Csv "$OutputPath\05_run_keys.csv" -NoTypeInformation

# Scheduled tasks
Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } |
    ForEach-Object {
        [PSCustomObject]@{
            Name    = $_.TaskName
            Path    = $_.TaskPath
            Execute = $_.Actions.Execute
            Args    = $_.Actions.Arguments
            User    = $_.Principal.UserId
            State   = $_.State
        }
    } | Export-Csv "$OutputPath\05_scheduled_tasks.csv" -NoTypeInformation

# Flag suspicious task paths
Get-ScheduledTask | ForEach-Object {
    $task = $_
    $_.Actions | Where-Object {
        $_.Execute -match 'Temp|AppData|Public|ProgramData|Downloads'
    } | ForEach-Object {
        Write-Finding "Suspicious Task: $($task.TaskName) -> $($_.Execute)"
    }
}

# Services with non-standard paths
Get-WmiObject Win32_Service |
    Where-Object { $_.PathName -notmatch 'C:\\Windows' -and $_.StartMode -ne 'Disabled' } |
    ForEach-Object {
        Write-Finding "Non-standard Service: $($_.Name) -> $($_.PathName)"
    } | Export-Csv "$OutputPath\05_services_nonstandard.csv" -NoTypeInformation

# WMI subscriptions
$wmiFilters   = Get-WMIObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue
$wmiConsumers = Get-WMIObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue
if ($wmiFilters -or $wmiConsumers) {
    Write-Finding "WMI SUBSCRIPTIONS FOUND:"
    $wmiFilters | ForEach-Object { Write-Finding "  Filter: $($_.Name) | Query: $($_.Query)" }
    $wmiConsumers | ForEach-Object { Write-Finding "  Consumer: $($_.Name) | Cmd: $($_.CommandLineTemplate)" }
}
$wmiFilters | Select-Object Name, Query | Export-Csv "$OutputPath\05_wmi_filters.csv" -NoTypeInformation
$wmiConsumers | Select-Object Name, CommandLineTemplate, ScriptText | Export-Csv "$OutputPath\05_wmi_consumers.csv" -NoTypeInformation

# Startup folders
$startupFolders = @(
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\"
)
foreach ($sf in $startupFolders) {
    $items = Get-ChildItem $sf -Force -ErrorAction SilentlyContinue
    if ($items) {
        $items | ForEach-Object { Write-Finding "Startup: $($_.FullName)" }
    }
}

# Winlogon
$winlogon = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
"Userinit: $($winlogon.Userinit)" | Out-File "$OutputPath\05_winlogon.txt"
"Shell: $($winlogon.Shell)" | Out-File "$OutputPath\05_winlogon.txt" -Append
if ($winlogon.Userinit -ne 'C:\Windows\system32\userinit.exe,') {
    Write-Finding "Winlogon Userinit modified: $($winlogon.Userinit)"
}

# IFEO debugger entries
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" |
    ForEach-Object {
        $dbg = (Get-ItemProperty $_.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger
        if ($dbg) {
            Write-Finding "IFEO Debugger: $($_.PSChildName) -> $dbg"
            [PSCustomObject]@{ Process=$_.PSChildName; Debugger=$dbg }
        }
    } | Export-Csv "$OutputPath\05_ifeo_debuggers.csv" -NoTypeInformation

Write-OK "Persistence mechanisms enumerated"

# =============================================================================
Write-Header "6. CREDENTIAL ARTIFACTS"
# =============================================================================
Write-Item "Collecting credential artifacts..."

# PSReadLine history
Get-ChildItem "C:\Users\*\AppData\Local\Microsoft\Windows\PowerShell\PSReadLine\*.txt" -Force -ErrorAction SilentlyContinue |
    ForEach-Object {
        $user = ($_.FullName -split '\\')[2]
        Copy-Item $_.FullName "$OutputPath\06_pshistory_$user.txt" -ErrorAction SilentlyContinue
    }

# WDigest status
$wdigest = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -ErrorAction SilentlyContinue).UseLogonCredential
if ($wdigest -eq 1) {
    Write-Finding "WDigest ENABLED — cleartext credentials in LSASS memory"
}

# LSASS PPL status
$ppl = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue).RunAsPPL
"WDigest: $wdigest | LSASS PPL: $ppl" | Out-File "$OutputPath\06_credential_config.txt"

Write-OK "Credential artifacts collected"

# =============================================================================
Write-Header "7. FILESYSTEM ANOMALIES"
# =============================================================================
Write-Item "Checking filesystem anomalies..."

# Recently created executables in suspicious locations
$suspiciousPaths = @('C:\Windows\Temp', "$env:TEMP", "$env:APPDATA", 'C:\ProgramData', 'C:\Users\Public')
foreach ($path in $suspiciousPaths) {
    Get-ChildItem $path -Recurse -Include *.exe,*.dll,*.ps1,*.bat,*.vbs -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.CreationTime -gt (Get-Date).AddDays(-7) } |
        ForEach-Object {
            Write-Finding "Recent executable: $($_.FullName) (created: $($_.CreationTime))"
        }
}

# Alternate Data Streams
Write-Item "Scanning for alternate data streams..."
Get-ChildItem C:\Windows\Temp, $env:TEMP, $env:APPDATA -Force -ErrorAction SilentlyContinue |
    ForEach-Object {
        Get-Item $_.FullName -Stream * -ErrorAction SilentlyContinue |
            Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' } |
            ForEach-Object { Write-Finding "ADS: $($_.FileName):$($_.Stream)" }
    }

Write-OK "Filesystem anomalies checked"

# =============================================================================
Write-Header "8. EVENT LOG ANALYSIS"
# =============================================================================
Write-Item "Analysing critical events..."

# Log clearing
$logClears = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -MaxEvents 10 -ErrorAction SilentlyContinue
if ($logClears) {
    Write-Finding "EVENT LOG CLEARED:"
    $logClears | ForEach-Object { Write-Finding "  $($_.TimeCreated) - $($_.Message)" }
}

# New services
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 20 -ErrorAction SilentlyContinue |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        [PSCustomObject]@{
            Time    = $_.TimeCreated
            Name    = $xml.Event.EventData.Data[0].'#text'
            Path    = $xml.Event.EventData.Data[1].'#text'
            Account = $xml.Event.EventData.Data[4].'#text'
        }
    } | Export-Csv "$OutputPath\08_new_services.csv" -NoTypeInformation

# Copy critical event logs
$evtxDest = "$OutputPath\EventLogs"
New-Item -ItemType Directory -Path $evtxDest -Force | Out-Null
$logsToCollect = @('Security', 'System', 'Application',
    'Microsoft-Windows-Sysmon/Operational',
    'Microsoft-Windows-PowerShell/Operational',
    'Microsoft-Windows-TaskScheduler/Operational',
    'Microsoft-Windows-WMI-Activity/Operational')
foreach ($log in $logsToCollect) {
    $safeName = $log -replace '/', '_' -replace ' ', '_'
    $evtxPath = "$env:SystemRoot\System32\winevt\Logs\$($log -replace '/', '%4').evtx"
    if (Test-Path $evtxPath) {
        Copy-Item $evtxPath "$evtxDest\$safeName.evtx" -ErrorAction SilentlyContinue
        Write-Item "Collected: $log"
    }
}

Write-OK "Event log analysis complete"

# =============================================================================
Write-Header "9. DRIVER AUDIT"
# =============================================================================
Write-Item "Auditing kernel drivers..."

# Unsigned drivers
Get-WmiObject Win32_SystemDriver | ForEach-Object {
    $path = $_.PathName -replace '"','' -replace ' .*',''
    if (Test-Path $path -ErrorAction SilentlyContinue) {
        $sig = Get-AuthenticodeSignature $path -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            Name   = $_.Name
            Path   = $path
            Status = $sig.Status
            Signer = $sig.SignerCertificate.Subject
        }
    }
} | Where-Object { $_.Status -ne 'Valid' } |
    Export-Csv "$OutputPath\09_unsigned_drivers.csv" -NoTypeInformation

# Check testsigning
$bcd = bcdedit /enum 2>$null
if ($bcd -match 'testsigning.*yes') {
    Write-Finding "TEST SIGNING ENABLED — driver signature enforcement disabled"
}

Write-OK "Driver audit complete"

# =============================================================================
Write-Header "FINALISE"
# =============================================================================

# Hash all collected files
Write-Item "Hashing output files for integrity..."
Get-ChildItem $OutputPath -Recurse -File |
    Where-Object { $_.Name -ne 'checksums.sha256' } |
    ForEach-Object {
        $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
        "$hash  $($_.FullName)"
    } | Out-File "$OutputPath\checksums.sha256"

Stop-Transcript | Out-Null

$fileCount = (Get-ChildItem $OutputPath -Recurse -File).Count
$size = (Get-ChildItem $OutputPath -Recurse | Measure-Object -Property Length -Sum).Sum / 1MB

Write-Host "`n$('='*50)" -ForegroundColor Green
Write-Host "  TRIAGE COMPLETE" -ForegroundColor Green
Write-Host $('='*50) -ForegroundColor Green
Write-Host "  Output:  $OutputPath" -ForegroundColor Cyan
Write-Host "  Files:   $fileCount" -ForegroundColor Cyan
Write-Host "  Size:    $([math]::Round($size,2)) MB" -ForegroundColor Cyan
Write-Host "  Time:    $(Get-Date)" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Archive: Compress-Archive -Path '$OutputPath' -DestinationPath '$OutputPath.zip'" -ForegroundColor Yellow
