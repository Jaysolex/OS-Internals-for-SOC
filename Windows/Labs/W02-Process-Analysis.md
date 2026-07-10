# W02 — Process Analysis & Injection Detection

**Module:** Windows/03-Process-Internals  
**Time:** 40 minutes  
**Objective:** Enumerate processes with parent-child context, find unsigned binaries, detect anomalous parent-child relationships, and understand injection indicators.

---

## Exercise 1 — Full Process Tree with Context

```powershell
# Full process list with parent, path, and signature
Get-WmiObject Win32_Process | ForEach-Object {
    $proc = Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue
    $sig = if ($proc.Path) {
        (Get-AuthenticodeSignature $proc.Path -ErrorAction SilentlyContinue).Status
    } else { "NoPath" }
    [PSCustomObject]@{
        PID       = $_.ProcessId
        PPID      = $_.ParentProcessId
        Name      = $_.Name
        Path      = $proc.Path
        Signature = $sig
        CmdLine   = $_.CommandLine
    }
} | Format-Table -AutoSize
```

---

## Exercise 2 — Validate Critical Process Parent-Child

```powershell
# Check that critical processes have correct parents
$critical = @{
    'lsass.exe'    = 'wininit.exe'
    'services.exe' = 'wininit.exe'
    'winlogon.exe' = 'smss.exe'
    'csrss.exe'    = 'smss.exe'
}

Get-WmiObject Win32_Process | ForEach-Object {
    $proc = $_
    $parent = Get-WmiObject Win32_Process |
        Where-Object { $_.ProcessId -eq $proc.ParentProcessId }
    if ($critical.ContainsKey($proc.Name)) {
        $expected = $critical[$proc.Name]
        $actual = $parent.Name
        $status = if ($actual -eq $expected -or $actual -eq $null) { "OK" } else { "ANOMALY" }
        [PSCustomObject]@{
            Process  = $proc.Name
            PID      = $proc.ProcessId
            Parent   = $actual
            Expected = $expected
            Status   = $status
        }
    }
} | Format-Table -AutoSize
```

---

## Exercise 3 — Find Unsigned Processes

```powershell
# All processes with invalid or missing signatures
Get-WmiObject Win32_Process | ForEach-Object {
    $proc = Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue
    if ($proc.Path) {
        $sig = Get-AuthenticodeSignature $proc.Path -ErrorAction SilentlyContinue
        if ($sig.Status -ne 'Valid') {
            [PSCustomObject]@{
                Name      = $_.Name
                PID       = $_.ProcessId
                Path      = $proc.Path
                SigStatus = $sig.Status
            }
        }
    }
} | Format-Table -AutoSize
```

---

## Exercise 4 — Detect Processes Without Disk Path

```powershell
# Processes with no file on disk (hollowing indicator)
Get-Process | ForEach-Object {
    try {
        $path = $_.Path
        if (-not $path) {
            Write-Host "NO PATH: $($_.Name) PID:$($_.Id)" -ForegroundColor Yellow
        } elseif (-not (Test-Path $path)) {
            Write-Host "FILE MISSING: $($_.Name) PID:$($_.Id) -> $path" -ForegroundColor Red
        }
    } catch {}
}
```

---

## Exercise 5 — Sysmon Process Creation Review

```powershell
# Review recent Sysmon process creation events
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 1
} -MaxEvents 30 -ErrorAction SilentlyContinue | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        Time       = $_.TimeCreated
        Image      = ($data | Where-Object {$_.Name -eq 'Image'}).'#text'
        CmdLine    = ($data | Where-Object {$_.Name -eq 'CommandLine'}).'#text'
        ParentImg  = ($data | Where-Object {$_.Name -eq 'ParentImage'}).'#text'
        User       = ($data | Where-Object {$_.Name -eq 'User'}).'#text'
    }
} | Format-Table -AutoSize
```

---

## Validation

```powershell
# Run Windows triage and check process output
powershell.exe -ExecutionPolicy Bypass -File `
    "$HOME\OS-Internals-for-SOC\Scripts\Windows\windows-triage.ps1" `
    -OutputPath C:\IR\lab_w02

Import-Csv C:\IR\lab_w02\04_processes.csv |
    Where-Object { $_.Signature -ne 'Valid' } |
    Format-Table Name, PID, Path, Signature -AutoSize
```
