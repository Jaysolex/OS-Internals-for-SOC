# W01 — Registry Forensics

**Module:** Windows/02-Registry-Internals  
**Time:** 30 minutes  
**Objective:** Enumerate registry persistence locations, understand hive structure, and practice forensic registry analysis.

---

## Exercise 1 — Enumerate All Autorun Keys

```powershell
# Query all run keys
$keys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($key in $keys) {
    Write-Host "=== $key ===" -ForegroundColor Cyan
    Get-ItemProperty $key -ErrorAction SilentlyContinue |
        Select-Object * -ExcludeProperty PS* | Format-List
}
```

---

## Exercise 2 — Check Critical Security Settings

```powershell
# Winlogon — should only have userinit.exe and explorer.exe
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" |
    Select-Object Userinit, Shell, Notify

# WDigest — should be 0 or absent
(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
    -ErrorAction SilentlyContinue).UseLogonCredential

# LSASS PPL — should be 1 on hardened systems
(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue).RunAsPPL

# UAC settings
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" |
    Select-Object EnableLUA, ConsentPromptBehaviorAdmin
```

---

## Exercise 3 — IFEO Check

```powershell
# Check for any IFEO debugger entries
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" |
    ForEach-Object {
        $dbg = (Get-ItemProperty $_.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger
        if ($dbg) {
            Write-Host "IFEO: $($_.PSChildName) -> $dbg" -ForegroundColor Red
        }
    }
# Should return nothing on a clean system
```

---

## Exercise 4 — Plant and Detect Run Key (Lab Only)

```powershell
# Plant a harmless run key
Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
    -Name "LabTest" `
    -Value "cmd.exe /c echo LabTest ran > C:\Temp\lab_test.txt"

# Verify it was added
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

# Sysmon should capture this — check
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational'; Id=13
} -MaxEvents 5 | Where-Object { $_.Message -match 'LabTest' }

# CLEANUP
Remove-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "LabTest"
```

---

## Exercise 5 — Export Hive for Offline Analysis

```powershell
# Export SOFTWARE hive (requires admin)
reg save HKLM\SOFTWARE C:\Temp\SOFTWARE.hiv

# View file
ls C:\Temp\SOFTWARE.hiv

# This is what you'd collect during IR
# Parse offline with RegRipper or Registry Explorer (Eric Zimmerman)
```

---

## Validation

Run the Windows triage script and verify it captures all persistence:

```powershell
powershell.exe -ExecutionPolicy Bypass -File `
    "C:\Path\To\OS-Internals-for-SOC\Scripts\Windows\windows-triage.ps1" `
    -OutputPath C:\IR\lab_w01

# Review the output
Get-ChildItem C:\IR\lab_w01
cat C:\IR\lab_w01\05_run_keys.csv
```
