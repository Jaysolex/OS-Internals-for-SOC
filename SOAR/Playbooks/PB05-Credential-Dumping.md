# PB05 — Credential Dumping Response Playbook

**Trigger:** Sysmon Event ID 10 — LSASS access with read permissions from non-system process  
**Severity:** High → Critical  
**Platform:** Windows  
**MITRE:** T1003.001 — OS Credential Dumping: LSASS Memory  

---

## What This Playbook Does

Responds to detected credential dumping attempts against LSASS. Determines whether dumping succeeded, what credentials were exposed, and drives credential rotation across the environment.

---

## Trigger Conditions

| Condition | Severity | Response |
|-----------|----------|---------|
| LSASS accessed with 0x1010/0x1410 | High | Investigate immediately |
| procdump.exe targeting LSASS | High | Contain source host |
| .dmp file created after LSASS access | Critical | Full IR, rotate all creds |
| WDigest enabled + LSASS access | Critical | Cleartext exposed |

---

## Playbook Flow

```
LSASS ACCESS ALERT (Sysmon EID 10)
        |
        v
STEP 1: TRIAGE
  What process accessed LSASS?
  What access mask was used?
  Was a dump file created?
        |
        v
STEP 2: DETERMINE SCOPE
  Was this a known security tool?
  Did credential theft succeed?
  What credentials were accessible?
        |
        v
STEP 3: CONTAIN
  Isolate host if active dumping
  Kill dumping process
        |
        v
STEP 4: ASSESS CREDENTIAL EXPOSURE
  Which accounts were logged in at dump time?
  Were domain admin credentials present?
        |
        v
STEP 5: ROTATE CREDENTIALS
  Reset all accounts logged in at time of dump
  Rotate service accounts
  Invalidate Kerberos tickets (krbtgt if Golden Ticket suspected)
        |
        v
STEP 6: HUNT FOR LATERAL MOVEMENT
  Were stolen credentials used elsewhere?
        |
        v
STEP 7: REPORT
```

---

## Step 1 — Triage

```powershell
# Get LSASS access event details
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational'; Id=10
} -MaxEvents 20 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'lsass.exe' } |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        [PSCustomObject]@{
            Time          = $_.TimeCreated
            SourceImage   = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SourceImage'}).'#text'
            SourcePID     = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SourceProcessId'}).'#text'
            GrantedAccess = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'GrantedAccess'}).'#text'
            CallTrace     = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'CallTrace'}).'#text'
        }
    } | Format-List

# Check if a dump file was created after the access
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational'; Id=11
} -MaxEvents 50 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match '\.dmp$|lsass' } |
    Select-Object TimeCreated, Message
```

---

## Step 2 — Determine Scope

```powershell
# Check WDigest status at time of dump
$wdigest = (Get-ItemProperty `
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
    -ErrorAction SilentlyContinue).UseLogonCredential

if ($wdigest -eq 1) {
    Write-Host "CRITICAL: WDigest was ENABLED — cleartext credentials were exposed" `
        -ForegroundColor Red
}

# Who was logged in at time of dump?
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 50 |
    Select-Object TimeCreated, Message | Format-Table -AutoSize

# What domain accounts had active sessions?
query session
klist
```

---

## Step 3 — Containment

```powershell
# Find and kill the dumping process
$dumpPID = <PID_FROM_SYSMON_EVENT>
Stop-Process -Id $dumpPID -Force -ErrorAction SilentlyContinue

# Remove any dump files
Get-ChildItem C:\ -Recurse -Filter "*.dmp" -ErrorAction SilentlyContinue |
    Where-Object { $_.CreationTime -gt (Get-Date).AddHours(-2) } |
    ForEach-Object {
        Write-Host "Found dump: $($_.FullName)" -ForegroundColor Red
        # Hash before deleting for evidence
        Get-FileHash $_.FullName
        Remove-Item $_.FullName -Force
    }

# Isolate if active dumping tool detected
Write-Host "If active attacker: isolate host via firewall or EDR"
```

---

## Step 4 — Credential Exposure Assessment

```powershell
# List all accounts with active logon sessions
Write-Host "=== ACCOUNTS WITH SESSIONS AT TIME OF DUMP ===" -ForegroundColor Red
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 100 |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        [PSCustomObject]@{
            Time     = $_.TimeCreated
            User     = $xml.Event.EventData.Data[5].'#text'
            Domain   = $xml.Event.EventData.Data[6].'#text'
            LogonId  = $xml.Event.EventData.Data[7].'#text'
            Type     = $xml.Event.EventData.Data[8].'#text'
        }
    } | Where-Object { $_.User -ne '-' } |
    Select-Object Time, User, Domain, Type |
    Sort-Object Time -Descending | Format-Table -AutoSize

Write-Host ""
Write-Host "ALL accounts above should have passwords reset immediately" -ForegroundColor Red
Write-Host "If any DOMAIN ADMIN accounts are listed — treat as domain compromise"
```

---

## Step 5 — Credential Rotation

```powershell
# Reset local accounts
# (Run for each account that was logged in)
net user <username> <newpassword>

# Force domain password change on next logon
# (Run on domain controller)
Set-ADUser -Identity <username> -ChangePasswordAtLogon $true

# Invalidate Kerberos tickets — reset krbtgt TWICE
# (Run on domain controller — ONLY if domain admin was compromised)
Write-Host "If domain admin compromised:"
Write-Host "  Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString -AsPlainText 'newpass' -Force)"
Write-Host "  Wait 10 hours (max ticket lifetime)"
Write-Host "  Reset krbtgt password a SECOND time"
Write-Host "  This invalidates all Golden Tickets"
```

---

## Step 6 — Lateral Movement Hunt

```powershell
# Look for the stolen credentials being used elsewhere
# Type 3 NTLM logons from this host to other systems
Get-WinEvent -FilterHashtable @{
    LogName='Security'; Id=4624
    StartTime=(Get-Date).AddHours(-24)
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $type = $xml.Event.EventData.Data[8].'#text'
    $auth = $xml.Event.EventData.Data[14].'#text'
    if ($type -eq '3' -and $auth -eq 'NTLM') {
        [PSCustomObject]@{
            Time    = $_.TimeCreated
            User    = $xml.Event.EventData.Data[5].'#text'
            Source  = $xml.Event.EventData.Data[18].'#text'
            Target  = $_.MachineName
        }
    }
} | Format-Table -AutoSize
```

---

## Step 7 — Report Template

```
CREDENTIAL DUMPING INCIDENT REPORT
=====================================
Incident ID:   INC-XXXX
Date:          
Host:          
Severity:      HIGH / CRITICAL
MITRE:         T1003.001 — LSASS Memory Dumping

DUMPING DETAILS
----------------
Dumping process:
Access mask:
Dump file created:     YES / NO
WDigest enabled:       YES / NO (if YES = cleartext exposed)

EXPOSED CREDENTIALS
--------------------
Local accounts:
Domain accounts:
Privileged accounts:   YES / NO (list)
Domain admin exposed:  YES / NO

CONTAINMENT
-----------
[ ] Dumping process killed
[ ] Dump files removed and hashed
[ ] Host isolated
[ ] Credentials rotated
[ ] krbtgt reset (if domain admin exposed)

LATERAL MOVEMENT
-----------------
[ ] Type 3 NTLM logons investigated
[ ] No lateral movement found
[ ] Lateral movement confirmed to: [hosts]

RECOMMENDATIONS
----------------
1. Enable LSASS PPL: reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 1
2. Disable WDigest: reg add HKLM\SYSTEM\...\WDigest /v UseLogonCredential /t REG_DWORD /d 0
3. Enable Credential Guard
4. Implement tiered admin model (no DA accounts on workstations)
5. Deploy EDR with LSASS protection
```

---

*PB05 — Credential Dumping Response | OS-Internals-for-SOC | Solomon James (@Jaysolex)*
