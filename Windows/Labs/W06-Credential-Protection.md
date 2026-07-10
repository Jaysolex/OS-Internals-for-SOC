# W06 — Windows Authentication & Credential Protection

**Module:** Windows/06-Authentication-LSASS  
**Time:** 35 minutes  
**Objective:** Audit credential protection settings, identify Kerberoastable accounts, check WDigest status, verify LSASS PPL, and understand what credential dumping leaves behind.

---

## Exercise 1 — Credential Protection Audit

```powershell
# WDigest status — should be 0 or absent
$wdigest = (Get-ItemProperty `
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
    -ErrorAction SilentlyContinue).UseLogonCredential

if ($wdigest -eq 1) {
    Write-Host "RISK: WDigest ENABLED — cleartext credentials stored in LSASS memory" `
        -ForegroundColor Red
} else {
    Write-Host "OK: WDigest disabled (value: $wdigest)" -ForegroundColor Green
}

# LSASS PPL protection
$ppl = (Get-ItemProperty `
    "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -ErrorAction SilentlyContinue).RunAsPPL

if ($ppl -eq 1) {
    Write-Host "OK: LSASS Protected Process Light (PPL) is ENABLED" -ForegroundColor Green
} else {
    Write-Host "RISK: LSASS PPL is NOT enabled — credential dumping easier" -ForegroundColor Yellow
}

# Credential Guard
$cg = (Get-ItemProperty `
    "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" `
    -ErrorAction SilentlyContinue).LsaCfgFlags
Write-Host "Credential Guard setting: $cg (2 = enabled without lock)"
```

---

## Exercise 2 — NTLM Configuration

```powershell
# Check NTLM compatibility level
# 5 or 6 = NTLMv2 only (most secure)
$ntlm = (Get-ItemProperty `
    "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -ErrorAction SilentlyContinue).LmCompatibilityLevel

$ntlm_desc = switch ($ntlm) {
    0 { "INSECURE: LM and NTLM responses" }
    1 { "LOW: LM and NTLM, NTLMv2 if negotiated" }
    2 { "MEDIUM: NTLM only" }
    3 { "GOOD: NTLMv2 only" }
    4 { "BETTER: NTLMv2 only, refuse LM" }
    5 { "SECURE: NTLMv2 only, refuse LM and NTLM" }
    default { "Unknown: $ntlm" }
}

Write-Host "NTLM Level: $ntlm - $ntlm_desc"
[ $ntlm -lt 3 ] && Write-Host "RECOMMEND: Set to 5 for NTLMv2 only" -ForegroundColor Yellow
```

---

## Exercise 3 — Kerberoastable Account Discovery

```powershell
# Find accounts with Service Principal Names (Kerberoastable)
# Requires Active Directory module or domain join
if (Get-Module -ListAvailable -Name ActiveDirectory) {
    Import-Module ActiveDirectory
    Get-ADUser -Filter { ServicePrincipalName -ne "$null" } `
        -Properties ServicePrincipalName, PasswordLastSet, LastLogonDate |
        Where-Object { $_.SamAccountName -ne 'krbtgt' } |
        Select-Object SamAccountName, ServicePrincipalName, PasswordLastSet |
        Format-Table -AutoSize
} else {
    Write-Host "ActiveDirectory module not available"
    Write-Host "In a domain environment, run: Get-ADUser -Filter {ServicePrincipalName -ne '$null'}"
}

# Check current Kerberos tickets
klist
```

---

## Exercise 4 — Sysmon LSASS Access Monitoring

```powershell
# Check for LSASS access events in Sysmon
$lsassAccess = Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational'
    Id=10
} -MaxEvents 50 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'lsass.exe' } |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        [PSCustomObject]@{
            Time          = $_.TimeCreated
            SourceImage   = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SourceImage'}).'#text'
            GrantedAccess = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'GrantedAccess'}).'#text'
        }
    }

if ($lsassAccess) {
    Write-Host "LSASS access events found:" -ForegroundColor Yellow
    $lsassAccess | Format-Table -AutoSize
} else {
    Write-Host "No LSASS access events in Sysmon log" -ForegroundColor Green
}
```

---

## Exercise 5 — Local Account Security Audit

```powershell
# Full local account audit
Write-Host "=== LOCAL USER ACCOUNTS ===" -ForegroundColor Cyan
Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet,
    PasswordNeverExpires, Description | Format-Table -AutoSize

Write-Host "=== LOCAL ADMINISTRATORS ===" -ForegroundColor Cyan
Get-LocalGroupMember -Group "Administrators" | Format-Table -AutoSize

Write-Host "=== RECENT ACCOUNT CHANGES (4720, 4722, 4726, 4738) ===" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=@(4720,4722,4726,4738)
} -MaxEvents 20 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message | Format-List
```

---

## Validation

```powershell
# Save credential config findings
$results = @{
    WDigest = $wdigest
    PPL     = $ppl
    NTLM    = $ntlm
}
$results | ConvertTo-Json | Out-File C:\IR\lab_w06_cred_config.json
Write-Host "Results saved to C:\IR\lab_w06_cred_config.json"
```
