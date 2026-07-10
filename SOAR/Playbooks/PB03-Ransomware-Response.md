# PB03 — Ransomware Response Playbook

**Trigger:** Shadow copy deletion detected (Event ID 4688 with vssadmin/wmic delete) OR mass file rename with unusual extensions  
**Severity:** Critical  
**Platform:** Windows  
**MITRE:** T1490 — Inhibit System Recovery, T1486 — Data Encrypted for Impact  

---

## What This Playbook Does

Provides a structured response to ransomware incidents from first detection through containment, scope assessment, and recovery initiation. Speed is critical — every minute of delay increases encryption scope.

---

## Critical Rule

**DO NOT REBOOT ANY AFFECTED HOST.**  
Rebooting may complete the encryption, destroy volatile evidence, and eliminate recovery options.

---

## Playbook Flow

```
SHADOW COPY DELETION OR MASS FILE RENAME DETECTED
        |
        v
STEP 1: IMMEDIATE CONTAINMENT (within 5 minutes)
  Network isolate all affected hosts
  Alert management and legal
        |
        v
STEP 2: SCOPE ASSESSMENT
  Which hosts are affected?
  Has encryption started?
  What data is at risk?
        |
        v
STEP 3: EVIDENCE PRESERVATION
  Acquire memory from affected hosts
  Preserve disk state
  Document ransom note
        |
        v
STEP 4: RECOVERY ASSESSMENT
  Are offline backups intact?
  Are they accessible from network (may be encrypted too)?
        |
        v
STEP 5: ERADICATION
  Identify initial access vector
  Remove malware from clean systems
        |
        v
STEP 6: RECOVERY
  Restore from clean backups
  Rebuild if necessary
        |
        v
STEP 7: POST-INCIDENT
  Report, lessons learned, hardening
```

---

## Step 1 — Immediate Containment

**Network isolation — highest priority:**

```powershell
# Isolate host immediately via Windows Firewall
# Block everything except your management IP
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound
netsh advfirewall firewall add rule name="IR-MGMT" `
    dir=in action=allow remoteip=<MANAGEMENT_IP> protocol=any

Write-Host "HOST ISOLATED — DO NOT REBOOT"
```

**Alert chain — notify immediately:**
- SOC Manager
- CISO / Security Leadership  
- Legal Counsel (ransomware = potential data breach notification requirement)
- IT Infrastructure (stop backups connecting to network)
- Executive team if critical systems affected

---

## Step 2 — Scope Assessment

```powershell
# Check which hosts have shadow copy deletion events
# Run on domain controller or SIEM

# Check for mass file rename (encryption indicator)
# Files renamed to unusual extensions in short timeframe
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational'; Id=11
} -MaxEvents 1000 -ErrorAction SilentlyContinue | ForEach-Object {
    $xml = [xml]$_.ToXml()
    ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetFilename'}).'#text'
} | ForEach-Object {
    [System.IO.Path]::GetExtension($_)
} | Group-Object | Sort-Object Count -Descending | Select-Object -First 20

# Look for ransom note files
Get-ChildItem C:\ -Recurse -Include "*.txt","*.html","*.hta" `
    -ErrorAction SilentlyContinue |
    Where-Object { $_.CreationTime -gt (Get-Date).AddHours(-2) } |
    Where-Object { (Get-Content $_ -ErrorAction SilentlyContinue) -match "ransom|bitcoin|decrypt|payment" } |
    Select-Object FullName, CreationTime
```

---

## Step 3 — Evidence Preservation

```powershell
# Acquire memory BEFORE any other action
# Use WinPmem or DumpIt
# winpmem_mini.exe C:\IR\memory.raw

# Document current state
$irDir = "C:\IR\ransomware_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $irDir -Force | Out-Null

# Running processes
Get-WmiObject Win32_Process |
    Select-Object ProcessId, ParentProcessId, Name, CommandLine |
    Export-Csv "$irDir\processes.csv" -NoTypeInformation

# Network connections
Get-NetTCPConnection | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        Local=$_.LocalAddress+":"+$_.LocalPort
        Remote=$_.RemoteAddress+":"+$_.RemotePort
        State=$_.State; Process=$proc.Name
    }
} | Export-Csv "$irDir\connections.csv" -NoTypeInformation

# Collect ransom note
Get-ChildItem C:\ -Recurse -Include "README*.txt","RECOVER*.txt","HOW_TO*.txt" `
    -ErrorAction SilentlyContinue |
    ForEach-Object { Copy-Item $_.FullName $irDir }

# Note the file extension being used
Write-Host "Document the encrypted file extension for threat intel matching"
```

---

## Step 4 — Recovery Assessment

```powershell
# Check if shadow copies survived (unlikely but check)
vssadmin list shadows
Get-WmiObject Win32_ShadowCopy | Select-Object ID, InstallDate

# Check backup status (DO NOT connect backup system to network if not already connected)
Write-Host "BACKUP CHECK — Answer these questions:"
Write-Host "1. When was the last clean backup?"
Write-Host "2. Is the backup stored offline or air-gapped?"
Write-Host "3. Has the backup target been connected to the network during incident?"
Write-Host "4. Can you restore from backup to clean hardware?"
Write-Host ""
Write-Host "IF BACKUP IS NETWORK-CONNECTED: Isolate backup system immediately"
```

---

## Step 5 — Initial Access Investigation

```powershell
# Determine how ransomware entered
# Common vectors: phishing, RDP brute force, VPN exploit, supply chain

# Check RDP logons before incident
Get-WinEvent -FilterHashtable @{
    LogName='Security'; Id=4624
    StartTime=(Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue | Where-Object {
    $xml = [xml]$_.ToXml()
    $xml.Event.EventData.Data[8].'#text' -eq '10'  # Type 10 = RDP
} | Select-Object TimeCreated, Message | Format-List

# Check for phishing email delivery
Write-Host "Review email gateway logs for suspicious attachments in last 7 days"
Write-Host "Common initial access: .zip, .iso, .lnk, .xlsm, .docm attachments"

# Check first execution time of ransomware binary
# Use Prefetch and Amcache
Write-Host "Run: PECmd.exe -d C:\Windows\Prefetch to find ransomware first execution"
Write-Host "Run: AmcacheParser.exe -f C:\Windows\AppCompat\Programs\Amcache.hve"
```

---

## Communication Templates

### Internal Alert (send immediately)

```
SUBJECT: [CRITICAL] Ransomware Incident Detected — Action Required

Ransomware activity has been detected on [HOSTNAME(S)].

Current status:
- Affected systems isolated from network
- Evidence preservation in progress
- Scope assessment underway

Immediate actions required:
- IT: Do NOT connect backup systems to the network
- Legal: Prepare for potential breach notification assessment
- Management: IR team has been engaged

Next update: [TIME — typically 1 hour]

IR Lead: Solomon James
```

### Executive Summary (after scope assessment)

```
RANSOMWARE INCIDENT SUMMARY
============================
Detection time:
Systems affected:
Data potentially encrypted:
Backups available: YES / NO
Estimated recovery time:
External IR required: YES / NO
Regulatory notification required: Assessment in progress
```

---

## Decision Tree — Pay or Not Pay

This decision belongs to executive leadership and legal counsel, not the security team. The security team provides:

1. Technical scope of the damage
2. Viability of backup recovery
3. Evidence of data exfiltration (double-extortion)
4. Threat actor identity and known decryptor availability

Do NOT make payment recommendations. Document the options and escalate.

---

## Post-Incident Hardening Checklist

```
[ ] Implement offline backup strategy (3-2-1 rule)
[ ] Restrict RDP to VPN-only or disable entirely
[ ] Implement network segmentation (blast radius reduction)
[ ] Deploy EDR on all endpoints
[ ] Enable Protected Folders (Windows Controlled Folder Access)
[ ] Implement email attachment sandboxing
[ ] Enable MFA on all remote access
[ ] Patch externally-facing systems within 48 hours of critical CVE
[ ] Conduct phishing awareness training
[ ] Test backup restoration process quarterly
```

---

*PB03 — Ransomware Response | OS-Internals-for-SOC | Solomon James (@Jaysolex)*
