# H06 — Kerberoasting Hunt

**Hypothesis:** An attacker with domain credentials is requesting RC4-encrypted Kerberos service tickets for offline password cracking.

**OS Mechanism:** The Kerberos protocol allows any authenticated domain user to request service tickets for any SPN-registered account. Tickets encrypted with RC4 are faster to crack offline.

**MITRE:** T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting

---

## Baseline

In a healthy environment:
- Service ticket requests use AES256 encryption (0x12) not RC4 (0x17)
- Users request tickets for services they actually use
- A single user does not request tickets for dozens of services in minutes

## Anomaly Indicators

- Event ID 4769 with TicketEncryptionType = 0x17 (RC4)
- Multiple service ticket requests from one account in short timeframe
- Service ticket requests for accounts the user never normally accesses
- Requests coming from unusual source IPs (not the user's normal workstation)

---

## Hunt Queries

### PowerShell — Domain Controller

```powershell
# Find Kerberoastable accounts (have SPN, are user accounts)
Get-ADUser -Filter { ServicePrincipalName -ne "$null" } `
    -Properties ServicePrincipalName, PasswordLastSet, LastLogonDate |
    Select-Object SamAccountName, ServicePrincipalName, PasswordLastSet, LastLogonDate |
    Where-Object { $_.SamAccountName -ne 'krbtgt' }
```

### Splunk SPL

```spl
index=wineventlog EventCode=4769 TicketEncryptionType=0x17
| where NOT match(ServiceName, "\$$")
| stats count by AccountName, ServiceName, IpAddress
| where count > 1
| sort -count
```

```spl
| Volume-based Kerberoasting (many tickets in short window)
index=wineventlog EventCode=4769 TicketEncryptionType=0x17
| where NOT match(ServiceName, "\$$")
| bucket _time span=5m
| stats dc(ServiceName) AS unique_services count BY AccountName, IpAddress, _time
| where unique_services > 5
| sort -unique_services
```

### KQL

```kql
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"
| where ServiceName !endswith "$"
| summarize RequestCount=count(), Services=make_set(ServiceName)
    by AccountName, IpAddress, bin(TimeGenerated, 5m)
| where RequestCount > 5
| sort by RequestCount desc
```

---

## Validation

1. Confirm the requesting account — is it a service account or user account?
2. Check if the account normally accesses the requested services
3. Check source IP — is it the user's normal workstation?
4. Look for subsequent authentication using the targeted service accounts

## Response

1. Identify all targeted service accounts from the 4769 events
2. Reset passwords for all targeted accounts immediately
3. Enforce AES-only Kerberos where possible
4. Enable fine-grained password policies for service accounts
5. Consider managed service accounts (MSAs) which have automatic 240-char passwords
