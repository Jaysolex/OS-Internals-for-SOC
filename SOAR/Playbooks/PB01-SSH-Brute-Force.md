# PB01 — SSH Brute Force Response Playbook

**Trigger:** Wazuh Rule 100006 / Sigma linux-ssh-brute-force / SIEM alert — 10+ SSH failures in 5 minutes from single IP  
**Severity:** Medium → Critical (if successful login follows)  
**Platform:** Linux  
**MITRE:** T1110.001 — Brute Force: Password Guessing  

---

## What This Playbook Does

Automates the response to SSH brute force attacks from initial detection through containment, enrichment, and remediation. Escalates automatically when brute force is followed by a successful login.

---

## Trigger Conditions

| Condition | Threshold | Action |
|-----------|-----------|--------|
| Failed SSH attempts | >10 in 5 minutes from single IP | Start playbook |
| Failed SSH + successful login | Any | Escalate to CRITICAL |
| Failed SSH targeting >5 accounts | Any count | Flag as password spray |

---

## Playbook Flow

```
ALERT RECEIVED
      |
      v
STEP 1: TRIAGE
  Extract: source IP, target username, failure count, timeframe
  Check: was there a successful login after failures?
      |
      v
STEP 2: ENRICH
  GeoIP lookup on source IP
  Threat Intel check (VirusTotal, AbuseIPDB)
  Check internal asset inventory for target host
  Check if source IP is internal or external
      |
      v
STEP 3: DECISION GATE
  IP reputation MALICIOUS?  ──YES──> AUTO-CONTAIN (Step 4)
  Successful login detected? ──YES──> CRITICAL ESCALATION (Step 5)
  Unknown reputation?        ──────> ANALYST REVIEW (Slack notification)
      |
      v
STEP 4: CONTAIN (Automated for malicious IPs)
  Block source IP at firewall
  Create ticket in TheHive
  Notify SOC via Slack
      |
      v
STEP 5: INVESTIGATE
  Pull auth.log context for source IP
  Check for post-login activity
  Check for new cron jobs or SSH keys added
      |
      v
STEP 6: REMEDIATE
  If no breach: close ticket, update blocklist
  If breach confirmed: escalate to DFIR, lock account, kill sessions
      |
      v
STEP 7: REPORT
  Document timeline and findings
  Update threat intelligence feed
```

---

## Step 1 — Triage

**Analyst actions:**

```bash
# Pull all auth events for the source IP
grep <SOURCE_IP> /var/log/auth.log | tail -100

# Count failures
grep "Failed password" /var/log/auth.log | grep <SOURCE_IP> | wc -l

# Check for successful login
grep "Accepted" /var/log/auth.log | grep <SOURCE_IP>

# Check rotated logs too
grep "Accepted" /var/log/auth.log.1 /var/log/auth.log.2 2>/dev/null | grep <SOURCE_IP>

# Timeline: first and last event
grep <SOURCE_IP> /var/log/auth.log | head -1
grep <SOURCE_IP> /var/log/auth.log | tail -1
```

**Automated extraction (SOAR pseudocode):**

```python
source_ip     = alert.fields["src_ip"]
target_host   = alert.fields["dest_host"]
failure_count = alert.fields["count"]
timeframe     = alert.fields["timeframe"]

# Check for success after failure
success = query_siem(
    f'index=linux_logs "Accepted" src_ip={source_ip} | earliest=-1h'
)
if success:
    alert.severity = "CRITICAL"
    alert.notes += "BRUTE FORCE FOLLOWED BY SUCCESSFUL LOGIN"
```

---

## Step 2 — Enrichment

```python
# GeoIP
geo = geoip_lookup(source_ip)

# Threat Intelligence
vt  = virustotal_lookup(source_ip)
abu = abuseipdb_lookup(source_ip)

# Internal check
is_internal = source_ip.startswith(("10.", "192.168.", "172."))

# Asset context
asset = asset_inventory_lookup(target_host)

enrichment = {
    "ip":          source_ip,
    "country":     geo["country"],
    "isp":         geo["isp"],
    "vt_score":    vt["malicious_count"],
    "abuse_score": abu["score"],
    "internal":    is_internal,
    "asset_owner": asset["owner"],
    "asset_tier":  asset["tier"]
}
```

---

## Step 3 — Decision Gate

```
abuse_score > 80 OR vt_score > 5
    YES → auto-contain (Step 4)
    NO  → notify analyst for review

successful_login detected
    YES → escalate to CRITICAL regardless of reputation
```

---

## Step 4 — Containment

**Firewall block (Linux iptables):**

```bash
# Block source IP
iptables -I INPUT -s <SOURCE_IP> -j DROP
iptables -I OUTPUT -d <SOURCE_IP> -j DROP

# Verify block
iptables -L INPUT | grep <SOURCE_IP>

# Make persistent
iptables-save > /etc/iptables/rules.v4
```

**If successful login confirmed — additional containment:**

```bash
# Kill active sessions for compromised account
pkill -u <USERNAME>
who | grep <USERNAME>

# Lock the account
passwd -l <USERNAME>
usermod -L <USERNAME>
```

**SOAR automation:**

```python
# Block IP
firewall_block(source_ip, reason="SSH Brute Force", auto=True)

# Create ticket
ticket = create_ticket(
    platform   = "TheHive",
    title      = f"SSH Brute Force from {source_ip} targeting {target_host}",
    severity   = alert.severity,
    tags       = ["T1110.001", "brute-force", "ssh", "linux"],
    assignee   = "soc-l1"
)

# Notify
notify_slack(
    channel = "#soc-alerts",
    message = f"""
SSH Brute Force DETECTED
IP:       {source_ip} ({enrichment['country']})
Host:     {target_host}
Failures: {failure_count}
AbuseIPDB Score: {enrichment['abuse_score']}
Ticket:   {ticket.url}
"""
)
```

---

## Step 5 — Investigation

**Run when successful login is confirmed:**

```bash
# Full activity after login
grep <SOURCE_IP> /var/log/auth.log | grep "Accepted" -A 50

# What account was compromised
COMPROMISED_USER=$(grep "Accepted" /var/log/auth.log | grep <SOURCE_IP> | \
  awk '{print $9}' | head -1)

# Post-login commands (bash history)
cat /home/$COMPROMISED_USER/.bash_history | tail -50

# New SSH keys added after breach
find /home/$COMPROMISED_USER/.ssh -newer /var/log/auth.log -ls 2>/dev/null

# New cron jobs
crontab -l -u $COMPROMISED_USER 2>/dev/null

# New files created by user
find / -user $COMPROMISED_USER -newer /var/log/auth.log \
  -not -path "/proc/*" -ls 2>/dev/null | head -20
```

---

## Step 6 — Remediation

### No Breach Confirmed

```
✅ IP blocked at perimeter
✅ Ticket created and documented
✅ IP added to threat intel blocklist feed
✅ Close ticket as Contained
```

### Breach Confirmed

```
🔴 ESCALATE TO DFIR TEAM

Actions:
  1. Do NOT remediate until DFIR authorises
  2. Preserve memory if possible: avml /media/usb/memory.lime
  3. Disable compromised account: passwd -l <user>
  4. Kill active sessions: pkill -u <user>
  5. Remove unauthorised SSH keys from authorized_keys
  6. Reset account password after forensics complete
  7. Hunt for persistence mechanisms: bash persistence-hunter.sh
  8. Check for lateral movement from this host
```

---

## Step 7 — Report Template

```
INCIDENT REPORT
===============
Incident ID:   INC-XXXX
Date:          
Severity:      
MITRE:         T1110.001 — Brute Force: Password Guessing

SOURCE
------
IP:            
Country:       
ISP:           
AbuseIPDB:     /100
VirusTotal:    /XX engines

TARGET
------
Host:          
Account:       
Successful Login: YES / NO

TIMELINE
--------
First failure:
Threshold crossed:
Alert generated:
Analyst notified:
IP blocked:
Breach confirmed:

ACTIONS TAKEN
-------------
[ ] IP blocked at firewall
[ ] Account locked (if breached)
[ ] Sessions terminated
[ ] Authorized_keys reviewed
[ ] Persistence hunt completed
[ ] Ticket created in TheHive
[ ] IP added to blocklist feed
[ ] DFIR escalated (if breached)

RECOMMENDATIONS
---------------
- Enable fail2ban or sshguard on target host
- Restrict SSH access to VPN/jump host only
- Enforce MFA for SSH authentication
- Implement GeoIP blocking for high-risk countries
- Rotate SSH keys for targeted accounts
```

---

## Escalation Criteria

| Condition | Escalation Level | Who |
|-----------|-----------------|-----|
| Brute force only, no success | L1 SOC | Monitor and close |
| Successful login confirmed | L2 SOC | Investigate immediately |
| Successful login + new persistence found | DFIR | Full IR engagement |
| Breach of privileged account or server | DFIR + Management | Incident declaration |

---

*PB01 — SSH Brute Force Response | OS-Internals-for-SOC | Solomon James (@Jaysolex)*
