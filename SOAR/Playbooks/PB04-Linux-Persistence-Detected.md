# PB04 — Linux Persistence Detected Response Playbook

**Trigger:** New cron job, systemd unit, SSH key, or LD_PRELOAD entry detected outside maintenance window  
**Severity:** High  
**Platform:** Linux  
**MITRE:** T1053.003, T1543.002, T1098.004, T1574.006  

---

## What This Playbook Does

Responds to detection of persistence mechanisms on Linux systems. Determines whether the persistence is attacker-planted or legitimate, identifies what it executes, and drives remediation.

---

## Trigger Sources

| Trigger | Source | Rule |
|---------|--------|------|
| New file in /etc/cron.d/ | auditd / Wazuh FIM | Rule 100014 |
| New .service file in /etc/systemd/system/ | auditd / Wazuh FIM | Rule 100016 |
| authorized_keys modified | auditd / Wazuh FIM | Rule 100013 |
| /etc/ld.so.preload created | auditd / Wazuh FIM | Rule 100017 |
| New user account created | auditd | Rule 100009 |
| Sudoers modified | auditd / Wazuh FIM | Rule 100011 |

---

## Playbook Flow

```
PERSISTENCE ALERT RECEIVED
        |
        v
STEP 1: CLASSIFY
  What type of persistence? (cron/systemd/SSH key/LD_PRELOAD)
  What does it execute?
  When was it created?
        |
        v
STEP 2: DETERMINE LEGITIMACY
  Does this match a known deployment, update, or admin action?
  Check change management records
  Check with system owner
        |
        v
STEP 3: THREAT ASSESSMENT
  Is the payload malicious?
  Network callbacks? Encoded commands? References to /tmp?
        |
        v
  LEGITIMATE?  ──YES──> Document, whitelist, close
  MALICIOUS?   ──────> Step 4: Contain
        |
        v
STEP 4: CONTAIN
  Disable/remove the persistence mechanism
  Kill any running payload processes
        |
        v
STEP 5: FULL PERSISTENCE HUNT
  Check ALL persistence locations on this host
        |
        v
STEP 6: SCOPE
  Has the attacker moved to other hosts?
        |
        v
STEP 7: REMEDIATE AND REPORT
```

---

## Step 1 — Classify and Extract Details

```bash
# For cron persistence
CRON_FILE="/etc/cron.d/<filename>"
cat "$CRON_FILE"
# What command does it run?
# Does it contain curl, wget, nc, bash -i, /tmp/?

# For systemd persistence
UNIT_FILE="/etc/systemd/system/<name>.service"
systemctl cat <service_name>
# What is ExecStart? Who does it run as?

# For SSH key persistence
KEYS_FILE="/home/<user>/.ssh/authorized_keys"
cat "$KEYS_FILE"
# How many keys? Are they known?

# For LD_PRELOAD
cat /etc/ld.so.preload
# What library is listed?
# Analyse the library: file, strings, ldd
```

---

## Step 2 — Legitimacy Check

```bash
# When was the file created?
stat /etc/cron.d/<filename>

# Who created it? (auditd)
sudo ausearch -f /etc/cron.d/<filename> | grep -A5 "type=PATH"

# Check change management
# Was there a maintenance window at this time?
# Was there a deployment or package update?

# Check package manager
dpkg -S /etc/cron.d/<filename> 2>/dev/null || echo "NOT INSTALLED BY PACKAGE"
rpm -qf /etc/cron.d/<filename> 2>/dev/null || echo "NOT INSTALLED BY PACKAGE"
```

---

## Step 3 — Payload Analysis

```bash
# Extract the command being run
# For cron:
PAYLOAD=$(grep -v "^#\|^$" /etc/cron.d/<filename> | awk '{print $NF}')
echo "Payload: $PAYLOAD"

# Check if payload file exists
[ -f "$PAYLOAD" ] && file "$PAYLOAD" || echo "Payload file missing — may have been deleted"

# If payload exists — analyse
strings "$PAYLOAD" | grep -iE "http|connect|bash|/tmp|exec|socket|curl|wget"

# Check if it's base64 encoded
echo "$PAYLOAD" | base64 -d 2>/dev/null | strings | head -20

# For SSH key — check key fingerprint
ssh-keygen -lf /home/<user>/.ssh/authorized_keys

# For LD_PRELOAD library
LIB=$(cat /etc/ld.so.preload)
file "$LIB"
strings "$LIB" | grep -iE "hook|intercept|hide|rootkit|http|connect"
nm -D "$LIB" 2>/dev/null | grep "getdents\|read\|open\|stat"
# Hooking getdents/read = hiding files — rootkit indicator
```

---

## Step 4 — Containment

```bash
# Cron persistence removal
rm /etc/cron.d/<malicious_file>
# For user crontab:
crontab -r -u <username>

# Systemd persistence removal
systemctl stop <malicious_service>
systemctl disable <malicious_service>
rm /etc/systemd/system/<malicious_service>.service
systemctl daemon-reload

# SSH key removal
# Edit authorized_keys and remove the malicious key
nano /home/<user>/.ssh/authorized_keys
# Or remove specific key by fingerprint

# LD_PRELOAD removal — CRITICAL
# Removing /etc/ld.so.preload stops the library from loading
# But existing processes already have it loaded
rm /etc/ld.so.preload
echo "LD_PRELOAD removed — existing processes may still be affected until reboot"

# Kill payload processes
PID=$(pgrep -f "<payload_name>")
kill -9 $PID
```

---

## Step 5 — Full Persistence Hunt

```bash
# Run automated hunt
sudo bash ~/OS-Internals-for-SOC/Scripts/Linux/persistence-hunter.sh | \
  tee /tmp/persistence_hunt_$(date +%Y%m%d).txt

# Also check manually
echo "=== ALL CRON LOCATIONS ==="
cat /etc/crontab
ls -la /etc/cron.d/ && cat /etc/cron.d/*
for u in $(cut -d: -f1 /etc/passwd); do
  cron=$(crontab -l -u $u 2>/dev/null | grep -v "^#\|^$")
  [ -n "$cron" ] && echo "USER $u: $cron"
done

echo "=== ALL SYSTEMD UNITS IN /etc/systemd/system/ ==="
ls -la /etc/systemd/system/*.service 2>/dev/null
for unit in /etc/systemd/system/*.service; do
  [ -f "$unit" ] && dpkg -S "$unit" 2>/dev/null || echo "NOT PACKAGED: $unit"
done

echo "=== ALL SSH AUTHORIZED KEYS ==="
find / -name "authorized_keys" 2>/dev/null | while read f; do
  echo "=== $f ==="; cat "$f"
done

echo "=== LD_PRELOAD STATUS ==="
cat /etc/ld.so.preload 2>/dev/null || echo "CLEAN — file does not exist"
```

---

## Step 6 — Lateral Movement Assessment

```bash
# Check what other hosts this system can reach
cat ~/.ssh/known_hosts
cat /root/.ssh/known_hosts

# Check recent SSH connections FROM this host
grep "Accepted\|Connected to" /var/log/auth.log | grep -v "from" | head -20

# Check for credential files that could enable lateral movement
find / -name "*.pem" -o -name "id_rsa" -o -name "id_ed25519" \
  -o -name ".aws/credentials" 2>/dev/null

# Review bash history for ssh commands
cat /root/.bash_history | grep "ssh "
for home in /home/*; do cat "$home/.bash_history" 2>/dev/null | grep "ssh "; done
```

---

## Step 7 — Report Template

```
PERSISTENCE INCIDENT REPORT
============================
Incident ID:   INC-XXXX
Date:          
Host:          
Severity:      HIGH
MITRE:         T1053.003 / T1543.002 / T1098.004 / T1574.006

PERSISTENCE DETAILS
--------------------
Type:          [ ] Cron  [ ] Systemd  [ ] SSH Key  [ ] LD_PRELOAD  [ ] Other
Location:      
Created:       
Created by:    
Payload:       

LEGITIMACY ASSESSMENT
----------------------
[ ] Change ticket exists
[ ] Known deployment
[ ] Package-managed
[ ] CONFIRMED MALICIOUS

PAYLOAD ANALYSIS
-----------------
File type:
Network callbacks found:    YES / NO
References to /tmp:         YES / NO
Base64 encoding:            YES / NO
Verdict:

CONTAINMENT ACTIONS
--------------------
[ ] Persistence removed
[ ] Payload processes killed
[ ] Full persistence hunt completed
[ ] Additional persistence found

SCOPE
------
[ ] Limited to this host
[ ] Lateral movement evidence found
[ ] Other hosts affected:

RECOMMENDATIONS
----------------
1. Conduct full IR if other persistence found
2. Reset credentials accessible from this host
3. Rotate SSH keys for all accounts on this system
4. Review change management process
5. Enable auditd if not already active
```

---

*PB04 — Linux Persistence Response | OS-Internals-for-SOC | Solomon James (@Jaysolex)*
