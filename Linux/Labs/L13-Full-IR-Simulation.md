# L13 — Full Incident Response Simulation

**Module:** Linux/12-Forensics-Artifacts  
**Time:** 60 minutes  
**Objective:** Simulate a complete Linux IR engagement from initial triage through forensic artifact collection, analysis, and evidence preservation. This lab ties together all previous modules.

---

## Scenario

You receive an alert: unusual outbound connections detected from a Linux server. SSH access is available. Conduct a live response investigation.

---

## Phase 1 — Immediate Triage (First 5 minutes)

```bash
# Step 1: Note the time and establish a timeline anchor
date
uptime
w

# Step 2: Check for active unusual connections
ss -tnap | grep -v "127.0.0.1\|::1"

# Step 3: Check who is logged in right now
who
last -F | head -10

# Step 4: Quick process check
ps auxef | grep -v "^\[" | tail -20
```

---

## Phase 2 — Run Full Triage Script

```bash
# Run the automated triage — captures everything in order
sudo bash ~/OS-Internals-for-SOC/Scripts/Linux/linux-triage.sh /tmp/ir_case_$(date +%Y%m%d)

# Review what was collected
ls /tmp/ir_case_$(date +%Y%m%d)/
```

---

## Phase 3 — Persistence Hunt

```bash
# Run persistence hunter
sudo bash ~/OS-Internals-for-SOC/Scripts/Linux/persistence-hunter.sh | \
  tee /tmp/ir_case_$(date +%Y%m%d)/persistence_findings.txt

echo "Findings saved to persistence_findings.txt"
```

---

## Phase 4 — Log Analysis

```bash
CASE_DATE=$(date +%Y%m%d)

# SSH authentication analysis
sudo bash ~/OS-Internals-for-SOC/Scripts/Linux/log-parser.sh brute | \
  tee /tmp/ir_case_$CASE_DATE/log_brute.txt

# Privilege escalation analysis
sudo bash ~/OS-Internals-for-SOC/Scripts/Linux/log-parser.sh privesc | \
  tee /tmp/ir_case_$CASE_DATE/log_privesc.txt

# Defense evasion analysis
sudo bash ~/OS-Internals-for-SOC/Scripts/Linux/log-parser.sh evasion | \
  tee /tmp/ir_case_$CASE_DATE/log_evasion.txt
```

---

## Phase 5 — Forensic Artifact Collection

```bash
CASE_DATE=$(date +%Y%m%d)
CASE_DIR=/tmp/ir_case_$CASE_DATE

# Collect shell histories
mkdir -p $CASE_DIR/histories
find /home /root -name ".*history" 2>/dev/null | while read f; do
  cp "$f" "$CASE_DIR/histories/$(echo $f | tr '/' '_')" 2>/dev/null
done

# Collect all SSH authorized_keys
mkdir -p $CASE_DIR/ssh_keys
find / -name "authorized_keys" 2>/dev/null | while read f; do
  cp "$f" "$CASE_DIR/ssh_keys/$(echo $f | tr '/' '_')" 2>/dev/null
done

# Collect cron jobs
mkdir -p $CASE_DIR/cron
cat /etc/crontab > $CASE_DIR/cron/system_crontab.txt
ls /etc/cron.d/ >> $CASE_DIR/cron/system_crontab.txt
for user in $(cut -d: -f1 /etc/passwd); do
  cron=$(crontab -l -u $user 2>/dev/null)
  [ -n "$cron" ] && echo "$cron" > "$CASE_DIR/cron/${user}_crontab.txt"
done

# Collect network state
ss -tnap > $CASE_DIR/network_state.txt
cat /proc/net/tcp > $CASE_DIR/proc_net_tcp.txt
arp -a > $CASE_DIR/arp_cache.txt

echo "All artifacts collected in $CASE_DIR"
```

---

## Phase 6 — Evidence Preservation

```bash
CASE_DATE=$(date +%Y%m%d)
CASE_DIR=/tmp/ir_case_$CASE_DATE

# Hash all collected files for chain of custody
find $CASE_DIR -type f -not -name "checksums.sha256" | \
  sort | xargs sha256sum > $CASE_DIR/checksums.sha256

echo "=== Chain of custody checksums ==="
wc -l $CASE_DIR/checksums.sha256

# Archive for transfer
tar czf /tmp/ir_case_${CASE_DATE}.tar.gz -C /tmp ir_case_${CASE_DATE}/
ls -lh /tmp/ir_case_${CASE_DATE}.tar.gz

echo ""
echo "Transfer command:"
echo "scp /tmp/ir_case_${CASE_DATE}.tar.gz analyst@workstation:/cases/"
```

---

## Phase 7 — IR Report Template

Fill this out based on your findings:

```
INCIDENT RESPONSE REPORT
========================
Date:          $(date)
Host:          $(hostname)
Investigator:  Solomon James

TIMELINE
--------
[ ] Initial alert time:
[ ] IR start time:
[ ] Triage complete:

FINDINGS
--------
Authentication:
  - Failed login attempts:
  - Successful logins from unusual IPs:
  - Accounts modified:

Persistence:
  - Cron jobs added:
  - Systemd units added:
  - SSH keys added:

Network:
  - Unusual outbound connections:
  - Listening ports not expected:

Defense Evasion:
  - Logs cleared:
  - Binaries deleted after execution:

INDICATORS OF COMPROMISE
------------------------
IPs:
Usernames:
File hashes:
File paths:

MITRE ATT&CK TECHNIQUES OBSERVED
----------------------------------

RECOMMENDED ACTIONS
-------------------
1. 
2.
3.
```

---

## Validation

Review all collected artifacts and ensure the chain of custody file covers everything:

```bash
CASE_DATE=$(date +%Y%m%d)
echo "Files collected: $(find /tmp/ir_case_$CASE_DATE -type f | wc -l)"
echo "Total size: $(du -sh /tmp/ir_case_$CASE_DATE | awk '{print $1}')"
cat /tmp/ir_case_$CASE_DATE/checksums.sha256 | wc -l
```
