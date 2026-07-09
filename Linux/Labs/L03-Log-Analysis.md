# L03 — Log Analysis

**Module:** Linux/02-Logging-System  
**Time:** 30 minutes  
**Objective:** Analyse auth.log, detect brute force patterns, understand log rotation, and simulate log tampering detection.

---

## Exercise 1 — Auth Log Analysis

```bash
# View recent authentication events
sudo tail -50 /var/log/auth.log

# Count failed logins by source
sudo grep "Failed password" /var/log/auth.log | \
  grep -oE "from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | \
  sort | uniq -c | sort -rn | head -10

# Find successful logins
sudo grep "Accepted" /var/log/auth.log | tail -10

# Check sudo usage
sudo grep "COMMAND" /var/log/auth.log | tail -10
```

---

## Exercise 2 — Simulate Brute Force and Detect It

```bash
# Terminal 1: watch auth log in real time
sudo tail -f /var/log/auth.log

# Terminal 2: generate failed SSH attempts (to localhost)
for i in {1..10}; do
  ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 \
    fakeuser@localhost 2>/dev/null || true
done

# Back in Terminal 1: observe the failure entries appear
# Then count them:
grep "Failed password" /var/log/auth.log | wc -l
```

---

## Exercise 3 — Log Rotation

```bash
# View logrotate config
cat /etc/logrotate.conf

# View current auth.log archives
ls -la /var/log/auth.log*

# Force a manual rotation
sudo logrotate -f /etc/logrotate.conf

# Verify new archive was created
ls -la /var/log/auth.log*
```

---

## Exercise 4 — Log Tampering Simulation (Safe)

```bash
# Create a test log file
echo "$(date) Test log entry" > /tmp/test.log
echo "$(date) Another entry" >> /tmp/test.log
cat /tmp/test.log

# Simulate shredding (safe — only test file)
shred -f -n 3 -z /tmp/test.log
cat /tmp/test.log
# Content is now garbage — unreadable

# This is what attackers do to /var/log/auth.log
# auditd would capture: shred execve against /var/log/auth.log
```

---

## Exercise 5 — journald Fallback

```bash
# View SSH events from journal (survives auth.log clearing)
journalctl _COMM=sshd --no-pager | tail -20

# View previous boot logs (if available)
journalctl -b -1 --no-pager 2>/dev/null | head -20 || echo "No previous boot log"

# Check journal disk usage
journalctl --disk-usage
```

---

## Validation

Run the log parser script and verify it detects the simulated brute force:

```bash
sudo bash ~/OS-Internals-for-SOC/Scripts/Linux/log-parser.sh brute
```
