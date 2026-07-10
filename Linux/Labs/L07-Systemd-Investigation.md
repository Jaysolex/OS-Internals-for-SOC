# L07 — Systemd & Init Investigation

**Module:** Linux/06-Systemd-Init  
**Time:** 35 minutes  
**Objective:** Enumerate all systemd units, identify non-standard services, create and detect a persistence timer, and use journald for forensic investigation.

---

## Exercise 1 — Enumerate All Active Units

```bash
# List all running services
systemctl list-units --type=service --state=active --no-pager

# List all enabled services (survive reboot)
systemctl list-unit-files --state=enabled --no-pager

# List all active timers
systemctl list-timers --no-pager

# Find non-package-managed units
echo "=== Units NOT installed by packages ==="
for unit in /etc/systemd/system/*.service; do
  [ -f "$unit" ] || continue
  if command -v dpkg &>/dev/null; then
    dpkg -S "$unit" 2>/dev/null || echo "NOT PACKAGED: $unit"
  fi
done
```

---

## Exercise 2 — Inspect Unit File Content

```bash
# Inspect a running service
systemctl cat ssh 2>/dev/null || systemctl cat sshd 2>/dev/null

# Look at ExecStart, User, Restart settings
systemctl show ssh --property=ExecStart,User,Restart,FragmentPath 2>/dev/null || \
systemctl show sshd --property=ExecStart,User,Restart,FragmentPath 2>/dev/null
```

---

## Exercise 3 — Create and Detect a Timer (Lab Only)

```bash
# Create a harmless timer that logs to a file
mkdir -p ~/.config/systemd/user/

cat > ~/.config/systemd/user/lab-timer.service << 'UNIT'
[Unit]
Description=Lab Timer Exercise

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'echo "Timer triggered at $(date)" >> /tmp/timer_lab.log'
UNIT

cat > ~/.config/systemd/user/lab-timer.timer << 'UNIT'
[Unit]
Description=Lab Timer

[Timer]
OnBootSec=1min
OnUnitActiveSec=2min

[Install]
WantedBy=timers.target
UNIT

# Enable and start
systemctl --user daemon-reload
systemctl --user enable lab-timer.timer
systemctl --user start lab-timer.timer

# Verify it's active
systemctl --user list-timers --no-pager

# Wait and check if it fires
sleep 70
cat /tmp/timer_lab.log

# CLEANUP
systemctl --user stop lab-timer.timer
systemctl --user disable lab-timer.timer
rm ~/.config/systemd/user/lab-timer.*
rm -f /tmp/timer_lab.log
```

---

## Exercise 4 — journald Forensics

```bash
# View SSH-related events from journal
journalctl _COMM=sshd --no-pager | tail -20

# View events from a specific time window
journalctl --since "1 hour ago" --no-pager | tail -30

# View events from previous boot (if available)
journalctl -b -1 --no-pager 2>/dev/null | head -20 || \
  echo "No previous boot journal available"

# Check journal disk usage
journalctl --disk-usage

# Export journal for offline analysis
journalctl --since "1 hour ago" --output=json | head -5
```

---

## Exercise 5 — Unit File Security Analysis

```bash
# Check all unit ExecStart values for network callbacks
grep -r "bash.*tcp\|curl\|wget\|nc \|netcat\|python.*socket" \
  /etc/systemd/system/ /usr/lib/systemd/system/ 2>/dev/null | \
  grep -v "^Binary"

# Find units running as root
grep -r "^User=root\|^User=$" \
  /etc/systemd/system/*.service 2>/dev/null

# Find units with Restart=always (auto-relaunching)
grep -rl "Restart=always" /etc/systemd/system/ 2>/dev/null
```

---

## Validation

```bash
# Verify the persistence hunter catches systemd timers
sudo bash ~/OS-Internals-for-SOC/Scripts/Linux/persistence-hunter.sh 2>/dev/null | \
  grep -A3 "SYSTEMD"
```
