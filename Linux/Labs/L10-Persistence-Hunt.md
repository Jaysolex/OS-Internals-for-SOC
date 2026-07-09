# L10 — Persistence Hunt

**Module:** Linux/09-Persistence-Mechanisms  
**Time:** 45 minutes  
**Objective:** Plant and then detect every major Linux persistence mechanism. Understand what each one looks like in logs and on disk.

---

## Setup: Plant Persistence (Safe Lab Environment Only)

```bash
# Create harmless payload (echo only — no network)
echo '#!/bin/bash' > /tmp/lab_payload.sh
echo 'echo "Persistence triggered at $(date)" >> /tmp/persistence.log' >> /tmp/lab_payload.sh
chmod +x /tmp/lab_payload.sh
```

---

## Exercise 1 — Cron Persistence

```bash
# Plant a user crontab entry
(crontab -l 2>/dev/null; echo "* * * * * /tmp/lab_payload.sh") | crontab -

# Verify it was added
crontab -l

# Wait 1 minute and check if it ran
sleep 65
cat /tmp/persistence.log

# CLEANUP — remove after lab
crontab -l | grep -v lab_payload | crontab -
```

---

## Exercise 2 — Systemd Persistence

```bash
# Create a user-level systemd unit (no root needed)
mkdir -p ~/.config/systemd/user/

cat > ~/.config/systemd/user/lab-persist.service << 'UNIT'
[Unit]
Description=Lab Persistence Exercise

[Service]
Type=oneshot
ExecStart=/tmp/lab_payload.sh

[Install]
WantedBy=default.target
UNIT

# Enable and start it
systemctl --user daemon-reload
systemctl --user enable lab-persist.service
systemctl --user start lab-persist.service

# Check status and log
systemctl --user status lab-persist.service
cat /tmp/persistence.log

# CLEANUP
systemctl --user disable lab-persist.service
systemctl --user stop lab-persist.service
rm ~/.config/systemd/user/lab-persist.service
```

---

## Exercise 3 — Shell Profile Persistence

```bash
# Add to bashrc (visible immediately on new shell)
echo "/tmp/lab_payload.sh" >> ~/.bashrc

# Open a new bash shell to trigger it
bash
cat /tmp/persistence.log

# CLEANUP
sed -i '/lab_payload/d' ~/.bashrc
```

---

## Exercise 4 — Run the Persistence Hunter

```bash
# Run the automated persistence hunter
sudo bash ~/OS-Internals-for-SOC/Scripts/Linux/persistence-hunter.sh

# Review findings
# It should detect any remaining persistence from above exercises
```

---

## Exercise 5 — Verify Detection

```bash
# Check auditd captured the crontab modification
sudo ausearch -f /var/spool/cron 2>/dev/null | tail -20

# Check systemd journal for unit creation
journalctl --user -u lab-persist.service --no-pager

# Check what files were recently modified in persistence locations
find /etc/cron.d /etc/systemd/system ~/.config/systemd -newer /etc/passwd -ls 2>/dev/null
```

---

## Cleanup Verification

```bash
# Ensure all planted persistence is removed
crontab -l | grep -v "^#" | grep -v "^$"
systemctl --user list-unit-files | grep lab
grep "lab_payload" ~/.bashrc
```

All should return empty.
