#!/usr/bin/env bash
# =============================================================================
# linux-triage.sh
# Live Response & Triage Script for Linux Systems
# Author: Solomon James (@Jaysolex)
# Usage: sudo bash linux-triage.sh [output_directory]
# =============================================================================

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ── Output directory ─────────────────────────────────────────────────────────
OUTDIR="${1:-/tmp/triage_$(hostname)_$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$OUTDIR"
LOGFILE="$OUTDIR/triage.log"

# ── Helpers ───────────────────────────────────────────────────────────────────
log()     { echo -e "${CYAN}[*]${RESET} $*" | tee -a "$LOGFILE"; }
ok()      { echo -e "${GREEN}[+]${RESET} $*" | tee -a "$LOGFILE"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*" | tee -a "$LOGFILE"; }
section() { echo -e "\n${BOLD}${RED}════════════════════════════════════════${RESET}" | tee -a "$LOGFILE"
            echo -e "${BOLD}  $*${RESET}" | tee -a "$LOGFILE"
            echo -e "${BOLD}${RED}════════════════════════════════════════${RESET}\n" | tee -a "$LOGFILE"; }

run() {
  # run <label> <output_file> <command...>
  local label="$1"; local outfile="$2"; shift 2
  log "Collecting: $label"
  { echo "# $label"; echo "# Collected: $(date)"; echo "# Command: $*"; echo; "$@" 2>&1; } \
    > "$OUTDIR/$outfile" || warn "Partial output for: $label"
}

check_root() {
  [[ $EUID -eq 0 ]] || { echo -e "${RED}[!] Run as root: sudo bash $0${RESET}"; exit 1; }
}

# =============================================================================
# MAIN
# =============================================================================
check_root

echo -e "${BOLD}${CYAN}"
cat << 'BANNER'
  ___  ___ ___ ___ ___ __  __ ___ ___  _ _ ___   _  ___ _   _
 / _ \/ __/ __|_ _| _ \  \/  |_ _|   \| | | __| | |/ __| | | |
| (_) \__ \__ \| ||  _/ |\/| || || |) | |_| _|  | |\__ \ |_| |
 \___/|___/___/___|_| |_|  |_|___|___/ \___/___| |_||___/\___/

     Linux Live Response Triage — OS Internals Security Project
BANNER
echo -e "${RESET}"

log "Output directory: $OUTDIR"
log "Hostname: $(hostname)"
log "Start time: $(date)"

# =============================================================================
section "1. SYSTEM IDENTITY"
# =============================================================================
run "System Info"        "01_system_info.txt"        uname -a
run "OS Release"         "01_os_release.txt"         cat /etc/os-release
run "Hostname"           "01_hostname.txt"            hostname -f
run "Uptime"             "01_uptime.txt"              uptime
run "Date & Timezone"    "01_datetime.txt"            bash -c "date; timedatectl 2>/dev/null || cat /etc/timezone"
run "Kernel Parameters"  "01_sysctl.txt"              sysctl -a 2>/dev/null
run "Loaded Modules"     "01_kernel_modules.txt"      lsmod
run "Mounted Filesystems" "01_mounts.txt"             cat /proc/mounts

# =============================================================================
section "2. USER & AUTHENTICATION"
# =============================================================================
run "All Users (passwd)"          "02_passwd.txt"           cat /etc/passwd
run "Shadow File"                 "02_shadow.txt"           cat /etc/shadow
run "Group Memberships"           "02_groups.txt"           cat /etc/group
run "Sudoers"                     "02_sudoers.txt"          bash -c "cat /etc/sudoers; ls -la /etc/sudoers.d/; cat /etc/sudoers.d/* 2>/dev/null"
run "Login History (wtmp)"        "02_login_history.txt"    last -F -x
run "Failed Logins (btmp)"        "02_failed_logins.txt"    lastb -F 2>/dev/null || echo "btmp empty or unavailable"
run "Last Login Per User"         "02_lastlog.txt"          lastlog
run "Currently Logged In"         "02_who.txt"              bash -c "who; w"
run "SSH Authorized Keys"         "02_ssh_auth_keys.txt"    bash -c "find / -name 'authorized_keys' -type f 2>/dev/null -exec echo '=== {} ===' \; -exec cat {} \;"
run "SSH Daemon Config"           "02_sshd_config.txt"      cat /etc/ssh/sshd_config
run "PAM Configuration"           "02_pam.txt"              bash -c "ls /etc/pam.d/; echo '---'; cat /etc/pam.d/sshd 2>/dev/null; cat /etc/pam.d/sudo 2>/dev/null"

# Shell histories
log "Collecting shell histories..."
mkdir -p "$OUTDIR/shell_histories"
find /home /root -name ".*history" -type f 2>/dev/null | while read -r f; do
  username=$(echo "$f" | awk -F'/' '{print $3}')
  cp "$f" "$OUTDIR/shell_histories/${username}_$(basename "$f")" 2>/dev/null || true
done
ok "Shell histories saved to shell_histories/"

# =============================================================================
section "3. NETWORK STATE"
# =============================================================================
run "TCP/UDP Connections (ss)"    "03_connections.txt"      ss -tnuap
run "Established Connections"     "03_established.txt"      ss -tnap state established
run "Network Interfaces"          "03_interfaces.txt"       ip addr show
run "Routing Table"               "03_routes.txt"           ip route show
run "ARP Cache"                   "03_arp.txt"              arp -a
run "DNS Config"                  "03_resolv.txt"           cat /etc/resolv.conf
run "Hosts File"                  "03_hosts.txt"            cat /etc/hosts
run "NSSwitch"                    "03_nsswitch.txt"         cat /etc/nsswitch.conf
run "Firewall Rules (iptables)"   "03_iptables.txt"         bash -c "iptables -L -n -v 2>/dev/null; iptables -t nat -L -n -v 2>/dev/null"
run "Firewall Rules (nftables)"   "03_nftables.txt"         nft list ruleset 2>/dev/null || echo "nftables not in use"
run "Kernel Network State (tcp)"  "03_proc_net_tcp.txt"     cat /proc/net/tcp
run "Kernel Network State (tcp6)" "03_proc_net_tcp6.txt"    cat /proc/net/tcp6
run "Listening Ports"             "03_listening.txt"        ss -tlnp

# =============================================================================
section "4. PROCESS STATE"
# =============================================================================
run "All Processes"               "04_processes.txt"        ps auxef
run "Process Tree"                "04_pstree.txt"           pstree -ap 2>/dev/null || ps -ejH
run "Open Files (lsof)"           "04_lsof.txt"             lsof -n 2>/dev/null || echo "lsof not available"

# Deleted binaries still running
log "Checking for processes running from deleted binaries..."
{
  echo "# Processes running from deleted disk binaries"
  echo "# $(date)"
  echo
  find /proc -maxdepth 2 -name exe -type l 2>/dev/null | while read -r exelink; do
    target=$(readlink "$exelink" 2>/dev/null)
    if echo "$target" | grep -q "(deleted)"; then
      pid=$(echo "$exelink" | awk -F'/' '{print $3}')
      cmdline=$(cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ')
      echo "PID: $pid | Binary: $target | CMD: $cmdline"
    fi
  done
} > "$OUTDIR/04_deleted_binary_processes.txt"
ok "Deleted binary check complete"

# Process environment variables (may contain credentials)
log "Sampling process environments (PIDs with unusual env)..."
{
  echo "# Process Environment Variables"
  echo "# Checking for credentials, tokens, suspicious vars"
  echo
  for pid in $(ls /proc | grep '^[0-9]' | head -50); do
    env_file="/proc/$pid/environ"
    if [[ -r "$env_file" ]]; then
      env_content=$(cat "$env_file" 2>/dev/null | tr '\0' '\n')
      if echo "$env_content" | grep -qiE "password|token|secret|key|aws|api"; then
        exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
        echo "=== PID $pid | $exe ==="
        echo "$env_content" | grep -iE "password|token|secret|key|aws|api"
        echo
      fi
    fi
  done
} > "$OUTDIR/04_process_env_credentials.txt"

# =============================================================================
section "5. PERSISTENCE MECHANISMS"
# =============================================================================
run "System Crontab"              "05_crontab_system.txt"   bash -c "cat /etc/crontab; ls -la /etc/cron.d/; cat /etc/cron.d/* 2>/dev/null"
run "Cron Directories"            "05_cron_dirs.txt"        bash -c "ls -la /etc/cron.daily/ /etc/cron.weekly/ /etc/cron.monthly/ /etc/cron.hourly/ 2>/dev/null"

log "Collecting per-user crontabs..."
{
  echo "# Per-user crontabs"
  echo "# $(date)"
  while IFS=: read -r user _ uid _ _ home _; do
    if [[ $uid -ge 1000 ]] || [[ $user == "root" ]]; then
      cron=$(crontab -l -u "$user" 2>/dev/null)
      if [[ -n "$cron" ]]; then
        echo "=== $user ==="
        echo "$cron"
        echo
      fi
    fi
  done < /etc/passwd
} > "$OUTDIR/05_user_crontabs.txt"

run "Systemd User Units"          "05_systemd_units.txt"    bash -c "systemctl list-units --all --no-pager; echo '---'; ls -la /etc/systemd/system/ 2>/dev/null"
run "Systemd Timers"              "05_systemd_timers.txt"   systemctl list-timers --all --no-pager
run "rc.local"                    "05_rc_local.txt"         cat /etc/rc.local 2>/dev/null || echo "Not present"
run "Profile Scripts"             "05_profile_scripts.txt"  bash -c "ls -la /etc/profile.d/; cat /etc/profile.d/* 2>/dev/null"
run "LD_PRELOAD Config"           "05_ld_preload.txt"       bash -c "cat /etc/ld.so.preload 2>/dev/null || echo 'Clean — /etc/ld.so.preload does not exist'; cat /etc/ld.so.conf; cat /etc/ld.so.conf.d/*"
run "At Jobs"                     "05_at_jobs.txt"          bash -c "atq 2>/dev/null; ls /var/spool/at/ 2>/dev/null"
run "Init Scripts (legacy)"       "05_init_scripts.txt"     ls -la /etc/init.d/ 2>/dev/null

# =============================================================================
section "6. FILESYSTEM ANOMALIES"
# =============================================================================

log "Finding SUID/SGID binaries..."
find / -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null \
  > "$OUTDIR/06_suid_sgid.txt"

log "Finding world-writable directories..."
find / -type d -perm -0002 -not -path "/proc/*" -not -path "/sys/*" -ls 2>/dev/null \
  > "$OUTDIR/06_world_writable_dirs.txt"

log "Finding executables in /tmp, /var/tmp, /dev/shm..."
find /tmp /var/tmp /dev/shm -type f -ls 2>/dev/null \
  > "$OUTDIR/06_tmp_files.txt"

log "Finding hidden files in temp directories..."
find /tmp /var/tmp /dev/shm /opt -name ".*" -ls 2>/dev/null \
  > "$OUTDIR/06_hidden_files.txt"

log "Files modified in last 24 hours (excluding /proc /sys /dev)..."
find / \( -path /proc -o -path /sys -o -path /dev \) -prune -o \
  -type f -mtime -1 -printf "%TY-%Tm-%Td %TH:%TM %p\n" 2>/dev/null | sort \
  > "$OUTDIR/06_recently_modified.txt"

log "Files with no owner (orphaned)..."
find / -nouser -nogroup -not -path "/proc/*" -not -path "/sys/*" -ls 2>/dev/null \
  > "$OUTDIR/06_orphaned_files.txt"

log "Checking /dev/shm contents..."
ls -laR /dev/shm 2>/dev/null > "$OUTDIR/06_devshm_contents.txt"

# =============================================================================
section "7. LOG TRIAGE"
# =============================================================================
run "Auth Log (last 500)"         "07_auth_log.txt"         bash -c "tail -500 /var/log/auth.log 2>/dev/null || journalctl _COMM=sshd -n 500 --no-pager"
run "Syslog (last 500)"           "07_syslog.txt"           bash -c "tail -500 /var/log/syslog 2>/dev/null || journalctl -n 500 --no-pager"
run "Kern Log (last 200)"         "07_kern_log.txt"         bash -c "tail -200 /var/log/kern.log 2>/dev/null || journalctl -k -n 200 --no-pager"
run "Failed SSH (all)"            "07_ssh_failures.txt"     bash -c "grep 'Failed password\|Invalid user\|authentication failure' /var/log/auth.log 2>/dev/null || journalctl _COMM=sshd --no-pager | grep -i failed"
run "Successful SSH"              "07_ssh_success.txt"      bash -c "grep 'Accepted password\|Accepted publickey' /var/log/auth.log 2>/dev/null || journalctl _COMM=sshd --no-pager | grep Accepted"
run "Sudo Usage"                  "07_sudo_usage.txt"       bash -c "grep 'sudo' /var/log/auth.log 2>/dev/null || journalctl _COMM=sudo --no-pager"
run "Log File Metadata"           "07_log_metadata.txt"     stat /var/log/auth.log /var/log/syslog /var/log/kern.log 2>/dev/null
run "Journal (last 24h)"          "07_journal.txt"          journalctl --since "24 hours ago" --no-pager 2>/dev/null | tail -1000

# Check for log gaps
log "Checking for log timestamp gaps..."
{
  echo "# Log Gap Analysis — auth.log"
  echo "# Large time gaps may indicate log tampering"
  echo
  if [[ -f /var/log/auth.log ]]; then
    awk '{print $1, $2, $3}' /var/log/auth.log | \
      awk 'NR==1{prev=$0; next} {print prev, "→", $0; prev=$0}' | \
      head -100
  fi
} > "$OUTDIR/07_log_gap_analysis.txt"

# =============================================================================
section "8. KERNEL & MODULES"
# =============================================================================
run "Loaded Modules (lsmod)"      "08_lsmod.txt"            lsmod
run "Module Details"              "08_module_info.txt"       bash -c "cat /proc/modules"
run "Kernel Ring Buffer"          "08_dmesg.txt"             dmesg --time-format=iso 2>/dev/null || dmesg
run "Module Load Discrepancy"     "08_module_diff.txt"       bash -c "echo '=== lsmod vs /proc/modules vs /sys/module ==='; diff <(lsmod | awk 'NR>1{print \$1}' | sort) <(ls /sys/module/ | sort) || echo 'Differences found above'"

# =============================================================================
section "9. PACKAGE & SOFTWARE INTEGRITY"
# =============================================================================
if command -v dpkg &>/dev/null; then
  run "Installed Packages (dpkg)"   "09_packages.txt"         dpkg -l
  log "Running package integrity check (debsums)..."
  if command -v debsums &>/dev/null; then
    debsums -c 2>/dev/null > "$OUTDIR/09_debsums_failures.txt" || true
    ok "debsums check complete — see 09_debsums_failures.txt"
  else
    echo "debsums not installed — apt install debsums" > "$OUTDIR/09_debsums_failures.txt"
  fi
fi

if command -v rpm &>/dev/null; then
  run "Installed Packages (rpm)"    "09_packages.txt"         rpm -qa
  log "Running RPM integrity check..."
  rpm -Va 2>/dev/null > "$OUTDIR/09_rpm_verify.txt" || true
fi

# =============================================================================
section "10. CREDENTIAL FILES"
# =============================================================================
log "Scanning for credential files..."
{
  echo "# Credential File Scan"
  echo "# $(date)"
  echo

  echo "=== AWS Credentials ==="
  find /home /root -path "*/.aws/credentials" 2>/dev/null -exec cat {} \;

  echo "=== SSH Private Keys ==="
  find /home /root /etc -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" 2>/dev/null | \
    while read -r f; do echo "Found: $f ($(stat -c '%U %G %a' "$f" 2>/dev/null))"; done

  echo "=== .env Files ==="
  find /var /opt /srv /home -name ".env" -type f 2>/dev/null | \
    while read -r f; do echo "=== $f ==="; cat "$f"; echo; done

  echo "=== Config Files with Passwords ==="
  grep -rli "password\|passwd\|secret\|api_key\|token" /etc /opt /srv 2>/dev/null | head -20

} > "$OUTDIR/10_credential_files.txt"

# =============================================================================
section "11. ROOTKIT INDICATORS"
# =============================================================================
log "Running basic rootkit indicator checks..."
{
  echo "# Rootkit Indicator Checks"
  echo "# $(date)"
  echo

  echo "=== /etc/ld.so.preload (should be empty) ==="
  if [[ -f /etc/ld.so.preload ]]; then
    warn_msg="SUSPICIOUS: /etc/ld.so.preload exists"
    echo "$warn_msg"
    cat /etc/ld.so.preload
  else
    echo "CLEAN: /etc/ld.so.preload does not exist"
  fi
  echo

  echo "=== /proc vs /sys module discrepancy ==="
  diff <(lsmod | awk 'NR>1{print $1}' | sort) <(ls /sys/module/ | sort) 2>/dev/null || echo "Discrepancies detected above"
  echo

  echo "=== Processes with hidden/deleted binary ==="
  find /proc -maxdepth 2 -name exe -type l 2>/dev/null | while read -r l; do
    t=$(readlink "$l" 2>/dev/null)
    [[ "$t" == *"(deleted)"* ]] && echo "PID $(echo $l | awk -F/ '{print $3}'): $t"
  done
  echo

  echo "=== Comparing /proc/net/tcp with ss output ==="
  echo "--- /proc/net/tcp (kernel) ---"
  wc -l /proc/net/tcp
  echo "--- ss -tn output (userspace) ---"
  ss -tn | wc -l
  echo "(Large discrepancy may indicate a rootkit hiding connections)"
  echo

  echo "=== Hidden /tmp files ==="
  find /tmp -name ".*" -ls 2>/dev/null

  echo "=== Unusual SUID binaries ==="
  find / -type f -perm -4000 2>/dev/null | \
    while read -r bin; do
      # Warn if not in known-good directories
      if ! echo "$bin" | grep -qE "^/bin|^/sbin|^/usr/bin|^/usr/sbin|^/usr/lib"; then
        echo "UNUSUAL SUID: $bin"
      fi
    done

} > "$OUTDIR/11_rootkit_indicators.txt"

# =============================================================================
section "FINALISE"
# =============================================================================

# Hash all collected files for integrity
log "Hashing output files for integrity..."
find "$OUTDIR" -type f -not -name "checksums.sha256" | \
  sort | xargs sha256sum 2>/dev/null > "$OUTDIR/checksums.sha256"

# Summary
FILECOUNT=$(find "$OUTDIR" -type f | wc -l)
DIRSIZE=$(du -sh "$OUTDIR" | awk '{print $1}')

echo ""
echo -e "${GREEN}${BOLD}════════════════════════════════════════${RESET}"
echo -e "${GREEN}${BOLD}  TRIAGE COMPLETE${RESET}"
echo -e "${GREEN}${BOLD}════════════════════════════════════════${RESET}"
echo -e "  Output:    ${CYAN}$OUTDIR${RESET}"
echo -e "  Files:     ${CYAN}$FILECOUNT${RESET}"
echo -e "  Size:      ${CYAN}$DIRSIZE${RESET}"
echo -e "  Completed: ${CYAN}$(date)${RESET}"
echo ""
echo -e "  ${YELLOW}Transfer to analyst workstation:${RESET}"
echo -e "  ${BOLD}tar czf triage_$(hostname).tar.gz -C $(dirname "$OUTDIR") $(basename "$OUTDIR")${RESET}"
echo -e "  ${BOLD}scp triage_$(hostname).tar.gz analyst@<workstation>:/cases/${RESET}"
echo ""
