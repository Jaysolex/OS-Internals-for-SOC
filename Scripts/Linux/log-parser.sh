#!/usr/bin/env bash
# =============================================================================
# log-parser.sh
# Log Parsing & Analysis for Security Investigations
# Author: Solomon James (@Jaysolex)
# Usage: sudo bash log-parser.sh [--mode <mode>] [--log <logfile>] [--ip <ip>]
#
# Modes:
#   brute       — Detect SSH brute force
#   exfil       — Detect data exfiltration patterns
#   persist     — Detect persistence mechanisms in logs
#   privesc     — Detect privilege escalation
#   evasion     — Detect log tampering / defense evasion
#   user <name> — Full investigation of a specific user
#   ip <addr>   — Full investigation of a specific IP
#   full        — Run all modules
# =============================================================================

set -uo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; BOLD='\033[1m'; RESET='\033[0m'

# ── Defaults ──────────────────────────────────────────────────────────────────
AUTH_LOG="${AUTH_LOG:-/var/log/auth.log}"
SYSLOG="${SYSLOG:-/var/log/syslog}"
KERN_LOG="${KERN_LOG:-/var/log/kern.log}"
AUDIT_LOG="${AUDIT_LOG:-/var/log/audit/audit.log}"
CRON_LOG="${CRON_LOG:-/var/log/cron.log}"
MODE="${1:-full}"
TARGET_IP=""
TARGET_USER=""
THRESHOLD_BRUTE=5     # failed attempts before flagging
THRESHOLD_SPRAY=3     # accounts targeted before flagging spray
OUTFILE="/tmp/log_analysis_$(date +%Y%m%d_%H%M%S).txt"

# ── Helpers ───────────────────────────────────────────────────────────────────
header() {
  echo -e "\n${BOLD}${CYAN}╔══════════════════════════════════════════════════╗${RESET}"
  echo -e "${BOLD}${CYAN}║  $*${RESET}"
  echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════╝${RESET}\n"
}
finding()  { echo -e "  ${RED}[FINDING]${RESET}  $*"; }
info()     { echo -e "  ${CYAN}[INFO]${RESET}     $*"; }
ok()       { echo -e "  ${GREEN}[CLEAN]${RESET}    $*"; }
warn()     { echo -e "  ${YELLOW}[WARN]${RESET}     $*"; }
metric()   { echo -e "  ${MAGENTA}[METRIC]${RESET}   $*"; }

log_exists() { [[ -f "$1" ]] && [[ -r "$1" ]]; }
require_log() {
  if ! log_exists "$1"; then
    warn "$1 not found or not readable — some checks skipped"
    return 1
  fi
  return 0
}

# Combine all rotated logs transparently
read_log() {
  local base="$1"
  if [[ -f "${base}.gz" ]]; then
    { cat "$base" 2>/dev/null; zcat "${base}".*.gz 2>/dev/null; cat "${base}".[0-9] 2>/dev/null; } 2>/dev/null
  else
    { cat "$base" 2>/dev/null; cat "${base}".[0-9] 2>/dev/null; } 2>/dev/null
  fi
}

# =============================================================================
# MODULE 1 — SSH BRUTE FORCE DETECTION
# =============================================================================
analyse_brute_force() {
  header "SSH Brute Force Analysis"
  require_log "$AUTH_LOG" || return

  info "Reading: $AUTH_LOG (+ rotated archives)"
  echo ""

  # --- Failed attempts by IP
  echo -e "${BOLD}Top Source IPs by Failure Count:${RESET}"
  echo "────────────────────────────────────────────────────"
  read_log "$AUTH_LOG" | \
    grep "Failed password" | \
    grep -oE "from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | \
    sort | uniq -c | sort -rn | head -20 | \
    while read -r count ip_str; do
      ip=$(echo "$ip_str" | awk '{print $2}')
      if [[ $count -gt $THRESHOLD_BRUTE ]]; then
        finding "Count: ${BOLD}$count${RESET}  |  IP: ${BOLD}$ip${RESET}"
      else
        metric "Count: $count  |  IP: $ip"
      fi
    done

  echo ""
  # --- Invalid users targeted
  echo -e "${BOLD}Top Targeted Usernames (Invalid User attempts):${RESET}"
  echo "────────────────────────────────────────────────────"
  read_log "$AUTH_LOG" | \
    grep "Invalid user" | \
    awk '{print $8}' | \
    sort | uniq -c | sort -rn | head -20 | \
    while read -r count user; do
      if [[ $count -gt $THRESHOLD_BRUTE ]]; then
        finding "Count: ${BOLD}$count${RESET}  |  User: ${BOLD}$user${RESET}"
      else
        metric "Count: $count  |  User: $user"
      fi
    done

  echo ""
  # --- Brute force followed by successful login (CRITICAL)
  echo -e "${BOLD}${RED}Brute Force → Successful Login Correlation:${RESET}"
  echo "────────────────────────────────────────────────────"
  # Get IPs with failures
  failed_ips=$(read_log "$AUTH_LOG" | grep "Failed password" | \
    grep -oE "from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | \
    awk '{print $2}' | sort -u)

  found_success=false
  while IFS= read -r ip; do
    success=$(read_log "$AUTH_LOG" | \
      grep "Accepted" | grep "$ip" | head -5)
    if [[ -n "$success" ]]; then
      finding "${BOLD}CRITICAL — Brute force followed by successful auth from $ip${RESET}"
      echo "$success" | while IFS= read -r line; do
        echo -e "    ${RED}→ $line${RESET}"
      done
      found_success=true
    fi
  done <<< "$failed_ips"
  $found_success || ok "No brute force → success correlation found"

  echo ""
  # --- Password spray detection (same password, many accounts)
  echo -e "${BOLD}Password Spray Detection (one IP → many users):${RESET}"
  echo "────────────────────────────────────────────────────"
  read_log "$AUTH_LOG" | grep "Failed password" | \
    grep -oE "from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | \
    awk '{print $2}' | sort | uniq -c | sort -rn | \
    while read -r count ip; do
      # Check how many distinct users this IP targeted
      user_count=$(read_log "$AUTH_LOG" | \
        grep "Failed password" | grep "$ip" | \
        awk '{for(i=1;i<=NF;i++) if($i=="for") print $(i+1)}' | \
        sort -u | wc -l)
      if [[ $user_count -ge $THRESHOLD_SPRAY ]]; then
        finding "IP $ip targeted ${BOLD}$user_count distinct users${RESET} — possible spray"
      fi
    done
}

# =============================================================================
# MODULE 2 — PRIVILEGE ESCALATION DETECTION
# =============================================================================
analyse_privesc() {
  header "Privilege Escalation Analysis"
  require_log "$AUTH_LOG" || return

  # --- Sudo usage
  echo -e "${BOLD}Sudo Activity:${RESET}"
  echo "────────────────────────────────────────────────────"
  read_log "$AUTH_LOG" | grep "sudo" | grep -v "pam_unix" | \
    while IFS= read -r line; do
      if echo "$line" | grep -q "COMMAND"; then
        info "$line"
      elif echo "$line" | grep -qiE "authentication failure|wrong password"; then
        finding "Sudo auth failure: $line"
      fi
    done

  echo ""
  # --- su usage
  echo -e "${BOLD}su (Switch User) Activity:${RESET}"
  echo "────────────────────────────────────────────────────"
  read_log "$AUTH_LOG" | grep -E "\bsu\b.*session|su:.*Successful|su.*FAILED" | \
    while IFS= read -r line; do
      if echo "$line" | grep -qi "FAILED\|failure"; then
        finding "$line"
      else
        info "$line"
      fi
    done

  echo ""
  # --- Root login directly (should never happen on hardened systems)
  echo -e "${BOLD}Direct Root Logins:${RESET}"
  echo "────────────────────────────────────────────────────"
  direct_root=$(read_log "$AUTH_LOG" | grep "Accepted" | grep " root " | head -20)
  if [[ -n "$direct_root" ]]; then
    while IFS= read -r line; do
      finding "$line"
    done <<< "$direct_root"
  else
    ok "No direct root SSH logins found"
  fi

  echo ""
  # --- auditd privesc events
  if require_log "$AUDIT_LOG"; then
    echo -e "${BOLD}Auditd Privilege Events:${RESET}"
    echo "────────────────────────────────────────────────────"
    grep -E "type=SYSCALL.*\beuid=0\b" "$AUDIT_LOG" 2>/dev/null | \
      grep -v "auid=0" | head -20 | \
      while IFS= read -r line; do
        finding "Non-root → root euid: $line"
      done || info "No auditd privilege escalation events found"
  fi
}

# =============================================================================
# MODULE 3 — PERSISTENCE IN LOGS
# =============================================================================
analyse_persistence() {
  header "Persistence Mechanism Analysis"

  # --- Cron job changes
  echo -e "${BOLD}Cron Job Activity in Logs:${RESET}"
  echo "────────────────────────────────────────────────────"
  if log_exists "$CRON_LOG"; then
    grep -E "RELOAD|new job|edit" "$CRON_LOG" 2>/dev/null | head -30 | \
      while IFS= read -r line; do info "$line"; done
  fi
  # Also check syslog for cron
  read_log "$SYSLOG" | grep -i "cron.*RELOAD\|cron.*edit\|cron.*new" 2>/dev/null | head -20 | \
    while IFS= read -r line; do info "$line"; done

  echo ""
  # --- New systemd units
  echo -e "${BOLD}Systemd Unit Changes in Journal:${RESET}"
  echo "────────────────────────────────────────────────────"
  journalctl --no-pager 2>/dev/null | \
    grep -E "systemd.*started|systemd.*enabled|Created symlink" 2>/dev/null | \
    grep -v "NetworkManager\|ssh\|rsyslog\|cron\|logrotate" | head -20 | \
    while IFS= read -r line; do warn "$line"; done

  echo ""
  # --- SSH key additions
  echo -e "${BOLD}SSH Authorized Key Modifications:${RESET}"
  echo "────────────────────────────────────────────────────"
  if log_exists "$AUDIT_LOG"; then
    grep "authorized_keys" "$AUDIT_LOG" 2>/dev/null | \
      grep -E "WRITE|CREATE" | head -20 | \
      while IFS= read -r line; do
        finding "authorized_keys modification: $line"
      done || ok "No authorized_keys modifications in auditd"
  else
    info "auditd not active — check file timestamps manually: find / -name authorized_keys -newer /etc/passwd"
  fi

  echo ""
  # --- rc.local / profile modifications
  echo -e "${BOLD}Startup Script Modifications:${RESET}"
  echo "────────────────────────────────────────────────────"
  if log_exists "$AUDIT_LOG"; then
    grep -E "/etc/rc.local|/etc/profile|/etc/profile.d" "$AUDIT_LOG" 2>/dev/null | head -10 | \
      while IFS= read -r line; do finding "$line"; done || ok "No startup script modifications in auditd"
  fi
}

# =============================================================================
# MODULE 4 — DEFENSE EVASION DETECTION
# =============================================================================
analyse_evasion() {
  header "Defense Evasion Analysis"

  # --- Log service stopped
  echo -e "${BOLD}Logging Service Start/Stop Events:${RESET}"
  echo "────────────────────────────────────────────────────"
  read_log "$SYSLOG" | \
    grep -iE "rsyslog|syslog|auditd" | \
    grep -iE "stop|start|restart|terminate" | head -20 | \
    while IFS= read -r line; do
      if echo "$line" | grep -qi "stop\|terminat"; then
        finding "Logging service stopped: $line"
      else
        info "$line"
      fi
    done

  echo ""
  # --- Log file size check (sudden shrink = clearing)
  echo -e "${BOLD}Log File Integrity Check:${RESET}"
  echo "────────────────────────────────────────────────────"
  for logfile in /var/log/auth.log /var/log/syslog /var/log/kern.log; do
    if [[ -f "$logfile" ]]; then
      size=$(stat -c%s "$logfile" 2>/dev/null)
      mtime=$(stat -c%y "$logfile" 2>/dev/null)
      lines=$(wc -l < "$logfile" 2>/dev/null)
      if [[ $size -lt 1024 ]]; then
        finding "$logfile is suspiciously small: ${size} bytes, $lines lines (modified: $mtime)"
      else
        info "$logfile: ${size} bytes | $lines lines | Modified: $mtime"
      fi
    fi
  done

  echo ""
  # --- Shred command usage
  echo -e "${BOLD}Shred Command Usage in Logs:${RESET}"
  echo "────────────────────────────────────────────────────"
  shred_use=$(read_log "$SYSLOG" 2>/dev/null | grep "shred"; \
    log_exists "$AUDIT_LOG" && grep "shred" "$AUDIT_LOG" 2>/dev/null || true)
  if [[ -n "$shred_use" ]]; then
    finding "shred command detected in logs:"
    echo "$shred_use" | while IFS= read -r line; do
      echo -e "    ${RED}→ $line${RESET}"
    done
  else
    ok "No shred usage found in logs"
  fi

  echo ""
  # --- LD_PRELOAD
  echo -e "${BOLD}LD_PRELOAD Manipulation:${RESET}"
  echo "────────────────────────────────────────────────────"
  if [[ -f /etc/ld.so.preload ]] && [[ -s /etc/ld.so.preload ]]; then
    finding "/etc/ld.so.preload EXISTS and is non-empty:"
    cat /etc/ld.so.preload | while IFS= read -r line; do
      echo -e "    ${RED}→ $line${RESET}"
    done
  else
    ok "/etc/ld.so.preload is clean"
  fi

  echo ""
  # --- Auditd gap detection
  echo -e "${BOLD}Auditd Continuity Check:${RESET}"
  echo "────────────────────────────────────────────────────"
  if log_exists "$AUDIT_LOG"; then
    first=$(head -1 "$AUDIT_LOG" | grep -oE "msg=audit\([0-9]+")
    last=$(tail -1 "$AUDIT_LOG" | grep -oE "msg=audit\([0-9]+")
    info "Audit log first entry: $first"
    info "Audit log last entry:  $last"
  else
    warn "auditd log not found — logging may have been disabled"
  fi
}

# =============================================================================
# MODULE 5 — USER INVESTIGATION
# =============================================================================
analyse_user() {
  local user="${1:-}"
  [[ -z "$user" ]] && { warn "No user specified. Usage: $0 user <username>"; return; }

  header "User Investigation: $user"

  # --- Account info
  echo -e "${BOLD}Account Information:${RESET}"
  echo "────────────────────────────────────────────────────"
  grep "^${user}:" /etc/passwd 2>/dev/null | \
    awk -F: '{printf "  User: %s\n  UID: %s\n  GID: %s\n  Home: %s\n  Shell: %s\n", $1,$3,$4,$6,$7}'
  groups "$user" 2>/dev/null | sed 's/^/  Groups: /'
  lastlog -u "$user" 2>/dev/null

  echo ""
  # --- Authentication events
  echo -e "${BOLD}Authentication Events:${RESET}"
  echo "────────────────────────────────────────────────────"
  read_log "$AUTH_LOG" | grep -E "\b${user}\b" | tail -50 | \
    while IFS= read -r line; do
      if echo "$line" | grep -qi "failed\|invalid\|failure"; then
        finding "$line"
      elif echo "$line" | grep -qi "accepted\|opened\|success"; then
        ok "$line"
      else
        info "$line"
      fi
    done

  echo ""
  # --- Sudo commands
  echo -e "${BOLD}Sudo Commands Run:${RESET}"
  echo "────────────────────────────────────────────────────"
  read_log "$AUTH_LOG" | grep "sudo" | grep "$user" | grep "COMMAND" | \
    while IFS= read -r line; do warn "$line"; done

  echo ""
  # --- Shell history
  echo -e "${BOLD}Shell History:${RESET}"
  echo "────────────────────────────────────────────────────"
  local home
  home=$(grep "^${user}:" /etc/passwd | awk -F: '{print $6}')
  for hist in "$home/.bash_history" "$home/.zsh_history" "$home/.sh_history"; do
    if [[ -f "$hist" ]]; then
      info "Reading: $hist"
      tail -100 "$hist" | nl | \
        while IFS= read -r line; do
          if echo "$line" | grep -qiE "wget|curl|nc |ncat|base64|python.*-c|chmod.*\+x|/tmp|/dev/shm"; then
            finding "$line"
          else
            echo "    $line"
          fi
        done
    fi
  done

  echo ""
  # --- Files owned by user modified recently
  echo -e "${BOLD}Files Recently Modified by $user:${RESET}"
  echo "────────────────────────────────────────────────────"
  find / -user "$user" -type f -mtime -7 -not -path "/proc/*" -not -path "/sys/*" \
    -ls 2>/dev/null | head -30 | \
    while IFS= read -r line; do
      if echo "$line" | grep -qE "/tmp|/dev/shm|/var/tmp"; then
        finding "$line"
      else
        info "$line"
      fi
    done

  echo ""
  # --- Crontab
  echo -e "${BOLD}Crontab for $user:${RESET}"
  echo "────────────────────────────────────────────────────"
  cron=$(crontab -l -u "$user" 2>/dev/null)
  if [[ -n "$cron" ]]; then
    finding "Crontab entries exist for $user:"
    echo "$cron" | while IFS= read -r line; do warn "  $line"; done
  else
    ok "No crontab entries for $user"
  fi
}

# =============================================================================
# MODULE 6 — IP INVESTIGATION
# =============================================================================
analyse_ip() {
  local ip="${1:-}"
  [[ -z "$ip" ]] && { warn "No IP specified. Usage: $0 ip <address>"; return; }

  header "IP Investigation: $ip"

  # --- All events from this IP
  echo -e "${BOLD}All Authentication Events from $ip:${RESET}"
  echo "────────────────────────────────────────────────────"
  read_log "$AUTH_LOG" | grep "$ip" | \
    while IFS= read -r line; do
      if echo "$line" | grep -qi "failed\|invalid"; then
        finding "$line"
      elif echo "$line" | grep -qi "accepted"; then
        ok "$line"
      else
        info "$line"
      fi
    done

  echo ""
  # --- Timeline
  echo -e "${BOLD}Timeline Summary for $ip:${RESET}"
  echo "────────────────────────────────────────────────────"
  local failures successes first_seen last_seen users_targeted
  failures=$(read_log "$AUTH_LOG" | grep "$ip" | grep -c "Failed" 2>/dev/null || echo 0)
  successes=$(read_log "$AUTH_LOG" | grep "$ip" | grep -c "Accepted" 2>/dev/null || echo 0)
  first_seen=$(read_log "$AUTH_LOG" | grep "$ip" | head -1 | awk '{print $1, $2, $3}')
  last_seen=$(read_log "$AUTH_LOG" | grep "$ip" | tail -1 | awk '{print $1, $2, $3}')
  users_targeted=$(read_log "$AUTH_LOG" | grep "$ip" | grep "Failed\|Invalid" | \
    awk '{for(i=1;i<=NF;i++) if($i=="for" || $i=="user") print $(i+1)}' | sort -u | tr '\n' ', ')

  metric "Failed attempts:  $failures"
  metric "Successful logins: $successes"
  metric "First seen:        $first_seen"
  metric "Last seen:         $last_seen"
  metric "Users targeted:    $users_targeted"

  if [[ $successes -gt 0 ]] && [[ $failures -gt $THRESHOLD_BRUTE ]]; then
    finding "${BOLD}CRITICAL: Brute force succeeded from this IP${RESET}"
  fi

  echo ""
  # --- Check syslog for broader activity
  echo -e "${BOLD}Syslog Events from $ip:${RESET}"
  echo "────────────────────────────────────────────────────"
  read_log "$SYSLOG" | grep "$ip" | tail -20 | \
    while IFS= read -r line; do info "$line"; done
}

# =============================================================================
# MODULE 7 — EXFILTRATION INDICATORS
# =============================================================================
analyse_exfil() {
  header "Exfiltration Indicator Analysis"

  # --- Large DNS queries in logs
  echo -e "${BOLD}Unusual DNS Activity:${RESET}"
  echo "────────────────────────────────────────────────────"
  if log_exists "$SYSLOG"; then
    # Look for unusually long domain names (DNS tunneling indicator)
    read_log "$SYSLOG" | grep -i "query\|dns" 2>/dev/null | \
      awk 'length($0) > 200' | head -10 | \
      while IFS= read -r line; do
        finding "Long DNS entry (possible tunneling): ${line:0:200}..."
      done || info "No suspicious DNS length patterns found"
  fi

  echo ""
  # --- Outbound connection patterns in logs
  echo -e "${BOLD}Outbound Connection Indicators:${RESET}"
  echo "────────────────────────────────────────────────────"
  read_log "$SYSLOG" | \
    grep -iE "curl|wget|nc |netcat|python.*socket|perl.*socket" 2>/dev/null | \
    tail -20 | \
    while IFS= read -r line; do
      finding "$line"
    done || ok "No obvious download/outbound tool usage in syslog"

  echo ""
  # --- Archiving/compression in logs (staging for exfil)
  echo -e "${BOLD}Archive/Compression Commands:${RESET}"
  echo "────────────────────────────────────────────────────"
  if log_exists "$AUDIT_LOG"; then
    grep -E "tar|zip|7z|gzip|bzip2" "$AUDIT_LOG" 2>/dev/null | \
      grep "EXECVE" | head -20 | \
      while IFS= read -r line; do warn "$line"; done || ok "No archiving detected in auditd"
  fi

  echo ""
  # --- Unusual cron outbound (scheduled exfil)
  echo -e "${BOLD}Cron Jobs with Network Commands:${RESET}"
  echo "────────────────────────────────────────────────────"
  {
    cat /etc/crontab 2>/dev/null
    cat /etc/cron.d/* 2>/dev/null
    for user in $(cut -d: -f1 /etc/passwd); do
      crontab -l -u "$user" 2>/dev/null
    done
  } | grep -iE "curl|wget|nc |netcat|scp|rsync|ftp" 2>/dev/null | \
    while IFS= read -r line; do
      finding "Network command in cron: $line"
    done || ok "No network commands found in crontabs"
}

# =============================================================================
# REPORT GENERATION
# =============================================================================
generate_report() {
  local mode="$1"
  {
    echo "=================================================================="
    echo "  LOG ANALYSIS REPORT"
    echo "  Generated: $(date)"
    echo "  Hostname:  $(hostname)"
    echo "  Analyst:   ${USER:-unknown}"
    echo "  Mode:      $mode"
    echo "=================================================================="
    echo ""
  } | tee -a "$OUTFILE"
}

# =============================================================================
# ENTRY POINT
# =============================================================================
clear
echo -e "${BOLD}${CYAN}"
cat << 'BANNER'
  _    ___   ___   ___   _   ___ ___ ___ ___
 | |  / _ \ / __| | _ \ /_\ | _ \ __/ __| __|
 | |_| (_) | (_ | |  _// _ \|   /\__ \__ \ _|
 |____\___/ \___| |_| /_/ \_\_|_\|___/___/___|

         Security Log Analysis Engine
BANNER
echo -e "${RESET}"

generate_report "$MODE"

case "$MODE" in
  brute)    analyse_brute_force | tee -a "$OUTFILE" ;;
  privesc)  analyse_privesc     | tee -a "$OUTFILE" ;;
  persist)  analyse_persistence | tee -a "$OUTFILE" ;;
  evasion)  analyse_evasion     | tee -a "$OUTFILE" ;;
  exfil)    analyse_exfil       | tee -a "$OUTFILE" ;;
  user)     analyse_user "${2:-}" | tee -a "$OUTFILE" ;;
  ip)       analyse_ip "${2:-}"   | tee -a "$OUTFILE" ;;
  full)
    analyse_brute_force | tee -a "$OUTFILE"
    analyse_privesc     | tee -a "$OUTFILE"
    analyse_persistence | tee -a "$OUTFILE"
    analyse_evasion     | tee -a "$OUTFILE"
    analyse_exfil       | tee -a "$OUTFILE"
    ;;
  *)
    echo "Usage: $0 [brute|privesc|persist|evasion|exfil|full|user <name>|ip <addr>]"
    exit 1
    ;;
esac

echo ""
echo -e "${GREEN}${BOLD}════════════════════════════════════════${RESET}"
echo -e "  Report saved: ${CYAN}$OUTFILE${RESET}"
echo -e "${GREEN}${BOLD}════════════════════════════════════════${RESET}"
