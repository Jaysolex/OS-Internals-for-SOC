#!/usr/bin/env bash
# =============================================================================
# persistence-hunter.sh
# Enumerate every persistence mechanism on a Linux system
# Author: Solomon James (@Jaysolex)
# Usage: sudo bash persistence-hunter.sh
# =============================================================================

set -uo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

OUTFILE="/tmp/persistence_$(hostname)_$(date +%Y%m%d_%H%M%S).txt"
FINDINGS=0

header()  { echo -e "\n${BOLD}${CYAN}━━━━ $* ━━━━${RESET}\n" | tee -a "$OUTFILE"; }
hit()     { echo -e "  ${RED}[HIT]${RESET}     $*" | tee -a "$OUTFILE"; ((FINDINGS++)); }
clean()   { echo -e "  ${GREEN}[CLEAN]${RESET}   $*" | tee -a "$OUTFILE"; }
info()    { echo -e "  ${CYAN}[INFO]${RESET}    $*" | tee -a "$OUTFILE"; }
warn()    { echo -e "  ${YELLOW}[CHECK]${RESET}   $*" | tee -a "$OUTFILE"; }

[[ $EUID -ne 0 ]] && { echo -e "${RED}Run as root${RESET}"; exit 1; }

echo -e "${BOLD}${CYAN}Persistence Hunter — $(date)${RESET}" | tee "$OUTFILE"
echo -e "Host: $(hostname) | Kernel: $(uname -r)\n" | tee -a "$OUTFILE"

# ── 1. CRON ───────────────────────────────────────────────────────────────────
header "CRON JOBS"

# System crontabs
for f in /etc/crontab /etc/cron.d/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* /etc/cron.hourly/*; do
  [[ -f "$f" ]] || continue
  content=$(grep -v "^#\|^$" "$f" 2>/dev/null)
  [[ -z "$content" ]] && continue
  warn "Non-empty cron file: $f"
  echo "$content" | while IFS= read -r line; do echo "    $line"; done | tee -a "$OUTFILE"
done

# Per-user crontabs
while IFS=: read -r user _ uid _ _ _ _; do
  cron=$(crontab -l -u "$user" 2>/dev/null | grep -v "^#\|^$")
  [[ -z "$cron" ]] && continue
  hit "User crontab: $user"
  echo "$cron" | while IFS= read -r line; do echo "    → $line"; done | tee -a "$OUTFILE"
done < /etc/passwd

# At jobs
atq_out=$(atq 2>/dev/null)
if [[ -n "$atq_out" ]]; then
  hit "Pending at jobs:"
  echo "$atq_out" | tee -a "$OUTFILE"
else
  clean "No at jobs"
fi

# ── 2. SYSTEMD ────────────────────────────────────────────────────────────────
header "SYSTEMD UNITS & TIMERS"

# Non-standard service units
while IFS= read -r unit; do
  unit_file=$(systemctl show "$unit" -p FragmentPath 2>/dev/null | cut -d= -f2)
  [[ -z "$unit_file" ]] && continue
  # Flag units not in /lib/systemd (package-managed)
  if ! echo "$unit_file" | grep -qE "^/lib/systemd|^/usr/lib/systemd"; then
    hit "Non-standard unit: $unit → $unit_file"
    grep -E "ExecStart|User|WorkingDirectory" "$unit_file" 2>/dev/null | \
      while IFS= read -r line; do echo "    $line"; done | tee -a "$OUTFILE"
  fi
done < <(systemctl list-units --type=service --state=enabled --no-legend --no-pager 2>/dev/null | awk '{print $1}')

# Systemd timers
info "Active timers:"
systemctl list-timers --no-pager 2>/dev/null | head -20 | tee -a "$OUTFILE"

# ── 3. INIT & PROFILE ─────────────────────────────────────────────────────────
header "INIT SCRIPTS & PROFILE HOOKS"

# rc.local
if [[ -f /etc/rc.local ]]; then
  content=$(grep -v "^#\|^$\|^exit" /etc/rc.local 2>/dev/null)
  if [[ -n "$content" ]]; then
    hit "/etc/rc.local has commands:"
    echo "$content" | while IFS= read -r line; do echo "    → $line"; done | tee -a "$OUTFILE"
  else
    clean "/etc/rc.local is empty"
  fi
fi

# /etc/profile.d/
for f in /etc/profile.d/*.sh; do
  [[ -f "$f" ]] || continue
  warn "Profile script: $f"
  cat "$f" | grep -v "^#\|^$" | while IFS= read -r line; do echo "    $line"; done | tee -a "$OUTFILE"
done

# /etc/environment
env_extra=$(grep -v "^#\|^$\|^PATH\|^LANG\|^LC_" /etc/environment 2>/dev/null)
if [[ -n "$env_extra" ]]; then
  hit "Unusual entries in /etc/environment:"
  echo "$env_extra" | tee -a "$OUTFILE"
else
  clean "/etc/environment looks normal"
fi

# ── 4. LD_PRELOAD ─────────────────────────────────────────────────────────────
header "DYNAMIC LINKER HIJACK"

if [[ -f /etc/ld.so.preload ]] && [[ -s /etc/ld.so.preload ]]; then
  hit "CRITICAL: /etc/ld.so.preload is non-empty"
  cat /etc/ld.so.preload | tee -a "$OUTFILE"
else
  clean "/etc/ld.so.preload does not exist or is empty"
fi

# Check LD_PRELOAD in common environment sources
for f in /etc/environment /etc/bash.bashrc /etc/profile; do
  if grep -q "LD_PRELOAD" "$f" 2>/dev/null; then
    hit "LD_PRELOAD set in $f:"
    grep "LD_PRELOAD" "$f" | tee -a "$OUTFILE"
  fi
done

# ── 5. SSH KEYS ───────────────────────────────────────────────────────────────
header "SSH AUTHORIZED KEYS"

find /home /root -name "authorized_keys" -type f 2>/dev/null | while read -r keyfile; do
  count=$(grep -c "ssh-" "$keyfile" 2>/dev/null || echo 0)
  if [[ $count -gt 0 ]]; then
    warn "$keyfile ($count key(s)):"
    cat "$keyfile" | while IFS= read -r line; do
      [[ "$line" =~ ^ssh- ]] || continue
      keytype=$(echo "$line" | awk '{print $1}')
      comment=$(echo "$line" | awk '{print $3}')
      echo "    Type: $keytype | Comment: $comment" | tee -a "$OUTFILE"
    done
  fi
done

# ── 6. SUID/SGID ──────────────────────────────────────────────────────────────
header "SUID / SGID BINARIES"

# Known-good SUID baseline
KNOWN_SUID=("sudo" "su" "passwd" "chsh" "chfn" "newgrp" "gpasswd" "pkexec" "mount" "umount" "ping" "ping6" "traceroute" "at" "crontab" "ssh-agent" "screen" "wall" "write" "expiry")

while IFS= read -r suid_file; do
  basename_file=$(basename "$suid_file")
  known=false
  for k in "${KNOWN_SUID[@]}"; do
    [[ "$basename_file" == "$k" ]] && known=true && break
  done
  if $known; then
    info "Known SUID: $suid_file"
  else
    hit "UNKNOWN SUID binary: $suid_file"
    file "$suid_file" | tee -a "$OUTFILE"
  fi
done < <(find / -type f -perm -4000 -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null)

# ── 7. USER ACCOUNTS ──────────────────────────────────────────────────────────
header "USER ACCOUNT ANOMALIES"

# Users with UID 0 (besides root)
while IFS=: read -r user _ uid _ _ _ shell; do
  if [[ $uid -eq 0 ]] && [[ "$user" != "root" ]]; then
    hit "Non-root user with UID 0: $user (shell: $shell)"
  fi
done < /etc/passwd

# Users with login shell who shouldn't have one
while IFS=: read -r user _ uid _ _ _ shell; do
  if [[ $uid -ge 1000 ]] && echo "$shell" | grep -qE "^/bin/|^/usr/bin/"; then
    info "User with login shell: $user (UID: $uid) → $shell"
  fi
done < /etc/passwd

# Recently created users (passwd modified in last 7 days)
if find /etc/passwd -mtime -7 2>/dev/null | grep -q passwd; then
  hit "/etc/passwd was modified in the last 7 days"
  stat /etc/passwd | tee -a "$OUTFILE"
fi

# ── 8. KERNEL MODULES ─────────────────────────────────────────────────────────
header "KERNEL MODULES"

info "Checking for unsigned or out-of-tree modules..."
while IFS= read -r mod_name; do
  mod_info=$(modinfo "$mod_name" 2>/dev/null)
  sig=$(echo "$mod_info" | grep "^sig_key:" | awk '{print $2}')
  filename=$(echo "$mod_info" | grep "^filename:" | awk '{print $2}')
  signer=$(echo "$mod_info" | grep "^signer:" | awk '{print $2}')
  # Out-of-tree = not in /lib/modules
  if ! echo "$filename" | grep -q "^/lib/modules"; then
    hit "Out-of-tree module: $mod_name → $filename"
  elif [[ -z "$signer" ]]; then
    warn "Unsigned module: $mod_name → $filename"
  fi
done < <(lsmod | awk 'NR>1{print $1}')

# ── 9. /dev/shm and /tmp ──────────────────────────────────────────────────────
header "VOLATILE STAGING DIRECTORIES"

for stagedir in /tmp /var/tmp /dev/shm; do
  executables=$(find "$stagedir" -type f -perm /111 2>/dev/null)
  hidden=$(find "$stagedir" -name ".*" -type f 2>/dev/null)
  if [[ -n "$executables" ]]; then
    hit "Executables in $stagedir:"
    echo "$executables" | while IFS= read -r f; do
      echo "    → $f ($(file -b "$f" | cut -c1-60))" | tee -a "$OUTFILE"
    done
  else
    clean "No executables in $stagedir"
  fi
  if [[ -n "$hidden" ]]; then
    hit "Hidden files in $stagedir:"
    echo "$hidden" | tee -a "$OUTFILE"
  fi
done

# ── SUMMARY ───────────────────────────────────────────────────────────────────
echo "" | tee -a "$OUTFILE"
echo -e "${BOLD}$(printf '═%.0s' {1..50})${RESET}" | tee -a "$OUTFILE"
echo -e "  FINDINGS: ${RED}${BOLD}$FINDINGS${RESET}" | tee -a "$OUTFILE"
echo -e "  REPORT:   ${CYAN}$OUTFILE${RESET}" | tee -a "$OUTFILE"
echo -e "${BOLD}$(printf '═%.0s' {1..50})${RESET}" | tee -a "$OUTFILE"
