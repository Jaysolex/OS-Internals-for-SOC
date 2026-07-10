# L12 — Kernel Module & Rootkit Detection

**Module:** Linux/11-Kernel-Modules  
**Time:** 35 minutes  
**Objective:** Audit kernel modules, detect unsigned and out-of-tree modules, compare module sources for discrepancies, and check for rootkit indicators.

---

## Exercise 1 — Module Inventory

```bash
# Full module listing
lsmod

# Get detailed info on each loaded module
lsmod | awk 'NR>1{print $1}' | while read mod; do
  filename=$(modinfo "$mod" 2>/dev/null | grep "^filename:" | awk '{print $2}')
  signer=$(modinfo "$mod" 2>/dev/null | grep "^signer:" | awk '{print $2}')
  version=$(modinfo "$mod" 2>/dev/null | grep "^version:" | awk '{print $2}')
  echo "Module: $mod | Version: $version | Signer: ${signer:-UNSIGNED} | File: $filename"
done | head -30
```

---

## Exercise 2 — Unsigned Module Detection

```bash
# Find unsigned or out-of-tree modules
echo "=== Module Signature Status ==="
lsmod | awk 'NR>1{print $1}' | while read mod; do
  signer=$(modinfo "$mod" 2>/dev/null | grep "^signer:" | awk '{print $2}')
  filename=$(modinfo "$mod" 2>/dev/null | grep "^filename:" | awk '{print $2}')
  if [ -z "$signer" ]; then
    echo "UNSIGNED: $mod -> $filename"
  fi
  # Out-of-tree check
  if ! echo "$filename" | grep -q "^/lib/modules"; then
    echo "OUT-OF-TREE: $mod -> $filename"
  fi
done

# Check kernel taint flags
taint=$(cat /proc/sys/kernel/tainted)
echo ""
echo "Kernel taint value: $taint"
[ "$taint" = "0" ] && echo "Clean kernel — no unexpected modifications" || \
  echo "TAINTED KERNEL: $taint — investigate loaded modules"
```

---

## Exercise 3 — Three-Source Module Comparison

```bash
# The rootkit detection technique — compare three independent sources
lsmod | awk 'NR>1{print $1}' | sort > /tmp/source_lsmod.txt
cat /proc/modules | awk '{print $1}' | sort > /tmp/source_proc.txt
ls /sys/module/ | sort > /tmp/source_sys.txt

echo "=== lsmod vs /proc/modules ==="
diff /tmp/source_lsmod.txt /tmp/source_proc.txt && \
  echo "MATCH" || echo "DISCREPANCY DETECTED"

echo "=== lsmod vs /sys/module ==="
diff /tmp/source_lsmod.txt /tmp/source_sys.txt && \
  echo "MATCH" || echo "DISCREPANCY DETECTED"

echo "Total modules: $(wc -l < /tmp/source_lsmod.txt)"

rm /tmp/source_lsmod.txt /tmp/source_proc.txt /tmp/source_sys.txt
```

---

## Exercise 4 — Rootkit Indicator Checklist

```bash
echo "=== ROOTKIT INDICATOR CHECKLIST ==="

# 1. LD_PRELOAD
echo -n "1. /etc/ld.so.preload: "
[ -f /etc/ld.so.preload ] && cat /etc/ld.so.preload || echo "CLEAN (file does not exist)"

# 2. Kernel taint
echo -n "2. Kernel taint: "
taint=$(cat /proc/sys/kernel/tainted)
[ "$taint" = "0" ] && echo "CLEAN (0)" || echo "TAINTED: $taint"

# 3. Process list discrepancy
proc_count=$(ls /proc | grep '^[0-9]' | wc -l)
ps_count=$(ps aux | wc -l)
echo "3. Process count: /proc=$proc_count ps=$ps_count (large diff = suspicious)"

# 4. Network connection discrepancy
tcp_count=$(wc -l < /proc/net/tcp)
ss_count=$(ss -tn 2>/dev/null | wc -l)
echo "4. TCP connections: /proc/net=$tcp_count ss=$ss_count (large diff = suspicious)"

# 5. Deleted binary processes
deleted=$(ls -la /proc/*/exe 2>/dev/null | grep "(deleted)" | wc -l)
echo "5. Processes with deleted binaries: $deleted"
[ "$deleted" -gt 0 ] && ls -la /proc/*/exe 2>/dev/null | grep "(deleted)"

echo ""
echo "All CLEAN = no rootkit indicators found"
echo "Any flags = investigate further with memory forensics"
```

---

## Exercise 5 — dmesg Module Analysis

```bash
# Check kernel ring buffer for module load messages
echo "=== Recent kernel module activity ==="
dmesg --time-format=iso 2>/dev/null | grep -iE "module|insmod|modprobe|loaded" | tail -20

# Check auto-load configuration
echo "=== Auto-load module configuration ==="
cat /etc/modules 2>/dev/null
ls /etc/modprobe.d/ 2>/dev/null && cat /etc/modprobe.d/*.conf 2>/dev/null | \
  grep -v "^#\|^$"
```

---

## Validation

```bash
# Run full triage and review kernel module section
sudo bash ~/OS-Internals-for-SOC/Scripts/Linux/linux-triage.sh /tmp/lab12
cat /tmp/lab12/08_lsmod.txt
cat /tmp/lab12/11_rootkit_indicators.txt
```
