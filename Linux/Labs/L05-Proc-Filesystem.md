# L05 — /proc Filesystem Deep Dive

**Module:** Linux/04-Proc-Filesystem  
**Time:** 30 minutes  
**Objective:** Use /proc as a forensic tool. Extract credentials from process environments, compare network state sources, and detect rootkit indicators via source discrepancy.

---

## Exercise 1 — Process Environment Variables

```bash
# Read your own process environment
cat /proc/$$/environ | tr '\0' '\n'

# Start a process with a sensitive variable (lab simulation)
SECRET=supersecrettoken123 bash -c 'sleep 60 &'; SLEEP_PID=$!

# Read the environment of that process
cat /proc/$SLEEP_PID/environ | tr '\0' '\n' | grep SECRET

# This demonstrates why scanning /proc/*/environ matters during IR
# Credentials passed as environment variables are readable here

# Cleanup
kill $SLEEP_PID 2>/dev/null
```

---

## Exercise 2 — Network State Comparison

```bash
# Get TCP connections from kernel (/proc/net/tcp)
echo "=== Kernel view (hex encoded) ==="
wc -l /proc/net/tcp
cat /proc/net/tcp | head -5

# Get TCP connections from userspace tool
echo "=== ss view ==="
ss -tn | wc -l

# Parse /proc/net/tcp manually (convert hex to decimal)
awk 'NR>1 {
  split($2,l,":");
  split($3,r,":");
  printf "Local: %d.%d.%d.%d:%d -> Remote: %d.%d.%d.%d:%d\n",
    strtonum("0x"substr(l[1],7,2)), strtonum("0x"substr(l[1],5,2)),
    strtonum("0x"substr(l[1],3,2)), strtonum("0x"substr(l[1],1,2)),
    strtonum("0x"l[2]),
    strtonum("0x"substr(r[1],7,2)), strtonum("0x"substr(r[1],5,2)),
    strtonum("0x"substr(r[1],3,2)), strtonum("0x"substr(r[1],1,2)),
    strtonum("0x"r[2])
}' /proc/net/tcp | head -10
```

---

## Exercise 3 — Module Source Comparison (Rootkit Detection)

```bash
# Three sources that should agree
lsmod | awk 'NR>1{print $1}' | sort > /tmp/source1.txt
cat /proc/modules | awk '{print $1}' | sort > /tmp/source2.txt
ls /sys/module/ | sort > /tmp/source3.txt

echo "=== lsmod vs /proc/modules ==="
diff /tmp/source1.txt /tmp/source2.txt && echo "MATCH" || echo "DISCREPANCY DETECTED"

echo "=== lsmod vs /sys/module ==="
diff /tmp/source1.txt /tmp/source3.txt && echo "MATCH" || echo "DISCREPANCY DETECTED"

# On a clean system all three should match exactly
# A rootkit manipulating one source but not others shows up here

# Cleanup
rm /tmp/source1.txt /tmp/source2.txt /tmp/source3.txt
```

---

## Exercise 4 — loginuid vs uid

```bash
# loginuid is set at login and never changes — even after sudo
echo "Current UID: $(id -u)"
echo "loginuid (original login): $(cat /proc/$$/loginuid)"

# sudo to root and check loginuid
sudo bash -c "echo UID: \$(id -u); echo loginuid: \$(cat /proc/\$\$/loginuid)"
# loginuid still shows original user — this is how auditd tracks attribution
```

---

## Exercise 5 — Kernel Parameters via /proc/sys

```bash
# Security-relevant kernel parameters
echo "ASLR: $(cat /proc/sys/kernel/randomize_va_space)"
echo "Kernel taint: $(cat /proc/sys/kernel/tainted)"
echo "dmesg restrict: $(cat /proc/sys/kernel/dmesg_restrict)"
echo "IP forwarding: $(cat /proc/sys/net/ipv4/ip_forward)"

# Check what IP forwarding=1 means for security
# (used by attackers to pivot through a compromised host)
echo ""
echo "IP forward should be 0 on workstations/servers"
echo "Value of 1 = host is acting as a router = pivot indicator"
```
