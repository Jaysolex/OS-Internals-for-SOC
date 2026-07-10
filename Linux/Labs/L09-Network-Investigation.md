# L09 — Network Investigation

**Module:** Linux/08-Networking-Stack  
**Time:** 35 minutes  
**Objective:** Map all network connections to their processes, detect reverse shell indicators, compare /proc/net with userspace tools, and investigate firewall rules.

---

## Exercise 1 — Full Network State Mapping

```bash
# Map every connection to its process
ss -tnap

# Enriched view with process paths
ss -tnap | while read -r line; do
  pid=$(echo "$line" | grep -oP 'pid=\K[0-9]+' | head -1)
  if [ -n "$pid" ]; then
    exe=$(readlink /proc/$pid/exe 2>/dev/null)
    echo "$line | EXE: $exe"
  else
    echo "$line"
  fi
done

# Listening services
echo "=== LISTENING PORTS ==="
ss -tlnp
```

---

## Exercise 2 — Reverse Shell Indicator Check

```bash
# Find shell processes with network connections
echo "=== Shell processes with sockets ==="
for pid in $(ls /proc | grep '^[0-9]'); do
  exe=$(readlink /proc/$pid/exe 2>/dev/null)
  # Check if it's a shell
  if echo "$exe" | grep -qE "/bash$|/sh$|/dash$|/zsh$"; then
    # Check if any fd is a socket
    for fd in $(ls /proc/$pid/fd/ 2>/dev/null); do
      fdlink=$(readlink /proc/$pid/fd/$fd 2>/dev/null)
      if echo "$fdlink" | grep -q "socket:"; then
        echo "POSSIBLE REVERSE SHELL: PID $pid ($exe) fd$fd -> $fdlink"
      fi
    done
  fi
done
```

---

## Exercise 3 — Kernel vs Userspace Network Comparison

```bash
# Count connections from kernel
kernel_count=$(grep -c "." /proc/net/tcp 2>/dev/null)
# Count from userspace
ss_count=$(ss -tn | wc -l)

echo "Kernel /proc/net/tcp entries: $kernel_count"
echo "ss -tn output lines: $ss_count"
echo ""
echo "Large difference = potential rootkit hiding connections"

# Check ARP cache
echo "=== ARP Cache (recent network neighbors) ==="
ip neigh show

# Check routing table
echo "=== Routing Table ==="
ip route show
```

---

## Exercise 4 — Firewall State

```bash
# Check iptables rules
sudo iptables -L -n -v 2>/dev/null | head -30

# Check nftables
sudo nft list ruleset 2>/dev/null | head -20

# Critical check — is IP forwarding enabled?
fwd=$(cat /proc/sys/net/ipv4/ip_forward)
echo "IP forwarding: $fwd"
[ "$fwd" = "1" ] && echo "WARNING: IP forwarding enabled — host may be used as pivot" || \
  echo "Normal: IP forwarding disabled"

# Check NAT rules (attacker pivot indicator)
sudo iptables -t nat -L -n -v 2>/dev/null | grep -v "^Chain\|^target\|^$"
```

---

## Exercise 5 — DNS and Hosts File

```bash
# Check hosts file for unauthorized entries
echo "=== Hosts file entries (excluding comments and localhost) ==="
grep -v "^#\|^$\|localhost\|127\." /etc/hosts

# Check DNS resolver config
echo "=== DNS servers ==="
cat /etc/resolv.conf

# Check NSSwitch for resolution order
echo "=== Name resolution order ==="
grep "^hosts:" /etc/nsswitch.conf
```

---

## Validation

```bash
# Run log parser network analysis
sudo bash ~/OS-Internals-for-SOC/Scripts/Linux/log-parser.sh exfil
```
