# Windows/09 — Networking Stack

> Every C2 channel, every lateral movement path, every exfiltration route is a network connection. Windows networking — Winsock, named pipes, DNS, WinHTTP — is the infrastructure attackers use to maintain persistence and move through environments. Understanding it at the internals level is what allows you to find connections that have been carefully hidden.

![MITRE](https://img.shields.io/badge/MITRE-T1071%20|%20T1090%20|%20T1572%20|%20T1095-red)
![Platform](https://img.shields.io/badge/Platform-Windows-blue)

---

## Windows Network Architecture

```
Application (browser, malware, PowerShell)
        |
        v
Winsock API (ws2_32.dll)        <- socket(), connect(), send(), recv()
        |
        v
Winsock Kernel (AFD.sys)        <- kernel socket implementation
        |
        v
Transport Layer (TCP/IP)
  tcpip.sys                     <- TCP, UDP, IP, ICMP
        |
        v
NDIS (Network Driver Interface Specification)
  ndis.sys                      <- abstraction layer over NIC drivers
        |
        v
Network Interface Card Driver
        |
        v
Physical / Virtual NIC
```

Windows Filtering Platform (WFP) sits alongside this stack providing the firewall framework — the kernel-level equivalent of Linux's Netfilter.

---

## Winsock and Socket API

Winsock (Windows Sockets) is the Windows implementation of the BSD socket API. All network communication goes through ws2_32.dll in userspace.

```powershell
# Current TCP connections with process
netstat -anob

# PowerShell equivalent
Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' } |
  ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{
      LocalPort  = $_.LocalPort
      RemoteAddr = $_.RemoteAddress
      RemotePort = $_.RemotePort
      State      = $_.State
      PID        = $_.OwningProcess
      Process    = $proc.Name
      Path       = $proc.Path
    }
  }

# All listening ports
Get-NetTCPConnection -State Listen |
  ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{
      Port    = $_.LocalPort
      PID     = $_.OwningProcess
      Process = $proc.Name
      Path    = $proc.Path
    }
  } | Sort-Object Port
```

---

## Named Pipes

Named pipes are an IPC mechanism providing bidirectional communication between processes — locally or across the network via SMB (\\server\pipe\name).

```
\\.\pipe\                   local named pipe namespace
\\server\pipe\              remote named pipe over SMB
```

**Attacker use of named pipes:**
- C2 communication between stager and payload
- Lateral movement (PsExec uses named pipe for command relay)
- Privilege escalation via impersonation (token impersonation via pipe)

```powershell
# List all named pipes
[System.IO.Directory]::GetFiles("\\.\pipe\") | Sort-Object

# List with Sysinternals PipeList
# pipelist.exe

# Sysmon Event ID 17 (pipe created) and 18 (pipe connected)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'
  Id=@(17,18)
} | Select-Object TimeCreated, Message | Format-List
```

### Named Pipe Impersonation

A service that creates a named pipe and calls `ImpersonateNamedPipeClient()` takes on the security context of the connecting client. If a privileged process connects to an attacker-controlled pipe, the attacker gains that process's token.

---

## DNS Resolution

Windows DNS resolution order:

```
1. DNS cache (check with ipconfig /displaydns)
2. hosts file (C:\Windows\System32\drivers\etc\hosts)
3. DNS server (from network config)
4. WINS/NetBIOS (legacy, if enabled)
5. LLMNR (Link-Local Multicast Name Resolution)
6. mDNS (Multicast DNS)
```

LLMNR and mDNS are broadcast protocols — an attacker can respond to these queries to intercept credentials (Responder attack).

```powershell
# Check DNS cache
ipconfig /displaydns

# Check hosts file
Get-Content C:\Windows\System32\drivers\etc\hosts

# Current DNS server config
Get-DnsClientServerAddress

# Check if LLMNR is disabled (should be on hardened systems)
(Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient").EnableMulticast

# Flush DNS cache
ipconfig /flushdns
Clear-DnsClientCache
```

---

## Windows Filtering Platform (WFP)

WFP is the kernel-level packet filtering framework — what Windows Firewall, EDRs, and network inspection drivers use.

```powershell
# View Windows Firewall rules
Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' } |
  Select-Object DisplayName, Direction, Action, Profile

# Check if firewall is enabled
Get-NetFirewallProfile | Select-Object Name, Enabled

# Outbound rules (attacker may add rules to allow C2)
Get-NetFirewallRule -Direction Outbound -Action Allow |
  Where-Object { $_.Enabled -eq 'True' } |
  Select-Object DisplayName, Profile

# Check WFP filters directly (requires admin)
netsh wfp show filters
```

---

## WinHTTP and WinINet

Two Windows HTTP client libraries used by applications and malware for HTTP/HTTPS communication.

```
WinINet (wininet.dll)   <- Internet Explorer based, user-level
WinHTTP (winhttp.dll)   <- service-oriented, used by Windows Update
```

Both support system proxy settings — malware using these libraries inherits proxy configuration, which may be a detection vector.

```powershell
# Check system proxy settings
netsh winhttp show proxy

# Check IE/WinINet proxy
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable
```

---

## C2 Communication Techniques

### HTTP/HTTPS Beaconing

Most common C2 protocol — blends with legitimate web traffic.

Detection:
- Regular interval connections to external hosts (beaconing pattern)
- HTTP requests with unusual User-Agent strings
- HTTPS to newly registered domains or domains with low reputation
- Large POST requests (data exfiltration)

```powershell
# Monitor DNS queries for C2 domain detection
# Enable DNS Client logging
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" `
  -Name EnableLogging -Value 1

# Check DNS query log
Get-WinEvent -LogName "Microsoft-Windows-DNS-Client/Operational" -MaxEvents 100 |
  Select-Object TimeCreated, Message
```

### DNS Tunneling

Data encoded in DNS query subdomains — bypasses firewalls allowing UDP 53.

Detection:
```powershell
# High frequency DNS queries to same domain
Get-WinEvent -LogName "Microsoft-Windows-DNS-Client/Operational" |
  ForEach-Object {
    if ($_.Message -match 'QueryName:\s+(\S+)') {
      $Matches[1]
    }
  } | Group-Object | Sort-Object Count -Descending | Select-Object -First 20
```

### SMB Lateral Movement

```
Lateral movement via SMB:
  - PsExec (creates service via named pipe PSEXECSVC)
  - WMI (DCOM over port 135 + dynamic ports)
  - WinRM (port 5985/5986)
  - RDP (port 3389)
  - Pass-the-Hash (NTLM authentication with hash)
```

```powershell
# Check for remote connections
Get-NetTCPConnection -State Established |
  Where-Object { $_.RemotePort -in @(445, 135, 5985, 5986, 3389) } |
  ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    "$($proc.Name):$($_.LocalPort) -> $($_.RemoteAddress):$($_.RemotePort)"
  }
```

---

## Network Forensics — ARP and Routing

```powershell
# ARP cache — recent network neighbors
Get-NetNeighbor | Where-Object { $_.State -ne 'Unreachable' }
arp -a

# Routing table
Get-NetRoute | Where-Object { $_.RouteMetric -lt 999 }
route print

# Interface statistics
Get-NetAdapterStatistics
netstat -e

# Active SMB sessions (lateral movement indicator)
Get-SmbSession
net session

# Open SMB shares
Get-SmbShare
net share
```

---

## Investigation Commands — Full Network Triage

```powershell
# All established connections with process path
Get-NetTCPConnection -State Established | ForEach-Object {
  $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
  [PSCustomObject]@{
    Local      = "$($_.LocalAddress):$($_.LocalPort)"
    Remote     = "$($_.RemoteAddress):$($_.RemotePort)"
    PID        = $_.OwningProcess
    Process    = $proc.Name
    Path       = $proc.Path
    Signed     = (Get-AuthenticodeSignature $proc.Path -ErrorAction SilentlyContinue).Status
  }
} | Format-Table -AutoSize

# Listening ports
Get-NetTCPConnection -State Listen |
  ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    "$($_.LocalAddress):$($_.LocalPort) <- $($proc.Name) (PID:$($_.OwningProcess))"
  } | Sort-Object

# DNS cache — C2 domain evidence
ipconfig /displaydns | Select-String "Record Name|A \(Host\) Record" | Select-Object -First 50

# Hosts file anomalies
Get-Content C:\Windows\System32\drivers\etc\hosts |
  Where-Object { $_ -notmatch '^#' -and $_ -match '\S' }

# Named pipes
[System.IO.Directory]::GetFiles("\\.\pipe\") |
  Where-Object { $_ -notmatch 'lsass|ntsvcs|svcctl|browser|wkssvc|srvsvc|netlogon|samr' }

# Firewall rules added recently
Get-NetFirewallRule |
  Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Outbound' } |
  Select-Object DisplayName, RemoteAddress, RemotePort, Program
```

---

## MITRE ATT&CK Mapping

| Technique | ID |
|-----------|-----|
| Application Layer Protocol: Web Protocols | T1071.001 |
| Application Layer Protocol: DNS | T1071.004 |
| Proxy | T1090 |
| Protocol Tunneling | T1572 |
| Non-Application Layer Protocol | T1095 |
| Non-Standard Port | T1571 |
| Remote Services: SMB/Windows Admin Shares | T1021.002 |
| Remote Services: Windows Remote Management | T1021.006 |

---

## Sigma Rule — Suspicious Outbound Connection from System Process

```yaml
title: System Process Making Outbound Connection to Internet
id: d6e7f8a9-b0c1-2345-defa-678901234567
status: stable
description: >
  Detects Windows system processes making outbound
  connections to non-RFC1918 addresses. System processes
  should not be initiating internet connections directly.
author: Solomon James (@Jaysolex)
tags:
  - attack.command_and_control
  - attack.t1071
logsource:
  product: windows
  category: network_connection
  service: sysmon
detection:
  selection:
    EventID: 3
    Image|contains:
      - '\system32\lsass.exe'
      - '\system32\services.exe'
      - '\system32\winlogon.exe'
      - '\system32\csrss.exe'
    Initiated: 'true'
  filter_private:
    DestinationIp|startswith:
      - '10.'
      - '192.168.'
      - '172.16.'
      - '127.'
  condition: selection and not filter_private
falsepositives:
  - Windows Update via lsass (rare, verify)
level: high
```

---

## Practitioner Notes

**On LLMNR and NBT-NS poisoning:** LLMNR and NetBIOS Name Service are broadcast protocols — any host on the network can respond. Responder and Inveigh exploit this to capture NTLMv2 hashes from any machine that makes a failed DNS lookup. Hardening: disable LLMNR via GPO (`Computer Configuration > Administrative Templates > Network > DNS Client > Turn off multicast name resolution`) and disable NBT-NS via network adapter settings.

**On named pipe analysis during IR:** Legitimate named pipes follow predictable naming patterns — system services use names like `svcctl`, `netlogon`, `samr`. Attacker-created pipes often use random strings, mimic legitimate names with subtle differences, or use names associated with known tools (e.g., Cobalt Strike default pipe names include `msagent_`, `postex_`, `mojo.`). Alert on new pipes not matching a baseline.

**On WinHTTP vs WinINet proxy inheritance:** Malware using WinHTTP inherits the system proxy configured via `netsh winhttp`, while malware using WinINet inherits the per-user proxy from HKCU. Understanding which library a sample uses determines whether proxying/SSL inspection will intercept its traffic.

---

## Knowledge Validation

**How does Responder exploit LLMNR and NBT-NS and what is the detection?**
When a Windows host fails to resolve a hostname via DNS, it falls back to LLMNR (multicast) and NBT-NS (broadcast) queries. Responder listens for these broadcasts and responds authoritatively to all of them — redirecting the querying host to connect to the attacker machine. When the querying host connects (typically via SMB or HTTP), it sends NTLMv2 authentication that can be captured and cracked offline. Detection: LLMNR queries visible in DNS Client event logs, unusual SMB connection attempts to unexpected hosts, and Responder's characteristic responses visible in network packet capture.

**A malware sample is communicating via HTTPS on port 443 to domains with valid certificates. Why is this difficult to detect with network-based controls alone?**
TLS encrypts the payload — network inspection cannot see the content without SSL inspection (MITM proxy). Valid certificates bypass reputation-based checks. Legitimate domains may be used for C2 (domain fronting, legitimate cloud services). Network-based detection must rely on behavioral indicators: beaconing regularity, JA3/JA3S fingerprints of the TLS handshake, connection timing patterns, data volume patterns, and domain age/reputation. Host-based detection via Sysmon network events provides process-to-connection correlation that network monitoring lacks.

**What is the forensic value of the DNS cache during an IR?**
The DNS cache (`ipconfig /displaydns`) contains recently resolved hostnames and their IP addresses — including C2 domains the malware contacted. It survives process termination and provides evidence of C2 infrastructure even if the malware is no longer running. It is volatile — cleared on reboot and by `ipconfig /flushdns`. Acquire it early in live response before any remediation actions that might trigger a reboot.

---

*Windows/09-Networking-Stack | OS-Internals-for-SOC | Solomon James (@Jaysolex)*
