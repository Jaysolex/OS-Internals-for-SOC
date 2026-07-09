# H09 — DNS Tunneling Hunt

**Hypothesis:** An attacker is using DNS queries to exfiltrate data or maintain C2 communication, bypassing network controls that allow UDP 53.

**OS Mechanism:** DNS uses UDP port 53 which must be allowed outbound. Data is encoded in subdomain strings of DNS queries. Responses carry data back in TXT, CNAME, or A records.

**MITRE:** T1071.004 — Application Layer Protocol: DNS

---

## Baseline

Normal DNS traffic:
- Short subdomain strings (hostname.domain.tld)
- Queries to a small set of domains
- Low query frequency per domain
- Standard record types (A, AAAA, MX, CNAME)

## Anomaly Indicators

- Very long subdomain strings (>50 chars) — data encoded in subdomain
- High-frequency queries to the same domain (beaconing)
- High entropy in subdomain strings (base64/hex encoding)
- Unusual record type requests (TXT, NULL, ANY)
- Single domain receiving queries from many internal hosts

---

## Hunt Queries

### Splunk SPL

```spl
| Long subdomain detection (DNS tunneling)
index=dns_logs
| rex field=query "^(?P<subdomain>.+?)\.(?:[^.]+\.){1,2}[^.]+$"
| eval subdomain_len=len(subdomain)
| where subdomain_len > 50
| stats count by query, src_ip, subdomain_len
| sort -subdomain_len
```

```spl
| High frequency queries (beaconing)
index=dns_logs
| bucket _time span=1m
| stats count by query, src_ip, _time
| where count > 20
| sort -count
```

```spl
| High entropy domain detection
index=dns_logs
| eval entropy=0
| eval chars=split(lower(replace(query,"[^a-z0-9]","")),"")
| eval char_count=mvcount(chars)
| eval entropy=(-1 * sum(map(frequencies, "X * log(X)/log(2)")))
| where entropy > 3.5
| table _time, src_ip, query, entropy
```

### KQL

```kql
DnsEvents
| where QueryType == "A" or QueryType == "TXT"
| extend subdomain = extract(@"^((?:[^.]+\.)+)[^.]+\.[^.]+$", 1, Name)
| extend subdomain_len = strlen(subdomain)
| where subdomain_len > 50
| summarize count=count() by Name, ClientIP, subdomain_len
| sort by subdomain_len desc
```

### Linux — Bash DNS Log Analysis

```bash
# High-frequency DNS queries from local resolver
cat /var/log/syslog | grep "named\|dnsmasq" | \
    awk '{print $NF}' | sort | uniq -c | sort -rn | head -20

# Long query strings
cat /var/log/syslog | grep "query\[A\]" | \
    awk '{print length($NF), $NF}' | sort -rn | head -20
```

---

## Validation

1. Capture DNS traffic for the suspicious domain: `tcpdump -i eth0 port 53 and host <suspect_domain>`
2. Decode subdomain content — base64, hex, or custom encoding
3. Identify the process making the queries via DNS Client logs or Sysmon Event 22
4. Check if the queried domain resolves to known C2 infrastructure

## Response

1. Block the tunneling domain at DNS resolver and firewall
2. Identify all internal hosts that queried the domain
3. Determine what data was exfiltrated — query volume × typical tunnel bandwidth
4. Hunt for the malware making the queries — check process DNS Event 22 logs
