# SOAR Playbooks

> Structured response playbooks for high-frequency security incidents. Each playbook is anchored to OS internals knowledge — the response steps are grounded in understanding what the OS recorded, what the attacker did to cover it, and where evidence survives.

---

## Playbook Index

| ID | Playbook | Trigger | Platform | MITRE |
|----|----------|---------|----------|-------|
| [PB01](./PB01-SSH-Brute-Force.md) | SSH Brute Force Response | 10+ SSH failures / 5 min | Linux | T1110.001 |
| [PB02](./PB02-Windows-Log-Cleared.md) | Windows Event Log Cleared | Event ID 1102 / 104 | Windows | T1070.001 |
| [PB03](./PB03-Ransomware-Response.md) | Ransomware Response | Shadow copy deletion + mass rename | Windows | T1490, T1486 |
| [PB04](./PB04-Linux-Persistence-Detected.md) | Linux Persistence Detected | New cron/systemd/SSH key/LD_PRELOAD | Linux | T1053, T1543 |
| [PB05](./PB05-Credential-Dumping.md) | Credential Dumping Response | Sysmon EID 10 — LSASS access | Windows | T1003.001 |

---

## Playbook Format

Every playbook contains:

| Section | Content |
|---------|---------|
| **Trigger** | What fires this playbook |
| **What This Playbook Does** | Plain-English summary |
| **Playbook Flow** | Visual decision tree |
| **Steps** | Detailed analyst and automation actions |
| **SOAR Pseudocode** | Automation logic for Shuffle/TheHive |
| **Escalation Criteria** | When to escalate and to whom |
| **Report Template** | Standardised documentation |

---

## Integration

These playbooks are designed to integrate with:

- **Wazuh** — alert source (rules in `/Detection-Engineering/Wazuh/`)
- **Shuffle** — automation execution
- **TheHive** — case management and ticket creation
- **Slack/Teams** — analyst notification
- **VirusTotal / AbuseIPDB** — threat enrichment

---

## Severity Escalation Matrix

| Alert Level | Response Time | Handler |
|-------------|--------------|---------|
| Medium | 4 hours | L1 SOC Analyst |
| High | 1 hour | L2 SOC Analyst |
| Critical | 15 minutes | L2 + IR Lead |
| Critical + Domain Admin | Immediate | IR Lead + CISO |
