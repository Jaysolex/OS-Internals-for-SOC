# Scripts

> Operational scripts for live response, log analysis, persistence hunting, and investigation workflows. Every script is built around the OS internals concepts covered in this repository.

---

## Linux Scripts

| Script | Purpose | Run As |
|--------|---------|--------|
| [linux-triage.sh](./Linux/linux-triage.sh) | Full live response collection — 11 artifact categories | root |
| [log-parser.sh](./Linux/log-parser.sh) | Modular log analysis engine — brute force, privesc, evasion, exfil | root |
| [persistence-hunter.sh](./Linux/persistence-hunter.sh) | Enumerate every persistence mechanism on a live system | root |

## Usage

```bash
# Full system triage
sudo bash linux-triage.sh /tmp/case_001

# Log analysis — specific mode
sudo bash log-parser.sh brute
sudo bash log-parser.sh privesc
sudo bash log-parser.sh user johndoe
sudo bash log-parser.sh ip 192.168.1.100
sudo bash log-parser.sh full

# Persistence hunt
sudo bash persistence-hunter.sh
```

## Output

All scripts write timestamped output to `/tmp/` by default.  
Archive and transfer to analyst workstation:

```bash
tar czf case_$(hostname)_$(date +%Y%m%d).tar.gz /tmp/triage_*
scp case_*.tar.gz analyst@workstation:/cases/
```
