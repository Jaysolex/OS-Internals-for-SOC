# Splunk SPL — Detection & Threat Hunting

> Production-ready SPL queries for Splunk Enterprise and Splunk Cloud.
> Each query is mapped to a MITRE ATT&CK technique and includes field context,
> tuning guidance, and what a true positive looks like versus a false positive.

---

## How to Use These Queries

1. Paste into Splunk Search bar or save as a Saved Search
2. Adjust `index=` to match your environment
3. Set time range appropriate to the detection (real-time for alerting, 24h for hunting)
4. Review tuning notes before enabling as production alerts

---

## Linux Detections

### SSH Brute Force Detection

Detects multiple failed SSH login attempts from a single source IP within a short window.
A count above 10 failures in 5 minutes from one IP is a reliable brute force indicator.
Correlate with successful logins from the same IP to identify breaches.

```spl
index=linux_logs sourcetype=syslog "Failed password"
| rex field=_raw "from (?P<src_ip>\d+\.\d+\.\d+\.\d+) port (?P<src_port>\d+)"
| rex field=_raw "for (?:invalid user )?(?P<username>\S+) from"
| bucket _time span=5m
| stats count AS failures dc(username) AS users_targeted BY src_ip _time
| where failures > 10
| eval severity=case(failures>100,"CRITICAL", failures>50,"HIGH", failures>10,"MEDIUM")
| eval mitre="T1110.001 - Brute Force: Password Guessing"
| table _time src_ip failures users_targeted severity mitre
| sort -failures
```

**True positive:** Single IP generating 50+ failures across multiple usernames in minutes.
**False positive:** Misconfigured automation using wrong credentials — check username patterns.

---

### Brute Force Followed by Successful Login

The critical correlation — brute force that succeeded. Highest priority alert.

```spl
index=linux_logs sourcetype=syslog
| rex field=_raw "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| eval event_type=case(
    match(_raw,"Failed password"), "failure",
    match(_raw,"Accepted password|Accepted publickey"), "success",
    true(), "other")
| where event_type IN ("failure","success")
| stats count(eval(event_type="failure")) AS failures
         count(eval(event_type="success")) AS successes
         BY src_ip
| where failures > 5 AND successes > 0
| eval severity="CRITICAL"
| eval mitre="T1110.001 - Brute Force succeeded"
| table src_ip failures successes severity mitre
```

---

### Log File Shredded or Cleared

Detects use of shred, truncate, or direct overwrites against Linux log files.
After an attack, clearing logs is one of the first attacker actions.
This query catches it in auditd records even if the log file itself is destroyed.

```spl
index=linux_auditd
(type=EXECVE a0="shred" a1="/var/log*")
OR (type=SYSCALL syscall=truncate a0="/var/log*")
OR (type=EXECVE a0="dd" (a2="/var/log*" OR a3="/var/log*"))
| eval action=case(
    a0="shred","File Shredded",
    syscall="truncate","File Truncated",
    a0="dd","DD Overwrite",
    true(),"Unknown")
| eval mitre="T1070.002 - Indicator Removal: Clear Linux Logs"
| table _time host auid uid action a0 a1 a2
| sort -_time
```

---

### rsyslog Daemon Stopped

Detects the logging daemon being stopped via systemctl or service command.
When rsyslog stops, no new log entries are written to /var/log/*.
The gap in log timeline itself becomes evidence after the fact.

```spl
index=linux_auditd type=EXECVE
(a0="systemctl" a1="stop" (a2="rsyslog" OR a2="syslog"))
OR (a0="service" a1="rsyslog" a2="stop")
| eval mitre="T1562.001 - Impair Defenses: Disable or Modify Tools"
| eval severity="HIGH"
| table _time host auid uid a0 a1 a2 severity mitre
| sort -_time
```

---

### Execution from Temporary Directories

Detects processes launched from /tmp, /var/tmp, or /dev/shm.
Legitimate software does not execute from these locations.
Attackers stage payloads here because they are world-writable.

```spl
index=linux_auditd type=EXECVE
(a0="/tmp/*" OR a0="/var/tmp/*" OR a0="/dev/shm/*")
| eval location=case(
    match(a0,"^/tmp/"),"Temp (/tmp)",
    match(a0,"^/var/tmp/"),"Persistent Temp (/var/tmp)",
    match(a0,"^/dev/shm/"),"Shared Memory (/dev/shm)")
| eval risk=case(
    match(a0,"^/dev/shm/"),"CRITICAL - RAM only, no disk artifact",
    match(a0,"^/var/tmp/"),"HIGH - Persists across reboots",
    true(),"HIGH")
| eval mitre="T1059 - Command and Scripting Interpreter"
| table _time host auid uid a0 location risk mitre
| sort -_time
```

---

### Kernel Module Loaded Outside Boot

Detects kernel module loading outside of expected system boot context.
Legitimate module loads happen at boot or during hardware changes.
Runtime module loading by user processes is a rootkit insertion indicator.

```spl
index=linux_auditd type=SYSCALL
(syscall="init_module" OR syscall="finit_module")
auid!=4294967295
| lookup users uid AS uid OUTPUT username
| eval mitre="T1547.006 - Boot/Logon Autostart: Kernel Modules"
| eval severity="HIGH"
| table _time host uid username syscall exe severity mitre
| sort -_time
```

---

### LD_PRELOAD Configuration Modified

Detects writes to /etc/ld.so.preload — the global library preload file.
Any content in this file loads into every dynamically linked process on the system.
This file should not exist on a clean system.

```spl
index=linux_auditd type=PATH name="/etc/ld.so.preload"
nametype IN ("CREATE","NORMAL")
| eval mitre="T1574.006 - Hijack Execution Flow: LD_PRELOAD"
| eval severity="CRITICAL"
| eval note="This file should not exist. Any entry preloads a library into every process."
| table _time host auid uid name nametype severity mitre note
| sort -_time
```

---

### Cron Persistence Added

Detects new files written to system cron directories.
Package managers add cron files during installation — flag anything outside maintenance windows.
Attacker cron entries frequently contain network commands or paths to /tmp.

```spl
index=linux_auditd type=PATH nametype=CREATE
(name="/etc/cron.d/*" OR name="/etc/cron.daily/*" OR
 name="/var/spool/cron/*" OR name="/etc/crontab")
| eval mitre="T1053.003 - Scheduled Task/Job: Cron"
| table _time host auid uid name nametype mitre
| sort -_time
```

---

### Systemd Service Created

Detects new .service unit files written to systemd directories.
Malicious services provide boot-persistent execution as SYSTEM or any user.
Flag units created outside package management or deployment windows.

```spl
index=linux_auditd type=PATH nametype=CREATE
name="/etc/systemd/system/*.service"
| eval mitre="T1543.002 - Create or Modify System Process: Systemd Service"
| table _time host auid uid name mitre
| sort -_time
```

---

### Process Running from Deleted Binary

Detects processes whose executable has been deleted from disk.
Attackers delete the binary after launch to remove the file-based IOC.
The binary is still recoverable from /proc/pid/exe while the process runs.

```spl
index=linux_auditd exe="*(deleted)*"
| eval mitre="T1036 - Masquerading"
| eval action="Binary deleted from disk — process still running in memory"
| eval recovery="cp /proc/" + pid + "/exe /tmp/recovered_binary"
| table _time host pid uid exe action recovery mitre
| sort -_time
```

---

### New User Account Created

Detects creation of new local user accounts on Linux.
Backdoor accounts provide persistent authenticated access independent of other mechanisms.

```spl
index=linux_auditd type=ADD_USER
| eval mitre="T1136.001 - Create Account: Local Account"
| table _time host auid uid acct exe mitre
| sort -_time
```

---

## Windows Detections

### Event Log Cleared

Detects Windows Security or System log clearing.
Event ID 1102 is generated in the Security log when it is cleared.
Event ID 104 is generated in the System log when it is cleared.
These events are themselves logged and cannot be silently suppressed.

```spl
index=wineventlog (EventCode=1102 OR (EventCode=104 Channel=System))
| eval log_cleared=case(EventCode=1102,"Security Log",EventCode=104,"System Log")
| eval mitre="T1070.001 - Indicator Removal: Clear Windows Event Logs"
| eval severity="HIGH"
| table _time host log_cleared SubjectUserName SubjectLogonId severity mitre
| sort -_time
```

---

### LSASS Memory Access

Detects processes opening LSASS with memory read permissions.
Access masks 0x1010 and 0x1410 include PROCESS_VM_READ — required for credential dumping.
Filter out known security products; everything else is suspicious.

```spl
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
GrantedAccess IN ("0x1010","0x1410","0x1438","0x143a","0x1418","0x1fffff")
NOT SourceImage IN ("C:\\Windows\\system32\\*","C:\\Windows\\SysWOW64\\*",
    "C:\\Program Files\\*","C:\\Program Files (x86)\\*")
| eval mitre="T1003.001 - OS Credential Dumping: LSASS Memory"
| eval severity="HIGH"
| table _time host SourceImage SourceProcessId GrantedAccess TargetImage severity mitre
| sort -_time
```

---

### WMI Event Subscription Created

Detects WMI permanent event subscription creation via Sysmon events 19, 20, and 21.
WMI subscriptions are fileless persistence — stored in the WMI repository, not on disk.
Any new subscription outside known monitoring tools should be investigated immediately.

```spl
index=sysmon EventCode IN (19,20,21)
| eval sub_type=case(EventCode=19,"Filter",EventCode=20,"Consumer",EventCode=21,"Binding")
| eval mitre="T1546.003 - Event Triggered Execution: WMI Event Subscription"
| eval severity="HIGH"
| table _time host sub_type EventCode User Name Type Query Destination severity mitre
| sort -_time
```

---

### Scheduled Task Created with Suspicious Path

Detects scheduled tasks where the executable path is outside Windows system directories.
Attackers create tasks pointing to payloads in Temp, AppData, or ProgramData.

```spl
index=wineventlog EventCode=4698
| rex field=Message "Task Content:\s*(?P<task_xml>[\s\S]+)"
| rex field=task_xml "<Command>(?P<command>[^<]+)</Command>"
| where NOT match(command,"(?i)C:\\\\Windows\\\\|C:\\\\Program Files")
| eval mitre="T1053.005 - Scheduled Task/Job: Scheduled Task"
| table _time host SubjectUserName TaskName command mitre
| sort -_time
```

---

### New Service with Non-Standard Path

Detects Windows service installation with executable paths outside system directories.
Legitimate services install to C:\Windows\ or C:\Program Files\.
Services from Temp, AppData, or user directories are almost always malicious.

```spl
index=wineventlog EventCode=7045
NOT ServiceFileName IN ("C:\\Windows\\*","\"C:\\Windows\\*",
    "C:\\Program Files\\*","\"C:\\Program Files*")
| eval mitre="T1543.003 - Create or Modify System Process: Windows Service"
| table _time host ServiceName ServiceFileName ServiceType AccountName mitre
| sort -_time
```

---

### Office Application Spawning Shell

Detects Microsoft Office applications (Word, Excel, PowerPoint) spawning command interpreters.
This is the signature of malicious macro execution — the most common initial access technique.
Very low false positive rate in managed environments.

```spl
index=sysmon EventCode=1
ParentImage IN ("*\\winword.exe","*\\excel.exe","*\\powerpnt.exe","*\\outlook.exe")
Image IN ("*\\cmd.exe","*\\powershell.exe","*\\wscript.exe",
          "*\\cscript.exe","*\\mshta.exe","*\\regsvr32.exe","*\\rundll32.exe")
| eval mitre="T1566.001 - Phishing: Spearphishing Attachment"
| eval severity="HIGH"
| table _time host ParentImage Image CommandLine User severity mitre
| sort -_time
```

---

### Encoded PowerShell Execution

Detects PowerShell launched with encoded command arguments.
Attackers encode commands to bypass script content inspection and logging.
Script block logging (Event 4104) will capture the decoded content.

```spl
index=sysmon EventCode=1
Image IN ("*\\powershell.exe","*\\pwsh.exe")
(CommandLine="*-enc *" OR CommandLine="*-EncodedCommand*" OR CommandLine="*-ec *")
| rex field=CommandLine "(?:-enc|-EncodedCommand|-ec)\s+(?P<encoded>[A-Za-z0-9+/=]+)"
| eval decoded=if(isnotnull(encoded),
    "base64 content — check Event 4104 for decoded version","no encoding found")
| eval mitre="T1059.001 - Command and Scripting Interpreter: PowerShell"
| table _time host Image CommandLine encoded decoded User mitre
| sort -_time
```

---

### Volume Shadow Copy Deletion

Detects deletion of VSS shadow copies — a critical ransomware pre-cursor indicator.
Ransomware deletes shadow copies before encrypting to prevent file recovery.
This query catches multiple deletion methods: vssadmin, wmic, wbadmin, bcdedit.

```spl
index=sysmon EventCode=1
((Image="*\\vssadmin.exe" (CommandLine="*delete*shadow*" OR CommandLine="*resize shadowstorage*"))
OR (Image="*\\wmic.exe" CommandLine="*shadowcopy*delete*")
OR (Image="*\\wbadmin.exe" CommandLine="*delete*catalog*")
OR (Image="*\\bcdedit.exe" CommandLine="*recoveryenabled*No*")
OR (Image="*\\powershell.exe" CommandLine="*ShadowCopy*Delete*"))
| eval mitre="T1490 - Inhibit System Recovery"
| eval severity="CRITICAL"
| eval note="Ransomware indicator — check for mass file rename events"
| table _time host Image CommandLine User severity mitre note
| sort -_time
```

---

### Hosts File Modified

Detects modifications to the Windows hosts file.
Attackers redirect security tool domains, update servers, or C2 check-in domains
to attacker-controlled IPs by modifying this file.

```spl
index=sysmon EventCode IN (11,2)
TargetFilename="*\\drivers\\etc\\hosts"
| eval mitre="T1565.001 - Data Manipulation: Stored Data Manipulation"
| eval severity="HIGH"
| table _time host Image TargetFilename User severity mitre
| sort -_time
```

---

### Registry Run Key Persistence

Detects new values added to Windows autorun registry keys.
Run keys execute their payload at every user logon — one of the oldest persistence mechanisms.
Filter legitimate software installers; flag anything from Temp or AppData paths.

```spl
index=sysmon EventCode=13
TargetObject IN ("*\\CurrentVersion\\Run\\*","*\\CurrentVersion\\RunOnce\\*",
                 "*\\CurrentVersion\\RunServices\\*")
NOT Image IN ("C:\\Windows\\*","C:\\Program Files\\*","C:\\Program Files (x86)\\*")
| eval mitre="T1547.001 - Boot/Logon Autostart: Registry Run Keys"
| table _time host Image TargetObject Details User mitre
| sort -_time
```

---

### LOLBin Making External Network Connection

Detects Living-Off-the-Land binaries establishing outbound connections to public IPs.
These binaries are abused for payload download and C2 communication while
bypassing application whitelisting and network inspection.

```spl
index=sysmon EventCode=3 Initiated=true
Image IN ("*\\certutil.exe","*\\bitsadmin.exe","*\\mshta.exe",
          "*\\regsvr32.exe","*\\rundll32.exe","*\\wscript.exe",
          "*\\cscript.exe","*\\msiexec.exe")
NOT DestinationIp IN ("10.*","192.168.*","172.16.*","172.17.*",
    "172.18.*","172.19.*","172.20.*","172.21.*","172.22.*","172.23.*",
    "172.24.*","172.25.*","172.26.*","172.27.*","172.28.*","172.29.*",
    "172.30.*","172.31.*","127.*","0.0.0.0")
| eval mitre="T1218 - System Binary Proxy Execution"
| eval severity="HIGH"
| table _time host Image DestinationIp DestinationPort User severity mitre
| sort -_time
```

---

### IFEO Debugger Entry Added

Detects Image File Execution Options Debugger registry entries.
Attackers use this to replace accessibility binaries (sethc.exe, utilman.exe)
with cmd.exe — providing a SYSTEM shell from the Windows lock screen.

```spl
index=sysmon EventCode=13
TargetObject="*\\Image File Execution Options\\*\\Debugger"
| rex field=TargetObject "Options\\\\(?P<target_process>[^\\\\]+)\\\\Debugger"
| eval mitre="T1546.012 - Event Triggered Execution: Image File Execution Options Injection"
| eval severity=case(
    target_process IN ("sethc.exe","utilman.exe","osk.exe","magnify.exe"),
    "CRITICAL - Lock screen backdoor",true(),"HIGH")
| table _time host target_process Details Image User severity mitre
| sort -_time
```

---

### Known Vulnerable Driver Loaded

Detects loading of kernel drivers known to be used in BYOVD attacks.
These drivers are legitimate and signed but contain exploitable vulnerabilities
used to achieve kernel code execution and disable security tools.

```spl
index=sysmon EventCode=6
ImageLoaded IN ("*\\RTCore64.sys","*\\gdrv.sys","*\\WinRing0.sys",
    "*\\WinRing0x64.sys","*\\dbutil_2_3.sys","*\\AsrDrv104.sys",
    "*\\iqvw64e.sys","*\\mhyprot2.sys","*\\HW64.sys")
| eval mitre="T1068 - Exploitation for Privilege Escalation"
| eval severity="CRITICAL"
| eval action="Isolate host — kernel-level compromise likely"
| table _time host ImageLoaded Signed Hashes severity action mitre
| sort -_time
```

---

### Kerberoasting Detection

Detects Kerberoasting by identifying RC4-encrypted service ticket requests.
Attackers request RC4 tickets (type 0x17) because they crack faster offline
even when the environment defaults to AES encryption.

```spl
index=wineventlog EventCode=4769
TicketEncryptionType=0x17
NOT ServiceName="*$"
| stats count AS requests dc(ServiceName) AS services_targeted
  BY AccountName IpAddress
| where requests > 2
| eval mitre="T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting"
| eval severity=case(services_targeted>10,"CRITICAL",
    services_targeted>3,"HIGH",true(),"MEDIUM")
| table AccountName IpAddress requests services_targeted severity mitre
| sort -requests
```

---

## Log Gap Detection

Detects hosts that have stopped sending logs — indicating logging was disabled or cleared.
A host that was active and suddenly goes silent is one of the strongest evasion indicators.

```spl
| tstats latest(_time) AS last_event WHERE index=sysmon BY host
| eval hours_silent=round((now()-last_event)/3600,1)
| eval last_seen=strftime(last_event,"%Y-%m-%d %H:%M:%S")
| where hours_silent > 2
| eval severity=case(hours_silent>24,"CRITICAL",hours_silent>6,"HIGH",true(),"MEDIUM")
| table host last_seen hours_silent severity
| sort -hours_silent
```
