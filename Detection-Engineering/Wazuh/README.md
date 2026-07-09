# Wazuh — Custom Rules & Decoders

> Production-ready Wazuh custom rules mapped to MITRE ATT&CK techniques.
> These rules extend Wazuh's built-in detection with OS-internals-level coverage
> for Linux and Windows attack techniques documented in this repository.

---

## How to Deploy These Rules

1. Copy the rule XML blocks into `/var/ossec/etc/rules/local_rules.xml`
2. Test rules before reloading: `wazuh-logtest`
3. Reload Wazuh manager: `systemctl restart wazuh-manager`
4. Verify rules loaded: `grep "rule_id" /var/ossec/logs/ossec.log`

**Rule ID ranges used:** 100001 — 100050 (local custom rules range)

Adjust IDs if they conflict with existing custom rules in your deployment.

---

## Linux Rules

### Log File Tampered or Shredded

Fires when shred is executed against log files or when auth.log is modified unexpectedly.
Wazuh File Integrity Monitoring (FIM) must be enabled for the log file rule to work.
Add `/var/log` to the FIM directories in ossec.conf to enable.

```xml
<group name="linux,log_tampering,defense_evasion,">

  <!-- Shred executed against log files -->
  <rule id="100001" level="14">
    <decoded_as>json</decoded_as>
    <field name="audit.execve.a0">shred</field>
    <field name="audit.execve.a1">/var/log</field>
    <description>Shred command executed against log files — evidence destruction</description>
    <mitre>
      <id>T1070.004</id>
    </mitre>
    <group>pci_dss_10.5,gdpr_IV_30.1.d,</group>
  </rule>

  <!-- Auth log file modified via FIM -->
  <rule id="100002" level="12">
    <if_group>syscheck</if_group>
    <field name="file">/var/log/auth.log</field>
    <description>Auth log file was modified — possible tampering or clearing</description>
    <mitre>
      <id>T1070.002</id>
    </mitre>
  </rule>

  <!-- Auth log emptied (size dropped to near zero) -->
  <rule id="100003" level="15">
    <if_sid>100002</if_sid>
    <field name="size_after">^[0-9]{1,3}$</field>
    <description>Auth log file size dropped to near zero — likely cleared by attacker</description>
    <mitre>
      <id>T1070.002</id>
    </mitre>
  </rule>

</group>
```

---

### rsyslog Daemon Stopped

Fires when the rsyslog service is stopped.
After this event, no new log entries are written to /var/log/*.
Wazuh itself continues logging via its own agent — providing coverage even after rsyslog stops.

```xml
<group name="linux,defense_evasion,impair_defenses,">

  <rule id="100004" level="13">
    <if_group>syslog</if_group>
    <match>rsyslog.*stopped|rsyslog.*terminating|rsyslog.*exiting</match>
    <description>rsyslog logging daemon stopped — system logging disabled</description>
    <mitre>
      <id>T1562.001</id>
    </mitre>
    <group>gdpr_IV_30.1.d,pci_dss_10.6.1,</group>
  </rule>

  <!-- auditd stopped -->
  <rule id="100005" level="15">
    <if_group>syslog</if_group>
    <match>auditd.*stopped|auditd.*killed|audit.*daemon.*exit</match>
    <description>auditd kernel audit daemon stopped — audit logging disabled</description>
    <mitre>
      <id>T1562.001</id>
    </mitre>
  </rule>

</group>
```

---

### SSH Brute Force Detection

Wazuh has built-in SSH brute force rules (5712, 5720).
These custom rules extend coverage with additional thresholds and MITRE tagging.

```xml
<group name="linux,authentication,brute_force,">

  <!-- SSH brute force — high volume -->
  <rule id="100006" level="12" frequency="15" timeframe="120">
    <if_matched_sid>5716</if_matched_sid>
    <same_source_ip/>
    <description>SSH brute force attack — 15+ failures in 2 minutes from same IP</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
    <group>pci_dss_11.4,gdpr_IV_35.7.d,</group>
  </rule>

  <!-- SSH brute force succeeded after failures -->
  <rule id="100007" level="15">
    <if_matched_sid>100006</if_matched_sid>
    <if_sid>5715</if_sid>
    <same_source_ip/>
    <description>CRITICAL — SSH brute force succeeded. Failed attempts followed by successful login</description>
    <mitre>
      <id>T1110.001</id>
      <id>T1078</id>
    </mitre>
  </rule>

  <!-- SSH login from new country (requires GeoIP) -->
  <rule id="100008" level="10">
    <if_sid>5715</if_sid>
    <field name="geoip.country_name">\.+</field>
    <description>SSH successful login from $(geoip.country_name) — verify if expected</description>
    <mitre>
      <id>T1078</id>
    </mitre>
  </rule>

</group>
```

---

### New User Account Created

Fires when a new local user account is created on a Linux system.
Attackers create backdoor accounts for persistent authenticated access.

```xml
<group name="linux,account_management,persistence,">

  <rule id="100009" level="10">
    <if_group>syslog</if_group>
    <match>new user|useradd|adduser</match>
    <description>New local user account created on Linux system</description>
    <mitre>
      <id>T1136.001</id>
    </mitre>
    <group>pci_dss_8.1.2,gdpr_IV_32.2,</group>
  </rule>

  <!-- User added to sudo group -->
  <rule id="100010" level="12">
    <if_group>syslog</if_group>
    <match>added.*sudo|usermod.*sudo|gpasswd.*sudo</match>
    <description>User added to sudo group — privilege escalation risk</description>
    <mitre>
      <id>T1098</id>
      <id>T1548.003</id>
    </mitre>
  </rule>

</group>
```

---

### Sudoers File Modified

Fires when /etc/sudoers or files in /etc/sudoers.d/ are modified.
Attackers modify sudoers to grant NOPASSWD root access to compromised accounts.

```xml
<group name="linux,privilege_escalation,persistence,">

  <rule id="100011" level="13">
    <if_group>syscheck</if_group>
    <field name="file">/etc/sudoers</field>
    <description>Sudoers file modified — review for unauthorized privilege grants</description>
    <mitre>
      <id>T1548.003</id>
    </mitre>
  </rule>

  <rule id="100012" level="13">
    <if_group>syscheck</if_group>
    <field name="file">/etc/sudoers.d/</field>
    <description>File added or modified in /etc/sudoers.d/ — review for unauthorized grants</description>
    <mitre>
      <id>T1548.003</id>
    </mitre>
  </rule>

</group>
```

---

### SSH Authorized Keys Modified

Fires when authorized_keys files are modified.
Adding a public key grants permanent passwordless SSH access independent of password changes.

```xml
<group name="linux,persistence,credential_access,">

  <rule id="100013" level="12">
    <if_group>syscheck</if_group>
    <field name="file">authorized_keys</field>
    <description>SSH authorized_keys file modified — verify key addition is authorized</description>
    <mitre>
      <id>T1098.004</id>
    </mitre>
    <group>pci_dss_8.1,gdpr_IV_32.2,</group>
  </rule>

</group>
```

---

### Cron Job Added

Fires when new cron job files are created in system cron directories.
Attacker cron jobs frequently contain network callbacks or paths to /tmp.

```xml
<group name="linux,persistence,scheduled_job,">

  <rule id="100014" level="10">
    <if_group>syscheck</if_group>
    <field name="file">/etc/cron.d/</field>
    <description>New file added to /etc/cron.d/ — review for malicious scheduled job</description>
    <mitre>
      <id>T1053.003</id>
    </mitre>
  </rule>

  <rule id="100015" level="10">
    <if_group>syscheck</if_group>
    <field name="file">/var/spool/cron/</field>
    <description>User crontab modified — review scheduled job changes</description>
    <mitre>
      <id>T1053.003</id>
    </mitre>
  </rule>

</group>
```

---

### Systemd Service Created

Fires when new .service unit files appear in systemd directories.
Malicious service units execute at boot as any user including root.

```xml
<group name="linux,persistence,systemd,">

  <rule id="100016" level="11">
    <if_group>syscheck</if_group>
    <field name="file">/etc/systemd/system/</field>
    <match>\.service$</match>
    <description>New systemd service unit file created — review for malicious persistence</description>
    <mitre>
      <id>T1543.002</id>
    </mitre>
  </rule>

</group>
```

---

### LD_PRELOAD Manipulation

Fires when /etc/ld.so.preload is created or modified.
This file should not exist on clean systems. Any content preloads a library into every process.

```xml
<group name="linux,defense_evasion,persistence,">

  <rule id="100017" level="15">
    <if_group>syscheck</if_group>
    <field name="file">/etc/ld.so.preload</field>
    <description>CRITICAL — /etc/ld.so.preload modified. Library preloaded into ALL processes</description>
    <mitre>
      <id>T1574.006</id>
    </mitre>
  </rule>

</group>
```

---

### Kernel Module Loaded

Fires when a kernel module is loaded via auditd syscall monitoring.
Requires auditd rules for init_module and finit_module syscalls.

```xml
<group name="linux,persistence,rootkit,">

  <rule id="100018" level="12">
    <decoded_as>auditd-generic</decoded_as>
    <field name="audit.syscall">init_module|finit_module</field>
    <description>Kernel module loaded — verify against expected module list</description>
    <mitre>
      <id>T1547.006</id>
    </mitre>
  </rule>

</group>
```

---

## Windows Rules

### Windows Event Log Cleared

Fires when Security or System event logs are cleared.
Event 1102 = Security log cleared. Event 104 = System log cleared.
These are generated before the clear and cannot be suppressed by the attacker.

```xml
<group name="windows,defense_evasion,log_tampering,">

  <rule id="100020" level="14">
    <if_group>windows</if_group>
    <field name="win.system.eventID">1102</field>
    <description>Windows Security event log cleared by $(win.eventdata.subjectUserName)</description>
    <mitre>
      <id>T1070.001</id>
    </mitre>
    <group>pci_dss_10.5.5,gdpr_IV_30.1.d,</group>
  </rule>

  <rule id="100021" level="14">
    <if_group>windows</if_group>
    <field name="win.system.eventID">104</field>
    <description>Windows System event log cleared</description>
    <mitre>
      <id>T1070.001</id>
    </mitre>
  </rule>

  <!-- Audit policy changed -->
  <rule id="100022" level="13">
    <if_group>windows</if_group>
    <field name="win.system.eventID">4719</field>
    <description>Windows audit policy changed — logging may be disabled</description>
    <mitre>
      <id>T1562.002</id>
    </mitre>
  </rule>

</group>
```

---

### New Windows Service Installed

Fires on Event ID 7045 — new service installation.
Filters for services with executable paths outside Windows system directories.

```xml
<group name="windows,persistence,service_creation,">

  <rule id="100023" level="10">
    <if_group>windows</if_group>
    <field name="win.system.eventID">7045</field>
    <description>New Windows service installed: $(win.eventdata.serviceName)</description>
    <mitre>
      <id>T1543.003</id>
    </mitre>
    <group>pci_dss_11.4,</group>
  </rule>

  <!-- Service from suspicious path -->
  <rule id="100024" level="14">
    <if_sid>100023</if_sid>
    <field name="win.eventdata.imageFile" negate="yes">(?i)C:\\Windows\\|C:\\Program Files</field>
    <description>New service installed from non-standard path: $(win.eventdata.imageFile)</description>
    <mitre>
      <id>T1543.003</id>
    </mitre>
  </rule>

</group>
```

---

### Scheduled Task Created

Fires on Event ID 4698 — scheduled task creation.
Windows scheduled tasks provide persistent execution at any trigger condition.

```xml
<group name="windows,persistence,scheduled_task,">

  <rule id="100025" level="10">
    <if_group>windows</if_group>
    <field name="win.system.eventID">4698</field>
    <description>Scheduled task created: $(win.eventdata.taskName) by $(win.eventdata.subjectUserName)</description>
    <mitre>
      <id>T1053.005</id>
    </mitre>
  </rule>

  <rule id="100026" level="14">
    <if_sid>100025</if_sid>
    <field name="win.eventdata.taskContentCommand">(?i)\\Temp\\|\\AppData\\|\\Public\\|\\ProgramData\\</field>
    <description>Scheduled task created with suspicious executable path</description>
    <mitre>
      <id>T1053.005</id>
    </mitre>
  </rule>

</group>
```

---

### User Account Created

Fires on Event ID 4720 — local Windows user account creation.
Attackers create backdoor accounts for persistent access to compromised systems.

```xml
<group name="windows,account_management,persistence,">

  <rule id="100027" level="10">
    <if_group>windows</if_group>
    <field name="win.system.eventID">4720</field>
    <description>Local Windows user account created: $(win.eventdata.targetUserName)</description>
    <mitre>
      <id>T1136.001</id>
    </mitre>
    <group>pci_dss_8.1.2,gdpr_IV_32.2,</group>
  </rule>

  <!-- User added to Administrators group -->
  <rule id="100028" level="13">
    <if_group>windows</if_group>
    <field name="win.system.eventID">4732</field>
    <field name="win.eventdata.targetUserName" type="pcre2">(?i)administrators</field>
    <description>User $(win.eventdata.memberName) added to local Administrators group</description>
    <mitre>
      <id>T1098</id>
    </mitre>
  </rule>

</group>
```

---

### Windows Hosts File Modified

Fires when the Windows hosts file is modified via FIM.
Attackers redirect security tool domains and C2 check-in endpoints.

```xml
<group name="windows,defense_evasion,">

  <rule id="100029" level="12">
    <if_group>syscheck</if_group>
    <field name="file">drivers\\etc\\hosts</field>
    <description>Windows hosts file modified — check for unauthorized DNS redirections</description>
    <mitre>
      <id>T1565.001</id>
    </mitre>
  </rule>

</group>
```

---

### PowerShell Encoded Command

Fires when PowerShell is launched with base64 encoded command arguments.
Encoded commands are used to bypass script logging and content inspection.

```xml
<group name="windows,execution,defense_evasion,">

  <rule id="100030" level="10">
    <if_group>windows</if_group>
    <field name="win.system.eventID">4688</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)powershell.*(-enc|-EncodedCommand|-ec)\s+[A-Za-z0-9+/=]{20,}</field>
    <description>PowerShell launched with encoded command — possible obfuscation</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>

</group>
```

---

### Volume Shadow Copy Deletion

Fires when shadow copy deletion commands are executed.
This is a critical ransomware pre-cursor indicator.

```xml
<group name="windows,impact,ransomware,">

  <rule id="100031" level="15">
    <if_group>windows</if_group>
    <field name="win.system.eventID">4688</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(vssadmin.*delete.*shadow|wmic.*shadowcopy.*delete|wbadmin.*delete.*catalog|bcdedit.*recoveryenabled.*no)</field>
    <description>CRITICAL — Volume shadow copy deletion detected. Possible ransomware activity</description>
    <mitre>
      <id>T1490</id>
    </mitre>
    <group>pci_dss_10.6.1,</group>
  </rule>

</group>
```

---

## ossec.conf FIM Configuration

Add these directories to your ossec.conf to enable File Integrity Monitoring
for the paths referenced by rules above.

```xml
<!-- Add inside <syscheck> block in /var/ossec/etc/ossec.conf -->

<!-- Linux critical paths -->
<directories check_all="yes" realtime="yes" report_changes="yes">/etc/passwd,/etc/shadow,/etc/group</directories>
<directories check_all="yes" realtime="yes" report_changes="yes">/etc/sudoers,/etc/sudoers.d</directories>
<directories check_all="yes" realtime="yes" report_changes="yes">/etc/ssh/sshd_config</directories>
<directories check_all="yes" realtime="yes" report_changes="yes">/etc/cron.d,/etc/crontab</directories>
<directories check_all="yes" realtime="yes" report_changes="yes">/etc/systemd/system</directories>
<directories check_all="yes" realtime="yes">/var/log</directories>
<directories check_all="yes" realtime="yes">/bin,/sbin,/usr/bin,/usr/sbin</directories>

<!-- Windows critical paths -->
<windows_registry>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</windows_registry>
<windows_registry>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce</windows_registry>
<windows_registry>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services</windows_registry>
<windows_registry>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon</windows_registry>
<windows_registry>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options</windows_registry>
```

---

## Deployment Checklist

Before deploying to production:

- [ ] Test each rule with `wazuh-logtest` using sample log entries
- [ ] Verify rule IDs 100001-100031 don't conflict with existing custom rules
- [ ] Enable FIM on required directories in ossec.conf
- [ ] Enable auditd rules on Linux endpoints for kernel-level coverage
- [ ] Configure active response for highest-severity rules (level 15)
- [ ] Test alert routing to ticketing system or SOAR platform
- [ ] Document baseline false positives for your environment
