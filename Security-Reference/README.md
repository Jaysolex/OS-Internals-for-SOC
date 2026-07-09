# Security Reference

> Operational reference material — MITRE mappings, artifact cheat sheets, critical event IDs, and investigation command libraries. Designed to be used during live investigations, not read once and forgotten.

---

## Linux Critical Artifact Locations

| Artifact | Path | Forensic Value |
|----------|------|----------------|
| Authentication events | `/var/log/auth.log` | SSH, sudo, PAM, su — who authenticated and how |
| General system events | `/var/log/syslog` | Service starts/stops, kernel messages, application events |
| Kernel messages | `/var/log/kern.log` | Driver errors, hardware failures, kernel panics |
| Cron execution | `/var/log/cron.log` | Scheduled job execution — persistence validation |
| Login history | `/var/log/wtmp` | All login/logout sessions — binary, read with `last` |
| Failed logins | `/var/log/btmp` | Failed authentication attempts — binary, read with `lastb` |
| Last login per user | `/var/log/lastlog` | Sparse binary — `lastlog` command |
| Audit log | `/var/log/audit/audit.log` | Syscall-level activity — file access, process exec, network |
| systemd journal | `/var/log/journal/` | Binary journal — `journalctl` |
| User accounts | `/etc/passwd` | UID, GID, home directory, shell |
| Password hashes | `/etc/shadow` | Hashed passwords — root only |
| Group membership | `/etc/group` | Group definitions |
| Sudo rules | `/etc/sudoers` + `/etc/sudoers.d/` | Who can run what as root |
| SSH daemon config | `/etc/ssh/sshd_config` | Authentication settings |
| SSH authorized keys | `~/.ssh/authorized_keys` | Keys permitted to authenticate |
| Crontabs (system) | `/etc/crontab`, `/etc/cron.d/` | System-level scheduled jobs |
| Crontabs (user) | `/var/spool/cron/crontabs/<user>` | Per-user scheduled jobs |
| Systemd units | `/etc/systemd/system/` | Persistence via service units |
| rc.local | `/etc/rc.local` | Legacy startup persistence |
| Profile scripts | `/etc/profile.d/` | Login-time script execution |
| Bash history | `~/.bash_history` | User command history |
| Hosts file | `/etc/hosts` | Static DNS override |
| Environment | `/etc/environment` | System-wide environment variables |
| LD_PRELOAD | `/etc/ld.so.preload` | Library preload — should be empty |
| Kernel modules | `/proc/modules`, `/sys/module/`, `lsmod` | Loaded kernel modules |
| Running processes | `/proc/<pid>/` | Live process state |
| Network connections | `/proc/net/tcp`, `/proc/net/tcp6` | Kernel-level network state |
| Temp staging | `/tmp/`, `/var/tmp/`, `/dev/shm/` | Attacker staging locations |
| SUID binaries | `find / -perm -4000` | Privilege escalation vectors |

---

## Windows Critical Artifact Locations

| Artifact | Path | Forensic Value |
|----------|------|----------------|
| Security Event Log | `C:\Windows\System32\winevt\Logs\Security.evtx` | Auth, privilege, object access |
| System Event Log | `C:\Windows\System32\winevt\Logs\System.evtx` | Services, drivers, hardware |
| PowerShell Log | `...\Microsoft-Windows-PowerShell%4Operational.evtx` | Script block content |
| Sysmon Log | `...\Microsoft-Windows-Sysmon%4Operational.evtx` | Process, network, file, registry |
| WMI Log | `...\Microsoft-Windows-WMI-Activity%4Operational.evtx` | WMI execution |
| Task Scheduler Log | `...\Microsoft-Windows-TaskScheduler%4Operational.evtx` | Task creation/execution |
| Prefetch | `C:\Windows\Prefetch\*.pf` | Program executed, when, how often |
| Amcache | `C:\Windows\AppCompat\Programs\Amcache.hve` | Application execution with hash |
| Shimcache | `SYSTEM` hive — `ControlSet\Control\SessionManager\AppCompatCache` | Execution history |
| SRUM | `C:\Windows\System32\sru\SRUDB.dat` | Per-app network/CPU usage 30-60 days |
| LNK files | `%AppData%\Roaming\Microsoft\Windows\Recent\` | File access — proves user awareness |
| Shellbags | `NTUSER.DAT` + `UsrClass.dat` | Folder navigation — proves folder access |
| Jump Lists | `%AppData%\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` | Recent files per app |
| MFT | `C:\$MFT` | Every file — timestamps, attributes, even deleted |
| USN Journal | `C:\$Extend\$UsnJrnl` | File system change log |
| SAM hive | `C:\Windows\System32\config\SAM` | Local user accounts and NTLM hashes |
| SYSTEM hive | `C:\Windows\System32\config\SYSTEM` | Services, boot config, timezone |
| SOFTWARE hive | `C:\Windows\System32\config\SOFTWARE` | Installed apps, run keys |
| SECURITY hive | `C:\Windows\System32\config\SECURITY` | LSA secrets, cached credentials |
| NTUSER.DAT | `C:\Users\<user>\NTUSER.DAT` | User-specific registry hive |
| Scheduled Tasks | `C:\Windows\System32\Tasks\` | Task XML definitions |
| WMI Repository | `C:\Windows\System32\wbem\Repository\` | WMI persistent subscriptions |
| Startup folder | `%AppData%\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\` | User persistence |
| System Startup | `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\` | System-wide persistence |
| Recycle Bin | `C:\$Recycle.Bin\<SID>\` | Deleted files — original path, deletion time |
| Shadow Copies | `C:\System Volume Information\` | Point-in-time volume snapshots |
| Hosts file | `C:\Windows\System32\drivers\etc\hosts` | Static DNS override |
| PSReadLine history | `%AppData%\Local\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` | PS command history |
| Pagefile | `C:\pagefile.sys` | Virtual memory — process fragments |
| Hibernation file | `C:\hiberfil.sys` | Compressed RAM snapshot |

---

## Windows Critical Security Event IDs

### Authentication & Account Events

| Event ID | Log | Description | Detection Use |
|----------|-----|-------------|---------------|
| 4624 | Security | Successful logon | Lateral movement, after-hours access |
| 4625 | Security | Failed logon | Brute force, password spray |
| 4627 | Security | Group membership info | Admin group usage |
| 4634 | Security | Logoff | Session duration analysis |
| 4647 | Security | User-initiated logoff | — |
| 4648 | Security | Explicit credential use | Pass-the-hash, runas, lateral movement |
| 4672 | Security | Special privileges assigned to new logon | Admin/SYSTEM logon |
| 4720 | Security | User account created | Backdoor account |
| 4722 | Security | User account enabled | Previously disabled backdoor activated |
| 4724 | Security | Password reset attempt | Credential manipulation |
| 4726 | Security | User account deleted | Cleanup / anti-forensics |
| 4728 | Security | Member added to global security group | Privilege escalation |
| 4732 | Security | Member added to local security group | Local admin group add |
| 4738 | Security | User account changed | Account manipulation |
| 4740 | Security | User account locked out | Brute force, account lockout |
| 4756 | Security | Member added to universal security group | Domain-wide privilege escalation |
| 4771 | Security | Kerberos pre-auth failed | Kerberoasting, AS-REP roasting |
| 4776 | Security | NTLM auth attempt | NTLM relay, pass-the-hash |
| 4798 | Security | User's local group membership queried | Domain recon |
| 4799 | Security | Security-enabled local group queried | Domain recon |

### Logon Types Reference

| Type | Name | Description | Attack Scenario |
|------|------|-------------|----------------|
| 2 | Interactive | Physical keyboard logon | — |
| 3 | Network | SMB, net use | Lateral movement via SMB |
| 4 | Batch | Scheduled task | Persistence execution |
| 5 | Service | Service startup | Malicious service |
| 7 | Unlock | Workstation unlock | — |
| 8 | NetworkCleartext | Basic auth with cleartext | Credential exposure |
| 9 | NewCredentials | RunAs with /netonly | Pass-the-hash alternative |
| 10 | RemoteInteractive | RDP | RDP lateral movement |
| 11 | CachedInteractive | Cached domain creds | Offline attack |

### Process & Execution Events

| Event ID | Log | Description | Detection Use |
|----------|-----|-------------|---------------|
| 4688 | Security | Process created | Command execution (requires audit policy) |
| 4689 | Security | Process exited | Process lifetime |
| 1 | Sysmon | Process created | Full cmdline, hash, parent process |
| 3 | Sysmon | Network connection | C2 communication, lateral movement |
| 7 | Sysmon | Image loaded | DLL injection, side-loading |
| 8 | Sysmon | CreateRemoteThread | Process injection |
| 10 | Sysmon | ProcessAccess | LSASS dumping (OpenProcess on lsass) |
| 11 | Sysmon | FileCreate | File dropped to disk |
| 12/13/14 | Sysmon | Registry events | Registry persistence, modification |
| 15 | Sysmon | FileCreateStreamHash | ADS creation |
| 17/18 | Sysmon | Pipe created/connected | Named pipe — lateral movement, C2 |
| 19/20/21 | Sysmon | WMI events | WMI subscription persistence |
| 22 | Sysmon | DNS query | C2 domain resolution |
| 23 | Sysmon | FileDelete | Evidence of file deletion |
| 25 | Sysmon | ProcessTampering | Process hollowing detection |
| 4104 | PowerShell | Script block logged | Script content — deobfuscated |
| 4103 | PowerShell | Module logging | Cmdlet invocations |
| 400/403 | PowerShell | Engine start/stop | PowerShell session |

### Service & Persistence Events

| Event ID | Log | Description | Detection Use |
|----------|-----|-------------|---------------|
| 4697 | Security | Service installed | Malicious service creation |
| 7045 | System | New service installed | Lateral movement, persistence |
| 7034 | System | Service crashed unexpectedly | Exploit side-effect |
| 7036 | System | Service state changed | Service started/stopped |
| 4698 | Security | Scheduled task created | Persistence |
| 4699 | Security | Scheduled task deleted | Cleanup |
| 4700 | Security | Scheduled task enabled | Dormant persistence activated |
| 4702 | Security | Scheduled task updated | Persistence modification |

### Defense Evasion Events

| Event ID | Log | Description | Detection Use |
|----------|-----|-------------|---------------|
| 1102 | Security | Audit log cleared | Log tampering — T1070.001 |
| 104 | System | System log cleared | Log tampering |
| 4719 | Security | System audit policy changed | Attacker disabling logging |
| 4902 | Security | Per-user audit policy table created | — |
| 4906 | Security | CrashOnAuditFail changed | Audit bypass |

---

## Linux Audit Rules — Production Deployment

```bash
# /etc/audit/rules.d/security.rules
# Deploy with: auditctl -R /etc/audit/rules.d/security.rules

# Delete all existing rules
-D

# Buffer size
-b 8192

# Failure mode (1=log, 2=panic)
-f 1

# ============================================================
# IDENTITY AND AUTHENTICATION
# ============================================================
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# SSH
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /root/.ssh -p wa -k ssh_keys
-a always,exit -F arch=b64 -S open -F dir=/home -F name=authorized_keys -F perm=wa -k ssh_authorized_keys

# PAM
-w /etc/pam.d -p wa -k pam_config
-w /lib/security -p wa -k pam_modules
-w /etc/security -p wa -k pam_config

# Sudo
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d -p wa -k sudoers

# ============================================================
# PRIVILEGE ESCALATION
# ============================================================
-a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -k privilege_abuse
-a always,exit -F arch=b32 -S setuid -S setgid -S setreuid -S setregid -k privilege_abuse

# SUID/SGID execution
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid!=0 -k privilege_escalation

# ============================================================
# PROCESS EXECUTION
# ============================================================
-a always,exit -F arch=b64 -S execve -k process_execution
-a always,exit -F arch=b32 -S execve -k process_execution

# ============================================================
# NETWORK CONFIGURATION CHANGES
# ============================================================
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network_modification
-w /etc/hosts -p wa -k hosts_file
-w /etc/resolv.conf -p wa -k dns_config
-w /etc/network -p wa -k network_config
-w /etc/sysconfig/network -p wa -k network_config

# ============================================================
# LOG TAMPERING
# ============================================================
-w /var/log/auth.log -p wa -k log_tampering
-w /var/log/syslog -p wa -k log_tampering
-w /var/log/audit/audit.log -p wa -k log_tampering
-w /var/log -p wa -k log_tampering

# Shred command
-w /usr/bin/shred -p x -k log_tampering

# ============================================================
# KERNEL MODULE LOADING
# ============================================================
-w /sbin/insmod -p x -k kernel_module
-w /sbin/modprobe -p x -k kernel_module
-w /sbin/rmmod -p x -k kernel_module
-a always,exit -F arch=b64 -S init_module -S delete_module -k kernel_module

# ============================================================
# PERSISTENCE MECHANISMS
# ============================================================
-w /etc/cron.d -p wa -k cron_persistence
-w /etc/cron.daily -p wa -k cron_persistence
-w /etc/cron.weekly -p wa -k cron_persistence
-w /etc/cron.monthly -p wa -k cron_persistence
-w /etc/crontab -p wa -k cron_persistence
-w /var/spool/cron -p wa -k cron_persistence
-w /etc/systemd/system -p wa -k systemd_persistence
-w /etc/rc.local -p wa -k startup_persistence
-w /etc/profile.d -p wa -k startup_persistence
-w /etc/ld.so.preload -p wa -k ld_preload

# ============================================================
# SUSPICIOUS DIRECTORIES
# ============================================================
-w /tmp -p x -k tmp_execution
-w /var/tmp -p x -k tmp_execution
-w /dev/shm -p rwxa -k shm_activity

# ============================================================
# MAKE RULES IMMUTABLE (comment out during tuning)
# -e 2
```

---

## Sysmon Configuration Template

```xml
<Sysmon schemaversion="4.90">
  <HashAlgorithms>SHA256,IMPHASH</HashAlgorithms>
  <CheckRevocation/>
  
  <EventFiltering>

    <!-- Event ID 1: Process Creation -->
    <RuleGroup name="ProcessCreate" groupRelation="or">
      <ProcessCreate onmatch="include">
        <!-- Living-off-the-land binaries -->
        <Image condition="is">C:\Windows\System32\cmd.exe</Image>
        <Image condition="is">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Image>
        <Image condition="is">C:\Windows\System32\mshta.exe</Image>
        <Image condition="is">C:\Windows\System32\regsvr32.exe</Image>
        <Image condition="is">C:\Windows\System32\rundll32.exe</Image>
        <Image condition="is">C:\Windows\System32\certutil.exe</Image>
        <Image condition="is">C:\Windows\System32\bitsadmin.exe</Image>
        <Image condition="is">C:\Windows\System32\wscript.exe</Image>
        <Image condition="is">C:\Windows\System32\cscript.exe</Image>
        <Image condition="is">C:\Windows\System32\wmic.exe</Image>
        <Image condition="is">C:\Windows\System32\msiexec.exe</Image>
        <Image condition="is">C:\Windows\System32\sc.exe</Image>
        <Image condition="is">C:\Windows\System32\schtasks.exe</Image>
        <Image condition="is">C:\Windows\System32\net.exe</Image>
        <Image condition="is">C:\Windows\System32\reg.exe</Image>
        <Image condition="is">C:\Windows\System32\whoami.exe</Image>
        <Image condition="is">C:\Windows\System32\nltest.exe</Image>
        <!-- Anything in temp or user-writable locations -->
        <Image condition="contains">\AppData\</Image>
        <Image condition="contains">\Temp\</Image>
        <Image condition="contains">\ProgramData\</Image>
        <Image condition="contains">\Users\Public\</Image>
      </ProcessCreate>
    </RuleGroup>

    <!-- Event ID 3: Network Connection -->
    <RuleGroup name="NetworkConnect" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- PowerShell making network connections -->
        <Image condition="is">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Image>
        <!-- Living off the land with network access -->
        <Image condition="is">C:\Windows\System32\certutil.exe</Image>
        <Image condition="is">C:\Windows\System32\bitsadmin.exe</Image>
        <Image condition="is">C:\Windows\System32\mshta.exe</Image>
        <Image condition="is">C:\Windows\System32\regsvr32.exe</Image>
        <!-- Non-standard ports -->
        <DestinationPort condition="is">4444</DestinationPort>
        <DestinationPort condition="is">1337</DestinationPort>
        <DestinationPort condition="is">8080</DestinationPort>
      </NetworkConnect>
    </RuleGroup>

    <!-- Event ID 7: Image Loaded (DLL) -->
    <RuleGroup name="ImageLoad" groupRelation="or">
      <ImageLoad onmatch="include">
        <!-- Unsigned DLLs loaded by system processes -->
        <Signed condition="is">false</Signed>
      </ImageLoad>
      <ImageLoad onmatch="exclude">
        <!-- Reduce noise from known unsigned but legitimate -->
        <ImageLoaded condition="contains">\AppData\Local\Temp\</ImageLoaded>
      </ImageLoad>
    </RuleGroup>

    <!-- Event ID 10: Process Access (LSASS dumping) -->
    <RuleGroup name="ProcessAccess" groupRelation="or">
      <ProcessAccess onmatch="include">
        <TargetImage condition="is">C:\Windows\system32\lsass.exe</TargetImage>
      </ProcessAccess>
    </RuleGroup>

    <!-- Event ID 11: File Create -->
    <RuleGroup name="FileCreate" groupRelation="or">
      <FileCreate onmatch="include">
        <!-- Executables created in user-writable locations -->
        <TargetFilename condition="contains">\AppData\</TargetFilename>
        <TargetFilename condition="contains">\Temp\</TargetFilename>
        <TargetFilename condition="contains">\ProgramData\</TargetFilename>
        <TargetFilename condition="end with">.exe</TargetFilename>
        <TargetFilename condition="end with">.dll</TargetFilename>
        <TargetFilename condition="end with">.ps1</TargetFilename>
        <TargetFilename condition="end with">.bat</TargetFilename>
        <TargetFilename condition="end with">.vbs</TargetFilename>
      </FileCreate>
    </RuleGroup>

    <!-- Event IDs 12/13/14: Registry -->
    <RuleGroup name="RegistryEvent" groupRelation="or">
      <RegistryEvent onmatch="include">
        <!-- Autorun keys -->
        <TargetObject condition="contains">CurrentVersion\Run</TargetObject>
        <TargetObject condition="contains">CurrentVersion\RunOnce</TargetObject>
        <TargetObject condition="contains">Winlogon</TargetObject>
        <TargetObject condition="contains">AppInit_DLLs</TargetObject>
        <TargetObject condition="contains">Image File Execution Options</TargetObject>
        <!-- Service installation -->
        <TargetObject condition="contains">SYSTEM\CurrentControlSet\Services</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <!-- Event IDs 19/20/21: WMI -->
    <RuleGroup name="WmiEvent" groupRelation="or">
      <WmiEvent onmatch="include">
        <Operation condition="is">Created</Operation>
      </WmiEvent>
    </RuleGroup>

    <!-- Event ID 22: DNS Query -->
    <RuleGroup name="DnsQuery" groupRelation="or">
      <DnsQuery onmatch="include">
        <!-- All DNS queries from PowerShell, mshta, etc. -->
        <Image condition="is">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Image>
        <Image condition="is">C:\Windows\System32\mshta.exe</Image>
        <Image condition="is">C:\Windows\System32\wscript.exe</Image>
        <Image condition="is">C:\Windows\System32\cscript.exe</Image>
      </DnsQuery>
    </RuleGroup>

  </EventFiltering>
</Sysmon>
```

---

## Living-Off-the-Land Binaries (LOLBins)

Legitimate Windows binaries abused for execution, download, persistence, and lateral movement. Presence alone is not suspicious — context and parent process are critical.

| Binary | Abuse Technique | MITRE |
|--------|----------------|-------|
| `powershell.exe` | Download, execution, encoded commands | T1059.001 |
| `cmd.exe` | Command execution, persistence | T1059.003 |
| `mshta.exe` | Execute HTA files, remote scripts | T1218.005 |
| `regsvr32.exe` | Execute COM DLLs, bypass AppLocker (Squiblydoo) | T1218.010 |
| `rundll32.exe` | Execute DLL exports, bypass execution controls | T1218.011 |
| `certutil.exe` | Download files, base64 decode | T1140, T1105 |
| `bitsadmin.exe` | Background file download | T1197 |
| `wmic.exe` | Process creation, lateral movement, recon | T1047 |
| `msiexec.exe` | Execute MSI payloads from URL | T1218.007 |
| `cscript.exe` / `wscript.exe` | Execute VBScript, JScript payloads | T1059.005 |
| `odbcconf.exe` | Execute DLLs via ODBC config | T1218.008 |
| `ieexec.exe` | Download and execute | T1218 |
| `installutil.exe` | .NET assembly execution, bypass AppLocker | T1218.004 |
| `msbuild.exe` | Inline C# execution | T1127.001 |
| `cmstp.exe` | Execute INF files, bypass UAC | T1218.003 |
| `forfiles.exe` | Execute commands in file context | T1202 |
| `pcalua.exe` | Execute commands via compatibility layer | T1202 |
| `appsyncpublishingserver.exe` | Script execution | T1216 |
| `diskshadow.exe` | VSS shadow copy management, code exec | T1490 |
| `dnscmd.exe` | DLL injection via DNS server plugin | T1574 |
| `esentutl.exe` | File copy, ADS manipulation | T1039 |
| `expand.exe` | File decompression | T1140 |
| `extrac32.exe` | Extract files from CAB | T1140 |
| `findstr.exe` | Search files — recon, ADS access | T1083 |
| `ftp.exe` | File download/upload | T1105 |
| `makecab.exe` | Archive files for exfiltration | T1560 |
| `mavinject.exe` | DLL injection into running process | T1055 |
| `nltest.exe` | Domain controller enumeration | T1018 |
| `ntdsutil.exe` | AD database dump | T1003.003 |
| `pcwrun.exe` | Execute programs via compatibility | T1202 |
| `replace.exe` | File replacement | T1036 |
| `rpcping.exe` | RPC connectivity check | T1018 |
| `runscripthelper.exe` | Script execution | T1216 |
| `sfc.exe` | System file checker abuse | T1036 |
| `syncappvpublishingserver.exe` | Script execution | T1216 |
| `tttracer.exe` | Execute arbitrary processes | T1218 |
| `wab.exe` | Execute COM objects | T1218 |
| `xwizard.exe` | DLL execution | T1218 |

---

## MITRE ATT&CK Quick Reference — OS Internals Aligned

### Execution (TA0002)
| Sub-technique | ID | OS Component |
|--------------|-----|--------------|
| PowerShell | T1059.001 | Windows process execution |
| Windows Command Shell | T1059.003 | Windows process execution |
| Unix Shell | T1059.004 | Linux process execution |
| Python/Perl/Ruby | T1059.006 | Scripting runtimes |
| Scheduled Task | T1053.005 | Windows Task Scheduler |
| Cron | T1053.003 | Linux cron daemon |
| Systemd Timer | T1053.006 | Linux systemd |
| WMI | T1047 | Windows WMI subsystem |
| Services | T1569.002 | Windows SCM |

### Persistence (TA0003)
| Sub-technique | ID | OS Component |
|--------------|-----|--------------|
| Registry Run Keys | T1547.001 | Windows Registry |
| Logon Script | T1037.001 | Windows logon process |
| Startup Folder | T1547.001 | Windows shell |
| Systemd Service | T1543.002 | Linux systemd |
| SysV Service | T1543.002 | Linux init |
| Cron Job | T1053.003 | Linux cron |
| SSH Authorized Keys | T1098.004 | Linux SSH |
| WMI Subscription | T1546.003 | Windows WMI |
| COM Hijacking | T1546.015 | Windows COM |
| AppInit DLLs | T1546.010 | Windows registry/loader |
| Image File Execution Options | T1546.012 | Windows registry |
| Boot Logon — RC Scripts | T1037.004 | Linux rc.local |
| Kernel Module | T1547.006 | Linux kernel |
| LD_PRELOAD | T1574.006 | Linux dynamic linker |

### Privilege Escalation (TA0004)
| Sub-technique | ID | OS Component |
|--------------|-----|--------------|
| SUID/GUID Abuse | T1548.001 | Linux file permissions |
| Sudo Abuse | T1548.003 | Linux sudo |
| Token Impersonation | T1134.001 | Windows access token |
| Process Injection | T1055 | OS process model |
| DLL Injection | T1055.001 | Windows loader |
| Kernel Exploit | T1068 | OS kernel |
| Bypass UAC | T1548.002 | Windows UAC |

### Defense Evasion (TA0005)
| Sub-technique | ID | OS Component |
|--------------|-----|--------------|
| Clear Linux Logs | T1070.002 | Linux logging system |
| Clear Windows Log | T1070.001 | Windows Event Log |
| Timestomping | T1070.006 | Filesystem timestamps |
| Masquerading | T1036 | Filesystem naming |
| Alternate Data Streams | T1564.004 | NTFS ADS |
| Hidden Files | T1564.001 | Filesystem attributes |
| Rootkit | T1014 | OS kernel |
| Process Hollowing | T1055.012 | Windows process model |
| Disable Logging | T1562.001 | Logging subsystems |
| LD_PRELOAD | T1574.006 | Linux dynamic linker |

### Credential Access (TA0006)
| Sub-technique | ID | OS Component |
|--------------|-----|--------------|
| LSASS Memory | T1003.001 | Windows LSASS |
| SAM Dump | T1003.002 | Windows SAM hive |
| NTDS.dit | T1003.003 | AD database |
| LSA Secrets | T1003.004 | Windows LSA |
| /etc/shadow | T1003.008 | Linux shadow file |
| Kerberoasting | T1558.003 | Kerberos |
| AS-REP Roasting | T1558.004 | Kerberos |
| LLMNR Poisoning | T1557.001 | Windows name resolution |

---

## Investigation Command Libraries

### Linux — Live Response Commands

```bash
# ============================================================
# SYSTEM CONTEXT
# ============================================================
date; hostname; uname -a; uptime; who; w; id

# ============================================================
# NETWORK STATE
# ============================================================
ss -tnap                                    # TCP connections with process
ss -tnap | grep ESTABLISHED                 # Active connections
cat /proc/net/tcp                           # Kernel-level TCP (bypasses userspace)
ip route show                               # Routing table
ip addr show                                # Interface addresses
arp -a                                      # ARP cache — lateral movement neighbors
cat /etc/hosts                              # Static DNS
cat /etc/resolv.conf                        # DNS servers

# ============================================================
# PROCESS STATE
# ============================================================
ps auxef                                    # All processes with environment
ls -la /proc/*/exe 2>/dev/null | grep -v proc   # All process binaries
ls -la /proc/*/exe 2>/dev/null | grep deleted   # Deleted binaries still running
for pid in $(ls /proc | grep '^[0-9]'); do
    echo "PID: $pid"
    cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' '; echo
done

# ============================================================
# USER AND AUTHENTICATION
# ============================================================
cat /etc/passwd | grep -v "nologin\|false"  # Users with shell access
cat /etc/shadow                              # Password hashes (root)
last -F | head -50                           # Login history with full timestamps
lastb | head -50                             # Failed logins
lastlog | grep -v "Never"                   # Last login per user
find / -name "authorized_keys" 2>/dev/null  # All SSH authorized_keys
cat /etc/sudoers; ls /etc/sudoers.d/        # Sudo configuration

# ============================================================
# PERSISTENCE
# ============================================================
cat /etc/crontab
ls -la /etc/cron.d/ && cat /etc/cron.d/*
for user in $(cut -d: -f1 /etc/passwd); do
    crontab -l -u $user 2>/dev/null && echo "--- $user ---"
done
ls -la /etc/systemd/system/*.service 2>/dev/null
cat /etc/rc.local 2>/dev/null
ls /etc/profile.d/
cat /etc/ld.so.preload 2>/dev/null

# ============================================================
# FILESYSTEM TRIAGE
# ============================================================
find /tmp /var/tmp /dev/shm -type f -ls 2>/dev/null
find / -type f -perm /111 \( -path /tmp -o -path /var/tmp -o -path /dev/shm \) -ls 2>/dev/null
find / -type f -mtime -1 -not \( -path /proc -o -path /sys \) -ls 2>/dev/null | head -100
find / -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null

# ============================================================
# LOG TRIAGE
# ============================================================
tail -200 /var/log/auth.log
grep "Failed password\|Invalid user\|Accepted" /var/log/auth.log | tail -100
grep "sudo" /var/log/auth.log | grep -v "pam_unix" | tail -50
stat /var/log/auth.log                      # Check modification time
journalctl -n 500 --no-pager               # systemd journal

# ============================================================
# KERNEL AND MODULES
# ============================================================
lsmod
cat /proc/modules
diff <(lsmod | awk 'NR>1{print $1}' | sort) <(ls /sys/module/ | sort)
dmesg | tail -100
```

### Windows — Live Response Commands

```powershell
# ============================================================
# SYSTEM CONTEXT
# ============================================================
Get-Date; hostname; [System.Environment]::OSVersion; Get-Uptime
Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordLastSet
Get-LocalGroupMember -Group "Administrators"
whoami /all

# ============================================================
# NETWORK STATE
# ============================================================
netstat -ano                               # All connections with PID
Get-NetTCPConnection | Where-Object State -eq 'Established' |
  Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess
Get-NetTCPConnection | ForEach-Object {
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
arp -a                                     # ARP cache
Get-DnsClientCache                         # DNS cache — C2 domain evidence
ipconfig /displaydns                       # DNS cache (legacy)
Get-Content C:\Windows\System32\drivers\etc\hosts  # Hosts file

# ============================================================
# PROCESS STATE
# ============================================================
Get-Process | Sort-Object CPU -Descending | Select-Object -First 20 |
  Select-Object Name,Id,CPU,WorkingSet,Path
Get-WmiObject Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine |
  Sort-Object ProcessId
# Find processes without a verified path
Get-Process | Where-Object { -not $_.Path } | Select-Object Name, Id

# ============================================================
# PERSISTENCE
# ============================================================
# Registry autorun keys
$runKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)
foreach ($key in $runKeys) {
    Write-Host "=== $key ===" -ForegroundColor Cyan
    Get-ItemProperty $key -ErrorAction SilentlyContinue
}

# Scheduled tasks
Get-ScheduledTask | Where-Object State -ne 'Disabled' |
  ForEach-Object {
    [PSCustomObject]@{
        Name    = $_.TaskName
        Path    = $_.TaskPath
        Execute = $_.Actions.Execute
        Args    = $_.Actions.Arguments
        User    = $_.Principal.UserId
    }
  }

# Services
Get-Service | Where-Object Status -eq Running |
  Get-WmiObject Win32_Service |
  Select-Object Name,StartMode,PathName,StartName |
  Where-Object { $_.PathName -notmatch "^C:\\Windows" }

# WMI subscriptions
Get-WMIObject -Namespace root\subscription -Class __EventFilter
Get-WMIObject -Namespace root\subscription -Class __EventConsumer
Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding

# Startup folders
Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*" -Force
Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\*" -Force

# ============================================================
# FILESYSTEM TRIAGE
# ============================================================
Get-ChildItem C:\Windows\Temp,C:\Users\*\AppData\Local\Temp -Recurse -Force -ErrorAction SilentlyContinue |
  Where-Object { $_.Extension -in '.exe','.dll','.ps1','.bat','.vbs','.js' } |
  Sort-Object CreationTime -Descending

# Recently modified executables
Get-ChildItem C:\Windows\System32 -Filter *.exe |
  Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } |
  Select-Object FullName, LastWriteTime, Length

# ============================================================
# CREDENTIAL ARTIFACTS
# ============================================================
# PowerShell history (per user)
Get-ChildItem C:\Users\*\AppData\Local\Microsoft\Windows\PowerShell\PSReadLine\*.txt |
  ForEach-Object { Write-Host "=== $($_.DirectoryName) ==="; Get-Content $_ }

# Credential Manager
cmdkey /list
```

---

## Threat Hunting Hypotheses

| Hypothesis | Data Source | Query Focus |
|------------|-------------|-------------|
| Attacker used LOLBins to execute payload | Process creation logs | Parent/child process chains for known LOLBins |
| Persistence via scheduled task | Task Scheduler log + file creation | New tasks with unusual execution paths |
| LSASS accessed for credential dumping | Sysmon EID 10 | OpenProcess on lsass.exe from non-system processes |
| WMI used for lateral movement | WMI logs + network | WMI network connections to remote hosts |
| PowerShell used with encoded commands | PowerShell logs | Base64 patterns in script block logs |
| Attacker cleared event logs | Security EID 1102 | Log clearing events with correlation to prior activity |
| Fileless execution via process injection | Sysmon EID 8 | CreateRemoteThread from unusual sources |
| C2 via DNS tunneling | DNS query logs | High-frequency queries to same domain, long subdomain strings |
| Living-off-the-land download | Process + network | certutil, bitsadmin, or msiexec with outbound connections |
| Shadow copy deletion pre-ransomware | Process creation | vssadmin, wbadmin, wmic with shadow delete arguments |
| Linux cron persistence added | auditd | Writes to /etc/cron.d or /var/spool/cron |
| SSH key added for backdoor | auditd / FIM | Writes to authorized_keys outside of provisioning window |
| LD_PRELOAD library injected | auditd / FIM | Write to /etc/ld.so.preload |
| Kernel module loaded by non-root | auditd | insmod/modprobe by non-system user |

---

*Security-Reference | OS-Internals-for-SOC | Solomon James (@Jaysolex)*
