"""
Attack Storyline Generation — Phase 3.

Correlates events across all log sources to produce a structured attack storyline:
  - ATT&CK-mapped attack steps in chronological order
  - Lateral movement path reconstruction (from_host → to_host with method)
  - Blast radius: compromised hosts/users, accessed resources, persistence mechanisms
  - Threat actor profile heuristics

The build_storyline() function is deterministic and requires no LLM — it operates
entirely on structured ForensicEvent fields and pattern matching.

Session model
─────────────
Each actor is identified by (user, source_host).  A session stays "open" for an
actor as long as consecutive events from that actor arrive within
INACTIVITY_TIMEOUT_SECONDS of each other.  Once the gap exceeds the timeout, a
new session is opened for the same actor.

This single-linkage temporal clustering correctly handles "low and slow" attacks:
  - A 13-minute pause between lateral movement and execution → same session ✓
  - A 59-minute pause mid-chain → same session ✓
  - A 2-hour gap (attacker re-enters separately) → new session, new chain ✓

Deduplication applies per (actor, session) pair, not globally, so the same
technique can appear in multiple distinct sessions of the same actor.
"""

import re
from collections import defaultdict
from datetime import timedelta
from backend.schema import ForensicEvent

# ── Sliding inactivity timeout ─────────────────────────────────────────────────
#
# If an actor (user, host) is silent for longer than this, any subsequent event
# from that actor opens a new session rather than extending the existing one.
# 60 minutes is chosen to accommodate "hands-on-keyboard" dwell times observed in
# real-world intrusions while still separating distinct re-entry episodes.

INACTIVITY_TIMEOUT_SECONDS: int = 3600  # 60 minutes

# ── MITRE ATT&CK tactic progression ───────────────────────────────────────────

TACTIC_ORDER = [
    'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
    'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
    'Collection', 'Command and Control', 'Exfiltration', 'Impact',
]

# ── Event ID → ATT&CK (highest-signal mapping; patterns take priority) ────────

_EID_TECHNIQUE: dict[str, tuple[str, str, str]] = {
    # (technique_id, name, tactic)
    # 4688/4624/4663 are handled conditionally in _classify() — not here.

    # ── Persistence ──────────────────────────────────────────────────────────
    '4698': ('T1053.005', 'Scheduled Task',                       'Persistence'),
    '7045': ('T1543.003', 'Windows Service',                       'Persistence'),
    '4657': ('T1547.001', 'Registry Run Keys',                     'Persistence'),
    '4728': ('T1098',     'Domain Group Membership Change',        'Persistence'),
    '4732': ('T1098',     'Local Group Membership Change',         'Persistence'),
    '4735': ('T1098',     'Security-Enabled Local Group Modified', 'Persistence'),
    '4756': ('T1098',     'Universal Group Membership Change',     'Persistence'),
    '4742': ('T1098',     'Computer Account Modified',             'Persistence'),
    '4780': ('T1098',     'Admin Account ACL Modified',            'Persistence'),
    '4794': ('T1098',     'DSRM Password Reset Attempt',          'Persistence'),
    '4720': ('T1136.002', 'Domain Account Created',                'Persistence'),
    '5137': ('T1136.002', 'AD Directory Object Created',           'Persistence'),

    # ── Credential Access ─────────────────────────────────────────────────────
    '4662': ('T1003.006', 'DCSync / DS-Replication',              'Credential Access'),
    '4929': ('T1003.006', 'DS Replication Source NC Removed',     'Credential Access'),
    '4625': ('T1110',     'Brute Force',                          'Credential Access'),
    '4767': ('T1110',     'Account Unlocked After Lockout',       'Credential Access'),
    '4769': ('T1558.003', 'Kerberoasting',                        'Credential Access'),
    '4768': ('T1558.004', 'AS-REP Roasting',                      'Credential Access'),
    '4771': ('T1558.004', 'Kerberos Pre-Auth Failure',            'Credential Access'),
    '4648': ('T1078',     'Explicit Credential Logon',            'Credential Access'),
    # AD CS — certificate issuance / template abuse (ESC1-ESC8)
    '4886': ('T1649',     'Certificate Issued (AD CS)',           'Credential Access'),
    '4887': ('T1649',     'Certificate Request Approved (AD CS)', 'Credential Access'),

    # ── Privilege Escalation ──────────────────────────────────────────────────
    '4672': ('T1134',     'Special Privileges Assigned',          'Privilege Escalation'),
    '4765': ('T1134.005', 'SID-History Injection',                'Privilege Escalation'),
    '4766': ('T1134.005', 'SID-History Injection Attempt',        'Privilege Escalation'),

    # ── Lateral Movement ──────────────────────────────────────────────────────
    '4776': ('T1550.002', 'NTLM Authentication',                  'Lateral Movement'),
    '8004': ('T1550.002', 'NTLM Auth (NTLMSSP)',                  'Lateral Movement'),
    '5140': ('T1021.002', 'SMB/Windows Admin Shares',             'Lateral Movement'),
    '5145': ('T1021.002', 'SMB Share File Access',                'Lateral Movement'),

    # ── Defense Evasion ───────────────────────────────────────────────────────
    '1102': ('T1070.001', 'Clear Windows Event Logs',             'Defense Evasion'),
    '4719': ('T1562.002', 'Disable Windows Audit Policy',         'Defense Evasion'),
    '4739': ('T1484.001', 'Domain Policy Modification',           'Defense Evasion'),
    '4713': ('T1484.001', 'Kerberos Policy Changed',              'Defense Evasion'),
    '4899': ('T1649',     'Certificate Template Modified (AD CS)','Defense Evasion'),
    '5136': ('T1484.001', 'AD Directory Object Modified',         'Defense Evasion'),

    # ── Impact ────────────────────────────────────────────────────────────────
    '4726': ('T1531',     'Domain Account Deleted',               'Impact'),
    '5141': ('T1531',     'AD Directory Object Deleted',          'Impact'),
}

# Pattern-based classification (checked first; more specific than EID mapping).
# Ordered: most specific / highest-signal first within each tactic group.
_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [

    # ── Initial Access ────────────────────────────────────────────────────────
    (re.compile(r'\bwinword\b.*cmd|word.*spawns|macro.*delivery|\.docm\b|\.xlsm\b.*exec|excel.*spawns.*cmd', re.I),
        'T1566.001', 'Spearphishing Attachment', 'Initial Access'),
    (re.compile(r'\bphish(?:ing)?\b.*(?:link|url|click)|clicked.*(?:link|url)|open.*url.*mail|href.*(?:download|redirect)|malicious.*url.*email', re.I),
        'T1566.002', 'Spearphishing Link', 'Initial Access'),
    (re.compile(r'\b(?:teams|slack|discord|telegram|whatsapp)\b.*(?:phish|malicious|link|payload)|social.*engineer.*(?:teams|slack)', re.I),
        'T1566.003', 'Spearphishing via Service', 'Initial Access'),
    (re.compile(r'\b(?:log4(?:shell|j)|proxylogon|proxyshell|bluekeep|zerologon|eternalblue|cve-20(?:17-0144|19-0708|20-1472|21-(?:34527|26855|31207|42278|42287)))\b', re.I),
        'T1190', 'Exploit Public-Facing Application', 'Initial Access'),
    (re.compile(r'\b(?:vpn|citrix|netscaler|pulse\s*secure|fortinet|globalprotect|anyconnect|sonicwall|juniper)\b.*(?:logon|auth|connect|session)|external.*rdp.*(?:success|logon)|rdp.*from.*(?:internet|wan|public|external)', re.I),
        'T1133', 'External Remote Services', 'Initial Access'),
    (re.compile(r'\b(?:usb|removable\s+media|autorun\.inf|autoplay|u3\s+drive|thumb\s*drive|flash\s*drive)\b', re.I),
        'T1091', 'Replication Through Removable Media', 'Initial Access'),
    (re.compile(r'\bsupply.*chain|trojanized.*(?:update|package|installer)|malicious.*npm|malicious.*pip|compromised.*software\b', re.I),
        'T1195.002', 'Compromise Software Supply Chain', 'Initial Access'),

    # ── Execution ─────────────────────────────────────────────────────────────
    (re.compile(r'\bpowershell\b.*-e(?:nc\b|ncodedcommand)|iex.*downloadstring|invoke-expression|invoke-mimikatz|downloadcradle', re.I),
        'T1059.001', 'PowerShell', 'Execution'),
    (re.compile(r'\bcmd(?:\.exe)?\b.*(?:/c\s+|/k\s+)(?:net\b|sc\b|reg\b|wmic\b|certutil\b|curl\b|wget\b)|command.*shell.*exec', re.I),
        'T1059.003', 'Windows Command Shell', 'Execution'),
    (re.compile(r'\bwscript\b|\bcscript\b|\.vbs\b.*exec|\.js\b.*wscript|jscript.*shell|vbscript.*run', re.I),
        'T1059.005', 'Visual Basic / VBScript', 'Execution'),
    (re.compile(r'\bmshta\b.*(?:http|vbscript|javascript|\.hta\b)|hta.*application.*exec', re.I),
        'T1218.005', 'Mshta', 'Execution'),
    (re.compile(r'\bregsvr32\b.*(?:/s\b|scrobj|http|\.sct\b)|squiblydoo', re.I),
        'T1218.010', 'Regsvr32', 'Execution'),
    (re.compile(r'\bmsiexec\b.*(?:/q\b|/i\b.*http|/package\b.*http)', re.I),
        'T1218.007', 'Msiexec', 'Execution'),
    (re.compile(r'\binstallutil\b.*(?:/logfile|\.exe\b)', re.I),
        'T1218.004', 'InstallUtil', 'Execution'),

    # ── Persistence ───────────────────────────────────────────────────────────
    (re.compile(r'\bwmi.*(?:event)?filter\b|\b__eventfilter\b|commandlineeventconsumer', re.I),
        'T1546.003', 'WMI Event Subscription', 'Persistence'),
    (re.compile(r'\bbitsadmin\b|bits.*job\b|start-bitstransfer', re.I),
        'T1197', 'BITS Jobs', 'Persistence'),
    (re.compile(r'\bsethc\b|image\s+file\s+execution\s+options|accessibility.*debug|debugger.*sethc|utilman.*cmd', re.I),
        'T1546.008', 'Accessibility Features', 'Persistence'),
    (re.compile(r'inprocserver32|com.*hijack|clsid.*dll', re.I),
        'T1546.015', 'COM Hijacking', 'Persistence'),
    (re.compile(r'\bauthorized_keys\b|ssh.*backdoor|rsa.*pub.*key|ssh.*persistence', re.I),
        'T1098.004', 'SSH Authorized Keys', 'Persistence'),
    (re.compile(r'winlogon.*userinitmpr|logon.*script|logon\.bat', re.I),
        'T1037.001', 'Logon Script', 'Persistence'),
    (re.compile(r'\bwebshell\b|\.(?:aspx|php|jsp).*(?:cmd|exec|shell|eval)|china\s*chopper|b374k|r57|c99\b', re.I),
        'T1505.003', 'Web Shell', 'Persistence'),
    (re.compile(r'\biam\s+create.user\b|createuser.*svc|attachuserpolicy.*administrator', re.I),
        'T1136.003', 'Cloud Account', 'Persistence'),
    (re.compile(r'\bapplication\s+shim|sdb.*inject|sdbinst\b|shim.*database', re.I),
        'T1546.011', 'Application Shimming', 'Persistence'),

    # ── Privilege Escalation ──────────────────────────────────────────────────
    (re.compile(r'\bzerologon\b|cve-2020-1472|netlogon.*exploit|nl_auth.*empty\s*password', re.I),
        'T1068', 'ZeroLogon (CVE-2020-1472)', 'Privilege Escalation'),
    (re.compile(r'\bnopac\b|cve-2021-42278|cve-2021-42287|samaccountname.*spoof', re.I),
        'T1068', 'noPac (CVE-2021-42278/42287)', 'Privilege Escalation'),
    (re.compile(r'\bprintnightmare\b|cve-2021-34527|spoolsv.*cmd|print\s+spooler.*exploit', re.I),
        'T1068', 'PrintNightmare (CVE-2021-34527)', 'Privilege Escalation'),
    (re.compile(r'\bjuicypotato\b|\brottenpotato\b|\bsweetpotato\b|\bgodpotato\b|seimpersonatepriv', re.I),
        'T1134.002', 'Create Process with Token', 'Privilege Escalation'),
    (re.compile(r'\bfodhelper\b|ms-settings.*shell.*open.*command|uac.*bypass|bypass.*uac|eventvwr.*bypass', re.I),
        'T1548.002', 'Bypass User Account Control', 'Privilege Escalation'),
    (re.compile(r'\balwaysinstallelevated\b|malicious.*msi|msi.*elevated', re.I),
        'T1548.002', 'Bypass User Account Control', 'Privilege Escalation'),
    (re.compile(r'\bunquoted.*service\b|service.*path.*unquoted', re.I),
        'T1574.009', 'Unquoted Service Path', 'Privilege Escalation'),
    (re.compile(r'\bsid.*history\b|add.*sid.*history|inject.*sid|sidhistory', re.I),
        'T1134.005', 'SID-History Injection', 'Privilege Escalation'),
    (re.compile(r'\bdll.*hijack|dll.*side.?load|missing.*dll.*search|phantom.*dll', re.I),
        'T1574.001', 'DLL Search Order Hijacking', 'Privilege Escalation'),

    # ── Defense Evasion ───────────────────────────────────────────────────────
    (re.compile(r'\bskeleton[-_\s]key\b|misc::skeleton|patching.*lsass|lsass.*patch', re.I),
        'T1207', 'Rogue Domain Controller', 'Defense Evasion'),
    (re.compile(r'\bmsse-\d+|createremotethread|reflective.*inject|pipe.*created', re.I),
        'T1055', 'Process Injection', 'Defense Evasion'),
    (re.compile(r'\bamsi\b|amsiutils|invoke-obfuscat|etw.*bypass|amsi\.dll|clm.*bypass|constrained.*language.*bypass', re.I),
        'T1562.001', 'Disable or Modify Tools', 'Defense Evasion'),
    (re.compile(r'\bwevtutil\s+cl\b|event.*log.*cleared|clearev\b', re.I),
        'T1070.001', 'Clear Windows Event Logs', 'Defense Evasion'),
    (re.compile(r'\bdel\b.*\.(?:log|evtx|etl)\b|rm\s+-[rf]+.*\.log|remove.*log.*file|forfiles.*delete.*log', re.I),
        'T1070.004', 'File Deletion', 'Defense Evasion'),
    (re.compile(r'\btimestomp\b|touch\s+-[amt]\b|set-item.*last.*write|modify.*timestamp', re.I),
        'T1070.006', 'Timestomp', 'Defense Evasion'),
    (re.compile(r'\breg\s+(?:add|delete|import)\b|regini\b|set-itemproperty.*hk(?:lm|cu|cr)|registry.*modif', re.I),
        'T1112', 'Modify Registry', 'Defense Evasion'),
    (re.compile(r'\bmasquerad|svchost.*unusual.*path|lsass.*renamed|process.*impersonat|binary.*rename', re.I),
        'T1036', 'Masquerading', 'Defense Evasion'),
    (re.compile(r'\bsc\s+(?:config|delete|stop)\b.*(?:sense|windefend|mssecflt|mwac|mbam)|set-mppreference.*disable|defender.*disabled|netsh.*advfirewall.*off', re.I),
        'T1562.004', 'Disable or Modify Firewall / AV', 'Defense Evasion'),
    (re.compile(r'\bcertutil\b.*(?:-encode|-decode|-urlcache|-verifyctl)|\bbase64\b.*(?:encode|decode).*payload', re.I),
        'T1140', 'Deobfuscate/Decode Files', 'Defense Evasion'),

    # ── Credential Access ─────────────────────────────────────────────────────
    (re.compile(r'\bmimikatz\b|\bsekurlsa\b|\blsadump::(?:sam|dcsync|lsa|cache)\b', re.I),
        'T1003', 'OS Credential Dumping', 'Credential Access'),
    (re.compile(r'\bdcsync\b|DS-Replication|1131f6aa|1131f6ab', re.I),
        'T1003.006', 'DCSync', 'Credential Access'),
    (re.compile(r'\bprocdump\b|comsvcs.*minidump|lsass.*dump|ntds\.dit', re.I),
        'T1003', 'OS Credential Dumping', 'Credential Access'),
    (re.compile(r'\bgolden.*ticket\b|\bkrbtgt\b.*hash|lsadump::golden|\bptt\b|kerberos.*ptt', re.I),
        'T1558.001', 'Golden Ticket', 'Credential Access'),
    (re.compile(r'\bsilver.*ticket\b|lsadump::silver|forged.*tgs|tgs.*forge', re.I),
        'T1558.002', 'Silver Ticket', 'Credential Access'),
    (re.compile(r'\bkerberoast\b|etype.*0x17|rc4.*kerberoast|GetUserSPNs|getnpusers', re.I),
        'T1558.003', 'Kerberoasting', 'Credential Access'),
    (re.compile(r'\bas[-_]rep\s*roast|asreproast|preauth.*not.*required|UF_DONT_REQUIRE_PREAUTH', re.I),
        'T1558.004', 'AS-REP Roasting', 'Credential Access'),
    (re.compile(r'\bntlm.*relay\b|responder\b|ntlmrelayx|smbrelayx|llmnr.*poison|nbt[-_]ns.*poison', re.I),
        'T1557.001', 'LLMNR/NBT-NS Poisoning', 'Credential Access'),
    # AD CS abuse (ESC1–ESC8): certipy/certify tools, SAN abuse, PKINIT, forged certs
    (re.compile(r'\bcertipy\b|\bcertify\.exe\b|\badcspwn\b|esc[1-8]\b|adcs.*exploit|certificate.*san.*template|pkinit.*abuse|pkiextendedkeyusage|enroll.*dc.*cert|pfx.*dump', re.I),
        'T1649', 'Steal or Forge Authentication Certificates (AD CS)', 'Credential Access'),
    (re.compile(r'\bpassword\s+spray|pwspray\b|many.*failed.*logon.*same.*pass|o365.*spray|fireprox\b|exchange.*spray|lockout.*multiple.*accounts', re.I),
        'T1110.003', 'Password Spraying', 'Credential Access'),
    (re.compile(r'\bcredential.*stuff|stuffing\b|combo.*list.*login|breached.*cred.*logon', re.I),
        'T1110.004', 'Credential Stuffing', 'Credential Access'),
    (re.compile(r'\blazagne\b|browser.*password|credential.*manager|dpapi.*cred|vaultcmd\b|cmdkey\s+/list|windows.*vault', re.I),
        'T1555', 'Credentials from Password Stores', 'Credential Access'),
    (re.compile(r'\bunattend(?:ed)?\.xml|sysprep\.xml|groups\.xml|web\.config.*password|appsettings.*password|connection.*string.*password|\.netrc\b', re.I),
        'T1552.001', 'Credentials in Files', 'Credential Access'),
    (re.compile(r'reg.*query.*password|hklm.*security.*cache|lsa.*secrets\b|winlogon.*defaultpassword|autologon.*password', re.I),
        'T1552.002', 'Credentials in Registry', 'Credential Access'),
    (re.compile(r'\bresponder\b.*hash|force.*auth|uncpath.*\\\\|net.*use.*\\\\[^\\]+\\[^\\]+.*password', re.I),
        'T1187', 'Forced Authentication', 'Credential Access'),

    # ── Discovery ─────────────────────────────────────────────────────────────
    (re.compile(r'\bpowerview\b|Get-Domain(?:User|Group|Computer|Controller|Trust)|Find-LocalAdminAccess|Get-NetLocalGroup', re.I),
        'T1069.002', 'Domain Groups Discovery', 'Discovery'),
    (re.compile(r'\bbloodhound\b|\bsharphound\b|Invoke-BloodHound|CollectionMethod|ADExplorer\b', re.I),
        'T1069.002', 'AD Reconnaissance (BloodHound)', 'Discovery'),
    (re.compile(r'\bnmap\b|\bport.*scan\b|\bnetwork.*scan\b|masscan\b|unicornscan\b', re.I),
        'T1046', 'Network Service Discovery', 'Discovery'),
    (re.compile(r'\bldapdomaindump\b|\badrecon\b|ldap.*dump|bloodhound.*session|ldapsearch\b|dsquery\b', re.I),
        'T1087.002', 'Domain Account Enumeration', 'Discovery'),
    (re.compile(r'\bnet\s+user\b.*domain|net\s+group.*domain admins|nltest.*dclist|nltest.*domain_trusts', re.I),
        'T1087.002', 'Domain Account Discovery', 'Discovery'),
    (re.compile(r'\bnet\s+user\b(?!.*domain)|wmic\s+useraccount|get-localuser\b', re.I),
        'T1087.001', 'Local Account Discovery', 'Discovery'),
    (re.compile(r'\b(?:ipconfig|ifconfig|ip\s+addr\b|arp\s+-a|route\s+print|netsh\s+interface)', re.I),
        'T1016', 'System Network Configuration Discovery', 'Discovery'),
    (re.compile(r'\b(?:net\s+view\b|nbtscan\b|netscan\b|advanced.*ip.*scanner|angry.*ip|arp-scan)\b', re.I),
        'T1018', 'Remote System Discovery', 'Discovery'),
    (re.compile(r'\b(?:whoami\b|getuid\b|echo\s+%username%|id\b.*uid=|hostname\b|%logonserver%)', re.I),
        'T1033', 'System Owner/User Discovery', 'Discovery'),
    (re.compile(r'\bnetstat\b|\bss\s+-[anptu]+\b|network.*connections.*list', re.I),
        'T1049', 'System Network Connections Discovery', 'Discovery'),
    (re.compile(r'\btasklist\b|get-process\b|wmic\s+process\b|ps\s+aux\b', re.I),
        'T1057', 'Process Discovery', 'Discovery'),
    (re.compile(r'\bsysteminfo\b|uname\s+-a\b|get-computerinfo\b|wmic\s+os\b|winver\b', re.I),
        'T1082', 'System Information Discovery', 'Discovery'),
    (re.compile(r'\bnet\s+share\b|showmount\b|smbclient\s+-L\b|get-smbshare\b', re.I),
        'T1135', 'Network Share Discovery', 'Discovery'),
    (re.compile(r'\bnet\s+accounts\b|password.*policy\b|account.*lockout.*policy\b|get-addefaultdomainpasswordpolicy\b', re.I),
        'T1201', 'Password Policy Discovery', 'Discovery'),
    (re.compile(r'\bnltest\b.*domain_trusts|get-adtrust\b|get-forest\b|trusteddomains\b|domain.*trust.*enum', re.I),
        'T1482', 'Domain Trust Discovery', 'Discovery'),

    # ── Lateral Movement ──────────────────────────────────────────────────────
    (re.compile(r'\bpass[-_]the[-_]hash\b|sekurlsa::pth|ntlm.*hash.*logon|overpass.*hash', re.I),
        'T1550.002', 'Pass the Hash', 'Lateral Movement'),
    (re.compile(r'\bpass[-_]the[-_]ticket\b|rubeus.*ptt|kerberos::ptt|use.*ticket', re.I),
        'T1550.003', 'Pass the Ticket', 'Lateral Movement'),
    (re.compile(r'\bpsexec\b|\bpsexesvc\b|\bsmbexec\b|\batexec\b', re.I),
        'T1021.002', 'SMB/PsExec Lateral Movement', 'Lateral Movement'),
    (re.compile(r'\bdcomexec\b|\bdcom\b.*(?:lateral|exec|remote)|MMC20\.Application|ShellWindows|ShellBrowserWindow', re.I),
        'T1021.003', 'DCOM Lateral Movement', 'Lateral Movement'),
    (re.compile(r'\bwmiexec\b|\bwmic\s+/node:\b|win32_process.*create|invoke-wmimethod', re.I),
        'T1047', 'WMI Remote Execution', 'Lateral Movement'),
    (re.compile(r'\brdp\b.*lateral|mstsc.*lateral|logon type.*10\b|type\s+10\b', re.I),
        'T1021.001', 'Remote Desktop Protocol', 'Lateral Movement'),
    (re.compile(r'\btscon\b|\brdp.*hijack|shadow.*session.*connect|shadow\s+/server\b', re.I),
        'T1563.002', 'RDP Session Hijacking', 'Lateral Movement'),
    (re.compile(r'\bwinrm\b|\benter-pssession\b|\binvoke-command\b.*ComputerName', re.I),
        'T1021.006', 'Windows Remote Management', 'Lateral Movement'),
    (re.compile(r'\beternalblue\b|ms17-010|cve-2017-0144|doublepulsar\b|smb.*exploit.*445', re.I),
        'T1210', 'Exploitation of Remote Services', 'Lateral Movement'),

    # ── Collection ────────────────────────────────────────────────────────────
    (re.compile(r'\brobocopy\b|staging.*directory|data.*staging\b', re.I),
        'T1074', 'Data Staged', 'Collection'),
    (re.compile(r'\bkeylog\b|keylogger\b|hook.*keyboard|GetAsyncKeyState|SetWindowsHook', re.I),
        'T1056.001', 'Keylogging', 'Collection'),
    (re.compile(r'\bscreenshot\b|screen.*capture\b|printscreen\b|copyfromscreen\b|bitblt\b', re.I),
        'T1113', 'Screen Capture', 'Collection'),
    (re.compile(r'\b7z\b.*(?:a\b|-mhe|-p)|\brar\b.*(?:-p\b|-hp\b)|\bzip\b.*password|compress.*archive.*exfil', re.I),
        'T1560', 'Archive Collected Data', 'Collection'),

    # ── Command and Control ───────────────────────────────────────────────────
    (re.compile(r'\bchisel\b|\bplink\.exe\b|\bngrok\b|\bfrp\b|ssh.*-[RL]\s+\d{4}|socat.*tcp.*forward|protocol.*tunnel', re.I),
        'T1572', 'Protocol Tunneling', 'Command and Control'),
    (re.compile(r'\bdns.*tunnel|dnscat\b|iodine\b|dns2tcp\b|base64.*dns.*txt|exfil.*dns\b', re.I),
        'T1071.004', 'DNS Tunneling', 'Command and Control'),
    (re.compile(r'\bbeacon\b.*(?:http|https)|c2.*(?:http|https)|cobalt.*strike.*http|malleable.*profile|sleep.*jitter\b', re.I),
        'T1071.001', 'Web Protocols C2', 'Command and Control'),
    (re.compile(r'\bsocks[45]?\b.*proxy|proxychains\b|pivot.*proxy|socks.*forward', re.I),
        'T1090.002', 'External Proxy', 'Command and Control'),

    # ── Exfiltration ──────────────────────────────────────────────────────────
    (re.compile(r'\bmega\.nz\b|\brclone\b|azcopy\b|aws\s+s3.*cp\b|exfil.*cloud|curl.*upload.*(?:mega|dropbox|onedrive)', re.I),
        'T1567', 'Exfiltration to Cloud Storage', 'Exfiltration'),
    (re.compile(r'\bexfil\b|data.*exfil|certutil.*encode.*exfil|nc\b.*-e\b|curl.*upload\b', re.I),
        'T1048', 'Exfiltration over Alternative Protocol', 'Exfiltration'),
    (re.compile(r'\bdns.*exfil|base64.*dns.*query|txt.*record.*data|dnscat.*send', re.I),
        'T1048.003', 'DNS Exfiltration', 'Exfiltration'),

    # ── Impact ────────────────────────────────────────────────────────────────
    (re.compile(r'\bransom\b|\.encrypted\b|\.locked\b|your.*files.*encrypted|payment.*bitcoin|cryptolocker|lockbit|ryuk|conti\b|revil|darkside|blackcat|alphv\b|readme.*decrypt', re.I),
        'T1486', 'Data Encrypted for Impact (Ransomware)', 'Impact'),
    (re.compile(r'\bvssadmin\b.*delete|delete.*shadow|net\s+stop\s+vss', re.I),
        'T1490', 'Inhibit System Recovery', 'Impact'),
    (re.compile(r'\bnet\s+stop\b.*(?:vss\b|backup\b|sql\b|mssql\b|exchange\b|mysql\b)|taskkill.*(?:sql|backup|antivirus)|sc\s+stop\b.*(?:vss|mssql|backup)', re.I),
        'T1489', 'Service Stop', 'Impact'),
    (re.compile(r'\bshutdown\b.*(?:/r\b|/s\b|/h\b|-r\b|-h\b)|restart-computer\b|poweroff\b.*forced|halt\b.*system', re.I),
        'T1529', 'System Shutdown/Reboot', 'Impact'),
    (re.compile(r'\bwbadmin\b.*delete|bcdedit.*(?:recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)|diskshadow.*delete\s+shadows', re.I),
        'T1561', 'Boot/Recovery Config Destruction', 'Impact'),
]

# ── Conditional guards for high-noise Event IDs ────────────────────────────────
#
# These regexes gate the three Event IDs that produce the most false positives
# when mapped unconditionally:
#
#   4688 (Process Creation) → T1059 only when a real shell or LOLBin is present.
#        chrome.exe / excel.exe / outlook.exe launching normally must be ignored.
#
#   4624 (Logon Success)    → T1078 only for Network (type 3) or NewCredentials
#        (type 9) logons.  Interactive (2) and Service (5) logons are local ops.
#
#   4663 (Object Access)    → T1005 only when the accessing process is not a
#        known Office app, OR the path leads to a staging/temp directory.

_SHELL_LOLBIN_RE = re.compile(
    r'\b(?:cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|'
    r'certutil|msiexec|bitsadmin|wmic|forfiles|pcalua|installutil|cmstp|'
    r'msbuild|regasm|regsvcs|bash|sh|zsh|python|python3|ruby|perl|node)\b',
    re.IGNORECASE,
)

_STAGING_PATH_RE = re.compile(
    r'\\(?:temp|tmp|staging|exfil|transfer)\\', re.IGNORECASE,
)

_OFFICE_PROC_RE = re.compile(
    r'\b(?:excel|winword|powerpnt|outlook|onenote|access|publisher|visio)\.exe\b',
    re.IGNORECASE,
)


def _classify(e: ForensicEvent) -> tuple[str, str, str] | None:
    """Return (technique_id, name, tactic) — pattern check first, conditional EID fallback."""
    desc = (e.description or '').lower()

    for pat, tid, name, tactic in _PATTERNS:
        if pat.search(desc):
            return tid, name, tactic

    eid = e.event_id or ''

    if eid == '4688':
        # T1059 only when the process name or command line contains a shell or LOLBin.
        # Standard GUI apps (Chrome, Office, Explorer) return None.
        if _SHELL_LOLBIN_RE.search(desc):
            return ('T1059', 'Command and Scripting Interpreter', 'Execution')
        return None

    if eid == '4624':
        # T1078 lateral movement only on Network (3) or NewCredentials (9) logons.
        # Interactive (2), Service (5), Unlock (7) etc. are normal local operations.
        m = re.search(r'logon type:\s*(\d+)', desc)
        if m and m.group(1) in ('3', '9'):
            return ('T1078', 'Valid Accounts', 'Lateral Movement')
        return None

    if eid == '4663':
        # T1005 is skipped when an Office app reads its own files outside staging dirs.
        if _OFFICE_PROC_RE.search(desc) and not _STAGING_PATH_RE.search(desc):
            return None
        return ('T1005', 'Data from Local System', 'Collection')

    return _EID_TECHNIQUE.get(eid)


def _actor_key(e: ForensicEvent) -> tuple[str, str]:
    """
    Stable identity for an attack actor: (normalized_user, source_host).

    Using both user and host means a different user on the same host,
    or the same user pivoting to a new host, are tracked as distinct actors.
    This correctly models credential-based lateral movement where the attacker
    may use different accounts at different stages.
    """
    return ((e.user or 'unknown').lower(), e.source_host or 'unknown')


def _is_lateral(e: ForensicEvent) -> bool:
    """Return True when this event represents lateral movement."""
    desc = (e.description or '').lower()
    if e.event_id in ('5140', '5145', '8004'):
        return True
    if e.event_id == '4624':
        if re.search(r'logon type:\s*(?:3|10)\b|type\s+(?:3|10)\b|network logon', desc, re.I):
            return True
    if e.event_id == '4776':
        if re.search(r'workstation.*name|source.*address', desc, re.I):
            return True
    if re.search(
        r'\bpsexec\b|\bpsexesvc\b|\bwmiexec\b|\bsmbexec\b|\batexec\b|\bdcomexec\b'
        r'|\bwmic\s+/node:\b|win32_process.*create'
        r'|\bpass[-_]the[-_]hash\b|sekurlsa::pth'
        r'|\bpass[-_]the[-_]ticket\b|rubeus.*ptt'
        r'|\btscon\b|\brdp.*hijack|shadow.*session.*connect'
        r'|\bdcom.*exec|MMC20\.Application|ShellWindows|ShellBrowserWindow'
        r'|\beternalblue\b|ms17-010|doublepulsar\b'
        r'|\bwinrm\b|\benter-pssession\b|\binvoke-command\b.*computername',
        desc, re.I,
    ):
        return True
    return False


def _extract_src(e: ForensicEvent) -> str | None:
    # EID 5140/5145 and network logon events emit the source IP under several field
    # names depending on the Windows version and export tool:
    #   "Source Address:", "Source Network Address:", "IpAddress:", "Client Address:"
    #   "Source:" (short form used in simple CSV logs)
    # Some formatters also prefix the IP with one or two backslashes.
    desc = e.description or ''
    m = re.search(
        r'(?:Source(?:\s+Network)?\s+Address|IpAddress|Client\s+(?:IP\s+)?Address)'
        r':\s*\\{0,2}(\d[\d.:a-fA-F]+)',
        desc, re.IGNORECASE,
    )
    if m:
        ip = m.group(1).rstrip('.,;').strip()
        if ip not in ('-', '', '::1', '127.0.0.1'):
            return ip
    # Short "Source: IP" format used in simplified event logs
    m2 = re.search(
        r'(?<![A-Za-z])Source:\s*\\{0,2}(\d[\d.:a-fA-F]+)',
        desc, re.IGNORECASE,
    )
    if m2:
        ip = m2.group(1).rstrip('.,;').strip()
        if ip not in ('-', '', '::1', '127.0.0.1'):
            return ip
    # "Workstation: HOSTNAME" as fallback source identifier
    m3 = re.search(r'Workstation:\s*([\w][\w\-]{1,30})', desc, re.IGNORECASE)
    if m3:
        host = m3.group(1).rstrip('.,;').strip()
        if host.lower() not in ('unknown', '-', 'n/a'):
            return host
    return None


# Matches "Account Name: jsmith" in Windows Event Log descriptions.
# Uses \w+ so it won't capture multi-word noise or domain-qualified names.
_ACCT_NAME_RE = re.compile(r'Account\s+Name:\s*([\w][\w\-\.]{0,48})', re.IGNORECASE)

_SKIP_ACCOUNTS = frozenset({
    'system', 'local service', 'network service', 'anonymous logon',
    '-', 'n/a', 'unknown', 'null',
})


def _extract_account_name(desc: str) -> str | None:
    """
    Extract a human Account Name from a Windows Event Log description when the
    structured e.user field is unpopulated (common for EID 4104, 1102, etc.).
    Skips machine accounts ($), built-in service accounts, and placeholder values.
    """
    for m in _ACCT_NAME_RE.finditer(desc):
        name = m.group(1).strip()
        if name.endswith('$'):
            continue
        if name.lower() in _SKIP_ACCOUNTS:
            continue
        return name
    return None


def _extract_resource(desc: str) -> str | None:
    # Try Share Name first (EID 5140/5145) — strip leading backslashes from UNC paths.
    m = re.search(r'Share\s+Name:\s*(\\{0,3}\S+)', desc, re.IGNORECASE)
    if m:
        resource = m.group(1).lstrip('\\').strip()[:100]
        if resource and resource not in ('', '-'):
            return resource
    # Fall back to Object Name (EID 4663).
    m = re.search(r'Object\s+Name:\s*([^\r\n]{1,100})', desc, re.IGNORECASE)
    if m:
        resource = m.group(1).strip().rstrip('.').strip()[:100]
        if resource and resource not in ('', '-'):
            return resource
    return None


# ── Main builder ───────────────────────────────────────────────────────────────

def build_storyline(events: list[ForensicEvent]) -> dict:
    """
    Build a structured attack storyline from a list of ForensicEvents.

    Uses a sliding inactivity timeout (INACTIVITY_TIMEOUT_SECONDS) to group
    events from the same actor into coherent sessions.  Deduplication of
    attack steps is scoped to each (actor, session) pair rather than being
    global, so:

      - Repeated technique use by the same actor within one session is
        collapsed (prevents noise from repeated logons, etc.).
      - The same technique appearing in a distinct later session (after a long
        pause) is recorded as a new step, correctly surfacing re-entry.

    Returns a plain dict matching AttackStoryline schema.
    """
    if not events:
        return _empty()

    sorted_events = sorted(events, key=lambda e: e.timestamp)
    t0   = sorted_events[0].timestamp
    tend = sorted_events[-1].timestamp
    duration_minutes = (tend - t0).total_seconds() / 60

    # ── Three-tier user attribution ───────────────────────────────────────────
    #
    # Tier 1 — Structured field: e.user from the parser (most reliable).
    # Tier 2 — IP correlation: earlier event with same source IP already had a user.
    # Tier 3 — Host-session propagation: most-recently-known user on same host
    #           within INACTIVITY_TIMEOUT_SECONDS (models single-session attack chains
    #           where only the logon event carries an explicit username).
    #
    # Precomputed in one forward pass so session state accumulates correctly.

    _IP_RE = re.compile(
        r'(?:Source(?:\s+Network)?\s+Address|IpAddress|Client(?:\s+(?:IP\s+)?)?Address)'
        r':\s*\\{0,2}(\d[\d.:a-fA-F]+)',
        re.IGNORECASE,
    )
    _SKIP_IPS = frozenset({'127.0.0.1', '::1', '-', '0.0.0.0', ''})

    ip_to_user: dict[str, str] = {}
    for e in sorted_events:
        if e.user and e.description:
            m = _IP_RE.search(e.description)
            if m:
                ip = m.group(1).strip()
                if ip not in _SKIP_IPS:
                    ip_to_user.setdefault(ip, e.user)

    host_session: dict[str, tuple[str, object]] = {}
    effective_users: list[str | None] = []

    for e in sorted_events:
        eff: str | None = e.user or None

        # Tier 2 — IP correlation (also supersedes SYSTEM with a specific human account)
        if (not eff or eff.lower() == 'system') and e.description:
            m = _IP_RE.search(e.description)
            if m:
                ip = m.group(1).strip()
                if ip not in _SKIP_IPS:
                    corr = ip_to_user.get(ip)
                    if corr:
                        eff = corr

        # Tier 3 — host-session propagation (only when eff is still None; SYSTEM is kept)
        if not eff and e.source_host and e.source_host in host_session:
            last_user, last_ts = host_session[e.source_host]
            if (e.timestamp - last_ts).total_seconds() <= INACTIVITY_TIMEOUT_SECONDS:
                eff = last_user

        effective_users.append(eff)

        # SYSTEM does not represent a persistent human session — do not use it to
        # seed host_session, so the previous human user's window stays intact.
        if eff and eff.lower() != 'system' and e.source_host:
            host_session[e.source_host] = (eff, e.timestamp)

    # ── Session-aware attack step collection ───────────────────────────────────
    #
    # State per actor:
    #   step_actor_last[actor]  → timestamp of the most recent classified event
    #   step_actor_sid[actor]   → current session index (increments on timeout)
    # State per (actor, session):
    #   step_seen[(actor, sid)] → set of (technique_id, host) already recorded
    #
    # Algorithm (O(n) single pass):
    #   For each classified event e:
    #     1. Compute gap = e.timestamp - step_actor_last[actor]
    #     2. If gap > INACTIVITY_TIMEOUT_SECONDS → new session (sid += 1)
    #     3. Dedup check: if (tid, host) already in step_seen[(actor, sid)] → skip
    #     4. Otherwise → record step, add to step_seen

    step_actor_last: dict[tuple, object] = {}
    step_actor_sid:  dict[tuple, int]    = {}
    step_seen:       dict[tuple, set]    = defaultdict(set)

    attack_steps: list[dict] = []
    step_num = 0

    for e, eff_u in zip(sorted_events, effective_users):
        cls = _classify(e)
        if cls is None:
            continue
        tid, tname, tactic = cls

        actor  = ((eff_u or 'unknown').lower(), e.source_host or 'unknown')
        last_t = step_actor_last.get(actor)
        gap_sec = (
            (e.timestamp - last_t).total_seconds()
            if last_t is not None else float('inf')
        )

        if gap_sec > INACTIVITY_TIMEOUT_SECONDS:
            step_actor_sid[actor] = step_actor_sid.get(actor, -1) + 1

        sid = step_actor_sid.get(actor, 0)
        step_actor_last[actor] = e.timestamp

        session_key = (actor, sid)
        step_sig    = (tid, e.source_host)
        if step_sig in step_seen[session_key]:
            continue
        step_seen[session_key].add(step_sig)

        step_num += 1
        attack_steps.append({
            'step_number':    step_num,
            'timestamp':      e.timestamp.isoformat(),
            'host':           e.source_host,
            'user':           eff_u,
            'tactic':         tactic,
            'technique_id':   tid,
            'technique_name': tname,
            'description':    (e.description or '')[:200],
            'event_ids':      [e.id] if e.id else [],
            'confidence':     'high' if e.event_id else 'medium',
        })

    # ── Session-aware lateral movement paths ───────────────────────────────────
    #
    # Lateral paths use the same sliding-window session model.
    # The dedup key is (src, dst, user, session_id): the same src→dst move by
    # the same user within one session is collapsed, but a return path in a
    # later session (after a long gap) is recorded as a distinct entry.

    lat_actor_last: dict[tuple, object] = {}
    lat_actor_sid:  dict[tuple, int]    = {}
    lateral_paths:  list[dict]          = []
    seen_lateral:   set[tuple]          = set()

    for e, eff_u in zip(sorted_events, effective_users):
        if not _is_lateral(e):
            continue
        src = _extract_src(e)
        if not src:
            continue
        dst  = e.source_host
        user = eff_u or 'unknown'
        actor = (user.lower(), dst)

        last_t  = lat_actor_last.get(actor)
        gap_sec = (
            (e.timestamp - last_t).total_seconds()
            if last_t is not None else float('inf')
        )
        if gap_sec > INACTIVITY_TIMEOUT_SECONDS:
            lat_actor_sid[actor] = lat_actor_sid.get(actor, -1) + 1
        lat_actor_last[actor] = e.timestamp
        sid = lat_actor_sid.get(actor, 0)

        lat_key = (src, dst, user, sid)
        if lat_key in seen_lateral:
            continue
        seen_lateral.add(lat_key)

        desc = e.description or ''
        if e.event_id in ('5140', '5145'):
            method, tid = 'SMB Share Access', 'T1021.002'
        elif re.search(r'eternalblue|ms17-010|doublepulsar', desc, re.I):
            method, tid = 'EternalBlue/MS17-010 Exploit', 'T1210'
        elif re.search(r'wmiexec|wmic\s+/node:|win32_process.*create', desc, re.I):
            method, tid = 'WMI Remote Execution', 'T1047'
        elif re.search(r'psexec|psexesvc|smbexec', desc, re.I):
            method, tid = 'PsExec/SMBExec', 'T1021.002'
        elif re.search(r'dcomexec|MMC20\.Application|ShellWindows|ShellBrowserWindow', desc, re.I):
            method, tid = 'DCOM Remote Execution', 'T1021.003'
        elif re.search(r'tscon|rdp.*hijack|shadow.*session.*connect', desc, re.I):
            method, tid = 'RDP Session Hijacking', 'T1563.002'
        elif re.search(r'winrm|enter-pssession|invoke-command.*computername', desc, re.I):
            method, tid = 'WinRM Remote Execution', 'T1021.006'
        elif re.search(r'pass[-_]the[-_]hash|sekurlsa::pth', desc, re.I):
            method, tid = 'Pass-the-Hash', 'T1550.002'
        elif re.search(r'pass[-_]the[-_]ticket|rubeus.*ptt|kerberos::ptt', desc, re.I):
            method, tid = 'Pass-the-Ticket', 'T1550.003'
        elif e.event_id in ('4776', '8004'):
            method, tid = 'NTLM Authentication', 'T1550.002'
        elif e.event_id == '4624':
            lt = re.search(r'Logon Type:\s*(\d+)', desc, re.I)
            if lt and lt.group(1) == '10':
                method, tid = 'RDP (Remote Interactive)', 'T1021.001'
            else:
                method, tid = 'Network Logon (Type 3)', 'T1021.002'
        else:
            method, tid = 'Remote Execution', 'T1021.002'

        lateral_paths.append({
            'from_host':    src,
            'to_host':      dst,
            'user':         user,
            'method':       method,
            'timestamp':    e.timestamp.isoformat(),
            'technique_id': tid,
        })

    # ── Blast radius ───────────────────────────────────────────────────────────
    compromised_hosts = sorted({e.source_host for e in sorted_events if e.source_host})

    # Collect compromised users from the structured e.user field first.
    # Fall back to description parsing for high-signal EIDs where the username is
    # embedded in the log text rather than a dedicated field (common for 4104, 1102).
    _HIGH_SIG_EIDS = frozenset({'4104', '4688', '4624', '4625', '1102', '4672', '4698', '4720', '4769'})
    user_set: set[str] = set()
    for e, eff_u in zip(sorted_events, effective_users):
        if eff_u and not eff_u.endswith('$'):
            user_set.add(eff_u)
        elif not eff_u and e.event_id in _HIGH_SIG_EIDS:
            extracted = _extract_account_name(e.description or '')
            if extracted and not extracted.endswith('$'):
                user_set.add(extracted)
    compromised_users = sorted(user_set)

    # Accessed resources: EID 4769 exposes the Kerberos target service (e.g. MSSQLSvc);
    # EID 5140/5145 expose the SMB share name; EID 4663 exposes the object path.
    accessed_resources: list[str] = []
    for e in sorted_events:
        if e.event_id == '4769':
            m = re.search(r'Service\s+Name:\s*([^\r\n\s][^\r\n]{0,99})', e.description or '', re.IGNORECASE)
            if m:
                svc = m.group(1).strip().rstrip('.')
                if svc and svc not in ('-', '$krbtgt') and svc not in accessed_resources:
                    accessed_resources.append(svc)
        elif e.event_id in ('4663', '5140', '5145'):
            res = _extract_resource(e.description or '')
            if res and res not in accessed_resources:
                accessed_resources.append(res)

    persistence_steps = [s for s in attack_steps if s['tactic'] == 'Persistence']
    persistence_mechanisms = list(dict.fromkeys(s['technique_name'] for s in persistence_steps))

    # When no explicit persistence EID was logged, infer prior persistent access from
    # the anti-forensic cleanup combo: audit log clearing (T1070.001) + VSS deletion (T1490).
    # Attackers perform this cleanup *after* establishing persistence.
    if not persistence_mechanisms:
        evasion_tids = {s['technique_id'] for s in attack_steps if s['tactic'] == 'Defense Evasion'}
        impact_tids  = {s['technique_id'] for s in attack_steps if s['tactic'] == 'Impact'}
        if 'T1070.001' in evasion_tids and 'T1490' in impact_tids:
            persistence_mechanisms.append(
                'Inferred: audit log clearing + VSS deletion indicates prior persistent access'
            )

    # ── Tactic progression ─────────────────────────────────────────────────────
    tactics_seen = dict.fromkeys(s['tactic'] for s in attack_steps)
    tactic_progression = [t for t in TACTIC_ORDER if t in tactics_seen]

    # ── Entry vector / patient zero host ──────────────────────────────────────
    # Priority 1 — explicit Initial Access step from pattern matching
    # Priority 2 — earliest lateral path arriving from a non-RFC-1918 source IP
    #              (indicates the external beachhead host)
    # Priority 3 — earliest classified attack step chronologically
    _RFC1918 = re.compile(
        r'^(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+'
        r'|192\.168\.\d+\.\d+|127\.\d+\.\d+\.\d+|::1|-)$'
    )

    entry_vector     = 'Unknown'
    patient_zero_host = ''

    for s in attack_steps:
        if s['tactic'] == 'Initial Access':
            actor_str = f" (user: {s['user']})" if s['user'] else ''
            entry_vector     = f"{s['technique_name']} on {s['host']}{actor_str} at {s['timestamp'][:16]}"
            patient_zero_host = s['host'] or ''
            break

    if entry_vector == 'Unknown' and lateral_paths:
        for lp in lateral_paths:
            src = lp.get('from_host', '')
            if src and not _RFC1918.match(src):
                patient_zero_host = lp['to_host']
                entry_vector = (
                    f"External connection from {src} → {lp['to_host']} "
                    f"via {lp['method']} (user: {lp['user']}) at {lp['timestamp'][:16]}"
                )
                break

    if entry_vector == 'Unknown' and attack_steps:
        first             = attack_steps[0]
        actor_str         = f" (user: {first['user']})" if first['user'] else ''
        entry_vector      = f"{first['technique_name']} on {first['host']}{actor_str} at {first['timestamp'][:16]}"
        patient_zero_host = first['host'] or ''

    # ── Threat actor profile ───────────────────────────────────────────────────
    tids_seen  = {s['technique_id'] for s in attack_steps}
    names_seen = {s['technique_name'] for s in attack_steps}

    has_cobalt      = any(
        re.search(r'\bmsse-\d+|createremotethread', e.description or '', re.I)
        for e in sorted_events
    )
    has_kerberoast  = 'T1558.003' in tids_seen
    has_asrep       = 'T1558.004' in tids_seen
    has_dcsync      = 'T1003.006' in tids_seen
    has_golden      = 'T1558.001' in tids_seen
    has_silver      = 'T1558.002' in tids_seen
    has_pth         = 'T1550.002' in tids_seen
    has_ptt         = 'T1550.003' in tids_seen
    has_skeleton    = 'T1207' in tids_seen
    has_ntlm_relay  = 'T1557.001' in tids_seen
    has_recon       = any(t in tids_seen for t in ('T1069.002', 'T1087.002', 'T1046'))
    has_lateral     = any(s['tactic'] == 'Lateral Movement' for s in attack_steps)
    n_persist       = len(persistence_mechanisms)
    n_lateral_hosts = len({p['to_host'] for p in lateral_paths})

    if has_skeleton:
        actor_profile = (
            'APT — Domain persistence via Skeleton Key implant detected. '
            'Attacker can authenticate as any domain user without knowing their password.'
        )
    elif has_cobalt:
        actor_profile = 'APT — Cobalt Strike C2 (MSSE named pipe / CreateRemoteThread injection confirmed)'
    elif has_kerberoast and has_dcsync and has_golden:
        actor_profile = (
            'APT — Full AD domain compromise chain: '
            'Kerberoasting → DCSync (NTDS extraction) → Golden Ticket forged. '
            'Attacker has indefinite domain persistence.'
        )
    elif has_kerberoast and has_dcsync:
        actor_profile = 'APT — AD credential theft: Kerberoasting + DCSync (NTDS extraction)'
    elif has_ntlm_relay and (has_pth or has_ptt):
        actor_profile = (
            'APT — NTLM relay attack with credential forwarding: '
            f'{n_lateral_hosts} host(s) reached via Pass-the-Hash / Pass-the-Ticket'
        )
    elif (has_pth or has_ptt) and n_lateral_hosts >= 3:
        actor_profile = (
            f'APT — Credential-based lateral movement: '
            f'{n_lateral_hosts} hosts compromised via '
            f'{"Pass-the-Hash" if has_pth else "Pass-the-Ticket"}'
        )
    elif has_asrep and has_lateral:
        actor_profile = 'APT — AS-REP Roasting followed by lateral movement using harvested credentials'
    elif has_golden or has_silver:
        ticket_type = 'Golden' if has_golden else 'Silver'
        actor_profile = (
            f'APT — {ticket_type} Ticket attack: forged Kerberos ticket grants '
            f'persistent access without domain credentials'
        )
    elif has_recon and has_kerberoast:
        actor_profile = 'APT — AD reconnaissance (BloodHound/LDAP) followed by Kerberoasting'
    elif n_persist >= 4:
        actor_profile = f'Persistent threat actor — {n_persist} distinct persistence mechanisms deployed'
    elif 'Exploitation for Privilege Escalation' in names_seen:
        actor_profile = 'Threat actor exploiting unpatched vulnerability for privilege escalation'
    elif 'Bypass User Account Control' in names_seen and n_persist >= 2:
        actor_profile = 'Insider or post-initial-access actor — UAC bypass + persistence'
    else:
        actor_profile = 'Threat actor profile requires additional corroborating evidence'

    confidence = 'high' if len(attack_steps) >= 5 else ('medium' if len(attack_steps) >= 2 else 'low')

    return {
        'threat_actor_profile':  actor_profile,
        'entry_vector':          entry_vector,
        'patient_zero_host':     patient_zero_host,
        'tactic_progression':    tactic_progression,
        'attack_steps':          attack_steps,
        'lateral_paths':         lateral_paths,
        'blast_radius': {
            'compromised_hosts':       compromised_hosts,
            'compromised_users':       compromised_users,
            'accessed_resources':      accessed_resources,
            'estimated_data_at_risk':  (
                f"{len(accessed_resources)} resource(s) accessed across "
                f"{len(compromised_hosts)} host(s)"
            ),
            'persistence_mechanisms':  persistence_mechanisms,
        },
        'total_duration_minutes': round(duration_minutes, 1),
        'confidence':             confidence,
        'total_attack_steps':     len(attack_steps),
        'total_lateral_paths':    len(lateral_paths),
    }


def _empty() -> dict:
    return {
        'threat_actor_profile':   '',
        'entry_vector':           '',
        'patient_zero_host':      '',
        'tactic_progression':     [],
        'attack_steps':           [],
        'lateral_paths':          [],
        'blast_radius': {
            'compromised_hosts':      [],
            'compromised_users':      [],
            'accessed_resources':     [],
            'estimated_data_at_risk': '',
            'persistence_mechanisms': [],
        },
        'total_duration_minutes': 0.0,
        'confidence':             'low',
        'total_attack_steps':     0,
        'total_lateral_paths':    0,
    }
