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

## Real Datasets Added (fetch_real_datasets.py)
`otrf_empire_psexec_real.jsonl` - OTRF Empire PsExec lateral real capture.
`otrf_empire_mimikatz_sam_real.jsonl` - OTRF Mimikatz SAM access real capture.
Source: OTRF/Security-Datasets atomic/windows (MIT License).
