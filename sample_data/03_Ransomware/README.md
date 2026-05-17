# 03_Ransomware — Ransomware Deployment and Impact

## Scenario Overview

Attacker gains initial access via RDP brute-force against `Administrator` on DC-01
from external IP `185.234.219.42`. After successful logon, the actor deploys
ransomware, disables recovery mechanisms, deletes shadow copies, and encrypts files.

## Environment

| Host | Role |
|---|---|
| DC-01 | Domain Controller — initial RDP target |
| FILESERVER-01 | File server — encryption target |
| 185.234.219.42 | Attacker IP (external) |

## Attack Timeline (2024-11-15)

- 06:12–06:47 — RDP brute-force: repeated EID 4625 Type-10 failures against `Administrator`
- 06:48 — Successful RDP logon (EID 4624 Type-10) from attacker IP
- 07:10 — `vssadmin delete shadows /all` — shadow copy deletion (T1490)
- 07:12 — `bcdedit /set {default} recoveryenabled no` — boot recovery disabled
- 07:15 — Ransomware binary dropped and executed; file encryption begins
- 07:30 — Security event log cleared (EID 1102)

## Format

Single JSONL file: `scenario_ransomware.jsonl`  
Sources: Windows Security (EID 4624/4625/1102/4688), Sysmon (EID 1/11)

## Expected Detections

**MITRE coverage:** T1110.003 (Brute Force) → T1078 (Valid Accounts) → T1490 (Inhibit Recovery) →
T1486 (Data Encrypted for Impact) → T1070.001 (Event Log Clearing)

**Rules expected:** LAT-012 (RDP Brute Force), PERS-005 (Event Log Cleared), PERS-010 (Shadow Copy Deletion)

**Behavioral rules expected:** `auth_failure_burst`, `rdp_lateral_movement`, `boot_recovery_disabled`,
`shadow_copy_deletion`

**Severity:** CRITICAL (ransomware triad: vssadmin + bcdedit + T1490)
