# 02_APT_Cobalt_Strike — Cobalt Strike C2 Beacon Campaign

## Scenario Overview

APT actor delivers a Cobalt Strike stager via a spear-phishing macro document to
`bcooper` on WORKSTATION-04. PowerShell downloads the staged beacon, injects it
into a hollow `rundll32.exe`, and communicates via the default named pipe
(`MSSE-1337-server`). The actor then escalates privileges, performs credential
access, and moves laterally across the domain.

## Environment

| Host | Role |
|---|---|
| WORKSTATION-04 | Initial victim — bcooper / Finance |
| DC-01 | Domain Controller |
| FILESERVER-01 | File server — lateral pivot target |
| C2 | 45.33.32.156 (external) |

## Attack Timeline (2024-10-15)

- 09:32 — `WINWORD.EXE` opens macro-enabled document, spawns PowerShell stager  
- 09:32 — PowerShell IEX downloads beacon from `45.33.32.156:443`  
- 09:33 — Hollow `rundll32.exe` created; Cobalt Strike beacon loaded via reflective DLL injection  
- 09:33 — Named pipe `MSSE-1337-server` created; svchost.exe connects (process injection)  
- 09:45 — Credential access: LSASS process-access (Sysmon EID 10) for token impersonation  
- 10:00 — SMB lateral movement to FILESERVER-01 using injected credentials  

## Format

Single JSONL file: `scenario_c2_cobalt_strike.jsonl`  
Sources: Sysmon (EID 1/3/10/17/18), Windows Security (EID 4624/4672/4688)

## Expected Detections

**MITRE coverage:** T1566 (Phishing) → T1059.001 (PowerShell IEX) → T1218 (Signed Binary Proxy) →
T1055 (Process Injection) → T1003.001 (LSASS access) → T1021.002 (SMB lateral)

**Rules expected:** TOOL-002 (Mimikatz/CS), LAT-002 (Admin Share), DCS-006 (LSASS),
PRIV-003 (SeDebugPrivilege), LAT-006 (Admin Network Logon)
