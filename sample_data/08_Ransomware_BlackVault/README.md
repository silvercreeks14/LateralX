# 08_Ransomware_BlackVault — Healthcare Ransomware (MEDHEALTHCARE)

## Scenario Overview

Attacker brute-forces NTLM credentials for `jdavis` against the RDP Gateway
(`RDP-GW-01`) at MEDHEALTHCARE. After successful authentication, they use mshta.exe
to load a remote HTA file, drop a payload via encoded PowerShell, and move laterally
to an application server using a service account (`svc-app`). Four separate log
sources record the full chain from perimeter to internal pivot.

## Environment

| Host | Role |
|---|---|
| RDP-GW-01 | RDP Gateway — initial victim (jdavis) |
| DC-01 | Domain Controller (MEDHEALTHCARE) |
| APPSERVER-01 | Application server — lateral movement target |
| 45.129.56.200 | Attacker IP (external) |

## Attack Timeline (2024-11-20 – 2024-11-21)

- 23:15–23:21 — NTLM credential brute force: repeated EID 4776 failures for `jdavis` from `45.129.56.200`
- 23:xx — Successful authentication (implied by subsequent access)
- 23:51 — Sysmon EID 1: `mshta.exe` spawned by `explorer.exe`, loading `http://45.129.56.200/lnk.hta`
- 23:51 — Sysmon EID 1: PowerShell IEX (base64-encoded command) spawned by mshta
- 23:51 — Sysmon EID 3: PowerShell C2 callback to `91.108.4.190:443`
- 23:51 — Sysmon EID 11: `svcupd.exe` dropped in `%TEMP%`
- 00:10 — EID 4624 Type-3 + EID 4672: `svc-app` network logon to APPSERVER-01 (elevated NTLM)
- 00:10 — EID 4688: `wmiprvse.exe` spawned; `cmd.exe /c whoami` confirms code execution on APPSERVER-01

## Format

Multi-source, mixed formats:

| File | Source | Format |
|---|---|---|
| `dc_auth_events.jsonl` | Windows Security (DC-01) | JSONL |
| `endpoint_sysmon.csv` | Sysmon (RDP-GW-01) | CSV |
| `server_security_events.csv` | Windows Security (APPSERVER-01) | CSV |
| `perimeter_firewall.csv` | Perimeter firewall | CSV |

## Expected Detections

**MITRE coverage:** T1110.003 (Credential Brute Force) → T1218.005 (mshta LOLBAS) →
T1059.001 (PowerShell IEX) → T1105 (Ingress Tool Transfer) → T1021.001 (RDP) →
T1078 (Valid Accounts — service account lateral)

**Rules expected:** LAT-012 (RDP Brute Force), LAT-006 (Admin Network Logon)

**Behavioral rules expected:** `auth_failure_burst`, `rdp_lateral_movement`, `certutil_download`

**Severity:** HIGH — credential theft leading to domain lateral movement in a healthcare environment.
