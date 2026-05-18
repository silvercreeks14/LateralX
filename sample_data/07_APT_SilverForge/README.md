# 07_APT_SilverForge — Multi-Source APT Campaign (NEXCORP)

## Scenario Overview

Simulated APT campaign against NEXCORP.LOCAL. An external actor gains initial network
access via an employee workstation (`mwilson`, WS-FIN01), moves laterally using stolen
credentials, performs DCSync against DC-01, creates a persistent backdoor domain admin
account, and clears the audit log before exiting. Spans two days of telemetry across
four log sources.

## Environment

| Host | Role |
|---|---|
| DC-01 | Domain Controller (NEXCORP.LOCAL) |
| WS-HR01 | jsmith's workstation |
| WS-FIN01 | mwilson's workstation — initial victim |
| WS-IT01 | itadmin's workstation — lateral target |
| FILESERVER-01 | File server — lateral pivot |
| 185.220.101.45 | Attacker C2 (external) |

## Attack Timeline (2024-11-12 – 2024-11-13)

- 07:xx — Normal morning logons (jsmith, mwilson, itadmin) — baseline noise
- 14:28 — Outbound connection from mwilson (WS-FIN01) to attacker C2 `185.220.101.45:80`
- 14:30 — C2 beacon established (repeated HTTPS to same IP)
- Day 2, 09:05 — EID 4662: `mwilson` triggers DCSync (`DS-Replication-Get-Changes-All`)
- Day 2, 09:10 — EID 4672: SeDebugPrivilege + SeImpersonatePrivilege assigned to mwilson
- Day 2, 10:00 — EID 4720/4728: backdoor account `backdoor_svc` created and added to Domain Admins
- Day 2, 16:00 — EID 1102: Security audit log cleared by mwilson

## Format

Multi-source, mixed formats:

| File | Source | Format |
|---|---|---|
| `dc01_security_events.jsonl` | Windows Security (DC-01) | JSONL |
| `sysmon_endpoint.jsonl` | Sysmon (all endpoints) | JSONL |
| `fileserver_winlogs.csv` | Windows Security (FILESERVER-01) | CSV |
| `firewall_netflow.csv` | Perimeter firewall | CSV |

## Expected Detections

**MITRE coverage:** T1071.001 (C2 via HTTPS) → T1003.006 (DCSync) → T1136.002 (Domain Account
Created) → T1098 (Account Manipulation) → T1070.001 (Event Log Clearing)

**Rules expected:** DCS-001, DCS-002, PERS-002, PERS-005, LAT-006

**Behavioral rules expected:** `smb_lateral_movement`, `lateral_velocity`, `off_hours_privilege`

**Note:** Use this scenario to test multi-source correlation. Events across the four files
must be joined by hostname and timestamp to reconstruct the full kill chain. Baseline
morning traffic in `firewall_netflow.csv` is intentional — it exercises FP suppression.
