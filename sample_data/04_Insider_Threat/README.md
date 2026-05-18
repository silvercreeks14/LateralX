# 04_Insider_Threat — Insider Data Exfiltration

## Scenario Overview

Disgruntled employee `hsmith` (HR department) accesses and exfiltrates sensitive
data from multiple file shares (HR, Finance, Legal, Payroll) after hours. Uses
legitimate credentials and built-in tools to avoid detection — no malware involved.
Classic insider threat: authorized access, unauthorized intent.

## Environment

| Host | Role |
|---|---|
| WORKSTATION-03 | hsmith's workstation |
| HRSERVER-01 | HR data server |
| FILESERVER-01 | Finance, Legal, Payroll shares |
| C2 / Upload | External cloud storage (HTTPS upload) |

## Attack Timeline (2024-11-22)

- 22:14 — Off-hours interactive logon (EID 4624 Type-2) — hsmith normally works 08:00–17:30
- 22:15 — `net use` maps H:, I:, J:, K: to four sensitive network shares simultaneously
- 22:16 — EID 4624 Type-3 logons to HRSERVER-01 and FILESERVER-01
- 22:20 — Bulk file copy (xcopy/robocopy) — thousands of files
- 22:45 — `certutil -encode` used to encode sensitive files (LOLBin staging)
- 22:55 — Large outbound HTTPS upload to cloud storage (`bytes_out: 2.3 GB`)

## Format

Single JSONL file: `scenario_insider_exfil.jsonl`  
Sources: Windows Security (EID 4624/4634/5140/5145), Sysmon (EID 1/3/11)

## Expected Detections

**MITRE coverage:** T1078 (Valid Accounts) → T1039 (Data from Network Shared Drive) →
T1005 (Local Data Staging) → T1041 (Exfiltration over C2 Channel)

**Behavioral rules expected:** `off_hours_privilege`, `smb_lateral_movement`, `certutil_download`,
`lateral_velocity`

**Note:** This scenario deliberately avoids attack tooling. Severity will be MEDIUM
without privilege escalation signals. Use it to test behavioral baseline detection.
