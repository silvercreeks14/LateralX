# 06_Windows_Techniques — Isolated Windows Attack Technique Files

## Scenario Overview

Four focused event files, each demonstrating a specific Windows attack technique or
technique family in isolation. Use these to test individual detection rules and verify
MITRE technique tagging before loading full multi-phase scenarios.

## Files

| File | Technique | MITRE | Key Event |
|---|---|---|---|
| `scenario_lolbas.jsonl` | LOLBAS initial access via mshta.exe | T1218.005 | Outlook spawns mshta → PowerShell IEX → encoded payload |
| `scenario_privilege_escalation_windows.jsonl` | UAC bypass via fodhelper.exe | T1548.002 | HKCU ms-settings registry hijack; fodhelper spawns elevated cmd |
| `scenario_persistence_wmi.jsonl` | WMI event subscription persistence | T1546.003 | `__EventFilter` + `CommandLineEventConsumer` in root\subscription namespace |
| `scenario_windows_attack.jsonl` | Mixed Windows attacker tradecraft | Multiple | certutil decode, encoded PowerShell, RC4 Kerberos, lateral Type-3 logon |

## Environment

| Host | User | Technique file |
|---|---|---|
| WORKSTATION-02 | alice | scenario_lolbas.jsonl |
| WORKSTATION-08 | ltorres | scenario_privilege_escalation_windows.jsonl |
| WORKSTATION-09 | amorris | scenario_persistence_wmi.jsonl |
| WORKSTATION-01/02, DC-01, FILESERVER-01 | jdoe, alice, svc_backup | scenario_windows_attack.jsonl |

## Format

All files: JSONL  
Sources: Windows Security (EID 4624/4625/4663/4672/4688/4769), Sysmon (EID 1/3)

## Expected Detections

**MITRE coverage:** T1218.005 (mshta) · T1548.002 (UAC bypass) · T1546.003 (WMI persistence) ·
T1059.001 (PowerShell IEX) · T1027 (Obfuscated Command) · T1558.003 (Kerberoasting) ·
T1110.001 (Credential Brute Force)

**Behavioral rules expected:** `certutil_download`, `off_hours_privilege`, `lateral_velocity`,
`auth_failure_burst`

**Note:** These files are not connected scenarios. Each covers a specific gap in the AD
full-chain scenarios (folders 01–04 and 07–11). Import individually to test one rule at
a time; do not combine into a single case.
