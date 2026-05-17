# Scenario 14: Carbanak+FIN7 ATT&CK Evaluation (Round 3)

Synthetic multi-stage scenario modelled on publicly documented Carbanak (FIN7) tradecraft from MITRE ATT&CK Evaluations Enterprise Round 3 (2021).

Ground truth for this scenario is derived exclusively from the public MITRE evaluation procedure document — independent of the LateralX rule authors — to validate Layer B behavioral rules against externally-authored adversary specifications.

## Data Source

**MITRE Engenuity ATT&CK Evaluations Enterprise — Carbanak+FIN7 (2021)**
URL: https://attackevals.mitre-engenuity.org/enterprise/carbanak-fin7
License: Public evaluation procedure document, freely available

This scenario models the Carbanak operator phases covering WMI-based lateral execution, LSASS credential dumping, pass-the-hash lateral movement, SMB/RDP lateral movement, scheduled task persistence, and event log clearing.

## Environment

- Victim user: `dbouchard` (no EID 4768 Kerberos TGT — Carbanak uses NTLM/PTH throughout)
- Domain: `corp.local`
- Hosts: WORKSTATION-05, FILE-SERVER-01, APP-SERVER-01, DC-01
- Attacker process: `carbanak.exe` (NOT in `_T1003_SAFE_SOURCES` — allows lsass_pth_correlation to fire)

## Attack Chain

| Phase | File | MITRE Technique | ATT&CK ID | Expected Detection |
|-------|------|-----------------|-----------|-------------------|
| WMI Lateral | `01_wmi_lateral.jsonl` | WMI remote execution (cmd.exe child of wmiprvse.exe) | T1047 | `wmi_shell_spawn` |
| LSASS Dump | `02_lsass_dump.jsonl` | LSASS process access (carbanak.exe, GrantedAccess 0x1010) | T1003.001 | `lsass_pth_correlation` (correlates with phase 3) |
| PTH Lateral | `03_pth_lateral.jsonl` | Pass-the-Hash — NTLM Type-9 logon without prior Kerberos TGT | T1550.002 | `lsass_pth_correlation`, `pass_the_hash` |
| SMB+RDP | `04_smb_rdp_lateral.jsonl` | SMB Type-3 + RDP Type-10 lateral movement | T1021.002, T1021.001 | `smb_lateral_movement`, `rdp_lateral_movement`, `lateral_velocity` |
| Persistence | `05_persistence.jsonl` | Scheduled task creation (EID 4698) | T1053.005 | Layer A only: T1053.005 text pattern |
| Defense Evasion | `06_evasion.jsonl` | Event log clearing (wevtutil + EID 1102) | T1070.001 | `event_log_clearing` |

## Expected Detections (7 total — Layer B behavioral)

```
wmi_shell_spawn
lsass_pth_correlation
pass_the_hash
smb_lateral_movement
rdp_lateral_movement
lateral_velocity
event_log_clearing
```

Note: Phase 5 (`05_persistence.jsonl`) is detected by Layer A text-pattern matching only
(T1053.005 mapped from "scheduled task was created" / "task name:" keywords in EID 4698).
It is not counted in Layer B ground truth as no behavioral sequence rule covers it.

## Key Differences from OTRF Empire Baseline

- Carbanak uses its own compiled implant (`carbanak.exe`), not Empire PowerShell agent
- WMI lateral execution: EID 1 `ParentImage=wmiprvse.exe` → `Image=cmd.exe` fires `wmi_shell_spawn`
- LSASS access uses `carbanak.exe` (not in `_T1003_SAFE_SOURCES`) at `GrantedAccess=0x1010`
- No Kerberos TGT (EID 4768) for `dbouchard` — all lateral is NTLM-based PTH
- Uses both SMB (Type-3) and RDP (Type-10) lateral movement in the same session
- EID 4698 scheduled task persistence exercises the T1053.005 keyword added to cover
  real Windows event format (not just schtasks.exe command-line events)

## Validation Notes

This scenario reduces the Layer B testing paradox (Gap 3) identified in eval analysis:
the ground truth comes from MITRE's public adversary emulation procedure document,
not from the same team that authored the behavioral rules. All 7 expected Layer B
detections fire (F1=1.000) on eval run 2026-05-18.
