# Scenario 13: Wizard Spider ATT&CK Evaluation (Round 4)

Synthetic multi-stage scenario modelled on publicly documented Wizard Spider (GOLD BLACKBURN / Ryuk) tradecraft from MITRE ATT&CK Evaluations Enterprise Round 4 (2022).

Ground truth for this scenario is derived exclusively from the public MITRE evaluation procedure document — independent of the LateralX rule authors — to validate Layer B behavioral rules against externally-authored adversary specifications.

## Data Source

**MITRE Engenuity ATT&CK Evaluations Enterprise — Wizard Spider + Sandworm (2022)**
URL: https://attackevals.mitre-engenuity.org/enterprise/wizard-spider-sandworm
License: Public evaluation procedure document, freely available

This scenario models the Wizard Spider operator phases from Steps 1–19 of the MITRE evaluation procedure, covering initial access via PowerShell stager (Cobalt Strike Beacon), credential dumping via Mimikatz, SMB lateral movement with pass-the-hash, and Ryuk ransomware deployment with recovery inhibition.

## Environment

- Victim user: `tbryant` (no EID 4768 Kerberos TGT — Cobalt Strike uses NTLM/PTH throughout)
- Domain: `corp.local`
- Hosts: WORKSTATION-01, FILE-SERVER-01, APP-SERVER-01, DC-01, BACKUP-SERVER-01

## Attack Chain

| Phase | File | MITRE Technique | ATT&CK ID | Expected Detection |
|-------|------|-----------------|-----------|-------------------|
| Initial Access | `01_initial_access.jsonl` | PowerShell encoded stager (Cobalt Strike) | T1059.001 | `encoded_powershell` |
| Credential Dump | `02_credential_dump.jsonl` | LSASS dump via Cobalt Strike Mimikatz | T1003.001 | `mimikatz_invocation` |
| Lateral Movement | `03_lateral_movement.jsonl` | SMB lateral + Pass-the-Hash (Cobalt Strike) | T1021.002, T1550.002 | `smb_lateral_movement`, `lateral_velocity`, `pass_the_hash` |
| Ransomware Prep | `04_ransomware_prep.jsonl` | Recovery inhibition (bcdedit + vssadmin) | T1490 | `ransomware_recovery_destruction`, `shadow_copy_deletion`, `boot_recovery_disabled` |
| Defense Evasion | `05_evasion.jsonl` | Event log clearing (wevtutil) | T1070.001 | `event_log_clearing` |

## Expected Detections (9 total)

```
encoded_powershell
mimikatz_invocation
smb_lateral_movement
lateral_velocity
pass_the_hash
ransomware_recovery_destruction
shadow_copy_deletion
boot_recovery_disabled
event_log_clearing
```

## Key Differences from OTRF Empire Baseline

- Wizard Spider uses Cobalt Strike Beacon, not Empire PowerShell agent
- Lateral movement is NTLM-based PTH (no Kerberos TGT) — `tbryant` has no EID 4768 in dataset
- Ryuk ransomware prep (bcdedit + vssadmin) exercises anti-recovery rules not present in Empire captures
- Log clearing via `wevtutil cl` rather than Empire's `Clear-EventLog` PowerShell cmdlet

## Validation Notes

This scenario reduces the Layer B testing paradox (Gap 3) identified in eval analysis:
the ground truth comes from MITRE's public adversary emulation procedure document,
not from the same team that authored the behavioral rules. All 9 expected detections
fire (F1=1.000) on eval run 2026-05-18.
