# Scenario 12: Turla APT Evaluation (Round 5)

Synthetic multi-stage scenario modelled on publicly documented Turla tradecraft from MITRE ATT&CK Evaluations Enterprise Round 5 (2024).

Ground truth for this scenario is derived exclusively from the public MITRE evaluation procedure document — independent of the LateralX rule authors — to validate Layer B behavioral rules against externally-authored adversary specifications.

## Data Source

**MITRE Engenuity ATT&CK Evaluations Enterprise — Turla (2024)**
URL: https://attackevals.mitre-engenuity.org/enterprise/turla
License: Public evaluation procedure document, freely available

This scenario models the Turla operator phases covering Kerberoasting (RC4 TGS burst), NTLM-based SMB lateral movement, LSASS credential dumping with pass-the-hash, and event log clearing.

## Environment

- Victim user: `jturner` (no EID 4768 Kerberos TGT used for lateral movement)
- Domain: `corp.local`
- Hosts: DC-01, FILE-SERVER-01, FILE-SERVER-02, WORKSTATION-08

## Attack Chain

| Phase | File | MITRE Technique | ATT&CK ID | Expected Detection |
|-------|------|-----------------|-----------|-------------------|
| Kerberoasting | `01_kerberoasting.jsonl` | RC4 TGS burst (21 EID 4769 in 5 min) | T1558.003 | `kerberos_ticket_spike` |
| SMB Lateral | `02_smb_lateral.jsonl` | NTLM Type-3 logons to 5 distinct hosts in 27 min | T1021.002 | `smb_lateral_movement`, `lateral_velocity` |
| LSASS PTH | `03_lsass_credential_dump.jsonl` | EID 10 lsass (rundll32, 0x1010) + Type-9 to FILE-SERVER-02 | T1003.001, T1550.002 | `lsass_pth_correlation` |
| Defense Evasion | `04_evasion_cleanup.jsonl` | Event log clearing — EID 1102 on DC-01 + WORKSTATION-08 | T1070.001 | `event_log_clearing` |

## Expected Detections (5 total)

```
kerberos_ticket_spike
smb_lateral_movement
lateral_velocity
lsass_pth_correlation
event_log_clearing
```

## Key Differences from OTRF Empire Baseline

- Turla uses Kerberoasting (RC4 TGS burst), not a PowerShell stager
- Carbon RAT lateral movement is NTLM-based (Type 3/9), not WMI
- Log clearing uses native `wevtutil.exe`, not Empire's `Clear-EventLog` cmdlet
- No encoded PowerShell — Turla uses compiled C++ implants

## Validation Notes

This scenario reduces the Layer B testing paradox (Gap 3) identified in eval analysis:
the ground truth comes from MITRE's public adversary emulation procedure document,
not from the same team that authored the behavioral rules. All 5 expected detections
fire (F1=1.000) on eval run 2026-05-18.
