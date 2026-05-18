# APT29-Style AD Full Attack Chain — Scenario Files

## Overview
A realistic full-chain Active Directory attack scenario modeled on the CISA/NSA APT29 advisory
(AA21-116A) and supplemented with real log patterns from:
- **EVTX-ATTACK-SAMPLES** (SBousseaden/EVTX-ATTACK-SAMPLES, GitHub)
- **DetectionLab** (clong/DetectionLab, GitHub)
- **OTRF Security Datasets** (OTRF/Security-Datasets, GitHub)
- **APT29 CISA AA21-116A advisory** (public IOC/TTPs)
- **Windows Advanced Audit Policy event patterns** from Microsoft docs

## Attack Chain Summary

| Phase | MITRE Tactic | Key Technique | Log File | Format |
|-------|-------------|--------------|----------|--------|
| 1. Initial Access | Initial Access | Spearphishing + macro dropper | `01_initial_access_plaso.csv` | Plaso L2T CSV |
| 2. Reconnaissance | Discovery | BloodHound + nltest domain enum | `02_recon_sysmon.csv` | Sysmon CSV |
| 3. Credential Access | Credential Access | Kerberoasting + AS-REP Roasting | `03_kerberoasting_winlog.json` | Timesketch JSON |
| 4. Privilege Escalation | Privilege Escalation | DCSync + LSASS dump | `04_privesc_winlog.json` | Timesketch JSONL |
| 5. Lateral Movement | Lateral Movement | PsExec + Pass-the-Hash + RDP | `05_lateral_movement_sysmon.csv` | Sysmon CSV |
| 6. Persistence | Persistence | Scheduled task + registry autorun + service | `06_persistence_winlog.json` | Timesketch JSON |
| 7. Exfiltration / Impact | Collection + Exfiltration | NTDS.dit extraction + shadow copy deletion | `07_exfiltration_network.csv` | Network Flow CSV |

## Environment
- **Domain**: CORP.LOCAL (192.168.10.0/24)
- **DC**: DC01 (192.168.10.10), DC02 (192.168.10.11)
- **Workstations**: WS01 (192.168.10.101), WS02 (192.168.10.102), WS03 (192.168.10.103)
- **Server**: SRV-FILE01 (192.168.10.50), SRV-EXCH01 (192.168.10.51)
- **Attacker**: 185.220.101.47 (initial), pivoting via internal hosts

## Actors
- **jsmith** — compromised helpdesk user (initial victim)
- **svc_backup** — service account kerberoasted (cracked password)
- **mrodriguez** — IT admin lateral movement target
- **dadmin** — Domain Admin — attacker ultimately impersonates via DCSync

## Expected Detections (by rule)
RECON-001, RECON-003, RECON-005, RECON-007, RECON-008, RECON-011,
KERB-001, KERB-002, KERB-003, KERB-004, KERB-005, KERB-008, KERB-010,
DCS-001, DCS-002, DCS-006, DCS-007, DCS-010,
LAT-001, LAT-002, LAT-003, LAT-005, LAT-006, LAT-007,
PRIV-001, PRIV-003, PRIV-008,
PERS-002, PERS-003, PERS-004, PERS-005,
TOOL-001, TOOL-002, TOOL-003
