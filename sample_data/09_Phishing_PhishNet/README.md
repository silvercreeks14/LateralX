# 09_Phishing_PhishNet — Macro Phishing → Credential Theft → Lateral Movement

## Scenario Overview

User `jsmith` on WORKSTATION-03 opens a malicious Word document that triggers a macro.
The macro spawns wscript → cmd → PowerShell IEX, downloads a C2 agent (`stage2.exe`),
runs Mimikatz via rundll32, and uses harvested credentials to authenticate laterally to
FILE-SERVER-01. The firewall log shows the attacker's initial scan attempts being blocked
before the victim's outbound C2 beacon succeeds.

## Environment

| Host | Role |
|---|---|
| WORKSTATION-03 | jsmith's workstation — initial victim |
| FILE-SERVER-01 | File server — lateral movement target (10.0.1.5) |
| 185.199.110.55 | Attacker C2 (external) |

## Attack Timeline (2025-01-14)

- 09:08–09:11 — Firewall blocks inbound scan from attacker (ports 80/445/443) — pre-attack reconnaissance
- 09:12 — EID 4688: `WINWORD.EXE` spawns `wscript.exe` (macro execution)
- 09:12 — EID 4688: wscript → `cmd.exe /c`
- 09:12 — EID 4688: cmd → `powershell.exe -encodedcommand` (IEX download stager)
- 09:13 — EID 4688: PowerShell drops and runs `stage2.exe -c 185.199.110.55`
- 09:13 — EID 4672: `SeDebugPrivilege` + `SeImpersonatePrivilege` assigned to stage2.exe
- 09:14 — EID 4688: `rundll32.exe … mimi.dll sekurlsa::logonpasswords` (Mimikatz credential dump)
- 09:15 — EID 4688: `net user`, `net view`, `ping` — domain reconnaissance
- 09:16 — EID 4625 ×3: failed logins (password spray attempt) before credential use
- 09:22 — EID 4624 Type-3 + EID 4672: jsmith lateral logon to FILE-SERVER-01 (NTLM, elevated)
- 09:27 — Firewall: 3 × 15 MB outbound HTTPS flows from FILE-SERVER-01 to C2 (~45 MB exfil)

## Format

Two-source CSV:

| File | Source | Format |
|---|---|---|
| `endpoint_events.csv` | Windows Security + Sysmon (WORKSTATION-03 / FILE-SERVER-01) | CSV |
| `firewall_events.csv` | Perimeter firewall | CSV |

## Expected Detections

**MITRE coverage:** T1566.001 (Spearphishing Attachment) → T1059.005 (VBScript) →
T1059.001 (PowerShell IEX) → T1003.001 (LSASS / Mimikatz) → T1021.002 (SMB Lateral) →
T1041 (Exfiltration over C2)

**Rules expected:** TOOL-002 (Mimikatz/CS), DCS-006 (LSASS), LAT-002 (Admin Share), LAT-006

**Behavioral rules expected:** `auth_failure_burst`, `smb_lateral_movement`, `certutil_download`

**Severity:** CRITICAL — Mimikatz + lateral movement + data exfiltration triad.
