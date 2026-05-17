# 10_WebShell_WebDoor — IIS Web Shell → SQL Server Data Theft

## Scenario Overview

Attacker probes a retail company's IIS web server (`WEB-SERVER-01`) from external IP
`91.234.55.12`. After blocked RDP/SSH attempts, they exploit a web vulnerability to
achieve code execution via `w3wp.exe → cmd.exe`. They download a SQL client via
`certutil`, pivot laterally to `DB-SERVER-01` using the `svc-db` service account, and
exfiltrate customer PII and payment card data (~60 MB across three HTTPS sessions).

## Environment

| Host | Role |
|---|---|
| WEB-SERVER-01 | IIS web server — initial compromise (172.16.0.10) |
| DB-SERVER-01 | SQL Server — data theft target (172.16.0.20) |
| 91.234.55.12 | Attacker IP (external) |

## Attack Timeline (2025-01-22)

- 14:22–14:28 — Firewall blocks attacker probes (RDP :3389, SSH :22, HTTP :80/443)
- 14:25–14:31 — Attacker succeeds via HTTP :80 (web exploit)
- 14:32 — EID 4688: `w3wp.exe` spawns `cmd.exe /c whoami` — confirmed RCE as IIS_AppPool
- 14:32–14:34 — EID 4688 ×5: recon commands (whoami, ipconfig, net, netstat, ping)
- 14:35 — EID 4688: `certutil.exe -urlcache -split -f` downloads `sqlcli.exe` from C2
- 14:36 — EID 4624 Type-3 + EID 4672: `svc-db` network logon to DB-SERVER-01 (SeImpersonatePrivilege)
- 14:36–14:37 — EID 4688 ×3: `osql` queries — `customers`, `payment_cards`, `user_credentials` tables
- 14:38 — EID 4688: `bcp` bulk export → `customers_dump.csv` staged for exfil
- 14:55–14:59 — Firewall: 3 × 20 MB HTTPS flows from DB-SERVER-01 to attacker (~60 MB total)

## Format

Two-source CSV:

| File | Source | Format |
|---|---|---|
| `web_server_events.csv` | Windows Security (WEB-SERVER-01 / DB-SERVER-01) | CSV |
| `firewall_events.csv` | Perimeter firewall | CSV |

## Expected Detections

**MITRE coverage:** T1190 (Exploit Public-Facing App) → T1059.003 (cmd.exe shell) →
T1105 (certutil download — T1608.002) → T1078 (Valid Accounts — svc-db lateral) →
T1005 (Local Data Staging) → T1041 (Exfiltration over C2)

**Rules expected:** LAT-006 (Admin Network Logon), DCS-006 (SeImpersonatePrivilege)

**Behavioral rules expected:** `certutil_download`, `smb_lateral_movement`, `lateral_velocity`

**Severity:** CRITICAL — web shell + credential reuse + PII/payment-card exfiltration.
