"""
Executive incident report generator.
Produces a self-contained HTML file suitable for printing or sharing
with management and legal teams — no external CSS or JS dependencies.
"""

import math
import sys
from collections import Counter
from datetime import datetime
from backend.schema import RCAResult, ForensicEvent, Case, Note, Upload, MLStats
from backend.analysis.scoring import severity_label
from backend.analysis import rules as rules_mod


# ── Suspicious-event detection infrastructure ──────────────────────────────────
# Each entry maps a lowercase keyword found in event descriptions to a
# (human-readable label, severity colour) pair.
# Severity colours: "red" = critical, "orange" = high, "amber" = medium.

_SUSPICIOUS_KW: dict[str, tuple[str, str]] = {
    # Living-off-the-land binaries
    "certutil":        ("LOLBin: certutil",      "red"),
    "mshta":           ("LOLBin: mshta",         "red"),
    "regsvr32":        ("LOLBin: regsvr32",       "orange"),
    "rundll32":        ("LOLBin: rundll32",       "orange"),
    "wscript":         ("LOLBin: wscript",        "orange"),
    "cscript":         ("LOLBin: cscript",        "orange"),
    "msiexec":         ("LOLBin: msiexec",        "orange"),
    "wmic":            ("LOLBin: wmic",           "orange"),
    # Execution / obfuscation
    "-enc":            ("Encoded Command",        "red"),
    "encodedcommand":  ("Encoded Command",        "red"),
    "base64":          ("Base64 Payload",         "red"),
    "invoke-":         ("PS Invoke",              "red"),
    " iex ":           ("PS IEX",                 "red"),
    "powershell":      ("PowerShell",             "amber"),
    # Defense evasion
    "vssadmin":        ("Shadow Copy Tamper",     "red"),
    "shadowcopy":      ("Shadow Copy Tamper",     "red"),
    "bcdedit":         ("Boot Config Edit",       "red"),
    "wevtutil":        ("Log Clearing",           "red"),
    "clear-eventlog":  ("Log Clearing",           "red"),
    # Credential access
    "mimikatz":        ("Credential Dump",        "red"),
    "sekurlsa":        ("Credential Dump",        "red"),
    "lsass":           ("LSASS Access",           "red"),
    "pass-the-hash":   ("Pass-the-Hash",          "red"),
    "dcsync":          ("DCSync",                 "red"),
    "ntds.dit":        ("NTDS Dump",              "red"),
    "credential":      ("Credential Activity",   "amber"),
    # Lateral movement
    "psexec":          ("PsExec",                 "red"),
    "wmiexec":         ("WMI Exec",               "red"),
    "admin$":          ("Admin Share",            "red"),
    "ipc$":            ("IPC Share",              "orange"),
    "lateral":         ("Lateral Move",           "orange"),
    # Discovery / recon
    "net user":        ("User Enumeration",       "orange"),
    "net localgroup":  ("Group Enumeration",      "orange"),
    "net group":       ("Group Enumeration",      "orange"),
    "nltest":          ("Domain Recon",           "orange"),
    "whoami":          ("User Recon",             "amber"),
    "systeminfo":      ("System Recon",           "amber"),
    # Persistence
    "schtasks":        ("Scheduled Task",         "orange"),
    "at.exe":          ("Scheduled Task",         "orange"),
    "reg add":         ("Registry Write",         "orange"),
    "sc.exe":          ("Service Manipulation",   "orange"),
    # C2 / download
    "download":        ("Download Activity",      "orange"),
    " wget ":          ("Download Tool",          "orange"),
    " curl ":          ("Download Tool",          "orange"),
    "nc.exe":          ("Netcat",                 "red"),
    "netcat":          ("Netcat",                 "red"),
    # Impact
    "ransom":          ("Ransomware Indicator",   "red"),
    "encrypt":         ("Encryption Activity",   "orange"),
    "delete shadow":   ("Shadow Delete",          "red"),
}

# Event IDs that are inherently noteworthy (not only via keyword scan).
# For EID 4688 (process create) we require a keyword match too — it fires
# too broadly on its own.
_SUSPICIOUS_EVENT_IDS: dict[str, tuple[str, str]] = {
    "4625": ("Failed Logon",              "orange"),
    "4648": ("Explicit Credential Use",   "red"),
    "4672": ("Privileged Logon",          "orange"),
    "4697": ("Service Installed",         "red"),
    "4698": ("Scheduled Task Created",    "red"),
    "4702": ("Scheduled Task Modified",   "orange"),
    "4720": ("Account Created",           "red"),
    "4726": ("Account Deleted",           "orange"),
    "4728": ("Added to Domain Admins",    "red"),
    "4732": ("Added to Local Admins",     "orange"),
    "4756": ("Added to Universal Group",  "orange"),
    "7045": ("Service Installed",         "red"),
    "1102": ("Audit Log Cleared",         "red"),
    "4104": ("PS Script Block Logged",    "orange"),
    "4776": ("NTLM Auth",                 "amber"),
    "4769": ("Kerberos SPN Request",      "amber"),
}

_SEVERITY_COLOR   = {"red": "#ef4444", "orange": "#f97316", "amber": "#f59e0b"}
_SEVERITY_BG      = {"red": "#fef2f2", "orange": "#fff7ed", "amber": "#fffbeb"}
_SEVERITY_BORDER  = {"red": "#fecaca", "orange": "#fed7aa", "amber": "#fde68a"}
_SEVERITY_RANK    = {"red": 0, "orange": 1, "amber": 2}

# Ordered ATT&CK kill-chain phases used for the progress visualization
# and dynamic remediation.
_KILL_CHAIN_PHASES = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
]


def _detect_suspicious(event: ForensicEvent) -> tuple[str, str] | None:
    """
    Return (reason_label, severity_colour) when the event matches a known
    suspicious pattern; return None if the event is benign.

    Detection order:
      1. Specific event IDs (fast path, skips 4688 unless keyword also matches)
      2. Keyword scan of the description field
    """
    desc_lower = event.description.lower()

    if event.event_id and event.event_id in _SUSPICIOUS_EVENT_IDS:
        # 4688 Process Create — only flag if a suspicious keyword is also present
        if event.event_id == "4688":
            for kw, (label, color) in _SUSPICIOUS_KW.items():
                if kw in desc_lower:
                    return f"Process Create: {label}", color
        else:
            label, color = _SUSPICIOUS_EVENT_IDS[event.event_id]
            return label, color

    for kw, (label, color) in _SUSPICIOUS_KW.items():
        if kw in desc_lower:
            return label, color

    return None


# ── CSS ────────────────────────────────────────────────────────────────────────

_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;color:#1e293b;background:#f8fafc}
.page{max-width:960px;margin:0 auto;background:#fff;box-shadow:0 0 40px rgba(0,0,0,.08)}
.hdr{background:#0f172a;color:#fff;padding:40px 48px 32px}
.hdr h1{font-size:26px;font-weight:700;letter-spacing:-.5px}
.hdr .sub{color:#94a3b8;font-size:13px;margin-top:6px}
.meta{display:flex;gap:32px;margin-top:24px;flex-wrap:wrap}
.mi{font-size:11px;color:#64748b}
.mi span{display:block;color:#e2e8f0;font-size:15px;font-weight:600;margin-top:3px}
.badge{display:inline-block;padding:3px 12px;border-radius:20px;font-size:11px;font-weight:700;letter-spacing:1px}
.CRITICAL{background:#7f1d1d;color:#fecaca}
.HIGH{background:#7c2d12;color:#fed7aa}
.MEDIUM{background:#713f12;color:#fef08a}
.LOW{background:#14532d;color:#bbf7d0}
.sec{padding:32px 48px;border-bottom:1px solid #f1f5f9}
.sec h2{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:1.5px;color:#94a3b8;margin-bottom:16px}
.narr{font-size:15px;line-height:1.8;color:#374151;border-left:4px solid #3b82f6;padding-left:20px;font-style:italic}
.two{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.card{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:16px}
.card h3{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:#94a3b8;margin-bottom:8px}
.card p{font-size:13px;color:#374151;line-height:1.6}
.plist{list-style:none}
.plist li{display:flex;gap:10px;padding:8px 0;border-bottom:1px solid #f1f5f9;font-size:13px}
.plist li:last-child{border-bottom:none}
.pnum{font-weight:700;color:#3b82f6;min-width:22px}
.alist{list-style:none}
.alist li{padding:6px 0;font-size:13px;color:#374151;border-bottom:1px solid #f8fafc}
.alist li::before{content:"⚠ ";color:#f59e0b}
.mgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px}
.mtag{background:#eff6ff;border:1px solid #bfdbfe;border-radius:6px;padding:10px 12px}
.mtag .tid{font-family:monospace;font-size:11px;color:#1d4ed8;font-weight:700}
.mtag .tname{font-size:12px;color:#1e40af;margin-top:2px}
.mtag .ttac{font-size:10px;color:#93c5fd;margin-top:1px;text-transform:uppercase;letter-spacing:.5px}
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;padding:8px 12px;background:#f8fafc;color:#64748b;font-size:10px;text-transform:uppercase;letter-spacing:1px;border-bottom:1px solid #e2e8f0}
td{padding:7px 12px;border-bottom:1px solid #f8fafc;color:#374151;word-break:break-all}
.tbadge{background:#e0f2fe;color:#0369a1;padding:2px 8px;border-radius:10px;font-family:sans-serif;font-size:10px;font-weight:600;word-break:normal}
.score-bar{height:8px;background:#e2e8f0;border-radius:4px;overflow:hidden;margin-top:8px}
.score-fill{height:100%;border-radius:4px;transition:width .3s}
.ftr{padding:20px 48px;background:#f8fafc;font-size:11px;color:#94a3b8;display:flex;justify-content:space-between}
.gauge-wrap{display:flex;align-items:center;gap:40px;flex-wrap:wrap}
.gauge-stats{display:grid;grid-template-columns:1fr 1fr;gap:10px;flex:1}
.gstat{background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;padding:10px 14px}
.gstat .label{font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#94a3b8;font-weight:700}
.gstat .value{font-size:18px;font-weight:700;color:#1e293b;margin-top:4px}
.exec-box{background:#f0f9ff;border:1px solid #bae6fd;border-radius:8px;padding:20px 24px;margin-bottom:16px}
.exec-box p{font-size:14px;line-height:1.8;color:#0c4a6e}
.exec-bullets{list-style:none;display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-top:12px}
.exec-bullets li{font-size:12px;color:#374151;padding:5px 0;border-bottom:1px solid #e0f2fe}
.exec-bullets li::before{content:"▸ ";color:#0ea5e9;font-weight:700}
.rules-wrap{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.rule-block{background:#0f172a;border-radius:8px;padding:16px;overflow-x:auto}
.rule-block h4{font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#64748b;margin-bottom:10px;font-weight:700}
.rule-entry{font-family:monospace;font-size:11px;color:#e2e8f0;line-height:1.7;border-bottom:1px solid #1e293b;padding-bottom:10px;margin-bottom:10px;white-space:pre-wrap;word-break:break-all}
.rule-entry:last-child{border-bottom:none;margin-bottom:0;padding-bottom:0}
.snort-rule{font-family:monospace;font-size:11px;color:#86efac;line-height:1.6;padding:4px 0;border-bottom:1px solid #1e293b;white-space:pre-wrap;word-break:break-all}
.snort-rule:last-child{border-bottom:none}
"""


def _sec(title: str, body: str, ai: bool = False) -> str:
    ai_attr = ' data-ai-generated="true"' if ai else ' data-ai-generated="false"'
    return f'<div class="sec"{ai_attr}><h2>{title}</h2>{body}</div>'


def _pivot_html(chain: list[str]) -> str:
    if not chain:
        return ""
    items = "".join(
        f'<li><span class="pnum">{i+1}.</span>{s}</li>' for i, s in enumerate(chain)
    )
    return _sec("Lateral Movement — Pivot Chain", f'<ul class="plist">{items}</ul>')


def _anomalous_html(events: list[str]) -> str:
    if not events:
        return ""
    items = "".join(f"<li>{e}</li>" for e in events)
    return _sec("Anomalous Events Detected", f'<ul class="alist">{items}</ul>')


def _mitre_html(techniques: list) -> str:
    if not techniques:
        return ""
    tags = "".join(
        f'<div class="mtag"><div class="tid">{t.id}</div>'
        f'<div class="tname">{t.name}</div>'
        f'<div class="ttac">{t.tactic}</div></div>'
        for t in techniques
    )
    return _sec("MITRE ATT&amp;CK Techniques", f'<div class="mgrid">{tags}</div>')


def _ioc_html(iocs: list, limit: int = 60) -> str:
    if not iocs:
        return ""
    shown = iocs[:limit]
    rows = "".join(
        f'<tr><td><span class="tbadge">{i.type}</span></td>'
        f'<td style="font-family:monospace">{i.value}</td>'
        f'<td style="color:#94a3b8;word-break:normal">{i.context[:80]}</td></tr>'
        for i in shown
    )
    table = (
        '<table><thead><tr><th>Type</th><th>Value</th><th>Context</th></tr></thead>'
        f'<tbody>{rows}</tbody></table>'
    )
    title = (
        f"Indicators of Compromise (top {limit} of {len(iocs)})"
        if len(iocs) > limit else
        f"Indicators of Compromise ({len(iocs)} total)"
    )
    return _sec(title, table)


# ── NEW: Suspicious-events section (replaces flat 100-event table) ─────────────

def _suspicious_events_html(events: list[ForensicEvent], result: RCAResult, limit: int = 50) -> str:
    """
    Evidence-focused event section — only events that match a known attack
    pattern are shown, colour-coded by severity with a detection label.

    Replaces the old flat 100-event timeline table which added length without
    analytic value. Sorted critical-first then chronological; capped at 50.
    """
    high_risk_users = {
        s.entity for s in (result.ml_anomaly_scores or [])
        if s.risk_level in ("high_risk", "suspicious")
    }

    flagged: list[tuple[ForensicEvent, str, str]] = []
    for e in events:
        hit = _detect_suspicious(e)
        if hit:
            reason, color = hit
            # Promote severity when the actor is also ML-flagged
            if e.user and e.user in high_risk_users and color == "amber":
                color = "orange"
                reason += " + ML risk"
            flagged.append((e, reason, color))

    total = len(events)
    sus_count = len(flagged)

    if not flagged:
        body = (
            '<div style="text-align:center;padding:32px;color:#94a3b8">'
            '<div style="font-size:36px;margin-bottom:8px">✓</div>'
            '<p style="font-size:14px;font-weight:600;color:#475569">No suspicious patterns detected</p>'
            f'<p style="font-size:12px;margin-top:6px">Scanned {total:,} events — '
            'no known attack signatures, suspicious commands, or high-risk event IDs found.</p>'
            '</div>'
        )
        return _sec(f"Suspicious Events (0 of {total:,} flagged)", body)

    # Sort: most severe first, then chronological within same severity
    flagged.sort(key=lambda x: (_SEVERITY_RANK.get(x[2], 3), x[0].timestamp))
    capped = flagged[:limit]

    red_c    = sum(1 for _, _, c in capped if c == "red")
    orange_c = sum(1 for _, _, c in capped if c == "orange")
    amber_c  = sum(1 for _, _, c in capped if c == "amber")

    cap_note = f" — showing top {limit} of {sus_count}" if sus_count > limit else ""
    sev_badges = (
        (f'<span style="padding:3px 10px;border-radius:12px;font-size:11px;font-weight:700;'
         f'background:#fef2f2;color:#dc2626;border:1px solid #fecaca">{red_c} CRITICAL</span> '
         if red_c else "")
        + (f'<span style="padding:3px 10px;border-radius:12px;font-size:11px;font-weight:700;'
           f'background:#fff7ed;color:#ea580c;border:1px solid #fed7aa">{orange_c} HIGH</span> '
           if orange_c else "")
        + (f'<span style="padding:3px 10px;border-radius:12px;font-size:11px;font-weight:700;'
           f'background:#fffbeb;color:#d97706;border:1px solid #fde68a">{amber_c} MEDIUM</span>'
           if amber_c else "")
    )

    summary = (
        f'<div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap;'
        f'padding:12px 16px;background:#f8fafc;border-radius:8px;border:1px solid #e2e8f0;margin-bottom:16px">'
        f'<span style="font-size:13px;color:#64748b">'
        f'<strong style="font-size:20px;color:#1e293b">{sus_count}</strong> of {total:,} events flagged{cap_note}'
        f'</span>'
        f'<div style="margin-left:auto;display:flex;gap:6px;flex-wrap:wrap">{sev_badges}</div>'
        f'</div>'
    )

    rows = []
    for e, reason, color in capped:
        ts  = e.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        fc  = _SEVERITY_COLOR.get(color, "#94a3b8")
        bg  = _SEVERITY_BG.get(color, "#f8fafc")
        brd = _SEVERITY_BORDER.get(color, "#e2e8f0")
        desc = e.description[:160] + ("…" if len(e.description) > 160 else "")
        eid_span = (
            f'<span style="font-family:monospace;font-size:10px;background:#e0f2fe;'
            f'color:#0369a1;padding:1px 6px;border-radius:3px;margin-right:4px">'
            f'EID {e.event_id}</span>'
        ) if e.event_id else ""
        detection_badge = (
            f'<span style="font-size:11px;font-weight:700;color:{fc};'
            f'background:{bg};padding:2px 8px;border-radius:4px;border:1px solid {brd};'
            f'white-space:nowrap">{reason}</span>'
        )
        rows.append(
            f'<tr style="background:{bg}">'
            f'<td style="border-left:4px solid {fc};padding:8px 12px;font-size:11px;'
            f'font-family:monospace;color:#475569;white-space:nowrap">{ts}</td>'
            f'<td style="padding:8px 12px;font-size:12px;font-weight:600;color:#1e293b">{e.source_host}</td>'
            f'<td style="padding:8px 12px;font-size:12px;color:#475569">{e.user or "—"}</td>'
            f'<td style="padding:8px 12px">{eid_span}{detection_badge}</td>'
            f'<td style="padding:8px 12px;font-size:12px;color:#374151;word-break:break-all">{desc}</td>'
            f'</tr>'
        )

    table = (
        '<table style="border-collapse:collapse;width:100%">'
        '<thead><tr style="background:#f1f5f9">'
        '<th style="border-bottom:2px solid #e2e8f0;padding:8px 12px;font-size:10px;'
        'text-transform:uppercase;letter-spacing:1px;color:#64748b">Timestamp</th>'
        '<th style="border-bottom:2px solid #e2e8f0;padding:8px 12px;font-size:10px;'
        'text-transform:uppercase;letter-spacing:1px;color:#64748b">Host</th>'
        '<th style="border-bottom:2px solid #e2e8f0;padding:8px 12px;font-size:10px;'
        'text-transform:uppercase;letter-spacing:1px;color:#64748b">User</th>'
        '<th style="border-bottom:2px solid #e2e8f0;padding:8px 12px;font-size:10px;'
        'text-transform:uppercase;letter-spacing:1px;color:#64748b">Detection</th>'
        '<th style="border-bottom:2px solid #e2e8f0;padding:8px 12px;font-size:10px;'
        'text-transform:uppercase;letter-spacing:1px;color:#64748b">Description</th>'
        '</tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table>'
    )

    return _sec(f"Suspicious Events ({sus_count} of {total:,} flagged{cap_note})", summary + table)  # noqa


# ── NEW: ATT&CK kill-chain coverage visualization ──────────────────────────────

def _kill_chain_html(result: RCAResult) -> str:
    """
    Horizontal kill-chain progress bar showing which ATT&CK phases were
    observed in this incident, with technique counts per active phase.
    Inactive phases are shown greyed-out so the analyst can see coverage gaps.
    """
    seen: dict[str, list] = {}
    for t in result.mitre_techniques:
        seen.setdefault(t.tactic, []).append(t)

    if not seen:
        return ""

    phase_cells = []
    for phase in _KILL_CHAIN_PHASES:
        techs = seen.get(phase, [])
        active = bool(techs)
        short = phase.replace("Command and Control", "C2").replace(
            "Privilege Escalation", "Priv. Escal.").replace(
            "Defense Evasion", "Def. Evasion").replace(
            "Credential Access", "Cred. Access").replace(
            "Lateral Movement", "Lateral Move")
        bg    = "#0f172a" if active else "#f8fafc"
        brd   = "#3b82f6" if active else "#e2e8f0"
        fc    = "#e2e8f0" if active else "#94a3b8"
        fw    = "700" if active else "400"
        glow  = "box-shadow:0 0 0 2px rgba(59,130,246,0.25);" if active else ""
        badge = (
            f'<div style="font-size:10px;margin-top:4px;color:#60a5fa;font-weight:700">'
            f'{len(techs)} tech{"s" if len(techs) != 1 else ""}</div>'
        ) if active else ""

        phase_cells.append(
            f'<div style="flex:1;min-width:68px;text-align:center;padding:10px 4px;'
            f'background:{bg};border:2px solid {brd};border-radius:6px;{glow}">'
            f'<div style="font-size:10px;font-weight:{fw};color:{fc};line-height:1.3">{short}</div>'
            f'{badge}</div>'
        )

    phases_row = (
        '<div style="display:flex;gap:4px;overflow-x:auto;padding-bottom:4px">'
        + "".join(phase_cells)
        + "</div>"
    )

    # Technique pills grouped by active phase
    tech_pills = []
    for phase in _KILL_CHAIN_PHASES:
        techs = seen.get(phase, [])
        if not techs:
            continue
        pills = "".join(
            f'<span style="display:inline-block;margin:2px;padding:3px 9px;'
            f'background:#eff6ff;border:1px solid #bfdbfe;border-radius:4px;'
            f'font-size:11px;color:#1e40af">'
            f'<span style="font-family:monospace;font-weight:700">{t.id}</span>'
            f' {t.name}</span>'
            for t in techs
        )
        tech_pills.append(
            f'<div style="margin-top:10px">'
            f'<span style="font-size:10px;font-weight:700;text-transform:uppercase;'
            f'letter-spacing:1px;color:#64748b">{phase}</span>'
            f'<div style="margin-top:4px">{pills}</div></div>'
        )

    legend = (
        '<div style="display:flex;gap:20px;margin-top:12px;font-size:11px;color:#64748b">'
        '<div style="display:flex;align-items:center;gap:6px">'
        '<div style="width:12px;height:12px;background:#0f172a;border:2px solid #3b82f6;border-radius:3px"></div>'
        '<span>Observed in this incident</span></div>'
        '<div style="display:flex;align-items:center;gap:6px">'
        '<div style="width:12px;height:12px;background:#f8fafc;border:2px solid #e2e8f0;border-radius:3px"></div>'
        '<span>Not observed</span></div></div>'
    )

    active_count = sum(1 for p in _KILL_CHAIN_PHASES if p in seen)
    body = phases_row + legend + "".join(tech_pills)
    return _sec(
        f"ATT&amp;CK Kill Chain — {active_count} of {len(_KILL_CHAIN_PHASES)} phases observed",
        body,
    )


# ── NEW: Entity involvement cards ──────────────────────────────────────────────

def _entity_involvement_html(events: list[ForensicEvent], result: RCAResult) -> str:
    """
    Visual grid of host and user involvement cards, each showing total event
    count, suspicious event count, activity bar, and ML risk badge.
    Gives the analyst a fast risk-ranked view of every entity in the incident
    without reading through the full event list.
    """
    host_total: dict[str, int] = {}
    host_sus:   dict[str, int] = {}
    user_total: dict[str, int] = {}
    user_sus:   dict[str, int] = {}

    for e in events:
        host_total[e.source_host] = host_total.get(e.source_host, 0) + 1
        if _detect_suspicious(e):
            host_sus[e.source_host] = host_sus.get(e.source_host, 0) + 1
        if e.user:
            user_total[e.user] = user_total.get(e.user, 0) + 1
            if _detect_suspicious(e):
                user_sus[e.user] = user_sus.get(e.user, 0) + 1

    ml_risk: dict[str, str] = {
        s.entity: s.risk_level for s in (result.ml_anomaly_scores or [])
    }
    patient_zero = result.patient_zero_candidate or ""

    def _card(name: str, total: int, sus: int, kind: str,
               ml_level: str | None = None, is_pz: bool = False) -> str:
        pct = int(sus / total * 100) if total else 0
        bar_color = (
            "#ef4444" if pct > 50 else
            "#f97316" if pct > 20 else
            "#22c55e"
        )
        border = "#fca5a5" if is_pz else "#e2e8f0"
        bg = "#fff5f5" if is_pz else "#f8fafc"
        icon = "🖥" if kind == "host" else "👤"

        pz_badge = (
            '<span style="font-size:10px;padding:1px 7px;border-radius:10px;'
            'background:#fef2f2;color:#dc2626;border:1px solid #fecaca;font-weight:700;'
            'margin-right:4px">PATIENT ZERO</span>'
        ) if is_pz else ""

        ml_badge = ""
        if ml_level == "high_risk":
            ml_badge = (
                '<span style="font-size:10px;padding:1px 7px;border-radius:10px;'
                'background:#fef2f2;color:#dc2626;border:1px solid #fecaca;font-weight:700">ML HIGH</span>'
            )
        elif ml_level == "suspicious":
            ml_badge = (
                '<span style="font-size:10px;padding:1px 7px;border-radius:10px;'
                'background:#fff7ed;color:#ea580c;border:1px solid #fed7aa;font-weight:700">ML RISK</span>'
            )

        return (
            f'<div style="background:{bg};border:1px solid {border};border-radius:8px;'
            f'padding:14px 16px;min-width:150px;flex:0 0 auto">'
            f'<div style="font-size:10px;text-transform:uppercase;letter-spacing:1px;'
            f'color:#94a3b8;margin-bottom:4px">{icon} {kind}</div>'
            f'<div style="font-size:13px;font-weight:700;color:#1e293b;word-break:break-all;'
            f'margin-bottom:6px">{name}</div>'
            f'<div style="margin-bottom:6px">{pz_badge}{ml_badge}</div>'
            f'<div style="font-size:11px;color:#64748b;margin-bottom:6px">'
            f'{total:,} events &bull; {sus} suspicious ({pct}%)</div>'
            f'<div style="height:6px;background:#e2e8f0;border-radius:3px;overflow:hidden">'
            f'<div style="height:100%;width:{min(pct,100)}%;background:{bar_color};'
            f'border-radius:3px"></div></div></div>'
        )

    host_cards = "".join(
        _card(h, t, host_sus.get(h, 0), "host", is_pz=(patient_zero in h or h in patient_zero))
        for h, t in sorted(host_total.items(), key=lambda x: -x[1])[:8]
    )
    user_cards = "".join(
        _card(u, t, user_sus.get(u, 0), "user", ml_risk.get(u),
              is_pz=(patient_zero in u or u in patient_zero))
        for u, t in sorted(user_total.items(), key=lambda x: -x[1])[:8]
    )

    if not host_cards and not user_cards:
        return ""

    sections = []
    if host_cards:
        sections.append(
            f'<p style="font-size:10px;font-weight:700;text-transform:uppercase;'
            f'letter-spacing:1px;color:#94a3b8;margin-bottom:10px">'
            f'Hosts ({len(host_total)})</p>'
            f'<div style="display:flex;flex-wrap:wrap;gap:10px">{host_cards}</div>'
        )
    if user_cards:
        sections.append(
            f'<p style="font-size:10px;font-weight:700;text-transform:uppercase;'
            f'letter-spacing:1px;color:#94a3b8;margin-top:18px;margin-bottom:10px">'
            f'Entity Accounts ({len(user_total)})</p>'
            f'<div style="display:flex;flex-wrap:wrap;gap:10px">{user_cards}</div>'
        )

    return _sec("Entity Involvement", "".join(sections))


# ── NEW: Dynamic context-aware remediation ────────────────────────────────────

_TACTIC_BASE_REC: dict[str, str] = {
    "Initial Access":       "Patch public-facing applications, enforce MFA on VPN/RDP, review phishing-resistant authentication.",
    "Execution":            "Block LOLBins via AppLocker/WDAC, restrict PowerShell execution policy, enable Script Block Logging (EID 4104).",
    "Persistence":          "Audit all scheduled tasks, startup registry keys, and service configurations. Remove any persistence artefacts identified in this incident.",
    "Privilege Escalation": "Enforce least-privilege, audit and rotate elevated credentials, deploy PAM solution for privileged access.",
    "Defense Evasion":      "Restore tamper protection on EDR, review log-clearing events (EID 1102), re-enable disabled security controls.",
    "Credential Access":    "Deploy Credential Guard, disable NTLM where possible, rotate ALL domain credentials if any credential-dump activity was confirmed.",
    "Discovery":            "Alert on bulk LDAP/WMI queries, abnormal net.exe usage, and port-scan patterns. Review exactly what data was enumerated.",
    "Lateral Movement":     "Segment the network, restrict SMB between workstations, enforce a tiered admin model, audit all administrative shares.",
    "Collection":           "Apply DLP controls on sensitive file shares, audit all file-access events during the incident window.",
    "Command and Control":  "Proxy all outbound traffic, block identified C2 IPs and domains at every egress point.",
    "Exfiltration":         "Review egress firewall logs for large or unusual outbound transfers. Deploy CASB for cloud storage monitoring.",
    "Impact":               "Verify backup integrity immediately. If ransomware is confirmed: isolate affected systems, do not pay, and engage an incident response firm.",
}


def _dynamic_remediation_html(result: RCAResult, events: list[ForensicEvent], tier1_only: bool = False) -> str:
    """
    Two-tier, evidence-aware remediation plan.

    Tier 1 — Immediate actions: incident-specific artefacts (exact IPs to block,
    accounts to disable, hashes to quarantine) derived from the actual IOCs,
    ML scores, event patterns, and patient-zero candidate in this report.

    Tier 2 — Hardening steps: per-tactic recommendations from _TACTIC_BASE_REC,
    each enriched with context extracted from this specific incident so the
    recommendations read as targeted guidance rather than generic boilerplate.
    """
    sev = severity_label(result.severity_score)

    # ── Extract incident-specific artefacts ────────────────────────────────────
    ip_iocs     = [i.value for i in result.iocs if i.type == "ip"][:10]
    hash_iocs   = [i.value for i in result.iocs if i.type in ("md5", "sha256")][:5]
    domain_iocs = [i.value for i in result.iocs if i.type == "domain"][:5]

    involved_hosts = sorted({e.source_host for e in events})
    involved_users = sorted({e.user for e in events if e.user})
    high_risk_users = [
        s.entity for s in (result.ml_anomaly_scores or [])
        if s.risk_level == "high_risk"
    ]
    patient_zero = result.patient_zero_candidate or ""

    all_desc = " ".join(e.description.lower() for e in events)
    event_ids = {e.event_id for e in events if e.event_id}

    # ── Urgency banner ─────────────────────────────────────────────────────────
    _urgency: dict[str, tuple[str, str, str]] = {
        "CRITICAL": ("#450a0a", "#fca5a5",
                     "🚨 CRITICAL — Immediate containment required. Escalate to CISO and legal counsel. "
                     "Preserve all forensic evidence BEFORE any remediation action."),
        "HIGH":     ("#431407", "#fdba74",
                     "⚠️ HIGH — Urgent response required within 24 hours. Activate incident response plan "
                     "and notify relevant stakeholders."),
        "MEDIUM":   ("#422006", "#fcd34d",
                     "⚡ MEDIUM — Investigate and remediate within 72 hours. Monitor closely for escalation."),
        "LOW":      ("#052e16", "#86efac",
                     "ℹ️ LOW — Schedule remediation in the next maintenance window. Continue monitoring."),
    }
    urg_bg, urg_border, urg_text = _urgency.get(sev, _urgency["MEDIUM"])
    urgency_html = (
        f'<div style="background:{urg_bg};border-left:5px solid {urg_border};'
        f'padding:14px 18px;border-radius:6px;margin-bottom:20px">'
        f'<p style="font-size:13px;color:{urg_border};font-weight:600;line-height:1.6">'
        f'{urg_text}</p></div>'
    )

    # ── Tier 1: Immediate, incident-specific actions ───────────────────────────
    immediate: list[str] = []

    if patient_zero:
        immediate.append(
            f"<strong>Isolate</strong> patient-zero system "
            f"<code style='background:#1e293b;color:#e2e8f0;padding:1px 6px;border-radius:3px'>"
            f"{patient_zero}</code> — disconnect from the network before any remediation."
        )

    if high_risk_users:
        users_code = ", ".join(
            f"<code style='background:#1e293b;color:#e2e8f0;padding:1px 5px;border-radius:3px'>{u}</code>"
            for u in high_risk_users[:5]
        )
        immediate.append(
            f"<strong>Disable and reset</strong> ML-flagged high-risk account(s): {users_code} — "
            "revoke all active sessions, reset passwords, and re-issue credentials via a clean device."
        )
    elif involved_users:
        users_code = ", ".join(
            f"<code style='background:#1e293b;color:#e2e8f0;padding:1px 5px;border-radius:3px'>{u}</code>"
            for u in involved_users[:5]
        )
        immediate.append(
            f"<strong>Audit active sessions</strong> for all involved accounts: {users_code}."
        )

    if ip_iocs:
        ips = ", ".join(
            f"<code style='background:#1e293b;color:#fca5a5;padding:1px 5px;border-radius:3px'>{ip}</code>"
            for ip in ip_iocs
        )
        immediate.append(
            f"<strong>Block at perimeter firewall/WAF</strong> — malicious IPs identified in this incident: {ips}."
        )

    if domain_iocs:
        doms = ", ".join(
            f"<code style='background:#1e293b;color:#fca5a5;padding:1px 5px;border-radius:3px'>{d}</code>"
            for d in domain_iocs
        )
        immediate.append(
            f"<strong>Sinkhole or block at DNS</strong> — malicious domains identified: {doms}."
        )

    if hash_iocs:
        hashes = ", ".join(
            f"<code style='background:#1e293b;color:#fde68a;padding:1px 5px;border-radius:3px'>"
            f"{h[:20]}…</code>"
            for h in hash_iocs
        )
        immediate.append(
            f"<strong>Quarantine/blacklist file hash(es)</strong> in EDR and AV: {hashes}."
        )

    if "vssadmin" in all_desc or "shadowcopy" in all_desc or "delete shadow" in all_desc:
        immediate.append(
            "<strong>Verify backup integrity NOW</strong> — VSS/shadow-copy deletion commands were "
            "detected. Do not attempt restore until backup integrity is confirmed independently."
        )

    if any(kw in all_desc for kw in ("mimikatz", "sekurlsa", "lsass", "ntds.dit", "dcsync")):
        immediate.append(
            "<strong>Rotate ALL domain credentials</strong> — credential-dump activity was confirmed. "
            "Assume every cached password in the affected domain is compromised. "
            "Prioritise privileged and service accounts."
        )

    if "4720" in event_ids:
        immediate.append(
            "<strong>Audit all accounts created</strong> during the incident window (EID 4720 detected) — "
            "verify no backdoor or persistence accounts remain active in Active Directory."
        )

    if "1102" in event_ids:
        immediate.append(
            "<strong>Restore audit policy and review SIEM gaps</strong> — "
            "audit log clearing (EID 1102) was detected; determine what activity may have been wiped."
        )

    if not immediate:
        hosts_code = ", ".join(
            f"<code style='background:#1e293b;color:#e2e8f0;padding:1px 5px;border-radius:3px'>{h}</code>"
            for h in involved_hosts[:4]
        )
        immediate.append(
            f"<strong>Review all active sessions</strong> on involved hosts: {hosts_code}."
        )
        immediate.append(
            "<strong>Preserve forensic evidence</strong> — take memory images and disk snapshots "
            "before rebooting any affected systems."
        )

    imm_items = "".join(
        f'<li style="padding:8px 0;border-bottom:1px solid rgba(255,255,255,0.08);'
        f'font-size:13px;color:#e2e8f0;line-height:1.6">{item}</li>'
        for item in immediate
    )
    immediate_html = (
        '<div style="background:#0f172a;border-radius:8px;padding:20px 24px;margin-bottom:20px">'
        '<h3 style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1.5px;'
        'color:#ef4444;margin-bottom:14px">Immediate Actions — Specific to This Incident</h3>'
        f'<ul style="list-style:none;padding:0;margin:0">{imm_items}</ul>'
        '</div>'
    )

    # ── Tier 2: Per-tactic hardening, enriched with incident evidence ──────────
    seen_tactics = {t.tactic for t in result.mitre_techniques}

    # Build per-tactic evidence enrichments from actual event data
    evidence_notes: dict[str, str] = {}

    if "Initial Access" in seen_tactics and result.initial_access_vector:
        evidence_notes["Initial Access"] = (
            f"Observed initial vector in this incident: <em>{result.initial_access_vector}</em>."
        )

    if "Execution" in seen_tactics:
        sus_cmds = [
            e.description[:80]
            for e in events
            if any(kw in e.description.lower()
                   for kw in ("powershell", "-enc", "mshta", "wmic", "rundll32", "cscript"))
        ][:3]
        if sus_cmds:
            evidence_notes["Execution"] = (
                f"Suspicious commands seen: <em>{' | '.join(sus_cmds)}</em>."
            )

    if "Lateral Movement" in seen_tactics and len(involved_hosts) > 1:
        chain = " → ".join(involved_hosts[:6])
        evidence_notes["Lateral Movement"] = (
            f"Movement observed across: <em>{chain}</em>."
        )

    if "Credential Access" in seen_tactics:
        if high_risk_users:
            evidence_notes["Credential Access"] = (
                f"Compromised account(s) identified: "
                f"<em>{', '.join(high_risk_users[:4])}</em>."
            )
        elif any(kw in all_desc for kw in ("mimikatz", "lsass", "ntds.dit")):
            evidence_notes["Credential Access"] = (
                "Credential-dump tooling detected — treat all cached credentials as compromised."
            )

    if "Command and Control" in seen_tactics and ip_iocs:
        evidence_notes["Command and Control"] = (
            f"Observed C2 endpoints: <em>{', '.join(ip_iocs[:4])}</em>."
        )

    if "Impact" in seen_tactics:
        if "ransom" in all_desc or "encrypt" in all_desc:
            evidence_notes["Impact"] = (
                "Ransomware/encryption indicators present — do NOT reboot before forensic preservation."
            )
        elif "vssadmin" in all_desc or "delete shadow" in all_desc:
            evidence_notes["Impact"] = (
                "Shadow-copy deletion detected — backups may have been targeted before encryption."
            )

    rec_items: list[str] = []
    for phase in _KILL_CHAIN_PHASES:
        if phase not in seen_tactics:
            continue
        base = _TACTIC_BASE_REC.get(phase, "Review and remediate.")
        note = evidence_notes.get(phase, "")
        note_html = (
            f'<div style="font-size:12px;color:#6b7280;margin-top:3px">{note}</div>'
            if note else ""
        )
        rec_items.append(
            f'<li style="padding:10px 0;border-bottom:1px solid #f1f5f9;display:flex;gap:12px">'
            f'<span style="color:#3b82f6;font-weight:700;flex-shrink:0;font-size:14px">▸</span>'
            f'<div><strong style="font-size:13px">{phase}:</strong> '
            f'<span style="font-size:13px;color:#374151">{base}</span>'
            f'{note_html}</div></li>'
        )

    hardening_html = ""
    if rec_items and not tier1_only:
        hardening_html = (
            '<div>'
            '<h3 style="font-size:11px;font-weight:700;text-transform:uppercase;'
            'letter-spacing:1.5px;color:#64748b;margin-bottom:14px">'
            'Hardening Steps — By Observed ATT&amp;CK Tactic</h3>'
            f'<ul style="list-style:none;padding:0;margin:0">{"".join(rec_items)}</ul>'
            '</div>'
        )

    return _sec("Remediation Plan", urgency_html + immediate_html + hardening_html)


# ── Severity gauge SVG ─────────────────────────────────────────────────────────

def _severity_gauge_svg(score: int, color: str) -> str:
    cx, cy, r = 100, 100, 72
    stroke_w = 14
    bg = f"M {cx-r},{cy} A {r},{r} 0 0,1 {cx+r},{cy}"

    if score <= 0:
        fill_path = ""
    elif score >= 100:
        fill_path = f"M {cx-r},{cy} A {r},{r} 0 0,1 {cx+r},{cy}"
    else:
        angle = math.pi * (1.0 - score / 100.0)
        ex = cx + r * math.cos(angle)
        ey = cy - r * math.sin(angle)
        fill_path = f"M {cx-r},{cy} A {r},{r} 0 0,1 {ex:.1f},{ey:.1f}"

    fill_el = (
        f'<path d="{fill_path}" fill="none" stroke="{color}" '
        f'stroke-width="{stroke_w}" stroke-linecap="round"/>'
        if fill_path else ""
    )
    return (
        f'<svg viewBox="0 0 200 120" xmlns="http://www.w3.org/2000/svg" '
        f'style="width:200px;height:120px;flex-shrink:0">'
        f'<path d="{bg}" fill="none" stroke="#e2e8f0" stroke-width="{stroke_w}" stroke-linecap="round"/>'
        f'{fill_el}'
        f'<text x="100" y="90" text-anchor="middle" font-family="Segoe UI,Arial,sans-serif" '
        f'font-size="36" font-weight="700" fill="{color}">{score}</text>'
        f'<text x="100" y="108" text-anchor="middle" font-family="Segoe UI,Arial,sans-serif" '
        f'font-size="11" fill="#94a3b8">/ 100</text>'
        f'</svg>'
    )


def _exec_summary_html(result: RCAResult, events: list[ForensicEvent],
                       sev: str, t_start: str, t_end: str) -> str:
    hosts = sorted({e.source_host for e in events})
    users = sorted({e.user for e in events if e.user})
    technique_count = len(result.mitre_techniques)
    ioc_count = len(result.iocs)

    risk_sentence = {
        "CRITICAL": "This incident represents a <strong>critical-severity compromise</strong> requiring immediate executive escalation and potential legal notification.",
        "HIGH":     "This incident represents a <strong>high-severity threat</strong> requiring urgent remediation and potential regulatory review.",
        "MEDIUM":   "This incident represents a <strong>medium-severity event</strong> that warrants prompt investigation and containment.",
        "LOW":      "This incident represents a <strong>low-severity anomaly</strong> that should be reviewed during normal operational cycles.",
    }.get(sev, "This incident requires review.")

    bullets = [
        f"<strong>{result.analyzed_event_count:,}</strong> log events analysed",
        f"<strong>{technique_count}</strong> MITRE ATT&amp;CK techniques mapped",
        f"<strong>{ioc_count}</strong> indicators of compromise extracted",
        f"<strong>{len(hosts)}</strong> host(s) involved: {', '.join(hosts[:5])}{'…' if len(hosts) > 5 else ''}",
        f"<strong>{len(users)}</strong> user account(s) active during incident",
        f"Confidence level: <strong>{result.confidence.upper()}</strong>",
        f"Timeline: <strong>{t_start}</strong> — <strong>{t_end}</strong>",
    ]
    if result.patient_zero_candidate:
        bullets.append(f"Patient-zero candidate: <strong>{result.patient_zero_candidate}</strong>")
    if result.consensus_agreement is not None:
        bullets.append(f"Multi-model consensus: <strong>{int(result.consensus_agreement * 100)}%</strong>")

    bullets_html = "".join(f"<li>{b}</li>" for b in bullets)
    narrative_preview = result.narrative[:300] + "…" if len(result.narrative) > 300 else result.narrative

    return _sec("Executive Summary", f"""
<div class="exec-box">
  <p>{risk_sentence} The automated forensic analysis covered the period from {t_start} to {t_end},
  examining {result.analyzed_event_count:,} events across {len(hosts)} host(s). {narrative_preview}</p>
  <ul class="exec-bullets">{bullets_html}</ul>
</div>""")


def _detection_rules_html(result: RCAResult) -> str:
    sigma_rules = rules_mod.generate_sigma_rules(result.iocs, result.mitre_techniques)
    snort_rules = rules_mod.generate_snort_rules(result.iocs)
    yara_rules  = rules_mod.generate_yara_rules(result.iocs, result.mitre_techniques)

    if not sigma_rules and not snort_rules and not yara_rules:
        return ""

    sigma_entries = ""
    for r in sigma_rules[:10]:
        sigma_entries += (
            f'<div class="rule-entry">'
            f'<span style="color:#7dd3fc">title:</span> {r["title"]}\n'
            f'<span style="color:#7dd3fc">id:</span> {r["id"]}\n'
            f'<span style="color:#7dd3fc">tags:</span> {", ".join(r["tags"])}\n'
            f'<span style="color:#86efac">detection:</span>\n'
            f'  keywords: {r["detection"]["keywords"]}'
            f'</div>'
        )

    snort_entries = "".join(
        f'<div class="snort-rule">{rule}</div>' for rule in snort_rules[:10]
    )

    yara_entries = "".join(
        f'<div class="rule-entry">{rule}</div>' for rule in yara_rules[:10]
    )

    _sigma_fallback = '<p style="color:#64748b;font-size:12px">No Sigma rules generated.</p>'
    _snort_fallback = '<p style="color:#64748b;font-size:12px">No IP-based IOCs — no Snort rules.</p>'
    _yara_fallback  = '<p style="color:#64748b;font-size:12px">No YARA rules generated.</p>'
    sigma_col = (
        f'<div class="rule-block"><h4>Sigma Rules ({len(sigma_rules)} generated)</h4>'
        f'{sigma_entries or _sigma_fallback}'
        f'</div>'
    )
    yara_col = (
        f'<div class="rule-block"><h4>YARA Rules ({len(yara_rules)} generated)</h4>'
        f'{yara_entries or _yara_fallback}'
        f'</div>'
    )
    snort_col = (
        f'<div class="rule-block"><h4>Snort / Suricata Rules ({len(snort_rules)} generated)</h4>'
        f'{snort_entries or _snort_fallback}'
        f'</div>'
    )

    return _sec(
        f"Detection Rules — Sigma ({len(sigma_rules)}) · YARA ({len(yara_rules)}) · Snort ({len(snort_rules)})",
        f'<div class="rules-wrap">{sigma_col}{yara_col}{snort_col}</div>',
    )


# ── Quick scan report (unchanged structure) ────────────────────────────────────

def generate_quick_scan_report(result: RCAResult) -> str:
    sev = severity_label(result.severity_score)
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    score_color = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#22c55e"}[sev]

    gauge_svg = _severity_gauge_svg(result.severity_score, score_color)
    severity_section = f"""
<div class="sec">
  <h2>Quick Scan — Severity Score</h2>
  <div class="gauge-wrap">
    {gauge_svg}
    <div class="gauge-stats">
      <div class="gstat"><div class="label">Severity</div>
        <div class="value" style="color:{score_color}">{sev}</div></div>
      <div class="gstat"><div class="label">Events Scanned</div>
        <div class="value">{result.analyzed_event_count}</div></div>
      <div class="gstat"><div class="label">MITRE Techniques</div>
        <div class="value">{len(result.mitre_techniques)}</div></div>
      <div class="gstat"><div class="label">IOC Count</div>
        <div class="value">{len(result.iocs)}</div></div>
    </div>
  </div>
</div>"""

    ml_svg = _ml_anomaly_chart_svg(result.ml_anomaly_scores or [])
    ml_section = (
        _sec("ML Behavioral Anomaly Scores", f'<div class="chart-wrap">{ml_svg}</div>')
        if ml_svg else ""
    )

    notice = _sec("Report Type", """
<div class="exec-box">
  <p>This is a <strong>Quick Scan Snapshot</strong> — a fast, deterministic analysis with no LLM involvement.
  It detects MITRE ATT&amp;CK techniques, extracts IOCs, calculates severity, and runs ML behavioral anomaly
  scoring. Run <strong>AI Analysis</strong> or <strong>Multi-Model Consensus</strong> to generate an
  in-depth investigation narrative.</p>
</div>""")

    header = f"""
<div class="hdr">
  <h1>Quick Scan Snapshot</h1>
  <div class="sub">Forensic Intelligence Pipeline — Deterministic Analysis</div>
  <div class="meta">
    <div class="mi">Generated<span>{now}</span></div>
    <div class="mi">Severity
      <span><span class="badge {sev}">{sev}</span> ({result.severity_score}/100)</span>
    </div>
    <div class="mi">Events<span>{result.analyzed_event_count}</span></div>
    <div class="mi">Analysis Type<span>Quick Scan</span></div>
  </div>
</div>"""

    body = (
        header + severity_section + notice
        + _mitre_html(result.mitre_techniques)
        + _ioc_html(result.iocs)
        + ml_section
        + f'<div class="ftr"><span>Forensic Intelligence Pipeline v4 — Quick Scan Snapshot</span>'
          f'<span>{now}</span></div>'
    )
    return (
        f'<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">'
        f'<title>Quick Scan Snapshot — {now}</title>'
        f'<style>{_CSS}</style></head><body><div class="page">{body}</div></body></html>'
    )


# ── Deep analysis report ───────────────────────────────────────────────────────

def generate_report(result: RCAResult, events: list[ForensicEvent]) -> str:
    """
    Full AI analysis HTML report.
    Section order:
      Header → Severity gauge → Executive summary → Entity involvement
      → RCA findings → Narrative → Kill chain → Pivot chain → Anomalous events
      → Suspicious events → MITRE → IOCs → Detection rules → Remediation plan
    """
    sev = severity_label(result.severity_score)
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    timestamps = [e.timestamp for e in events]
    t_start = min(timestamps).strftime("%Y-%m-%d %H:%M") if timestamps else "—"
    t_end   = max(timestamps).strftime("%Y-%m-%d %H:%M") if timestamps else "—"
    score_color = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#22c55e"}[sev]

    consensus_html = (
        f'<div class="mi">Consensus Agreement<span>{int(result.consensus_agreement * 100)}%</span></div>'
        if result.consensus_agreement is not None else ""
    )

    header = f"""
<div class="hdr">
  <h1>Security Incident Analysis Report</h1>
  <div class="sub">Forensic Intelligence Pipeline — Automated RCA</div>
  <div class="meta">
    <div class="mi">Generated<span>{now}</span></div>
    <div class="mi">Severity
      <span><span class="badge {sev}">{sev}</span> ({result.severity_score}/100)</span>
    </div>
    <div class="mi">Confidence<span>{result.confidence.upper()}</span></div>
    <div class="mi">Events<span>{result.analyzed_event_count}</span></div>
    <div class="mi">Time Range<span>{t_start} – {t_end}</span></div>
    {consensus_html}
  </div>
</div>"""

    gauge_svg = _severity_gauge_svg(result.severity_score, score_color)
    severity_section = f"""
<div class="sec">
  <h2>Severity Score</h2>
  <div class="gauge-wrap">
    {gauge_svg}
    <div class="gauge-stats">
      <div class="gstat"><div class="label">Severity</div>
        <div class="value" style="color:{score_color}">{sev}</div></div>
      <div class="gstat"><div class="label">Confidence</div>
        <div class="value">{result.confidence.upper()}</div></div>
      <div class="gstat"><div class="label">MITRE Techniques</div>
        <div class="value">{len(result.mitre_techniques)}</div></div>
      <div class="gstat"><div class="label">IOC Count</div>
        <div class="value">{len(result.iocs)}</div></div>
    </div>
  </div>
</div>"""

    findings = _sec("Root Cause Analysis", f"""
<div class="two">
  <div class="card"><h3>Patient Zero Candidate</h3>
    <p>{result.patient_zero_candidate or "Not identified"}</p></div>
  <div class="card"><h3>Initial Access Vector</h3>
    <p>{result.initial_access_vector or "Unknown"}</p></div>
</div>""")

    narrative_section = _sec("Detailed Narrative", f'<p class="narr">{result.narrative}</p>', ai=True)

    body = (
        header
        + severity_section
        + _exec_summary_html(result, events, sev, t_start, t_end)
        + _entity_involvement_html(events, result)
        + findings
        + narrative_section
        + _kill_chain_html(result)
        + _pivot_html(result.pivot_chain)
        + _anomalous_html(result.anomalous_events)
        + _suspicious_events_html(events, result)
        + _mitre_html(result.mitre_techniques)
        + _ioc_html(result.iocs)
        + _detection_rules_html(result)
        + _dynamic_remediation_html(result, events)
        + f'<div class="ftr"><span>Forensic Intelligence Pipeline v4</span><span>{now}</span></div>'
    )

    return (
        f'<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">'
        f'<title>Incident Report — {now}</title>'
        f'<style>{_CSS}</style></head><body><div class="page">{body}</div></body></html>'
    )


# ── SVG Chart Helpers ──────────────────────────────────────────────────────────

def _ml_anomaly_chart_svg(ml_scores: list) -> str:
    if not ml_scores:
        return ""
    scores = sorted(ml_scores, key=lambda s: s.anomaly_score, reverse=True)[:20]
    row_h = 28
    label_w = 130
    bar_area = 300
    chart_h = len(scores) * row_h + 30
    chart_w = label_w + bar_area + 60

    COLORS = {"high_risk": "#ef4444", "suspicious": "#f59e0b", "normal": "#22c55e"}
    rows_svg = ""
    for i, s in enumerate(scores):
        y = i * row_h + 20
        pct = min(s.anomaly_score, 1.0)
        bar_w = int(pct * bar_area)
        color = COLORS.get(s.risk_level, "#94a3b8")
        label = s.entity[:18] + ("…" if len(s.entity) > 18 else "")
        score_txt = f"{int(pct * 100)}%"
        rows_svg += (
            f'<text x="{label_w - 6}" y="{y + 13}" text-anchor="end" font-size="11" fill="#374151">{label}</text>'
            f'<rect x="{label_w}" y="{y}" width="{bar_w}" height="18" rx="3" fill="{color}" opacity="0.85"/>'
            f'<text x="{label_w + bar_w + 6}" y="{y + 13}" font-size="11" fill="{color}" font-weight="600">{score_txt}</text>'
        )

    legend = (
        f'<circle cx="{label_w}" cy="{chart_h - 6}" r="5" fill="#ef4444"/>'
        f'<text x="{label_w + 10}" y="{chart_h - 2}" font-size="10" fill="#64748b">High Risk</text>'
        f'<circle cx="{label_w + 80}" cy="{chart_h - 6}" r="5" fill="#f59e0b"/>'
        f'<text x="{label_w + 90}" y="{chart_h - 2}" font-size="10" fill="#64748b">Suspicious</text>'
        f'<circle cx="{label_w + 175}" cy="{chart_h - 6}" r="5" fill="#22c55e"/>'
        f'<text x="{label_w + 185}" y="{chart_h - 2}" font-size="10" fill="#64748b">Normal</text>'
    )

    return (
        f'<svg viewBox="0 0 {chart_w} {chart_h + 10}" '
        f'xmlns="http://www.w3.org/2000/svg" style="width:100%;max-width:{chart_w}px">'
        f'{rows_svg}{legend}</svg>'
    )


def _event_density_chart_svg(events: list[ForensicEvent]) -> str:
    if not events:
        return ""
    counts: Counter = Counter(e.timestamp.strftime("%Y-%m-%d") for e in events)
    days = sorted(counts.keys())
    if not days:
        return ""

    max_count = max(counts.values()) or 1
    bar_w = max(8, min(30, 560 // len(days)))
    gap = max(2, bar_w // 4)
    chart_w = len(days) * (bar_w + gap) + 60
    chart_h = 140

    bars_svg = ""
    for i, day in enumerate(days):
        cnt = counts[day]
        bar_h = int((cnt / max_count) * 100)
        x = 40 + i * (bar_w + gap)
        y = chart_h - 30 - bar_h
        ratio = cnt / max_count
        r = int(59 + ratio * 196)
        g = int(130 - ratio * 110)
        b = int(246 - ratio * 230)
        color = f"rgb({r},{g},{b})"
        bars_svg += f'<rect x="{x}" y="{y}" width="{bar_w}" height="{bar_h}" rx="2" fill="{color}"/>'
        if len(days) <= 14 or i % max(1, len(days) // 7) == 0:
            short = day[5:]
            bars_svg += (
                f'<text x="{x + bar_w // 2}" y="{chart_h - 12}" '
                f'text-anchor="middle" font-size="9" fill="#64748b">{short}</text>'
            )

    y_axis = (
        f'<text x="38" y="{chart_h - 30}" text-anchor="end" font-size="9" fill="#94a3b8">{max_count}</text>'
        f'<text x="38" y="{chart_h - 30 - 50}" text-anchor="end" font-size="9" fill="#94a3b8">{max_count // 2}</text>'
        f'<line x1="40" y1="{chart_h - 30}" x2="{chart_w - 10}" y2="{chart_h - 30}" '
        f'stroke="#e2e8f0" stroke-width="1"/>'
    )

    return (
        f'<svg viewBox="0 0 {chart_w} {chart_h}" '
        f'xmlns="http://www.w3.org/2000/svg" style="width:100%;max-width:{chart_w}px">'
        f'{y_axis}{bars_svg}</svg>'
    )


# ── Case report ────────────────────────────────────────────────────────────────

def _tool_registry_html(tool_config: dict | None, ml_stats: "MLStats | None") -> str:
    if not tool_config:
        return ""
    rows = "".join(
        f'<tr><td>{k}</td><td style="font-family:monospace">{v}</td></tr>'
        for k, v in tool_config.items()
    )
    table = (
        '<table><thead><tr><th>Component / Parameter</th><th>Value at Analysis Time</th></tr></thead>'
        f'<tbody>{rows}</tbody></table>'
    )
    stats_table = ""
    if ml_stats and ml_stats.total_verifications > 0:
        def _fmt(v: float | None) -> str:
            return f"{v:.4f}" if v is not None else "N/A"
        stats_table = f"""
<div style="margin-top:14px">
  <p style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:1px;
     color:#94a3b8;margin-bottom:8px">ML Model Validation Metrics (analyst-verified feedback)</p>
  <table>
    <thead><tr><th>Metric</th><th>Value</th><th>Notes</th></tr></thead>
    <tbody>
      <tr><td>Total Analyst Verifications</td><td>{ml_stats.total_verifications}</td>
          <td>Ground-truth labels submitted by analysts via the TP/FP feedback interface</td></tr>
      <tr><td>True Positives</td><td>{ml_stats.true_positives}</td><td></td></tr>
      <tr><td>True Negatives</td><td>{ml_stats.true_negatives}</td><td></td></tr>
      <tr><td>False Positives</td><td>{ml_stats.false_positives}</td><td></td></tr>
      <tr><td>False Negatives</td><td>{ml_stats.false_negatives}</td><td></td></tr>
      <tr><td>Precision</td><td>{_fmt(ml_stats.precision)}</td>
          <td>Of entities flagged as anomalous, fraction confirmed by analyst</td></tr>
      <tr><td>Recall</td><td>{_fmt(ml_stats.recall)}</td>
          <td>Of truly anomalous entities, fraction correctly flagged</td></tr>
      <tr><td>F1 Score</td><td>{_fmt(ml_stats.f1_score)}</td>
          <td>Harmonic mean of precision and recall</td></tr>
      <tr><td>Accuracy</td><td>{_fmt(ml_stats.accuracy)}</td><td></td></tr>
    </tbody>
  </table>
  <p style="font-size:11px;color:#64748b;margin-top:8px">
    <strong>Note:</strong> Metrics are derived from voluntary analyst feedback submitted
    through this platform and are not independently peer-reviewed. They should be
    treated as indicative performance data, not formally validated error rates.
  </p>
</div>"""
    return _sec("Forensic Tool Registry", f"""
<div style="background:#f0f9ff;border:1px solid #bae6fd;border-radius:6px;padding:10px 14px;margin-bottom:12px">
  <p style="font-size:11px;color:#0369a1">
    <strong>Component Provenance (ISO/IEC 27037 §9.1):</strong>
    The tool configuration below was captured at report-generation time.
    It provides a reproducible record of the software environment used during
    this analysis, enabling independent verification.
  </p>
</div>
{table}{stats_table}""")


def _cm(label: str, value: str, mono: bool = False) -> str:
    """Cover-page metadata cell used in generate_case_report."""
    val_style = 'style="font-family:monospace"' if mono else ""
    return (
        f'<div class="cm">{label}'
        f'<span {val_style}>{value}</span></div>'
    )

_CASE_CSS_EXTRA = """
.case-cover{background:linear-gradient(135deg,#0f172a 0%,#1e3a5f 100%);color:#fff;padding:60px 48px 48px}
.case-cover h1{font-size:28px;font-weight:800;letter-spacing:-.5px}
.case-cover .subtitle{color:#7dd3fc;font-size:14px;margin-top:4px;letter-spacing:.5px}
.case-cover .case-meta{display:flex;gap:36px;margin-top:32px;flex-wrap:wrap}
.case-cover .cm{font-size:11px;color:#64748b}
.case-cover .cm span{display:block;color:#e2e8f0;font-size:15px;font-weight:600;margin-top:3px}
.status-active{color:#4ade80}
.status-closed{color:#94a3b8}
.status-archived{color:#fbbf24}
.chart-wrap{padding:8px 0}
.note-card{background:#fffbeb;border:1px solid #fde68a;border-radius:6px;padding:12px 14px;margin-bottom:8px}
.note-card.pinned{background:#eff6ff;border-color:#bfdbfe}
.note-meta{font-size:10px;color:#94a3b8;margin-bottom:4px}
.note-body{font-size:13px;color:#374151;line-height:1.6}
.stat-row{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:16px}
.stat-box{background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;padding:12px;text-align:center}
.stat-box .sv{font-size:22px;font-weight:700;color:#1e293b}
.stat-box .sl{font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#94a3b8;margin-top:2px}
"""


def generate_case_report(
    case: Case,
    result: RCAResult,
    events: list[ForensicEvent],
    notes: list[Note],
    uploads: list[Upload] | None = None,
    ml_stats: MLStats | None = None,
    tool_config: dict | None = None,
) -> str:
    """
    Professional-grade digital forensics case report conforming to:
      ISO/IEC 27037:2012 (digital evidence handling guidelines)
      ACPO Good Practice Guide for Digital Evidence (4 principles)
      SWGDE Best Practices for Computer Forensics
      NIJ Electronic Crime Scene Investigation Guide

    Section order:
      Cover → Document Control → Case Particulars → Examiner Declaration
      → Scope & Objectives → Methodology & Tools → Executive Summary
      → Severity Assessment → Entity Involvement → Root Cause Analysis
      → Investigation Narrative → ATT&CK Kill Chain → Pivot Chain
      → Anomalous Events → Suspicious Events → MITRE ATT&CK Mapping
      → ML Entity Behavior Analysis → IOCs → Detection Rules
      → Remediation Plan → Evidence Manifest / Chain of Custody
      → Analyst Notes → Conclusions → Limitations & Caveats
      → Legal Disclaimer → Signature Block
    """
    sev        = severity_label(result.severity_score)
    now        = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    now_date   = datetime.utcnow().strftime("%Y-%m-%d")
    timestamps = [e.timestamp for e in events]
    t_start    = min(timestamps).strftime("%Y-%m-%d %H:%M") if timestamps else "N/A"
    t_end      = max(timestamps).strftime("%Y-%m-%d %H:%M") if timestamps else "N/A"
    score_color = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#22c55e"}[sev]

    hosts      = sorted({e.source_host for e in events})
    entities   = sorted({e.user for e in events if e.user})
    report_ref = f"FIP-{case.case_id[:8].upper()}-{datetime.utcnow().strftime('%Y%m%d')}"
    analyst    = case.created_by or "Digital Forensics Examiner"

    # ── 1. Cover page ─────────────────────────────────────────────────────────
    sev_bg = {"CRITICAL": "#7f1d1d", "HIGH": "#7c2d12", "MEDIUM": "#713f12", "LOW": "#14532d"}[sev]
    sev_fg = {"CRITICAL": "#fecaca", "HIGH": "#fed7aa", "MEDIUM": "#fef08a", "LOW": "#bbf7d0"}[sev]
    cover = f"""
<div class="case-cover">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:12px;margin-bottom:32px">
    <div>
      <div class="subtitle">DIGITAL FORENSICS INVESTIGATION REPORT</div>
      <div style="font-size:11px;color:#64748b;margin-top:4px;letter-spacing:.5px">
        CONFIDENTIAL — RESTRICTED DISTRIBUTION
      </div>
    </div>
    <div style="text-align:right">
      <div style="background:{sev_bg};color:{sev_fg};padding:6px 16px;border-radius:4px;
                  font-size:12px;font-weight:800;letter-spacing:2px;display:inline-block">
        {sev} SEVERITY
      </div>
    </div>
  </div>
  <h1 style="font-size:26px;font-weight:800;letter-spacing:-.5px;color:#fff;margin-bottom:8px">{case.title}</h1>
  {f'<p style="font-size:13px;color:#94a3b8;margin-bottom:24px;line-height:1.6">{case.description}</p>' if case.description else '<div style="margin-bottom:24px"></div>'}
  <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:20px">
    {_cm("Report Reference", report_ref, mono=True)}
    {_cm("Case Identifier", case.case_id[:16] + "…", mono=True)}
    {_cm("Case Status", case.status.upper())}
    {_cm("Case Opened", case.created_at.strftime("%Y-%m-%d"))}
    {_cm("Examiner", analyst)}
    {_cm("Report Date", now_date)}
    {_cm("Evidence Window", f"{t_start} &ndash; {t_end}")}
    {_cm("Severity Score", f"{result.severity_score}/100 ({sev})")}
  </div>
</div>"""

    # ── 2. Document control ────────────────────────────────────────────────────
    doc_control = _sec("Document Control", f"""
<table>
  <thead><tr><th>Field</th><th>Value</th></tr></thead>
  <tbody>
    <tr><td>Report Reference</td><td style="font-family:monospace">{report_ref}</td></tr>
    <tr><td>Document Version</td><td>1.0 (Auto-generated)</td></tr>
    <tr><td>Classification</td><td>CONFIDENTIAL — FOR AUTHORISED RECIPIENTS ONLY</td></tr>
    <tr><td>Prepared By</td><td>{analyst} (via LateralX Forensic Intelligence Platform)</td></tr>
    <tr><td>Date of Issue</td><td>{now}</td></tr>
    <tr><td>Case Title</td><td>{case.title}</td></tr>
    <tr><td>Case Identifier</td><td style="font-family:monospace">{case.case_id}</td></tr>
    <tr><td>Case Status</td><td>{case.status.upper()}</td></tr>
    <tr><td>Evidence Window Start</td><td>{t_start} UTC</td></tr>
    <tr><td>Evidence Window End</td><td>{t_end} UTC</td></tr>
    <tr><td>Log Events Analysed</td><td>{result.analyzed_event_count:,}</td></tr>
    <tr><td>Hosts in Scope</td><td>{len(hosts)}</td></tr>
    <tr><td>Entity Accounts in Scope</td><td>{len(entities)}</td></tr>
    <tr><td>Generating Platform</td><td>LateralX Forensic Intelligence Platform (FIP)</td></tr>
    <tr><td>Analysis Method</td><td>
      {"AI-assisted (LLM narrative) + Deterministic (MITRE, IOC, ML scoring)"
       if result.windows_analyzed > 0
       else "Deterministic Quick Scan (MITRE, IOC, ML scoring — no LLM)"}
    </td></tr>
  </tbody>
</table>""")

    # ── 3. Case Particulars ───────────────────────────────────────────────────
    case_particulars = _sec("Case Particulars", f"""
<table>
  <thead><tr><th>Item</th><th>Detail</th></tr></thead>
  <tbody>
    <tr><td>Incident Classification</td><td>{
        result.attack_classification.primary_attack.replace("_", " ").title()
        if result.attack_classification else "Under Investigation"
    }</td></tr>
    <tr><td>Severity Rating</td><td><strong style="color:{score_color}">{sev}</strong> ({result.severity_score}/100)</td></tr>
    <tr><td>Analysis Confidence</td><td>{result.confidence.upper()}</td></tr>
    <tr><td>MITRE ATT&amp;CK Techniques Identified</td><td>{len(result.mitre_techniques)}</td></tr>
    <tr><td>Indicators of Compromise (IOCs)</td><td>{len(result.iocs)}</td></tr>
    <tr><td>Patient Zero Candidate</td><td>{result.patient_zero_candidate or "Not positively identified"}</td></tr>
    <tr><td>Initial Access Vector</td><td>{result.initial_access_vector or "Undetermined"}</td></tr>
    <tr><td>Lateral Movement Steps</td><td>{len(result.pivot_chain)}</td></tr>
    <tr><td>Hosts Observed</td><td style="font-family:monospace">{", ".join(hosts[:10])}{"…" if len(hosts) > 10 else ""}</td></tr>
    <tr><td>Entity Accounts Observed</td><td style="font-family:monospace">{", ".join(entities[:10])}{"…" if len(entities) > 10 else ""}</td></tr>
    {f'<tr><td>Attack Classification</td><td>{result.attack_classification.primary_attack.replace("_"," ").title()} ({int(result.attack_classification.confidence*100)}% confidence)</td></tr>' if result.attack_classification else ""}
    {f'<tr><td>Multi-Window Consensus</td><td>{int(result.consensus_agreement*100)}%</td></tr>' if result.consensus_agreement is not None else ""}
  </tbody>
</table>""")

    # ── 4. Examiner Declaration ───────────────────────────────────────────────
    examiner_decl = _sec("Examiner Declaration", f"""
<div style="background:#fffbeb;border:1px solid #fde68a;border-radius:6px;padding:16px 20px;margin-bottom:16px">
  <p style="font-size:12px;font-weight:700;color:#92400e;margin-bottom:6px">DECLARATION OF EXAMINER</p>
  <p style="font-size:13px;color:#374151;line-height:1.7">
    I, <strong>{analyst}</strong>, hereby declare that the digital forensic analysis documented in this
    report was conducted using automated forensic tooling (LateralX FIP) in accordance with
    generally accepted digital forensics principles. The analysis was performed on the evidence
    items listed in the Evidence Manifest section of this report.
  </p>
  <p style="font-size:13px;color:#374151;margin-top:8px;line-height:1.7">
    All findings presented herein are derived directly from the digital evidence submitted to the
    platform. This report accurately represents the output of the automated analysis to the best
    of my knowledge. Where AI-generated narrative is included, it is clearly labelled and should
    be considered an analytical aid subject to expert review, not a standalone forensic conclusion.
  </p>
  <p style="font-size:13px;color:#374151;margin-top:8px;line-height:1.7">
    This report has been generated on <strong>{now}</strong> and relates exclusively to the
    evidence items and time window described herein.
  </p>
</div>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-top:16px">
  <div style="border:1px solid #e2e8f0;border-radius:6px;padding:14px">
    <p style="font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#94a3b8;margin-bottom:4px">Examiner Name</p>
    <p style="font-size:14px;color:#1e293b">{analyst}</p>
  </div>
  <div style="border:1px solid #e2e8f0;border-radius:6px;padding:14px">
    <p style="font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#94a3b8;margin-bottom:4px">Date of Report</p>
    <p style="font-size:14px;color:#1e293b">{now}</p>
  </div>
</div>""")

    # ── 5. Scope and Objectives ───────────────────────────────────────────────
    scope_section = _sec("Scope and Objectives", f"""
<div class="card" style="margin-bottom:12px">
  <h3>Scope of Examination</h3>
  <p>This forensic analysis is limited to the digital evidence items submitted to the platform
  for Case <strong>{case.title}</strong> (Reference: {report_ref}). The examination covers
  {result.analyzed_event_count:,} log events spanning the period from
  <strong>{t_start} UTC</strong> to <strong>{t_end} UTC</strong>, across
  <strong>{len(hosts)}</strong> host system(s).</p>
  <p style="margin-top:8px">The analysis encompasses: identification of attack techniques mapped
  to the MITRE ATT&amp;CK framework; extraction of indicators of compromise; root cause analysis
  including patient-zero identification and lateral movement chain reconstruction; ML-based
  entity behavioural anomaly scoring; and automated generation of detection rules.</p>
</div>
<div class="card">
  <h3>Objectives</h3>
  <p>1. Establish the nature, origin, and scope of the security incident.</p>
  <p style="margin-top:4px">2. Identify the initial access vector and compromised entities.</p>
  <p style="margin-top:4px">3. Map observed adversary behaviour to the MITRE ATT&amp;CK framework.</p>
  <p style="margin-top:4px">4. Extract indicators of compromise for threat intelligence and blocking.</p>
  <p style="margin-top:4px">5. Provide an evidence-based remediation plan proportionate to the identified risk.</p>
</div>""")

    # ── 6. Methodology and Tools ──────────────────────────────────────────────
    is_ai = result.windows_analyzed > 0
    method_section = _sec("Methodology and Analytical Tools", f"""
<div style="margin-bottom:12px">
  <p style="font-size:13px;color:#374151;line-height:1.7">
    Analysis was conducted using the <strong>LateralX Forensic Intelligence Platform (FIP)</strong>,
    an on-premises automated digital forensics tool. No evidence data was transmitted to any
    external cloud service during this analysis. All processing occurred locally on the examiner's
    infrastructure.
  </p>
</div>
<table>
  <thead><tr><th>Analytical Method</th><th>Description</th><th>Applied</th></tr></thead>
  <tbody>
    <tr>
      <td>Event Parsing &amp; Normalisation</td>
      <td>Ingestion and normalisation of log artefacts (CSV, JSON, PCAP) into a structured event model</td>
      <td style="color:#16a34a;font-weight:700">YES</td>
    </tr>
    <tr>
      <td>MITRE ATT&amp;CK Mapping</td>
      <td>Rule-based mapping of observed events to MITRE ATT&amp;CK tactics and techniques via keyword and EventID matching</td>
      <td style="color:#16a34a;font-weight:700">YES</td>
    </tr>
    <tr>
      <td>IOC Extraction</td>
      <td>Automated extraction of IP addresses, domain names, file hashes, registry keys, and file paths from event descriptions</td>
      <td style="color:#16a34a;font-weight:700">YES</td>
    </tr>
    <tr>
      <td>ML Anomaly Scoring (Isolation Forest)</td>
      <td>Unsupervised machine learning model scores each entity session against a learned behavioural baseline</td>
      <td style="color:#16a34a;font-weight:700">YES</td>
    </tr>
    <tr>
      <td>Deterministic Behavioural Checks</td>
      <td>Z-score spike detection, lateral velocity analysis, authentication failure burst detection, off-hours privilege detection</td>
      <td style="color:#16a34a;font-weight:700">YES</td>
    </tr>
    <tr>
      <td>Supervised Attack Classification</td>
      <td>Multi-class classifier assigns primary attack category (ransomware, credential theft, lateral movement, etc.) with confidence score</td>
      <td style="color:{"#16a34a" if result.attack_classification else "#dc2626"};font-weight:700">{"YES" if result.attack_classification else "NO (no classification data)"}</td>
    </tr>
    <tr>
      <td>LLM-assisted Narrative Generation</td>
      <td>Local large language model (Ollama) generates an investigation narrative from windowed event analysis. Output is explainable — each sentence is mapped to source event IDs</td>
      <td style="color:{"#16a34a" if is_ai else "#dc2626"};font-weight:700">{"YES (" + str(result.windows_analyzed) + " analysis windows)" if is_ai else "NO (Quick Scan mode)"}</td>
    </tr>
    <tr>
      <td>Tamper-evident Audit Logging</td>
      <td>All examiner actions (uploads, analyses, exports) recorded in a SHA-256 hash-chained audit log to ensure integrity</td>
      <td style="color:#16a34a;font-weight:700">YES</td>
    </tr>
    <tr>
      <td>Detection Rule Generation</td>
      <td>Automated Sigma and Snort/Suricata rule generation from identified IOCs and MITRE techniques</td>
      <td style="color:#16a34a;font-weight:700">YES</td>
    </tr>
  </tbody>
</table>
<div style="background:#f0f9ff;border:1px solid #bae6fd;border-radius:6px;padding:12px 16px;margin-top:12px">
  <p style="font-size:12px;color:#0369a1">
    <strong>Evidence Handling Note (ISO/IEC 27037:2012 §9):</strong>
    Evidence files are processed read-only. Original files are not modified by the platform.
    SHA-256 hashes of all submitted evidence are recorded at ingestion time (see Evidence Manifest).
    The hash-chain audit log provides a tamper-evident record of all analysis actions.
  </p>
</div>""")

    # ── 7. Forensic Tool Registry ─────────────────────────────────────────────
    tool_registry = _tool_registry_html(tool_config, ml_stats)

    # ── 8. Executive Summary ──────────────────────────────────────────────────
    exec_summary = _exec_summary_html(result, events, sev, t_start, t_end)

    # ── 9. Severity Assessment ────────────────────────────────────────────────
    gauge_svg = _severity_gauge_svg(result.severity_score, score_color)
    gauge_section = f"""
<div class="sec">
  <h2>Severity Assessment</h2>
  <div class="gauge-wrap">
    {gauge_svg}
    <div class="gauge-stats">
      <div class="gstat"><div class="label">Overall Severity</div>
        <div class="value" style="color:{score_color}">{sev}</div></div>
      <div class="gstat"><div class="label">Analysis Confidence</div>
        <div class="value">{result.confidence.upper()}</div></div>
      <div class="gstat"><div class="label">MITRE Techniques</div>
        <div class="value">{len(result.mitre_techniques)}</div></div>
      <div class="gstat"><div class="label">IOCs Extracted</div>
        <div class="value">{len(result.iocs)}</div></div>
    </div>
  </div>
  <div style="margin-top:14px;padding:10px 14px;background:#f8fafc;border-radius:6px;border:1px solid #e2e8f0">
    <p style="font-size:11px;color:#64748b">
      <strong>Severity Scale:</strong>
      CRITICAL (80–100) — Immediate executive escalation required;
      HIGH (60–79) — Urgent response within 24 hours;
      MEDIUM (35–59) — Remediation within 72 hours;
      LOW (0–34) — Scheduled maintenance window.
    </p>
  </div>
</div>"""

    # ── 9. Entity Involvement ─────────────────────────────────────────────────
    entity_section = _entity_involvement_html(events, result)

    # ── 10. Root Cause Analysis ────────────────────────────────────────────────
    rca_section = ""
    if result.patient_zero_candidate or result.initial_access_vector:
        rca_section = _sec("Root Cause Analysis — Attribution Findings", f"""
<div class="two">
  <div class="card"><h3>Patient Zero Candidate</h3>
    <p>{result.patient_zero_candidate or "Not identified"}</p>
    <p style="font-size:11px;color:#94a3b8;margin-top:6px">
      The system or account where the initial compromise is believed to have originated.
    </p>
  </div>
  <div class="card"><h3>Initial Access Vector</h3>
    <p>{result.initial_access_vector or "Undetermined"}</p>
    <p style="font-size:11px;color:#94a3b8;margin-top:6px">
      The technique by which the adversary first gained access to the environment.
    </p>
  </div>
</div>""")

    # ── 11. Investigation Narrative ────────────────────────────────────────────
    narrative_section = ""
    if result.narrative and result.windows_analyzed > 0:
        narr_preview = result.narrative[:600] + ("…" if len(result.narrative) > 600 else "")
        narrative_section = _sec("Investigation Narrative (AI-Assisted)", f"""
<p class="narr">{narr_preview}</p>""", ai=True)

    # ── 12. Event Activity Timeline ────────────────────────────────────────────
    density_svg = _event_density_chart_svg(events)
    density_section = (
        _sec("Event Activity Timeline", f"""
<p style="font-size:12px;color:#64748b;margin-bottom:8px">
  Daily event volume chart showing activity distribution across the evidence window.
  Peaks may indicate periods of intense adversary activity.
</p>
<div class="chart-wrap">{density_svg}</div>""")
        if density_svg else ""
    )

    # ── 13. ATT&CK Kill Chain ──────────────────────────────────────────────────
    kill_chain = _kill_chain_html(result)

    # ── 14. Pivot Chain ────────────────────────────────────────────────────────
    pivot = _pivot_html(result.pivot_chain)

    # ── 16. Suspicious Events (evidence table) ─────────────────────────────────
    suspicious_events = _suspicious_events_html(events, result, limit=15)

    # ── 17. MITRE ATT&CK Techniques ────────────────────────────────────────────
    mitre = _mitre_html(result.mitre_techniques)

    # ── 18. ML Entity Behavior Analysis ────────────────────────────────────────
    ml_svg = _ml_anomaly_chart_svg(result.ml_anomaly_scores or [])
    ml_section = ""
    if ml_svg:
        ml_section = _sec("ML Behavioral Anomaly Scores",
                          f'<div class="chart-wrap">{ml_svg}</div>')

    # ── 19. IOCs ────────────────────────────────────────────────────────────────
    iocs = _ioc_html(result.iocs, limit=15)

    # ── 21. Remediation Plan ────────────────────────────────────────────────────
    remediation = _dynamic_remediation_html(result, events, tier1_only=True)

    # ── 22. Evidence Manifest / Chain of Custody ───────────────────────────────
    evidence_html = ""
    if uploads:
        rows_html = ""
        for i, u in enumerate(uploads, 1):
            ts   = u.uploaded_at.strftime("%Y-%m-%d %H:%M UTC") if u.uploaded_at else "—"
            hash_display = u.file_hash if u.file_hash else "NOT RECORDED"
            hash_style = (
                'style="font-family:monospace;font-size:10px;word-break:break-all"'
                if u.file_hash else
                'style="color:#dc2626;font-size:10px"'
            )
            rows_html += (
                f'<tr>'
                f'<td style="text-align:center;font-weight:700">{i}</td>'
                f'<td style="font-family:monospace">{u.filename}</td>'
                f'<td style="text-align:right">{u.event_count:,}</td>'
                f'<td>{u.uploaded_by or "—"}</td>'
                f'<td>{ts}</td>'
                f'<td {hash_style}>{hash_display}</td>'
                f'</tr>'
            )
        evidence_html = _sec(
            f"Evidence Manifest and Chain of Custody ({len(uploads)} item{'s' if len(uploads) != 1 else ''})",
            f"""
<div style="background:#fffbeb;border:1px solid #fde68a;border-radius:6px;padding:10px 14px;margin-bottom:12px">
  <p style="font-size:11px;color:#92400e">
    <strong>CHAIN OF CUSTODY NOTICE (ACPO Principle 1):</strong>
    Evidence files were processed read-only by the LateralX FIP platform. SHA-256 hashes
    are recorded at ingestion and can be independently verified against the original source
    files. Any item without a recorded hash should be re-verified against the original
    evidence source before reliance in legal proceedings.
  </p>
</div>
<table>
  <thead>
    <tr>
      <th>#</th>
      <th>Evidence Item (Filename)</th>
      <th>Events Parsed</th>
      <th>Submitted By</th>
      <th>Date/Time of Ingestion (UTC)</th>
      <th>SHA-256 Hash (Full)</th>
    </tr>
  </thead>
  <tbody>{rows_html}</tbody>
</table>""",
        )

    # ── 23. Analyst Notes ───────────────────────────────────────────────────────
    notes_html = ""
    if notes:
        note_cards = ""
        pinned = [n for n in notes if n.is_pinned]
        regular = [n for n in notes if not n.is_pinned]
        for n in (pinned + regular):
            pinned_cls = " pinned" if n.is_pinned else ""
            pin_badge  = ' <span style="color:#1d4ed8;font-weight:700">[PINNED]</span>' if n.is_pinned else ""
            ts = n.created_at.strftime("%Y-%m-%d %H:%M UTC")
            note_cards += (
                f'<div class="note-card{pinned_cls}">'
                f'<div class="note-meta">{n.author} &bull; {ts}{pin_badge}</div>'
                f'<div class="note-body">{n.content}</div>'
                f'</div>'
            )
        notes_html = _sec(f"Analyst Working Notes ({len(notes)} note{'s' if len(notes) != 1 else ''})", f"""
<div style="background:#eff6ff;border:1px solid #bfdbfe;border-radius:6px;padding:10px 14px;margin-bottom:12px">
  <p style="font-size:11px;color:#1e40af">
    Analyst notes are recorded observations made by the examining analyst during the investigation.
    They represent contemporaneous working notes and form part of the evidential record.
  </p>
</div>
{note_cards}""")

    # ── 24. Conclusions ──────────────────────────────────────────────────────────
    attack_type_str = (
        result.attack_classification.primary_attack.replace("_", " ").title()
        if result.attack_classification else "undetermined"
    )
    conclusions = _sec("Conclusions", f"""
<div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;padding:16px 20px">
  <ol style="margin:0 0 0 20px;font-size:13px;color:#374151;line-height:2">
    <li>Incident of <strong>{sev.lower()} severity</strong> ({result.severity_score}/100), classified as <strong>{attack_type_str}</strong>.</li>
    <li>{'Patient-zero: <strong>' + result.patient_zero_candidate + '</strong>.' if result.patient_zero_candidate else 'Patient-zero not positively identified.'}</li>
    <li>{'Initial access: <strong>' + result.initial_access_vector + '</strong>.' if result.initial_access_vector else 'Initial access vector undetermined.'}</li>
    <li>{len(result.mitre_techniques)} ATT&amp;CK technique(s) across {len({t.tactic for t in result.mitre_techniques})} tactic(s). {len(result.iocs)} IOC(s) extracted.</li>
  </ol>
</div>""")

    # ── 25. Limitations and Caveats ──────────────────────────────────────────────
    limitations = _sec("Limitations and Professional Caveats", f"""
<div style="background:#fff7ed;border:1px solid #fed7aa;border-radius:6px;padding:16px 20px">
  <p style="font-size:12px;font-weight:700;color:#c2410c;margin-bottom:10px">
    IMPORTANT — READ BEFORE RELYING ON THIS REPORT IN LEGAL PROCEEDINGS
  </p>
  <ol style="margin:0 0 0 18px;font-size:13px;color:#374151;line-height:2.1">
    <li><strong>AI-Generated Narrative:</strong> Where a narrative section is present, it was generated
    by a local large language model (LLM). LLM output is probabilistic and may contain errors,
    hallucinations, or omissions. Every factual claim in the narrative should be independently
    verified against the cited source events before use in legal proceedings.</li>
    <li><strong>Automated MITRE Mapping:</strong> MITRE ATT&amp;CK technique mapping is performed
    by keyword and EventID matching heuristics. Some mappings may be false positives; others may
    be absent if relevant evidence was not present in the ingested log files.</li>
    <li><strong>ML Anomaly Scores:</strong> Entity anomaly scores are statistical outlier indicators,
    not evidence of malicious activity per se. A high-risk score indicates statistical deviation
    from the training baseline and requires manual investigation to confirm.</li>
    <li><strong>Evidence Completeness:</strong> This analysis is limited to the log artefacts
    submitted to the platform. Absence of evidence is not evidence of absence. Logs may be
    incomplete, tampered with, or cover only a subset of the affected systems.</li>
    <li><strong>Temporal Scope:</strong> The analysis covers only the evidence window from
    {t_start} to {t_end} UTC. Activity outside this window is not reflected in this report.</li>
    <li><strong>Tool Validation:</strong> The LateralX FIP platform has not been formally accredited
    by UKAS, ASCLD, or an equivalent forensic accreditation body. Results should be corroborated
    by a qualified, accredited forensic examiner before submission as primary evidence in court.</li>
    <li><strong>Hash Verification:</strong> Chain-of-custody integrity depends on SHA-256 hashes
    recorded at ingestion. If original evidence files are unavailable for comparison, the integrity
    of the evidence chain cannot be formally verified.</li>
  </ol>
</div>""")

    # ── 26. Legal Disclaimer ──────────────────────────────────────────────────────
    legal_disclaimer = _sec("Legal Disclaimer", f"""
<div style="border:1px solid #e2e8f0;border-radius:6px;padding:14px 18px;font-size:12px;color:#374151;line-height:1.8">
  <p>This report has been generated automatically by the LateralX Forensic Intelligence Platform
  (FIP) for use by authorised personnel only. It is provided for informational and investigative
  purposes and does not constitute legal advice.</p>
  <p style="margin-top:8px">The findings in this report are derived from automated analysis of
  digital artefacts and represent the output of software-based detection methods. They are
  intended to support, not replace, the independent judgment of a qualified digital forensics
  examiner.</p>
  <p style="margin-top:8px">This report and its contents are CONFIDENTIAL. Unauthorised
  disclosure, distribution, or reproduction is prohibited. Recipients are responsible for
  ensuring this document is handled in accordance with applicable data protection legislation
  (including but not limited to GDPR, UK GDPR, and any jurisdiction-specific equivalents)
  and in a manner consistent with the classification marking on the cover page.</p>
  <p style="margin-top:8px">For questions regarding the methodology, tooling, or findings
  contained within this report, contact the named examiner.</p>
</div>""")

    # ── 27. Signature Block ────────────────────────────────────────────────────────
    signature_block = _sec("Certification", f"""
<div style="display:grid;grid-template-columns:1fr 1fr;gap:24px">
  <div style="border:1px solid #e2e8f0;border-radius:6px;padding:14px">
    <p style="font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#94a3b8;margin-bottom:4px">Examiner</p>
    <p style="font-size:14px;color:#1e293b">{analyst}</p>
  </div>
  <div style="border:1px solid #e2e8f0;border-radius:6px;padding:14px">
    <p style="font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#94a3b8;margin-bottom:4px">Report Reference</p>
    <p style="font-size:14px;font-family:monospace;color:#1e293b">{report_ref}</p>
    <p style="font-size:11px;color:#64748b">{now}</p>
  </div>
</div>""")

    footer = (
        f'<div class="ftr">'
        f'<span>LateralX FIP — Digital Forensics Case Report &bull; {report_ref}</span>'
        f'<span>CONFIDENTIAL &bull; {now}</span>'
        f'</div>'
    )

    body = (
        cover
        + case_particulars
        + exec_summary
        + gauge_section
        + rca_section
        + narrative_section
        + density_section
        + kill_chain
        + pivot
        + suspicious_events
        + mitre
        + ml_section
        + iocs
        + remediation
        + evidence_html
        + notes_html
        + conclusions
        + signature_block
        + footer
    )

    combined_css = _CSS + _CASE_CSS_EXTRA
    return (
        f'<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">'
        f'<meta name="description" content="Forensic Case Report — {case.title}">'
        f'<title>Forensic Report — {case.title} — {report_ref}</title>'
        f'<style>{combined_css}</style></head>'
        f'<body><div class="page">{body}</div></body></html>'
    )


# ── Court-mode report ──────────────────────────────────────────────────────────

_COURT_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
@page{margin:2.5cm 2cm}
@media print{
  .pb{page-break-before:always}
  .no-break{page-break-inside:avoid}
}
body{font-family:'Times New Roman',Georgia,serif;color:#000;background:#fff;font-size:11pt;line-height:1.65}
.page{max-width:860px;margin:0 auto;padding:48px 40px}
h1{font-family:Arial,Helvetica,sans-serif;font-size:20pt;text-align:center;margin-bottom:6px;letter-spacing:-.3px}
h2{font-family:Arial,Helvetica,sans-serif;font-size:12pt;margin-top:32px;margin-bottom:8px;
   border-bottom:2px solid #000;padding-bottom:4px;text-transform:uppercase;letter-spacing:.5px}
h3{font-family:Arial,Helvetica,sans-serif;font-size:10.5pt;margin-top:14px;margin-bottom:5px}
p{margin-bottom:8px}
table{width:100%;border-collapse:collapse;font-size:10pt;margin:10px 0}
th{text-align:left;padding:5px 8px;background:#e0e0e0;font-family:Arial,Helvetica,sans-serif;
   font-size:9pt;border:1px solid #888;font-weight:700}
td{padding:4px 8px;border:1px solid #bbb;vertical-align:top;word-break:break-word}
.cover{text-align:center;padding:60px 20px 40px;border-bottom:3px double #000;margin-bottom:36px}
.cover .sub{font-family:Arial,sans-serif;font-size:12pt;letter-spacing:2px;text-transform:uppercase;margin-bottom:16px;color:#333}
.cover h1{font-size:22pt}
.cover .meta{margin-top:28px;font-size:10pt;line-height:2}
.cover .report-id{font-family:'Courier New',monospace;font-size:9pt;color:#444;margin-top:12px}
.meta-tbl{width:100%;border-collapse:collapse;margin:10px 0;font-size:10pt}
.meta-tbl td{padding:4px 6px;border:none;vertical-align:top}
.meta-tbl td:first-child{font-family:Arial,sans-serif;font-weight:700;width:200px;color:#222}
.integrity-ok{font-family:Arial,sans-serif;font-weight:700}
.integrity-fail{font-family:Arial,sans-serif;font-weight:700;text-decoration:underline}
.ev-num{font-family:'Courier New',monospace;font-size:9pt;color:#444;min-width:44px;display:inline-block}
.ev-sus{font-family:Arial,sans-serif;font-size:9pt;font-weight:700}
.ev-row{padding:3px 0;border-bottom:1px solid #ddd;font-size:10pt}
.attestation{border:2px solid #000;padding:24px 28px;margin-top:36px}
.sig-line{border-top:1px solid #000;margin-top:48px;padding-top:4px;font-size:9pt;font-family:Arial,sans-serif}
.footer{font-size:9pt;margin-top:28px;border-top:1px solid #000;padding-top:8px;
        text-align:center;font-family:Arial,sans-serif;color:#333}
.notice{border:1px solid #999;padding:12px 16px;background:#f5f5f5;font-size:10pt;margin-bottom:16px}
code{font-family:'Courier New',monospace;font-size:9pt}
"""


def _court_sec(roman: str, title: str, body: str) -> str:
    return f'<h2>{roman}. {title}</h2>{body}'


def generate_court_report(
    result: RCAResult,
    events: list[ForensicEvent],
    *,
    audit_status: dict | None = None,
    uploads: list | None = None,
    case: object | None = None,
) -> str:
    """
    Court-ready forensic report: black-and-white, printer-optimised, formally
    structured with Roman-numeral sections, chain-of-custody verification,
    and an analyst attestation block.  Suitable for submission as a forensic
    exhibit in legal proceedings.

    Parameters
    ----------
    result        : RCAResult from the latest analysis run.
    events        : All forensic events in scope for this report.
    audit_status  : dict from /audit-log/verify — hash-chain verification result.
    uploads       : List of Upload ORM rows (evidence file manifest).
    case          : Optional Case ORM row (adds case metadata to cover).
    """
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    sev = severity_label(result.severity_score)
    timestamps = [e.timestamp for e in events]
    t_start = min(timestamps).strftime("%Y-%m-%d %H:%M") if timestamps else "Not available"
    t_end   = max(timestamps).strftime("%Y-%m-%d %H:%M") if timestamps else "Not available"

    case_title = getattr(case, "title", None) or "Forensic Workspace Analysis"
    case_id    = getattr(case, "case_id", None) or "N/A"
    analyst    = getattr(case, "created_by", None) or "Not recorded"
    report_id  = f"FIP-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"

    # ── Cover page ────────────────────────────────────────────────────────────
    cover = f"""
<div class="cover">
  <div class="sub">Forensic Intelligence Report</div>
  <h1>{case_title}</h1>
  <div class="meta">
    <div>Report Reference: <strong>{report_id}</strong></div>
    <div>Date / Time Generated: <strong>{now}</strong></div>
    <div>Examining Analyst: <strong>{analyst}</strong></div>
    <div>Case Identifier: <strong>{case_id}</strong></div>
    <div>Evidence Period: <strong>{t_start}</strong> to <strong>{t_end}</strong></div>
    <div>Overall Severity Assessment: <strong>{sev} ({result.severity_score}/100)</strong></div>
    <div>Analysis Confidence: <strong>{result.confidence.upper()}</strong></div>
  </div>
  <div class="report-id">
    Platform: Forensic Intelligence Pipeline (air-gapped, Ollama local inference) &mdash;
    Report type: Court-Ready Exhibit
  </div>
</div>

<div class="notice">
  <strong>IMPORTANT NOTICE:</strong> This report was generated by an automated forensic
  analysis platform and must be reviewed by a qualified digital forensic examiner before
  submission as evidence. The findings presented herein are based solely on the digital
  artefacts ingested into the system and are subject to the limitations described herein.
</div>"""

    # ── I. Chain of Custody & Evidence Integrity ──────────────────────────────
    chain_rows = ""
    if audit_status:
        valid    = audit_status.get("valid", False)
        total    = audit_status.get("total", 0)
        chained  = audit_status.get("chained", 0)
        legacy   = audit_status.get("legacy_pre_chain", 0)
        broken   = audit_status.get("broken_at")
        msg      = audit_status.get("message", "Unknown")
        status_cls  = "integrity-ok" if valid else "integrity-fail"
        status_text = "VERIFIED — Chain intact" if valid else f"ALERT — Chain broken at entry #{broken}"
        chain_rows = f"""
<table class="meta-tbl">
  <tr><td>Hash Chain Status</td>
      <td><span class="{status_cls}">{status_text}</span></td></tr>
  <tr><td>Total Audit Entries</td><td>{total}</td></tr>
  <tr><td>Hash-Chained Entries</td><td>{chained}</td></tr>
  <tr><td>Legacy Entries (pre-chain)</td><td>{legacy}</td></tr>
  <tr><td>Verification Message</td><td>{msg}</td></tr>
</table>"""
    else:
        chain_rows = '<p>Audit chain verification was not performed for this report.</p>'

    file_rows = ""
    if uploads:
        file_tbl_rows = "".join(
            f'<tr><td><code>{u.filename}</code></td>'
            f'<td>{u.event_count:,}</td>'
            f'<td>{u.uploaded_by or "—"}</td>'
            f'<td>{u.uploaded_at.strftime("%Y-%m-%d %H:%M") if u.uploaded_at else "—"}</td>'
            f'<td><code>{u.file_hash or "—"}</code></td></tr>'
            for u in uploads
        )
        file_rows = (
            '<h3>Evidence File Manifest</h3>'
            '<table><thead><tr>'
            '<th>Filename</th><th>Events</th><th>Uploaded By</th>'
            '<th>Upload Time (UTC)</th><th>SHA-256 Hash</th>'
            '</tr></thead><tbody>' + file_tbl_rows + '</tbody></table>'
        )
    else:
        file_rows = '<p>No file upload records available.</p>'

    chain_section = _court_sec(
        "I", "Chain of Custody &amp; Evidence Integrity",
        chain_rows + file_rows,
    )

    # ── II. Executive Summary ─────────────────────────────────────────────────
    hosts = sorted({e.source_host for e in events})
    users = sorted({e.user for e in events if e.user})
    summary_rows = f"""
<table class="meta-tbl">
  <tr><td>Incident Severity</td><td><strong>{sev}</strong> ({result.severity_score}/100)</td></tr>
  <tr><td>Analysis Confidence</td><td>{result.confidence.upper()}</td></tr>
  <tr><td>Total Events Examined</td><td>{result.analyzed_event_count:,}</td></tr>
  <tr><td>Analysis Windows</td><td>{result.windows_analyzed}</td></tr>
  <tr><td>Evidence Period Start</td><td>{t_start}</td></tr>
  <tr><td>Evidence Period End</td><td>{t_end}</td></tr>
  <tr><td>Hosts Involved</td><td>{", ".join(hosts) if hosts else "None identified"}</td></tr>
  <tr><td>User Accounts Active</td><td>{", ".join(users[:10]) if users else "None identified"}{"…" if len(users) > 10 else ""}</td></tr>
  <tr><td>Patient Zero Candidate</td><td>{result.patient_zero_candidate or "Not identified"}</td></tr>
  <tr><td>Initial Access Vector</td><td>{result.initial_access_vector or "Unknown"}</td></tr>
  <tr><td>MITRE Techniques Mapped</td><td>{len(result.mitre_techniques)}</td></tr>
  <tr><td>Indicators of Compromise</td><td>{len(result.iocs)}</td></tr>
</table>"""
    exec_section = _court_sec("II", "Executive Summary", summary_rows)

    # ── III. Incident Narrative ───────────────────────────────────────────────
    narrative_body = (
        f'<p style="font-style:italic;line-height:1.8">{result.narrative}</p>'
        if result.narrative else "<p>No narrative available.</p>"
    )
    if result.pivot_chain:
        pivot_items = "".join(
            f'<li style="padding:3px 0">{i+1}. {step}</li>'
            for i, step in enumerate(result.pivot_chain)
        )
        narrative_body += f'<h3>Lateral Movement — Pivot Chain</h3><ul>{pivot_items}</ul>'
    narrative_section = _court_sec("III", "Incident Narrative", narrative_body)

    # ── IV. MITRE ATT&CK Findings ─────────────────────────────────────────────
    if result.mitre_techniques:
        mitre_rows = "".join(
            f'<tr><td><code>{t.id}</code></td><td>{t.name}</td><td>{t.tactic}</td>'
            f'<td>{t.evidence or "—"}</td></tr>'
            for t in result.mitre_techniques
        )
        mitre_body = (
            '<table><thead><tr><th>Technique ID</th><th>Name</th>'
            '<th>Tactic</th><th>Evidence</th></tr></thead>'
            f'<tbody>{mitre_rows}</tbody></table>'
        )
    else:
        mitre_body = "<p>No MITRE ATT&amp;CK techniques identified.</p>"
    mitre_section = _court_sec("IV", "MITRE ATT&amp;CK Technique Mapping", mitre_body)

    # ── V. Indicators of Compromise ───────────────────────────────────────────
    if result.iocs:
        ioc_rows = "".join(
            f'<tr><td>{i.type}</td><td><code>{i.value}</code></td>'
            f'<td>{i.context[:120]}{"…" if len(i.context) > 120 else ""}</td></tr>'
            for i in result.iocs
        )
        ioc_body = (
            f'<p>Total: {len(result.iocs)} indicator(s) extracted.</p>'
            '<table><thead><tr><th>Type</th><th>Value</th><th>Context</th></tr></thead>'
            f'<tbody>{ioc_rows}</tbody></table>'
        )
    else:
        ioc_body = "<p>No indicators of compromise extracted.</p>"
    ioc_section = _court_sec("V", "Indicators of Compromise", ioc_body)

    # ── VI. Suspicious Event Index ────────────────────────────────────────────
    flagged_events: list[tuple[ForensicEvent, str]] = []
    for e in events:
        hit = _detect_suspicious(e)
        if hit:
            reason, _ = hit
            flagged_events.append((e, reason))
    flagged_events.sort(key=lambda x: x[0].timestamp)

    cap = 500
    noted = f" (showing first {cap} of {len(flagged_events)} — full dataset on record)" if len(flagged_events) > cap else ""
    if flagged_events:
        ev_rows = ""
        for idx, (e, reason) in enumerate(flagged_events[:cap], 1):
            ts  = e.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            eid = f" EID:{e.event_id}" if e.event_id else ""
            ev_rows += (
                f'<div class="ev-row no-break">'
                f'<span class="ev-num">[{idx:04d}]</span> '
                f'<strong>{ts}</strong> &mdash; {e.source_host} '
                f'({e.user or "no user"}){eid} &mdash; '
                f'<span class="ev-sus">[{reason}]</span> &mdash; '
                f'{e.description[:200]}{"…" if len(e.description) > 200 else ""}'
                f'</div>'
            )
        ev_body = (
            f'<p>Total flagged events: <strong>{len(flagged_events)}</strong>{noted}</p>'
            f'<div style="margin-top:10px">{ev_rows}</div>'
        )
    else:
        total_ev = len(events)
        ev_body = f'<p>No suspicious events detected in the {total_ev:,}-event dataset.</p>'
    ev_section = _court_sec("VI", "Suspicious Event Index", ev_body)

    # ── VII. Analyst Attestation ──────────────────────────────────────────────
    attestation = f"""
<div class="attestation no-break">
  <h3 style="font-family:Arial,sans-serif;margin-bottom:16px">VII. Analyst Attestation</h3>
  <p>I, the undersigned digital forensic examiner, hereby certify that:</p>
  <ol style="margin:12px 0 12px 24px;line-height:2">
    <li>The forensic examination described in this report was conducted using
        the Forensic Intelligence Platform, operating in air-gapped mode with
        local Ollama inference (no external data transmission).</li>
    <li>The evidence files listed in Section I were examined without
        modification; their SHA-256 hashes confirm integrity as recorded.</li>
    <li>The findings contained herein represent the output of automated
        forensic analysis and have been reviewed for accuracy and completeness
        by the examiner prior to submission.</li>
    <li>This report was generated on <strong>{now}</strong> and reflects the
        state of evidence at that time.</li>
  </ol>
  <div class="sig-line" style="margin-top:48px">
    Examiner name (print): _______________________________________________
  </div>
  <div class="sig-line" style="margin-top:36px">
    Signature: _____________________________________________ &nbsp;&nbsp;
    Date: _______________________
  </div>
  <div class="sig-line" style="margin-top:36px">
    Certifications / Qualifications: _____________________________________
  </div>
  <div class="sig-line" style="margin-top:36px">
    Organisation: ________________________________________________________
  </div>
</div>"""

    footer = (
        f'<div class="footer">'
        f'Forensic Intelligence Pipeline — Court-Ready Report &mdash; '
        f'Report ID: {report_id} &mdash; Generated: {now} UTC'
        f'</div>'
    )

    body = (
        cover
        + chain_section
        + '<div class="pb"></div>'
        + exec_section
        + narrative_section
        + '<div class="pb"></div>'
        + mitre_section
        + ioc_section
        + '<div class="pb"></div>'
        + ev_section
        + '<div class="pb"></div>'
        + attestation
        + footer
    )

    return (
        f'<!DOCTYPE html><html lang="en">'
        f'<head><meta charset="UTF-8">'
        f'<title>Court Report — {report_id}</title>'
        f'<style>{_COURT_CSS}</style></head>'
        f'<body><div class="page">{body}</div></body></html>'
    )
