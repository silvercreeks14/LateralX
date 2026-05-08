"""
Incident severity scorer.
Rule-based 0–100 score built from ATT&CK technique weights,
lateral movement, blast radius, and confirmed privileged abuse.
"""

from backend.schema import ForensicEvent, MitreTechnique

# ATT&CK technique → severity contribution points
_WEIGHTS: dict[str, int] = {
    "T1490": 20,      # Inhibit System Recovery (ransomware prep)
    "T1486": 20,      # Data Encrypted for Impact
    "T1485": 20,      # Data Destruction
    "T1003.001": 15,  # LSASS credential dump
    "T1558.003": 12,  # Kerberoasting
    "T1136.001": 10,  # Local account creation (persistence)
    "T1053.005": 9,   # Scheduled task (persistence)
    "T1547.001": 8,   # Registry run key (persistence)
    "T1543.003": 8,   # Windows service (persistence)
    "T1021.002": 10,  # Lateral movement SMB
    "T1078": 5,       # Valid accounts — weight lowered; trigger tightened in mitre.py
    "T1105": 7,       # Tool download
    "T1059.001": 7,   # PowerShell
    "T1218.005": 6,   # Mshta LOLBin
    "T1047": 6,       # WMI execution
    "T1059.003": 4,   # Command shell
    "T1218.010": 4,   # Regsvr32
    "T1021.001": 8,   # RDP lateral movement
    "T1021.006": 7,   # WinRM lateral movement
    "T1048.003": 9,   # Exfiltration over unencrypted protocol
    "T1082": 2,       # Discovery
}

# Attack-specific artefacts that reliably indicate malicious activity
_HIGH_SIGNAL_KEYWORDS = frozenset({
    "certutil", "mimikatz", "lsass", "vssadmin", "psexec", "mshta",
    "-enc", "encodedcommand", "procdump", "dcsync", "sekurlsa",
    "net user /add", "schtasks /create", "reg add", "sc create",
})


def calculate_severity(
    events: list[ForensicEvent],
    mitre_techniques: list[MitreTechnique],
    suspicious_users: list[str],
) -> int:
    """
    Score breakdown (max 100):
      MITRE technique weights          up to 40
      Lateral movement                 up to 20
      Host blast radius                up to 15
      Privileged account + abuse       up to 15
      High-signal evidence bonus       up to 10

    Volume alone is not scored — a 200-event backup log should not score
    higher than a 10-event mimikatz execution.
    """
    score = 0

    # MITRE weights (capped at 40)
    score += min(sum(_WEIGHTS.get(t.id, 2) for t in mitre_techniques), 40)

    # Lateral movement flagged by graph analysis
    if suspicious_users:
        score += 20

    # Blast radius — unique hosts involved (capped at 15)
    score += min(len(set(e.source_host for e in events)) * 3, 15)

    # Privileged account performing a confirmed suspicious action.
    # Requires BOTH a privileged username AND a high-signal keyword in the
    # same event — prevents normal SYSTEM/service scheduling from scoring.
    _PRIV_TERMS = ("admin", "svc_", "service", "system", "root")
    for event in events:
        u = (event.user or "").lower()
        if any(kw in u for kw in _PRIV_TERMS):
            desc_lower = event.description.lower()
            if any(sig in desc_lower for sig in _HIGH_SIGNAL_KEYWORDS):
                score += 15
                break

    # High-signal evidence bonus: count distinct attack artefacts present
    found: set[str] = set()
    for event in events:
        desc = event.description.lower()
        for sig in _HIGH_SIGNAL_KEYWORDS:
            if sig in desc:
                found.add(sig)
    if len(found) >= 3:
        score += 10
    elif found:
        score += 5

    return min(score, 100)


def severity_label(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    elif score >= 50:
        return "HIGH"
    elif score >= 25:
        return "MEDIUM"
    return "LOW"
