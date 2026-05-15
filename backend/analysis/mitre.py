"""
MITRE ATT&CK technique mapper.
Pure Python — no LLM call needed. Maps keyword patterns in event
descriptions to standardised ATT&CK technique IDs.
"""

from backend.schema import ForensicEvent, MitreTechnique

# (trigger_keywords, technique) — first match per technique ID wins
_MAP: list[tuple[list[str], MitreTechnique]] = [
    (["certutil", "urlcache", "bitsadmin /transfer"],
     MitreTechnique(id="T1105", name="Ingress Tool Transfer", tactic="Command and Control")),

    (["vssadmin delete", "wmic shadowcopy delete", "shadowcopy delete"],
     MitreTechnique(id="T1490", name="Inhibit System Recovery", tactic="Impact")),

    (["mshta"],
     MitreTechnique(id="T1218.005", name="Mshta", tactic="Defense Evasion")),

    (["wmic"],
     MitreTechnique(id="T1047", name="Windows Management Instrumentation", tactic="Execution")),

    (["-encodedcommand", "-enc ", "powershell.exe -enc"],
     MitreTechnique(id="T1059.001", name="PowerShell (Encoded)", tactic="Execution")),

    (["powershell"],
     MitreTechnique(id="T1059.001", name="PowerShell", tactic="Execution")),

    (["cmd.exe", "cmd /c", "cmd.exe /c"],
     MitreTechnique(id="T1059.003", name="Windows Command Shell", tactic="Execution")),

    (["regsvr32"],
     MitreTechnique(id="T1218.010", name="Regsvr32", tactic="Defense Evasion")),

    (["net use", "psexec", "\\\\"],
     MitreTechnique(id="T1021.002", name="SMB/Windows Admin Shares", tactic="Lateral Movement")),

    # RDP lateral movement: require session-hijack tool or explicit type-10 logon context
    (["mstsc.exe", "tscon.exe", "logon type: 10", "xfreerdp", "shadow rdp"],
     MitreTechnique(id="T1021.001", name="Remote Desktop Protocol", tactic="Lateral Movement")),

    # WinRM remote execution
    (["winrm", "invoke-command", "enter-pssession", "new-pssession", "psremoting"],
     MitreTechnique(id="T1021.006", name="Windows Remote Management", tactic="Lateral Movement")),

    # EIDs 4624/4648 fire on every successful logon — too broad for lateral movement.
    # Require network logon context (type 3) or explicit lateral movement tooling.
    (["logon type: 3", "pass-the-hash", "overpass-the-hash", "pth attack"],
     MitreTechnique(id="T1078", name="Valid Accounts", tactic="Lateral Movement")),

    # Exfiltration: require explicit tooling keywords, not just any DNS/FTP traffic
    (["dnscat", "dns exfiltration", "dns covert channel", "certutil -encode",
      "icmp tunnel", "iodine", "nslookup -type=txt exfil"],
     MitreTechnique(id="T1048.003", name="Exfiltration Over Unencrypted Protocol", tactic="Exfiltration")),

    # Large outbound transfer flagged by network correlator (bytes_out in description)
    (["t1048 exfil", "large outbound transfer", "bytes_out", "data exfiltrated"],
     MitreTechnique(id="T1048", name="Exfiltration Over Alternative Protocol", tactic="Exfiltration")),

    # DDoS: network-level denial of service
    # Includes Windows Filtering Platform event signatures (EID 5152/5156/5157 flood)
    # and port exhaustion (EID 4227) which is a reliable DDoS symptom
    (["ddos", "denial of service", "syn flood", "udp flood", "icmp flood",
      "volumetric attack", "amplification attack", "connection flood",
      "t1498", "network dos", "network denial",
      "port exhaustion", "high rates of connections",
      "filtering platform has blocked a packet",
      "filtering platform has blocked a connection"],
     MitreTechnique(id="T1498", name="Network Denial of Service", tactic="Impact")),

    # Endpoint DoS: service timeouts and application-layer exhaustion
    # EID 7011 (service transaction timeout) is a direct DDoS impact indicator
    (["application layer dos", "http flood", "slow loris", "slowloris",
      "endpoint dos", "resource exhaustion", "cpu exhaustion", "t1499",
      "timeout.*waiting for a transaction", "w3svc", "world wide web publishing",
      "service timed out", "iis timeout"],
     MitreTechnique(id="T1499", name="Endpoint Denial of Service", tactic="Impact")),

    # ── AD Credential Attacks ────────────────────────────────────────────────
    # EIDs 4768/4769 fire on all Kerberos ticket activity — require explicit tooling keywords.
    (["kerberoast", "getuserspns", "as-rep roasting", "spn scan", "etype 0x17", "rc4-hmac"],
     MitreTechnique(id="T1558.003", name="Kerberoasting", tactic="Credential Access")),

    (["as-rep roast", "asreproast", "getnpusers", "preauth not required",
      "UF_DONT_REQUIRE_PREAUTH"],
     MitreTechnique(id="T1558.004", name="AS-REP Roasting", tactic="Credential Access")),

    (["dcsync", "ds-replication", "1131f6aa", "lsadump::dcsync", "getchangesall"],
     MitreTechnique(id="T1003.006", name="DCSync", tactic="Credential Access")),

    (["golden ticket", "lsadump::golden", "krbtgt hash", "kerberos::golden"],
     MitreTechnique(id="T1558.001", name="Golden Ticket", tactic="Credential Access")),

    (["silver ticket", "lsadump::silver", "forged tgs"],
     MitreTechnique(id="T1558.002", name="Silver Ticket", tactic="Credential Access")),

    (["pass-the-hash", "sekurlsa::pth", "pth attack", "overpass-the-hash",
      "ntlm hash logon"],
     MitreTechnique(id="T1550.002", name="Pass the Hash", tactic="Lateral Movement")),

    (["pass-the-ticket", "rubeus ptt", "kerberos::ptt", "use ticket"],
     MitreTechnique(id="T1550.003", name="Pass the Ticket", tactic="Lateral Movement")),

    (["skeleton key", "misc::skeleton", "patching lsass"],
     MitreTechnique(id="T1207", name="Rogue Domain Controller (Skeleton Key)",
                    tactic="Defense Evasion")),

    # ── AD Reconnaissance ────────────────────────────────────────────────────
    (["bloodhound", "sharphound", "invoke-bloodhound", "collectionmethod"],
     MitreTechnique(id="T1069.002", name="Domain Groups Discovery (BloodHound)",
                    tactic="Discovery")),

    (["ldapdomaindump", "adrecon", "ldap dump", "ldap query"],
     MitreTechnique(id="T1087.002", name="Domain Account Enumeration", tactic="Discovery")),

    (["powerview", "get-domainuser", "get-domaingroupmember", "find-localadminaccess",
      "get-netgroupmember"],
     MitreTechnique(id="T1069.002", name="Domain Groups Discovery (PowerView)",
                    tactic="Discovery")),

    (["nltest /dclist", "net group /domain", "net user /domain", "dsquery"],
     MitreTechnique(id="T1087.002", name="Domain Account Discovery", tactic="Discovery")),

    # ── NTLM Relay ───────────────────────────────────────────────────────────
    (["responder", "ntlmrelayx", "smbrelayx", "llmnr poison", "nbt-ns poison"],
     MitreTechnique(id="T1557.001", name="LLMNR/NBT-NS Poisoning and SMB Relay",
                    tactic="Credential Access")),

    # ── General Credential / System Discovery ────────────────────────────────
    (["whoami", "ipconfig", "net user", "systeminfo", "hostname"],
     MitreTechnique(id="T1082", name="System Information Discovery", tactic="Discovery")),

    (["schtasks", "taskschd", "at.exe"],
     MitreTechnique(id="T1053.005", name="Scheduled Task", tactic="Persistence")),

    (["reg add", "run\\", "runonce\\"],
     MitreTechnique(id="T1547.001", name="Registry Run Keys", tactic="Persistence")),

    (["mimikatz", "lsass.exe", "procdump", "comsvcs.dll", "ntds.dit", "secretsdump"],
     MitreTechnique(id="T1003.001", name="LSASS Memory Dumping", tactic="Credential Access")),

    (["net localgroup administrators", "net user /add"],
     MitreTechnique(id="T1136.001", name="Local Account Creation", tactic="Persistence")),

    (["sc create", "sc config", "services.exe"],
     MitreTechnique(id="T1543.003", name="Windows Service", tactic="Persistence")),

    # ── AD Group/Policy Manipulation ─────────────────────────────────────────
    (["net group /add", "add-adgroupmember", "net localgroup /add domain admins"],
     MitreTechnique(id="T1098.007", name="Additional Group Membership",
                    tactic="Persistence")),

    (["set-domainobject", "set-addomainmode", "gpupdate /force", "domain policy"],
     MitreTechnique(id="T1484.001", name="Domain Policy Modification", tactic="Defense Evasion")),
]

_TACTIC_ORDER = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery",
    "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact",
]


def map_techniques(events: list[ForensicEvent]) -> list[MitreTechnique]:
    """
    Scan all events for ATT&CK indicator keywords.
    Returns a deduplicated, tactic-ordered list of matched techniques.
    """
    seen_ids: set[str] = set()
    results: list[MitreTechnique] = []

    for event in events:
        combined = (event.description + " " + event.event_type).lower()
        for keywords, technique in _MAP:
            if technique.id in seen_ids:
                continue
            if any(kw.lower() in combined for kw in keywords):
                results.append(MitreTechnique(
                    id=technique.id,
                    name=technique.name,
                    tactic=technique.tactic,
                    evidence=event.description[:120],
                ))
                seen_ids.add(technique.id)

    results.sort(
        key=lambda t: _TACTIC_ORDER.index(t.tactic) if t.tactic in _TACTIC_ORDER else 99
    )
    return results
