"""
MITRE ATT&CK technique mapper.
Pure Python — no LLM call needed. Maps keyword patterns in event
descriptions to standardised ATT&CK technique IDs.
"""

import re as _re
from backend.schema import ForensicEvent, MitreTechnique

# Matches 50+ contiguous base64 chars — signals an encoded payload blob.
_B64_RE = _re.compile(r'[A-Za-z0-9+/]{50,}={0,2}')


# ── Per-technique event guards ─────────────────────────────────────────────────
# Each guard(event, combined) returns False to suppress the match.

# Benign GrantedAccess masks for lsass EID-10 events — mirrors behavioral.py _BENIGN_MASKS.
# Defined locally to avoid circular import.
_T1003_BENIGN_GA = frozenset({
    "0x1000",   # PROCESS_QUERY_LIMITED_INFORMATION
    "0x400",    # PROCESS_QUERY_INFORMATION
    "0x800",    # PROCESS_SUSPEND_RESUME
    "0x100000", # SYNCHRONIZE
    "0x3000",   # PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_LIMITED_INFORMATION
})


def _guard_t1003(event, combined: str) -> bool:
    eid = event.event_id
    # EID 5156/5158: WFP firewall allow/drop — lsass appears as process name, not target
    # EID 3: network connection FROM lsass — not a credential access event
    # EID 12/13: registry key create/set BY lsass (W32Time, system services) — not an attack
    if eid in ("5156", "5158", "3", "12", "13"):
        return False
    # EID 10 (ProcessAccess): only signal when lsass is the TARGET with a non-benign
    # GrantedAccess mask. Benign system processes (svchost) use read-only masks; attackers
    # (PowerShell via Mimikatz/Empire PTH) use 0x1010 / 0x1038.
    if eid == "10":
        target = (event.extra or {}).get("TargetImage", "").lower()
        if "lsass" not in target:
            return False
        ga = (event.extra or {}).get("GrantedAccess", "").lower()
        if ga in _T1003_BENIGN_GA:
            return False
    return True


def _guard_t1021002(event, combined: str) -> bool:
    # LogonType 9 (NewCredentials / over-pass-the-hash / runas /netonly) is always
    # a lateral-movement signal — bypass all suppression filters unconditionally.
    if "logon type: 9" in combined:
        return True
    # Loopback and link-local source IPs identify DC replication Type-3 logons, not
    # lateral movement. No auth-package check needed — the IP alone is sufficient;
    # EID 4624 messages do not contain the word "kerberos" in plain text.
    if any(ip in combined for ip in ("::1", "127.0.0.1", "fe80::")):
        return False
    # Machine account users (name ends in $): system operations, not human lateral move.
    # Check event.user first; fall back to description text because some adapters set
    # event.user from SubjectUserName ("-" → None) and never reach TargetUserName.
    if (event.user or "").endswith("$"):
        return False
    if _re.search(r'account:\s*\w+\$', combined):
        return False
    return True


def _guard_t1047(event, combined: str) -> bool:
    # EID 7 is an image/DLL load event. wmiprvse.exe loading a DLL is not WMI execution;
    # it fires because "wmic" is a substring of "wmiprvse".
    return event.event_id != "7"


def _guard_t1027(event, combined: str) -> bool:
    # CMS (Cryptographic Message Syntax) blocks match _B64_RE but are legitimate
    # Protect-CmsMessage / Unprotect-CmsMessage cmdlet output — not obfuscation.
    if any(cms in combined for cms in
           ("begin cms", "unprotect-cmsmessage", "protect-cmsmessage")):
        return False
    return True


_GUARDS: dict[str, object] = {
    "T1003.001": _guard_t1003,
    "T1021.002": _guard_t1021002,
    "T1047":     _guard_t1047,
    "T1027":     _guard_t1027,
}

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

    (["net use", "psexec", "\\admin$", "\\c$", "\\ipc$", "\\d$", "logon type: 3"],
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
    (["systeminfo", "get-computerinfo", "whoami /all", "whoami /priv",
      "whoami /groups", "hostname.exe"],
     MitreTechnique(id="T1082", name="System Information Discovery", tactic="Discovery")),

    (["schtasks", "at.exe"],
     MitreTechnique(id="T1053.005", name="Scheduled Task", tactic="Persistence")),

    # Change C: "run\\" was matching ClickToRun\OfficeClickToRun paths. Use specific
    # persistence registry key substrings that won't match legitimate software paths.
    # Micro-fix 2: "\\winlogon" narrowed to "currentversion\\winlogon" — the plain
    # "\winlogon" matched EID 4656/4663 object-handle events for winlogon.exe (process
    # path), not the registry persistence key under CurrentVersion.
    (["reg add", "currentversion\\run\\", "currentversion\\runonce\\",
      "currentversion\\winlogon", "userinitmprlogonscript", "\\startup"],
     MitreTechnique(id="T1547.001", name="Registry Run Keys", tactic="Persistence")),

    # Change B: "lsass.exe" removed — too broad (fires on EID 5156/3/12/13 where
    # lsass is the process name, not the target). Lsass-as-target detection is now
    # handled by the compound rule in _COMPOUND_MAP below.
    (["mimikatz", "procdump", "comsvcs.dll", "ntds.dit", "secretsdump"],
     MitreTechnique(id="T1003.001", name="LSASS Memory Dumping", tactic="Credential Access")),

    (["net localgroup administrators", "net user /add"],
     MitreTechnique(id="T1136.001", name="Local Account Creation", tactic="Persistence")),

    (["sc create", "sc config"],
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

# Compound rules: (context_keywords, trigger_keywords, technique, extra_regex|None)
# A rule fires when ANY context keyword AND (ANY trigger keyword OR extra_regex) are present.
# Context requirement prevents firing on generic events that lack ScriptBlock logging.
_COMPOUND_MAP: list[tuple[list[str], list[str], MitreTechnique, "_re.Pattern[str] | None"]] = [
    (
        # Change D: EID 10 ProcessAccess where lsass is the TargetImage and a
        # GrantedAccess value is logged — the canonical Sysmon credential-dump signal.
        # Replaces the removed "lsass.exe" keyword in _MAP.
        ["targetimage: c:\\windows\\system32\\lsass"],
        ["grantedaccess:"],
        MitreTechnique(id="T1003.001", name="LSASS Memory Dumping",
                       tactic="Credential Access",
                       evidence="lsass.exe TargetImage + GrantedAccess (EID 10)"),
        None,
    ),
    (
        # EID 4103/4104 adapter format: "PowerShell script. Path: … Script: {payload}"
        ["powershell script. path:", ". script:"],
        [
            # AMSI bypass via reflection
            "amsiutils", "amsiinitfailed", "amsiscanbuffer", "amsicontext",
            # Reflection-based assembly loading
            "[system.reflection.assembly]::load", "[reflection.assembly]::load",
            # Decode-then-execute patterns
            "frombase64string",
            # String-array obfuscation
            "-join [char]",
        ],
        MitreTechnique(id="T1027", name="Obfuscated Files or Information",
                       tactic="Defense Evasion"),
        _B64_RE,  # also fires on 50+ char base64 blobs within a ScriptBlock event
    ),
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
                guard = _GUARDS.get(technique.id)
                if guard and not guard(event, combined):
                    continue
                results.append(MitreTechnique(
                    id=technique.id,
                    name=technique.name,
                    tactic=technique.tactic,
                    evidence=event.description[:120],
                ))
                seen_ids.add(technique.id)

        for ctx_kws, trig_kws, technique, extra_re in _COMPOUND_MAP:
            if technique.id in seen_ids:
                continue
            if not any(ck in combined for ck in ctx_kws):
                continue
            if (any(tk in combined for tk in trig_kws)
                    or (extra_re is not None and extra_re.search(event.description))):
                guard = _GUARDS.get(technique.id)
                if guard and not guard(event, combined):
                    continue
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
