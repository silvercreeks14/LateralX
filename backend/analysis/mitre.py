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

# OS processes that access lsass legitimately (WER, WMI, Group Policy, antivirus host).
# Exclude them from EID-10 T1003 detection regardless of GrantedAccess value.
_T1003_SAFE_SOURCES = frozenset({
    "svchost.exe",
    "werfault.exe",
    "wmiprvse.exe",
    "msiexec.exe",
    "services.exe",
    "wininit.exe",   # parent of lsass; has legitimate handle for process tracking
    "csrss.exe",
    "smss.exe",
    "lsm.exe",       # Local Session Manager
})

# OS images that legitimately write registry keys — used by T1082/T1484.001/T1547.001 guards
# to suppress EID-12/13 events from known-good system processes.
_SAFE_REG_WRITERS = frozenset({
    "system",        # kernel (no path)
    "svchost.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "csrss.exe",
    "wininit.exe",
    "smss.exe",
    "spoolsv.exe",
    "taskhostw.exe",
    "explorer.exe",
    "logonui.exe",   # Windows logon UI — writes CurrentVersion\Winlogon for lock screen
    "userinit.exe",
    "dwm.exe",
})


def _img_basename(extra: dict | None) -> str:
    img = (extra or {}).get("Image", "").lower()
    return img.rsplit("\\", 1)[-1] if "\\" in img else img


def _guard_t1003(event, combined: str) -> bool:
    eid = event.event_id
    # EID 5156/5158: WFP firewall allow/drop — lsass appears as process name, not target
    # EID 3: network connection FROM lsass — not a credential access event
    # EID 12/13: registry key create/set BY lsass (W32Time, system services) — not an attack
    if eid in ("5156", "5158", "3", "12", "13"):
        return False
    # EID 10 (ProcessAccess): only signal when lsass is the TARGET with a non-benign
    # GrantedAccess mask AND the caller is not a trusted OS process.
    if eid == "10":
        target = (event.extra or {}).get("TargetImage", "").lower()
        if "lsass" not in target:
            return False
        ga = (event.extra or {}).get("GrantedAccess", "").lower()
        if ga in _T1003_BENIGN_GA:
            return False
        src = (event.extra or {}).get("SourceImage", "").lower()
        src_base = src.rsplit("\\", 1)[-1] if "\\" in src else src
        if src_base in _T1003_SAFE_SOURCES:
            return False
    return True


def _guard_t1082(event, combined: str) -> bool:
    # EID 12/13: registry key events can contain discovery tool names in their value data
    # (e.g., scheduled task XML storing "systeminfo") — T1082 requires process execution,
    # not a registry write. Suppress all registry events for this technique.
    return event.event_id not in ("12", "13")


def _guard_t1484001(event, combined: str) -> bool:
    # EID 12/13: svchost.exe and other OS processes write GPO registry keys during
    # legitimate Group Policy processing — exclude known safe system processes.
    if event.event_id in ("12", "13"):
        if _img_basename(event.extra) in _SAFE_REG_WRITERS:
            return False
    return True


def _guard_t1547001(event, combined: str) -> bool:
    # EID 12/13: winlogon.exe writes currentversion\winlogon during profile loads;
    # svchost.exe writes run-key paths during service registration — both are benign.
    if event.event_id in ("12", "13"):
        if _img_basename(event.extra) in _SAFE_REG_WRITERS:
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
    "T1082":     _guard_t1082,
    "T1484.001": _guard_t1484001,
    "T1547.001": _guard_t1547001,
}

# (trigger_keywords, technique) — first match per technique ID wins
_MAP: list[tuple[list[str], MitreTechnique]] = [
    # Ingress tool transfer — expanded to cover Cobalt Strike, Sliver, and Havoc download paths.
    # start-bitstransfer: Cobalt Strike BITS staging; invoke-webrequest / wget.exe / curl.exe:
    # used by virtually every C2 framework as an alternative to certutil.
    (["certutil", "urlcache", "bitsadmin /transfer",
      "start-bitstransfer", "invoke-webrequest -uri", "wget.exe", "curl.exe -o",
      "downloadfile(", "downloaddata("],
     MitreTechnique(id="T1105", name="Ingress Tool Transfer", tactic="Command and Control")),

    (["vssadmin delete", "wmic shadowcopy delete", "shadowcopy delete"],
     MitreTechnique(id="T1490", name="Inhibit System Recovery", tactic="Impact")),

    (["mshta"],
     MitreTechnique(id="T1218.005", name="Mshta", tactic="Defense Evasion")),

    # WMI execution — expanded to cover PowerShell-based WMI invocation (Invoke-WMIMethod,
    # Register-WMIEvent) used by Cobalt Strike and PowerLurk for agentless lateral execution
    # and event-subscription persistence respectively.
    (["wmic", "win32_process create", "invoke-wmimethod", "register-wmievent",
      "commandlinetemplate", "activescriptconsumer"],
     MitreTechnique(id="T1047", name="Windows Management Instrumentation", tactic="Execution")),

    (["-encodedcommand", "-enc ", "powershell.exe -enc"],
     MitreTechnique(id="T1059.001", name="PowerShell (Encoded)", tactic="Execution")),

    # Download-cradle variants used by non-Empire C2 frameworks (Cobalt Strike, Sliver, Havoc).
    # These appear in EID 4104 ScriptBlock logs where the word "powershell" may not be present.
    (["invoke-expression", "iex (", ".downloadstring(", ".downloadfile(",
      "net.webclient", "invoke-restmethod", "invoke-webrequest",
      "system.net.webclient", "new-object net."],
     MitreTechnique(id="T1059.001", name="PowerShell (Download Cradle)", tactic="Execution")),

    (["powershell"],
     MitreTechnique(id="T1059.001", name="PowerShell", tactic="Execution")),

    (["cmd.exe", "cmd /c", "cmd.exe /c"],
     MitreTechnique(id="T1059.003", name="Windows Command Shell", tactic="Execution")),

    (["regsvr32"],
     MitreTechnique(id="T1218.010", name="Regsvr32", tactic="Defense Evasion")),

    # SMB/Admin Shares — extended with Impacket tool names used by non-Empire frameworks.
    # smbexec / wmiexec / dcomexec are Impacket suites used by Cobalt Strike, CrackMapExec,
    # Sliver, and custom ransomware operators as psexec alternatives.
    (["net use ", "net use\\", "psexec", "\\admin$", "\\c$", "\\ipc$", "\\d$",
      "logon type: 3", "logon type: 9",    # Type 9 = NewCredentials (over-pass-the-hash)
      "smbexec", "wmiexec", "dcomexec", "atexec"],
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

    (["pass-the-ticket", "rubeus ptt", "kerberos::ptt", "use ticket",
      "rubeus.exe", "rubeus asktgt", "/ptt"],  # Rubeus process + PTT injection flag
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

    # EID 4698 "A scheduled task was created" fires on any task-creation event, including
    # attacker persistence without schtasks.exe in the command line.
    (["schtasks", "at.exe", "scheduled task was created", "task name:"],
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

    # Process Injection (T1055) — Win32/NT API calls appearing in Sysmon EID 1/10 CommandLine or
    # ScriptBlock text. Cobalt Strike uses VirtualAllocEx+WriteProcessMemory+CreateRemoteThread;
    # Sliver uses similar Go-native syscall wrappers; Havoc uses NtCreateThread variants.
    # APC injection (QueueUserAPC) is used by CS sleep obfuscation and process-injection modules.
    (["virtualallocex", "writeprocessmemory", "createremotethread",
      "ntcreatethread", "ntallocatevirtualmemory", "queueuserapc",
      "process hollowing", "reflective dll", "shellcode injection",
      "ntunmapviewofsection"],
     MitreTechnique(id="T1055", name="Process Injection", tactic="Defense Evasion")),

    # System Network Configuration Discovery (T1016) — recon commands common to all C2 frameworks
    # during the post-exploitation discovery phase (Empire, Cobalt Strike, Sliver, Havoc alike).
    (["ipconfig /all", "netstat -ano", "arp -a", "route print",
      "get-netadapter", "get-netipaddress", "nbtstat -a"],
     MitreTechnique(id="T1016", name="System Network Configuration Discovery", tactic="Discovery")),

    # System Network Connections Discovery (T1049) — listing active connections.
    # Distinct from T1016; these reveal active C2 channels and lateral movement targets.
    (["netstat -an", "get-nettcpconnection", "get-netudpendpoint",
      "ss -tlnp", "netstat -b"],
     MitreTechnique(id="T1049", name="System Network Connections Discovery", tactic="Discovery")),

    # Rundll32 proxy execution (T1218.011) — used by Cobalt Strike, Havoc, and custom loaders
    # to execute shellcode or DLL payloads via signed Windows binary.
    (["rundll32.exe javascript", "rundll32 javascript",
      "rundll32.exe http", "rundll32 comsvcs",
      "rundll32.exe shell32", "rundll32.exe url.dll"],
     MitreTechnique(id="T1218.011", name="Rundll32", tactic="Defense Evasion")),
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
