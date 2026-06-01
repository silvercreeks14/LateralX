"""
Attack graph builder.
Produces a Cytoscape.js-compatible dict from a list of ForensicEvents.
Lateral movement is flagged when a single user touches 3+ distinct hosts
within a 30-minute sliding window.
For PCAP events, network flows are rendered as IP-to-IP edges labelled
with protocol:port; high-port non-HTTP/S destinations are flagged C2-like.
When both PCAP/WAF events and host log events are present, a cross-source
scenario graph is produced linking:
  external IP → EventID 4688 (process creation) → EventID 4769 (Kerberoasting)
within a ±10-minute temporal correlation window.
"""

import re as _re
from collections import defaultdict
from datetime import timedelta
from backend.schema import ForensicEvent

LATERAL_WINDOW_MINUTES = 30
SCENARIO_WINDOW_MINUTES = 10
SUSPICIOUS_HOST_THRESHOLD = 3

# ── Semantic event classification ─────────────────────────────────────────────
# These patterns work across Windows Event Logs, Linux syslog, CloudTrail,
# Apache/Nginx, Zeek/Suricata, and generic security logs.  EventID-based
# classification always wins; these patterns apply only when event_id is absent.

_SEM_PROCESS = _re.compile(
    r'\b(?:execve?|execl|system|popen|spawn|fork|clone)\b'
    r'|new\s+process\s+(?:creat|start)|process\s+creat'
    r'|\b(?:cmd\.exe|powershell(?:\.exe)?|pwsh|wscript|cscript|mshta|regsvr32|rundll32)\b'
    r'|\b(?:certutil|bitsadmin|msiexec|wmic|cmstp|installutil|ieexec)\b'
    r'|/bin/(?:bash|sh|zsh|dash|ksh)\b|/usr/bin/python|/usr/bin/perl'
    r'|\bcommand\s+(?:execut|run|launch)|executed\s+(?:command|script|binary)'
    r'|\bprocess\s+start|started\s+process|\bexec(?:uted)?\b.*\.(exe|sh|py|pl|rb|bat|ps1)\b',
    _re.IGNORECASE,
)

_SEM_KERBEROS = _re.compile(
    r'\b(?:kerberos|kerberoast|krbtgt|golden\s+ticket|silver\s+ticket)\b'
    r'|\b(?:pass[- ]the[- ](?:ticket|hash|key)|pth\b|overpass[- ]the[- ]hash)\b'
    r'|\b(?:ticket\s+(?:grant|request)|service\s+ticket|tgt\b|as[- ]rep|kdc)\b'
    r'|\b(?:privilege\s+escal|escalat.*privilege|privesc|sudo\s+root|suid\s+root)\b'
    r'|\b(?:token\s+(?:impersonat|steal)|impersonat.*token|elevat.*token)\b'
    r'|\b(?:mimikatz|sekurlsa|lsadump|dcsync|ntds\.dit)\b',
    _re.IGNORECASE,
)

_SEM_LATERAL = _re.compile(
    r'\b(?:psexec|paexec|wmiexec|smbexec|atexec|dcomexec)\b'
    r'|\b(?:lateral\s+move|moving\s+lateral|pivot(?:ing)?)\b'
    r'|\b(?:network\s+logon|remote\s+(?:logon|login|shell|exec)|winrm|wsman)\b'
    r'|\b(?:ssh\s+(?:connect|open|accept|session)|scp\s+from|sftp\s+(?:put|get))\b'
    r'|\bnet\s+use\b|\bipc\$\b|\badmin\$\b|mapped\s+(?:drive|share)'
    r'|\b(?:rdp|remote\s+desktop|mstsc|xfreerdp|rdesktop)\b(?!.*setup)',
    _re.IGNORECASE,
)

_SEM_AUTH = _re.compile(
    r'\b(?:log(?:ged|on|in|out)|sign(?:ed)?\s+(?:in|on)|auth(?:entic)?(?:ated)?)\b'
    r'|\b(?:accepted\s+password|password\s+accepted|login\s+(?:success|ok|accept))\b'
    r'|\b(?:invalid\s+(?:password|user)|failed\s+(?:login|auth|logon))\b'
    r'|\bsu(?:do)?\s+(?:root|-l\s+root|to\s+root)|\bsu\s+[a-z]|\bsudo\b'
    r'|\b(?:session\s+open(?:ed)?|pam_unix.*session|pam_succeed)\b'
    r'|\b(?:logon\s+type|logon\s+success|logoff|log\s+off)\b',
    _re.IGNORECASE,
)

_SEM_IMPACT = _re.compile(
    r'\b(?:vssadmin|wbadmin|bcdedit|diskpart)\b.*(?:delete|remove|disable)'
    r'|\b(?:delete|remov).{0,30}(?:shadow|backup|vss|volume)'
    r'|\b(?:ransom|encryptfile|encrypt\s+file|\.locked|\.encrypted)\b'
    r'|\b(?:exfiltrat|data\s+theft|data\s+exfil|upload\s+to\s+http|sent\s+to\s+remote)\b'
    r'|\b(?:wipe|shred|scrub|destroy).{0,20}(?:disk|drive|file|data)'
    r'|\b(?:rm\s+-rf|del\s+/[fqs]|format\s+[c-z]:)\b',
    _re.IGNORECASE,
)

_SEM_EVASION = _re.compile(
    r'\b(?:wevtutil\s+cl|clearev|clear\s+event\s+log|del\s+.*\.evtx)\b'
    r'|\b(?:disable|stop|kill|bypass).{0,30}(?:firewall|defender|antivirus|av\b|edr|sysmon)\b'
    r'|\b(?:obfuscat|encode|base64).{0,40}(?:command|payload|script)'
    r'|\b(?:bypass|disable).{0,20}(?:amsi|etw|wdac|uac|applocker)\b'
    r'|\b(?:timestomp|anti.forensic|delete\s+log|log\s+tamper)\b',
    _re.IGNORECASE,
)


def _classify_event_semantic(e: ForensicEvent) -> str | None:
    """
    Classify a forensic event into an attack category using description text.

    Covers Windows Event Logs, Linux syslog, CloudTrail, Apache/Nginx, Zeek,
    and generic security logs.  Returns one of:
      'kerberos' | 'lateral_movement' | 'process_creation' |
      'authentication' | 'impact' | 'defense_evasion' | None

    Priority order matters: kerberos/lateral are checked first because their
    descriptions often also match the broader process/auth patterns.
    """
    text = f"{e.description or ''} {e.event_type or ''}"
    if _SEM_KERBEROS.search(text):
        return "kerberos"
    if _SEM_LATERAL.search(text):
        return "lateral_movement"
    if _SEM_IMPACT.search(text):
        return "impact"
    if _SEM_EVASION.search(text):
        return "defense_evasion"
    if _SEM_PROCESS.search(text):
        return "process_creation"
    if _SEM_AUTH.search(text):
        return "authentication"
    return None


def _step_description(stage: str, source: str, target: str) -> str:
    """Plain-English explanation of a scenario link for the story view."""
    if stage == "initial_access":
        return (
            f"External traffic from {source} was temporally correlated with suspicious "
            f"activity on {target}, indicating this as the likely intrusion vector."
        )
    if stage == "execution":
        return (
            f"Suspicious process or command execution on {source} was followed by "
            f"privileged activity on {target} within the correlation window."
        )
    if stage == "compromise":
        return (
            f"Account '{source}' made privileged requests against {target} — consistent "
            f"with credential theft, token impersonation, or account compromise."
        )
    if stage == "privilege_escalation":
        return (
            f"Following the compromise of {source}, authenticated network access was "
            f"detected on {target} — indicating lateral movement or privilege escalation."
        )
    return f"Suspicious activity link detected: {source} → {target}."

_IP_RE = _re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')

# Well-known benign public IPs — never treated as suspicious external nodes
_BENIGN_PUBLIC_IPS = frozenset({
    "8.8.8.8", "8.8.4.4",                      # Google Public DNS
    "1.1.1.1", "1.0.0.1",                       # Cloudflare DNS
    "9.9.9.9", "149.112.112.112",               # Quad9 DNS
    "208.67.222.222", "208.67.220.220",         # OpenDNS
    "4.2.2.1", "4.2.2.2",                       # Level3 DNS
    "13.107.4.52", "13.107.6.52",               # Microsoft 365
    "20.112.52.29", "20.189.173.0",             # Microsoft Azure
})

# RFC 1918 / loopback / link-local ranges — treated as internal, not external IPs
_RFC1918 = _re.compile(
    r'^(?:'
    r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'          # 10.0.0.0/8
    r'172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|'  # 172.16-31.x.x/12
    r'192\.168\.\d{1,3}\.\d{1,3}|'              # 192.168.0.0/16
    r'127\.\d{1,3}\.\d{1,3}\.\d{1,3}|'          # loopback
    r'169\.254\.\d{1,3}\.\d{1,3}'               # link-local
    r')$'
)


def _is_external_ip(s: str) -> bool:
    """True when s is a valid IPv4 address, outside RFC 1918/loopback, and not a known benign public IP."""
    return _is_ip_address(s) and not bool(_RFC1918.match(s)) and s not in _BENIGN_PUBLIC_IPS


# Accounts that touch many hosts by design — exclude from lateral movement detection
_SERVICE_ACCOUNT_TERMS = frozenset({
    "svc_", "_svc", "svc-", "-svc",
    "backup", "system", "svchost", "localsystem",
    "network service", "local service", "nt authority",
})


def _is_service_account(user: str) -> bool:
    u = user.lower().strip()
    if u.endswith("$"):
        return True
    return any(t in u for t in _SERVICE_ACCOUNT_TERMS)


def _is_ip_address(s: str) -> bool:
    """Return True if s looks like a bare IPv4 address."""
    return bool(_IP_RE.match(s or ""))


# Destination ports considered "standard" — not flagged as C2-like
_STANDARD_PORTS = frozenset([
    80, 443, 53, 25, 465, 587, 110, 143, 993, 995,
    21, 22, 23, 389, 636, 88, 445, 139, 3389, 5985, 5986,
])

# Protocols whose high-port traffic is inherently suspicious (C2 channels)
_SENSITIVE_PROTOCOLS = frozenset(["KERBEROS", "SMB", "SMB2"])

# Hostname substrings that indicate a server-class machine
_SERVER_KEYWORDS = frozenset([
    "server", "srv", "dc", "sql", "web", "mail", "file",
    "exchange", "backup", "domain", "print", "app", "db",
])


def _host_subtype(hostname: str) -> str:
    """Return 'server' if the hostname looks like a server, else 'workstation'."""
    h = hostname.lower()
    return "server" if any(kw in h for kw in _SERVER_KEYWORDS) else "workstation"


def _is_c2_like(protocol: str, dst_port: int | None) -> bool:
    """Heuristic: flag traffic that looks like a C2 beacon channel."""
    if protocol in _SENSITIVE_PROTOCOLS:
        return True
    if dst_port is not None and dst_port > 1024 and dst_port not in _STANDARD_PORTS:
        return True
    return False


def _build_network_graph(pcap_events: list[ForensicEvent]) -> dict:
    """
    Build a host-to-host network graph from PCAP flow events.
    source_host = src_ip, extra["dst_ip"] = dst_ip, event_type = protocol.
    """
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    edge_counts: dict[str, int] = defaultdict(int)
    edge_first_ts: dict[str, str] = {}
    suspicious_ips: set[str] = set()

    for e in pcap_events:
        src = e.source_host
        extra = e.extra or {}
        dst = extra.get("dst_ip", "")
        if not dst:
            continue

        try:
            dst_port: int | None = int(extra.get("dst_port", 0)) or None
        except (ValueError, TypeError):
            dst_port = None

        protocol = e.event_type.upper()
        label = f"{protocol}:{dst_port}" if dst_port else protocol
        suspicious = _is_c2_like(protocol, dst_port)

        for ip, node_type in ((src, "host"), (dst, "host")):
            if ip not in nodes:
                nodes[ip] = {
                    "data": {"id": ip, "label": ip, "type": node_type,
                             "subtype": "workstation", "suspicious": False},
                    "classes": "host workstation",
                }

        edge_key = f"{src}--[{label}]-->{dst}"
        edge_counts[edge_key] += 1
        if edge_key not in edge_first_ts:
            edge_first_ts[edge_key] = e.timestamp.isoformat()
            edges.append({
                "data": {
                    "id": edge_key,
                    "source": src,
                    "target": dst,
                    "timestamp": e.timestamp.isoformat(),
                    "label": label,
                    "suspicious": suspicious,
                    "count": 1,
                    "seq": 0,
                }
            })

        if suspicious:
            suspicious_ips.add(src)

    # Backfill counts + flag suspicious source nodes
    for edge in edges:
        edge["data"]["count"] = edge_counts[edge["data"]["id"]]

    for ip in suspicious_ips:
        if ip in nodes:
            nodes[ip]["data"]["suspicious"] = True
            nodes[ip]["classes"] = "host workstation suspicious"

    edges.sort(key=lambda e: e["data"]["timestamp"])
    for i, edge in enumerate(edges):
        edge["data"]["seq"] = i + 1

    return {
        "elements": {"nodes": list(nodes.values()), "edges": edges},
        "suspicious_users": list(suspicious_ips),
        "total_logon_events": 0,
        "unique_hosts": len(nodes),
        "network_connections": sum(edge_counts.values()),
    }


def _build_generic_graph(all_events: list[ForensicEvent]) -> dict:
    """
    Fallback graph for uploads with no logon events (e.g. process telemetry,
    generic CSV, endpoint logs). Every unique source_host becomes a host node;
    every unique user becomes a user node; each event produces a user→host edge
    (or a host self-edge when user is unknown).
    """
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    edge_counts: dict[str, int] = defaultdict(int)
    edge_first_ts: dict[str, str] = {}
    user_timeline: dict[str, list] = defaultdict(list)

    for e in all_events:
        host = e.source_host
        user = e.user or "unknown_user"

        if host not in nodes:
            subtype = _host_subtype(host)
            nodes[host] = {
                "data": {"id": host, "label": host, "type": "host",
                         "subtype": subtype, "suspicious": False},
                "classes": f"host {subtype}",
            }
        if user not in nodes:
            nodes[user] = {
                "data": {"id": user, "label": user, "type": "user", "suspicious": False},
                "classes": "user",
            }

        edge_key = f"{user}-->{host}"
        edge_counts[edge_key] += 1
        if edge_key not in edge_first_ts:
            edge_first_ts[edge_key] = e.timestamp.isoformat()
            edges.append({
                "data": {
                    "id": edge_key,
                    "source": user,
                    "target": host,
                    "timestamp": e.timestamp.isoformat(),
                    "event_id": e.event_id or "",
                    "suspicious": False,
                    "count": 1,
                }
            })
        user_timeline[user].append((e.timestamp, host))

    # Lateral movement detection — same sliding-window logic as logon graph.
    # Exclude service accounts and machine accounts (legitimately touch many hosts).
    suspicious_users: set[str] = set()
    for user, timeline in user_timeline.items():
        if user == "unknown_user" or _is_service_account(user):
            continue
        timeline.sort(key=lambda x: x[0])
        for i in range(len(timeline)):
            window_end = timeline[i][0] + timedelta(minutes=LATERAL_WINDOW_MINUTES)
            hosts_in_window = {h for ts, h in timeline if timeline[i][0] <= ts <= window_end}
            if len(hosts_in_window) >= SUSPICIOUS_HOST_THRESHOLD:
                suspicious_users.add(user)
                break

    for edge in edges:
        edge["data"]["count"] = edge_counts[edge["data"]["id"]]
        if edge["data"]["source"] in suspicious_users:
            edge["data"]["suspicious"] = True
    for user in suspicious_users:
        if user in nodes:
            nodes[user]["data"]["suspicious"] = True
            nodes[user]["classes"] = "user suspicious"

    edges.sort(key=lambda e: e["data"]["timestamp"])
    for i, edge in enumerate(edges):
        edge["data"]["seq"] = i + 1

    return {
        "elements": {"nodes": list(nodes.values()), "edges": edges},
        "suspicious_users": list(suspicious_users),
        "total_logon_events": len(all_events),
        "unique_hosts": len([n for n in nodes.values() if n["data"]["type"] == "host"]),
        "network_connections": 0,
        "graph_mode": "general",
    }


def _build_cross_source_scenario_graph(
    pcap_events: list[ForensicEvent],
    non_pcap_events: list[ForensicEvent],
) -> dict:
    """
    Causal Sequence attack graph linking WAF/PCAP traffic to host telemetry.

    Four attack tiers, each drawn as a scenario edge:
      TIER 1  External IP  ──initial_access──►  process-creation host (EventID 4688)
      TIER 2  Host (4688)  ──execution──►        Kerberoasting DC     (EventID 4769)
      TIER 3  User (4769)  ──compromise──►       target DC            (terminal impact)
      TIER 4  DC (4769)    ──privilege_escalation──► subsequent logon host

    Cross-tier links require the two events to fall within ±SCENARIO_WINDOW_MINUTES.
    WAF logs may store the real attacker IP in extra["client_ip"], which takes
    priority over source_host (which may be the WAF appliance itself).  Both the
    node-creation pass (TIER 1) and the cross-link pass use the same client_ip
    extraction so the edge always references the correct, pre-existing node — no
    orphaned / disconnected nodes.
    """
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    edge_seen: set[str] = set()
    scenario_window = timedelta(minutes=SCENARIO_WINDOW_MINUTES)

    def ensure_node(node_id: str, node_type: str, subtype: str = "") -> None:
        if node_id in nodes:
            return
        if node_type == "external_ip":
            nodes[node_id] = {
                "data": {"id": node_id, "label": node_id, "type": "external_ip",
                         "suspicious": True},
                "classes": "external_ip suspicious",
            }
        elif node_type == "user":
            nodes[node_id] = {
                "data": {"id": node_id, "label": node_id, "type": "user",
                         "suspicious": False},
                "classes": "user",
            }
        else:
            st = subtype or _host_subtype(node_id)
            nodes[node_id] = {
                "data": {"id": node_id, "label": node_id, "type": "host",
                         "subtype": st, "suspicious": False},
                "classes": f"host {st}",
            }

    def add_edge(src: str, dst: str, ts: str, event_id: str = "",
                 suspicious: bool = False, attack_stage: str = "") -> None:
        stage_suffix = f"[{attack_stage}]" if attack_stage else ""
        eid = f"{src}--{stage_suffix}-->{dst}"
        if eid in edge_seen:
            return
        edge_seen.add(eid)
        edata: dict = {
            "id": eid,
            "source": src,
            "target": dst,
            "timestamp": ts,
            "event_id": event_id,
            "suspicious": suspicious,
            "count": 1,
            "seq": 0,
        }
        if attack_stage:
            edata["attack_stage"] = attack_stage
            edata["scenario_link"] = True
        edges.append({"data": edata})

    def _waf_src(e: ForensicEvent) -> str:
        """Extract the real attacker IP: prefer extra['client_ip'], fall back to source_host."""
        return (e.extra or {}).get("client_ip") or e.source_host or ""

    # ── TIER 1: WAF / PCAP — External IP nodes and baseline network edges ────
    # WAF CSV logs store the real attacker IP in extra["client_ip"].
    # Always prefer that over source_host (which may be the WAF device hostname).
    # Only non-RFC1918 IPs are classified as external_ip (orange hexagon);
    # internal IPs become plain host nodes so they don't pollute the scenario chain.
    #
    # Correlated sessions (enriched by network_host_correlator before graph build):
    # extra["correlated_host"] / ["correlated_user"] replace the firewall's UNKNOWN-HOST
    # attribution, merging the perimeter session onto the actual host/user nodes so the
    # attack path is one continuous chain instead of two disconnected subgraphs.
    for e in pcap_events:
        extra = e.extra or {}
        src = _waf_src(e)
        dst = extra.get("dst_ip", "")
        if not src:
            continue

        corr_host = extra.get("correlated_host")
        corr_user = extra.get("correlated_user")
        is_exfil  = extra.get("t1048_exfil", False)

        try:
            dst_port: int | None = int(extra.get("dst_port", 0)) or None
        except (ValueError, TypeError):
            dst_port = None
        protocol = e.event_type.upper()

        if corr_host:
            # Merge: use the resolved host (and optional user) instead of the raw
            # firewall src_ip so the PCAP session attaches to the correct host node.
            ensure_node(corr_host, "host")
            if corr_user:
                ensure_node(corr_user, "user")
                add_edge(corr_user, corr_host, e.timestamp.isoformat(),
                         event_id=e.event_id or "", suspicious=is_exfil)
            if dst:
                dst_type = "external_ip" if _is_external_ip(dst) else "host"
                ensure_node(dst, dst_type)
                add_edge(corr_host, dst, e.timestamp.isoformat(),
                         event_id=e.event_id or "", suspicious=True,
                         attack_stage="compromise" if is_exfil else "")
            continue   # skip default src→dst edge for this session

        # Default: no host correlation — draw raw firewall src → dst edge
        src_type = "external_ip" if _is_external_ip(src) else "host"
        ensure_node(src, src_type)
        if dst:
            dst_type = "external_ip" if _is_external_ip(dst) else "host"
            ensure_node(dst, dst_type)
            suspicious = _is_c2_like(protocol, dst_port)
            add_edge(src, dst, e.timestamp.isoformat(),
                     event_id=e.event_id or "", suspicious=suspicious)

    # ── TIER 2: Host events — build nodes, intra-host edges, categorise ──────
    process_events: list[ForensicEvent] = []   # EventID 4688 (process creation)
    kerberos_events: list[ForensicEvent] = []  # EventID 4769 (Kerberoasting)
    logon_events: list[ForensicEvent] = []
    user_timeline: dict[str, list] = defaultdict(list)

    for e in non_pcap_events:
        host = e.source_host or "unknown_host"
        user = e.user
        ensure_node(host, "host")
        if user:
            ensure_node(user, "user")
            add_edge(user, host, e.timestamp.isoformat(), event_id=e.event_id or "")
            user_timeline[user].append((e.timestamp, host))

        _sem = None  # computed lazily — only when event_id is absent
        if e.event_id == "4688":
            process_events.append(e)
        elif e.event_id == "4769":
            kerberos_events.append(e)
        elif (e.event_id in ("4624", "4648", "4768")
              or "logon" in e.event_type.lower()
              or "logon" in e.description.lower()):
            logon_events.append(e)
        elif not e.event_id:
            # No EventID — fall back to semantic classification
            _sem = _classify_event_semantic(e)
            if _sem == "process_creation":
                process_events.append(e)
            elif _sem == "kerberos":
                kerberos_events.append(e)
            elif _sem in ("authentication", "lateral_movement"):
                logon_events.append(e)

    # ── TIER 1 → 2 Cross-link: External IP → 4688 host (Initial Exploitation) ─
    # CRITICAL: use _waf_src() here (same as TIER 1) so the edge source references
    # the real attacker IP node that was created above — not the WAF device hostname,
    # which would produce a disconnected phantom IP node in the graph.
    #
    # Primary:  temporal correlation within ±SCENARIO_WINDOW_MINUTES.
    # Fallback: WAF log rows carry extra["client_ip"] (plain PCAP events do not).
    #   When WAF and host logs are captured at different times (e.g. WAF at 15:51,
    #   workstation triage at 12:15), no temporal match is found and the graph
    #   becomes disconnected.  For these genuine multi-source uploads we fall back
    #   to connecting the WAF attacker IP to the first process-creation host
    #   regardless of timestamp — preserving a single continuous attack chain.
    #   Existing PCAP-based tests (which never set client_ip) are unaffected.
    waf_linked: set[str] = set()   # attacker IPs that already have an initial_access edge

    for pcap_e in pcap_events:
        src_ip = _waf_src(pcap_e)
        if not src_ip or not _is_external_ip(src_ip):
            continue   # only external (non-RFC1918) IPs trigger initial_access
        src_type = "external_ip"
        ensure_node(src_ip, src_type)
        for proc in process_events:
            if abs(proc.timestamp - pcap_e.timestamp) <= scenario_window:
                proc_host = proc.source_host or "unknown_host"
                ensure_node(proc_host, "host")
                add_edge(
                    src_ip, proc_host,
                    pcap_e.timestamp.isoformat(),
                    event_id="4688",
                    suspicious=True,
                    attack_stage="initial_access",
                )
                nodes[src_ip]["data"]["suspicious"] = True
                nodes[src_ip]["classes"] = f"{src_type} suspicious"
                waf_linked.add(src_ip)

    # WAF fallback: connect unlinked external attacker IPs to the first available
    # process host when timestamps differ (e.g. WAF and host logs captured at different times).
    if process_events:
        first_proc_host = process_events[0].source_host or "unknown_host"
        ensure_node(first_proc_host, "host")
        for pcap_e in pcap_events:
            if not (pcap_e.extra or {}).get("client_ip"):
                continue   # only WAF log rows carry client_ip; skip plain PCAP
            src_ip = _waf_src(pcap_e)
            if not src_ip or not _is_external_ip(src_ip) or src_ip in waf_linked:
                continue
            src_type = "external_ip"
            ensure_node(src_ip, src_type)
            add_edge(
                src_ip, first_proc_host,
                pcap_e.timestamp.isoformat(),
                event_id="4688",
                suspicious=True,
                attack_stage="initial_access",
            )
            nodes[src_ip]["data"]["suspicious"] = True
            nodes[src_ip]["classes"] = f"{src_type} suspicious"
            waf_linked.add(src_ip)

    # ── TIER 2 → 3 Cross-link: 4688 host → 4769 DC (Pivot / Priv Esc) ───────
    for proc in process_events:
        proc_host = proc.source_host or "unknown_host"
        for kerb in kerberos_events:
            if abs(kerb.timestamp - proc.timestamp) <= scenario_window:
                kerb_host = kerb.source_host or "unknown_host"
                ensure_node(kerb_host, "host")
                add_edge(
                    proc_host, kerb_host,
                    proc.timestamp.isoformat(),
                    event_id="4769",
                    suspicious=True,
                    attack_stage="execution",
                )
                nodes[proc_host]["data"]["suspicious"] = True
                st = _host_subtype(proc_host)
                nodes[proc_host]["classes"] = f"host {st} suspicious"

    # ── TIER 3: Compromise — Kerberoasting user → target DC ──────────────────
    # Mark the Kerberoasting host (DC-01) as the terminal impact node with the
    # exact classes required by the frontend crimson node style.
    # Draw a "compromise" edge from the compromised service account to the DC.
    # Kerberos (4769) events may log the requesting account in extra["TargetUserName"]
    # rather than the top-level user field depending on the parser/log source; fall
    # back to those extra fields so the edge is always drawn when the data is present.
    _KERB_USER_FIELDS = ("TargetUserName", "SubjectUserName", "AccountName", "account_name")

    for kerb in kerberos_events:
        kerb_host = kerb.source_host or "unknown_host"
        ensure_node(kerb_host, "host")
        nodes[kerb_host]["data"]["suspicious"] = True
        nodes[kerb_host]["data"]["target"] = True
        st = _host_subtype(kerb_host)
        nodes[kerb_host]["classes"] = f"host {st} suspicious target"

        # Resolve the compromising user — top-level field first, then extra dict.
        kerb_user = kerb.user
        if not kerb_user and kerb.extra:
            for field in _KERB_USER_FIELDS:
                v = (kerb.extra.get(field) or "").strip()
                if v and not v.endswith("$"):  # skip machine accounts
                    kerb_user = v
                    break

        if kerb_user:
            ensure_node(kerb_user, "user")
            add_edge(
                kerb_user, kerb_host,
                kerb.timestamp.isoformat(),
                event_id="4769",
                suspicious=True,
                attack_stage="compromise",
            )

    # ── TIER 4: Post-compromise — 4769 DC → subsequent logon host (Priv Esc) ─
    for kerb in kerberos_events:
        kerb_host = kerb.source_host or "unknown_host"
        ensure_node(kerb_host, "host")
        nodes[kerb_host]["data"]["suspicious"] = True
        nodes[kerb_host]["data"]["target"] = True
        st = _host_subtype(kerb_host)
        nodes[kerb_host]["classes"] = f"host {st} suspicious target"
        for logon_e in logon_events:
            delta = logon_e.timestamp - kerb.timestamp
            if timedelta(0) < delta <= scenario_window:
                logon_host = logon_e.source_host or "unknown_host"
                if logon_host == kerb_host:
                    continue
                ensure_node(logon_host, "host")
                add_edge(
                    kerb_host, logon_host,
                    kerb.timestamp.isoformat(),
                    event_id="4769",
                    suspicious=True,
                    attack_stage="privilege_escalation",
                )

    # ── Lateral movement detection (host log users) ───────────────────────────
    suspicious_users: set[str] = set()
    for user, timeline in user_timeline.items():
        if _is_service_account(user):
            continue
        timeline.sort(key=lambda x: x[0])
        for i in range(len(timeline)):
            window_end = timeline[i][0] + timedelta(minutes=LATERAL_WINDOW_MINUTES)
            hosts_in_window = {
                h for ts, h in timeline if timeline[i][0] <= ts <= window_end
            }
            if len(hosts_in_window) >= SUSPICIOUS_HOST_THRESHOLD:
                suspicious_users.add(user)
                break

    for edge in edges:
        if edge["data"].get("source") in suspicious_users and not edge["data"].get("scenario_link"):
            edge["data"]["suspicious"] = True
    for user in suspicious_users:
        if user in nodes:
            nodes[user]["data"]["suspicious"] = True
            nodes[user]["classes"] = "user suspicious"

    # ── Chronological sequence numbering ──────────────────────────────────────
    edges.sort(key=lambda e: e["data"]["timestamp"])
    for i, edge in enumerate(edges):
        edge["data"]["seq"] = i + 1

    scenario_count = sum(1 for e in edges if e["data"].get("scenario_link"))
    all_suspicious = list(suspicious_users) + [
        nid for nid, n in nodes.items()
        if n["data"]["suspicious"] and nid not in suspicious_users
    ]

    # ── Scenario story: human-readable attack chain for the Story View ─────────
    _STAGE_ORDER = {
        "initial_access": 0,
        "execution": 1,
        "compromise": 2,
        "privilege_escalation": 3,
    }
    scenario_story = [
        {
            "step": 0,  # renumbered below after sorting
            "attack_stage": e["data"]["attack_stage"],
            "source": e["data"]["source"],
            "target": e["data"]["target"],
            "timestamp": e["data"]["timestamp"],
            "event_id": e["data"].get("event_id", ""),
            "description": _step_description(
                e["data"]["attack_stage"],
                e["data"]["source"],
                e["data"]["target"],
            ),
        }
        for e in edges
        if e["data"].get("scenario_link") and e["data"].get("attack_stage")
    ]
    scenario_story.sort(key=lambda s: (
        s["timestamp"],
        _STAGE_ORDER.get(s["attack_stage"], 9),
    ))
    for i, step in enumerate(scenario_story):
        step["step"] = i + 1

    return {
        "elements": {"nodes": list(nodes.values()), "edges": edges},
        "suspicious_users": all_suspicious,
        "total_logon_events": len(logon_events),
        "unique_hosts": sum(1 for n in nodes.values() if n["data"]["type"] == "host"),
        "network_connections": sum(1 for e in edges if not e["data"].get("scenario_link")),
        "graph_mode": "scenario",
        "scenario_links": scenario_count,
        "scenario_story": scenario_story,
    }


def build_attack_graph(events: list[ForensicEvent]) -> dict:
    """
    Build a Cytoscape.js-compatible graph from forensic events.

    Priority order:
      1. PCAP + host logs     → cross-source multi-stage scenario graph
      2. PCAP-only upload     → IP-to-IP network graph
      3. Has logon event IDs  → lateral-movement logon graph
      4. Any other log events → general activity graph (all events)
    """
    pcap_events = [e for e in events if e.raw_source == "pcap"]
    logon_events_all = [e for e in events if e.raw_source != "pcap"]

    # Cross-source scenario graph: PCAP traffic + host log events present together
    if pcap_events and logon_events_all:
        return _build_cross_source_scenario_graph(pcap_events, logon_events_all)

    # PCAP-only → network flow graph
    if pcap_events and not logon_events_all:
        return _build_network_graph(pcap_events)

    # Host-log-only paths below ───────────────────────────────────────────────

    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    edge_seen: set[str] = set()
    user_timeline: dict[str, list] = defaultdict(list)

    # Select logon events by Event ID or keyword matching
    logon_events = [
        e for e in logon_events_all
        if (e.event_id in ("4624", "4648", "4768", "4769"))
        or "logon" in e.event_type.lower()
        or "login" in e.description.lower()
        or "logged on" in e.description.lower()
    ]

    # No logon events → fall back to showing the full event set as a host graph
    if not logon_events and logon_events_all:
        return _build_generic_graph(logon_events_all)

    edge_counts: dict[str, int] = defaultdict(int)

    for e in logon_events:
        host = e.source_host
        user = e.user or "unknown_user"

        if host not in nodes:
            subtype = _host_subtype(host)
            nodes[host] = {
                "data": {"id": host, "label": host, "type": "host",
                         "subtype": subtype, "suspicious": False},
                "classes": f"host {subtype}",
            }

        if user not in nodes:
            nodes[user] = {
                "data": {"id": user, "label": user, "type": "user", "suspicious": False},
                "classes": "user",
            }

        edge_key = f"{user}-->{host}"
        edge_counts[edge_key] += 1
        if edge_key not in edge_seen:
            edge_seen.add(edge_key)
            edges.append(
                {
                    "data": {
                        "id": edge_key,
                        "source": user,
                        "target": host,
                        "timestamp": e.timestamp.isoformat(),
                        "event_id": e.event_id or "",
                        "suspicious": False,
                        "count": 1,
                    }
                }
            )

        user_timeline[user].append((e.timestamp, host))

    # ------------------------------------------------------------------ #
    # Lateral movement detection: sliding window over each user's events  #
    # Service accounts (svc_, machine accounts, SYSTEM) are excluded.    #
    # ------------------------------------------------------------------ #
    suspicious_users: set[str] = set()
    for user, timeline in user_timeline.items():
        if _is_service_account(user):
            continue
        timeline.sort(key=lambda x: x[0])
        for i in range(len(timeline)):
            window_end = timeline[i][0] + timedelta(minutes=LATERAL_WINDOW_MINUTES)
            hosts_in_window = {
                h for ts, h in timeline if timeline[i][0] <= ts <= window_end
            }
            if len(hosts_in_window) >= SUSPICIOUS_HOST_THRESHOLD:
                suspicious_users.add(user)
                break

    for edge in edges:
        edge["data"]["count"] = edge_counts[edge["data"]["id"]]
        if edge["data"]["source"] in suspicious_users:
            edge["data"]["suspicious"] = True

    for user in suspicious_users:
        if user in nodes:
            nodes[user]["data"]["suspicious"] = True
            nodes[user]["classes"] = "user suspicious"

    edges.sort(key=lambda e: e["data"]["timestamp"])
    for i, edge in enumerate(edges):
        edge["data"]["seq"] = i + 1

    return {
        "elements": {
            "nodes": list(nodes.values()),
            "edges": edges,
        },
        "suspicious_users": list(suspicious_users),
        "total_logon_events": len(logon_events),
        "unique_hosts": len([n for n in nodes.values() if n["data"]["type"] == "host"]),
        "network_connections": 0,
        "graph_mode": "logon",
    }
