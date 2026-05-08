"""
AD-Specialized Lateral Movement Detection (LMD) model.

Detects six AD attack classes using a Random Forest classifier trained on
synthetic feature vectors derived from ForensicEvent fields.  No LabelEncoder
is used — all features are numeric/binary so the model is portable across
deployments without re-encoding drift.

Attack classes
──────────────
  0  Normal
  1  Kerberoasting / AS-REP Roasting
  2  DCSync / Credential Theft
  3  Golden Ticket / Silver Ticket / Pass-the-Ticket
  4  Lateral Movement (SMB / WMI / RDP / PsExec)
  5  Reconnaissance (BloodHound / LDAP enum / domain discovery)

Model file: rf_model.pkl (auto-regenerated when absent or feature-mismatched)
"""

import re
import logging
import numpy as np
from pathlib import Path
from typing import TypedDict

import joblib
from pyvis.network import Network
from sklearn.ensemble import RandomForestClassifier

from backend.schema import ForensicEvent

log = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH   = PROJECT_ROOT / "rf_model.pkl"

# ── Attack class registry ──────────────────────────────────────────────────────

_ATTACK_CLASSES: dict[int, dict] = {
    0: {"name": "Normal",              "label": "Normal Traffic",         "color": "#64748b", "severity": "none"},
    1: {"name": "kerberoasting",       "label": "Kerberoasting/AS-REP",   "color": "#8b5cf6", "severity": "high"},
    2: {"name": "dcsync",              "label": "DCSync/Credential Theft","color": "#ef4444", "severity": "critical"},
    3: {"name": "golden_ticket",       "label": "Golden/Silver Ticket",   "color": "#f59e0b", "severity": "critical"},
    4: {"name": "lateral_movement",    "label": "Lateral Movement",       "color": "#fbbf24", "severity": "high"},
    5: {"name": "reconnaissance",      "label": "AD Reconnaissance",      "color": "#38bdf8", "severity": "medium"},
}

_N_FEATURES = 18  # must match _extract_row_features() output length

# ── Feature names (for human-readable output) ─────────────────────────────────

FEATURE_NAMES = [
    "EventID",
    "DestinationPort",
    "Has_Kerberoast",     # kerberoast/GetUserSPNs/rc4-hmac/etype 0x17
    "Has_ASREPRoast",     # as-rep roasting/GetNPUsers/asreproast
    "Has_PTH",            # sekurlsa::pth / mimikatz pass-the-hash
    "Has_DCSync",         # DS-Replication / lsadump::dcsync / 1131f6aa
    "Has_GoldenTicket",   # krbtgt / lsadump::golden / golden ticket / ptt
    "Has_SilverTicket",   # silver ticket / lsadump::silver
    "Has_PassTicket",     # pass-the-ticket / rubeus asktgt / rubeus ptt
    "Has_BloodHound",     # bloodhound / sharphound / ldapdomaindump / adrecon
    "Has_LSASS",          # lsass dump / procdump / comsvcs minidump / ntds.dit
    "Has_WMI_Lateral",    # wmiexec / wmic /node: / wmiprvse
    "Has_SMB_Lateral",    # psexec / net use / admin$ / ipc$ / smbexec
    "Has_RDP",            # mstsc / xfreerdp / logon type 10
    "Has_NTLMRelay",      # responder / ntlmrelayx / smbrelayx
    "Has_DomainEnum",     # nltest / net group /domain / net user /domain
    "EID_4769",           # Kerberos service ticket
    "EID_4662",           # Object access (DCSync indicator)
]

# ── Regex patterns per feature ────────────────────────────────────────────────

_RE: dict[str, re.Pattern] = {
    "Has_Kerberoast":   re.compile(r'kerberoast|GetUserSPNs|getnpusers|rc4[-\s]hmac|etype.*0x17|etype.*23|4769.*0x17', re.I),
    "Has_ASREPRoast":   re.compile(r'as[-_]rep\s*roast|asreproast|GetNPUsers|preauth.*not.*required|4768.*0x17', re.I),
    "Has_PTH":          re.compile(r'sekurlsa::pth|pass[-_]the[-_]hash|mimikatz.*pth|ntlm.*hash.*logon|aes256.*logon', re.I),
    "Has_DCSync":       re.compile(r'dcsync|DS[-_]Replication|1131f6aa|1131f6ab|lsadump::dcsync|GetChangesAll|replicat.*secret', re.I),
    "Has_GoldenTicket": re.compile(r'golden.*ticket|lsadump::golden|krbtgt.*hash|\bptt\b|kerberos.*golden|forged.*tgt', re.I),
    "Has_SilverTicket": re.compile(r'silver.*ticket|lsadump::silver|forged.*tgs|service.*ticket.*forge', re.I),
    "Has_PassTicket":   re.compile(r'pass[-_]the[-_]ticket|rubeus.*asktgt|rubeus.*ptt|rubeus.*s4u|kerberos::ptt', re.I),
    "Has_BloodHound":   re.compile(r'bloodhound|sharphound|Invoke-BloodHound|CollectionMethod|ldapdomaindump|adrecon|ldap.*dump', re.I),
    "Has_LSASS":        re.compile(r'lsass.*dump|procdump.*lsass|comsvcs.*minidump|ntds\.dit|vssadmin.*ntds|secretsdump', re.I),
    "Has_WMI_Lateral":  re.compile(r'wmiexec|wmic\s+/node:|wmiprvse.*cmd|invoke-wmimethod|win32_process.*create', re.I),
    "Has_SMB_Lateral":  re.compile(r'psexec|psexesvc|net\s+use\s+\\\\|\\\\.*\\admin\$|\\\\.*\\ipc\$|admin\s+share|ipc\$|smbexec|atexec|dcomexec|logon\s+type\s*[:\s]*3\b', re.I),
    "Has_RDP":          re.compile(r'mstsc|xfreerdp|rdesktop|logon type[:\s]*10\b|type\s*10\b|remote.*interactive', re.I),
    "Has_NTLMRelay":    re.compile(r'responder|ntlmrelayx|smbrelayx|ntlm.*relay|llmnr.*poison|nbt.*ns.*poison', re.I),
    "Has_DomainEnum":   re.compile(r'nltest\s*/dclist|net\s+group.*domain\s+admins|net\s+user\s+.*/domain|dsquery|Get-Domain|powerview', re.I),
}


def _extract_row_features(row: dict) -> list[float]:
    """Extract the 18-element feature vector for a single event row."""
    desc = str(row.get("CommandLine", "")) + " " + str(row.get("desc_extra", ""))
    eid  = int(row.get("EventID", 0) or 0)
    port = float(row.get("DestinationPort", 0) or 0)

    feats = [float(eid), port]
    for fname in FEATURE_NAMES[2:-2]:   # Has_* features
        feats.append(1.0 if _RE[fname].search(desc) else 0.0)
    feats.append(1.0 if eid == 4769 else 0.0)  # EID_4769
    feats.append(1.0 if eid == 4662 else 0.0)  # EID_4662
    return feats


# ── Synthetic training data generation ───────────────────────────────────────

def _synthetic_samples(n_per_class: int = 300) -> tuple[np.ndarray, np.ndarray]:
    """
    Generate synthetic AD attack training samples calibrated against
    OTRF/Security-Datasets event structure (github.com/OTRF/Security-Datasets).

    Key corrections validated by benchmark evaluation (v2→v3):
      - Recon: EID 4662 + Has_BloodHound → Recon (NOT DCSync); port varies 0/389
      - Lateral: PTH alone (Has_PTH, no SMB) and WMI alone (port 0/135) are valid
      - DCSync: EID 4662 + Has_DCSync, Has_BloodHound always 0 (clear class boundary)
      - GoldenTicket: Has_GoldenTicket/Has_SilverTicket must dominate — reduced noise flags
    """
    rng = np.random.default_rng(42)
    rows, labels = [], []

    def _row(eid=0, port=0, **flags):
        r = [float(eid), float(port)] + [0.0] * 14 + [0.0, 0.0]
        fname_idx = {n: i + 2 for i, n in enumerate(FEATURE_NAMES[2:-2])}
        for k, v in flags.items():
            if k in fname_idx:
                r[fname_idx[k]] = float(v)
        if eid == 4769: r[16] = 1.0
        if eid == 4662: r[17] = 1.0
        return r

    # ── Class 0: Normal ─────────────────────────────────────────────────────
    for _ in range(n_per_class):
        rows.append(_row(eid=int(rng.choice([4624, 4688, 4663, 4648, 4769, 4768, 0])),
                         port=float(rng.choice([80, 443, 3389, 445, 88, 0, 0]))))
        labels.append(0)

    # ── Class 1: Kerberoasting (EID 4769 RC4-HMAC) ──────────────────────────
    for _ in range(n_per_class):
        rows.append(_row(eid=4769, port=88,
                         Has_Kerberoast=1,
                         Has_DomainEnum=int(rng.random() > 0.6)))
        labels.append(1)

    # ── Class 1b: AS-REP Roasting (EID 4768/4771, preauth disabled) ─────────
    for _ in range(n_per_class):
        rows.append(_row(eid=int(rng.choice([4768, 4771])), port=88,
                         Has_ASREPRoast=1))
        labels.append(1)

    # ── Class 2a: DCSync (EID 4662 + Has_DCSync, BloodHound NEVER present) ──
    # Benchmark finding: mixing Has_BloodHound into DCSync training caused false
    # positives when real BloodHound events used EID 4662.
    for _ in range(n_per_class):
        rows.append(_row(eid=4662,
                         Has_DCSync=1,
                         Has_LSASS=int(rng.random() > 0.5)))
        labels.append(2)

    # ── Class 2b: LSASS credential dump (procdump / comsvcs / mimikatz) ──────
    for _ in range(n_per_class):
        rows.append(_row(eid=int(rng.choice([4688, 4656])),
                         Has_LSASS=1))
        labels.append(2)

    # ── Class 3: Golden/Silver Ticket ────────────────────────────────────────
    # Benchmark finding: noisy co-occurrence of Has_Kerberoast/Has_DCSync caused
    # false positives. Dominant indicator must be Has_GoldenTicket or Has_SilverTicket.
    for _ in range(n_per_class):
        gt = int(rng.random() > 0.5)
        rows.append(_row(eid=int(rng.choice([4769, 4768])), port=88,
                         Has_GoldenTicket=gt,
                         Has_SilverTicket=1 - gt,
                         Has_PassTicket=int(rng.random() > 0.4)))
        labels.append(3)

    # ── Class 3b: Pass-the-Ticket (explicit rubeus ptt / kerberos::ptt) ──────
    for _ in range(n_per_class // 2):
        rows.append(_row(eid=int(rng.choice([4769, 4624])),
                         Has_PassTicket=1,
                         Has_GoldenTicket=int(rng.random() > 0.5)))
        labels.append(3)

    # ── Class 4a: SMB/PsExec lateral movement ────────────────────────────────
    for _ in range(n_per_class // 3):
        rows.append(_row(eid=int(rng.choice([4624, 5140, 4688])), port=445,
                         Has_SMB_Lateral=1))
        labels.append(4)

    # ── Class 4b: WMI lateral movement (EID 4688, port 0 or 135) ────────────
    # Benchmark finding: only port=135 in training missed OTRF wmic /node: events
    # which use EID 4688 process creation with port=0.
    for _ in range(n_per_class // 3):
        rows.append(_row(eid=int(rng.choice([4688, 4688, 4688, 4624])),
                         port=int(rng.choice([0, 0, 135])),
                         Has_WMI_Lateral=1))
        labels.append(4)

    # ── Class 4c: Pass-the-Hash lateral (EID 4624 logon type 9, Has_PTH alone) ──
    # Benchmark finding: PTH-only events (no SMB_Lateral) were missed because
    # training always paired PTH with SMB. Real OTRF PTH = EID 4624 + Has_PTH.
    for _ in range(n_per_class // 3):
        rows.append(_row(eid=int(rng.choice([4624, 4648])),
                         Has_PTH=1,
                         Has_SMB_Lateral=int(rng.random() > 0.6)))
        labels.append(4)

    # ── Class 4d: RDP lateral movement ───────────────────────────────────────
    for _ in range(n_per_class // 3):
        rows.append(_row(eid=int(rng.choice([4624, 4688])), port=3389,
                         Has_RDP=1))
        labels.append(4)

    # ── Class 5a: BloodHound recon — EID 4688 process creation (port=0) ──────
    # Benchmark finding: fixed port=389 missed SharpHound.exe EID 4688 events.
    for _ in range(n_per_class // 3):
        rows.append(_row(eid=4688, port=0,
                         Has_BloodHound=1))
        labels.append(5)

    # ── Class 5b: BloodHound LDAP burst — EID 4662, Has_BloodHound=1 ─────────
    # Benchmark finding: EID 4662 in training was exclusively DCSync, causing
    # BloodHound LDAP access (also EID 4662) to be misclassified as DCSync.
    for _ in range(n_per_class // 3):
        rows.append(_row(eid=4662,
                         Has_BloodHound=1))
        labels.append(5)

    # ── Class 5c: Domain enumeration (nltest / net group / PowerView) ─────────
    # Benchmark finding: port=389 in training missed EID 4688 nltest/net events.
    for _ in range(n_per_class // 3):
        rows.append(_row(eid=int(rng.choice([4688, 4688, 4624, 0])),
                         port=int(rng.choice([0, 0, 389])),
                         Has_DomainEnum=1,
                         Has_BloodHound=int(rng.random() > 0.7)))
        labels.append(5)

    # Add jitter so the RF gets real variance to split on
    X = np.array(rows, dtype=float)
    noise_cols = [1]   # only port gets small float noise; binary cols stay binary
    X[:, noise_cols] += rng.normal(0, 2, (len(X), len(noise_cols)))
    X[:, noise_cols] = np.clip(X[:, noise_cols], 0, 65535)

    return X, np.array(labels)


def _train_and_save() -> RandomForestClassifier:
    log.info("LMD: training AD-specialized Random Forest…")
    X, y = _synthetic_samples(n_per_class=300)
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        min_samples_leaf=3,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X, y)
    joblib.dump({"model": clf, "n_features": _N_FEATURES, "version": 3}, MODEL_PATH)
    log.info("LMD: model saved to %s", MODEL_PATH)
    return clf


def _load_model() -> RandomForestClassifier:
    if MODEL_PATH.exists():
        try:
            saved = joblib.load(MODEL_PATH)
            if isinstance(saved, dict) and saved.get("n_features") == _N_FEATURES and saved.get("version") == 3:
                return saved["model"]
        except Exception:
            pass
    return _train_and_save()


# ── Public API ────────────────────────────────────────────────────────────────

class LMDDetection(TypedDict):
    event_index: int
    attack_class: int
    attack_name: str
    attack_label: str
    severity: str
    color: str
    source_ip: str
    dest_ip: str
    image: str
    command_line: str
    event_id: int
    destination_port: int
    matched_features: list[str]


class LMDResult(TypedDict):
    total_events: int
    detections: list[LMDDetection]
    attack_counts: dict[str, int]
    graph: dict
    anomaly_strings: list[str]


def run_lmd_model_and_graph(events: list[ForensicEvent],
                             output_path: str | None = None) -> tuple[list[str], dict]:
    """
    Run the AD-specialized LMD model on ForensicEvents.

    Returns (anomaly_strings, graph_data) for backwards-compatibility with
    existing callers in routes.py.  The full structured result is available
    via run_lmd_full() below.
    """
    full = run_lmd_full(events, output_path)
    return full["anomaly_strings"], full["graph"]


def run_lmd_full(events: list[ForensicEvent],
                 output_path: str | None = None) -> LMDResult:
    """Full structured LMD result including per-detection metadata."""
    if not events:
        return LMDResult(total_events=0, detections=[], attack_counts={},
                         graph={"nodes": [], "edges": []}, anomaly_strings=[])

    clf = _load_model()

    # ── Build feature matrix ─────────────────────────────────────────────────
    rows_raw = []
    for e in events:
        extra = e.extra or {}
        dest_ip  = extra.get("destinationip") or extra.get("DestinationIp") or ""
        src_ip   = extra.get("sourceip")      or extra.get("SourceIp")      or e.source_host or ""
        cmd      = extra.get("commandline")   or extra.get("CommandLine")   or e.description or ""
        image    = extra.get("image")         or extra.get("Image")         or ""
        dport    = int(extra.get("destinationport") or extra.get("DestinationPort") or 0)

        # Combine image + command line + description for pattern matching
        combined = f"{image} {cmd} {e.description or ''}"

        rows_raw.append({
            "EventID":         e.event_id or 0,
            "DestinationPort": dport,
            "CommandLine":     cmd,
            "desc_extra":      combined,
            "_src_ip":         src_ip,
            "_dst_ip":         dest_ip,
            "_image":          image,
            "_cmd":            cmd,
        })

    X = np.array([_extract_row_features(r) for r in rows_raw], dtype=float)
    preds = clf.predict(X)
    probs = clf.predict_proba(X)

    # ── Build structured detections ──────────────────────────────────────────
    detections: list[LMDDetection] = []
    anomaly_strings: list[str] = []
    attack_counts: dict[str, int] = {}

    for i, (row, pred, prob) in enumerate(zip(rows_raw, preds, probs)):
        if pred == 0:
            continue
        cls   = _ATTACK_CLASSES[int(pred)]
        conf  = float(prob[int(pred)])
        label = cls["label"]

        matched = [
            fname for fname in FEATURE_NAMES[2:-2]
            if X[i, FEATURE_NAMES.index(fname)] > 0.5
        ]

        det: LMDDetection = {
            "event_index":    i,
            "attack_class":   int(pred),
            "attack_name":    cls["name"],
            "attack_label":   label,
            "severity":       cls["severity"],
            "color":          cls["color"],
            "source_ip":      row["_src_ip"],
            "dest_ip":        row["_dst_ip"],
            "image":          row["_image"],
            "command_line":   str(row["_cmd"])[:200],
            "event_id":       int(row["EventID"] or 0),
            "destination_port": int(row["DestinationPort"] or 0),
            "matched_features": matched,
        }
        detections.append(det)
        attack_counts[label] = attack_counts.get(label, 0) + 1

        src = row["_src_ip"] or "unknown"
        dst = row["_dst_ip"] or "unknown"
        anomaly_strings.append(
            f"DETECTED [{label}] ({conf:.0%} confidence): {src} → {dst}"
            + (f" via {row['_image']}" if row["_image"] else "")
        )

    # ── Build graph ──────────────────────────────────────────────────────────
    net = Network(height="750px", width="100%", bgcolor="#1e293b",
                  font_color="white", directed=True)

    _ATTACK_COLORS = {c["label"]: c["color"] for c in _ATTACK_CLASSES.values() if c["name"] != "Normal"}

    nodes_meta: dict[str, str] = {}   # ip → role
    edges_agg:  dict[tuple, dict] = {}

    for det in detections:
        src, dst = det["source_ip"] or "unknown", det["dest_ip"] or "unknown"
        if not src or not dst or src == dst:
            continue
        nodes_meta.setdefault(src, "attacker")
        if nodes_meta.get(dst, "normal") == "normal":
            nodes_meta[dst] = "victim"
        key = (src, dst, det["attack_label"])
        if key not in edges_agg:
            edges_agg[key] = {"count": 0, "color": det["color"],
                               "label": det["attack_label"], "src": src, "dst": dst}
        edges_agg[key]["count"] += 1

    graph_nodes, graph_edges = [], []

    for ip, role in nodes_meta.items():
        if role == "attacker":
            net.add_node(ip, label=f"ATTACKER: {ip}", color="darkred",
                         shape="triangle", title="Role: Attacker")
            graph_nodes.append({"data": {"id": ip, "label": f"ATTACKER: {ip}",
                                         "color": "darkred", "shape": "triangle",
                                         "title": f"Role: Attacker\nIP: {ip}"}})
        else:
            net.add_node(ip, label=f"VICTIM: {ip}", color="orange",
                         shape="box", title="Role: Victim")
            graph_nodes.append({"data": {"id": ip, "label": f"VICTIM: {ip}",
                                         "color": "orange", "shape": "rectangle",
                                         "title": f"Role: Victim\nIP: {ip}"}})

    for (src, dst, lbl), info in edges_agg.items():
        cnt   = info["count"]
        color = info["color"]
        elabel = f"{lbl} ({cnt})" if cnt > 1 else lbl
        net.add_edge(src, dst, color=color, label=elabel,
                     title=f"{lbl} × {cnt}")
        graph_edges.append({"data": {
            "id":     f"{src}-{dst}-{lbl}",
            "source": src, "target": dst,
            "label":  elabel, "color": color,
            "title":  f"{lbl} × {cnt}",
        }})

    net.repulsion(node_distance=300, central_gravity=0.1,
                  spring_length=250, spring_strength=0.01, damping=0.95)

    graph_path = Path(output_path) if output_path else PROJECT_ROOT / "attack_graph.html"
    try:
        net.save_graph(str(graph_path))
    except Exception as exc:
        log.warning("LMD: could not save graph HTML: %s", exc)

    return LMDResult(
        total_events=len(events),
        detections=detections,
        attack_counts=attack_counts,
        graph={"nodes": graph_nodes, "edges": graph_edges},
        anomaly_strings=list(dict.fromkeys(anomaly_strings)),
    )
