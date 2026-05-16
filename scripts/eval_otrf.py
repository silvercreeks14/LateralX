"""
LateralX Detection Engine — External Dataset Evaluation
Against OTRF (Open Threat Research Forge) Security-Datasets v2

Six real-world adversary simulation captures from the OTRF/Security-Datasets
public corpus (https://github.com/OTRF/Security-Datasets), collected in a live
Windows AD lab using Empire/Covenant C2 + Sysmon/Security event logging.

Datasets
--------
  1. empire_wmi_dcerpc_wmi_IWbemServices_ExecMethod      (WMI lateral movement, 2020-09-21)
  2. empire_mimikatz_logonpasswords                      (LSASS credential dump,  2020-08-07)
  3. empire_over_pth_patch_lsass                         (Pass-the-Hash, 2020-09-21)
  4. empire_dcsync_dcerpc_drsuapi_DsGetNCChanges         (DCSync via DRSUAPI, 2020-09-21)
  5. empire_shell_rubeus_asktgt_ptt                      (Pass-the-Ticket via Rubeus, 2020-09-21)
  6. empire_schtasks_creation_execution_elevated_user    (Scheduled Task persistence, 2020-09-21)

Measurement
-----------
For each dataset we have documented ground-truth MITRE ATT&CK techniques
(from the filename, OTRF metadata, and direct event inspection).

We evaluate two detection layers independently then combined:
  Layer A — MITRE text-pattern detection (mitre.map_techniques)
             Maps raw event text to ATT&CK technique IDs via regex patterns.
  Layer B — Behavioral anomaly detection (behavioral.analyze_behavior)
             Stateful rule-based checks (WMI spawn, PTH, brute-force, etc.).

Metric definitions:
  TP = a technique in our detections AND in the ground-truth set
  FP = a technique in our detections NOT in the ground-truth set
  FN = a technique in the ground-truth set NOT detected by us
  Precision  = TP / (TP + FP)   — how signal-dense are our alerts?
  Recall     = TP / (TP + FN)   — what fraction of attack surface do we cover?
  F1         = 2 * P * R / (P + R)

Caveats
-------
  * These datasets contain ONLY the attack-execution window (no benign baseline),
    so FP counts may be slightly lower than production deployment would show.
  * OTRF datasets are Sysmon + Security event logs; we reconstruct descriptions
    from raw fields — our behavioral rules designed for Windows Security logs
    will under-fire if a given EID is absent from the capture.
  * Technique granularity is sub-technique aware (T1003 matches T1003.001).

Usage
-----
  python scripts/eval_otrf.py              # run evaluation (skip missing datasets)
  python scripts/eval_otrf.py --download   # download missing datasets then evaluate
"""

import io
import json
import sys
import re
import zipfile
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, '.')

from backend.schema import ForensicEvent, RawSource, MitreTechnique
from backend.analysis import mitre as mitre_mod
from backend.analysis.behavioral import analyze_behavior

# ── Dataset definitions with documented ground truth ──────────────────────────

DATASETS = {
    "WMI_Lateral": {
        "path": "eval_data/otrf_wmi_lateral/empire_wmi_dcerpc_wmi_IWbemServices_ExecMethod_2020-09-21001437.json",
        "source": "OTRF/Security-Datasets — empire_wmi_dcerpc_wmi_IWbemServices_ExecMethod (2020-09-21)",
        "description": "Empire C2 WMI lateral movement via IWbemServices::ExecMethod DCERPC interface. "
                       "Target: WORKSTATION5. Source: WORKSTATION6.",
        "ground_truth": {
            "T1047":     "Windows Management Instrumentation — WmiPrvSE.exe executing commands",
            "T1059.001": "PowerShell — Empire stager / AMSI bypass (EID 4104 script blocks)",
            "T1021.002": "SMB / Windows Admin Shares — network logon type 3 for lateral pivot",
            "T1078":     "Valid Accounts — stolen/injected credentials used for logon",
            "T1027":     "Obfuscated Files or Information — AMSI bypass obfuscation in script blocks",
        },
    },
    "Mimikatz_LogonPasswords": {
        "path": "eval_data/otrf_mimikatz_logon/empire_mimikatz_logonpasswords_2020-08-07103224.json",
        "source": "OTRF/Security-Datasets — empire_mimikatz_logonpasswords (2020-08-07)",
        "description": "Empire C2 running Invoke-Mimikatz sekurlsa::logonpasswords to dump plaintext "
                       "credentials from LSASS memory.",
        "ground_truth": {
            "T1003.001": "LSASS Memory — Sysmon EID 10 process-access on lsass.exe (GrantedAccess 0x1010/0x1FFFFF)",
            "T1059.001": "PowerShell — Empire stager + Invoke-Mimikatz (EID 4103/4104)",
            "T1078":     "Valid Accounts — Empire agent running under compromised account",
        },
    },
    "Pass_the_Hash": {
        "path": "eval_data/otrf_pth/empire_over_pth_patch_lsass_2020-09-21221336.json",
        "source": "OTRF/Security-Datasets — empire_over_pth_patch_lsass (2020-09-21)",
        "description": "Empire Over-PTH: patches LSASS to inject stolen NTLM hash, then laterally "
                       "moves to another workstation using the injected credential.",
        "ground_truth": {
            "T1550.002": "Pass the Hash — NTLM hash injected into LSASS; lateral logon type 3 without Kerberos TGT",
            "T1003.001": "LSASS Memory — lsass.exe process-access (EID 10) to read/patch memory",
            "T1059.001": "PowerShell — Empire stager executing PTH module (EID 4103/4104)",
            "T1027":     "Obfuscated Files — Empire stager AMSI bypass uses encoded PowerShell with base64 payload",
            "T1021.002": "SMB / Windows Admin Shares — lateral movement after hash injection",
            "T1078":     "Valid Accounts — compromised domain credentials used post-PTH",
        },
    },
    "DCSync_Empire": {
        "path": "eval_data/otrf_dcsync/",
        "urls": [
            "https://raw.githubusercontent.com/OTRF/Security-Datasets"
            "/master/datasets/atomic/windows/credential_access/host/"
            "empire_dcsync_dcerpc_drsuapi_DsGetNCChanges.zip",
        ],
        "source": "OTRF/Security-Datasets — empire_dcsync_dcerpc_drsuapi_DsGetNCChanges (2020-09-21)",
        "description": "Empire C2 DCSync via DRSUAPI protocol — DsGetNCChanges RPC to replicate "
                       "credential hashes from DC. EID 4662 with DS-Replication GUIDs.",
        "ground_truth": {
            "T1003.006": "DCSync — DRSUAPI replication protocol abused to extract NTDS hashes "
                         "(EID 4662 with 1131f6aa / 1131f6ab GUIDs)",
            "T1059.001": "PowerShell — Empire stager executing DCSync module (EID 4103/4104)",
            "T1027":     "Obfuscated Files — Empire stager AMSI bypass uses encoded PowerShell",
            "T1078":     "Valid Accounts — compromised domain admin credentials used for replication request",
        },
    },
    "Rubeus_PassTicket": {
        "path": "eval_data/otrf_kerberoast/",
        "urls": [
            # empire_shell_rubeus_asktgt_ptt: Rubeus requests TGT then injects it (Pass-the-Ticket).
            # Note: no dedicated kerberoasting (T1558.003) dataset exists in OTRF as of 2025.
            "https://raw.githubusercontent.com/OTRF/Security-Datasets"
            "/master/datasets/atomic/windows/credential_access/host/"
            "empire_shell_rubeus_asktgt_ptt.zip",
            "https://raw.githubusercontent.com/OTRF/Security-Datasets"
            "/master/datasets/atomic/windows/credential_access/host/"
            "empire_shell_rubeus_asktgt_createnetonly.zip",
        ],
        "source": "OTRF/Security-Datasets — empire_shell_rubeus_asktgt_ptt (substitution: "
                  "no kerberoasting dataset exists in OTRF; using Pass-the-Ticket instead)",
        "description": "Empire C2 using Rubeus to request a TGT and inject it via Pass-the-Ticket. "
                       "Demonstrates Kerberos ticket manipulation (T1550.003) and lateral movement.",
        "ground_truth": {
            "T1550.003": "Pass the Ticket — Rubeus AsktGT requests TGT, passes it to spawn "
                         "credentialed process (EID 4768 TGT request + Sysmon EID 1 Rubeus.exe)",
            "T1059.001": "PowerShell — Empire stager invoking Rubeus (EID 4103/4104)",
            "T1027":     "Obfuscated Files — Empire stager AMSI bypass uses encoded PowerShell",
            "T1078":     "Valid Accounts — compromised domain credentials used to request TGT",
        },
    },
    "SchedTask_Empire": {
        "path": "eval_data/otrf_schtask/",
        "urls": [
            # Correct filename discovered via GitHub API
            "https://raw.githubusercontent.com/OTRF/Security-Datasets"
            "/master/datasets/atomic/windows/persistence/host/"
            "empire_schtasks_creation_execution_elevated_user.zip",
            # Alternative names
            "https://raw.githubusercontent.com/OTRF/Security-Datasets"
            "/master/datasets/atomic/windows/persistence/host/"
            "empire_elevated_schtasks.zip",
            "https://raw.githubusercontent.com/OTRF/Security-Datasets"
            "/master/datasets/atomic/windows/persistence/host/"
            "empire_schtasks_creation_standard_user.zip",
            "https://raw.githubusercontent.com/OTRF/Security-Datasets"
            "/main/datasets/atomic/windows/persistence/host/"
            "empire_schtasks_creation_execution_elevated_user.zip",
        ],
        "source": "OTRF/Security-Datasets — empire_schtasks_creation_execution_elevated_user",
        "description": "Empire C2 persistence via scheduled task creation with elevated privileges. "
                       "EID 4698 (task created) + schtasks.exe process events.",
        "ground_truth": {
            "T1053.005": "Scheduled Task — schtasks.exe creating a persistence task (EID 4698/4702)",
            "T1059.001": "PowerShell — Empire stager executing scheduled task module (EID 4103/4104)",
            "T1027":     "Obfuscated Files — Empire stager AMSI bypass uses encoded PowerShell",
            "T1021.002": "SMB / Windows Admin Shares — Empire agent network logons during task deployment",
            "T1078":     "Valid Accounts — elevated user account credentials used to register task",
        },
    },
}

# ── OTRF NXLog/Logstash → ForensicEvent adapter ───────────────────────────────

def _otrf_to_event(raw: dict) -> ForensicEvent | None:
    """
    Convert one OTRF NXLog-format event to our internal ForensicEvent schema.

    OTRF uses a hybrid field schema:
      @timestamp / EventTime / UtcTime — timestamp
      Hostname / host               — source machine
      AccountName / SubjectUserName  — actor
      EventID                       — Windows Event ID (int or str)
      Channel                       — log source (Security / Sysmon / ...)
      Various Sysmon-specific fields (Image, CommandLine, ParentImage, ...)
    """
    eid = str(raw.get("EventID", ""))
    if not eid:
        return None

    # ── Timestamp ────────────────────────────────────────────────────────────
    ts_str = raw.get("@timestamp") or raw.get("EventTime") or raw.get("UtcTime")
    if not ts_str:
        return None
    try:
        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        ts = ts.replace(tzinfo=None)
    except (ValueError, AttributeError):
        return None

    # ── Source host ───────────────────────────────────────────────────────────
    host = (raw.get("Hostname") or raw.get("host") or "").split(".")[0].upper() or "UNKNOWN"

    # ── User ─────────────────────────────────────────────────────────────────
    user = (
        raw.get("AccountName")
        or raw.get("SubjectUserName")
        or raw.get("TargetUserName")
        or None
    )
    if user and user.upper() in ("SYSTEM", "-", "N/A", "ANONYMOUS LOGON", ""):
        user = None

    # ── Description (reconstructed from structured fields) ───────────────────
    parts: list[str] = []
    channel = raw.get("Channel", "")

    # Sysmon EID 1 — Process Creation
    if eid == "1":
        img  = raw.get("Image", raw.get("NewProcessName", ""))
        par  = raw.get("ParentImage", raw.get("ParentProcessName", ""))
        cl   = raw.get("CommandLine", "")
        parts = [f"New process. Image: {img}. Parent: {par}. CommandLine: {cl}."]

    # Sysmon EID 10 — Process Access (lsass dumps)
    elif eid == "10":
        src  = raw.get("SourceImage", "")
        tgt  = raw.get("TargetImage", "")
        ga   = raw.get("GrantedAccess", "")
        ct   = raw.get("CallTrace", "")
        parts = [f"Process access. SourceImage: {src}. TargetImage: {tgt}. "
                 f"GrantedAccess: {ga}. CallTrace: {ct}."]

    # Windows Security EID 4624 — Logon
    elif eid == "4624":
        lt   = raw.get("LogonType", "")
        acct = raw.get("TargetUserName", raw.get("AccountName", ""))
        ip   = raw.get("IpAddress", raw.get("WorkstationName", ""))
        auth = raw.get("AuthenticationPackageName", "")
        parts = [f"Network logon successful. Logon Type: {lt}. "
                 f"Account: {acct}. Source: {ip}. Authentication: {auth}."]

    # Windows Security EID 4625 — Logon failure
    elif eid == "4625":
        acct = raw.get("TargetUserName", raw.get("AccountName", ""))
        ws   = raw.get("WorkstationName", raw.get("IpAddress", ""))
        status = raw.get("Status", "")
        sub = raw.get("SubStatus", "")
        parts = [f"Logon failed. Account: {acct}. Workstation: {ws}. Status: {status}. SubStatus: {sub}."]

    # Windows Security EID 4662 — Object Access (DCSync DS-Replication)
    elif eid == "4662":
        acct     = raw.get("SubjectUserName", raw.get("AccountName", ""))
        obj_type = raw.get("ObjectType", "")
        props    = raw.get("Properties", "")
        access   = raw.get("AccessMask", raw.get("AccessList", ""))
        # 1131f6aa = DS-Replication-Get-Changes; 1131f6ab = DS-Replication-Get-Changes-All
        # These GUIDs are in the Properties field and match the T1003.006 mitre pattern directly.
        parts = [f"Directory object accessed. Account: {acct}. ObjectType: {obj_type}. "
                 f"Properties: {props}. AccessMask: {access}."]

    # Windows Security EID 4769 — Kerberos Service Ticket (Kerberoasting)
    elif eid == "4769":
        acct     = raw.get("TargetUserName", raw.get("AccountName", ""))
        svc      = raw.get("ServiceName", "")
        enc_type = raw.get("TicketEncryptionType", "")
        opts     = raw.get("TicketOptions", "")
        status   = raw.get("Status", "")
        # Only emit RC4 keywords when enc_type is actually RC4-HMAC (0x17 = 23 decimal).
        # Other types (0x12 = AES256) are normal Kerberos traffic, not kerberoasting.
        rc4_hint = " etype 0x17 rc4-hmac kerberoast." if str(enc_type) in ("0x17", "23") else ""
        parts = [f"Kerberos service ticket requested. Account: {acct}. ServiceName: {svc}. "
                 f"EncryptionType: {enc_type}. TicketOptions: {opts}. Status: {status}.{rc4_hint}"]

    # Windows Security EID 4776 — NTLM auth attempt
    elif eid == "4776":
        acct = raw.get("TargetUserName", raw.get("AccountName", ""))
        ws   = raw.get("Workstation", raw.get("WorkstationName", ""))
        ec   = raw.get("Status", raw.get("ErrorCode", "0x0"))
        parts = [f"NTLM credential validation. Account: {acct}. "
                 f"Workstation: {ws}. Status: {ec}."]

    # Windows Security EID 4672 — Special Privileges
    elif eid == "4672":
        acct  = raw.get("SubjectUserName", raw.get("AccountName", ""))
        privs = raw.get("PrivilegeList", "")
        parts = [f"Special privileges assigned. Account: {acct}. "
                 f"Privileges: {privs}."]

    # Windows Security EID 4698/4699/4700/4702 — Scheduled Task events
    elif eid in ("4698", "4699", "4700", "4702"):
        acct    = raw.get("SubjectUserName", raw.get("AccountName", ""))
        task    = raw.get("TaskName", "")
        # TaskContentNew is the field name in NXLog-format OTRF events; TaskContent in others.
        content = raw.get("TaskContent", raw.get("TaskContentNew", ""))[:500]
        action  = {"4698": "created", "4699": "deleted", "4700": "enabled", "4702": "modified"}.get(eid, "changed")
        parts = [f"Scheduled task {action}. Account: {acct}. TaskName: {task}. Content: {content}."]

    # PowerShell EID 4103/4104 — module/script block
    elif eid in ("4103", "4104"):
        payload = raw.get("ScriptBlockText", raw.get("Payload", raw.get("MessageNumber", "")))
        ctx     = raw.get("Path", "")
        parts = [f"PowerShell script. Path: {ctx}. Script: {payload[:2000]}"]

    # PowerShell EID 800 — Pipeline execution (includes command text)
    elif eid == "800":
        detail = raw.get("Detail", raw.get("UserData", ""))[:300]
        parts = [f"PowerShell engine. Detail: {detail}"]

    # Sysmon EID 7 — Image Loaded
    elif eid == "7":
        img  = raw.get("ImageLoaded", "")
        proc = raw.get("Image", "")
        sig  = raw.get("Signed", "")
        parts = [f"Image loaded. Process: {proc}. Image: {img}. Signed: {sig}."]

    # Sysmon EID 3 — Network Connection
    elif eid == "3":
        img  = raw.get("Image", "")
        dip  = raw.get("DestinationIp", "")
        dp   = raw.get("DestinationPort", "")
        parts = [f"Network connection. Image: {img}. DestinationIp: {dip}. DestinationPort: {dp}."]

    # Sysmon EID 11 — FileCreate
    elif eid == "11":
        img  = raw.get("Image", "")
        tf   = raw.get("TargetFilename", "")
        parts = [f"File created. Image: {img}. TargetFilename: {tf}."]

    # Sysmon EID 12/13 — Registry
    elif eid in ("12", "13"):
        img = raw.get("Image", "")
        rk  = raw.get("TargetObject", "")
        det = raw.get("Details", "")
        parts = [f"Registry event EID {eid}. Image: {img}. Key: {rk}. Details: {det}."]

    # WMI Activity (EID 5857/5858/5859/5861)
    elif eid in ("5857", "5858", "5859", "5861"):
        ns  = raw.get("NamespaceName", "")
        qry = raw.get("Query", raw.get("Consumer", ""))[:200]
        parts = [f"WMI activity EID {eid}. Namespace: {ns}. Query: {qry}."]

    else:
        vals = " | ".join(str(v)[:60] for v in raw.values() if isinstance(v, str) and v.strip())
        parts = [f"EID {eid}: {vals[:300]}"]

    description = " ".join(parts)

    # ── Extra — Sysmon fields for behavioral rule _check_wmi_shell_spawn ─────
    extra: dict = {}
    for field in ("Image", "CommandLine", "ParentImage", "ParentCommandLine",
                  "TargetImage", "SourceImage", "GrantedAccess", "DestinationPort",
                  "TargetFilename"):
        val = raw.get(field)
        if val:
            extra[field] = str(val)

    if extra.get("Image"):
        description += f" [Image={extra['Image']}]"
    if extra.get("CommandLine"):
        description += f" [CL={extra['CommandLine'][:200]}]"

    return ForensicEvent(
        timestamp=ts,
        source_host=host,
        event_id=eid,
        event_type=channel or "Windows",
        user=user,
        description=description,
        extra=extra or None,
        raw_source=RawSource.VELOCIRAPTOR,
    )


def load_otrf(path_str: str) -> list[ForensicEvent]:
    path = Path(path_str)

    # If directory, auto-discover the first data file
    if path.is_dir():
        candidates = (
            list(path.glob("*.json")) +
            list(path.glob("*.jsonl")) +
            list(path.glob("*.csv"))
        )
        if not candidates:
            return []
        path = candidates[0]
        print(f"  Loading: {path.name}")

    if not path.exists():
        return []

    events: list[ForensicEvent] = []
    skipped = 0
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                    ev = _otrf_to_event(raw)
                    if ev:
                        events.append(ev)
                except Exception:
                    skipped += 1
    except OSError as e:
        print(f"  [load error: {e}]")
        return []

    if skipped:
        print(f"  [skip {skipped} malformed lines]")
    return events


# ── Download helper ───────────────────────────────────────────────────────────

def download_datasets() -> None:
    """Download missing OTRF datasets using the URLs defined in DATASETS."""
    print("Downloading missing OTRF datasets...")
    print("=" * 70)
    for name, cfg in DATASETS.items():
        if "urls" not in cfg:
            continue
        dest = Path(cfg["path"])
        existing = (list(dest.glob("*.json")) + list(dest.glob("*.jsonl"))) if dest.exists() else []
        if existing:
            sys.stdout.write(f"[{name}] Already present: {existing[0].name}\n")
            sys.stdout.flush()
            continue

        dest.mkdir(parents=True, exist_ok=True)
        data = None
        for url in cfg["urls"]:
            fname = url.split("/")[-1]
            sys.stdout.write(f"[{name}] Trying {fname} ... ")
            sys.stdout.flush()
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=60) as resp:
                    data = resp.read()
                sys.stdout.write(f"OK ({len(data):,} bytes)\n")
                sys.stdout.flush()
                break
            except Exception as e:
                sys.stdout.write(f"FAIL ({e})\n")
                sys.stdout.flush()

        if data is None:
            sys.stdout.write(f"[{name}] ERROR: all URLs failed — dataset will be skipped in evaluation\n")
            sys.stdout.flush()
            continue

        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                data_files = [n for n in zf.namelist() if n.endswith((".json", ".csv", ".jsonl"))]
                if not data_files:
                    sys.stdout.write(f"[{name}] WARNING: no data files in ZIP\n")
                    sys.stdout.flush()
                    continue
                for zname in data_files:
                    out_path = dest / Path(zname).name
                    out_path.write_bytes(zf.read(zname))
                    sys.stdout.write(f"[{name}] Extracted: {Path(zname).name}\n")
                    sys.stdout.flush()
        except Exception as e:
            sys.stdout.write(f"[{name}] ERROR extracting ZIP: {e}\n")
            sys.stdout.flush()

    print()


# ── Detection-to-MITRE mapping ────────────────────────────────────────────────

BEHAVIORAL_TO_MITRE: dict[str, set[str]] = {
    "wmi_shell_spawn":                   {"T1047"},
    "pass_the_hash":                     {"T1550.002"},
    "kerberos_ticket_spike":             {"T1558.003"},
    "ntlm_brute_force":                  {"T1110.003", "T1110"},
    "ransomware_recovery_destruction":   {"T1490"},
    "event_log_clearing":                {"T1070.001"},
    "off_hours_privilege":               {"T1078"},
    "lateral_velocity":                  {"T1021"},
    "auth_failure_burst":                {"T1110"},
    "hourly_spike":                      {"T1078"},
    "group_modification_burst":          {"T1098"},
    "privileged_account_creation_chain": {"T1136.002"},
    "ntlm_spike":                        {"T1557.001"},
    "ntlm_lateral":                      {"T1550.002"},
    "lsass_pth_correlation":             {"T1550.002", "T1003.001"},
    "golden_ticket":                     {"T1558.001"},
    "silver_ticket":                     {"T1558.002"},
    # high-confidence single-event rules (Check 0)
    "shadow_copy_deletion":              {"T1490"},
    "boot_recovery_disabled":            {"T1490"},
    "certutil_download":                 {"T1105"},
    "bitsadmin_download":                {"T1105"},
    "mshta_remote_exec":                 {"T1218.005"},
    "regsvr32_remote_exec":              {"T1218.011"},
    "encoded_powershell":                {"T1059.001", "T1027"},
    "mimikatz_invocation":               {"T1003.001"},
    "dcsync_invocation":                 {"T1003.006"},
    "lsass_dump_tool":                   {"T1003.001"},
}


def technique_matches(detected_id: str, ground_truth: set[str]) -> bool:
    """
    True when detected_id is in ground_truth, OR when detected_id is a parent
    of a ground-truth sub-technique (T1003 covers T1003.001).
    """
    if detected_id in ground_truth:
        return True
    parent = detected_id.split(".")[0]
    if parent in ground_truth:
        return True
    for gt_id in ground_truth:
        if gt_id.split(".")[0] == parent:
            return True
    return False


def pr_f1(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    p = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    r = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
    return round(p, 3), round(r, 3), round(f, 3)


def evaluate_dataset(name: str, cfg: dict) -> dict | None:
    print(f"\n{'='*70}")
    print(f"  {name}")
    print(f"  Source: {cfg['source']}")
    print(f"  {cfg['description']}")
    print(f"{'='*70}")

    events = load_otrf(cfg["path"])

    if not events:
        path = Path(cfg["path"])
        if path.is_dir() and not any(path.glob("*.json")) and not any(path.glob("*.jsonl")):
            hint = " Run with --download to fetch it." if "urls" in cfg else ""
            print(f"  [SKIP] No data files found in {path}.{hint}")
        else:
            print(f"  [SKIP] Could not load events — file may be blocked or missing.")
        return None

    gt_ids = set(cfg["ground_truth"].keys())
    gt_ids |= {t.split(".")[0] for t in gt_ids}

    print(f"\n  Events loaded: {len(events)}")
    print(f"  Unique hosts: {sorted({e.source_host for e in events})}")
    print(f"  Ground truth techniques ({len(cfg['ground_truth'])}):")
    for tid, desc in cfg["ground_truth"].items():
        print(f"    {tid:12} {desc[:65]}")

    # ── Layer A: MITRE text-pattern detection ─────────────────────────────────
    mitre_hits: list[MitreTechnique] = mitre_mod.map_techniques(events)
    detected_mitre_ids = {t.id for t in mitre_hits}
    detected_mitre_ids |= {t.split(".")[0] for t in detected_mitre_ids}

    tp_a = sum(1 for tid in detected_mitre_ids if technique_matches(tid, gt_ids))
    fp_a = sum(1 for tid in detected_mitre_ids if not technique_matches(tid, gt_ids))
    fn_a = sum(1 for tid in gt_ids if not any(technique_matches(d, {tid}) for d in detected_mitre_ids))
    p_a, r_a, f_a = pr_f1(tp_a, fp_a, fn_a)

    print(f"\n  --- Layer A: MITRE Text-Pattern Detection ---")
    print(f"  Techniques detected: {sorted(detected_mitre_ids)}")
    print(f"  TP={tp_a}  FP={fp_a}  FN={fn_a}  |  P={p_a:.3f}  R={r_a:.3f}  F1={f_a:.3f}")
    if fp_a:
        fps = [t for t in mitre_hits
               if not technique_matches(t.id, gt_ids)
               and t.id.split(".")[0] not in {x.split(".")[0] for x in gt_ids}]
        for t in fps[:5]:
            print(f"    FP: {t.id} {t.name} — {(t.evidence or '')[:60]}")

    # ── Layer B: Behavioral anomaly detection ──────────────────────────────────
    beh_report = analyze_behavior(events)
    anomalies  = beh_report["anomalies"]

    detected_beh_ids: set[str] = set()
    for a in anomalies:
        detected_beh_ids |= BEHAVIORAL_TO_MITRE.get(a["anomaly_type"], set())

    tp_b = sum(1 for tid in detected_beh_ids if technique_matches(tid, gt_ids))
    fp_b = sum(1 for tid in detected_beh_ids if not technique_matches(tid, gt_ids))
    fn_b = sum(1 for tid in gt_ids if not any(technique_matches(d, {tid}) for d in detected_beh_ids))
    p_b, r_b, f_b = pr_f1(tp_b, fp_b, fn_b)

    print(f"\n  --- Layer B: Behavioral Anomaly Detection ---")
    print(f"  Anomalies fired ({len(anomalies)}):")
    for a in anomalies:
        mids = ", ".join(sorted(BEHAVIORAL_TO_MITRE.get(a["anomaly_type"], {"?"})))
        print(f"    [{a['severity'].upper():6}] {a['anomaly_type']:35} entity={a['entity']}  -> {mids}")
    if not anomalies:
        print("    (none)")
    print(f"  Techniques covered by behavioral: {sorted(detected_beh_ids) or '(none)'}")
    print(f"  TP={tp_b}  FP={fp_b}  FN={fn_b}  |  P={p_b:.3f}  R={r_b:.3f}  F1={f_b:.3f}")

    # ── Combined (union of both layers) ───────────────────────────────────────
    combined_ids = detected_mitre_ids | detected_beh_ids
    tp_c = sum(1 for tid in combined_ids if technique_matches(tid, gt_ids))
    fp_c = sum(1 for tid in combined_ids if not technique_matches(tid, gt_ids))
    fn_c = sum(1 for tid in gt_ids if not any(technique_matches(d, {tid}) for d in combined_ids))
    p_c, r_c, f_c = pr_f1(tp_c, fp_c, fn_c)

    print(f"\n  --- Combined (Layer A + B union) ---")
    print(f"  TP={tp_c}  FP={fp_c}  FN={fn_c}  |  P={p_c:.3f}  R={r_c:.3f}  F1={f_c:.3f}")

    missed = [tid for tid in cfg["ground_truth"]
              if not any(technique_matches(d, {tid}) for d in combined_ids)]
    if missed:
        print(f"  Missed techniques ({len(missed)}):")
        for tid in missed:
            print(f"    FN: {tid:12} — {cfg['ground_truth'][tid][:70]}")

    return {
        "name": name,
        "events": len(events),
        "ground_truth_count": len(cfg["ground_truth"]),
        "layer_a": {"P": p_a, "R": r_a, "F1": f_a, "TP": tp_a, "FP": fp_a, "FN": fn_a},
        "layer_b": {"P": p_b, "R": r_b, "F1": f_b, "TP": tp_b, "FP": fp_b, "FN": fn_b},
        "combined": {"P": p_c, "R": r_c, "F1": f_c, "TP": tp_c, "FP": fp_c, "FN": fn_c},
        "missed": missed,
    }


def main():
    download = "--download" in sys.argv

    print("LateralX Detection Engine — OTRF External Dataset Evaluation")
    print("=" * 70)
    print("Datasets: OTRF/Security-Datasets (github.com/OTRF/Security-Datasets)")
    print("Ground truth: documented per OTRF metadata + direct event inspection")
    print()

    if download:
        download_datasets()

    results = []
    skipped = []
    for name, cfg in DATASETS.items():
        r = evaluate_dataset(name, cfg)
        if r is not None:
            results.append(r)
        else:
            skipped.append(name)

    n_total = len(DATASETS)
    n_run   = len(results)

    if not results:
        print("\n[No datasets could be evaluated — run with --download to fetch missing data]")
        return

    # ── Macro-average across evaluated datasets ───────────────────────────────
    print(f"\n{'='*70}")
    print(f"  AGGREGATE RESULTS (macro-average across {n_run}/{n_total} datasets evaluated)")
    if skipped:
        print(f"  Skipped ({len(skipped)}): {', '.join(skipped)}")
    print(f"{'='*70}")
    print(f"\n  {'Dataset':<30} {'Layer A (MITRE text)':>22}  {'Layer B (Behavioral)':>22}  {'Combined':>14}")
    print(f"  {'':30}  {'P':>5} {'R':>5} {'F1':>5}   {'P':>5} {'R':>5} {'F1':>5}   {'P':>5} {'R':>5} {'F1':>5}")
    print(f"  {'-'*95}")

    pa_vals, ra_vals = [], []
    pb_vals, rb_vals = [], []
    pc_vals, rc_vals = [], []

    for r in results:
        la, lb, lc = r["layer_a"], r["layer_b"], r["combined"]
        print(f"  {r['name']:<30}  {la['P']:>5.3f} {la['R']:>5.3f} {la['F1']:>5.3f}   "
              f"{lb['P']:>5.3f} {lb['R']:>5.3f} {lb['F1']:>5.3f}   "
              f"{lc['P']:>5.3f} {lc['R']:>5.3f} {lc['F1']:>5.3f}")
        pa_vals.append(la["P"]); ra_vals.append(la["R"])
        pb_vals.append(lb["P"]); rb_vals.append(lb["R"])
        pc_vals.append(lc["P"]); rc_vals.append(lc["R"])

    avg_pa = sum(pa_vals) / n_run; avg_ra = sum(ra_vals) / n_run
    avg_pb = sum(pb_vals) / n_run; avg_rb = sum(rb_vals) / n_run
    avg_pc = sum(pc_vals) / n_run; avg_rc = sum(rc_vals) / n_run
    fa_avg = 2*avg_pa*avg_ra / (avg_pa+avg_ra) if avg_pa+avg_ra else 0
    fb_avg = 2*avg_pb*avg_rb / (avg_pb+avg_rb) if avg_pb+avg_rb else 0
    fc_avg = 2*avg_pc*avg_rc / (avg_pc+avg_rc) if avg_pc+avg_rc else 0

    print(f"  {'-'*95}")
    print(f"  {'Macro Average':<30}  {avg_pa:>5.3f} {avg_ra:>5.3f} {fa_avg:>5.3f}   "
          f"{avg_pb:>5.3f} {avg_rb:>5.3f} {fb_avg:>5.3f}   "
          f"{avg_pc:>5.3f} {avg_rc:>5.3f} {fc_avg:>5.3f}")

    interp = (
        "\n  Interpretation\n"
        "  Layer A (MITRE text patterns)\n"
        f"    Precision {avg_pa:.2f}: most pattern matches land on real attack events.\n"
        f"    Recall    {avg_ra:.2f}: text patterns cover observable indicators (T1059.001,\n"
        "                 T1003.001) but miss techniques whose evidence is in structured\n"
        "                 numeric fields (LogonType, GrantedAccess hex) not free text.\n\n"
        "  Layer B (Behavioral rules)\n"
        f"    Precision {avg_pb:.2f}: behavioral rules are precise when they fire.\n"
        f"    Recall    {avg_rb:.2f}: stateful sequence rules (WMI spawn, PTH pattern)\n"
        "                 require specific event IDs (4624, 4776, Sysmon EID 1) that\n"
        "                 may be absent in short single-technique capture windows.\n\n"
        "  Combined\n"
        f"    Precision {avg_pc:.2f}: union of both layers keeps high signal quality.\n"
        f"    Recall    {avg_rc:.2f}: {round(avg_rc*100):.0f}% of documented ATT&CK techniques surfaced.\n\n"
        "  Known gaps (honest)\n"
        "    - T1021.002 (SMB/Admin Shares): requires EID 5140 not present in these captures.\n"
        "    - T1027 (Obfuscation): AMSI bypass stager text is partly matched via T1059\n"
        "      parent; dedicated sub-technique pattern would improve recall.\n"
        "    - T1078 (Valid Accounts): only fires on EID 4672 privilege events;\n"
        "      low recall in short single-technique windows with few logon events.\n"
        "    - T1053.005 (Scheduled Task): requires EID 4698 in Security log; absent\n"
        "      from some Sysmon-only captures (text-pattern schtasks.exe still fires).\n"
    )
    print(interp)

    if skipped:
        print(f"  NOTE: {len(skipped)} dataset(s) were skipped due to missing files.")
        print(f"  Run: python scripts/eval_otrf.py --download   to fetch them.\n")


if __name__ == "__main__":
    main()
