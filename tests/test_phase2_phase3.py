"""
Verification tests for Phase 2 (normalizer + behavioral) and Phase 3 (storyline).
Run with: python -m pytest tests/test_phase2_phase3.py -v
"""
import pytest
from datetime import datetime
from backend.schema import ForensicEvent


def ev(ts, eid, host, user, desc, id_=None):
    return ForensicEvent(
        timestamp=ts, event_type="test", source_host=host,
        user=user, description=desc, raw_source="generic",
        event_id=eid, id=id_,
    )


# ── Shared test events ─────────────────────────────────────────────────────────
@pytest.fixture(scope="module")
def events():
    evs = [
        ev("2024-11-14T09:16:02", "4769", "DC-01", "jdoe",
           "A Kerberos service ticket was requested. Service Name: MSSQLSvc/SQLSERVER-01.corp.local:1433 "
           "Ticket Encryption Type: 0x17 Failure Code: 0x0.", id_=1),
        ev("2024-11-14T09:16:18", "4769", "DC-01", "jdoe",
           "A Kerberos service ticket was requested. Service Name: HTTP/WEBSERVER-01.corp.local "
           "Ticket Encryption Type: 0x17 Failure Code: 0x0.", id_=2),
        ev("2024-11-14T09:16:34", "4769", "DC-01", "jdoe",
           "A Kerberos service ticket was requested. Service Name: CIFS/FILESERVER-01.corp.local "
           "Ticket Encryption Type: 0x17 Failure Code: 0x0.", id_=3),
        # Process creation - WINWORD spawning cmd/PowerShell
        ev("2024-11-14T09:14:51", "4688", "WORKSTATION-06", "jdoe",
           "A new process has been created. Creator Subject: Account Name: jdoe Account Domain: CORP "
           "Logon ID: 0xA3B122. Process Information: New Process ID: 0x1C44 "
           "New Process Name: C:\\Windows\\System32\\cmd.exe Token Elevation Type: TokenElevationTypeFull (2) "
           "Creator Process Name: C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE "
           "Process Command Line: cmd.exe /c powershell.exe -ep bypass -enc BASE64PAYLOAD.", id_=4),
        # Network logon type 3 to DC-01
        ev("2024-11-14T09:18:14", "4624", "DC-01", "jdoe",
           "An account was successfully logged on. Logon Information: Logon Type: 3 Network. "
           "New Logon: Account Name: jdoe Account Domain: CORP Logon ID: 0xB4C233. "
           "Network Information: Workstation Name: WORKSTATION-06 Source Network Address: 10.0.0.54 "
           "Source Port: 49234 Authentication Package: NTLM.", id_=5),
        # Golden ticket (all-zeros Logon GUID)
        ev("2024-11-14T09:20:07", "4624", "HRSERVER-01", "Administrator",
           "An account was successfully logged on. Logon Information: Logon Type: 3 Network. "
           "New Logon: Account Name: Administrator Logon ID: 0xC5D344. "
           "Network Information: Source Network Address: 10.0.0.54 Authentication Package: Kerberos. "
           "Logon GUID: {00000000-0000-0000-0000-000000000000}.", id_=6),
        # DCSync (4662 with replication GUIDs)
        ev("2024-11-14T09:18:55", "4662", "DC-01", "jdoe",
           "An operation was performed on an object. Subject: Account Name: jdoe Account Domain: CORP. "
           "Object Type: domainDNS. Accesses: Control Access. "
           "Properties: {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} DS-Replication-Get-Changes "
           "{1131f6ab-9c07-11d1-f79f-00c04fc2dcd2} DS-Replication-Get-Changes-All.", id_=7),
        # Registry persistence (HKCU Run key)
        ev("2024-11-14T09:24:04", "4657", "WORKSTATION-06", "jdoe",
           "A registry value was modified. Subject: Account Name: jdoe Account Domain: CORP. "
           "Object: Object Name: HKCU Software Microsoft Windows CurrentVersion Run "
           "Object Value Name: WindowsDefenderUpdate Type: REG_SZ New Value: rundll32.exe beacon.dll,Start.", id_=8),
        # Special privs at 16:22 (inside 07:00-19:00 — should NOT fire off-hours check)
        ev("2024-10-28T16:22:44", "4672", "WORKSTATION-08", "ltorres",
           "Special privileges assigned to new logon. Subject: Account Name: ltorres. "
           "Privileges: SeDebugPrivilege SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege "
           "SeTcbPrivilege SeBackupPrivilege SeLoadDriverPrivilege.", id_=9),
        # Scheduled task
        ev("2024-11-14T09:23:11", "4698", "WORKSTATION-06", "jdoe",
           "A scheduled task was created. Task Name: Microsoft Windows Diagnosis DiagnosticHub "
           "Task Actions: schtasks.exe /Create /SC ONLOGON /TN WindowsSecurityHealth /TR rundll32.exe.", id_=10),
        # New service
        ev("2024-12-10T20:16:04", "7045", "WORKSTATION-09", "amorris",
           "A new service was installed in the system. Service Name: WindowsSecurityUpdate "
           "Service File Name: C:\\Windows\\System32\\svchost32.exe -k LocalSystemNetworkRestricted "
           "Service Type: User Mode Service Start Type: Auto Start Service Account: LocalSystem.", id_=11),
        # File access (HR data)
        ev("2024-11-14T09:21:03", "4663", "HRSERVER-01", "Administrator",
           "An attempt was made to access an object. Subject: Account Name: Administrator "
           "Logon ID: 0xC5D344. Object: Object Type: File "
           "Object Name: C:\\HRData\\EmployeeRecords\\. Process Name: robocopy.exe. "
           "Access: ReadData ListDirectory.", id_=12),
        # Mimikatz (pattern-based, no specific EID mapping — should resolve via _PATTERNS)
        ev("2024-11-14T09:19:22", "4688", "WORKSTATION-06", "jdoe",
           "A new process has been created. "
           "New Process Name: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe "
           "Creator Process Name: C:\\Windows\\System32\\rundll32.exe "
           "Process Command Line: powershell.exe -c Invoke-Mimikatz -Command lsadump::dcsync "
           "/domain:corp.local /user:krbtgt.", id_=13),
        # SMB share on third host — gives jdoe 3 hosts (WORKSTATION-06, DC-01, FILESERVER-01)
        ev("2024-11-14T09:17:30", "5140", "FILESERVER-01", "jdoe",
           "A network share object was accessed. Share Name: \\\\*\\C$ "
           "Source Address: 10.0.0.54.", id_=20),
    ]
    # Auth failure burst: 12 failures for "admin" within ~44 seconds
    for i in range(12):
        evs.append(ev(
            datetime(2024, 11, 14, 9, 30, i * 4).isoformat(),
            "4625", "DC-01", "admin",
            "An account failed to log on. Logon Type: 3.", id_=100 + i,
        ))
    return evs


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 2a: Normalizer
# ═══════════════════════════════════════════════════════════════════════════════

class TestNormalizer:
    def test_process_creation_compressed(self, events):
        from backend.analysis.normalizer import extract_signal
        e = next(x for x in events if x.event_id == "4688" and "WINWORD" in x.description)
        sig = extract_signal(e)
        assert len(sig) < len(e.description), "Signal should be shorter than original"
        assert "proc=cmd.exe" in sig
        assert "parent=WINWORD.EXE" in sig
        assert "cmd=" in sig
        assert "elevated=FULL" in sig

    def test_logon_ok_compressed(self, events):
        from backend.analysis.normalizer import extract_signal
        e = next(x for x in events if x.event_id == "4624" and "NTLM" in x.description)
        sig = extract_signal(e)
        assert len(sig) < len(e.description)
        assert "LOGON_OK" in sig
        assert "type=Network" in sig
        assert "src=10.0.0.54" in sig
        assert "auth=NTLM" in sig

    def test_golden_ticket_flagged(self, events):
        from backend.analysis.normalizer import extract_signal
        e = next(x for x in events if "00000000-0000-0000-0000-000000000000" in x.description)
        sig = extract_signal(e)
        assert "GOLDEN_TICKET_INDICATOR" in sig

    def test_dcsync_flagged(self, events):
        from backend.analysis.normalizer import extract_signal
        e = next(x for x in events if x.event_id == "4662")
        sig = extract_signal(e)
        assert "DCSYNC_ACCESS" in sig
        assert "DS-Replication-Get-Changes-All" in sig

    def test_registry_mod_compressed(self, events):
        from backend.analysis.normalizer import extract_signal
        e = next(x for x in events if x.event_id == "4657")
        sig = extract_signal(e)
        assert len(sig) < len(e.description)
        assert "REG_MOD" in sig
        assert "WindowsDefenderUpdate" in sig

    def test_special_privs_compressed(self, events):
        from backend.analysis.normalizer import extract_signal
        e = next(x for x in events if x.event_id == "4672")
        sig = extract_signal(e)
        assert len(sig) < len(e.description)
        assert "SPECIAL_PRIVS" in sig
        assert "SeDebugPrivilege" in sig

    def test_scheduled_task_compressed(self, events):
        from backend.analysis.normalizer import extract_signal
        e = next(x for x in events if x.event_id == "4698")
        sig = extract_signal(e)
        assert len(sig) < len(e.description), f"Expected compression: {len(sig)} vs {len(e.description)}: {sig!r}"
        assert "SCHTASK_CREATE" in sig
        assert "DiagnosticHub" in sig

    def test_service_install_compressed(self, events):
        from backend.analysis.normalizer import extract_signal
        e = next(x for x in events if x.event_id == "7045")
        sig = extract_signal(e)
        assert len(sig) < len(e.description)
        assert "SVC_INSTALL" in sig
        assert "WindowsSecurityUpdate" in sig

    def test_kerberoasting_flagged(self, events):
        from backend.analysis.normalizer import extract_signal
        e = next(x for x in events if x.event_id == "4769")
        sig = extract_signal(e)
        assert "KRB_TGS" in sig
        assert "RC4_KERBEROAST_RISK" in sig

    def test_llm_token_reduction_gte_30pct(self, events):
        from backend.analysis.llm import _events_to_text as new_text

        def old_text(evs):
            lines = []
            for e in sorted(evs, key=lambda x: x.timestamp):
                ts = e.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                parts = [ts, f"host={e.source_host}", f"type={e.event_type}"]
                if e.user:
                    parts.append(f"user={e.user}")
                if e.event_id:
                    parts.append(f"EventID={e.event_id}")
                parts.append(e.description[:250])
                lines.append(" | ".join(parts))
            return "\n".join(lines)

        sample = [e for e in events if e.event_id in ("4688", "4624", "4662", "4657", "4698")][:8]
        old_len = len(old_text(sample))
        new_len = len(new_text(sample))
        reduction_pct = (1 - new_len / old_len) * 100
        assert reduction_pct >= 30, (
            f"Expected >= 30% token reduction, got {reduction_pct:.1f}% "
            f"({old_len} -> {new_len} chars)"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 2b: Behavioral Analysis
# ═══════════════════════════════════════════════════════════════════════════════

class TestBehavioral:
    def test_lateral_velocity_fires_for_jdoe(self, events):
        from backend.analysis.behavioral import analyze_behavior
        report = analyze_behavior(events)
        vel_anomalies = [a for a in report["anomalies"] if a["anomaly_type"] == "lateral_velocity"]
        jdoe_vel = [a for a in vel_anomalies if a["user"] == "jdoe"]
        assert jdoe_vel, (
            f"Expected lateral_velocity for jdoe (hits WORKSTATION-06, DC-01, FILESERVER-01). "
            f"All velocity anomalies: {vel_anomalies}"
        )
        assert jdoe_vel[0]["observed"] >= 3

    def test_auth_failure_burst_fires(self, events):
        from backend.analysis.behavioral import analyze_behavior
        report = analyze_behavior(events)
        burst = [a for a in report["anomalies"] if a["anomaly_type"] == "auth_failure_burst"]
        assert burst, "Expected auth_failure_burst for admin (12 failures)"
        assert burst[0]["observed"] >= 10

    def test_off_hours_privilege_does_not_fire_in_hours(self, events):
        """ltorres gets SeDebugPrivilege at 16:22 — inside 07:00-19:00, should NOT fire."""
        from backend.analysis.behavioral import analyze_behavior
        report = analyze_behavior(events)
        off_hours = [
            a for a in report["anomalies"]
            if a["anomaly_type"] == "off_hours_privilege" and a["user"] == "ltorres"
        ]
        assert not off_hours, (
            f"ltorres privilege at 16:22 is inside business hours — should not be flagged. Got: {off_hours}"
        )

    def test_off_hours_privilege_fires_at_night(self, events):
        """Add a 02:00 SeDebugPrivilege event — must be flagged."""
        from backend.analysis.behavioral import analyze_behavior
        night_event = ev(
            "2024-11-14T02:15:00", "4672", "WORKSTATION-06", "hacker",
            "Special privileges assigned to new logon. Privileges: SeDebugPrivilege.",
            id_=999,
        )
        report = analyze_behavior(events + [night_event])
        off_hours = [
            a for a in report["anomalies"]
            if a["anomaly_type"] == "off_hours_privilege" and a["user"] == "hacker"
        ]
        assert off_hours, "Expected off_hours_privilege at 02:15 to fire"

    def test_report_has_required_keys(self, events):
        from backend.analysis.behavioral import analyze_behavior
        report = analyze_behavior(events)
        assert "anomalies" in report
        assert "profiled_users" in report
        assert "analysis_window_hours" in report
        assert "highest_severity" in report
        assert report["profiled_users"] > 0

    def test_empty_events_returns_empty_report(self):
        from backend.analysis.behavioral import analyze_behavior
        report = analyze_behavior([])
        assert report["anomalies"] == []
        assert report["highest_severity"] == "none"


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 3: Attack Storyline
# ═══════════════════════════════════════════════════════════════════════════════

class TestStoryline:
    def test_kerberoasting_step_present(self, events):
        from backend.analysis.storyline import build_storyline
        story = build_storyline(events)
        tids = [s["technique_id"] for s in story["attack_steps"]]
        assert "T1558.003" in tids, f"Expected Kerberoasting T1558.003 in attack steps. Got: {tids}"

    def test_dcsync_step_present(self, events):
        from backend.analysis.storyline import build_storyline
        story = build_storyline(events)
        tids = [s["technique_id"] for s in story["attack_steps"]]
        assert "T1003.006" in tids, f"Expected DCSync T1003.006. Got: {tids}"

    def test_mimikatz_classified_as_credential_access(self, events):
        from backend.analysis.storyline import build_storyline
        story = build_storyline(events)
        mimikatz_steps = [
            s for s in story["attack_steps"] if s["tactic"] == "Credential Access"
            and "OS Credential Dumping" in s["technique_name"]
        ]
        assert mimikatz_steps, "Mimikatz should be classified as OS Credential Dumping / Credential Access"

    def test_lateral_paths_detected(self, events):
        from backend.analysis.storyline import build_storyline
        story = build_storyline(events)
        assert story["total_lateral_paths"] >= 1
        to_hosts = [p["to_host"] for p in story["lateral_paths"]]
        assert "DC-01" in to_hosts or "HRSERVER-01" in to_hosts

    def test_hr_data_in_blast_radius(self, events):
        from backend.analysis.storyline import build_storyline
        story = build_storyline(events)
        resources = story["blast_radius"]["accessed_resources"]
        assert any("HRData" in r for r in resources), f"Expected HRData in resources. Got: {resources}"

    def test_apt_threat_actor_profile(self, events):
        from backend.analysis.storyline import build_storyline
        story = build_storyline(events)
        profile = story["threat_actor_profile"]
        assert "APT" in profile or "Kerberoast" in profile, (
            f"Expected APT profile. Got: {profile!r}"
        )

    def test_tactic_progression_ordered(self, events):
        from backend.analysis.storyline import build_storyline, TACTIC_ORDER
        story = build_storyline(events)
        prog = story["tactic_progression"]
        assert len(prog) >= 3, f"Expected at least 3 tactics. Got: {prog}"
        # Verify the progression follows the kill chain order
        indices = [TACTIC_ORDER.index(t) for t in prog if t in TACTIC_ORDER]
        assert indices == sorted(indices), f"Tactic progression is not in kill chain order: {prog}"

    def test_persistence_mechanisms_captured(self, events):
        from backend.analysis.storyline import build_storyline
        story = build_storyline(events)
        pm = story["blast_radius"]["persistence_mechanisms"]
        assert len(pm) >= 2, f"Expected at least 2 persistence mechanisms. Got: {pm}"

    def test_confidence_high_for_long_chain(self, events):
        from backend.analysis.storyline import build_storyline
        story = build_storyline(events)
        assert story["total_attack_steps"] >= 5
        assert story["confidence"] == "high"

    def test_empty_events_returns_empty_storyline(self):
        from backend.analysis.storyline import build_storyline
        story = build_storyline([])
        assert story["attack_steps"] == []
        assert story["lateral_paths"] == []
        assert story["confidence"] == "low"

    def test_all_required_keys_present(self, events):
        from backend.analysis.storyline import build_storyline
        story = build_storyline(events)
        required = [
            "threat_actor_profile", "entry_vector", "tactic_progression",
            "attack_steps", "lateral_paths", "blast_radius",
            "total_duration_minutes", "confidence",
            "total_attack_steps", "total_lateral_paths",
        ]
        for key in required:
            assert key in story, f"Missing key: {key}"
        br_required = [
            "compromised_hosts", "compromised_users", "accessed_resources",
            "estimated_data_at_risk", "persistence_mechanisms",
        ]
        for key in br_required:
            assert key in story["blast_radius"], f"Missing blast_radius key: {key}"
