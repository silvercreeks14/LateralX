"""
Mutation tests for LateralX Layer B behavioral detection rules.

Unlike positive tests (which verify rules fire on correctly-formed attack events),
mutation tests verify precision: that rules do NOT fire when a single critical field
differs from the attack condition.  Each test pair has:
  positive  — events that MUST trigger the rule
  mutated   — same events with one field changed; rule MUST NOT fire

This guards against overly broad predicates that generate false positives when
a near-miss condition is present (e.g., business-hours SeDebugPrivilege, slightly
below-threshold failure counts, or same-host LSASS access without lateral move).

Methodology reference:
  Papadakis, M. et al. (2019). "Mutation Testing Advances: An Analysis and Survey."
  Advances in Computers, Vol. 112, pp. 275–378. Elsevier.

  Fraser, G. & Zeller, A. (2012). "Mutation-Driven Generation of Unit Tests and Oracles."
  IEEE Transactions on Software Engineering, 38(2), pp. 278–292.
"""

import pytest
from datetime import datetime, timedelta

from backend.schema import ForensicEvent, RawSource
from backend.analysis.behavioral import (
    analyze_behavior,
    AUTH_FAIL_THRESHOLD,
    AUTH_FAIL_WINDOW_MIN,
    KERB_TICKET_THRESHOLD,
    KERB_TICKET_WINDOW_MIN,
    SMB_LATERAL_HOST_THRESHOLD,
    SMB_LATERAL_WINDOW_MIN,
    RDP_LATERAL_HOST_THRESHOLD,
    WORK_HOUR_START,
    WORK_HOUR_END,
    NTLM_BRUTE_THRESHOLD,
    NTLM_BRUTE_WINDOW_MIN,
    PTT_LOOKBACK_MIN,
)

# ── Fixture helpers ────────────────────────────────────────────────────────────

_OFF_HOURS  = datetime(2024, 11, 15, 23, 0, 0)  # 23:00 — outside 07:00–19:00
_WORK_HOURS = datetime(2024, 11, 15, 12, 0, 0)  # 12:00 — inside  07:00–19:00


def _ev(
    user: str,
    ts: datetime,
    event_id: str,
    host: str = "HOST-A",
    desc: str = "event",
    extra: dict | None = None,
) -> ForensicEvent:
    return ForensicEvent(
        timestamp=ts,
        event_type="Security",
        source_host=host,
        user=user,
        description=desc,
        raw_source=RawSource.GENERIC,
        event_id=event_id,
        extra=extra,
    )


def _fired(events: list[ForensicEvent], anomaly_type: str) -> bool:
    result = analyze_behavior(events)
    return any(a["anomaly_type"] == anomaly_type for a in result["anomalies"])


# ── 1. Authentication Failure Burst ───────────────────────────────────────────

class TestAuthFailureBurst:
    """auth_failure_burst fires on ≥AUTH_FAIL_THRESHOLD EID 4625 in AUTH_FAIL_WINDOW_MIN min."""

    def _failures(self, count: int, spread_minutes: float, user: str = "victim") -> list[ForensicEvent]:
        base = _WORK_HOURS
        interval = (spread_minutes * 60) / max(count - 1, 1)
        return [
            _ev(user, base + timedelta(seconds=i * interval), "4625",
                desc=f"Account failed to log on. Account Name: {user}. Failure Reason: Bad password.")
            for i in range(count)
        ]

    def test_positive_exactly_at_threshold(self):
        """Exactly AUTH_FAIL_THRESHOLD failures in window − 1 minute → fires."""
        events = self._failures(AUTH_FAIL_THRESHOLD, AUTH_FAIL_WINDOW_MIN - 1)
        assert _fired(events, "auth_failure_burst"), (
            f"Expected auth_failure_burst to fire on {AUTH_FAIL_THRESHOLD} failures "
            f"in {AUTH_FAIL_WINDOW_MIN - 1} min"
        )

    def test_mutation_one_below_threshold(self):
        """AUTH_FAIL_THRESHOLD − 1 failures in same window → MUST NOT fire."""
        events = self._failures(AUTH_FAIL_THRESHOLD - 1, AUTH_FAIL_WINDOW_MIN - 1)
        assert not _fired(events, "auth_failure_burst"), (
            f"auth_failure_burst fired on {AUTH_FAIL_THRESHOLD - 1} failures "
            f"(one below threshold {AUTH_FAIL_THRESHOLD})"
        )

    def test_mutation_spread_beyond_window(self):
        """AUTH_FAIL_THRESHOLD failures spread over AUTH_FAIL_WINDOW_MIN + 10 min → MUST NOT fire."""
        events = self._failures(AUTH_FAIL_THRESHOLD, AUTH_FAIL_WINDOW_MIN + 10)
        assert not _fired(events, "auth_failure_burst"), (
            f"auth_failure_burst fired on {AUTH_FAIL_THRESHOLD} failures spread beyond "
            f"the {AUTH_FAIL_WINDOW_MIN}-min window"
        )


# ── 2. Kerberos Ticket Spike (Kerberoasting) ──────────────────────────────────

class TestKerberosTicketSpike:
    """kerberos_ticket_spike fires on ≥KERB_TICKET_THRESHOLD EID 4769 in KERB_TICKET_WINDOW_MIN min."""

    def _tickets(self, count: int, spread_minutes: float, user: str = "attacker") -> list[ForensicEvent]:
        base = _WORK_HOURS
        interval = (spread_minutes * 60) / max(count - 1, 1)
        return [
            _ev(user, base + timedelta(seconds=i * interval), "4769",
                desc=f"A Kerberos service ticket was requested. Account Name: {user}. "
                     f"Service Name: svc_{i:03d}. Ticket Encryption Type: 0x17.")
            for i in range(count)
        ]

    def test_positive_at_threshold(self):
        """Exactly KERB_TICKET_THRESHOLD tickets in window − 1 min → fires."""
        events = self._tickets(KERB_TICKET_THRESHOLD, KERB_TICKET_WINDOW_MIN - 1)
        assert _fired(events, "kerberos_ticket_spike"), (
            f"Expected kerberos_ticket_spike on {KERB_TICKET_THRESHOLD} tickets"
        )

    def test_mutation_one_below_threshold(self):
        """KERB_TICKET_THRESHOLD − 1 tickets → MUST NOT fire."""
        events = self._tickets(KERB_TICKET_THRESHOLD - 1, KERB_TICKET_WINDOW_MIN - 1)
        assert not _fired(events, "kerberos_ticket_spike"), (
            f"kerberos_ticket_spike fired on {KERB_TICKET_THRESHOLD - 1} tickets "
            f"(one below threshold {KERB_TICKET_THRESHOLD})"
        )

    def test_mutation_spread_beyond_window(self):
        """KERB_TICKET_THRESHOLD tickets spread over KERB_TICKET_WINDOW_MIN + 10 min → MUST NOT fire."""
        events = self._tickets(KERB_TICKET_THRESHOLD, KERB_TICKET_WINDOW_MIN + 10)
        assert not _fired(events, "kerberos_ticket_spike"), (
            f"kerberos_ticket_spike fired on {KERB_TICKET_THRESHOLD} tickets spread "
            f"beyond the {KERB_TICKET_WINDOW_MIN}-min window"
        )

    def test_mutation_machine_account_excluded(self):
        """Machine account (user$) tickets should not trigger Kerberoasting detection."""
        events = self._tickets(KERB_TICKET_THRESHOLD, KERB_TICKET_WINDOW_MIN - 1, user="DC01$")
        assert not _fired(events, "kerberos_ticket_spike"), (
            "kerberos_ticket_spike incorrectly fired on machine account (user$) tickets"
        )


# ── 3. Ransomware Recovery Destruction Triad ──────────────────────────────────

class TestRansomwareTriad:
    """ransomware_recovery_destruction fires on ≥2 of {vssadmin, bcdedit, wbadmin} in 10 min."""

    def _triad_events(self, tools: list[str], spread_minutes: float = 5.0) -> list[ForensicEvent]:
        base = _WORK_HOURS
        _CMDS = {
            "vssadmin": "vssadmin delete shadows /all /quiet",
            "bcdedit":  "bcdedit /set {default} recoveryenabled no",
            "wbadmin":  "wbadmin delete catalog -quiet",
        }
        events = []
        for i, tool in enumerate(tools):
            ts = base + timedelta(minutes=i * (spread_minutes / max(len(tools) - 1, 1)))
            cmd = _CMDS[tool]
            events.append(_ev("attacker", ts, "4688", desc=f"New process. {cmd}"))
        return events

    def test_positive_full_triad(self):
        """All 3 tools within 10 min → fires with high severity."""
        events = self._triad_events(["vssadmin", "bcdedit", "wbadmin"])
        result = analyze_behavior(events)
        hits = [a for a in result["anomalies"] if a["anomaly_type"] == "ransomware_recovery_destruction"]
        assert hits, "Expected ransomware_recovery_destruction on full 3-tool triad"
        assert hits[0]["severity"] == "high", "Full triad should be severity=high"

    def test_partial_two_of_three_fires_medium(self):
        """2-of-3 tools → fires but with medium severity (not high)."""
        events = self._triad_events(["vssadmin", "bcdedit"])
        result = analyze_behavior(events)
        hits = [a for a in result["anomalies"] if a["anomaly_type"] == "ransomware_recovery_destruction"]
        assert hits, "Expected ransomware_recovery_destruction on 2-of-3 triad"
        assert hits[0]["severity"] == "medium", "2-of-3 triad should be severity=medium"

    def test_mutation_single_tool_no_fire(self):
        """Only vssadmin alone (1-of-3) → MUST NOT fire (rule requires ≥2)."""
        events = self._triad_events(["vssadmin"])
        assert not _fired(events, "ransomware_recovery_destruction"), (
            "ransomware_recovery_destruction incorrectly fired on a single tool (need ≥2)"
        )

    def test_mutation_spread_beyond_window(self):
        """All 3 tools spread over 20 min (> 10-min window) → MUST NOT fire."""
        events = self._triad_events(["vssadmin", "bcdedit", "wbadmin"], spread_minutes=20)
        assert not _fired(events, "ransomware_recovery_destruction"), (
            "ransomware_recovery_destruction fired on tools spread beyond the 10-min window"
        )


# ── 4. SMB Lateral Movement ───────────────────────────────────────────────────

class TestSmbLateralMovement:
    """smb_lateral_movement fires on ≥SMB_LATERAL_HOST_THRESHOLD Type-3 logons in 30 min."""

    def _smb_logons(self, hosts: list[str], spread_minutes: float = 5.0,
                    user: str = "attacker", logon_type: str = "3") -> list[ForensicEvent]:
        base = _WORK_HOURS
        return [
            _ev(user, base + timedelta(minutes=i * (spread_minutes / max(len(hosts) - 1, 1))),
                "4624", host=h,
                desc=f"Account logged on. Account Name: {user}. Logon Type: {logon_type}.")
            for i, h in enumerate(hosts)
        ]

    def test_positive_at_threshold(self):
        """Exactly SMB_LATERAL_HOST_THRESHOLD Type-3 logons to distinct hosts → fires."""
        hosts = [f"TARGET-{i:02d}" for i in range(SMB_LATERAL_HOST_THRESHOLD)]
        events = self._smb_logons(hosts)
        assert _fired(events, "smb_lateral_movement"), (
            f"Expected smb_lateral_movement on {SMB_LATERAL_HOST_THRESHOLD} distinct hosts"
        )

    def test_mutation_one_below_threshold(self):
        """SMB_LATERAL_HOST_THRESHOLD − 1 distinct hosts → MUST NOT fire."""
        hosts = [f"TARGET-{i:02d}" for i in range(SMB_LATERAL_HOST_THRESHOLD - 1)]
        events = self._smb_logons(hosts)
        assert not _fired(events, "smb_lateral_movement"), (
            f"smb_lateral_movement fired on {SMB_LATERAL_HOST_THRESHOLD - 1} hosts "
            f"(one below threshold {SMB_LATERAL_HOST_THRESHOLD})"
        )

    def test_mutation_wrong_logon_type(self):
        """SMB_LATERAL_HOST_THRESHOLD logons with Type 2 (interactive) → MUST NOT fire."""
        hosts = [f"TARGET-{i:02d}" for i in range(SMB_LATERAL_HOST_THRESHOLD)]
        events = self._smb_logons(hosts, logon_type="2")
        assert not _fired(events, "smb_lateral_movement"), (
            "smb_lateral_movement incorrectly fired on LogonType 2 (interactive) — "
            "rule requires Type 3 (network)"
        )

    def test_mutation_spread_beyond_window(self):
        """SMB_LATERAL_HOST_THRESHOLD logons spread over SMB_LATERAL_WINDOW_MIN + 10 min → MUST NOT fire."""
        hosts = [f"TARGET-{i:02d}" for i in range(SMB_LATERAL_HOST_THRESHOLD)]
        events = self._smb_logons(hosts, spread_minutes=SMB_LATERAL_WINDOW_MIN + 10)
        assert not _fired(events, "smb_lateral_movement"), (
            f"smb_lateral_movement fired on logons spread beyond the {SMB_LATERAL_WINDOW_MIN}-min window"
        )


# ── 5. Off-Hours Privilege ────────────────────────────────────────────────────

class TestOffHoursPrivilege:
    """off_hours_privilege fires on EID 4672 SeDebugPrivilege outside 07:00–19:00."""

    def test_positive_off_hours_sedebug(self):
        """EID 4672 with SeDebugPrivilege at 23:00 → fires."""
        events = [_ev("analyst", _OFF_HOURS, "4672",
                       desc="Special privileges assigned. Privileges: SeDebugPrivilege SeBackupPrivilege.")]
        assert _fired(events, "off_hours_privilege"), (
            "Expected off_hours_privilege on SeDebugPrivilege at 23:00"
        )

    def test_mutation_business_hours(self):
        """Same EID 4672 with SeDebugPrivilege at 12:00 (business hours) → MUST NOT fire."""
        events = [_ev("analyst", _WORK_HOURS, "4672",
                       desc="Special privileges assigned. Privileges: SeDebugPrivilege SeBackupPrivilege.")]
        assert not _fired(events, "off_hours_privilege"), (
            f"off_hours_privilege incorrectly fired at {WORK_HOUR_START:02d}:00–{WORK_HOUR_END:02d}:00 "
            f"(business hours)"
        )

    def test_mutation_no_sedebug_privilege(self):
        """EID 4672 at 23:00 but only SeBackupPrivilege (no SeDebugPrivilege) → MUST NOT fire."""
        events = [_ev("analyst", _OFF_HOURS, "4672",
                       desc="Special privileges assigned. Privileges: SeBackupPrivilege SeRestorePrivilege.")]
        assert not _fired(events, "off_hours_privilege"), (
            "off_hours_privilege incorrectly fired on SeBackupPrivilege (not SeDebugPrivilege)"
        )

    def test_mutation_machine_account_excluded(self):
        """Machine accounts (user$) should never trigger off_hours_privilege."""
        events = [_ev("DC01$", _OFF_HOURS, "4672",
                       desc="Special privileges assigned. Privileges: SeDebugPrivilege.")]
        assert not _fired(events, "off_hours_privilege"), (
            "off_hours_privilege incorrectly fired on machine account (user$) at off-hours"
        )


# ── 6. Pass-the-Hash (NTLM keyword) ──────────────────────────────────────────

class TestPassTheHash:
    """pass_the_hash fires on ≥2 NTLM lateral logons (EID 4624 Type 3/9) with no EID 4768 in session."""

    def _ntlm_logon(self, user: str, ts: datetime, host: str, logon_type: str = "3") -> ForensicEvent:
        return _ev(user, ts, "4624", host=host,
                   desc=f"Account logged on. Account Name: {user}. Logon Type: {logon_type}. "
                        f"Authentication Package: NTLM. Source Network Address: 10.0.0.50.")

    def _tgt(self, user: str, ts: datetime) -> ForensicEvent:
        return _ev(user, ts, "4768",
                   desc=f"A Kerberos authentication ticket (TGT) was requested. Account Name: {user}.")

    def test_positive_ntlm_no_tgt(self):
        """2 NTLM Type-3 logons to different hosts with no EID 4768 → fires."""
        base = _WORK_HOURS
        events = [
            self._ntlm_logon("attacker", base, "HOST-B"),
            self._ntlm_logon("attacker", base + timedelta(minutes=5), "HOST-C"),
        ]
        assert _fired(events, "pass_the_hash"), (
            "Expected pass_the_hash on 2 NTLM logons with no Kerberos TGT"
        )

    def test_mutation_kerberos_tgt_present(self):
        """Same NTLM logons + EID 4768 TGT for same user → MUST NOT fire (Kerberos available)."""
        base = _WORK_HOURS
        events = [
            self._tgt("user1", base - timedelta(minutes=5)),
            self._ntlm_logon("user1", base, "HOST-B"),
            self._ntlm_logon("user1", base + timedelta(minutes=5), "HOST-C"),
        ]
        assert not _fired(events, "pass_the_hash"), (
            "pass_the_hash incorrectly fired when a Kerberos TGT is present for the user"
        )

    def test_mutation_single_logon_below_threshold(self):
        """Only 1 NTLM logon (below the 2-logon threshold) → MUST NOT fire."""
        events = [self._ntlm_logon("attacker", _WORK_HOURS, "HOST-B")]
        assert not _fired(events, "pass_the_hash"), (
            "pass_the_hash fired on a single NTLM logon (threshold is 2)"
        )


# ── 7. LSASS PTH Correlation ──────────────────────────────────────────────────

class TestLsassPthCorrelation:
    """lsass_pth_correlation fires on EID 10 (lsass) → EID 4624 Type 9 different host within 30 min."""

    def _lsass_access(self, ts: datetime, host: str = "HOST-A",
                      src: str = "C:\\Windows\\powershell.exe",
                      ga: str = "0x1010") -> ForensicEvent:
        return _ev("attacker", ts, "10", host=host,
                   desc=f"Process accessed. SourceImage: {src}. "
                        f"TargetImage: C:\\Windows\\System32\\lsass.exe. GrantedAccess: {ga}.",
                   extra={"SourceImage": src, "TargetImage": "C:\\Windows\\System32\\lsass.exe",
                          "GrantedAccess": ga})

    def _lateral_logon(self, user: str, ts: datetime, host: str,
                       logon_type: str = "9") -> ForensicEvent:
        return _ev(user, ts, "4624", host=host,
                   desc=f"Account logged on. Account Name: {user}. Logon Type: {logon_type}. "
                        f"Authentication Package: NTLM.")

    def test_positive_lsass_type9_different_host(self):
        """EID 10 lsass on HOST-A + EID 4624 Type 9 on HOST-B within 20 min → fires."""
        base = _WORK_HOURS
        events = [
            self._lsass_access(base, host="HOST-A"),
            self._lateral_logon("attacker", base + timedelta(minutes=10), host="HOST-B"),
        ]
        assert _fired(events, "lsass_pth_correlation"), (
            "Expected lsass_pth_correlation: EID 10 lsass + Type-9 lateral logon on different host"
        )

    def test_mutation_type3_not_type9(self):
        """Change lateral logon from Type 9 to Type 3 → MUST NOT fire (rule requires Type 9)."""
        base = _WORK_HOURS
        events = [
            self._lsass_access(base, host="HOST-A"),
            self._lateral_logon("attacker", base + timedelta(minutes=10),
                                host="HOST-B", logon_type="3"),
        ]
        assert not _fired(events, "lsass_pth_correlation"), (
            "lsass_pth_correlation incorrectly fired on Type-3 logon (rule specifically requires Type 9)"
        )

    def test_mutation_same_host(self):
        """Type-9 logon on the SAME host as LSASS access → MUST NOT fire (local re-auth, not lateral)."""
        base = _WORK_HOURS
        events = [
            self._lsass_access(base, host="HOST-A"),
            self._lateral_logon("attacker", base + timedelta(minutes=5),
                                host="HOST-A", logon_type="9"),
        ]
        assert not _fired(events, "lsass_pth_correlation"), (
            "lsass_pth_correlation incorrectly fired when lsass access and logon are on the same host"
        )

    def test_mutation_benign_access_mask(self):
        """EID 10 with benign GrantedAccess 0x1000 (read-only query) → MUST NOT fire."""
        base = _WORK_HOURS
        events = [
            self._lsass_access(base, host="HOST-A", ga="0x1000"),
            self._lateral_logon("attacker", base + timedelta(minutes=5),
                                host="HOST-B", logon_type="9"),
        ]
        assert not _fired(events, "lsass_pth_correlation"), (
            "lsass_pth_correlation incorrectly fired on benign GrantedAccess 0x1000 "
            "(PROCESS_QUERY_LIMITED_INFORMATION — read-only)"
        )

    def test_mutation_beyond_time_window(self):
        """Type-9 logon occurs PTT_LOOKBACK_MIN + 10 min after LSASS access → MUST NOT fire."""
        base = _WORK_HOURS
        events = [
            self._lsass_access(base, host="HOST-A"),
            self._lateral_logon("attacker", base + timedelta(minutes=PTT_LOOKBACK_MIN + 10),
                                host="HOST-B", logon_type="9"),
        ]
        assert not _fired(events, "lsass_pth_correlation"), (
            f"lsass_pth_correlation fired on Type-9 logon >{PTT_LOOKBACK_MIN} min after lsass access"
        )


# ── 8. Pass-the-Ticket ────────────────────────────────────────────────────────

class TestPassTheTicket:
    """pass_the_ticket fires on EID 4769 RC4 (0x17) for lateral service + no EID 4768 in PTT_LOOKBACK_MIN."""

    def _tgs(self, user: str, ts: datetime, enc: str = "0x17",
             svc: str = "cifs/fileserver.corp.local") -> ForensicEvent:
        return _ev(user, ts, "4769",
                   desc=f"A Kerberos service ticket was requested. Account Name: {user}. "
                        f"Service Name: {svc}. Ticket Encryption Type: {enc}.")

    def _tgt(self, user: str, ts: datetime) -> ForensicEvent:
        return _ev(user, ts, "4768",
                   desc=f"A Kerberos authentication ticket (TGT) was requested. Account Name: {user}.")

    def test_positive_rc4_no_tgt(self):
        """EID 4769 RC4 (0x17) for cifs/ service with no prior EID 4768 → fires."""
        events = [self._tgs("attacker", _WORK_HOURS)]
        assert _fired(events, "pass_the_ticket"), (
            "Expected pass_the_ticket: RC4 TGS for lateral service with no TGT"
        )

    def test_mutation_tgt_present_within_window(self):
        """Same RC4 TGS + EID 4768 (TGT) within PTT_LOOKBACK_MIN → MUST NOT fire."""
        base = _WORK_HOURS
        events = [
            self._tgt("user1", base - timedelta(minutes=PTT_LOOKBACK_MIN - 5)),
            self._tgs("user1", base),
        ]
        assert not _fired(events, "pass_the_ticket"), (
            "pass_the_ticket incorrectly fired when a TGT is present within the lookback window"
        )

    def test_mutation_aes_encryption_not_rc4(self):
        """EID 4769 with AES256 (0x12) for cifs/ service, no TGT → MUST NOT fire (not RC4)."""
        events = [self._tgs("attacker", _WORK_HOURS, enc="0x12")]
        assert not _fired(events, "pass_the_ticket"), (
            "pass_the_ticket incorrectly fired on AES256-encrypted TGS (0x12) — "
            "rule specifically requires RC4 (0x17)"
        )

    def test_mutation_non_lateral_service(self):
        """EID 4769 RC4 for krbtgt (not a lateral service prefix) → MUST NOT fire."""
        events = [self._tgs("attacker", _WORK_HOURS, svc="krbtgt/corp.local")]
        assert not _fired(events, "pass_the_ticket"), (
            "pass_the_ticket incorrectly fired on krbtgt TGS — "
            "rule targets lateral-move service prefixes (cifs/, host/, rpcss/, http/)"
        )

    def test_mutation_machine_account(self):
        """Machine account (user$) RC4 TGS → MUST NOT fire (machine Kerberos is normal)."""
        events = [self._tgs("WORKSTATION01$", _WORK_HOURS)]
        assert not _fired(events, "pass_the_ticket"), (
            "pass_the_ticket incorrectly fired on machine account (user$) RC4 TGS"
        )


# ── 9. RDP Lateral Movement ───────────────────────────────────────────────────

class TestRdpLateralMovement:
    """rdp_lateral_movement fires on ≥RDP_LATERAL_HOST_THRESHOLD Type-10 logons in 30 min."""

    def _rdp_logon(self, user: str, ts: datetime, host: str) -> ForensicEvent:
        return _ev(user, ts, "4624", host=host,
                   desc=f"Account logged on. Account Name: {user}. Logon Type: 10.")

    def test_positive_at_threshold(self):
        """RDP_LATERAL_HOST_THRESHOLD Type-10 logons to distinct hosts → fires."""
        base = _WORK_HOURS
        hosts = [f"TARGET-{i:02d}" for i in range(RDP_LATERAL_HOST_THRESHOLD)]
        events = [
            self._rdp_logon("attacker", base + timedelta(minutes=i * 2), h)
            for i, h in enumerate(hosts)
        ]
        assert _fired(events, "rdp_lateral_movement"), (
            f"Expected rdp_lateral_movement on {RDP_LATERAL_HOST_THRESHOLD} Type-10 logons"
        )

    def test_mutation_one_below_threshold(self):
        """RDP_LATERAL_HOST_THRESHOLD − 1 distinct hosts → MUST NOT fire."""
        base = _WORK_HOURS
        hosts = [f"TARGET-{i:02d}" for i in range(RDP_LATERAL_HOST_THRESHOLD - 1)]
        events = [
            self._rdp_logon("attacker", base + timedelta(minutes=i * 2), h)
            for i, h in enumerate(hosts)
        ]
        assert not _fired(events, "rdp_lateral_movement"), (
            f"rdp_lateral_movement fired on {RDP_LATERAL_HOST_THRESHOLD - 1} hosts "
            f"(one below threshold {RDP_LATERAL_HOST_THRESHOLD})"
        )

    def test_mutation_type3_not_rdp(self):
        """Type-3 (network) logons to RDP_LATERAL_HOST_THRESHOLD hosts → MUST NOT fire for RDP rule."""
        base = _WORK_HOURS
        events = [
            _ev("attacker", base + timedelta(minutes=i), "4624", host=f"TARGET-{i:02d}",
                desc=f"Account logged on. Account Name: attacker. Logon Type: 3.")
            for i in range(RDP_LATERAL_HOST_THRESHOLD)
        ]
        assert not _fired(events, "rdp_lateral_movement"), (
            "rdp_lateral_movement incorrectly fired on Type-3 (SMB) logons — rule requires Type 10 (RDP)"
        )


# ── 10. Case Canonicalization ─────────────────────────────────────────────────

class TestCaseCanonicalization:
    """Rules must fire regardless of tool-name capitalisation in the description."""

    def test_vssadmin_uppercase_fires(self):
        """VSSADMIN.EXE DELETE SHADOWS (all-caps path) → must still fire ransomware check."""
        events = [_ev("attacker", _WORK_HOURS, "4688",
                      desc="New process. VSSADMIN.EXE DELETE SHADOWS /ALL /QUIET")]
        assert _fired(events, "shadow_copy_deletion"), (
            "shadow_copy_deletion missed all-caps VSSADMIN.EXE DELETE SHADOWS"
        )

    def test_mimikatz_mixed_case_fires(self):
        """Mimikatz.exe SekuRlsa::LogonPasswords (mixed case) → must fire mimikatz_invocation."""
        events = [_ev("attacker", _WORK_HOURS, "4688",
                      desc="New process. Image: C:\\Tools\\Mimikatz.exe. "
                           "CommandLine: Mimikatz.exe sekuRlsa::LogonPasswords")]
        assert _fired(events, "mimikatz_invocation"), (
            "mimikatz_invocation missed mixed-case sekuRlsa::LogonPasswords"
        )

    def test_encoded_powershell_case_invariant(self):
        """powershell.EXE -EnCoDeDcOmMaNd (mixed-case flag) + long b64 → must fire encoded_powershell."""
        _LONG_B64 = "JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdA"
        events = [_ev("attacker", _WORK_HOURS, "4688",
                      desc=f"New process. Image: powershell.EXE. "
                           f"CommandLine: powershell.EXE -EnCoDeDcOmMaNd {_LONG_B64}")]
        assert _fired(events, "encoded_powershell"), (
            "encoded_powershell missed mixed-case -EnCoDeDcOmMaNd flag with long base64 payload"
        )


# ── 11. Noise Tolerance ───────────────────────────────────────────────────────

class TestNoiseTolerance:
    """Attack rules fire even when attack events are mixed with benign noise."""

    def _noise(self, count: int = 80) -> list[ForensicEvent]:
        """Benign EID 4688 process-creation events filling the event stream."""
        return [
            _ev("user01", _WORK_HOURS + timedelta(seconds=i * 5), "4688",
                desc=f"New process. Image: C:\\Windows\\explorer.exe. CommandLine: explorer.exe")
            for i in range(count)
        ]

    def test_ransomware_triad_fires_amid_noise(self):
        """80 benign EID 4688 events + ransomware triad → must still fire."""
        triad = [
            _ev("attacker", _WORK_HOURS + timedelta(minutes=1), "4688",
                desc="New process. vssadmin delete shadows /all /quiet"),
            _ev("attacker", _WORK_HOURS + timedelta(minutes=3), "4688",
                desc="New process. bcdedit /set {default} recoveryenabled no"),
            _ev("attacker", _WORK_HOURS + timedelta(minutes=5), "4688",
                desc="New process. wbadmin delete catalog -quiet"),
        ]
        assert _fired(self._noise() + triad, "ransomware_recovery_destruction"), (
            "ransomware_recovery_destruction failed to fire when attack events were"
            " mixed with 80 benign events"
        )

    def test_kerberoast_fires_amid_normal_tgs(self):
        """30 normal AES TGS (0x12) + 20 RC4 TGS (0x17) in 8 min → spike fires."""
        base = _WORK_HOURS
        normal_tgs = [
            _ev("itadmin01", base + timedelta(minutes=i), "4769",
                desc=f"Kerberos ticket requested. Account Name: itadmin01. "
                     f"Service Name: cifs/FILE-SERVER-{i:02d}. Ticket Encryption Type: 0x12.")
            for i in range(30)
        ]
        attack_tgs = [
            _ev("attacker", base + timedelta(seconds=i * 20), "4769",
                desc=f"Kerberos ticket requested. Account Name: attacker. "
                     f"Service Name: svc_{i:03d}. Ticket Encryption Type: 0x17.")
            for i in range(KERB_TICKET_THRESHOLD)
        ]
        assert _fired(normal_tgs + attack_tgs, "kerberos_ticket_spike"), (
            "kerberos_ticket_spike failed to fire when attack TGS were mixed with "
            "30 benign AES TGS requests"
        )

    def test_smb_lateral_fires_amid_normal_logons(self):
        """20 benign Type-2 logons + SMB_LATERAL_HOST_THRESHOLD Type-3 to distinct hosts → fires."""
        base = _WORK_HOURS
        normal_logons = [
            _ev("user01", base + timedelta(minutes=i), "4624", host="WORKSTATION-01",
                desc=f"Account logged on. Account Name: user01. Logon Type: 2.")
            for i in range(20)
        ]
        lateral = [
            _ev("attacker", base + timedelta(minutes=i * 3), "4624", host=f"TARGET-{i:02d}",
                desc=f"Account logged on. Account Name: attacker. Logon Type: 3.")
            for i in range(SMB_LATERAL_HOST_THRESHOLD)
        ]
        assert _fired(normal_logons + lateral, "smb_lateral_movement"), (
            "smb_lateral_movement failed to fire when lateral logons were mixed with "
            "20 benign Type-2 logons"
        )


# ── 12. Cross-User Isolation ──────────────────────────────────────────────────

class TestCrossUserIsolation:
    """An attack by user A must not implicate user B in the same event stream."""

    def test_auth_burst_isolated_per_user(self):
        """User A hits auth burst threshold; user B has exactly 1 failure → only A flagged."""
        base = _WORK_HOURS
        attacker_failures = [
            _ev("attacker", base + timedelta(seconds=i * 30), "4625",
                desc="Account failed to log on. Account Name: attacker. Failure Reason: Bad password.")
            for i in range(AUTH_FAIL_THRESHOLD)
        ]
        innocent_failure = [
            _ev("alice", base + timedelta(minutes=1), "4625",
                desc="Account failed to log on. Account Name: alice. Failure Reason: Bad password.")
        ]
        result = analyze_behavior(attacker_failures + innocent_failure)
        fired_entities = {a["entity"] for a in result["anomalies"]
                         if a["anomaly_type"] == "auth_failure_burst"}
        assert "attacker" in fired_entities, "auth_failure_burst did not fire for attacker"
        assert "alice" not in fired_entities, (
            "auth_failure_burst incorrectly implicated alice (1 failure) due to attacker's burst"
        )

    def test_smb_lateral_isolated_per_user(self):
        """Attacker reaches SMB_LATERAL_HOST_THRESHOLD Type-3 logons; IT admin has 2 → only attacker flagged."""
        base = _WORK_HOURS
        lateral = [
            _ev("attacker", base + timedelta(minutes=i * 3), "4624", host=f"TARGET-{i:02d}",
                desc="Account logged on. Account Name: attacker. Logon Type: 3.")
            for i in range(SMB_LATERAL_HOST_THRESHOLD)
        ]
        admin_logons = [
            _ev("itadmin01", base + timedelta(minutes=i * 10), "4624", host=f"SRV-{i:02d}",
                desc="Account logged on. Account Name: itadmin01. Logon Type: 3.")
            for i in range(SMB_LATERAL_HOST_THRESHOLD - 1)
        ]
        result = analyze_behavior(lateral + admin_logons)
        fired_entities = {a["entity"] for a in result["anomalies"]
                         if a["anomaly_type"] == "smb_lateral_movement"}
        assert "attacker" in fired_entities, "smb_lateral_movement did not fire for attacker"
        assert "itadmin01" not in fired_entities, (
            "smb_lateral_movement incorrectly flagged itadmin01 who had "
            f"{SMB_LATERAL_HOST_THRESHOLD - 1} Type-3 logons (below threshold)"
        )


# ── 13. False-Positive Evasion Guards ────────────────────────────────────────

class TestFalsePositiveGuards:
    """Near-miss patterns that look like attacks but must NOT fire — guard against overly broad predicates."""

    def test_vssadmin_list_must_not_fire(self):
        """'vssadmin list shadows' (reconnaissance, not destruction) → MUST NOT fire ransomware check."""
        events = [_ev("sysadmin", _WORK_HOURS, "4688",
                      desc="New process. vssadmin list shadows /for=C:")]
        assert not _fired(events, "ransomware_recovery_destruction"), (
            "ransomware_recovery_destruction incorrectly fired on 'vssadmin list shadows' "
            "(reconnaissance command — no 'delete')"
        )

    def test_bcdedit_enable_recovery_must_not_fire(self):
        """'bcdedit /set {default} recoveryenabled yes' (remediation) → MUST NOT fire."""
        events = [_ev("sysadmin", _WORK_HOURS, "4688",
                      desc="New process. bcdedit /set {default} recoveryenabled yes")]
        assert not _fired(events, "ransomware_recovery_destruction"), (
            "ransomware_recovery_destruction incorrectly fired on 'recoveryenabled yes' "
            "(this ENABLES recovery — the opposite of ransomware behavior)"
        )

    def test_smb_machine_account_lateral_must_not_fire(self):
        """DC01$ (machine account) performing Type-3 logons to multiple hosts → MUST NOT fire."""
        base = _WORK_HOURS
        events = [
            _ev("DC01$", base + timedelta(minutes=i), "4624", host=f"TARGET-{i:02d}",
                desc="Account logged on. Account Name: DC01$. Logon Type: 3.")
            for i in range(SMB_LATERAL_HOST_THRESHOLD + 2)
        ]
        assert not _fired(events, "smb_lateral_movement"), (
            "smb_lateral_movement incorrectly fired on machine account DC01$ — "
            "DC replication and service auth use Type-3 legitimately"
        )

    def test_vssadmin_create_shadow_must_not_fire(self):
        """'vssadmin create shadow /for=C:' (creating a backup) → MUST NOT fire."""
        events = [_ev("backup_svc", _WORK_HOURS, "4688",
                      desc="New process. vssadmin create shadow /for=C:")]
        assert not _fired(events, "ransomware_recovery_destruction"), (
            "ransomware_recovery_destruction incorrectly fired on 'vssadmin create shadow' "
            "(backup operation — no 'delete' keyword)"
        )

    def test_bcdedit_enum_must_not_fire(self):
        """'bcdedit /enum all' (listing boot config, no modification) → MUST NOT fire."""
        events = [_ev("sysadmin", _WORK_HOURS, "4688",
                      desc="New process. bcdedit /enum all")]
        assert not _fired(events, "ransomware_recovery_destruction"), (
            "ransomware_recovery_destruction incorrectly fired on 'bcdedit /enum all' "
            "(enumeration command, not a boot-config modification)"
        )


class TestGoldenTicketPrecision:
    """
    Verify golden_ticket does NOT fire on Kerberoasting RC4 TGS bursts.

    Root cause of the original bug: Ticket Options 0x40810000 (forwardable|renewable|
    canonicalize) appeared in _GOLDEN_TICKET_OPTIONS, but this bitmask is a standard
    option set for all Kerberoasting TGS requests — not a Golden Ticket indicator.
    Fix: removed options-based detection; only anomalous ticket lifetime (>600 min)
    triggers golden_ticket now.
    """

    def _kerb_ev(self, svc: str, offset_sec: int = 0) -> ForensicEvent:
        ts = _WORK_HOURS + timedelta(seconds=offset_sec)
        return _ev(
            "attacker",
            ts,
            "4769",
            desc=(
                f"A Kerberos service ticket was requested. Account Name: attacker. "
                f"Service Name: {svc}. Ticket Options: 0x40810000. "
                f"Ticket Encryption Type: 0x17."
            ),
        )

    def test_kerberoasting_burst_must_not_fire_golden_ticket(self):
        """21 RC4 EID 4769 with options=0x40810000 → kerberos_ticket_spike YES, golden_ticket NO."""
        services = [f"cifs/HOST-{i:02d}.corp.local" for i in range(21)]
        events = [self._kerb_ev(svc, i * 15) for i, svc in enumerate(services)]
        assert _fired(events, "kerberos_ticket_spike"), (
            "kerberos_ticket_spike must fire on 21 RC4 TGS requests in 5 min"
        )
        assert not _fired(events, "golden_ticket"), (
            "golden_ticket incorrectly fired on Kerberoasting burst — "
            "Ticket Options 0x40810000 is a normal TGS option set, not a Golden Ticket indicator"
        )

    def test_anomalous_lifetime_fires_golden_ticket(self):
        """RC4 TGS with ticket_lifetime=700 min (>600 threshold) → golden_ticket fires."""
        ev = ForensicEvent(
            timestamp=_WORK_HOURS,
            event_type="Security",
            source_host="HOST-A",
            user="attacker",
            description=(
                "A Kerberos service ticket was requested. Service Name: cifs/server.corp.local. "
                "Ticket Encryption Type: 0x17. Ticket Lifetime: 700."
            ),
            raw_source=RawSource.GENERIC,
            event_id="4769",
            extra=None,
        )
        assert _fired([ev], "golden_ticket"), (
            "golden_ticket must fire when ticket lifetime exceeds 600 minutes"
        )
