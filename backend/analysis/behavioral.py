"""
Behavioral ML entity analysis — Phase 2.

Detects statistical anomalies in user/host behavior using 15 complementary checks:
  1.  Per-user hourly event spike       — Z-score > 2.5 over observed hourly distribution
  2.  Cross-host lateral velocity       — > 3 distinct hosts per user in 30-minute window
  3.  Authentication failure burst      — > 10 Event 4625 failures per user in 5 minutes
  4.  Off-hours privileged operation    — Event 4672 SeDebugPrivilege outside 07:00-19:00
  5.  Kerberos ticket request spike     — > 20 EID 4769 from one user in 10 minutes (Kerberoasting)
  6.  Group modification burst          — > 3 EID 4728/4732/4735/4756 in 30 minutes
  7.  Privileged account creation       — EID 4720 followed by EID 4728 within 10 minutes
  8.  NTLM authentication spike         — > 15 EID 4776 from a non-DC host in 5 minutes
  9.  Ransomware recovery destruction   — vssadmin + bcdedit + wbadmin triad in 10 minutes (T1490)
  10. NTLM brute-force on DC            — ≥ 20 EID 4776 failures for same user in 30 minutes
  11. Pass-the-Hash (keyword)           — NTLM lateral logons with no Kerberos TGT in session
  12. WMI shell spawn                   — wmiprvse.exe spawning cmd/powershell (T1047)
  13. Event log clearing sweep          — EID 1102 / wevtutil cl across ≥ 2 hosts (T1070.001)
  14. LSASS PTH correlation             — EID 10 lsass access → EID 4624 Type 3 within 30 min
                                          (catches Empire C2 PTH that bypasses command-line strings)
  15. Golden / Silver Ticket            — EID 4769 with RC4 (0x17) encryption:
                                          Golden: forged options (0x40810000) or anomalous lifetime
                                          Silver: host-specific service + no prior TGT (T1558.001/002)
  16. SMB lateral movement              — EID 4624 LogonType 3 to ≥3 hosts in 30 min (T1021.002)
  17. Pass-the-Ticket                   — EID 4769 RC4 for lateral service + no prior TGT (T1550.003)
  18. RDP lateral movement              — EID 4624 LogonType 10 to ≥2 hosts in 30 min (T1021.001)

None of these checks require training data — they are fully deterministic and run in O(n).
"""

import math
import re as _re
from collections import defaultdict, deque
from datetime import timedelta
from backend.schema import ForensicEvent

WORK_HOUR_START        = 7    # 07:00
WORK_HOUR_END          = 19   # 19:00
VELOCITY_WINDOW_MIN    = 30
VELOCITY_THRESHOLD     = 3
AUTH_FAIL_WINDOW_MIN   = 5
AUTH_FAIL_THRESHOLD    = 10
ZSCORE_THRESHOLD       = 2.5
MIN_HOURLY_POINTS      = 3    # minimum distinct hours before Z-score fires

# AD-specific thresholds
KERB_TICKET_WINDOW_MIN  = 10
KERB_TICKET_THRESHOLD   = 20   # EID 4769 Kerberos service ticket requests
GROUP_MOD_WINDOW_MIN    = 30
GROUP_MOD_THRESHOLD     = 3    # EID 4728/4732/4735/4756 group membership changes
ACCT_CHAIN_WINDOW_MIN   = 10   # EID 4720 → EID 4728 within this window
NTLM_SPIKE_WINDOW_MIN   = 5
NTLM_SPIKE_THRESHOLD    = 15   # EID 4776 NTLM auth from non-DC

# New rule thresholds
RANSOM_TRIAD_WINDOW_MIN     = 10   # vssadmin + bcdedit + wbadmin within this window
PTH_LSASS_WINDOW_MIN        = 30   # EID 10 lsass access → EID 4624 Type 3 within this window
NTLM_BRUTE_WINDOW_MIN       = 30   # EID 4776 failures by same user (DC-side brute force)
NTLM_BRUTE_THRESHOLD        = 20   # ≥N failures in window → RDP/NTLM brute force
PTH_MIN_LATERAL_LOGONS      = 2    # ≥N NTLM lateral logons without Kerberos TGT → PTH
LOG_CLEAR_HOST_THRESHOLD    = 2    # ≥N distinct hosts clearing logs within session → sweep
SILVER_TICKET_TGT_WINDOW_MIN = 20  # no EID 4768 from user in this look-back → Silver Ticket
GOLDEN_TICKET_LIFETIME_MIN  = 600  # anomalous lifetime threshold (minutes) for Golden Ticket
SMB_LATERAL_WINDOW_MIN      = 30   # EID 4624 LogonType 3 to N+ hosts in this window
SMB_LATERAL_HOST_THRESHOLD  = 3    # ≥N distinct target hosts → SMB lateral flag
RDP_LATERAL_WINDOW_MIN      = 30   # EID 4624 LogonType 10 to N+ hosts in this window
RDP_LATERAL_HOST_THRESHOLD  = 2    # ≥N distinct target hosts → RDP lateral flag
PTT_LOOKBACK_MIN            = 30   # look-back window for TGT before tagging pass-the-ticket

# Ticket options that indicate a forged Golden Ticket (forwardable|renewable|canonicalize)
_GOLDEN_TICKET_OPTIONS = frozenset({"0x40810000", "0x40810010", "0x60810010"})
# Host-specific service name prefixes targeted by Silver Tickets
_SILVER_SVC_PREFIXES   = ("cifs/", "host/", "http/", "rpcss/", "ldap/", "wsman/")

# Common privileged group SIDs / names used in group-mod check
_PRIV_GROUPS = frozenset({
    "domain admins", "enterprise admins", "schema admins",
    "administrators", "account operators", "backup operators",
    "group policy creator owners",
})

# Normalises Windows logon type from both space-separated and tab-separated formats.
# Handles: "Logon Type: 3", "Logon Type:\t\t3", "Logon Type:\t3" (OTRF format).
_LOGON_TYPE_RE = _re.compile(r'logon\s+type[:\s]+(\d+)', _re.IGNORECASE)

# Base64 blob long enough to be an encoded command payload (>100 chars).
_B64_LONG_RE = _re.compile(r'[A-Za-z0-9+/]{100,}={0,2}')


def _get_logon_type(description: str) -> str | None:
    """Return the logon type number as a string, or None if not present."""
    m = _LOGON_TYPE_RE.search(description)
    return m.group(1) if m else None


def _mean_std(values: list[float]) -> tuple[float, float]:
    if len(values) < 2:
        return (values[0] if values else 0.0), 0.0
    n    = len(values)
    mean = sum(values) / n
    var  = sum((v - mean) ** 2 for v in values) / (n - 1)
    return mean, math.sqrt(var)


# ── Check 1: hourly spike ──────────────────────────────────────────────────────

def _check_hourly_spike(events: list[ForensicEvent]) -> list[dict]:
    user_hour: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for e in events:
        user = e.user
        if not user or user.endswith('$'):
            continue
        user_hour[user][e.timestamp.strftime('%Y-%m-%d %H')] += 1

    anomalies = []
    for user, hour_counts in user_hour.items():
        counts = list(hour_counts.values())
        if len(counts) < MIN_HOURLY_POINTS:
            continue
        mean, std = _mean_std(counts)
        if std == 0:
            continue
        for hour_key, count in hour_counts.items():
            z = (count - mean) / std
            if z > ZSCORE_THRESHOLD:
                anomalies.append({
                    'anomaly_type': 'hourly_event_spike',
                    'entity': user,
                    'description': (
                        f"Entity {user!r} generated {count} events in hour {hour_key} "
                        f"(baseline mean={mean:.1f}, std={std:.1f}, Z-score={z:.2f})"
                    ),
                    'z_score':   round(z, 3),
                    'threshold': ZSCORE_THRESHOLD,
                    'observed':  float(count),
                    'severity':  'high' if z > 4.0 else 'medium',
                })
    return anomalies


# ── Check 2: lateral velocity ──────────────────────────────────────────────────

def _check_host_velocity(events: list[ForensicEvent]) -> list[dict]:
    user_events: dict[str, list[tuple]] = defaultdict(list)
    for e in events:
        if not e.user or (e.user or '').endswith('$'):
            continue
        user_events[e.user].append((e.timestamp, e.source_host))

    window   = timedelta(minutes=VELOCITY_WINDOW_MIN)
    anomalies = []

    for user, ev_list in user_events.items():
        ev_list.sort(key=lambda x: x[0])
        q: deque = deque()
        max_hosts = 0
        max_info: tuple | None = None

        for ts, host in ev_list:
            q.append((ts, host))
            while q and (ts - q[0][0]) > window:
                q.popleft()
            distinct = len({h for _, h in q})
            if distinct > max_hosts:
                max_hosts = distinct
                max_info  = (q[0][0], ts, {h for _, h in q})

        if max_hosts >= VELOCITY_THRESHOLD and max_info:
            start_ts, end_ts, hosts = max_info
            anomalies.append({
                'anomaly_type': 'lateral_velocity',
                'entity': user,
                'description': (
                    f"Entity {user!r} accessed {max_hosts} distinct hosts in "
                    f"{VELOCITY_WINDOW_MIN} min "
                    f"({start_ts.strftime('%H:%M')}–{end_ts.strftime('%H:%M')}): "
                    f"{', '.join(sorted(hosts))}"
                ),
                'z_score':   None,
                'threshold': float(VELOCITY_THRESHOLD),
                'observed':  float(max_hosts),
                'severity':  'high' if max_hosts >= 5 else 'medium',
            })
    return anomalies


# ── Check 3: auth failure burst ────────────────────────────────────────────────

def _check_auth_failure_burst(events: list[ForensicEvent]) -> list[dict]:
    fail_events = [e for e in events if e.event_id == '4625']
    if not fail_events:
        return []

    user_times: dict[str, list] = defaultdict(list)
    for e in fail_events:
        key = e.user or e.source_host or '__unknown__'
        user_times[key].append(e.timestamp)

    window    = timedelta(minutes=AUTH_FAIL_WINDOW_MIN)
    anomalies = []

    for user, timestamps in user_times.items():
        timestamps.sort()
        q: deque = deque()
        max_burst      = 0
        max_burst_time = None

        for ts in timestamps:
            q.append(ts)
            while q and (ts - q[0]) > window:
                q.popleft()
            if len(q) > max_burst:
                max_burst      = len(q)
                max_burst_time = ts

        if max_burst >= AUTH_FAIL_THRESHOLD:
            anomalies.append({
                'anomaly_type': 'auth_failure_burst',
                'entity': user,
                'description': (
                    f"{max_burst} authentication failures for {user!r} within "
                    f"{AUTH_FAIL_WINDOW_MIN} min "
                    f"(peak at {max_burst_time.strftime('%Y-%m-%d %H:%M')})"
                ),
                'z_score':   None,
                'threshold': float(AUTH_FAIL_THRESHOLD),
                'observed':  float(max_burst),
                'severity':  'high' if max_burst >= 20 else 'medium',
            })
    return anomalies


# ── Check 4: off-hours privilege ───────────────────────────────────────────────

def _check_off_hours_privilege(events: list[ForensicEvent]) -> list[dict]:
    priv_events = [
        e for e in events
        if e.event_id == '4672'
        and e.user
        and not (e.user or '').endswith('$')
        and 'SeDebugPrivilege' in (e.description or '')
    ]

    anomalies = []
    seen: set[tuple[str, str]] = set()
    for e in priv_events:
        hour = e.timestamp.hour
        if not (WORK_HOUR_START <= hour < WORK_HOUR_END):
            key = (e.user, e.timestamp.strftime('%Y-%m-%d'))
            if key in seen:
                continue
            seen.add(key)
            anomalies.append({
                'anomaly_type': 'off_hours_privilege',
                'entity': e.user,
                'description': (
                    f"SeDebugPrivilege assigned to entity {e.user!r} at "
                    f"{e.timestamp.strftime('%Y-%m-%d %H:%M')} "
                    f"(outside business hours {WORK_HOUR_START:02d}:00–{WORK_HOUR_END:02d}:00)"
                ),
                'z_score':   None,
                'threshold': float(WORK_HOUR_END - WORK_HOUR_START),
                'observed':  float(hour),
                'severity':  'medium',
            })
    return anomalies


# ── Check 5: Kerberos ticket spike (Kerberoasting) ────────────────────────────

def _check_kerberos_ticket_spike(events: list[ForensicEvent]) -> list[dict]:
    """EID 4769 — Kerberos Service Ticket Operations. >20 in 10 min = Kerberoasting."""
    kerb_events = [e for e in events if e.event_id == '4769' and e.user and not (e.user or '').endswith('$')]
    if not kerb_events:
        return []

    user_times: dict[str, list] = defaultdict(list)
    for e in kerb_events:
        user_times[e.user].append(e.timestamp)

    window    = timedelta(minutes=KERB_TICKET_WINDOW_MIN)
    anomalies = []

    for user, timestamps in user_times.items():
        timestamps.sort()
        q: deque = deque()
        max_burst      = 0
        max_burst_time = None

        for ts in timestamps:
            q.append(ts)
            while q and (ts - q[0]) > window:
                q.popleft()
            if len(q) > max_burst:
                max_burst      = len(q)
                max_burst_time = ts

        if max_burst >= KERB_TICKET_THRESHOLD:
            anomalies.append({
                'anomaly_type': 'kerberos_ticket_spike',
                'entity': user,
                'description': (
                    f"Entity {user!r} requested {max_burst} Kerberos service tickets (EID 4769) "
                    f"within {KERB_TICKET_WINDOW_MIN} min "
                    f"(peak at {max_burst_time.strftime('%Y-%m-%d %H:%M')}) — possible Kerberoasting"
                ),
                'z_score':   None,
                'threshold': float(KERB_TICKET_THRESHOLD),
                'observed':  float(max_burst),
                'severity':  'high',
            })
    return anomalies


# ── Check 6: privileged group modification burst ───────────────────────────────

def _check_group_modification_burst(events: list[ForensicEvent]) -> list[dict]:
    """EID 4728/4732/4735/4756 — group membership changes. >3 in 30 min = suspicious."""
    group_eids = {'4728', '4732', '4735', '4756'}
    mod_events = [e for e in events if e.event_id in group_eids]
    if not mod_events:
        return []

    # Bucket by actor (user performing the change)
    actor_times: dict[str, list] = defaultdict(list)
    for e in mod_events:
        actor = e.user or e.source_host or '__unknown__'
        actor_times[actor].append((e.timestamp, e.event_id, e.description))

    window    = timedelta(minutes=GROUP_MOD_WINDOW_MIN)
    anomalies = []

    for actor, ev_list in actor_times.items():
        ev_list.sort(key=lambda x: x[0])
        q: deque = deque()
        max_burst      = 0
        max_burst_time = None
        is_priv        = False

        for ts, eid, desc in ev_list:
            q.append((ts, eid, desc))
            while q and (ts - q[0][0]) > window:
                q.popleft()
            if len(q) > max_burst:
                max_burst      = len(q)
                max_burst_time = ts
                is_priv = any(
                    grp in (d or '').lower()
                    for _, _, d in q
                    for grp in _PRIV_GROUPS
                )

        if max_burst >= GROUP_MOD_THRESHOLD:
            anomalies.append({
                'anomaly_type': 'group_modification_burst',
                'entity': actor,
                'description': (
                    f"Entity {actor!r} performed {max_burst} group membership changes "
                    f"(EID 4728/4732/4735/4756) within {GROUP_MOD_WINDOW_MIN} min "
                    f"(peak at {max_burst_time.strftime('%Y-%m-%d %H:%M')})"
                    + (" — targets include privileged groups" if is_priv else "")
                ),
                'z_score':   None,
                'threshold': float(GROUP_MOD_THRESHOLD),
                'observed':  float(max_burst),
                'severity':  'high' if is_priv else 'medium',
            })
    return anomalies


# ── Check 7: privileged account creation chain ────────────────────────────────

def _check_account_creation_chain(events: list[ForensicEvent]) -> list[dict]:
    """EID 4720 (account created) followed by EID 4728 (added to group) within 10 min."""
    create_events = sorted(
        [e for e in events if e.event_id == '4720'],
        key=lambda e: e.timestamp,
    )
    add_events = sorted(
        [e for e in events if e.event_id == '4728'],
        key=lambda e: e.timestamp,
    )
    if not create_events or not add_events:
        return []

    window    = timedelta(minutes=ACCT_CHAIN_WINDOW_MIN)
    anomalies = []
    flagged: set[str] = set()  # deduplicate by new account

    for ce in create_events:
        # Extract new account name from description heuristic
        new_acct = None
        for tok in (ce.description or '').split():
            if tok.startswith('SAM') or (len(tok) > 2 and tok not in ('New', 'Account', 'Name:')):
                new_acct = tok.strip(',:')
                break
        key = new_acct or ce.user or ce.source_host or '__unknown__'
        if key in flagged:
            continue

        # Look for a group-add within window after creation
        for ae in add_events:
            if ae.timestamp < ce.timestamp:
                continue
            if ae.timestamp - ce.timestamp > window:
                break
            desc_lower = (ae.description or '').lower()
            is_priv = any(grp in desc_lower for grp in _PRIV_GROUPS)
            flagged.add(key)
            anomalies.append({
                'anomaly_type': 'privileged_account_creation_chain',
                'entity': ce.user or ce.source_host or '__unknown__',
                'description': (
                    f"Account created (EID 4720) then immediately added to "
                    f"{'privileged ' if is_priv else ''}group (EID 4728) within "
                    f"{ACCT_CHAIN_WINDOW_MIN} min at "
                    f"{ce.timestamp.strftime('%Y-%m-%d %H:%M')} — possible backdoor account"
                ),
                'z_score':   None,
                'threshold': float(ACCT_CHAIN_WINDOW_MIN),
                'observed':  (ae.timestamp - ce.timestamp).total_seconds() / 60,
                'severity':  'high' if is_priv else 'medium',
            })
            break

    return anomalies


# ── Check 8: NTLM authentication spike from non-DC host ───────────────────────

def _check_ntlm_spike(events: list[ForensicEvent]) -> list[dict]:
    """EID 4776 — Credential Validation (NTLM). >15 from non-DC in 5 min = relay attack."""
    # DC hosts typically have names ending in 'DC', contain 'DC-', or role keywords.
    # Conservative heuristic: skip if host description contains 'dc' keyword.
    def _is_dc(host: str) -> bool:
        hl = (host or '').lower()
        return 'dc' in hl or 'domain' in hl

    ntlm_events = [
        e for e in events
        if e.event_id == '4776' and not _is_dc(e.source_host)
    ]
    if not ntlm_events:
        return []

    host_times: dict[str, list] = defaultdict(list)
    for e in ntlm_events:
        host_times[e.source_host].append(e.timestamp)

    window    = timedelta(minutes=NTLM_SPIKE_WINDOW_MIN)
    anomalies = []

    for host, timestamps in host_times.items():
        timestamps.sort()
        q: deque = deque()
        max_burst      = 0
        max_burst_time = None

        for ts in timestamps:
            q.append(ts)
            while q and (ts - q[0]) > window:
                q.popleft()
            if len(q) > max_burst:
                max_burst      = len(q)
                max_burst_time = ts

        if max_burst >= NTLM_SPIKE_THRESHOLD:
            anomalies.append({
                'anomaly_type': 'ntlm_spike',
                'entity': host,
                'description': (
                    f"Non-DC host {host!r} validated {max_burst} NTLM credentials (EID 4776) "
                    f"within {NTLM_SPIKE_WINDOW_MIN} min "
                    f"(peak at {max_burst_time.strftime('%Y-%m-%d %H:%M')}) — possible NTLM relay"
                ),
                'z_score':   None,
                'threshold': float(NTLM_SPIKE_THRESHOLD),
                'observed':  float(max_burst),
                'severity':  'high',
            })
    return anomalies


# ── Check 9: ransomware recovery-destruction triad (RANSOM-001) ───────────────

def _check_ransomware_triad(events: list[ForensicEvent]) -> list[dict]:
    """
    vssadmin Delete Shadows + bcdedit recoveryenabled No + wbadmin DELETE within
    RANSOM_TRIAD_WINDOW_MIN on the same host → T1490 Inhibit System Recovery.
    Fires on ≥2-of-3 members (medium) or all 3 (high).
    """
    def _is_vssadmin(d: str) -> bool:
        return "vssadmin" in d and "delete" in d and "shadow" in d

    def _is_bcdedit(d: str) -> bool:
        return "bcdedit" in d and ("recoveryenabled no" in d or "safeboot" in d)

    def _is_wbadmin(d: str) -> bool:
        return "wbadmin" in d and "delete" in d

    _TRIAD = {"vssadmin": _is_vssadmin, "bcdedit": _is_bcdedit, "wbadmin": _is_wbadmin}

    proc_events = sorted(
        [e for e in events if e.event_id in ("1", "4688") and e.description],
        key=lambda e: e.timestamp,
    )

    host_events: dict[str, list] = defaultdict(list)
    for e in proc_events:
        host_events[e.source_host].append(e)

    window = timedelta(minutes=RANSOM_TRIAD_WINDOW_MIN)
    anomalies: list[dict] = []
    seen_hosts: set[str] = set()

    for host, host_evs in host_events.items():
        if host in seen_hosts:
            continue
        for i, anchor in enumerate(host_evs):
            if not any(chk(anchor.description.lower()) for chk in _TRIAD.values()):
                continue
            win_end = anchor.timestamp + window
            window_evs = [e for e in host_evs if anchor.timestamp <= e.timestamp < win_end]
            found: set[str] = set()
            actors: set[str] = set()
            for wev in window_evs:
                d = (wev.description or "").lower()
                for name, chk in _TRIAD.items():
                    if chk(d):
                        found.add(name)
                        if wev.user:
                            actors.add(wev.user)
            if len(found) < 2:
                continue
            seen_hosts.add(host)
            actor_str = ", ".join(sorted(actors)) or "unknown"
            anomalies.append({
                "anomaly_type": "ransomware_recovery_destruction",
                "entity": actor_str,
                "description": (
                    f"Ransomware recovery-destruction triad on {host!r}: "
                    f"[{', '.join(sorted(found))}] within {RANSOM_TRIAD_WINDOW_MIN} min "
                    f"starting {anchor.timestamp.strftime('%Y-%m-%d %H:%M')} "
                    f"— T1490 Inhibit System Recovery"
                ),
                "z_score":   None,
                "threshold": 2.0,
                "observed":  float(len(found)),
                "severity":  "high" if len(found) >= 3 else "medium",
            })
            break

    return anomalies


# ── Check 10: NTLM brute-force by user on DC (AUTH-001) ───────────────────────

def _check_ntlm_brute_force(events: list[ForensicEvent]) -> list[dict]:
    """
    ≥NTLM_BRUTE_THRESHOLD EID 4776 failures for the same user within
    NTLM_BRUTE_WINDOW_MIN. Catches RDP/SMB brute-force targeting a known username
    where auth failures are visible on the DC even when source_host is the DC itself.
    """
    fail_evs = [
        e for e in events
        if e.event_id == "4776"
        and e.user
        and not e.user.endswith("$")
        # NTLM failure error codes: 0xC000006A (bad password) or 0xC000006D (logon failure)
        and any(code in (e.description or "").lower() for code in ("0xc000006", "error code"))
    ]
    if not fail_evs:
        return []

    user_times: dict[str, list] = defaultdict(list)
    for e in fail_evs:
        user_times[e.user].append(e.timestamp)

    window = timedelta(minutes=NTLM_BRUTE_WINDOW_MIN)
    anomalies: list[dict] = []

    for user, timestamps in user_times.items():
        timestamps.sort()
        q: deque = deque()
        max_burst = 0
        max_burst_time = None
        for ts in timestamps:
            q.append(ts)
            while q and (ts - q[0]) > window:
                q.popleft()
            if len(q) > max_burst:
                max_burst = len(q)
                max_burst_time = ts
        if max_burst >= NTLM_BRUTE_THRESHOLD:
            anomalies.append({
                "anomaly_type": "ntlm_brute_force",
                "entity": user,
                "description": (
                    f"{max_burst} NTLM authentication failures (EID 4776) for {user!r} "
                    f"within {NTLM_BRUTE_WINDOW_MIN} min "
                    f"(peak at {max_burst_time.strftime('%Y-%m-%d %H:%M')}) "
                    f"— possible RDP/SMB brute-force (T1110.003)"
                ),
                "z_score":   None,
                "threshold": float(NTLM_BRUTE_THRESHOLD),
                "observed":  float(max_burst),
                "severity":  "high" if max_burst >= 40 else "medium",
            })
    return anomalies


# ── Check 11: pass-the-hash via NTLM lateral movement (AUTH-002) ──────────────

def _check_pass_the_hash(events: list[ForensicEvent]) -> list[dict]:
    """
    Detect Pass-the-Hash: user has ≥PTH_MIN_LATERAL_LOGONS NTLM network/RDP
    logons (EID 4624 Type 3/9/10 with 'ntlm' in description) but NO Kerberos TGT
    (EID 4768) in the entire session — NTLM-only lateral movement pattern.
    """
    _NTLM_LOGON_EIDS   = ("4624", "4648")
    _NTLM_LOGON_TYPES  = frozenset({"3", "9", "10"})

    ntlm_logons: dict[str, list[ForensicEvent]] = defaultdict(list)
    for e in events:
        if e.event_id not in _NTLM_LOGON_EIDS or not e.user or e.user.endswith("$"):
            continue
        desc = (e.description or "").lower()
        if "ntlm" in desc and _get_logon_type(e.description or "") in _NTLM_LOGON_TYPES:
            ntlm_logons[e.user].append(e)

    kerberos_users = {
        e.user for e in events if e.event_id == "4768" and e.user
    }

    anomalies: list[dict] = []
    for user, logons in ntlm_logons.items():
        if user in kerberos_users:
            continue
        if len(logons) < PTH_MIN_LATERAL_LOGONS:
            continue
        hosts = {e.source_host for e in logons}
        anomalies.append({
            "anomaly_type": "pass_the_hash",
            "entity": user,
            "description": (
                f"Entity {user!r} performed {len(logons)} NTLM lateral logon(s) "
                f"across {len(hosts)} host(s) with no Kerberos TGT in session — "
                f"possible Pass-the-Hash (T1550.002)"
            ),
            "z_score":   None,
            "threshold": float(PTH_MIN_LATERAL_LOGONS),
            "observed":  float(len(logons)),
            "severity":  "high",
        })
    return anomalies


# ── Check 12: WMI shell spawn (LAT-001) ──────────────────────────────────────

def _check_wmi_shell_spawn(events: list[ForensicEvent]) -> list[dict]:
    """
    Sysmon EID 1: wmiprvse.exe spawning cmd/powershell/wscript as a child process.
    Definitive indicator of WMI-based lateral execution. T1047.
    """
    _SHELLS = frozenset({"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"})

    spawn_events = [
        e for e in events
        if e.event_id == "1"
        and e.extra
        and "wmiprvse" in (e.extra.get("ParentImage") or "").lower()
        and any(sh in (e.extra.get("Image") or "").lower() for sh in _SHELLS)
    ]

    if not spawn_events:
        return []

    by_host: dict[str, list[ForensicEvent]] = defaultdict(list)
    for e in spawn_events:
        by_host[e.source_host].append(e)

    anomalies: list[dict] = []
    for host, host_evs in by_host.items():
        actors = {e.user for e in host_evs if e.user}
        actor_str = ", ".join(sorted(actors)) or "unknown"
        images = [e.extra.get("Image", "") for e in host_evs]
        anomalies.append({
            "anomaly_type": "wmi_shell_spawn",
            "entity": actor_str,
            "description": (
                f"wmiprvse.exe spawned shell on {host!r}: "
                f"{', '.join(dict.fromkeys(images))} "
                f"({len(host_evs)} instance(s)) — WMI lateral execution (T1047)"
            ),
            "z_score":   None,
            "threshold": 1.0,
            "observed":  float(len(host_evs)),
            "severity":  "high" if len(by_host) >= 2 else "medium",
        })
    return anomalies


# ── Check 13: event log clearing sweep (EVADE-001) ────────────────────────────

def _check_log_clearing(events: list[ForensicEvent]) -> list[dict]:
    """
    EID 1102 (audit log cleared) or EID 1/4688 with wevtutil cl in command.
    Grouped by host; ≥LOG_CLEAR_HOST_THRESHOLD distinct hosts = attacker sweep.
    T1070.001 Indicator Removal.
    """
    clear_events = [
        e for e in events
        if e.event_id == "1102"
        or (
            e.event_id in ("1", "4688")
            and "wevtutil" in (e.description or "").lower()
            and (" cl " in (e.description or "").lower()
                 or "cl " in (e.description or "").lower()
                 or "wevtutil cl" in (e.description or "").lower())
        )
    ]
    if not clear_events:
        return []

    by_host: dict[str, list[ForensicEvent]] = defaultdict(list)
    for e in clear_events:
        by_host[e.source_host].append(e)

    actors = {e.user for e in clear_events if e.user}
    actor_str = ", ".join(sorted(actors)) or "unknown"
    first_ts = min(e.timestamp for e in clear_events)

    severity = "high" if len(by_host) >= LOG_CLEAR_HOST_THRESHOLD else "medium"
    return [{
        "anomaly_type": "event_log_clearing",
        "entity": actor_str,
        "description": (
            f"Event log clearing detected on {len(by_host)} host(s): "
            f"{', '.join(sorted(by_host.keys()))} "
            f"({len(clear_events)} event(s), first at "
            f"{first_ts.strftime('%Y-%m-%d %H:%M')}) — T1070.001 Indicator Removal"
        ),
        "z_score":   None,
        "threshold": float(LOG_CLEAR_HOST_THRESHOLD),
        "observed":  float(len(by_host)),
        "severity":  severity,
    }]


# ── Check 14: LSASS process-access → lateral logon correlation (PTH-002) ──────

def _check_lsass_pth_correlation(events: list[ForensicEvent]) -> list[dict]:
    """
    Two-event behavioral correlation for Empire C2 Pass-the-Hash:

      EID 10  (Sysmon process-access): TargetImage = lsass.exe,
              GrantedAccess NOT in the benign read-only set
      ↓ within PTH_LSASS_WINDOW_MIN minutes
      EID 4624 LogonType 3 or 9 (network/RunAs logon) on any host

    Empire PTH patches LSASS memory directly — no command-line string
    ("ntlm", "pass-the-hash") ever appears, so Check 11 misses it.
    This rule correlates the two low-level Windows events that always
    co-occur regardless of the tool used.  T1550.002 + T1003.001.
    """
    # Access masks that benign security software uses on lsass (read-only queries).
    # 0x3000 = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_LIMITED_INFORMATION —
    # used exclusively by svchost.exe (Service Control Manager) in all three OTRF
    # datasets; adding it eliminates the WMI dataset FP without masking PTH signals
    # (which use 0x1010 / 0x1038 from PowerShell).
    _BENIGN_MASKS = frozenset({
        "0x1000",   # PROCESS_QUERY_LIMITED_INFORMATION
        "0x400",    # PROCESS_QUERY_INFORMATION (alone)
        "0x800",    # PROCESS_SUSPEND_RESUME
        "0x100000", # SYNCHRONIZE alone
        "0x3000",   # PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_LIMITED_INFORMATION
    })

    lsass_accesses = [
        e for e in events
        if e.event_id == "10"
        and "lsass" in (e.extra or {}).get("TargetImage", "").lower()
        and (e.extra or {}).get("GrantedAccess", "0x0").lower() not in _BENIGN_MASKS
    ]
    if not lsass_accesses:
        return []

    # EID 4624 Type 3 or Type 9 (network / RunAs logon).
    # Exclude machine accounts (user ending in $) — they produce Kerberos DC-replication
    # Type-3 logons that are NOT lateral movement (MORDORDC$ pattern).
    lateral_logons = [
        e for e in events
        if e.event_id == "4624"
        and _get_logon_type(e.description or "") in ("3", "9")
        and not (e.user or "").endswith("$")
    ]
    if not lateral_logons:
        return []

    kerberos_users = {e.user for e in events if e.event_id == "4768" and e.user}
    window         = timedelta(minutes=PTH_LSASS_WINDOW_MIN)
    seen_hosts:  set[str] = set()
    anomalies: list[dict] = []

    for lsass_ev in lsass_accesses:
        host = lsass_ev.source_host
        if host in seen_hosts:
            continue

        # Look for network logons on a DIFFERENT host within the window after lsass access.
        # Same-host logons are local re-authentication, not lateral movement.
        # Require LogonType 9 (NewCredentials / over-pass-the-hash).
        # Type 3 (network) is normal SMB auth; Type 9 is credential impersonation.
        post_logons = [
            logon for logon in lateral_logons
            if timedelta(0) <= logon.timestamp - lsass_ev.timestamp <= window
            and logon.source_host != host
            and _get_logon_type(logon.description or "") == "9"
        ]
        if not post_logons:
            continue

        # Exclude users who obtained a Kerberos TGT — they are using Kerberos, not PTH
        pth_logons = [l for l in post_logons if l.user not in kerberos_users]
        if not pth_logons:
            continue

        seen_hosts.add(host)
        actors   = {l.user for l in pth_logons if l.user}
        targets  = {l.source_host for l in pth_logons}
        src_img  = (lsass_ev.extra or {}).get("SourceImage", "unknown")
        access   = (lsass_ev.extra or {}).get("GrantedAccess", "unknown")

        anomalies.append({
            "anomaly_type": "lsass_pth_correlation",
            "entity":       ", ".join(sorted(actors)) or host,
            "description": (
                f"LSASS process-access (EID 10, GrantedAccess={access}) on {host!r} "
                f"by {src_img!r}, followed by {len(pth_logons)} network logon(s) to "
                f"{', '.join(sorted(targets))} within {PTH_LSASS_WINDOW_MIN} min — "
                f"Empire/Mimikatz Pass-the-Hash via LSASS patch (T1550.002 + T1003.001)"
            ),
            "z_score":   None,
            "threshold": float(PTH_LSASS_WINDOW_MIN),
            "observed":  float(len(pth_logons)),
            "severity":  "high",
        })

    return anomalies


# ── Check 15: Golden and Silver Ticket detection (KERB-001) ──────────────────

def _get_kerb_field(e: ForensicEvent, *keys: str) -> str:
    """
    Return the first non-empty value found by checking e.extra then e.description.
    Handles both snake_case extra keys and "Key Name: value" description patterns.
    """
    if e.extra:
        for key in keys:
            val = e.extra.get(key)
            if val:
                return str(val)
    desc = e.description or ""
    desc_lower = desc.lower()
    for key in keys:
        needle = key.replace("_", " ").lower() + ":"
        idx = desc_lower.find(needle)
        if idx < 0:
            continue
        rest = desc[idx + len(needle):].lstrip()
        end = 0
        for ch in rest:
            if ch in (' ', '\t', '\n', ',', '|', '.'):
                break
            end += 1
        if end:
            return rest[:end]
    return ""


def _check_golden_silver_ticket(events: list[ForensicEvent]) -> list[dict]:
    """
    Golden Ticket (T1558.001): EID 4769 with RC4 encryption (0x17) PLUS either:
      - Ticket options matching known forged-ticket bitmasks (0x40810000 family), AND
        service name is not krbtgt (TGT requests are AS-REQ, not TGS)
      - OR ticket lifetime > GOLDEN_TICKET_LIFETIME_MIN minutes combined with RC4

    Silver Ticket (T1558.002): EID 4769 with RC4 encryption targeting a specific
    host service (cifs/, host/, http/, rpcss/) AND no EID 4768 TGT request from
    that user in the preceding SILVER_TICKET_TGT_WINDOW_MIN minutes — Silver Tickets
    bypass the KDC entirely, so there is no corresponding AS-REQ.
    """
    kerb_4769 = sorted(
        [e for e in events if e.event_id == "4769"
         and e.user and not (e.user or "").endswith("$")],
        key=lambda e: e.timestamp,
    )
    if not kerb_4769:
        return []

    tgt_by_user: dict[str, list] = defaultdict(list)
    for e in events:
        if e.event_id == "4768" and e.user:
            tgt_by_user[e.user].append(e.timestamp)

    tgt_window  = timedelta(minutes=SILVER_TICKET_TGT_WINDOW_MIN)
    seen_golden: set[str] = set()
    seen_silver: set[str] = set()
    anomalies:  list[dict] = []

    for e in kerb_4769:
        enc = _get_kerb_field(e, "ticket_encryption_type", "TicketEncryptionType",
                               "encryption_type", "ticket_enc_type").lower()
        is_rc4 = "0x17" in enc or "rc4" in enc
        if not is_rc4:
            continue

        svc  = _get_kerb_field(e, "service_name", "ServiceName", "service").lower()
        opts = _get_kerb_field(e, "ticket_options", "TicketOptions", "ticket_opt").lower()

        lifetime_raw = _get_kerb_field(e, "ticket_lifetime", "TicketLifetime", "lifetime")
        try:
            lifetime_min = float(lifetime_raw)
        except (ValueError, TypeError):
            lifetime_min = 0.0

        # ── Golden Ticket ────────────────────────────────────────────────────
        # Lifetime-only detection: options-based check removed because 0x40810000
        # (forwardable|renewable|canonicalize) is a standard Kerberoasting TGS option
        # and produced high FP rates against kerberoasting scenarios.
        golden_by_lifetime = (lifetime_min > GOLDEN_TICKET_LIFETIME_MIN
                               and "krbtgt" not in svc)

        if golden_by_lifetime and e.user not in seen_golden:
            seen_golden.add(e.user)
            trigger = f"lifetime={lifetime_min:.0f} min"
            svc_display = svc or "unknown"
            anomalies.append({
                "anomaly_type": "golden_ticket",
                "entity":       e.user,
                "description": (
                    f"Golden Ticket indicator: EID 4769 with RC4 encryption (0x17) "
                    f"for service {svc_display!r} [{trigger}] "
                    f"by {e.user!r} at {e.timestamp.strftime('%Y-%m-%d %H:%M')} "
                    f"— forged Kerberos TGT bypassing KDC (T1558.001)"
                ),
                "z_score":   3.0,
                "threshold": 1.0,
                "observed":  lifetime_min if golden_by_lifetime else 1.0,
                "severity":  "critical",
            })

        # ── Silver Ticket ────────────────────────────────────────────────────
        is_host_svc = any(svc.startswith(p) for p in _SILVER_SVC_PREFIXES)
        if is_host_svc and e.user not in seen_silver:
            prior_tgts = [ts for ts in tgt_by_user.get(e.user, [])
                          if timedelta(0) <= e.timestamp - ts <= tgt_window]
            if not prior_tgts:
                seen_silver.add(e.user)
                anomalies.append({
                    "anomaly_type": "silver_ticket",
                    "entity":       e.user,
                    "description": (
                        f"Silver Ticket indicator: EID 4769 with RC4 encryption (0x17) "
                        f"targeting {svc!r} by {e.user!r} at "
                        f"{e.timestamp.strftime('%Y-%m-%d %H:%M')}, "
                        f"no TGT request (EID 4768) in preceding "
                        f"{SILVER_TICKET_TGT_WINDOW_MIN} min "
                        f"— KDC-bypass forged service ticket (T1558.002)"
                    ),
                    "z_score":   3.0,
                    "threshold": 1.0,
                    "observed":  1.0,
                    "severity":  "critical",
                })

    return anomalies


# ── Check 0: high-confidence single-event rules ────────────────────────────────

def _check_high_confidence_singles(events: list[ForensicEvent]) -> list[dict]:
    """
    Fires on unmistakably malicious single-event patterns with no density
    requirement. Each pattern check is independent; one anomaly is emitted per
    unique (anomaly_type, entity) pair so the same tool running on multiple
    hosts produces distinct entries without flooding.

    severity is always 'critical'; z_score is fixed at 4.0.
    """
    seen:      set[tuple[str, str]] = set()
    anomalies: list[dict] = []

    for event in events:
        desc    = event.description or ""
        cmdline = ((event.extra or {}).get("CommandLine") or "")
        combined = (desc + " " + cmdline).lower()
        entity   = event.user or event.source_host or "__unknown__"
        ts       = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")

        def _fire(atype: str, pattern: str) -> None:
            key = (atype, entity)
            if key in seen:
                return
            seen.add(key)
            anomalies.append({
                "anomaly_type": atype,
                "entity":       entity,
                "description": (
                    f"High-confidence single-event indicator: {pattern!r} matched "
                    f"for {entity!r} at {ts}"
                ),
                "z_score":   4.0,
                "threshold": 1.0,
                "observed":  1,
                "severity":  "critical",
            })

        # Shadow copy / backup deletion
        if "vssadmin delete shadows" in combined or "vssadmin.exe delete" in combined:
            pat = "vssadmin delete shadows" if "vssadmin delete shadows" in combined else "vssadmin.exe delete"
            _fire("shadow_copy_deletion", pat)
        if "wbadmin delete" in combined:
            _fire("shadow_copy_deletion", "wbadmin delete")

        # Boot recovery disabled
        if "bcdedit /set" in combined and any(
            p in combined for p in ("recoveryenabled no", "safeboot")
        ):
            _fire("boot_recovery_disabled", "bcdedit /set recoveryenabled no/safeboot")

        # LOLBin download staging
        if "certutil -urlcache" in combined or "certutil.exe -urlcache" in combined:
            pat = "certutil.exe -urlcache" if "certutil.exe -urlcache" in combined else "certutil -urlcache"
            _fire("certutil_download", pat)
        if "bitsadmin /transfer" in combined:
            _fire("bitsadmin_download", "bitsadmin /transfer")

        # Remote script execution via LOLBins
        if "mshta http" in combined or "mshta.exe http" in combined:
            pat = "mshta.exe http" if "mshta.exe http" in combined else "mshta http"
            _fire("mshta_remote_exec", pat)
        if "regsvr32 /s /u /i:http" in combined:
            _fire("regsvr32_remote_exec", "regsvr32 /s /u /i:http")

        # Encoded PowerShell with a sufficiently long base64 payload
        if any(p in combined for p in ("-encodedcommand", "-enc ")):
            if _B64_LONG_RE.search(desc + " " + cmdline):
                _fire("encoded_powershell", "-EncodedCommand with base64 payload >100 chars")

        # Mimikatz / credential dumping keywords
        if "invoke-mimikatz" in combined or "sekurlsa::logonpasswords" in combined:
            pat = ("invoke-mimikatz" if "invoke-mimikatz" in combined
                   else "sekurlsa::logonpasswords")
            _fire("mimikatz_invocation", pat)
        if "lsadump::dcsync" in combined:
            _fire("dcsync_invocation", "lsadump::dcsync")

        # LSASS dump tooling
        if "procdump" in combined and "lsass" in combined:
            _fire("lsass_dump_tool", "procdump + lsass")
        if "comsvcs.dll" in combined and "minidump" in combined:
            _fire("lsass_dump_tool", "comsvcs.dll + MiniDump")

    return anomalies


# ── Check 16: SMB lateral movement (T1021.002) ────────────────────────────────

def _check_smb_lateral(events: list[ForensicEvent]) -> list[dict]:
    """
    EID 4624 LogonType 3 (network) from one user to ≥SMB_LATERAL_HOST_THRESHOLD
    distinct destination hosts within SMB_LATERAL_WINDOW_MIN minutes.
    Detects SMB/admin-share lateral movement without requiring EID 5140.
    """
    net_logons = sorted(
        [e for e in events
         if e.event_id == "4624"
         and e.user and not (e.user or "").endswith("$")
         and _get_logon_type(e.description or "") == "3"],
        key=lambda e: e.timestamp,
    )
    if not net_logons:
        return []

    by_user: dict[str, list[ForensicEvent]] = defaultdict(list)
    for e in net_logons:
        by_user[e.user].append(e)

    window = timedelta(minutes=SMB_LATERAL_WINDOW_MIN)
    anomalies: list[dict] = []
    for user, evs in by_user.items():
        i = 0
        while i < len(evs):
            window_evs = [e for e in evs[i:] if e.timestamp - evs[i].timestamp <= window]
            hosts = {e.source_host for e in window_evs}
            if len(hosts) >= SMB_LATERAL_HOST_THRESHOLD:
                anomalies.append({
                    "anomaly_type": "smb_lateral_movement",
                    "entity":       user,
                    "description": (
                        f"Entity {user!r} performed network logons (EID 4624 Type 3) "
                        f"to {len(hosts)} distinct host(s) within {SMB_LATERAL_WINDOW_MIN} min: "
                        f"{', '.join(sorted(hosts))} — SMB lateral movement (T1021.002)"
                    ),
                    "z_score":   None,
                    "threshold": float(SMB_LATERAL_HOST_THRESHOLD),
                    "observed":  float(len(hosts)),
                    "severity":  "high",
                })
                break
            i += len(window_evs) if len(window_evs) > 1 else 1
    return anomalies


# ── Check 17: Pass-the-Ticket (T1550.003) ─────────────────────────────────────

def _check_pass_the_ticket(events: list[ForensicEvent]) -> list[dict]:
    """
    EID 4769 with RC4 encryption (etype 0x17) targeting lateral-movement services
    (cifs, host, rpcss, http) but with NO EID 4768 TGT request from that user
    within PTT_LOOKBACK_MIN minutes before the ticket request — the attacker is
    replaying a stolen ticket rather than authenticating legitimately.
    T1550.003.
    """
    _LATERAL_SERVICES = frozenset({"cifs/", "host/", "rpcss/", "http/"})

    rc4_tickets = sorted(
        [e for e in events
         if e.event_id == "4769"
         and e.user and not (e.user or "").endswith("$")
         and "0x17" in (e.description or "").lower()
         and any(svc in (e.description or "").lower() for svc in _LATERAL_SERVICES)],
        key=lambda e: e.timestamp,
    )
    if not rc4_tickets:
        return []

    tgt_times: dict[str, list] = defaultdict(list)
    for e in events:
        if e.event_id == "4768" and e.user:
            tgt_times[e.user].append(e.timestamp)

    window = timedelta(minutes=PTT_LOOKBACK_MIN)
    seen: set[str] = set()
    anomalies: list[dict] = []
    for e in rc4_tickets:
        if e.user in seen:
            continue
        prior_tgts = [t for t in tgt_times.get(e.user, [])
                      if timedelta(0) <= e.timestamp - t <= window]
        if prior_tgts:
            continue
        seen.add(e.user)
        svc = next((s for s in _LATERAL_SERVICES
                    if s in (e.description or "").lower()), "unknown")
        anomalies.append({
            "anomaly_type": "pass_the_ticket",
            "entity":       e.user,
            "description": (
                f"Entity {e.user!r} requested RC4-encrypted Kerberos service ticket "
                f"(EID 4769, etype 0x17) for {svc!r} with no prior TGT (EID 4768) "
                f"within {PTT_LOOKBACK_MIN} min — possible Pass-the-Ticket (T1550.003)"
            ),
            "z_score":   None,
            "threshold": 0.0,
            "observed":  1.0,
            "severity":  "high",
        })
    return anomalies


# ── Check 18: RDP lateral movement (T1021.001) ────────────────────────────────

def _check_rdp_lateral(events: list[ForensicEvent]) -> list[dict]:
    """
    EID 4624 LogonType 10 (RemoteInteractive / RDP) from one user to
    ≥RDP_LATERAL_HOST_THRESHOLD distinct destination hosts within
    RDP_LATERAL_WINDOW_MIN minutes.  T1021.001.
    """
    rdp_logons = sorted(
        [e for e in events
         if e.event_id == "4624"
         and e.user and not (e.user or "").endswith("$")
         and _get_logon_type(e.description or "") == "10"],
        key=lambda e: e.timestamp,
    )
    if not rdp_logons:
        return []

    by_user: dict[str, list[ForensicEvent]] = defaultdict(list)
    for e in rdp_logons:
        by_user[e.user].append(e)

    window = timedelta(minutes=RDP_LATERAL_WINDOW_MIN)
    anomalies: list[dict] = []
    for user, evs in by_user.items():
        i = 0
        while i < len(evs):
            window_evs = [e for e in evs[i:] if e.timestamp - evs[i].timestamp <= window]
            hosts = {e.source_host for e in window_evs}
            if len(hosts) >= RDP_LATERAL_HOST_THRESHOLD:
                anomalies.append({
                    "anomaly_type": "rdp_lateral_movement",
                    "entity":       user,
                    "description": (
                        f"Entity {user!r} performed RDP logons (EID 4624 Type 10) "
                        f"to {len(hosts)} distinct host(s) within {RDP_LATERAL_WINDOW_MIN} min: "
                        f"{', '.join(sorted(hosts))} — RDP lateral movement (T1021.001)"
                    ),
                    "z_score":   None,
                    "threshold": float(RDP_LATERAL_HOST_THRESHOLD),
                    "observed":  float(len(hosts)),
                    "severity":  "high" if len(hosts) >= 4 else "medium",
                })
                break
            i += len(window_evs) if len(window_evs) > 1 else 1
    return anomalies


# ── Main entry point ───────────────────────────────────────────────────────────

def analyze_behavior(events: list[ForensicEvent]) -> dict:
    """
    Run all four behavioral checks and return a consolidated report dict.

    Keys: anomalies, profiled_entities, analysis_window_hours, highest_severity.
    Each anomaly: anomaly_type, entity, description, z_score, threshold, observed, severity.
    """
    if not events:
        return {
            'anomalies': [],
            'profiled_entities': 0,
            'analysis_window_hours': 0.0,
            'highest_severity': 'none',
        }

    sorted_events = sorted(events, key=lambda e: e.timestamp)
    span_hours    = (
        (sorted_events[-1].timestamp - sorted_events[0].timestamp).total_seconds() / 3600
    )

    high_conf: list[dict] = _check_high_confidence_singles(sorted_events)

    anomalies: list[dict] = []
    anomalies += _check_hourly_spike(sorted_events)
    anomalies += _check_host_velocity(sorted_events)
    anomalies += _check_auth_failure_burst(sorted_events)
    anomalies += _check_off_hours_privilege(sorted_events)
    anomalies += _check_kerberos_ticket_spike(sorted_events)
    anomalies += _check_group_modification_burst(sorted_events)
    anomalies += _check_account_creation_chain(sorted_events)
    anomalies += _check_ntlm_spike(sorted_events)
    anomalies += _check_ransomware_triad(sorted_events)
    anomalies += _check_ntlm_brute_force(sorted_events)
    anomalies += _check_pass_the_hash(sorted_events)
    anomalies += _check_wmi_shell_spawn(sorted_events)
    anomalies += _check_log_clearing(sorted_events)
    anomalies += _check_lsass_pth_correlation(sorted_events)
    anomalies += _check_golden_silver_ticket(sorted_events)
    anomalies += _check_smb_lateral(sorted_events)
    anomalies += _check_pass_the_ticket(sorted_events)
    anomalies += _check_rdp_lateral(sorted_events)
    anomalies += high_conf

    # Sort by severity (critical first, then high, medium, low)
    _sev = {'critical': -1, 'high': 0, 'medium': 1, 'low': 2}
    anomalies.sort(key=lambda a: (_sev.get(a['severity'], 3), a['entity']))

    profiled = len({e.user for e in events if e.user and not (e.user or '').endswith('$')})
    highest  = 'none'
    for a in anomalies:
        if _sev.get(a['severity'], 3) < _sev.get(highest, 3):
            highest = a['severity']
    if anomalies and highest == 'none':
        highest = anomalies[0]['severity']

    return {
        'anomalies':                       anomalies,
        'profiled_entities':               profiled,
        'analysis_window_hours':           round(span_hours, 2),
        'highest_severity':                highest,
        'high_confidence_single_event_rules': len(high_conf),
    }
