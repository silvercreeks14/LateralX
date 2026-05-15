"""
Behavioral ML entity analysis — Phase 2.

Detects statistical anomalies in user/host behavior using eight complementary checks:
  1. Per-user hourly event spike     — Z-score > 2.5 over observed hourly distribution
  2. Cross-host lateral velocity     — > 3 distinct hosts per user in 30-minute window
  3. Authentication failure burst    — > 10 Event 4625 failures per user in 5 minutes
  4. Off-hours privileged operation  — Event 4672 SeDebugPrivilege outside 07:00-19:00
  5. Kerberos ticket request spike   — > 20 EID 4769 from one user in 10 minutes (Kerberoasting)
  6. Group modification burst        — > 3 EID 4728/4732/4735/4756 in 30 minutes
  7. Privileged account creation     — EID 4720 followed by EID 4728 within 10 minutes
  8. NTLM authentication spike       — > 15 EID 4776 from a non-DC host in 5 minutes

None of these checks require training data — they are fully deterministic and run in O(n).
"""

import math
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

# Common privileged group SIDs / names used in group-mod check
_PRIV_GROUPS = frozenset({
    "domain admins", "enterprise admins", "schema admins",
    "administrators", "account operators", "backup operators",
    "group policy creator owners",
})


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
    for e in priv_events:
        hour = e.timestamp.hour
        if not (WORK_HOUR_START <= hour < WORK_HOUR_END):
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

    anomalies: list[dict] = []
    anomalies += _check_hourly_spike(sorted_events)
    anomalies += _check_host_velocity(sorted_events)
    anomalies += _check_auth_failure_burst(sorted_events)
    anomalies += _check_off_hours_privilege(sorted_events)
    anomalies += _check_kerberos_ticket_spike(sorted_events)
    anomalies += _check_group_modification_burst(sorted_events)
    anomalies += _check_account_creation_chain(sorted_events)
    anomalies += _check_ntlm_spike(sorted_events)

    # Sort by severity (high first), then by entity
    _sev = {'high': 0, 'medium': 1, 'low': 2}
    anomalies.sort(key=lambda a: (_sev.get(a['severity'], 3), a['entity']))

    profiled = len({e.user for e in events if e.user and not (e.user or '').endswith('$')})
    highest  = 'none'
    for a in anomalies:
        if _sev.get(a['severity'], 3) < _sev.get(highest, 3):
            highest = a['severity']
    if anomalies and highest == 'none':
        highest = anomalies[0]['severity']

    return {
        'anomalies':              anomalies,
        'profiled_entities':      profiled,
        'analysis_window_hours':  round(span_hours, 2),
        'highest_severity':       highest,
    }
