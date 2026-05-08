"""
Behavioral ML entity analysis — Phase 2.

Detects statistical anomalies in user/host behavior using four complementary checks:
  1. Per-user hourly event spike     — Z-score > 2.5 over observed hourly distribution
  2. Cross-host lateral velocity     — > 3 distinct hosts per user in 30-minute window
  3. Authentication failure burst    — > 10 Event 4625 failures per user in 5 minutes
  4. Off-hours privileged operation  — Event 4672 SeDebugPrivilege outside 07:00-19:00

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
