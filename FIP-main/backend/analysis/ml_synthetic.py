"""
Synthetic baseline event generator for ML anomaly model training.

Produces ~3 000–5 000 ForensicEvent objects covering 7 realistic user-profile
types across 30 days.  The variety ensures the Isolation Forest learns that
very different "normal" patterns exist — so an IT admin legitimately using
net.exe is never flagged, while a standard worker running encoded PowerShell
at 3am correctly scores as anomalous.

Profile breakdown (30 users total → HIGH confidence threshold):
  standard_worker  ×8  — 09–17h, 1 host, Office/browser, zero admin tools
  it_admin         ×4  — varied hours, 8–15 hosts, legitimate admin tools
  service_account  ×5  — 22–04h, 1 host, scheduled/repetitive, no failures
  developer        ×4  — 10–19h, 1–3 hosts, build/test tools, moderate procs
  help_desk        ×4  — 08–17h, 5–10 rotating hosts, remote-access tools
  db_admin         ×3  — 00–06h maintenance windows, DB servers, backup tools
  executive        ×2  — 09–16h, 1 host, low volume, no technical processes
"""

import random
from datetime import datetime, timedelta
from backend.schema import ForensicEvent, RawSource

# ── Host pools ────────────────────────────────────────────────────────────────

_WS   = [f"WORKSTATION-{i:02d}" for i in range(1, 31)]   # 30 workstations
_SRV  = ["DC-01", "DC-02", "FILE-SERVER-01", "FILE-SERVER-02",
         "WEB-SERVER-01", "APP-SERVER-01", "PRINT-SERVER-01", "MGMT-SERVER-01"]
_DB   = ["DB-SERVER-01", "DB-SERVER-02", "DB-SERVER-03"]
_DEV  = [f"DEV-WS-{i:02d}" for i in range(1, 7)] + ["BUILD-SERVER-01", "DEV-SERVER-01"]
_EXEC = [f"EXEC-WS-{i:02d}" for i in range(1, 4)]

# ── Process name pools ────────────────────────────────────────────────────────

_PROCS_STANDARD = [
    "explorer.exe", "chrome.exe", "msedge.exe", "outlook.exe",
    "teams.exe", "excel.exe", "word.exe", "powerpoint.exe",
    "notepad.exe", "onedrive.exe", "zoom.exe", "slack.exe",
    "acrobat.exe", "winword.exe", "mspaint.exe",
]

_PROCS_ADMIN_LEGIT = [
    "powershell.exe", "cmd.exe", "mmc.exe", "net.exe",
    "eventvwr.exe", "taskschd.exe", "services.msc",
    "compmgmt.exe", "lusrmgr.exe", "gpmc.msc",
    "regedit.exe", "wbemtest.exe", "dfrgui.exe",
]

_PROCS_DEV = [
    "code.exe", "python.exe", "node.exe", "git.exe",
    "docker.exe", "java.exe", "devenv.exe", "rider.exe",
    "gradle.exe", "mvn.cmd", "pip.exe", "npm.cmd",
    "pytest.exe", "cargo.exe", "go.exe",
]

_PROCS_DB = [
    "sqlservr.exe", "mysqld.exe", "postgres.exe",
    "sqlagent.exe", "sqlcmd.exe", "pg_dump.exe",
    "mysqldump.exe", "sqlbackup.exe", "dbcc.exe",
]

_PROCS_HELPDESK = [
    "mstsc.exe", "powershell.exe", "cmd.exe",
    "teamviewer.exe", "anydesk.exe", "winrm.cmd",
    "psexec.exe", "net.exe", "ipconfig.exe", "ping.exe",
    "msconfig.exe", "eventvwr.exe",
]

_SCHEDULED_TASKS = [
    "\\CustomBackup\\NightlyBackup",
    "\\DBMaint\\IndexRebuild",
    "\\Monitoring\\HealthCheck",
    "\\Security\\VulnScan",
    "\\WindowsUpdate\\ScheduledScan",
    "\\Antivirus\\FullScan",
    "\\Reporting\\DailyReport",
]

# ── Event factory helpers ─────────────────────────────────────────────────────

def _ev(
    timestamp: datetime,
    event_type: str,
    source_host: str,
    user: str,
    description: str,
    event_id: str,
) -> ForensicEvent:
    return ForensicEvent(
        timestamp=timestamp,
        event_type=event_type,
        source_host=source_host,
        user=user,
        description=description,
        raw_source=RawSource.GENERIC,
        event_id=event_id,
    )


def _logon(dt: datetime, host: str, user: str, logon_type: int = 3) -> ForensicEvent:
    return _ev(
        dt, "logon", host, user,
        f"Account successfully logged on. Account: CORP\\{user}. "
        f"Logon Type: {logon_type}. Workstation: {host}.",
        "4624",
    )


def _logon_explicit(dt: datetime, host: str, user: str) -> ForensicEvent:
    return _ev(
        dt, "logon", host, user,
        f"Logon with explicit credentials. Account: CORP\\{user}. Target server: {host}.",
        "4648",
    )


def _logon_failed(dt: datetime, host: str, user: str) -> ForensicEvent:
    return _ev(
        dt, "logon", host, user,
        f"Account failed to log on. Account Name: {user}. "
        f"Failure Reason: Unknown user name or bad password. Status: 0xC000006D.",
        "4625",
    )


def _logoff(dt: datetime, host: str, user: str) -> ForensicEvent:
    return _ev(
        dt, "logoff", host, user,
        f"Account logged off. Account: CORP\\{user}. Logon Type: 2.",
        "4634",
    )


def _process(dt: datetime, host: str, user: str, proc: str, args: str = "") -> ForensicEvent:
    cmd = f"C:\\Windows\\System32\\{proc}{(' ' + args) if args else ''}"
    return _ev(
        dt, "process", host, user,
        f"New process created. Account: CORP\\{user}. "
        f"New Process Name: {cmd}. Parent: explorer.exe.",
        "4688",
    )


def _scheduled_task(dt: datetime, host: str, user: str, task: str) -> ForensicEvent:
    return _ev(
        dt, "scheduled_task", host, user,
        f"Scheduled task created. Task Name: {task}. Account: CORP\\{user}.",
        "4698",
    )


def _service(dt: datetime, host: str, user: str, svc: str) -> ForensicEvent:
    return _ev(
        dt, "service", host, user,
        f"A service was installed. Service Name: {svc}. Account: CORP\\{user}.",
        "7045",
    )


# ── Time helpers ──────────────────────────────────────────────────────────────

def _dt(rng: random.Random, base: datetime, day: int, h_min: int, h_max: int) -> datetime:
    return (base + timedelta(days=day)).replace(
        hour=rng.randint(h_min, h_max),
        minute=rng.randint(0, 59),
        second=rng.randint(0, 59),
        microsecond=0,
    )


def _working_days(base: datetime, total: int) -> list[int]:
    return [i for i in range(total) if (base + timedelta(days=i)).weekday() < 5]


def _all_days(base: datetime, total: int) -> list[int]:
    return list(range(total))


# ── Per-profile generators ────────────────────────────────────────────────────

def _gen_standard_worker(rng: random.Random, base: datetime, username: str, ws: str) -> list[ForensicEvent]:
    """
    Typical office user: single workstation, business hours, Office/browser apps.
    No admin tool usage; occasional (rare) failed logon from typo.
    """
    evs: list[ForensicEvent] = []
    days = _working_days(base, 30)
    active_days = rng.sample(days, min(20, len(days)))

    for day in active_days:
        n_procs = rng.randint(4, 10)
        evs.append(_logon(_dt(rng, base, day, 8, 10), ws, username, logon_type=2))

        # Occasional failed logon (fat-finger password)
        if rng.random() < 0.08:
            evs.append(_logon_failed(_dt(rng, base, day, 8, 9), ws, username))

        for _ in range(n_procs):
            proc = rng.choice(_PROCS_STANDARD)
            evs.append(_process(_dt(rng, base, day, 9, 17), ws, username, proc))

        evs.append(_logoff(_dt(rng, base, day, 16, 18), ws, username))

    return evs


def _gen_it_admin(rng: random.Random, base: datetime, username: str) -> list[ForensicEvent]:
    """
    IT administrator: accesses many different hosts via RDP/WinRM, uses admin
    tools legitimately, occasionally works outside business hours for maintenance.
    High unique_hosts is NORMAL for this profile.
    """
    evs: list[ForensicEvent] = []
    all_hosts = _WS[:15] + _SRV  # admins touch workstations AND servers
    days = _all_days(base, 30)
    active_days = rng.sample(days, min(22, len(days)))

    for day in active_days:
        # Each admin day involves touching 3–8 different machines
        hosts_today = rng.sample(all_hosts, rng.randint(3, 8))
        for host in hosts_today:
            evs.append(_logon_explicit(_dt(rng, base, day, 7, 19), host, username))

            n_procs = rng.randint(2, 6)
            for _ in range(n_procs):
                proc = rng.choice(_PROCS_ADMIN_LEGIT)
                evs.append(_process(_dt(rng, base, day, 7, 20), host, username, proc))

            # Occasional off-hours check (on-call)
            if rng.random() < 0.12:
                evs.append(_logon(_dt(rng, base, day, 21, 23), rng.choice(_SRV), username, logon_type=10))

    return evs


def _gen_service_account(rng: random.Random, base: datetime, username: str, host: str) -> list[ForensicEvent]:
    """
    Service account: predictable overnight schedule, always the same host,
    scheduled tasks and services only, zero failed logons, zero admin tools.
    High off_hours_ratio and low type_diversity are NORMAL for this profile.
    """
    evs: list[ForensicEvent] = []
    days = _all_days(base, 30)

    for day in days:
        if rng.random() < 0.9:  # 90% chance runs nightly
            run_hour = rng.choice([0, 1, 2, 3, 22, 23])
            dt_run = _dt(rng, base, day, run_hour, run_hour)
            evs.append(_logon(dt_run, host, username, logon_type=5))  # service logon
            task = rng.choice(_SCHEDULED_TASKS)
            evs.append(_scheduled_task(dt_run + timedelta(minutes=1), host, username, task))
            n_procs = rng.randint(1, 3)
            for _ in range(n_procs):
                proc = rng.choice(_PROCS_DB + ["robocopy.exe", "xcopy.exe", "wbadmin.exe"])
                evs.append(_process(dt_run + timedelta(minutes=rng.randint(2, 30)), host, username, proc))
            evs.append(_logoff(dt_run + timedelta(minutes=rng.randint(30, 120)), host, username))

    return evs


def _gen_developer(rng: random.Random, base: datetime, username: str) -> list[ForensicEvent]:
    """
    Developer: slightly extended business hours, dev tools generate many process
    creation events, touches dev workstation + build server occasionally.
    High process_event_ratio is NORMAL for this profile.
    """
    evs: list[ForensicEvent] = []
    ws = rng.choice(_DEV[:6])  # their assigned dev workstation
    days = _working_days(base, 30)
    active_days = rng.sample(days, min(22, len(days)))

    for day in active_days:
        evs.append(_logon(_dt(rng, base, day, 9, 11), ws, username, logon_type=2))

        # Developers create many processes (builds, test runs, linters)
        n_procs = rng.randint(10, 25)
        for _ in range(n_procs):
            proc = rng.choice(_PROCS_DEV)
            evs.append(_process(_dt(rng, base, day, 9, 20), ws, username, proc))

        # Occasional push to build server
        if rng.random() < 0.35:
            build_host = "BUILD-SERVER-01"
            evs.append(_logon_explicit(_dt(rng, base, day, 10, 18), build_host, username))
            evs.append(_process(_dt(rng, base, day, 10, 18), build_host, username,
                                 rng.choice(["gradle.exe", "mvn.cmd", "npm.cmd", "go.exe"])))

        # Occasional mild failed logon (expired password / typo)
        if rng.random() < 0.05:
            evs.append(_logon_failed(_dt(rng, base, day, 9, 10), ws, username))

        evs.append(_logoff(_dt(rng, base, day, 17, 21), ws, username))

    return evs


def _gen_help_desk(rng: random.Random, base: datetime, username: str) -> list[ForensicEvent]:
    """
    Help desk technician: rotates through many different workstations per day
    helping users.  Uses remote tools (mstsc.exe, psexec.exe) legitimately.
    High unique_hosts AND admin tool presence are NORMAL for this profile.
    """
    evs: list[ForensicEvent] = []
    days = _working_days(base, 30)
    active_days = rng.sample(days, min(22, len(days)))

    for day in active_days:
        # Each day involves 4–10 different user machines
        tickets_today = rng.randint(4, 10)
        hosts_today = rng.sample(_WS, tickets_today)

        for host in hosts_today:
            evs.append(_logon_explicit(_dt(rng, base, day, 8, 17), host, username))

            n_procs = rng.randint(2, 5)
            for _ in range(n_procs):
                proc = rng.choice(_PROCS_HELPDESK)
                evs.append(_process(_dt(rng, base, day, 8, 17), host, username, proc))

            # Occasional failed logon on a machine with wrong local creds
            if rng.random() < 0.07:
                evs.append(_logon_failed(_dt(rng, base, day, 8, 17), host, username))

    return evs


def _gen_db_admin(rng: random.Random, base: datetime, username: str) -> list[ForensicEvent]:
    """
    Database administrator: overnight maintenance windows (00–06h), works on
    DB servers specifically, uses DB tools and backup utilities.
    Very high off_hours_ratio is NORMAL for this profile.
    """
    evs: list[ForensicEvent] = []
    # DB admins have scheduled maintenance nights + ad-hoc
    days = _all_days(base, 30)
    maint_days = rng.sample(days, rng.randint(12, 20))

    for day in maint_days:
        target_host = rng.choice(_DB)
        maint_hour = rng.choice([0, 1, 2, 3, 4])

        evs.append(_logon(_dt(rng, base, day, maint_hour, maint_hour), target_host, username, logon_type=10))

        n_procs = rng.randint(3, 8)
        for _ in range(n_procs):
            proc = rng.choice(_PROCS_DB)
            evs.append(_process(
                _dt(rng, base, day, maint_hour, min(maint_hour + 3, 6)),
                target_host, username, proc
            ))

        task = rng.choice(_SCHEDULED_TASKS[:3])
        evs.append(_scheduled_task(
            _dt(rng, base, day, maint_hour, maint_hour),
            target_host, username, task
        ))

        evs.append(_logoff(
            _dt(rng, base, day, min(maint_hour + 2, 6), min(maint_hour + 4, 7)),
            target_host, username
        ))

        # Also touch backup server during maintenance
        if rng.random() < 0.5:
            backup_host = "MGMT-SERVER-01"
            evs.append(_logon_explicit(
                _dt(rng, base, day, maint_hour, maint_hour),
                backup_host, username
            ))
            evs.append(_process(
                _dt(rng, base, day, maint_hour, maint_hour),
                backup_host, username, "wbadmin.exe"
            ))

    return evs


def _gen_executive(rng: random.Random, base: datetime, username: str) -> list[ForensicEvent]:
    """
    Executive: very low event volume, strict business hours, single workstation,
    only standard apps (Teams, Outlook, browser), never touches admin tools.
    Low event_velocity and very low type_diversity are NORMAL for this profile.
    """
    evs: list[ForensicEvent] = []
    ws = rng.choice(_EXEC)
    days = _working_days(base, 30)
    # Executives travel — only ~12 active days in 30
    active_days = rng.sample(days, min(12, len(days)))

    for day in active_days:
        evs.append(_logon(_dt(rng, base, day, 8, 10), ws, username, logon_type=2))

        n_procs = rng.randint(2, 5)
        for _ in range(n_procs):
            proc = rng.choice(["outlook.exe", "teams.exe", "chrome.exe",
                                "msedge.exe", "zoom.exe", "excel.exe"])
            evs.append(_process(_dt(rng, base, day, 9, 16), ws, username, proc))

        evs.append(_logoff(_dt(rng, base, day, 14, 17), ws, username))

    return evs


# ── Main entry point ──────────────────────────────────────────────────────────

def generate_baseline_events(days: int = 30, seed: int = 42) -> list[ForensicEvent]:
    """
    Generate ~3 000–5 000 synthetic ForensicEvent objects covering 7 user
    profile types across `days` days.

    Designed so that, after feature extraction, the Isolation Forest learns:
    - IT admins and help-desk staff legitimately touch many hosts
    - Admins legitimately use powershell.exe and net.exe
    - Service accounts working at 2am is normal for them
    - High process creation is normal for developers
    - Low event volume at strict business hours is normal for executives

    Pass `seed` for a reproducible dataset; vary it to regenerate variety.
    """
    rng = random.Random(seed)
    base = (datetime.utcnow() - timedelta(days=days)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    events: list[ForensicEvent] = []

    # ── Standard workers ×8 ───────────────────────────────────────────────────
    for i in range(1, 9):
        ws = _WS[i - 1]
        events.extend(_gen_standard_worker(rng, base, f"user{i:02d}", ws))

    # ── IT admins ×4 ──────────────────────────────────────────────────────────
    for i in range(1, 5):
        events.extend(_gen_it_admin(rng, base, f"itadmin{i:02d}"))

    # ── Service accounts ×5 ───────────────────────────────────────────────────
    svc_hosts = ["BACKUP-01", "MGMT-SERVER-01", "FILE-SERVER-01", "DB-SERVER-01", "APP-SERVER-01"]
    for i, svc_host in enumerate(svc_hosts, 1):
        events.extend(_gen_service_account(rng, base, f"svc_backup{i:02d}", svc_host))

    # ── Developers ×4 ─────────────────────────────────────────────────────────
    for i in range(1, 5):
        events.extend(_gen_developer(rng, base, f"dev{i:02d}"))

    # ── Help desk ×4 ──────────────────────────────────────────────────────────
    for i in range(1, 5):
        events.extend(_gen_help_desk(rng, base, f"helpdesk{i:02d}"))

    # ── DB admins ×3 ──────────────────────────────────────────────────────────
    for i in range(1, 4):
        events.extend(_gen_db_admin(rng, base, f"dbadmin{i:02d}"))

    # ── Executives ×2 ─────────────────────────────────────────────────────────
    for i in range(1, 3):
        events.extend(_gen_executive(rng, base, f"exec{i:02d}"))

    return events
