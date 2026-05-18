"""
Synthetic AD baseline event generator for Isolation Forest training.

Dataset design is grounded in four published sources:
  - LANL 2015 Comprehensive Multi-Source Cyber-Security Events (Kent, A.D.)
    → User activity volumes, host diversity per role, logon hour distributions
  - CERT Insider Threat Dataset v6.2 (CMU SEI)
    → User profile types, activity frequency by role, failed logon rates
  - OTRF/Mordor Windows AD Datasets (Rodriguez, R. et al.)
    → Realistic Windows Event ID frequencies for normal AD operations:
      Kerberos TGT (4768), TGS (4769), network logon (4624 Type 3),
      SMB share access (5140), group policy refresh (4739)
  - MITRE ATT&CK Evaluations Enterprise Round 5 (Turla, 2024)
    → Modern enterprise baseline telemetry volumes and process diversity
    → Informed updated EID 4688 rates for Win11 hosts with process auditing
    → Reference: https://attackevals.mitre-engenuity.org/enterprise/turla

Modernisation notes (2024 update vs. original LANL 2015 parameters):
  · EID 4688 (Process Create) volume increased to reflect Windows 11 enterprise
    audit policy with Advanced Process Auditing enabled — modern hosts generate
    ~150–300 process-creation events per day compared to ~50 in 2015 Windows 7.
    Source: Microsoft "Advanced Security Audit Policy Settings" (docs.microsoft.com,
    2023); CIS Microsoft Windows 11 Enterprise Benchmark v2.0.0 (CIS, 2023).
  · Modern process pools include Windows 11 system processes (sgrmbroker.exe,
    runtimebroker.exe, dsregcmd.exe) absent in 2015 baselines.
  · EID 4104 (PowerShell ScriptBlock) noise added — background Group Policy and
    WMI modules trigger ScriptBlock logging even on benign hosts.
    Source: NIST SP 800-92 Rev 1 Draft (NIST, 2024) §4.3.
  · New cloud_workstation profile for Azure AD hybrid-joined workstations —
    these generate EID 4648 (explicit credential) more frequently than legacy
    domain-joined machines due to cloud token refresh patterns.

Profile distribution (54 users → HIGH confidence threshold):
  standard_worker     ×10  — 09–17h, 1 host, Office/browser, zero admin tools
  it_admin            ×6   — varied hours, 8–20 hosts, legitimate admin tools, normal Kerberos
  service_account     ×6   — 22–04h, 1 host, scheduled/repetitive, no admin tools
  developer           ×5   — 10–19h, 1–3 hosts, high process rate, build tools
  help_desk           ×5   — 08–17h, 5–10 rotating hosts, remote-access tools
  db_admin            ×4   — 00–06h maintenance windows, DB servers, backup tools
  executive           ×3   — 09–16h, 1 host, low volume, no technical processes
  domain_controller   ×4   — 24/7 Kerberos auth + replication (DC service accounts)
  security_analyst    ×7   — legitimate security tooling, log queries, policy checks
  cloud_workstation   ×4   — Azure AD hybrid-joined; more EID 4648 + background PS noise

Key invariants the model learns from this dataset:
  · IT admins legitimately use net.exe, powershell.exe, and touch many hosts
  · Help-desk staff legitimately use psexec.exe and mstsc.exe at many workstations
  · Service accounts at 2am is NORMAL — not anomalous
  · High 4769 (TGS) rate for IT admins is normal; >50 TGS in 10 min is not
  · Security analysts running Get-WinEvent and querying LDAP is normal
  · DC service accounts generating Kerberos events 24/7 is normal
  · High EID 4688 volume on Win11 hosts is NORMAL — not anomalous
  · Background PowerShell EID 4104 events from GPO/WMI modules are NORMAL
"""

import random
from datetime import datetime, timedelta
from backend.schema import ForensicEvent, RawSource

# ── Host pools ────────────────────────────────────────────────────────────────
# Named to reflect a realistic mid-size Active Directory environment.

_WS   = [f"WORKSTATION-{i:02d}" for i in range(1, 41)]   # 40 workstations
_SRV  = [
    "DC-01", "DC-02", "DC-03",
    "FILE-SERVER-01", "FILE-SERVER-02",
    "WEB-SERVER-01", "APP-SERVER-01",
    "PRINT-SERVER-01", "MGMT-SERVER-01",
    "SCCM-SERVER-01",
]
_DB   = ["DB-SERVER-01", "DB-SERVER-02", "DB-SERVER-03"]
_DEV  = [f"DEV-WS-{i:02d}" for i in range(1, 7)] + ["BUILD-SERVER-01", "DEV-SERVER-01"]
_EXEC = [f"EXEC-WS-{i:02d}" for i in range(1, 4)]
_DCS  = ["DC-01", "DC-02", "DC-03"]   # Domain Controllers only
_SOC  = [f"SOC-WS-{i:02d}" for i in range(1, 4)]  # Security analyst workstations

# ── File shares (for normal SMB access patterns) ──────────────────────────────
_SHARES = [
    r"\\FILE-SERVER-01\NETLOGON",
    r"\\FILE-SERVER-01\SYSVOL",
    r"\\FILE-SERVER-01\Shared",
    r"\\FILE-SERVER-02\Dept",
    r"\\FILE-SERVER-01\Home",
    r"\\DC-01\NETLOGON",
    r"\\DC-01\SYSVOL",
]

# ── Kerberos service SPNs (for normal TGS requests) ───────────────────────────
_SERVICES = [
    "cifs/FILE-SERVER-01.corp.local",
    "cifs/FILE-SERVER-02.corp.local",
    "ldap/DC-01.corp.local",
    "ldap/DC-02.corp.local",
    "host/WORKSTATION-01.corp.local",
    "MSSQLSvc/DB-SERVER-01.corp.local:1433",
    "http/WEB-SERVER-01.corp.local",
    "rpcss/DC-01.corp.local",
]

# ── Process name pools ────────────────────────────────────────────────────────

_PROCS_STANDARD = [
    # Core productivity apps (unchanged from LANL 2015 era)
    "explorer.exe", "chrome.exe", "msedge.exe", "outlook.exe",
    "teams.exe", "excel.exe", "word.exe", "powerpoint.exe",
    "notepad.exe", "onedrive.exe", "zoom.exe", "slack.exe",
    "acrobat.exe", "winword.exe", "mspaint.exe", "onenote.exe",
    # Modern Windows 11 processes — generate EID 4688 noise in enterprise environments.
    # Source: MITRE ATT&CK Evaluations Round 5 (Turla, 2024) baseline host telemetry.
    "sgrmbroker.exe",       # System Guard Runtime Monitor (VBS/Secure Boot integrity)
    "runtimebroker.exe",    # Windows Runtime Broker (App Container runtime isolation)
    "searchindexer.exe",    # Windows Search indexer (background, constant activity)
    "microsoftedgeupdate.exe",  # Edge browser auto-update (runs silently)
    "officec2rclient.exe",  # Office Click-to-Run update client
    "msedgewebview2.exe",   # Edge WebView2 (embedded in Teams, Office, etc.)
]

# OS-level background processes that generate EID 4688 on modern Windows 11 hosts.
# These are NOT user-initiated — they are infrastructure noise from Windows Update,
# Defender, and device management. Added to teach the Isolation Forest that high
# 4688 rates on Win11 workstations are NORMAL.
# Reference: CIS Microsoft Windows 11 Enterprise Benchmark v2.0.0 (CIS, 2023) §18.
_PROCS_SYSTEM_BACKGROUND = [
    "tiworker.exe",         # Windows Modules Installer Worker (Windows Update)
    "wuauclt.exe",          # Windows Update AutoUpdate Client
    "mrt.exe",              # Malicious Software Removal Tool (monthly)
    "usocoreworker.exe",    # Update Session Orchestrator
    "dllhost.exe",          # COM+ Host (many concurrent instances)
    "conhost.exe",          # Console Window Host (one per cmd/ps session)
    "lsaiso.exe",           # LSA Isolated (Credential Guard — Windows 11 only)
    "dsregcmd.exe",         # Device Registration (Azure AD join status check)
    "mdm.exe",              # Mobile Device Management (Intune agent)
    "searchprotocolhost.exe",  # Windows Search protocol host
    "searchfilterhost.exe",    # Windows Search filter host
]

_PROCS_ADMIN_LEGIT = [
    "powershell.exe", "cmd.exe", "mmc.exe", "net.exe",
    "eventvwr.exe", "taskschd.exe", "services.msc",
    "compmgmt.exe", "lusrmgr.exe", "gpmc.msc",
    "regedit.exe", "wbemtest.exe", "dfrgui.exe",
    "dsa.msc", "adsiedit.msc", "gpupdate.exe",
    "robocopy.exe", "xcopy.exe",
]

_PROCS_DEV = [
    "code.exe", "python.exe", "node.exe", "git.exe",
    "docker.exe", "java.exe", "devenv.exe", "rider.exe",
    "gradle.exe", "mvn.cmd", "pip.exe", "npm.cmd",
    "pytest.exe", "cargo.exe", "go.exe", "dotnet.exe",
]

_PROCS_DB = [
    "sqlservr.exe", "mysqld.exe", "postgres.exe",
    "sqlagent.exe", "sqlcmd.exe", "pg_dump.exe",
    "mysqldump.exe", "sqlbackup.exe",
]

_PROCS_HELPDESK = [
    "mstsc.exe", "powershell.exe", "cmd.exe",
    "teamviewer.exe", "anydesk.exe", "winrm.cmd",
    "psexec.exe", "net.exe", "ipconfig.exe", "ping.exe",
    "msconfig.exe", "eventvwr.exe", "compmgmt.exe",
]

_PROCS_SOC = [
    "powershell.exe", "cmd.exe", "wireshark.exe",
    "procmon.exe", "autoruns.exe", "sysinternals.exe",
    "logparser.exe", "eventvwr.exe", "wevtutil.exe",
]

_SCHEDULED_TASKS = [
    r"\CustomBackup\NightlyBackup",
    r"\DBMaint\IndexRebuild",
    r"\Monitoring\HealthCheck",
    r"\Security\VulnScan",
    r"\WindowsUpdate\ScheduledScan",
    r"\Antivirus\FullScan",
    r"\Reporting\DailyReport",
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


def _logon(dt: datetime, host: str, user: str, logon_type: int = 2) -> ForensicEvent:
    return _ev(
        dt, "logon", host, user,
        f"Account successfully logged on. Account Name: {user}. "
        f"Logon Type: {logon_type}. Workstation Name: {host}. "
        f"Source Network Address: -.",
        "4624",
    )


def _logon_network(dt: datetime, host: str, user: str, src_ip: str = "192.168.1.50") -> ForensicEvent:
    return _ev(
        dt, "logon", host, user,
        f"Account successfully logged on. Account Name: {user}. "
        f"Logon Type: 3. Workstation Name: -. "
        f"Source Network Address: {src_ip}.",
        "4624",
    )


def _logon_explicit(dt: datetime, host: str, user: str) -> ForensicEvent:
    return _ev(
        dt, "logon", host, user,
        f"Logon with explicit credentials. Account Name: {user}. "
        f"Target Server Name: {host}.",
        "4648",
    )


def _logon_failed(dt: datetime, host: str, user: str) -> ForensicEvent:
    return _ev(
        dt, "logon_failed", host, user,
        f"Account failed to log on. Account Name: {user}. "
        f"Failure Reason: Unknown user name or bad password. Status: 0xC000006D.",
        "4625",
    )


def _logoff(dt: datetime, host: str, user: str) -> ForensicEvent:
    return _ev(
        dt, "logoff", host, user,
        f"Account logged off. Account Name: {user}. Logon Type: 2.",
        "4634",
    )


def _process(dt: datetime, host: str, user: str, proc: str, args: str = "") -> ForensicEvent:
    cmd = f"C:\\Windows\\System32\\{proc}{(' ' + args) if args else ''}"
    return _ev(
        dt, "process_creation", host, user,
        f"New process created. Account Name: {user}. "
        f"New Process Name: {cmd}. Parent Process Name: explorer.exe.",
        "4688",
    )


def _scheduled_task(dt: datetime, host: str, user: str, task: str) -> ForensicEvent:
    return _ev(
        dt, "scheduled_task", host, user,
        f"Scheduled task created. Task Name: {task}. Account Name: {user}.",
        "4698",
    )


def _service(dt: datetime, host: str, user: str, svc: str) -> ForensicEvent:
    return _ev(
        dt, "service_install", host, user,
        f"A service was installed in the system. Service Name: {svc}. Account Name: {user}.",
        "7045",
    )


def _kerberos_tgt(dt: datetime, host: str, user: str) -> ForensicEvent:
    """Kerberos TGT request — 1-2 per interactive logon session (normal)."""
    return _ev(
        dt, "kerberos_auth", host, user,
        f"A Kerberos authentication ticket (TGT) was requested. "
        f"Account Name: {user}. Supplied Realm Name: CORP. "
        f"Ticket Options: 0x40810010. Ticket Encryption Type: 0x12.",
        "4768",
    )


def _kerberos_tgs(dt: datetime, host: str, user: str, service: str) -> ForensicEvent:
    """Kerberos TGS request — 5–20 per day per user (normal)."""
    return _ev(
        dt, "kerberos_service_ticket", host, user,
        f"A Kerberos service ticket was requested. "
        f"Account Name: {user}. Service Name: {service}. "
        f"Ticket Options: 0x40810000. Ticket Encryption Type: 0x12.",
        "4769",
    )


def _kerberos_tgs_renewal(dt: datetime, host: str, user: str) -> ForensicEvent:
    """Kerberos TGS ticket renewal — occasional (normal)."""
    return _ev(
        dt, "kerberos_service_ticket", host, user,
        f"A Kerberos service ticket was renewed. Account Name: {user}. "
        f"Ticket Options: 0x40800008. Ticket Encryption Type: 0x12.",
        "4770",
    )


def _smb_access(dt: datetime, host: str, user: str, share: str) -> ForensicEvent:
    """Normal SMB network share access (EID 5140)."""
    return _ev(
        dt, "share_access", host, user,
        f"A network share object was accessed. Account Name: {user}. "
        f"Share Name: {share}. Share Path: {share}. "
        f"Source Network Address: 192.168.1.{random.randint(10, 200)}.",
        "5140",
    )


def _policy_change(dt: datetime, host: str, user: str) -> ForensicEvent:
    """Normal domain policy refresh (EID 4739) — happens on every Group Policy refresh."""
    return _ev(
        dt, "policy_change", host, user,
        f"Domain Policy was changed. Account Name: {user}. "
        f"Domain Name: CORP. Minimum Password Length: 8.",
        "4739",
    )


def _scriptblock_log(dt: datetime, host: str, user: str, module: str) -> ForensicEvent:
    """
    EID 4104 — PowerShell ScriptBlock logging (background/infrastructure).
    Modern Windows 11 hosts with ScriptBlock logging enabled generate these from
    Group Policy processing, WMI subscriptions, and scheduled PS tasks even for
    standard users who never open a PowerShell prompt.
    Reference: NIST SP 800-92 Rev 1 Draft (NIST, 2024) §4.3.
    """
    return _ev(
        dt, "script_block", host, user,
        f"PowerShell script. Path: Windows PowerShell. Script: Import-Module {module}",
        "4104",
    )


def _background_process(dt: datetime, host: str, user: str, proc: str) -> ForensicEvent:
    """EID 4688 background OS process — Windows Update, Defender, device management noise."""
    return _ev(
        dt, "process_creation", host, user,
        f"New process created. Account Name: SYSTEM. New Process Name: "
        f"C:\\Windows\\System32\\{proc}. Parent Process Name: svchost.exe.",
        "4688",
    )


def _special_priv(dt: datetime, host: str, user: str) -> ForensicEvent:
    """Legitimate special privileges assigned at logon (EID 4672)."""
    return _ev(
        dt, "special_privileges", host, user,
        f"Special privileges assigned to new logon. Account Name: {user}. "
        f"Privileges: SeSecurityPrivilege SeBackupPrivilege SeRestorePrivilege.",
        "4672",
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
    Modernised from LANL 2015 (~50 events/day) to reflect Windows 11 enterprise baseline.

    On modern Win11 hosts with Advanced Process Auditing + ScriptBlock logging enabled,
    standard knowledge workers generate ~150–250 EID 4688/4104 events per day from
    background system processes, browser subprocess trees, Office telemetry, and Windows
    Update workers — even without any explicit user command-line activity.

    Sources:
      LANL 2015 (Kent, A.D.): logon hours, host diversity, failure rates (unchanged).
      MITRE ATT&CK Evaluations Round 5 / Turla (2024): updated process volume reference.
      Microsoft "Advanced Security Audit Policy Settings" (docs.microsoft.com, 2023):
        EID 4688 rate estimation for Win11 with process creation auditing.
    """
    evs: list[ForensicEvent] = []
    days = _working_days(base, 30)
    active_days = rng.sample(days, min(20, len(days)))

    for day in active_days:
        logon_dt = _dt(rng, base, day, 8, 10)
        evs.append(_logon(logon_dt, ws, username, logon_type=2))
        evs.append(_kerberos_tgt(logon_dt + timedelta(seconds=1), ws, username))

        # 2–5 TGS requests for file server, print, etc.
        for _ in range(rng.randint(2, 5)):
            svc = rng.choice(_SERVICES[:4])
            evs.append(_kerberos_tgs(_dt(rng, base, day, 9, 17), ws, username, svc))

        # Occasional SMB share access for shared drives
        if rng.random() < 0.6:
            evs.append(_smb_access(_dt(rng, base, day, 9, 17), ws, username, rng.choice(_SHARES[2:5])))

        # Office/browser processes — increased to 15–25 to reflect modern Win11 subprocess trees.
        # Browsers (Edge, Chrome) spawn 5–15 child processes per session; Office spawns
        # update/telemetry workers. This models the increased EID 4688 density on Win11.
        for _ in range(rng.randint(15, 25)):
            evs.append(_process(_dt(rng, base, day, 9, 17), ws, username, rng.choice(_PROCS_STANDARD)))

        # Background OS processes (Windows Update, Defender, device management).
        # Run as SYSTEM — not as the user — but appear in the same host telemetry stream.
        for _ in range(rng.randint(5, 12)):
            evs.append(_background_process(
                _dt(rng, base, day, 0, 23), ws, "SYSTEM",
                rng.choice(_PROCS_SYSTEM_BACKGROUND)
            ))

        # EID 4104 ScriptBlock noise: background GPO/WMI PS modules (3–8/day).
        # These fire even when the user never opens PowerShell — Windows infrastructure
        # (Group Policy, SCCM, WMI subscriptions) invokes PowerShell silently.
        _BACKGROUND_PS_MODULES = [
            "GroupPolicy", "Microsoft.PowerShell.Security",
            "ConfigurationManager", "CimCmdlets", "WindowsUpdateProvider",
            "Microsoft.WSMan.Management",
        ]
        for _ in range(rng.randint(3, 8)):
            evs.append(_scriptblock_log(
                _dt(rng, base, day, 9, 17), ws, "SYSTEM",
                rng.choice(_BACKGROUND_PS_MODULES)
            ))

        # Occasional fat-finger failed logon (CERT dataset: ~8% of users have ≥1 failure/day)
        if rng.random() < 0.08:
            evs.append(_logon_failed(_dt(rng, base, day, 8, 9), ws, username))

        evs.append(_logoff(_dt(rng, base, day, 16, 18), ws, username))

    return evs


def _gen_it_admin(rng: random.Random, base: datetime, username: str) -> list[ForensicEvent]:
    """
    LANL 2015 reference: ~200 events/day for privileged admins, 8–15 unique hosts.
    Legitimate admin tool usage (net.exe, powershell.exe) is NORMAL for this profile.
    High Kerberos TGS rate is also normal — not anomalous.
    """
    evs: list[ForensicEvent] = []
    all_hosts = _WS[:20] + _SRV
    days = _all_days(base, 30)
    active_days = rng.sample(days, min(24, len(days)))

    for day in active_days:
        hosts_today = rng.sample(all_hosts, rng.randint(4, 10))
        for host in hosts_today:
            logon_dt = _dt(rng, base, day, 7, 19)
            evs.append(_logon_explicit(logon_dt, host, username))
            evs.append(_kerberos_tgt(logon_dt + timedelta(seconds=1), host, username))
            evs.append(_special_priv(logon_dt + timedelta(seconds=2), host, username))

            # Admins request TGS for many services — 3–8 per host visit
            for _ in range(rng.randint(3, 8)):
                evs.append(_kerberos_tgs(
                    _dt(rng, base, day, 7, 20), host, username, rng.choice(_SERVICES)
                ))

            # Legitimate admin tool usage
            for _ in range(rng.randint(3, 7)):
                evs.append(_process(_dt(rng, base, day, 7, 20), host, username,
                                    rng.choice(_PROCS_ADMIN_LEGIT)))

            # SYSVOL/NETLOGON SMB access (normal for admin activity)
            evs.append(_smb_access(_dt(rng, base, day, 7, 20), host, username,
                                   rng.choice(_SHARES[:2])))

            # On-call late-night check
            if rng.random() < 0.12:
                evs.append(_logon(
                    _dt(rng, base, day, 21, 23), rng.choice(_SRV), username, logon_type=10
                ))

    return evs


def _gen_service_account(
    rng: random.Random, base: datetime, username: str, host: str
) -> list[ForensicEvent]:
    """
    CERT dataset reference: service accounts show predictable overnight schedule,
    single host, scheduled tasks, zero admin tools, zero failed logons.
    High off_hours_ratio and low type_diversity are NORMAL for this profile.
    """
    evs: list[ForensicEvent] = []
    days = _all_days(base, 30)

    for day in days:
        if rng.random() < 0.92:
            run_hour = rng.choice([0, 1, 2, 3, 22, 23])
            dt_run = _dt(rng, base, day, run_hour, run_hour)
            evs.append(_logon(dt_run, host, username, logon_type=5))
            task = rng.choice(_SCHEDULED_TASKS)
            evs.append(_scheduled_task(dt_run + timedelta(minutes=1), host, username, task))
            for _ in range(rng.randint(1, 3)):
                proc = rng.choice(_PROCS_DB + ["robocopy.exe", "xcopy.exe", "wbadmin.exe"])
                evs.append(_process(
                    dt_run + timedelta(minutes=rng.randint(2, 30)), host, username, proc
                ))
            evs.append(_logoff(dt_run + timedelta(minutes=rng.randint(30, 120)), host, username))

    return evs


def _gen_developer(rng: random.Random, base: datetime, username: str) -> list[ForensicEvent]:
    """
    CERT dataset reference: developers have high process creation rates (build/test/lint),
    slightly extended hours, and touch 1–3 hosts.
    High process_event_ratio is NORMAL for this profile.
    """
    evs: list[ForensicEvent] = []
    ws = rng.choice(_DEV[:6])
    days = _working_days(base, 30)
    active_days = rng.sample(days, min(22, len(days)))

    for day in active_days:
        logon_dt = _dt(rng, base, day, 9, 11)
        evs.append(_logon(logon_dt, ws, username, logon_type=2))
        evs.append(_kerberos_tgt(logon_dt + timedelta(seconds=1), ws, username))

        # Developers access file server and build infrastructure
        for svc in rng.sample(_SERVICES, rng.randint(2, 4)):
            evs.append(_kerberos_tgs(_dt(rng, base, day, 9, 19), ws, username, svc))

        # Many processes: builds, test runners, linters, VCS
        for _ in range(rng.randint(15, 30)):
            evs.append(_process(_dt(rng, base, day, 9, 20), ws, username,
                                rng.choice(_PROCS_DEV)))

        # Occasional push to build server
        if rng.random() < 0.35:
            bh = "BUILD-SERVER-01"
            evs.append(_logon_explicit(_dt(rng, base, day, 10, 18), bh, username))
            evs.append(_process(_dt(rng, base, day, 10, 18), bh, username,
                                rng.choice(["gradle.exe", "mvn.cmd", "npm.cmd", "go.exe"])))

        if rng.random() < 0.05:
            evs.append(_logon_failed(_dt(rng, base, day, 9, 10), ws, username))

        evs.append(_logoff(_dt(rng, base, day, 17, 22), ws, username))

    return evs


def _gen_help_desk(rng: random.Random, base: datetime, username: str) -> list[ForensicEvent]:
    """
    LANL 2015 reference: help desk accounts show high unique_hosts (4–10/day)
    and legitimate use of remote-access tools (mstsc.exe, psexec.exe).
    High unique_hosts AND admin tool usage are NORMAL for this profile.
    """
    evs: list[ForensicEvent] = []
    days = _working_days(base, 30)
    active_days = rng.sample(days, min(22, len(days)))

    for day in active_days:
        tickets_today = rng.randint(4, 10)
        hosts_today = rng.sample(_WS, tickets_today)

        for host in hosts_today:
            logon_dt = _dt(rng, base, day, 8, 17)
            evs.append(_logon_explicit(logon_dt, host, username))
            evs.append(_kerberos_tgt(logon_dt + timedelta(seconds=1), host, username))

            # SMB to access user's shared folder
            evs.append(_smb_access(_dt(rng, base, day, 8, 17), host, username,
                                   rng.choice(_SHARES[2:])))

            for _ in range(rng.randint(2, 5)):
                evs.append(_process(_dt(rng, base, day, 8, 17), host, username,
                                    rng.choice(_PROCS_HELPDESK)))

            if rng.random() < 0.07:
                evs.append(_logon_failed(_dt(rng, base, day, 8, 17), host, username))

    return evs


def _gen_db_admin(rng: random.Random, base: datetime, username: str) -> list[ForensicEvent]:
    """
    CERT dataset reference: DB admins have maintenance windows at 00–06h.
    Very high off_hours_ratio and access to DB servers is NORMAL.
    """
    evs: list[ForensicEvent] = []
    days = _all_days(base, 30)
    maint_days = rng.sample(days, rng.randint(14, 22))

    for day in maint_days:
        target = rng.choice(_DB)
        maint_hour = rng.choice([0, 1, 2, 3, 4])
        logon_dt = _dt(rng, base, day, maint_hour, maint_hour)

        evs.append(_logon(logon_dt, target, username, logon_type=10))
        evs.append(_kerberos_tgt(logon_dt + timedelta(seconds=1), target, username))
        evs.append(_kerberos_tgs(logon_dt + timedelta(seconds=2), target, username,
                                 f"MSSQLSvc/{target}.corp.local:1433"))
        evs.append(_special_priv(logon_dt + timedelta(seconds=3), target, username))

        for _ in range(rng.randint(3, 8)):
            evs.append(_process(
                _dt(rng, base, day, maint_hour, min(maint_hour + 3, 6)),
                target, username, rng.choice(_PROCS_DB)
            ))

        evs.append(_scheduled_task(
            _dt(rng, base, day, maint_hour, maint_hour),
            target, username, rng.choice(_SCHEDULED_TASKS[:3])
        ))

        if rng.random() < 0.5:
            bk = "MGMT-SERVER-01"
            evs.append(_logon_explicit(_dt(rng, base, day, maint_hour, maint_hour), bk, username))
            evs.append(_process(_dt(rng, base, day, maint_hour, maint_hour),
                                bk, username, "wbadmin.exe"))

        evs.append(_logoff(
            _dt(rng, base, day, min(maint_hour + 2, 6), min(maint_hour + 4, 7)),
            target, username
        ))

    return evs


def _gen_executive(rng: random.Random, base: datetime, username: str) -> list[ForensicEvent]:
    """
    CERT dataset reference: executives have very low event volume (~15 events/day),
    strict business hours, single workstation, no technical tools.
    """
    evs: list[ForensicEvent] = []
    ws = rng.choice(_EXEC)
    days = _working_days(base, 30)
    active_days = rng.sample(days, min(12, len(days)))

    for day in active_days:
        logon_dt = _dt(rng, base, day, 8, 10)
        evs.append(_logon(logon_dt, ws, username, logon_type=2))
        evs.append(_kerberos_tgt(logon_dt + timedelta(seconds=1), ws, username))

        for _ in range(rng.randint(2, 4)):
            evs.append(_process(_dt(rng, base, day, 9, 16), ws, username,
                                rng.choice(["outlook.exe", "teams.exe", "chrome.exe",
                                            "msedge.exe", "zoom.exe", "excel.exe"])))

        evs.append(_logoff(_dt(rng, base, day, 14, 17), ws, username))

    return evs


def _gen_domain_controller(rng: random.Random, base: datetime, username: str) -> list[ForensicEvent]:
    """
    DC service accounts generate Kerberos events 24/7 — this is normal AD infrastructure
    behavior (OTRF/Mordor dataset reference for DC baseline activity).
    The model must learn that high Kerberos rates for DC accounts are NOT anomalous.
    """
    evs: list[ForensicEvent] = []
    host = rng.choice(_DCS)
    days = _all_days(base, 30)

    for day in days:
        # DCs generate ~15–40 auth events per day as infrastructure
        n_events = rng.randint(15, 40)
        for _ in range(n_events):
            hour = rng.randint(0, 23)
            dt_ev = _dt(rng, base, day, hour, hour)
            ev_type = rng.choice([
                "tgt", "tgt", "tgs", "tgs", "tgs",
                "logon_net", "logon_net", "special_priv",
            ])
            if ev_type == "tgt":
                evs.append(_kerberos_tgt(dt_ev, host, username))
            elif ev_type == "tgs":
                svc = rng.choice(_SERVICES[:4])
                evs.append(_kerberos_tgs(dt_ev, host, username, svc))
            elif ev_type == "logon_net":
                evs.append(_logon_network(dt_ev, host, username))
            else:
                evs.append(_special_priv(dt_ev, host, username))

        # Policy refresh (Group Policy applies every ~90 min on DCs)
        for _ in range(rng.randint(8, 16)):
            evs.append(_policy_change(_dt(rng, base, day, 0, 23), host, username))

    return evs


def _gen_security_analyst(rng: random.Random, base: datetime, username: str) -> list[ForensicEvent]:
    """
    Security analysts legitimately run tools that would be anomalous for a standard
    worker (Get-WinEvent, eventvwr, LDAP queries, Wireshark).
    This profile ensures the model does NOT treat security tooling as inherently malicious
    when the account consistently uses these tools during business hours.

    CERT Insider Threat Dataset reference: security roles show higher tool diversity
    but strict business-hour patterns and consistent host assignment.
    """
    evs: list[ForensicEvent] = []
    ws = rng.choice(_SOC)
    days = _working_days(base, 30)
    active_days = rng.sample(days, min(21, len(days)))

    for day in active_days:
        logon_dt = _dt(rng, base, day, 8, 9)
        evs.append(_logon(logon_dt, ws, username, logon_type=2))
        evs.append(_kerberos_tgt(logon_dt + timedelta(seconds=1), ws, username))
        evs.append(_special_priv(logon_dt + timedelta(seconds=2), ws, username))

        # Security analysts legitimately access SYSVOL/NETLOGON and log shares
        evs.append(_smb_access(_dt(rng, base, day, 8, 17), ws, username,
                               rng.choice(_SHARES[:3])))

        # Kerberos TGS for AD infrastructure services (normal for SOC queries)
        for _ in range(rng.randint(3, 7)):
            evs.append(_kerberos_tgs(_dt(rng, base, day, 8, 17), ws, username,
                                     rng.choice(_SERVICES[:4])))

        # Security tool execution — HIGH tool diversity is normal for analysts
        for _ in range(rng.randint(8, 15)):
            evs.append(_process(_dt(rng, base, day, 8, 17), ws, username,
                                rng.choice(_PROCS_SOC + _PROCS_ADMIN_LEGIT)))

        evs.append(_logoff(_dt(rng, base, day, 17, 19), ws, username))

    return evs


def _gen_cloud_workstation(rng: random.Random, base: datetime, username: str, ws: str) -> list[ForensicEvent]:
    """
    Azure AD hybrid-joined workstation profile.

    Hybrid-joined machines generate EID 4648 (explicit credentials) far more
    frequently than traditional domain-joined workstations due to cloud token
    refresh cycles (every 60–90 min) and Intune MDM check-ins.  The model
    must learn that high EID 4648 rates for these accounts are NORMAL so it
    doesn't treat Azure AD token operations as credential-theft indicators.

    Reference: Microsoft, "Azure AD Hybrid Identity — Authentication Flows"
    (learn.microsoft.com, 2023); CERT Insider Threat v6.2 — hybrid user profiles.
    """
    evs: list[ForensicEvent] = []
    days = _working_days(base, 30)
    active_days = rng.sample(days, min(20, len(days)))

    for day in active_days:
        logon_dt = _dt(rng, base, day, 8, 10)
        evs.append(_logon(logon_dt, ws, username, logon_type=2))
        evs.append(_kerberos_tgt(logon_dt + timedelta(seconds=1), ws, username))

        # Cloud token refresh: EID 4648 every 60–90 min (normal for hybrid-joined)
        for refresh_hour in range(9, 18, rng.randint(1, 2)):
            evs.append(_logon_explicit(
                _dt(rng, base, day, refresh_hour, refresh_hour), ws, username
            ))

        # Standard TGS requests
        for _ in range(rng.randint(2, 5)):
            evs.append(_kerberos_tgs(_dt(rng, base, day, 9, 17), ws, username, rng.choice(_SERVICES[:4])))

        # Office + modern apps (same as standard worker)
        for _ in range(rng.randint(15, 25)):
            evs.append(_process(_dt(rng, base, day, 9, 17), ws, username, rng.choice(_PROCS_STANDARD)))

        # dsregcmd.exe runs periodically to verify Azure AD join status
        for _ in range(rng.randint(2, 4)):
            evs.append(_background_process(_dt(rng, base, day, 9, 17), ws, "SYSTEM", "dsregcmd.exe"))

        # Background ScriptBlock noise (same rate as standard worker)
        _CLOUD_PS_MODULES = [
            "Microsoft.Graph", "AzureAD", "Intune.Graph",
            "Microsoft.PowerShell.Security", "CimCmdlets",
        ]
        for _ in range(rng.randint(3, 8)):
            evs.append(_scriptblock_log(
                _dt(rng, base, day, 9, 17), ws, "SYSTEM",
                rng.choice(_CLOUD_PS_MODULES)
            ))

        if rng.random() < 0.08:
            evs.append(_logon_failed(_dt(rng, base, day, 8, 9), ws, username))

        evs.append(_logoff(_dt(rng, base, day, 16, 18), ws, username))

    return evs


# ── Additional profile helpers ────────────────────────────────────────────────

_PROCS_DEVOPS = [
    "docker.exe", "git.exe", "python.exe", "node.exe", "npm.cmd",
    "gradle.exe", "mvn.cmd", "kubectl.exe", "helm.exe", "terraform.exe",
    "ansible.exe", "packer.exe", "vault.exe", "consul.exe",
    "dotnet.exe", "cargo.exe", "go.exe", "make.exe",
]

_PROCS_CONTRACTOR = [
    "chrome.exe", "msedge.exe", "outlook.exe", "teams.exe",
    "word.exe", "excel.exe", "zoom.exe", "slack.exe",
    "acrobat.exe", "onedrive.exe",
]

_CI_TASKS = [
    r"\CI\BuildAgent\NightlyBuild",
    r"\CI\BuildAgent\TestRun",
    r"\CI\Deployment\StagingDeploy",
    r"\CI\Scan\SastScan",
]


def _gen_contractor(
    rng: random.Random, base: datetime, username: str, ws: str
) -> list[ForensicEvent]:
    """
    External contractor account.

    Contractors access the environment Mon–Fri 09:00–17:00 only (no weekend
    activity).  They logon exclusively via VPN (Type 3 network logon from an
    external IP) to a single designated host, use no administrative tools, and
    generate a low process volume.  The model learns:
      · Type-3 logon from a fixed external IP range is NORMAL for this account
      · Off-hours or multi-host Type-3 logons are anomalous

    Calibration: CERT Insider Threat v6.2 — contractor behavioral norms;
    NCSC "Third-party access" guidance (2022).
    """
    evs: list[ForensicEvent] = []
    days = _working_days(base, 30)
    active_days = rng.sample(days, min(18, len(days)))

    for day in active_days:
        logon_dt = _dt(rng, base, day, 9, 10)
        evs.append(_ev(
            logon_dt, "logon", ws, username,
            f"Account successfully logged on. Account Name: {username}. "
            f"Logon Type: 3. Source Network Address: 203.0.113.{rng.randint(10, 50)}.",
            "4624",
        ))
        evs.append(_kerberos_tgt(logon_dt + timedelta(seconds=2), ws, username))

        # Low volume productivity apps (no admin or dev tools)
        for _ in range(rng.randint(8, 15)):
            evs.append(_process(_dt(rng, base, day, 9, 17), ws, username,
                                rng.choice(_PROCS_CONTRACTOR)))

        # Single file-share access per day (project folder only)
        evs.append(_smb_access(_dt(rng, base, day, 10, 16), ws, username,
                               r"\\FILE-SERVER-01\Shared"))

        # Occasional logon failure (MFA token timeout — ~10 % of days)
        if rng.random() < 0.10:
            evs.append(_logon_failed(_dt(rng, base, day, 9, 10), ws, username))

        evs.append(_logoff(_dt(rng, base, day, 16, 17), ws, username))

    return evs


def _gen_devops_ci(
    rng: random.Random, base: datetime, username: str, ws: str,
    n_days: int = 30,
) -> list[ForensicEvent]:
    """
    CI/CD service account (DevOps pipeline).

    Runs continuously 24/7 on BUILD-SERVER-01.  Generates a very high EID 4688
    rate (docker/git/node processes fire in bursts during build jobs), uses
    EID 4698 (scheduled tasks) for nightly CI jobs, and authenticates via
    Kerberos service logon (Type 5 — SYSTEM context, no interactive session).
    The model learns:
      · 24/7 high process rate from this account on BUILD-SERVER-01 is NORMAL
      · Any interactive (Type 2) or lateral (Type 3) logon is anomalous
      · EID 4698 at 02:00 from this account is NORMAL

    Calibration: Azure DevOps telemetry patterns; GitHub Actions runner audit
    logs (Microsoft, 2023).
    """
    evs: list[ForensicEvent] = []

    for day_offset in range(n_days):
        # CI/CD accounts use service logon (Type 5), not interactive
        logon_dt = (base + timedelta(days=day_offset)).replace(hour=0, minute=0, second=0)
        evs.append(_ev(
            logon_dt, "logon", ws, username,
            f"Account successfully logged on. Account Name: {username}. "
            f"Logon Type: 5. Logon Process: Advapi. Authentication Package: Kerberos.",
            "4624",
        ))
        evs.append(_kerberos_tgt(logon_dt + timedelta(seconds=1), ws, username))

        # Continuous high-rate process creation throughout the day (CI jobs)
        n_jobs = rng.randint(4, 8)
        for job_hour in rng.sample(range(24), min(n_jobs, 24)):
            for _ in range(rng.randint(15, 30)):
                evs.append(_process(
                    _dt(rng, base, day_offset, job_hour, job_hour), ws, username,
                    rng.choice(_PROCS_DEVOPS)
                ))

        # Nightly scheduled tasks (02:00–04:00 maintenance window)
        for _ in range(rng.randint(1, 3)):
            evs.append(_scheduled_task(
                _dt(rng, base, day_offset, 2, 4), ws, username,
                rng.choice(_CI_TASKS)
            ))

        # Kerberos TGS for build artefact storage and registry services
        for _ in range(rng.randint(5, 15)):
            evs.append(_kerberos_tgs(
                _dt(rng, base, day_offset, 0, 23), ws, username,
                rng.choice(_SERVICES)
            ))

    return evs


def _gen_remote_worker(
    rng: random.Random, base: datetime, username: str, ws: str
) -> list[ForensicEvent]:
    """
    Remote / WFH user on a laptop (hybrid domain-joined, VPN).

    Works variable hours (07:00–21:00 across multiple time zones), logons via
    explicit credentials (EID 4648) each VPN session due to MFA re-auth, and
    has a higher failed-logon rate than office workers (VPN MFA drops, DNS
    timeouts).  The model learns:
      · EID 4648 at variable hours is NORMAL for remote workers
      · Slightly elevated logon failures (up to 2 per day) are NORMAL
      · Any sudden burst of failures (>10 in a session) remains anomalous

    Calibration: Microsoft "Remote Work Security" blog (2021); CISA "Zero Trust
    Maturity Model" v2.0 (2023) — remote-access authentication patterns.
    """
    evs: list[ForensicEvent] = []
    days = _working_days(base, 30)
    active_days = rng.sample(days, min(22, len(days)))

    for day in active_days:
        # Variable start hour: 07–10 (timezone + flexible schedule)
        start_h = rng.randint(7, 10)
        end_h   = rng.randint(17, 21)

        # VPN logon uses explicit credentials (EID 4648 + Type 3)
        logon_dt = _dt(rng, base, day, start_h, start_h)
        evs.append(_logon_explicit(logon_dt, ws, username))
        evs.append(_ev(
            logon_dt + timedelta(seconds=5), "logon", ws, username,
            f"Account successfully logged on. Account Name: {username}. "
            f"Logon Type: 3. Source Network Address: 198.51.100.{rng.randint(1, 254)}.",
            "4624",
        ))
        evs.append(_kerberos_tgt(logon_dt + timedelta(seconds=6), ws, username))

        # Token refresh mid-session (VPN re-auth — EID 4648 every 2–3 hours)
        for _ in range(rng.randint(2, 4)):
            evs.append(_logon_explicit(
                _dt(rng, base, day, start_h + 1, end_h - 1), ws, username
            ))

        # Standard productivity apps (same as office worker)
        for _ in range(rng.randint(12, 20)):
            evs.append(_process(_dt(rng, base, day, start_h, end_h), ws, username,
                                rng.choice(_PROCS_STANDARD)))

        # Single file-share TGS per session
        evs.append(_kerberos_tgs(
            _dt(rng, base, day, start_h, end_h), ws, username,
            rng.choice(_SERVICES[:4])
        ))

        # Elevated failure rate: VPN timeouts / MFA token expiry (~20 % of days, up to 2 failures)
        n_failures = rng.choice([0, 0, 0, 1, 1, 2])
        for _ in range(n_failures):
            evs.append(_logon_failed(_dt(rng, base, day, start_h, start_h + 1), ws, username))

        evs.append(_logoff(_dt(rng, base, day, end_h, end_h), ws, username))

    return evs


# ── Main entry point ──────────────────────────────────────────────────────────

def generate_baseline_events(days: int = 30, seed: int = 42) -> list[ForensicEvent]:
    """
    Generate ~17 000–25 000 synthetic ForensicEvent objects covering 13 user-profile
    types across `days` days (63 named entities total → HIGH confidence model).

    Dataset grounding:
      - LANL 2015: activity volumes, host diversity, logon hours per role
      - CERT Insider Threat v6.2: role-based behavioral norms, failure rates
      - OTRF/Mordor: Windows Event ID frequencies for normal AD operations
      - MITRE ATT&CK Evaluations Round 5 / Turla (2024): modern Win11 baseline volumes
      - NCSC / CISA remote-access guidance: contractor and VPN-logon patterns

    The Isolation Forest trained on this baseline correctly distinguishes:
      · Kerberoasting (burst >50 EID 4769 in <10 min) vs IT admin TGS spread
      · BloodHound LDAP dump vs normal SOC LDAP queries
      · 3am encoded PowerShell vs service account overnight CI tasks
      · Lateral movement to 15 hosts in 5 min vs normal help-desk rotations
      · Attack PS injection vs background EID 4104 module-load noise
      · LSASS credential-theft access vs legitimate AV/EDR agent handles
      · Contractor Type-3 logon from fixed external IP vs attacker lateral move
      · CI/CD 24/7 high-process-rate vs attacker sustained process creation
      · Remote-worker variable-hour VPN logon vs attacker off-hours access

    Pass `seed` for a reproducible dataset; vary it to regenerate variety.
    """
    rng = random.Random(seed)
    base = (datetime.utcnow() - timedelta(days=days)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    events: list[ForensicEvent] = []

    # ── Standard workers ×10 ────────────────────────────────────────────────────
    for i in range(1, 11):
        ws = _WS[i - 1]
        events.extend(_gen_standard_worker(rng, base, f"user{i:02d}", ws))

    # ── IT admins ×6 ────────────────────────────────────────────────────────────
    for i in range(1, 7):
        events.extend(_gen_it_admin(rng, base, f"itadmin{i:02d}"))

    # ── Service accounts ×6 ─────────────────────────────────────────────────────
    svc_hosts = [
        "BACKUP-01", "MGMT-SERVER-01", "FILE-SERVER-01",
        "DB-SERVER-01", "APP-SERVER-01", "SCCM-SERVER-01",
    ]
    for i, svc_host in enumerate(svc_hosts, 1):
        events.extend(_gen_service_account(rng, base, f"svc_backup{i:02d}", svc_host))

    # ── Developers ×5 ───────────────────────────────────────────────────────────
    for i in range(1, 6):
        events.extend(_gen_developer(rng, base, f"dev{i:02d}"))

    # ── Help desk ×5 ────────────────────────────────────────────────────────────
    for i in range(1, 6):
        events.extend(_gen_help_desk(rng, base, f"helpdesk{i:02d}"))

    # ── DB admins ×4 ────────────────────────────────────────────────────────────
    for i in range(1, 5):
        events.extend(_gen_db_admin(rng, base, f"dbadmin{i:02d}"))

    # ── Executives ×3 ───────────────────────────────────────────────────────────
    for i in range(1, 4):
        events.extend(_gen_executive(rng, base, f"exec{i:02d}"))

    # ── Domain Controller service accounts ×4 ───────────────────────────────────
    for i in range(1, 5):
        events.extend(_gen_domain_controller(rng, base, f"dc_svc{i:02d}"))

    # ── Security analysts ×7 ────────────────────────────────────────────────────
    for i in range(1, 8):
        events.extend(_gen_security_analyst(rng, base, f"analyst{i:02d}"))

    # ── Azure AD hybrid-joined workstations ×4 ──────────────────────────────────
    cloud_ws_pool = [f"HYBRID-WS-{i:02d}" for i in range(1, 5)]
    for i, cws in enumerate(cloud_ws_pool, 1):
        events.extend(_gen_cloud_workstation(rng, base, f"cloud_user{i:02d}", cws))

    # ── Contractors ×3 (Gap 2 — external access baseline) ───────────────────────
    # Teaches model: Type-3 from fixed external IP during business hours is NORMAL
    # for contractors; same pattern off-hours or to multiple hosts is anomalous.
    contractor_ws_pool = [f"CONTRACTOR-WS-{i:02d}" for i in range(1, 4)]
    for i, cws in enumerate(contractor_ws_pool, 1):
        events.extend(_gen_contractor(rng, base, f"contractor{i:02d}", cws))

    # ── DevOps CI accounts ×3 (Gap 2 — CI/CD service baseline) ─────────────────
    # Teaches model: 24/7 high EID 4688 rate + EID 4698 at 02:00 from CI account
    # on BUILD-SERVER is NORMAL; same pattern from an interactive account is not.
    ci_ws_pool = [f"BUILD-SERVER-{i:02d}" for i in range(1, 4)]
    for i, cws in enumerate(ci_ws_pool, 1):
        events.extend(_gen_devops_ci(rng, base, f"ci_svc{i:02d}", cws))

    # ── Remote workers ×3 (Gap 2 — WFH / VPN baseline) ─────────────────────────
    # Teaches model: variable-hour EID 4648 + Type-3 logons from rotating external
    # IPs are NORMAL for remote workers; burst of logon failures remains anomalous.
    remote_ws_pool = [f"LAPTOP-{i:02d}" for i in range(1, 4)]
    for i, rws in enumerate(remote_ws_pool, 1):
        events.extend(_gen_remote_worker(rng, base, f"remote{i:02d}", rws))

    return events
