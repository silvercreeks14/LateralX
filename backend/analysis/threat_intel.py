"""
Threat Intelligence Enrichment — VirusTotal & AbuseIPDB

Appends reputation scores to extracted IOC context strings.
Gracefully no-ops when API keys are absent — zero impact on existing flow.

Integration note: call enrich_iocs() AFTER ioc_mod.extract_iocs() in
run_analysis() and run_consensus() ONLY. Do NOT call it in ml_quick_scan()
because quick scan is designed to be instant and external HTTP calls would
break that contract.
"""

import os
import requests
from dotenv import load_dotenv
from backend.schema import IOC

# Load .env here so keys are available regardless of import order.
# load_dotenv() is idempotent — safe to call multiple times across modules.
load_dotenv()

_MAX_LOOKUPS = 4   # stay within free-tier rate limits per analysis
_TIMEOUT     = 8   # seconds per external request

# Module-level cache: {value: enriched_context_suffix}
# Avoids duplicate HTTP calls within a single server process lifetime.
_cache: dict[str, str] = {}


def get_status() -> dict:
    """Return which threat intel providers are configured."""
    return {
        "vt_configured":       bool(os.getenv("VT_API_KEY", "").strip()),
        "abuseipdb_configured": bool(os.getenv("ABUSEIPDB_KEY", "").strip()),
    }


def _vt_lookup(value: str, ioc_type: str) -> str:
    """Return a [VT: N/94 malicious] tag or empty string on failure."""
    key = os.getenv("VT_API_KEY", "").strip()
    if not key:
        return ""
    try:
        if ioc_type == "ip":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{value}"
        elif ioc_type == "domain":
            url = f"https://www.virustotal.com/api/v3/domains/{value}"
        else:
            return ""
        resp = requests.get(
            url,
            headers={"x-apikey": key},
            timeout=_TIMEOUT,
        )
        if resp.status_code == 200:
            stats = (
                resp.json()
                .get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )
            malicious = stats.get("malicious", 0)
            total     = sum(stats.values()) if stats else 94
            return f"[VT: {malicious}/{total} malicious]"
    except Exception:
        pass
    return ""


def _abuseipdb_lookup(ip: str) -> str:
    """Return an [AbuseIPDB: N%] tag or empty string on failure."""
    key = os.getenv("ABUSEIPDB_KEY", "").strip()
    if not key:
        return ""
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": key, "Accept": "application/json"},
            timeout=_TIMEOUT,
        )
        if resp.status_code == 200:
            score = resp.json().get("data", {}).get("abuseConfidenceScore", None)
            if score is not None:
                return f"[AbuseIPDB: {score}% confidence]"
    except Exception:
        pass
    return ""


def enrich_iocs(iocs: list[IOC]) -> list[IOC]:
    """
    Enrich IP and domain IOCs with reputation data from VirusTotal and AbuseIPDB.

    - At most _MAX_LOOKUPS external calls per invocation (free-tier protection).
    - Already-seen values are served from the in-process cache without HTTP.
    - If both API keys are absent, returns the original list unchanged.
    - Never raises: all external failures are silently swallowed.
    """
    vt_key      = os.getenv("VT_API_KEY", "").strip()
    abuseipdb_key = os.getenv("ABUSEIPDB_KEY", "").strip()
    if not vt_key and not abuseipdb_key:
        return iocs   # no-op — keys not configured

    enriched: list[IOC] = []
    calls_made = 0

    for ioc in iocs:
        if ioc.type not in ("ip", "domain"):
            enriched.append(ioc)
            continue

        if ioc.value in _cache:
            suffix = _cache[ioc.value]
        elif calls_made >= _MAX_LOOKUPS:
            suffix = ""
        else:
            parts: list[str] = []

            vt_tag = _vt_lookup(ioc.value, ioc.type)
            if vt_tag:
                calls_made += 1
                parts.append(vt_tag)

            if ioc.type == "ip" and calls_made < _MAX_LOOKUPS:
                ab_tag = _abuseipdb_lookup(ioc.value)
                if ab_tag:
                    calls_made += 1
                    parts.append(ab_tag)

            suffix = " ".join(parts)
            _cache[ioc.value] = suffix

        new_context = f"{ioc.context} {suffix}".strip() if suffix else ioc.context
        enriched.append(ioc.model_copy(update={"context": new_context}))

    return enriched
