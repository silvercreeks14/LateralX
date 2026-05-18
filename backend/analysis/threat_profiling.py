"""
Threat actor profiling via MITRE ATT&CK technique overlap.

Compares a session's detected technique IDs against documented technique sets
for 12 well-known threat groups (sourced from MITRE ATT&CK Groups page).
Returns ranked matches with overlap statistics and confidence tiers.

Standalone module — imports only stdlib. No circular import risk.
"""

import json
import logging
from pathlib import Path

log = logging.getLogger(__name__)

_DATA_FILE = Path(__file__).parent.parent / "data" / "threat_groups.json"


def _load_groups() -> list[dict]:
    try:
        with open(_DATA_FILE, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        log.warning("threat_groups.json unavailable: %s", exc)
        return []


_GROUPS: list[dict] = _load_groups()


def profile_attack(detected_technique_ids: list[str]) -> list[dict]:
    """
    Given a list of detected MITRE technique IDs, compute overlap with known
    threat actor technique sets and return the top 5 matches.

    Only groups with >= 2 overlapping techniques are considered.
    Results are sorted by overlap_pct descending (how much of the group's
    documented toolkit was observed in this session).

    Confidence tiers:
        low    — overlap_pct < 15
        medium — overlap_pct 15–30
        high   — overlap_pct > 30

    Note: Technique overlap is probabilistic. Attribution requires additional
    intelligence beyond technique co-occurrence.
    """
    if not detected_technique_ids or not _GROUPS:
        return []

    detected = set(detected_technique_ids)
    results: list[dict] = []

    for group in _GROUPS:
        group_techniques = set(group.get("techniques", []))
        if not group_techniques:
            continue

        overlap = detected & group_techniques
        if len(overlap) < 2:
            continue

        overlap_pct  = len(overlap) / len(group_techniques) * 100
        coverage_pct = len(overlap) / len(detected) * 100

        if overlap_pct < 15:
            confidence = "low"
        elif overlap_pct <= 30:
            confidence = "medium"
        else:
            confidence = "high"

        results.append({
            "group":               group["name"],
            "aliases":             group.get("also_known_as", []),
            "origin":              group.get("origin", "Unknown"),
            "overlap_techniques":  sorted(overlap),
            "overlap_pct":         round(overlap_pct, 1),
            "coverage_pct":        round(coverage_pct, 1),
            "confidence":          confidence,
        })

    results.sort(key=lambda x: x["overlap_pct"], reverse=True)
    return results[:5]
