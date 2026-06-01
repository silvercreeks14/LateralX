"""
IOC (Indicator of Compromise) extractor.
Regex-based extraction from event descriptions.
Exports to CSV and STIX 2.1 bundle format.
"""

import re
import uuid
from datetime import datetime, timezone
from backend.schema import ForensicEvent, IOC

# Private/loopback prefixes to filter out of IP results
_PRIVATE = (
    "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "127.", "0.", "255.",
)

# Well-known benign public IPs — DNS resolvers, NTP servers, Microsoft infra
_BENIGN_IPS = {
    "8.8.8.8", "8.8.4.4",           # Google Public DNS
    "1.1.1.1", "1.0.0.1",           # Cloudflare DNS
    "9.9.9.9", "149.112.112.112",   # Quad9 DNS
    "208.67.222.222", "208.67.220.220",  # OpenDNS
    "4.2.2.1", "4.2.2.2",           # Level3 DNS
    "13.107.4.52", "13.107.6.52",   # Microsoft 365
    "20.112.52.29", "20.189.173.0", # Microsoft Azure
}

_BENIGN_DOMAINS = {
    # Microsoft infrastructure
    "microsoft.com", "windows.com", "windowsupdate.com", "office.com",
    "live.com", "msn.com", "bing.com", "msftncsi.com", "windowsliveid.com",
    "azure.com", "azurewebsites.net", "azureedge.net", "trafficmanager.net",
    "visualstudio.com", "vsassets.io", "nuget.org",
    # Certificate authorities and revocation (OCSP/CRL traffic is benign)
    "digicert.com", "verisign.com", "symantec.com", "thawte.com",
    "geotrust.com", "comodo.com", "sectigo.com", "letsencrypt.org",
    "ocsp.msocsp.com", "crl.microsoft.com",
    # Common CDN / cloud providers
    "amazonaws.com", "cloudfront.net", "fastly.com", "akamai.com",
    "google.com", "googleapis.com", "gstatic.com", "github.com",
    "githubusercontent.com", "cloudflare.com",
}

_RE = {
    "ip":           re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    "url":          re.compile(r'https?://[^\s\'"<>]+'),
    "sha256":       re.compile(r'\b[0-9a-fA-F]{64}\b'),
    "md5":          re.compile(r'\b[0-9a-fA-F]{32}\b'),
    "file_path":    re.compile(r'[A-Za-z]:\\(?:[^\\\/:*?"<>|\r\n]+\\)*[^\\\/:*?"<>|\r\n]+'),
    "domain":       re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
        r'+(?:com|net|org|io|co|ru|cn|top|xyz|info|biz|onion)\b'
    ),
    "registry_key": re.compile(r'(?:HKEY_\w+|HKLM|HKCU|HKU|HKCR)\\[^\s]+'),
}

_SUSPICIOUS_PATH_FRAGMENTS = ("temp", "appdata", "programdata", "users\\", "public\\")


def extract_iocs(events: list[ForensicEvent]) -> list[IOC]:
    """Return a deduplicated list of IOCs extracted from all event descriptions."""
    seen: set[str] = set()
    iocs: list[IOC] = []

    for event in events:
        text = event.description
        ctx = text[:150]

        for ip in _RE["ip"].findall(text):
            if (ip not in seen
                    and not any(ip.startswith(p) for p in _PRIVATE)
                    and ip not in _BENIGN_IPS):
                seen.add(ip)
                iocs.append(IOC(type="ip", value=ip, context=ctx))

        for url in _RE["url"].findall(text):
            url = url.rstrip(".,;)")
            if url not in seen:
                seen.add(url)
                iocs.append(IOC(type="url", value=url, context=ctx))

        for h in _RE["sha256"].findall(text):
            if h not in seen:
                seen.add(h)
                iocs.append(IOC(type="sha256", value=h, context=ctx))

        for h in _RE["md5"].findall(text):
            if h not in seen:
                seen.add(h)
                iocs.append(IOC(type="md5", value=h, context=ctx))

        for path in _RE["file_path"].findall(text):
            low = path.lower()
            if path not in seen and any(f in low for f in _SUSPICIOUS_PATH_FRAGMENTS):
                seen.add(path)
                iocs.append(IOC(type="file_path", value=path, context=ctx))

        for domain in _RE["domain"].findall(text):
            d = domain.lower()
            if d not in seen and not any(b in d for b in _BENIGN_DOMAINS):
                seen.add(d)
                iocs.append(IOC(type="domain", value=d, context=ctx))

        for key in _RE["registry_key"].findall(text):
            if key not in seen:
                seen.add(key)
                iocs.append(IOC(type="registry_key", value=key, context=ctx))

    return iocs


def iocs_to_csv(iocs: list[IOC]) -> str:
    """Serialize IOC list to CSV."""
    lines = ["type,value,context"]
    for ioc in iocs:
        ctx = ioc.context.replace('"', '""')
        lines.append(f'{ioc.type},"{ioc.value}","{ctx}"')
    return "\n".join(lines)


def iocs_to_stix(iocs: list[IOC]) -> dict:
    """Serialize IOC list to a STIX 2.1 bundle."""
    now = datetime.now(timezone.utc).isoformat()
    objects = []

    for ioc in iocs:
        match ioc.type:
            case "ip":
                pattern = f"[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '{ioc.value}']"
            case "url":
                pattern = f"[url:value = '{ioc.value}']"
            case "domain":
                pattern = f"[domain-name:value = '{ioc.value}']"
            case "md5":
                pattern = f"[file:hashes.MD5 = '{ioc.value}']"
            case "sha256":
                pattern = f"[file:hashes.'SHA-256' = '{ioc.value}']"
            case _:
                continue  # file_path and registry_key have no standard STIX pattern

        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            "name": f"{ioc.type}: {ioc.value}",
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": now,
            "indicator_types": ["malicious-activity"],
            "description": ioc.context,
        })

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }
