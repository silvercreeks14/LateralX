"""
PCAP / PCAPng parser using pyshark (requires tshark / Wireshark on PATH).
Normalises network packets into ForensicEvent objects.

Flow-level deduplication: TCP/UDP/QUIC emit one event per unique
(src_ip, dst_ip, dst_port) tuple so a long capture doesn't flood the
timeline with thousands of identical connection rows.

Payload-bearing protocols (DNS, HTTP, TLS, SMB, Kerberos …) each emit
one event per packet because every packet carries distinct forensic info.

Hard cap: MAX_PACKETS events total — the sampler in llm.py handles
datasets larger than 400 events intelligently downstream.
"""

import asyncio
import os
import tempfile
from datetime import datetime, timezone
from backend.schema import ForensicEvent, RawSource

MAX_PACKETS = 5_000

# These protocols carry unique payload data on every packet
_PAYLOAD_PROTOCOLS = {
    "DNS", "HTTP", "TLS", "KERBEROS", "LDAP",
    "SMB", "SMB2", "FTP", "SMTP", "IMAP", "NBNS",
}

# These are bulk flow protocols — deduplicated by (src, dst, port)
_FLOW_PROTOCOLS = {"TCP", "UDP", "QUIC"}


def _get_ip(pkt):
    """Return (src_ip, dst_ip) from IPv4 or IPv6 layer, or ('', '') if absent."""
    try:
        return pkt.ip.src, pkt.ip.dst
    except AttributeError:
        pass
    try:
        return pkt.ipv6.src, pkt.ipv6.dst
    except AttributeError:
        return "", ""


def _get_ports(pkt):
    """Return (src_port, dst_port, transport) or ('', '', '')."""
    try:
        return str(pkt.tcp.srcport), str(pkt.tcp.dstport), "TCP"
    except AttributeError:
        pass
    try:
        return str(pkt.udp.srcport), str(pkt.udp.dstport), "UDP"
    except AttributeError:
        return "", "", ""


def _describe(pkt, src_ip: str, dst_ip: str,
              src_port: str, dst_port: str, proto: str) -> str:
    """Build a human-readable description string for the packet."""
    if proto == "DNS":
        try:
            qname = pkt.dns.qry_name
            qtype = pkt.dns.qry_type
            return f"DNS query {qtype} {qname} from {src_ip}"
        except AttributeError:
            return f"DNS {src_ip} -> {dst_ip}"

    if proto == "HTTP":
        try:
            method = pkt.http.request_method
            host = pkt.http.host
            uri = pkt.http.request_uri
            return f"HTTP {method} {host}{uri} from {src_ip}"
        except AttributeError:
            pass
        try:
            code = pkt.http.response_code
            return f"HTTP {code} response {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
        except AttributeError:
            pass
        return f"HTTP {src_ip}:{src_port} -> {dst_ip}:{dst_port}"

    if proto == "TLS":
        try:
            sni = pkt.tls.handshake_extensions_server_name
            return f"TLS ClientHello SNI={sni} {src_ip} -> {dst_ip}:{dst_port}"
        except AttributeError:
            pass
        return f"TLS {src_ip}:{src_port} -> {dst_ip}:{dst_port}"

    if proto == "ICMP":
        try:
            return f"ICMP type={pkt.icmp.type} code={pkt.icmp.code} {src_ip} -> {dst_ip}"
        except AttributeError:
            return f"ICMP {src_ip} -> {dst_ip}"

    if proto == "KERBEROS":
        try:
            msg_type = pkt.kerberos.msg_type
            realm = pkt.kerberos.realm
            return f"Kerberos msg_type={msg_type} realm={realm} {src_ip} -> {dst_ip}"
        except AttributeError:
            return f"Kerberos {src_ip} -> {dst_ip}"

    if proto in ("SMB", "SMB2"):
        try:
            cmd = pkt.smb2.cmd
            return f"{proto} cmd={cmd} {src_ip} -> {dst_ip}"
        except AttributeError:
            return f"{proto} {src_ip} -> {dst_ip}"

    if src_port and dst_port:
        return f"{proto} {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
    if src_ip:
        return f"{proto} {src_ip} -> {dst_ip}"
    return f"{proto} packet"


def _packet_to_event(pkt, seen_flows: set) -> ForensicEvent | None:
    """Convert one pyshark packet to a ForensicEvent, or None to skip it."""
    proto = pkt.highest_layer.upper()
    src_ip, dst_ip = _get_ip(pkt)

    if not src_ip:
        return None  # skip non-IP frames (ARP, STP, etc.)

    src_port, dst_port, transport = _get_ports(pkt)

    # Deduplicate flow-level protocols — one event per unique flow
    if proto in _FLOW_PROTOCOLS:
        flow_key = f"{src_ip}:{dst_ip}:{dst_port}:{proto}"
        if flow_key in seen_flows:
            return None
        seen_flows.add(flow_key)

    description = _describe(pkt, src_ip, dst_ip, src_port, dst_port, proto)

    # Packet timestamp — pyshark returns a datetime; strip tzinfo for SQLAlchemy
    try:
        ts = pkt.sniff_time
        if ts.tzinfo is not None:
            ts = ts.replace(tzinfo=None)
    except Exception:
        ts = datetime.utcnow()

    extra: dict = {}
    if transport:
        extra["transport"] = transport
    if dst_ip:
        extra["dst_ip"] = dst_ip
    if dst_port:
        extra["dst_port"] = dst_port

    return ForensicEvent(
        timestamp=ts,
        event_type=proto,
        source_host=src_ip,
        user=None,
        description=description[:1000],
        raw_source=RawSource.PCAP,
        event_id=None,
        extra=extra if extra else None,
    )


def parse_pcap(raw_bytes: bytes, filename: str) -> list[ForensicEvent]:
    """
    Parse a PCAP or PCAPng file from raw bytes.
    Returns a list of ForensicEvent objects (capped at MAX_PACKETS).

    Raises ValueError with a human-readable message if pyshark or tshark
    is not available.
    """
    try:
        import pyshark
    except ImportError:
        raise ValueError(
            "pyshark is not installed. Run: pip install pyshark\n"
            "Also ensure Wireshark / tshark is installed and on PATH."
        )

    # pyshark uses asyncio internally for tshark subprocess management.
    # When called from a starlette threadpool worker, the thread has no event
    # loop — create a fresh one so pyshark can operate normally.
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            raise RuntimeError
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    suffix = ".pcapng" if filename.lower().endswith(".pcapng") else ".pcap"

    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(raw_bytes)
        tmp_path = tmp.name

    events: list[ForensicEvent] = []
    seen_flows: set[str] = set()

    try:
        try:
            cap = pyshark.FileCapture(tmp_path, keep_packets=False)
        except Exception as exc:
            # Covers TSharkNotFoundException and similar startup errors
            if "tshark" in str(exc).lower() or "wireshark" in str(exc).lower() or "not found" in str(exc).lower():
                raise ValueError(
                    "tshark not found. Install Wireshark and ensure tshark.exe is on PATH.\n"
                    "Download: https://www.wireshark.org/download.html"
                ) from exc
            raise ValueError(f"Failed to open capture file: {exc}") from exc

        try:
            for pkt in cap:
                if len(events) >= MAX_PACKETS:
                    break
                try:
                    ev = _packet_to_event(pkt, seen_flows)
                    if ev is not None:
                        events.append(ev)
                except Exception:
                    continue
        except Exception as exc:
            exc_str = str(exc)
            if "tshark" in exc_str.lower() or "not found" in exc_str.lower():
                raise ValueError(
                    "tshark not found. Install Wireshark and ensure tshark.exe is on PATH.\n"
                    "Download: https://www.wireshark.org/download.html"
                ) from exc
            raise ValueError(f"Capture read error: {exc}") from exc
        finally:
            try:
                cap.close()
            except Exception:
                pass
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    if not events:
        raise ValueError(
            "No IP packets found in the capture file. "
            "Ensure the file is a valid PCAP/PCAPng and tshark is on PATH."
        )

    return events
