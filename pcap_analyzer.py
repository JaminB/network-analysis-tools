#!/usr/bin/env python3
"""
pcap_analyzer.py — PCAP/PCAPNG conversation analyzer

Reads a packet capture file and writes a CSV with per-conversation statistics:
transport/application protocol, packet/byte counts, encryption details, GeoIP,
ASN, blacklist status, and a Wireshark display filter.

GeoIP databases (DB-IP lite, free from https://db-ip.com/db/lite/):
  dbip-country-lite-YYYY-MM.mmdb  (or .mmdb.gz)
  dbip-asn-lite-YYYY-MM.mmdb      (or .mmdb.gz)
Place both files in the current directory, or specify --db-dir.
"""

# ── Phase 0: Self-install dependencies ────────────────────────────────────────
import subprocess
import sys


def _ensure_deps():
    required = ["scapy", "maxminddb", "requests"]
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", "--quiet"] + required,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


_ensure_deps()

# ── Standard-library imports ───────────────────────────────────────────────────
import argparse
import csv
import gzip
import ipaddress
import os
import shutil
import struct
import tarfile
import time
from pathlib import Path

# ── Third-party imports ───────────────────────────────────────────────────────
import maxminddb
import requests as _requests
from scapy.all import PcapReader, IP, IPv6, TCP, UDP, Raw

try:
    from scapy.layers.tls.crypto.suites import _tls_cipher_suites as _TLS_SUITES
except Exception:
    _TLS_SUITES = {}

# ── Constants ──────────────────────────────────────────────────────────────────
CACHE_DIR     = Path.home() / ".pcap_analyzer"
BLOCKLIST_DIR = CACHE_DIR / "blocklists"
BLOCKLIST_TTL = 86400  # seconds

WELL_KNOWN_PORTS = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    67:    "DHCP",
    80:    "HTTP",
    110:   "POP3",
    143:   "IMAP",
    161:   "SNMP",
    389:   "LDAP",
    443:   "HTTPS",
    465:   "SMTPS",
    587:   "SMTP",
    636:   "LDAPS",
    993:   "IMAPS",
    995:   "POP3S",
    1433:  "MSSQL",
    1521:  "Oracle",
    3306:  "MySQL",
    3389:  "RDP",
    5432:  "PostgreSQL",
    5900:  "VNC",
    6379:  "Redis",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    27017: "MongoDB",
}

PROTO_NAMES = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6"}

BLACKLISTS = {
    "Spamhaus DROP":    "https://www.spamhaus.org/drop/drop.txt",
    "Emerging Threats": "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
    "Feodo Tracker":    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
}

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

TLS_VERSION_MAP = {
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

TLS13_CIPHER_IDS = {0x1301, 0x1302, 0x1303, 0x1304, 0x1305}

HTTP_METHODS = (
    b"GET ", b"POST ", b"PUT ", b"DELETE ",
    b"HEAD ", b"OPTIONS ", b"PATCH ", b"CONNECT ",
)

CSV_FIELDS = [
    "conversation_id",
    "transport_protocol",
    "application_protocol",
    "client_ip",
    "client_port",
    "server_ip",
    "server_port",
    "packets_sent",
    "packets_received",
    "bytes_sent",
    "bytes_received",
    "encrypted",
    "encryption_detail",
    "key_exchange",
    "tls_version",
    "wireshark_filter",
    "server_country",
    "server_asn_number",
    "server_asn_org",
    "server_blacklisted",
    "blacklist_source",
]


# ── GeoIP ──────────────────────────────────────────────────────────────────────

def _find_mmdb(prefix, search_dir):
    """
    Return a Path to an extracted .mmdb file whose name starts with prefix.
    Searches search_dir for <prefix>*.mmdb first, then <prefix>*.mmdb.gz
    (which it decompresses in-place to a .mmdb file beside the .gz).
    Returns None if nothing is found.
    """
    d = Path(search_dir)

    for candidate in sorted(d.glob(f"{prefix}*.mmdb")):
        return candidate

    for gz in sorted(d.glob(f"{prefix}*.mmdb.gz")):
        extracted = gz.with_suffix("")  # strips .gz → leaves .mmdb
        if not extracted.exists():
            print(f"  Extracting {gz.name}…")
            with gzip.open(gz, "rb") as f_in, open(extracted, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
        return extracted

    return None


def setup_geoip(db_dir, skip_geo):
    """
    Locate DB-IP country and ASN databases in db_dir.
    Returns (country_reader, asn_reader) or (None, None).
    Uses maxminddb directly so any MMDB-format database works regardless of type string.
    """
    if skip_geo:
        return None, None

    country_path = _find_mmdb("dbip-country-lite", db_dir)
    asn_path     = _find_mmdb("dbip-asn-lite",     db_dir)

    if not country_path and not asn_path:
        print(
            "[GeoIP] No DB-IP databases found in current directory.\n"
            "  Download the free lite databases from https://db-ip.com/db/lite/\n"
            "    dbip-country-lite-YYYY-MM.mmdb.gz\n"
            "    dbip-asn-lite-YYYY-MM.mmdb.gz\n"
            "  Place them alongside the capture file (or use --db-dir).\n"
            "[GeoIP] Continuing without GeoIP.\n"
        )
        return None, None

    readers = {}
    for label, path in (("country", country_path), ("asn", asn_path)):
        if path is None:
            print(f"  [GeoIP] {label} database not found — {label} columns will be empty.")
            readers[label] = None
        else:
            try:
                readers[label] = maxminddb.open_database(str(path))
                print(f"  {label.capitalize()} DB: {path.name}")
            except Exception as exc:
                print(f"  [GeoIP] Could not open {label} database: {exc}")
                readers[label] = None

    return readers["country"], readers["asn"]


def _is_private(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return True


_GEO_EMPTY = {"country": "", "asn_num": "", "asn_org": ""}


def lookup_geo(ip_str, country_reader, asn_reader, cache):
    if ip_str in cache:
        return cache[ip_str]
    if (country_reader is None and asn_reader is None) or _is_private(ip_str):
        cache[ip_str] = _GEO_EMPTY
        return _GEO_EMPTY

    result = {"country": "", "asn_num": "", "asn_org": ""}

    if country_reader is not None:
        try:
            rec = country_reader.get(ip_str)
            if rec:
                country = rec.get("country") or rec.get("registered_country") or {}
                result["country"] = country.get("iso_code", "")
        except Exception:
            pass

    if asn_reader is not None:
        try:
            rec = asn_reader.get(ip_str)
            if rec:
                result["asn_num"] = rec.get("autonomous_system_number", "")
                result["asn_org"] = rec.get("autonomous_system_organization", "")
        except Exception:
            pass

    cache[ip_str] = result
    return result


# ── Blacklists ─────────────────────────────────────────────────────────────────

def _fetch_or_cached(name, url, ttl):
    BLOCKLIST_DIR.mkdir(parents=True, exist_ok=True)
    safe = name.replace(" ", "_").lower() + ".txt"
    path = BLOCKLIST_DIR / safe
    if path.exists() and (time.time() - path.stat().st_mtime) < ttl:
        return path.read_text(errors="replace")
    try:
        resp = _requests.get(url, timeout=30)
        resp.raise_for_status()
        path.write_text(resp.text)
        return resp.text
    except Exception as exc:
        print(f"  [Blacklist] Fetch failed for {name}: {exc}")
        return path.read_text(errors="replace") if path.exists() else ""


def _parse_cidrs(raw):
    nets = []
    for line in raw.splitlines():
        line = line.split(";")[0].split("#")[0].strip()
        if not line:
            continue
        if "/" not in line:
            if line.count(".") == 3:
                line += "/32"
            elif ":" in line:
                line += "/128"
            else:
                continue
        try:
            nets.append(ipaddress.ip_network(line, strict=False))
        except ValueError:
            pass
    return nets


def setup_blacklists(skip_blacklist):
    if skip_blacklist:
        return []
    result = []
    for name, url in BLACKLISTS.items():
        print(f"  Loading blocklist: {name}…")
        text = _fetch_or_cached(name, url, BLOCKLIST_TTL)
        nets = _parse_cidrs(text)
        result.append((name, nets))
        print(f"    {len(nets)} networks loaded.")
    return result


def check_blacklist(ip_str, blocklists, cache):
    if ip_str in cache:
        return cache[ip_str]
    if _is_private(ip_str) or not blocklists:
        cache[ip_str] = (False, "")
        return (False, "")
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        cache[ip_str] = (False, "")
        return (False, "")
    for name, nets in blocklists:
        if any(addr in net for net in nets):
            cache[ip_str] = (True, name)
            return (True, name)
    cache[ip_str] = (False, "")
    return (False, "")


# ── TLS parsing ────────────────────────────────────────────────────────────────

def _iter_tls_records(data):
    """Yield (content_type, version_int, payload) for each TLS record in data."""
    offset = 0
    while offset + 5 <= len(data):
        ct  = data[offset]
        ver = struct.unpack_from(">H", data, offset + 1)[0]
        ln  = struct.unpack_from(">H", data, offset + 3)[0]
        end = offset + 5 + ln
        if end > len(data):
            break
        yield ct, ver, data[offset + 5:end]
        offset = end


def _parse_server_hello(hs_data):
    """
    Parse a TLS handshake fragment at a message boundary.
    Returns dict on success (type == ServerHello == 0x02), None otherwise.
    """
    if len(hs_data) < 4:
        return None
    if hs_data[0] != 0x02:
        return None
    hs_len = struct.unpack_from(">I", b"\x00" + hs_data[1:4])[0]
    body   = hs_data[4:4 + hs_len]
    if len(body) < 35:
        return None
    # body[0:2]=server_version  body[2:34]=random  body[34]=session_id_len
    version_int    = struct.unpack_from(">H", body, 0)[0]
    session_id_len = body[34]
    offset = 35 + session_id_len
    if offset + 2 > len(body):
        return None
    cipher_id = struct.unpack_from(">H", body, offset)[0]
    return {"version_int": version_int, "cipher_id": cipher_id}


def analyze_tls(payloads_c2s, payloads_s2c):
    """
    Inspect collected TCP payloads for TLS.
    Returns enriched dict or None.
    """
    found_tls = any(
        len(p) >= 3 and p[0] == 0x16 and p[1] == 0x03
        for p in payloads_c2s + payloads_s2c
    )
    if not found_tls:
        return None

    result = {
        "encrypted":   True,
        "tls_version": "",
        "cipher_name": "",
        "kex":         "",
        "enc_algo":    "",
    }

    for payload in payloads_s2c:
        for ct, _ver, rec_body in _iter_tls_records(payload):
            if ct != 0x16:
                continue
            hs_offset = 0
            while hs_offset < len(rec_body):
                sh = _parse_server_hello(rec_body[hs_offset:])
                if sh:
                    _enrich_tls_result(result, sh)
                    return result
                if hs_offset + 4 > len(rec_body):
                    break
                msg_len = struct.unpack_from(">I", b"\x00" + rec_body[hs_offset + 1:hs_offset + 4])[0]
                hs_offset += 4 + msg_len

    return result


def _enrich_tls_result(result, sh):
    version_int = sh["version_int"]
    cipher_id   = sh["cipher_id"]

    if cipher_id in TLS13_CIPHER_IDS:
        tls_ver = "TLS 1.3"
    else:
        tls_ver = TLS_VERSION_MAP.get(version_int, f"TLS ({hex(version_int)})")
    result["tls_version"] = tls_ver

    cipher_name = _TLS_SUITES.get(cipher_id, f"Unknown ({hex(cipher_id)})")
    result["cipher_name"] = cipher_name

    cu = cipher_name.upper()
    if "ECDHE" in cu or tls_ver == "TLS 1.3":
        result["kex"] = "ECDHE"
    elif "DHE" in cu:
        result["kex"] = "DHE"
    elif "RSA" in cu:
        result["kex"] = "RSA"

    if "_WITH_" in cipher_name:
        result["enc_algo"] = cipher_name.split("_WITH_", 1)[1]
    elif tls_ver == "TLS 1.3":
        parts = cipher_name.split("_", 1)
        result["enc_algo"] = parts[1] if len(parts) > 1 else cipher_name
    else:
        result["enc_algo"] = cipher_name


# ── QUIC detection ─────────────────────────────────────────────────────────────

def _is_quic(payload):
    if not payload or len(payload) < 5:
        return False
    if (payload[0] & 0xC0) != 0xC0:
        return False
    version = struct.unpack_from(">I", payload, 1)[0]
    return version in (0x00000001, 0x6B3343CF) or (0xFF000001 <= version <= 0xFF00001D)


# ── Application protocol detection ────────────────────────────────────────────

def detect_app_proto(proto_num, client_port, server_port, first_payload, is_quic_flow):
    if is_quic_flow:
        return "QUIC/HTTP3"

    for port in (server_port, client_port):
        if port in WELL_KNOWN_PORTS:
            label = WELL_KNOWN_PORTS[port]
            if first_payload and len(first_payload) >= 2 and first_payload[0] == 0x16 and first_payload[1] == 0x03:
                if label == "HTTP":
                    return "HTTPS"
                if label in ("SMTP", "POP3", "IMAP", "FTP", "LDAP"):
                    return label + "S"
            return label

    if first_payload:
        if len(first_payload) >= 2 and first_payload[0] == 0x16 and first_payload[1] == 0x03:
            return "TLS"
        if first_payload.startswith(b"SSH-"):
            return "SSH"
        if any(first_payload.startswith(m) for m in HTTP_METHODS):
            return "HTTP"
        if first_payload.startswith(b"HTTP/"):
            return "HTTP"

    if proto_num == 17 and (client_port == 53 or server_port == 53):
        return "DNS"

    return "Unknown"


# ── Wireshark filter ───────────────────────────────────────────────────────────

def make_wireshark_filter(proto_num, client_ip, client_port, server_ip, server_port):
    proto = "tcp" if proto_num == 6 else "udp"
    ip_kw = "ipv6" if ":" in (client_ip or "") else "ip"
    fwd = (
        f"{ip_kw}.src=={client_ip} && {proto}.srcport=={client_port} && "
        f"{ip_kw}.dst=={server_ip} && {proto}.dstport=={server_port}"
    )
    rev = (
        f"{ip_kw}.src=={server_ip} && {proto}.srcport=={server_port} && "
        f"{ip_kw}.dst=={client_ip} && {proto}.dstport=={client_port}"
    )
    return f"({fwd}) || ({rev})"


# ── Packet analysis ────────────────────────────────────────────────────────────

def _canonical_key(proto, src_ip, src_port, dst_ip, dst_port):
    lo, hi = sorted([(src_ip, src_port), (dst_ip, dst_port)])
    return (proto, lo[0], lo[1], hi[0], hi[1])


def _new_flow(proto_num):
    return {
        "proto_num":         proto_num,
        "client_ip":         None,
        "client_port":       None,
        "server_ip":         None,
        "server_port":       None,
        "client_locked":     False,
        "pkts_sent":         0,
        "pkts_recv":         0,
        "bytes_sent":        0,
        "bytes_recv":        0,
        "payloads_c2s":      [],
        "payloads_s2c":      [],
        "first_payload_c2s": b"",
        "is_quic":           False,
    }


def _assign_client(flow, src_ip, src_port, dst_ip, dst_port):
    flow["client_ip"]    = src_ip
    flow["client_port"]  = src_port
    flow["server_ip"]    = dst_ip
    flow["server_port"]  = dst_port
    flow["client_locked"] = True


def analyze_pcap(filepath, country_reader, asn_reader, blocklists):
    flows     = {}
    geo_cache = {}
    bl_cache  = {}

    print(f"Reading packets from: {filepath}")
    pkt_count = 0

    with PcapReader(str(filepath)) as reader:
        for pkt in reader:
            pkt_count += 1
            if pkt_count % 10_000 == 0:
                print(f"  {pkt_count:,} packets processed, {len(flows):,} conversations…")

            if IP in pkt:
                ip_layer = pkt[IP]
                src_ip   = ip_layer.src
                dst_ip   = ip_layer.dst
            elif IPv6 in pkt:
                ip_layer = pkt[IPv6]
                src_ip   = ip_layer.src
                dst_ip   = ip_layer.dst
            else:
                continue

            if TCP in pkt:
                transport = pkt[TCP]
                proto_num = 6
            elif UDP in pkt:
                transport = pkt[UDP]
                proto_num = 17
            else:
                continue

            src_port = transport.sport
            dst_port = transport.dport

            key = _canonical_key(proto_num, src_ip, src_port, dst_ip, dst_port)
            if key not in flows:
                flows[key] = _new_flow(proto_num)
            flow = flows[key]

            # ── Client/server determination ────────────────────────────────────
            if not flow["client_locked"]:
                if proto_num == 6:
                    flags = int(transport.flags)
                    syn   = bool(flags & 0x02)
                    ack   = bool(flags & 0x10)
                    if syn and not ack:
                        _assign_client(flow, src_ip, src_port, dst_ip, dst_port)
                    elif syn and ack and flow["client_ip"] is None:
                        _assign_client(flow, dst_ip, dst_port, src_ip, src_port)

                if not flow["client_locked"] and flow["client_ip"] is None:
                    if dst_port in WELL_KNOWN_PORTS and src_port not in WELL_KNOWN_PORTS:
                        _assign_client(flow, src_ip, src_port, dst_ip, dst_port)
                    elif src_port in WELL_KNOWN_PORTS and dst_port not in WELL_KNOWN_PORTS:
                        _assign_client(flow, dst_ip, dst_port, src_ip, src_port)
                    else:
                        _assign_client(flow, src_ip, src_port, dst_ip, dst_port)

            # ── Direction ──────────────────────────────────────────────────────
            is_c2s = (src_ip == flow["client_ip"] and src_port == flow["client_port"])

            pkt_bytes = len(bytes(ip_layer))
            if is_c2s:
                flow["pkts_sent"]  += 1
                flow["bytes_sent"] += pkt_bytes
            else:
                flow["pkts_recv"]  += 1
                flow["bytes_recv"] += pkt_bytes

            # ── Payload collection ─────────────────────────────────────────────
            if Raw in pkt:
                raw = bytes(pkt[Raw].load)

                if proto_num == 17 and _is_quic(raw):
                    flow["is_quic"] = True

                if is_c2s:
                    if len(flow["payloads_c2s"]) < 20:
                        flow["payloads_c2s"].append(raw)
                    if not flow["first_payload_c2s"]:
                        flow["first_payload_c2s"] = raw[:32]
                else:
                    if len(flow["payloads_s2c"]) < 20:
                        flow["payloads_s2c"].append(raw)

    print(f"  Done — {pkt_count:,} packets → {len(flows):,} conversations.\n")

    # ── Build output rows ──────────────────────────────────────────────────────
    rows = []
    for conv_id, (key, flow) in enumerate(flows.items(), start=1):
        proto_num   = flow["proto_num"]
        client_ip   = flow["client_ip"]   or key[1]
        client_port = flow["client_port"] or key[2]
        server_ip   = flow["server_ip"]   or key[3]
        server_port = flow["server_port"] or key[4]

        tls = analyze_tls(flow["payloads_c2s"], flow["payloads_s2c"])

        if flow["is_quic"]:
            encrypted    = True
            enc_detail   = "QUIC (TLS 1.3)"
            key_exchange = "ECDHE"
            tls_version  = "TLS 1.3"
        elif tls and tls["encrypted"]:
            encrypted    = True
            enc_detail   = tls["enc_algo"] or tls["cipher_name"] or "Unknown cipher"
            key_exchange = tls["kex"]
            tls_version  = tls["tls_version"]
        else:
            encrypted    = False
            enc_detail   = "plaintext"
            key_exchange = ""
            tls_version  = ""

        sample_payload = flow["first_payload_c2s"] or (
            flow["payloads_c2s"][0][:32] if flow["payloads_c2s"] else b""
        )
        app_proto = detect_app_proto(
            proto_num, client_port, server_port, sample_payload, flow["is_quic"]
        )
        if encrypted and tls and app_proto == "Unknown":
            app_proto = "TLS"

        ws_filter = make_wireshark_filter(proto_num, client_ip, client_port, server_ip, server_port)
        geo       = lookup_geo(server_ip, country_reader, asn_reader, geo_cache)
        bl_hit, bl_source = check_blacklist(server_ip, blocklists, bl_cache)

        rows.append({
            "conversation_id":    conv_id,
            "transport_protocol": PROTO_NAMES.get(proto_num, str(proto_num)),
            "application_protocol": app_proto,
            "client_ip":          client_ip,
            "client_port":        client_port,
            "server_ip":          server_ip,
            "server_port":        server_port,
            "packets_sent":       flow["pkts_sent"],
            "packets_received":   flow["pkts_recv"],
            "bytes_sent":         flow["bytes_sent"],
            "bytes_received":     flow["bytes_recv"],
            "encrypted":          encrypted,
            "encryption_detail":  enc_detail,
            "key_exchange":       key_exchange,
            "tls_version":        tls_version,
            "wireshark_filter":   ws_filter,
            "server_country":     geo["country"],
            "server_asn_number":  geo["asn_num"],
            "server_asn_org":     geo["asn_org"],
            "server_blacklisted": bl_hit,
            "blacklist_source":   bl_source,
        })

    return rows


def write_csv(rows, output_path):
    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"Output: {output_path}  ({len(rows)} conversations)")


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Analyze a PCAP/PCAPNG file and export per-conversation statistics to CSV.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "GeoIP databases (free from https://db-ip.com/db/lite/):\n"
            "  dbip-country-lite-YYYY-MM.mmdb[.gz]\n"
            "  dbip-asn-lite-YYYY-MM.mmdb[.gz]\n"
            "Place both in the current directory or specify --db-dir.\n"
        ),
    )
    parser.add_argument("input",     help="Input PCAP or PCAPNG file")
    parser.add_argument("--output", "-o", help="Output CSV (default: <input>_analysis.csv)")
    parser.add_argument(
        "--db-dir",
        default=".",
        help="Directory containing DB-IP .mmdb/.mmdb.gz files (default: current directory)",
    )
    parser.add_argument("--skip-geo",       action="store_true", help="Skip GeoIP lookups")
    parser.add_argument("--skip-blacklist", action="store_true", help="Skip blacklist checks")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        sys.exit(f"Error: file not found: {input_path}")

    output_path = (
        Path(args.output)
        if args.output
        else input_path.with_name(input_path.stem + "_analysis.csv")
    )

    db_dir = Path(args.db_dir).resolve()

    print("=== PCAP Conversation Analyzer ===\n")

    print("[1/3] Setting up GeoIP databases…")
    country_reader, asn_reader = setup_geoip(db_dir, args.skip_geo)
    if args.skip_geo:
        print("  Skipped.\n")
    else:
        print()

    print("[2/3] Loading IP blocklists…")
    blocklists = setup_blacklists(args.skip_blacklist)
    if args.skip_blacklist:
        print("  Skipped.\n")
    else:
        print()

    print(f"[3/3] Analyzing {input_path.name}…")
    rows = analyze_pcap(input_path, country_reader, asn_reader, blocklists)

    if country_reader:
        country_reader.close()
    if asn_reader:
        asn_reader.close()

    write_csv(rows, output_path)


if __name__ == "__main__":
    main()
