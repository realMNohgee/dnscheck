#!/usr/bin/env python3
"""dnscheck — DNS record lookup tool. Zero dependencies, Python stdlib."""

import argparse
import json
import re
import socket
import struct
import subprocess
import sys
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# DNS wire format parsing
# ---------------------------------------------------------------------------

DNS_RECORD_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
}

DNS_CLASSES = {
    1: "IN",
}


def build_dns_query(domain: str, qtype: int = 1) -> bytes:
    """Build a DNS query packet."""
    # Transaction ID (random)
    txid = struct.pack(">H", 0x1234)
    # Flags: standard query, recursion desired
    flags = struct.pack(">H", 0x0100)
    # Questions: 1
    qdcount = struct.pack(">H", 1)
    # Answer RRs, Authority RRs, Additional RRs: 0
    rest = struct.pack(">HHH", 0, 0, 0)

    # Question section
    qname = b""
    for label in domain.encode('ascii').split(b'.'):
        qname += struct.pack("B", len(label)) + label
    qname += b"\x00"

    qtype_bytes = struct.pack(">H", qtype)
    qclass = struct.pack(">H", 1)  # IN

    return txid + flags + qdcount + rest + qname + qtype_bytes + qclass


def parse_dns_name(data: bytes, offset: int) -> tuple:
    """Parse a DNS name from wire format. Returns (name, new_offset)."""
    labels = []
    jumped = False
    original_offset = offset
    max_hops = 10

    while max_hops > 0:
        max_hops -= 1
        if offset >= len(data):
            break

        length = data[offset]

        if length == 0:
            offset += 1
            break

        # Pointer
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                original_offset = offset + 2
            offset = pointer
            jumped = True
            continue

        offset += 1
        if offset + length > len(data):
            break
        labels.append(data[offset:offset + length].decode('ascii', errors='replace'))
        offset += length

    name = '.'.join(labels)
    if not jumped:
        return name, offset
    return name, original_offset


def parse_dns_response(data: bytes) -> List[Dict[str, Any]]:
    """Parse a DNS response packet and return records."""
    if len(data) < 12:
        return []

    txid = struct.unpack(">H", data[0:2])[0]
    flags = struct.unpack(">H", data[2:4])[0]
    qdcount = struct.unpack(">H", data[4:6])[0]
    ancount = struct.unpack(">H", data[6:8])[0]
    nscount = struct.unpack(">H", data[8:10])[0]
    arcount = struct.unpack(">H", data[10:12])[0]

    rcode = flags & 0x000F
    if rcode != 0:
        return []

    offset = 12

    # Skip question section
    for _ in range(qdcount):
        _, offset = parse_dns_name(data, offset)
        offset += 4  # qtype + qclass

    records = []
    total_rr = ancount + nscount + arcount

    for _ in range(total_rr):
        if offset + 10 > len(data):
            break

        name, offset = parse_dns_name(data, offset)
        if offset + 10 > len(data):
            break

        rtype = struct.unpack(">H", data[offset:offset+2])[0]
        rclass = struct.unpack(">H", data[offset+2:offset+4])[0]
        ttl = struct.unpack(">I", data[offset+4:offset+8])[0]
        rdlength = struct.unpack(">H", data[offset+8:offset+10])[0]
        offset += 10

        if offset + rdlength > len(data):
            break

        rdata = data[offset:offset+rdlength]
        offset += rdlength

        record = {
            "name": name.rstrip('.'),
            "type": DNS_RECORD_TYPES.get(rtype, str(rtype)),
            "class": DNS_CLASSES.get(rclass, str(rclass)),
            "ttl": ttl,
        }

        # Parse record-specific data
        if rtype == 1:  # A
            if len(rdata) == 4:
                record["data"] = socket.inet_ntoa(rdata)
        elif rtype == 28:  # AAAA
            if len(rdata) == 16:
                record["data"] = socket.inet_ntop(socket.AF_INET6, rdata)
        elif rtype == 2:  # NS
            ns_name, _ = parse_dns_name(data, offset - rdlength)
            record["data"] = ns_name.rstrip('.')
        elif rtype == 5:  # CNAME
            cname, _ = parse_dns_name(data, offset - rdlength)
            record["data"] = cname.rstrip('.')
        elif rtype == 12:  # PTR
            ptr_name, _ = parse_dns_name(data, offset - rdlength)
            record["data"] = ptr_name.rstrip('.')
        elif rtype == 15:  # MX
            if len(rdata) >= 2:
                preference = struct.unpack(">H", rdata[0:2])[0]
                mx_name, _ = parse_dns_name(data, offset - rdlength + 2)
                record["priority"] = preference
                record["data"] = mx_name.rstrip('.')
        elif rtype == 16:  # TXT
            try:
                txt_parts = []
                pos = 0
                while pos < len(rdata):
                    txt_len = rdata[pos]
                    pos += 1
                    if pos + txt_len <= len(rdata):
                        txt_parts.append(rdata[pos:pos+txt_len].decode('ascii', errors='replace'))
                        pos += txt_len
                    else:
                        break
                record["data"] = ''.join(txt_parts)
            except Exception:
                record["data"] = repr(rdata)
        elif rtype == 6:  # SOA
            mname, off = parse_dns_name(data, offset - rdlength)
            rname, off = parse_dns_name(data, off)
            if off + 20 <= offset:
                serial = struct.unpack(">I", data[off:off+4])[0]
                record["data"] = f"{mname} {rname} serial={serial}"
        else:
            record["data"] = repr(rdata[:32])

        records.append(record)

    return records


def dns_query(domain: str, qtype_name: str, nameserver: str = None) -> List[Dict[str, Any]]:
    """Send a DNS query and return parsed records."""
    qtype_map = {
        "A": 1, "NS": 2, "CNAME": 5, "SOA": 6,
        "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33,
    }
    qtype = qtype_map.get(qtype_name.upper(), 1)

    query = build_dns_query(domain, qtype)

    # Try DNS-over-UDP to common resolvers
    resolvers = [nameserver] if nameserver else ["8.8.8.8", "1.1.1.1", "8.8.4.4"]
    for resolver in resolvers:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(query, (resolver, 53))
            response, _ = sock.recvfrom(4096)
            sock.close()
            records = parse_dns_response(response)
            if records:
                return records
        except Exception:
            continue

    return []


# ---------------------------------------------------------------------------
# Subprocess-based fallback (host/dig)
# ---------------------------------------------------------------------------

def fallback_lookup(domain: str, qtype: str) -> List[Dict[str, Any]]:
    """Use host or dig as fallback for DNS lookups."""
    records = []

    # Try dig first (more structured output)
    try:
        r = subprocess.run(
            ["dig", "+short", "-t", qtype, domain],
            capture_output=True, text=True, timeout=5
        )
        if r.returncode == 0 and r.stdout.strip():
            for line in r.stdout.strip().split('\n'):
                line = line.strip()
                if line:
                    records.append({"name": domain, "type": qtype, "data": line, "ttl": 0, "class": "IN"})
            return records
    except Exception:
        pass

    # Try host
    try:
        r = subprocess.run(
            ["host", "-t", qtype, domain],
            capture_output=True, text=True, timeout=5
        )
        if r.returncode == 0:
            for line in r.stdout.strip().split('\n'):
                if " has " in line or " is " in line:
                    parts = line.split()
                    # host output format varies
                    records.append({"name": domain, "type": qtype, "data": line, "ttl": 0, "class": "IN"})
            return records
    except Exception:
        pass

    return records


def socket_lookup(domain: str, qtype: str) -> List[Dict[str, Any]]:
    """Use socket.getaddrinfo for A/AAAA records."""
    records = []
    sock_family = socket.AF_INET if qtype == "A" else socket.AF_INET6

    try:
        addrs = socket.getaddrinfo(domain, None, family=sock_family)
        for addr in addrs:
            ip = addr[4][0]
            records.append({"name": domain, "type": qtype, "data": ip, "ttl": 0, "class": "IN"})
    except socket.gaierror:
        pass

    return records


def lookup_records(domain: str, qtype: str) -> List[Dict[str, Any]]:
    """Look up DNS records, trying multiple methods."""
    # Try direct DNS query first
    records = dns_query(domain, qtype)
    if records:
        return records

    # Fall back to socket for A/AAAA
    if qtype in ("A", "AAAA"):
        records = socket_lookup(domain, qtype)
        if records:
            return records

    # Fall back to dig/host
    records = fallback_lookup(domain, qtype)
    return records


# ---------------------------------------------------------------------------
# TXT record parsing
# ---------------------------------------------------------------------------

def parse_spf(txt_data: str) -> Optional[Dict[str, Any]]:
    """Parse SPF record from TXT data."""
    if not txt_data.startswith("v=spf1"):
        return None
    parts = txt_data.split()
    result = {"version": "spf1", "mechanisms": [], "modifiers": {}}
    for part in parts[1:]:
        if '=' in part and not part.startswith(('include:', 'a:', 'mx:', 'ptr:', 'ip4:', 'ip6:', 'exists:')):
            k, v = part.split('=', 1)
            result["modifiers"][k] = v
        else:
            result["mechanisms"].append(part)
    return result


def parse_dmarc(txt_data: str) -> Optional[Dict[str, Any]]:
    """Parse DMARC record from TXT data."""
    if not txt_data.startswith("v=DMARC1"):
        return None
    result = {"version": "DMARC1"}
    parts = txt_data.split(';')
    for part in parts:
        part = part.strip()
        if '=' in part:
            k, v = part.split('=', 1)
            result[k.strip()] = v.strip()
    return result


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_lookup(args) -> int:
    """Look up a specific DNS record type."""
    records = lookup_records(args.domain, args.type.upper())

    if args.format == "json":
        print(json.dumps(records, indent=2, default=str))
    else:
        if not records:
            print(f"No {args.type} records found for {args.domain}")
        for r in records:
            priority = f" priority={r['priority']}" if 'priority' in r else ""
            ttl = f" [TTL: {r['ttl']}s]" if r.get('ttl') else ""
            print(f"{r['type']:<8} {r['data']}{priority}{ttl}")

    return 0 if records else 1


def cmd_all(args) -> int:
    """Look up all common record types."""
    all_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]
    all_records = {}

    for qtype in all_types:
        records = lookup_records(args.domain, qtype)
        if records:
            all_records[qtype] = records

    if args.format == "json":
        print(json.dumps(all_records, indent=2, default=str))
    else:
        found_any = False
        for qtype, records in all_records.items():
            print(f"\n--- {qtype} Records ---")
            for r in records:
                found_any = True
                priority = f" priority={r['priority']}" if 'priority' in r else ""
                ttl = f" [TTL: {r['ttl']}s]" if r.get('ttl') else ""
                print(f"  {r['data']}{priority}{ttl}")
        if not found_any:
            print(f"No records found for {args.domain}")

    return 0


def cmd_mx_priority(args) -> int:
    """Show MX records sorted by priority."""
    records = lookup_records(args.domain, "MX")

    # Sort by priority
    records.sort(key=lambda r: r.get("priority", 999))

    if args.format == "json":
        print(json.dumps(records, indent=2, default=str))
    else:
        if not records:
            print(f"No MX records found for {args.domain}")
        print(f"{'Priority':<10} {'Mail Server':<40} TTL")
        print("-" * 60)
        for r in records:
            ttl = r.get('ttl', 0)
            print(f"{r.get('priority', '?'):<10} {r['data']:<40} {ttl}s")

    return 0 if records else 1


def cmd_txt(args) -> int:
    """Show TXT records with SPF/DMARC parsing."""
    records = lookup_records(args.domain, "TXT")

    if args.format == "json":
        print(json.dumps(records, indent=2, default=str))
    else:
        if not records:
            print(f"No TXT records found for {args.domain}")
        for r in records:
            data = r.get("data", "")
            print(f"\nTXT: {data[:100]}{'...' if len(data) > 100 else ''}")

            # Try SPF parsing
            spf = parse_spf(data)
            if spf:
                print("  [SPF detected]")
                if spf["mechanisms"]:
                    print(f"  Mechanisms: {', '.join(spf['mechanisms'][:5])}")
                if spf["modifiers"]:
                    for k, v in spf["modifiers"].items():
                        print(f"  {k}: {v}")

            # Try DMARC parsing
            dmarc = parse_dmarc(data)
            if dmarc:
                print("  [DMARC detected]")
                for k, v in dmarc.items():
                    if k != "version":
                        print(f"  {k}: {v}")

    return 0


def main():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--format", choices=["text", "json"], default="text",
                        help="Output format (default: text)")

    p = argparse.ArgumentParser(
        description="dnscheck — DNS record lookup tool")

    sub = p.add_subparsers(dest="cmd", required=True)

    sp_lookup = sub.add_parser("lookup", parents=[common],
                               help="Look up a specific DNS record type")
    sp_lookup.add_argument("type", choices=["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "PTR"],
                           help="DNS record type")
    sp_lookup.add_argument("domain", help="Domain name to look up")

    sp_all = sub.add_parser("all", parents=[common],
                            help="Look up all common record types")
    sp_all.add_argument("domain", help="Domain name to look up")

    sp_mx = sub.add_parser("mx-priority", parents=[common],
                           help="Show MX records sorted by priority")
    sp_mx.add_argument("domain", help="Domain name to look up")

    sp_txt = sub.add_parser("txt", parents=[common],
                            help="Show TXT records with SPF/DMARC parsing")
    sp_txt.add_argument("domain", help="Domain name to look up")

    args = p.parse_args()

    if args.cmd == "lookup":
        return cmd_lookup(args)
    elif args.cmd == "all":
        return cmd_all(args)
    elif args.cmd == "mx-priority":
        return cmd_mx_priority(args)
    elif args.cmd == "txt":
        return cmd_txt(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
