"""
Analyzer service: parses PCAP from DB and stores analysis results in SQLite.

Uses existing tables: ip_observations, devices, domains, flows, analysis_runs.
No schema changes.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from collections import defaultdict, Counter
from datetime import datetime
from typing import Dict, Tuple, Any

from scapy.all import PcapReader, ARP, Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR  # type: ignore

from utils.db import get_db_connection

# Fix for Windows colorama issue - use simple print to stderr
def log(msg):
    """Safe logging that works on Windows"""
    try:
        sys.stderr.write(f"{msg}\n")
        sys.stderr.flush()
    except:
        pass


def _get_pcap_blob(pcap_id: int) -> bytes:
    with get_db_connection() as conn:
        cur = conn.cursor()
        row = cur.execute('SELECT file_data FROM pcaps WHERE id = ?', (pcap_id,)).fetchone()
        if not row:
            raise ValueError('PCAP not found')
        return row[0]


def analyze_pcap(pcap_id: int) -> Dict[str, Any]:
    """Analyze the PCAP for the given ID and store results in the DB.

    Returns a compact summary dict suitable for response payloads.
    """
    file_bytes = _get_pcap_blob(pcap_id)
    
    # Use sys.stderr instead of print to avoid colorama issues on Windows
    import sys
    sys.stderr.write(f"[ANALYZER] Starting analysis for PCAP ID {pcap_id}\n")
    sys.stderr.write(f"[ANALYZER] File size: {len(file_bytes)} bytes ({len(file_bytes) / (1024*1024):.2f} MB)\n")
    sys.stderr.flush()

    # Write to a temporary file for Scapy (keep original extension for pcapng support)
    # Detect file type by magic bytes
    file_ext = '.pcap'
    if file_bytes[:4] == b'\x0a\x0d\x0d\x0a':  # pcapng magic bytes
        file_ext = '.pcapng'
        log("[ANALYZER] Detected PCAPNG format")
    elif file_bytes[:4] == b'\xd4\xc3\xb2\xa1' or file_bytes[:4] == b'\xa1\xb2\xc3\xd4':  # pcap magic bytes
        file_ext = '.pcap'
        log("[ANALYZER] Detected PCAP format")
    
    with tempfile.NamedTemporaryFile(delete=False, suffix=file_ext) as tmp:
        tmp.write(file_bytes)
        tmp_path = tmp.name
    
    log(f"[ANALYZER] Temporary file created: {tmp_path}")

    total_packets = 0
    total_bytes = 0
    start_ts = None
    end_ts = None

    protocol_counts = Counter()
    size_min = None
    size_max = None
    size_sum = 0

    ip_stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        'packets': 0,
        'bytes': 0,
        'srcPackets': 0,
        'dstPackets': 0,
        'bytesUp': 0,
        'bytesDown': 0,
        'first': None,
        'last': None,
    })

    # Map ip -> mac (best-effort)
    ip_mac: Dict[str, str] = {}

    # Domain observations: key (domain, source, ip_or_none) -> count
    domain_counts: Dict[Tuple[str, str, str | None], int] = defaultdict(int)

    # Flow aggregates: key (src, sport, dst, dport, proto) -> stats
    flow_stats: Dict[Tuple[str, int, str, int, str], Dict[str, Any]] = {}

    packet_errors = 0
    try:
        log("[ANALYZER] Opening PCAP file for reading...")
        with PcapReader(tmp_path) as pcap:
            log("[ANALYZER] Starting packet iteration...")
            for pkt in pcap:
                # Log progress every 10000 packets
                if total_packets > 0 and total_packets % 10000 == 0:
                    log(f"[ANALYZER] Processed {total_packets} packets...")
                try:
                    ts = float(getattr(pkt, 'time', datetime.utcnow().timestamp()))
                    raw_len = len(bytes(pkt)) if pkt is not None else 0
                except Exception as e:
                    packet_errors += 1
                    if packet_errors <= 5:  # Only log first 5 errors
                        log(f"[ANALYZER] Warning: Packet parsing error: {e}")
                    ts = datetime.utcnow().timestamp()
                    raw_len = 0

                total_packets += 1
                total_bytes += raw_len
                start_ts = ts if start_ts is None else min(start_ts, ts)
                end_ts = ts if end_ts is None else max(end_ts, ts)

                # Packet size stats
                size_min = raw_len if size_min is None else min(size_min, raw_len)
                size_max = raw_len if size_max is None else max(size_max, raw_len)
                size_sum += raw_len

                # Protocols and layers
                proto = 'OTHER'
                if pkt.haslayer(ARP):
                    proto = 'ARP'
                elif pkt.haslayer(IP):
                    if pkt.haslayer(TCP):
                        proto = 'TCP'
                    elif pkt.haslayer(UDP):
                        proto = 'UDP'
                    elif pkt.haslayer(ICMP):
                        proto = 'ICMP'
                    else:
                        proto = 'IP'
                protocol_counts[proto] += 1

                # IP-level tracking and flows
                if pkt.haslayer(IP):
                    ip = pkt[IP]
                    src = ip.src
                    dst = ip.dst

                    # Mac association best-effort
                    if pkt.haslayer(Ether):
                        eth = pkt[Ether]
                        if src not in ip_mac and eth.src:
                            ip_mac[src] = eth.src
                        if dst not in ip_mac and eth.dst:
                            ip_mac[dst] = eth.dst

                    # IP stats (count both directions)
                    for who, direction in ((src, 'src'), (dst, 'dst')):
                        st = ip_stats[who]
                        st['packets'] += 1
                        st['bytes'] += raw_len
                        if direction == 'src':
                            st['srcPackets'] += 1
                            st['bytesUp'] += raw_len
                        else:
                            st['dstPackets'] += 1
                            st['bytesDown'] += raw_len
                        st['first'] = ts if st['first'] is None else min(st['first'], ts)
                        st['last'] = ts if st['last'] is None else max(st['last'], ts)

                    # Ports and flows
                    sport = 0
                    dport = 0
                    fproto = 'IP'
                    if pkt.haslayer(TCP):
                        tcp = pkt[TCP]
                        sport = int(tcp.sport)
                        dport = int(tcp.dport)
                        fproto = 'TCP'
                    elif pkt.haslayer(UDP):
                        udp = pkt[UDP]
                        sport = int(udp.sport)
                        dport = int(udp.dport)
                        fproto = 'UDP'
                    elif pkt.haslayer(ICMP):
                        fproto = 'ICMP'

                    key = (src, sport, dst, dport, fproto)
                    fs = flow_stats.get(key)
                    if fs is None:
                        fs = {
                            'packets': 0,
                            'bytes': 0,
                            'first': ts,
                            'last': ts,
                        }
                        flow_stats[key] = fs
                    fs['packets'] += 1
                    fs['bytes'] += raw_len
                    fs['first'] = min(fs['first'], ts)
                    fs['last'] = max(fs['last'], ts)

                # Domains via DNS (queries + answers)
                if pkt.haslayer(DNS):
                    dns = pkt[DNS]
                    # Get source IP (who made the DNS request)
                    src_ip = None
                    if pkt.haslayer(IP):
                        src_ip = pkt[IP].src
                    
                    # Queries
                    if dns.qr == 0 and dns.qd is not None and isinstance(dns.qd, DNSQR):
                        qname = dns.qd.qname.decode(errors='ignore').rstrip('.')
                        if qname:
                            domain_counts[(qname, 'DNS', src_ip)] += 1
                    # Answers: associate domain with source IP (who accessed it)
                    if dns.an is not None:
                        an = dns.an
                        # May be a RR or a list; iterate robustly
                        answers = []
                        try:
                            i = 0
                            while True:
                                rr = an[i]
                                answers.append(rr)
                                i += 1
                        except Exception:
                            if isinstance(an, DNSRR):
                                answers.append(an)
                        for rr in answers:
                            try:
                                name = rr.rrname.decode(errors='ignore').rstrip('.')
                                if name:
                                    # Store source IP (who accessed) instead of resolved IP
                                    domain_counts[(name, 'DNS', src_ip)] += 1
                            except Exception:
                                continue
    
    except Exception as e:
        log(f"[ANALYZER] ERROR during packet reading: {e}")
        log(f"[ANALYZER] Processed {total_packets} packets before error")
        # Continue with what we have
    
    finally:
        log("[ANALYZER] Cleaning up temporary file...")
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
    
    log("[ANALYZER] Packet processing complete:")
    print(f"  - Total packets: {total_packets}")
    print(f"  - Total bytes: {total_bytes}")
    print(f"  - Packet errors: {packet_errors}")
    print(f"  - Unique IPs: {len(ip_stats)}")
    print(f"  - Flows: {len(flow_stats)}")
    print(f"  - Domains: {len(domain_counts)}")

    avg_size = (size_sum / total_packets) if total_packets else 0.0
    duration_sec = (end_ts - start_ts) if (start_ts is not None and end_ts is not None) else 0.0

    log("[ANALYZER] Starting database writes...")
    
    # Prepare DB writes
    with get_db_connection() as conn:
        cur = conn.cursor()

        # Clear previous analysis artifacts to keep idempotent
        log("[ANALYZER] Clearing previous analysis data...")
        cur.execute('DELETE FROM ip_observations WHERE pcap_id = ?', (pcap_id,))
        cur.execute('DELETE FROM devices WHERE pcap_id = ?', (pcap_id,))
        cur.execute('DELETE FROM domains WHERE pcap_id = ?', (pcap_id,))
        cur.execute('DELETE FROM flows WHERE pcap_id = ?', (pcap_id,))

        # ip_observations
        log(f"[ANALYZER] Inserting {len(ip_stats)} IP observations...")
        for ip, st in ip_stats.items():
            cur.execute(
                'INSERT INTO ip_observations (pcap_id, ip, count) VALUES (?, ?, ?)',
                (pcap_id, ip, int(st['packets']))
            )

        # devices (best-effort from MAC mapping and seen times)
        log(f"[ANALYZER] Inserting {len(ip_stats)} devices...")
        for ip, st in ip_stats.items():
            mac = ip_mac.get(ip)
            hostname = None  # could be filled from DNS PTR in future
            first_seen = float(st['first']) if st['first'] is not None else None
            last_seen = float(st['last']) if st['last'] is not None else None
            cur.execute(
                'INSERT INTO devices (pcap_id, ip, mac, hostname, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?)',
                (pcap_id, ip, mac, hostname, first_seen, last_seen)
            )

        # domains
        log(f"[ANALYZER] Inserting {len(domain_counts)} domain observations...")
        for (domain, source, ip_str), count in domain_counts.items():
            cur.execute(
                'INSERT INTO domains (pcap_id, ip, domain, source, count) VALUES (?, ?, ?, ?, ?) '
                'ON CONFLICT(pcap_id, ip, domain, source) DO UPDATE SET count=excluded.count',
                (pcap_id, ip_str, domain, source, int(count))
            )

        # flows
        log(f"[ANALYZER] Inserting {len(flow_stats)} flows...")
        for (src, sport, dst, dport, proto), st in flow_stats.items():
            cur.execute(
                'INSERT INTO flows (pcap_id, src_ip, src_port, dst_ip, dst_port, protocol, packet_count, byte_count, first_seen, last_seen) '
                'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) '
                'ON CONFLICT(pcap_id, src_ip, src_port, dst_ip, dst_port, protocol) DO UPDATE SET '
                'packet_count=excluded.packet_count, byte_count=excluded.byte_count, first_seen=excluded.first_seen, last_seen=excluded.last_seen',
                (pcap_id, src, sport, dst, dport, proto, int(st['packets']), int(st['bytes']), float(st['first']), float(st['last']))
            )

        analyzed_at = datetime.utcnow().isoformat()
        notes = {
            'captureSummary': {
                'totalPackets': total_packets,
                'totalBytes': total_bytes,
                'startTs': start_ts,
                'endTs': end_ts,
                'durationSec': duration_sec,
                'protocols': dict(protocol_counts),
                'packetSizes': {
                    'min': size_min or 0,
                    'max': size_max or 0,
                    'avg': round(avg_size, 2)
                }
            }
        }

        log("[ANALYZER] Inserting analysis run metadata...")
        cur.execute(
            'INSERT INTO analysis_runs (pcap_id, analyzed_at, duration_ms, notes) VALUES (?, ?, ?, ?) '
            'ON CONFLICT(pcap_id) DO UPDATE SET analyzed_at=excluded.analyzed_at, duration_ms=excluded.duration_ms, notes=excluded.notes',
            (pcap_id, analyzed_at, int(duration_sec * 1000), json.dumps(notes))
        )

        log("[ANALYZER] Committing to database...")
        conn.commit()

    log("[ANALYZER] Analysis complete! Summary:")
    print(f"  - Packets: {total_packets}")
    print(f"  - IPs: {len(ip_stats)}")
    print(f"  - Flows: {len(flow_stats)}")
    print(f"  - Domains: {len(domain_counts)}")
    print(f"  - Duration: {duration_sec:.2f}s")
    
    return notes
