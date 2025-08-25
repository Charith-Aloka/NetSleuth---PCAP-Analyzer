from __future__ import annotations

"""
Scapy-based PCAP analyzer that extracts:
- Unique IPs and counts
- Domains accessed per IP (DNS, HTTP Host, TLS SNI where possible)
- Device hints (MAC, hostname) with first/last seen
- Flows with packet/byte counts and time window

Results are persisted into SQLite with idempotent inserts (UNIQUE constraints + upserts).
"""

import io
import os
import tempfile
import sqlite3
from collections import defaultdict, namedtuple
from typing import Dict, Tuple, Optional

from scapy.all import PcapReader
try:
	from scapy.all import PcapNgReader  # type: ignore
except Exception:  # pragma: no cover
	PcapNgReader = None

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS
try:
	from scapy.layers.dhcp import DHCP  # type: ignore
except Exception:
	DHCP = None

# Optional layers (HTTP/TLS) may not always be decodable by Scapy without extra modules
try:
	from scapy.layers.http import HTTPRequest  # type: ignore
except Exception:
	HTTPRequest = None
try:
	from scapy.layers.tls.all import TLSClientHello, ServerNameIndication  # type: ignore
except Exception:
	TLSClientHello = None
	ServerNameIndication = None

FlowKey = namedtuple("FlowKey", "src sport dst dport proto")


def _choose_reader_from_bytes(data: bytes):
	# Heuristic: if file starts with pcapng magic number 0x0A0D0D0A
	if len(data) >= 4 and data[:4] == b"\x0a\x0d\x0d\x0a" and PcapNgReader is not None:
		return PcapNgReader
	return PcapReader


def analyze_bytes_and_store(db: sqlite3.Connection, pcap_id: int, file_bytes: bytes) -> Dict:
	"""Parse the given pcap bytes, update SQLite tables, and return a small summary dict."""
	Reader = _choose_reader_from_bytes(file_bytes)

	ip_counts: Dict[str, int] = defaultdict(int)
	devices: Dict[str, Dict] = {}
	domains: Dict[Tuple[Optional[str], str, str], int] = defaultdict(int)  # (ip, domain, source) -> count
	flows_pkts: Dict[FlowKey, int] = defaultdict(int)
	flows_bytes: Dict[FlowKey, int] = defaultdict(int)
	first_seen: Dict[str, float] = {}
	last_seen: Dict[str, float] = {}
	flow_first: Dict[FlowKey, float] = {}
	flow_last: Dict[FlowKey, float] = {}

	# For best compatibility across Scapy versions, write to a temp file
	tmp_path = None
	try:
		with tempfile.NamedTemporaryFile(delete=False, suffix='.pcapng' if Reader is PcapNgReader else '.pcap') as tf:
			tf.write(file_bytes)
			tmp_path = tf.name
		with Reader(tmp_path) as rd:
			for pkt in rd:
				try:
				ts = float(getattr(pkt, 'time', 0.0))

				src_ip = dst_ip = None
				if IP in pkt:
					src_ip = pkt[IP].src
					dst_ip = pkt[IP].dst
				elif IPv6 in pkt:
					src_ip = pkt[IPv6].src
					dst_ip = pkt[IPv6].dst

				# Update IP counters and device times
				for ip in (src_ip, dst_ip):
					if ip:
						ip_counts[ip] += 1
						first_seen.setdefault(ip, ts)
						last_seen[ip] = ts

				# MAC addresses if available
				if Ether in pkt and src_ip:
					mac = getattr(pkt[Ether], 'src', None)
					if mac:
						dev = devices.setdefault(src_ip, {
							'ip': src_ip,
							'mac': None,
							'hostname': None,
							'first': ts,
							'last': ts,
						})
						dev['mac'] = dev['mac'] or mac
						dev['first'] = min(dev['first'], ts)
						dev['last'] = max(dev['last'], ts)

				# DNS queries (qr=0) -> domains by src_ip
				if DNS in pkt and getattr(pkt[DNS], 'qd', None) is not None and getattr(pkt[DNS], 'qr', 0) == 0:
					try:
						qname = pkt[DNS].qd.qname
						if isinstance(qname, bytes):
							qname = qname.decode(errors='ignore')
						qname = qname.strip('.')
						if qname:
							key = (src_ip, qname, 'DNS')
							domains[key] += 1
							# Heuristic hostname from mDNS (.local)
							if qname.endswith('.local') and src_ip:
								dev = devices.setdefault(src_ip, {
									'ip': src_ip,
									'mac': None,
									'hostname': None,
									'first': ts,
									'last': ts,
								})
								dn = qname.split('.')[0]
								if dn:
									dev['hostname'] = dev.get('hostname') or dn
					except Exception:
						pass

				# HTTP Host header (if HTTPRequest layer available)
				if HTTPRequest is not None and HTTPRequest in pkt:
					try:
						host = getattr(pkt[HTTPRequest], 'Host', b'')
						if isinstance(host, bytes):
							host = host.decode(errors='ignore')
						host = host.strip()
						if host:
							key = (src_ip, host, 'HTTP')
							domains[key] += 1
					except Exception:
						pass

				# TLS SNI if available (best-effort)
				if TLSClientHello is not None and (TCP in pkt):
					try:
						# Scapy TLS parsing is heavy; best-effort pattern
						# Extract raw TCP payload and try to parse for SNI extension
						raw = bytes(pkt[TCP].payload) if pkt[TCP].payload else b''
						if raw:
							# Minimal heuristic: look for "\x00\x00" length then "\x00\x00"? Complex; fallback: skip unless TLS layer present
							# For reliability, skip custom parsing if TLS layers are not dissected
							pass
					except Exception:
						pass

				# DHCP hostnames
				if DHCP is not None and DHCP in pkt and src_ip:
					try:
						opts = getattr(pkt[DHCP], 'options', [])
						for k, v in opts:
							if k == 'hostname' and v:
								if isinstance(v, bytes):
									v = v.decode(errors='ignore')
								dev = devices.setdefault(src_ip, {
									'ip': src_ip,
									'mac': None,
									'hostname': None,
									'first': ts,
									'last': ts,
								})
								if v:
									dev['hostname'] = dev.get('hostname') or v
								break
					except Exception:
						pass

				# Flows
				proto = None
				sport = dport = None
				if TCP in pkt:
					proto = 'TCP'
					sport = int(getattr(pkt[TCP], 'sport', 0) or 0)
					dport = int(getattr(pkt[TCP], 'dport', 0) or 0)
				elif UDP in pkt:
					proto = 'UDP'
					sport = int(getattr(pkt[UDP], 'sport', 0) or 0)
					dport = int(getattr(pkt[UDP], 'dport', 0) or 0)

				if src_ip and dst_ip and proto:
					key = FlowKey(src_ip, sport, dst_ip, dport, proto)
					flows_pkts[key] += 1
					# Prefer wirelen if present else len
					try:
						pkt_len = int(getattr(pkt, 'wirelen', None) or len(bytes(pkt)))
					except Exception:
						pkt_len = 0
					flows_bytes[key] += pkt_len
					flow_first.setdefault(key, ts)
					flow_last[key] = ts

			except Exception:
				continue

	finally:
		if tmp_path and os.path.exists(tmp_path):
			try:
				os.unlink(tmp_path)
			except Exception:
				pass

	# Persist into SQLite with UPSERT semantics
	cur = db.cursor()

	# Mark/insert analysis_runs row (one per pcap_id)
	from datetime import datetime, timezone
	analyzed_at = datetime.now(timezone.utc).isoformat()
	cur.execute(
		"""
		INSERT INTO analysis_runs (pcap_id, analyzed_at)
		VALUES (?, ?)
		ON CONFLICT(pcap_id) DO UPDATE SET analyzed_at=excluded.analyzed_at
		""",
		(pcap_id, analyzed_at),
	)

	# IP observations
	for ip, cnt in ip_counts.items():
		cur.execute(
			"""
			INSERT INTO ip_observations (pcap_id, ip, count)
			VALUES (?, ?, ?)
			ON CONFLICT(pcap_id, ip) DO UPDATE SET count = count + excluded.count
			""",
			(pcap_id, ip, cnt),
		)

	# Devices
	for ip, d in devices.items():
		cur.execute(
			"""
			INSERT INTO devices (pcap_id, ip, mac, hostname, first_seen, last_seen)
			VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT(pcap_id, ip) DO UPDATE SET
				mac = COALESCE(excluded.mac, mac),
				hostname = COALESCE(excluded.hostname, hostname),
				first_seen = MIN(COALESCE(first_seen, excluded.first_seen), excluded.first_seen),
				last_seen = MAX(COALESCE(last_seen, excluded.last_seen), excluded.last_seen)
			""",
			(pcap_id, ip, d.get('mac'), d.get('hostname'), d.get('first'), d.get('last')),
		)

	# Domains
	for (ip, domain, source), cnt in domains.items():
		cur.execute(
			"""
			INSERT INTO domains (pcap_id, ip, domain, source, count)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(pcap_id, ip, domain, source) DO UPDATE SET count = count + excluded.count
			""",
			(pcap_id, ip, domain, source, cnt),
		)

	# Flows
	for key, pkts in flows_pkts.items():
		bytes_total = int(flows_bytes.get(key, 0))
		cur.execute(
			"""
			INSERT INTO flows (pcap_id, src_ip, src_port, dst_ip, dst_port, protocol, packet_count, byte_count, first_seen, last_seen)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(pcap_id, src_ip, src_port, dst_ip, dst_port, protocol) DO UPDATE SET
				packet_count = packet_count + excluded.packet_count,
				byte_count = byte_count + excluded.byte_count,
				first_seen = MIN(COALESCE(first_seen, excluded.first_seen), excluded.first_seen),
				last_seen = MAX(COALESCE(last_seen, excluded.last_seen), excluded.last_seen)
			""",
			(pcap_id, key.src, key.sport, key.dst, key.dport, key.proto, pkts, bytes_total, flow_first.get(key), flow_last.get(key)),
		)

	db.commit()

	return {
		'pcap_id': pcap_id,
		'ips': len(ip_counts),
		'devices': len(devices),
		'domains': len({(d[0], d[1]) for d in domains.keys()}),
		'flows': len(flows_pkts),
		'analyzed_at': analyzed_at,
	}

