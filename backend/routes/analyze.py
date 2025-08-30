"""
Analyze Routes - Trigger PCAP analysis and fetch structured results
"""

from flask import Blueprint, jsonify
from utils.db import get_db_connection

analyze_bp = Blueprint('analyze', __name__)


@analyze_bp.route('/analyze/<int:file_id>', methods=['POST'])
def analyze_file(file_id: int):
	try:
		# Lazy import to avoid hard dependency at app start
		from services.analyzer import analyze_bytes_and_store
		with get_db_connection() as conn:
			cur = conn.cursor()
			cur.execute('SELECT id, file_data FROM pcaps WHERE id = ?', (file_id,))
			row = cur.fetchone()
			if not row:
				return jsonify({'error': 'File not found'}), 404
			pcap_id = int(row['id'])
			file_bytes = row['file_data']

			summary = analyze_bytes_and_store(conn, pcap_id, file_bytes)
			return jsonify({'success': True, 'summary': summary})
	except Exception as e:
		return jsonify({'error': f'Analysis failed: {e}'}), 500


@analyze_bp.route('/analysis/<int:file_id>/summary', methods=['GET'])
def get_analysis_summary(file_id: int):
	try:
		with get_db_connection() as conn:
			cur = conn.cursor()
			# Check analysis run
			cur.execute('SELECT analyzed_at FROM analysis_runs WHERE pcap_id = ?', (file_id,))
			run = cur.fetchone()

			# Counts
			cur.execute('SELECT COUNT(*) AS c FROM ip_observations WHERE pcap_id = ?', (file_id,))
			ips = cur.fetchone()['c']
			cur.execute('SELECT COUNT(*) AS c FROM devices WHERE pcap_id = ?', (file_id,))
			devices = cur.fetchone()['c']
			cur.execute('SELECT COUNT(*) AS c FROM domains WHERE pcap_id = ?', (file_id,))
			domains = cur.fetchone()['c']
			cur.execute('SELECT COUNT(*) AS c FROM flows WHERE pcap_id = ?', (file_id,))
			flows = cur.fetchone()['c']

			return jsonify({
				'success': True,
				'analyzed': run is not None,
				'analyzed_at': run['analyzed_at'] if run else None,
				'counts': {'ips': ips, 'devices': devices, 'domains': domains, 'flows': flows}
			})
	except Exception as e:
		return jsonify({'error': f'Failed to get summary: {e}'}), 500


@analyze_bp.route('/analysis/<int:file_id>/ips', methods=['GET'])
def list_ips(file_id: int):
	try:
		with get_db_connection() as conn:
			cur = conn.cursor()
			cur.execute('SELECT ip, count FROM ip_observations WHERE pcap_id = ? ORDER BY count DESC', (file_id,))
			rows = [{'ip': r['ip'], 'count': r['count']} for r in cur.fetchall()]
			return jsonify({'success': True, 'items': rows})
	except Exception as e:
		return jsonify({'error': f'Failed to list IPs: {e}'}), 500


@analyze_bp.route('/analysis/<int:file_id>/devices', methods=['GET'])
def list_devices(file_id: int):
	try:
		with get_db_connection() as conn:
			cur = conn.cursor()
			cur.execute('SELECT ip, mac, hostname, first_seen, last_seen FROM devices WHERE pcap_id = ? ORDER BY last_seen DESC', (file_id,))
			rows = [dict(r) for r in cur.fetchall()]
			return jsonify({'success': True, 'items': rows})
	except Exception as e:
		return jsonify({'error': f'Failed to list devices: {e}'}), 500


@analyze_bp.route('/analysis/<int:file_id>/domains', methods=['GET'])
def list_domains(file_id: int):
	try:
		with get_db_connection() as conn:
			cur = conn.cursor()
			cur.execute('SELECT ip, domain, source, count FROM domains WHERE pcap_id = ? ORDER BY count DESC', (file_id,))
			rows = [dict(r) for r in cur.fetchall()]
			return jsonify({'success': True, 'items': rows})
	except Exception as e:
		return jsonify({'error': f'Failed to list domains: {e}'}), 500


@analyze_bp.route('/analysis/<int:file_id>/flows', methods=['GET'])
def list_flows(file_id: int):
	try:
		with get_db_connection() as conn:
			cur = conn.cursor()
			cur.execute('''
				SELECT src_ip, src_port, dst_ip, dst_port, protocol, packet_count, byte_count, first_seen, last_seen
				FROM flows WHERE pcap_id = ? ORDER BY packet_count DESC
			''', (file_id,))
			rows = [dict(r) for r in cur.fetchall()]
			return jsonify({'success': True, 'items': rows})
	except Exception as e:
		return jsonify({'error': f'Failed to list flows: {e}'}), 500


@analyze_bp.route('/analysis/<int:file_id>/user_activity', methods=['GET'])
def list_user_activity(file_id: int):
	"""Aggregate per-host activity: IP, MAC, hostname, domains, and time range."""
	try:
		with get_db_connection() as conn:
			cur = conn.cursor()

			# Collect unique hosts from devices, domains (non-null ip), and flows (src_ip)
			ips = set()
			cur.execute('SELECT DISTINCT ip FROM devices WHERE pcap_id = ?', (file_id,))
			ips.update([r['ip'] for r in cur.fetchall()])
			cur.execute('SELECT DISTINCT ip FROM domains WHERE pcap_id = ? AND ip IS NOT NULL', (file_id,))
			ips.update([r['ip'] for r in cur.fetchall() if r['ip']])
			cur.execute('SELECT DISTINCT src_ip AS ip FROM flows WHERE pcap_id = ?', (file_id,))
			ips.update([r['ip'] for r in cur.fetchall()])

			items = []
			for ip in sorted(ips):
				# Device info
				cur.execute('SELECT mac, hostname, first_seen, last_seen FROM devices WHERE pcap_id = ? AND ip = ? LIMIT 1', (file_id, ip))
				dev = cur.fetchone()
				mac = dev['mac'] if dev else None
				hostname = dev['hostname'] if dev else None

				# Domains: top 5 by total count for this IP
				cur.execute('''
					SELECT domain, SUM(count) AS total
					FROM domains
					WHERE pcap_id = ? AND (ip = ? OR ip IS NULL)
					GROUP BY domain
					ORDER BY total DESC
					LIMIT 5
				''', (file_id, ip))
				domain_list = [r['domain'] for r in cur.fetchall()]

				# Time range from flows for this IP; fallback to device first/last
				cur.execute('SELECT MIN(first_seen) AS start, MAX(last_seen) AS end FROM flows WHERE pcap_id = ? AND src_ip = ?', (file_id, ip))
				rng = cur.fetchone()
				start_ts = rng['start'] if rng and rng['start'] is not None else (dev['first_seen'] if dev else None)
				end_ts = rng['end'] if rng and rng['end'] is not None else (dev['last_seen'] if dev else None)

				items.append({
					'ip': ip,
					'mac': mac,
					'hostname': hostname,
					'user': None,  # Not currently derived; placeholder for future auth parsing
					'domains': domain_list,
					'time_start': start_ts,
					'time_end': end_ts,
				})

			# Sort by latest activity desc
			items.sort(key=lambda x: (x['time_end'] or 0), reverse=True)
			return jsonify({'success': True, 'items': items})
	except Exception as e:
		return jsonify({'error': f'Failed to build user activity: {e}'}), 500

