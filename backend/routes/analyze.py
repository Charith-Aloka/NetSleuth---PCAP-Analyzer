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

