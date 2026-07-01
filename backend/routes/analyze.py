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

			# Enhanced summary: protocols, packets, bytes
			cur.execute('''
				SELECT protocol, SUM(packet_count) as total_packets, SUM(byte_count) as total_bytes
				FROM flows
				WHERE pcap_id = ?
				GROUP BY protocol
			''', (file_id,))
			protocol_rows = cur.fetchall()
			protocols = {}
			total_packets = 0
			total_bytes = 0
			for row in protocol_rows:
				proto = row['protocol']
				pkts = row['total_packets'] or 0
				byts = row['total_bytes'] or 0
				protocols[proto] = {'packets': pkts, 'bytes': byts}
				total_packets += pkts
				total_bytes += byts

			# Unique websites (domains count)
			cur.execute('SELECT COUNT(DISTINCT domain) as c FROM domains WHERE pcap_id = ?', (file_id,))
			unique_websites = cur.fetchone()['c']

			return jsonify({
				'success': True,
				'analyzed': run is not None,
				'analyzed_at': run['analyzed_at'] if run else None,
				'counts': {
					'ips': ips,
					'devices': devices,
					'domains': domains,
					'flows': flows,
					'unique_websites': unique_websites,
					'total_packets': total_packets,
					'total_bytes': total_bytes
				},
				'protocols': protocols
			})
	except Exception as e:
		return jsonify({'error': f'Failed to get summary: {e}'}), 500


@analyze_bp.route('/analysis/<int:file_id>/ips', methods=['GET'])
def list_ips(file_id: int):
	try:
		from flask import request
		
		# Pagination parameters - default 10 rows per page
		page = int(request.args.get('page', 0))
		limit = min(int(request.args.get('limit', 10)), 100)  # Default 10, max 100
		offset = page * limit
		
		with get_db_connection() as conn:
			cur = conn.cursor()
			
			# Get total count
			cur.execute('SELECT COUNT(*) as total FROM ip_observations WHERE pcap_id = ?', (file_id,))
			total = cur.fetchone()['total']
			
			# Get paginated results
			cur.execute('''
				SELECT ip, count FROM ip_observations 
				WHERE pcap_id = ? 
				ORDER BY count DESC 
				LIMIT ? OFFSET ?
			''', (file_id, limit, offset))
			rows = [{'ip': r['ip'], 'count': r['count']} for r in cur.fetchall()]
			
			return jsonify({
				'success': True, 
				'items': rows,
				'pagination': {
					'page': page,
					'limit': limit,
					'total': total,
					'has_more': (offset + len(rows)) < total
				}
			})
	except Exception as e:
		return jsonify({'error': f'Failed to list IPs: {e}'}), 500


@analyze_bp.route('/analysis/<int:file_id>/devices', methods=['GET'])
def list_devices(file_id: int):
	try:
		from flask import request
		
		# Pagination parameters - default 10 rows per page
		page = int(request.args.get('page', 0))
		limit = min(int(request.args.get('limit', 10)), 100)  # Default 10, max 100
		offset = page * limit
		
		with get_db_connection() as conn:
			cur = conn.cursor()
			
			# Get total count
			cur.execute('SELECT COUNT(*) as total FROM devices WHERE pcap_id = ?', (file_id,))
			total = cur.fetchone()['total']
			
			# Get paginated results
			cur.execute('''
				SELECT ip, mac, hostname, first_seen, last_seen 
				FROM devices 
				WHERE pcap_id = ? 
				ORDER BY last_seen DESC 
				LIMIT ? OFFSET ?
			''', (file_id, limit, offset))
			rows = [dict(r) for r in cur.fetchall()]
			
			return jsonify({
				'success': True, 
				'items': rows,
				'pagination': {
					'page': page,
					'limit': limit,
					'total': total,
					'has_more': (offset + len(rows)) < total
				}
			})
	except Exception as e:
		return jsonify({'error': f'Failed to list devices: {e}'}), 500


@analyze_bp.route('/analysis/<int:file_id>/domains', methods=['GET'])
def list_domains(file_id: int):
	try:
		from flask import request
		
		# Pagination parameters - default 10 rows per page
		page = int(request.args.get('page', 0))
		limit = min(int(request.args.get('limit', 10)), 100)  # Default 10, max 100
		offset = page * limit
		
		with get_db_connection() as conn:
			cur = conn.cursor()
			
			# Get total count
			cur.execute('SELECT COUNT(*) as total FROM domains WHERE pcap_id = ?', (file_id,))
			total = cur.fetchone()['total']
			
			# Get paginated results
			cur.execute('''
				SELECT ip, domain, source, count 
				FROM domains 
				WHERE pcap_id = ? 
				ORDER BY count DESC 
				LIMIT ? OFFSET ?
			''', (file_id, limit, offset))
			rows = [dict(r) for r in cur.fetchall()]
			
			return jsonify({
				'success': True, 
				'items': rows,
				'pagination': {
					'page': page,
					'limit': limit,
					'total': total,
					'has_more': (offset + len(rows)) < total
				}
			})
	except Exception as e:
		return jsonify({'error': f'Failed to list domains: {e}'}), 500


@analyze_bp.route('/analysis/<int:file_id>/flows', methods=['GET'])
def list_flows(file_id: int):
	try:
		from flask import request
		
		# Pagination parameters - default 10 rows per page
		page = int(request.args.get('page', 0))
		limit = min(int(request.args.get('limit', 10)), 100)  # Default 10, max 100
		offset = page * limit
		
		with get_db_connection() as conn:
			cur = conn.cursor()
			
			# Get total count
			cur.execute('SELECT COUNT(*) as total FROM flows WHERE pcap_id = ?', (file_id,))
			total = cur.fetchone()['total']
			
			# Get paginated results
			cur.execute('''
				SELECT src_ip, src_port, dst_ip, dst_port, protocol, packet_count, byte_count, first_seen, last_seen
				FROM flows 
				WHERE pcap_id = ? 
				ORDER BY packet_count DESC
				LIMIT ? OFFSET ?
			''', (file_id, limit, offset))
			rows = [dict(r) for r in cur.fetchall()]
			
			return jsonify({
				'success': True, 
				'items': rows,
				'pagination': {
					'page': page,
					'limit': limit,
					'total': total,
					'has_more': (offset + len(rows)) < total
				}
			})
	except Exception as e:
		return jsonify({'error': f'Failed to list flows: {e}'}), 500


@analyze_bp.route('/analysis/<int:file_id>/user_activity', methods=['GET'])
def list_user_activity(file_id: int):
	"""Aggregate per-host activity: IP, MAC, hostname, domains, and time range with pagination."""
	try:
		from flask import request
		
		# Pagination parameters - default 10 rows per page
		page = int(request.args.get('page', 0))
		limit = min(int(request.args.get('limit', 10)), 100)  # Default 10, max 100
		offset = page * limit
		
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

			all_items = []
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

				all_items.append({
					'ip': ip,
					'mac': mac,
					'hostname': hostname,
					'user': None,  # Not currently derived; placeholder for future auth parsing
					'domains': domain_list,
					'time_start': start_ts,
					'time_end': end_ts,
				})

			# Sort by latest activity desc
			all_items.sort(key=lambda x: (x['time_end'] or 0), reverse=True)
			
			# Paginate results
			total = len(all_items)
			items = all_items[offset:offset + limit]
			
			return jsonify({
				'success': True, 
				'items': items,
				'pagination': {
					'page': page,
					'limit': limit,
					'total': total,
					'has_more': (offset + len(items)) < total
				}
			})
	except Exception as e:
		return jsonify({'error': f'Failed to build user activity: {e}'}), 500


@analyze_bp.route('/analysis/<int:file_id>/assess_domains', methods=['POST'])
def assess_domains(file_id: int):
	"""Trigger Gemini-based threat assessment for domains in this PCAP."""
	try:
		from services.threat_assessment import assess_pcap_domains
		
		# Add request timeout to prevent long-hanging requests
		import signal
		import threading
		
		result = None
		error = None
		
		def run_assessment():
			nonlocal result, error
			try:
				result = assess_pcap_domains(file_id)
			except Exception as e:
				error = e
		
		# Run assessment in thread with timeout
		thread = threading.Thread(target=run_assessment)
		thread.daemon = True
		thread.start()
		thread.join(timeout=300)  # 5 minute timeout
		
		if thread.is_alive():
			return jsonify({
				'error': 'Assessment timed out after 5 minutes. Try with fewer domains or check network connectivity.',
				'timeout': True
			}), 408  # Request Timeout
			
		if error:
			error_msg = str(error)
			if 'timeout' in error_msg.lower():
				return jsonify({
					'error': f'Assessment failed due to API timeout: {error_msg}',
					'timeout': True,
					'suggestion': 'The PCAP file has many domains. Please try again - the system will process in smaller chunks.'
				}), 408
			elif 'rate' in error_msg.lower() or 'quota' in error_msg.lower():
				return jsonify({
					'error': f'API rate limit reached: {error_msg}',
					'rate_limit': True,
					'suggestion': 'Please wait a few minutes before trying again.'
				}), 429  # Too Many Requests
			else:
				return jsonify({
					'error': f'Assessment failed: {error_msg}',
					'suggestion': 'Check your API key and network connection.'
				}), 500
		
		if result:
			return jsonify({'success': True, 'result': result})
		else:
			return jsonify({'error': 'Assessment completed but no result returned'}), 500
			
	except ImportError:
		return jsonify({
			'error': 'Gemini assessment not available. Please install required dependencies.',
			'missing_dependency': True
		}), 503  # Service Unavailable
	except Exception as e:
		return jsonify({'error': f'Unexpected error: {e}'}), 500


@analyze_bp.route('/analysis/<int:file_id>/assessments', methods=['GET'])
def get_assessments(file_id: int):
	"""Fetch stored domain assessments for a PCAP."""
	try:
		from flask import request
		
		# Check if summary only is requested
		if request.args.get('summary') == 'true':
			with get_db_connection() as conn:
				cur = conn.cursor()
				cur.execute('''
					SELECT 
						COUNT(*) as total,
						SUM(CASE WHEN verdict = 'malicious' THEN 1 ELSE 0 END) as malicious,
						SUM(CASE WHEN verdict = 'suspicious' THEN 1 ELSE 0 END) as suspicious,
						SUM(CASE WHEN verdict = 'benign' THEN 1 ELSE 0 END) as benign
					FROM domain_assessments
					WHERE pcap_id = ?
				''', (file_id,))
				result = cur.fetchone()
				
				return jsonify({
					'success': True,
					'available': result['total'] > 0,
					'total': result['total'],
					'malicious': result['malicious'],
					'suspicious': result['suspicious'], 
					'benign': result['benign'],
					'threats_found': result['malicious'] + result['suspicious']
				})
		
		# Pagination parameters - default 10 rows per page
		page = int(request.args.get('page', 0))
		limit = min(int(request.args.get('limit', 10)), 100)  # Default 10, max 100
		offset = page * limit
		
		with get_db_connection() as conn:
			cur = conn.cursor()
			
			# Get total count
			cur.execute('SELECT COUNT(*) as total FROM domain_assessments WHERE pcap_id = ?', (file_id,))
			total = cur.fetchone()['total']
			
			# Get paginated results
			cur.execute('''
				SELECT domain, verdict, reasons, assessed_at
				FROM domain_assessments
				WHERE pcap_id = ?
				ORDER BY assessed_at DESC, domain ASC
				LIMIT ? OFFSET ?
			''', (file_id, limit, offset))
			rows = [dict(r) for r in cur.fetchall()]
			
			return jsonify({
				'success': True, 
				'items': rows,
				'pagination': {
					'page': page,
					'limit': limit,
					'total': total,
					'has_more': (offset + len(rows)) < total
				}
			})
	except Exception as e:
		return jsonify({'error': f'Failed to load assessments: {e}'}), 500

