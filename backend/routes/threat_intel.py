"""
Threat Intelligence Routes
API endpoints for checking IP reputation
"""

from flask import Blueprint, jsonify, request
from services.threat_intel_service import threat_intel_service

threat_intel_bp = Blueprint('threat_intel', __name__)

@threat_intel_bp.route('/threat-intel/check/<ip_address>', methods=['GET'])
def check_ip_reputation(ip_address):
    """
    Check IP reputation using threat intelligence services
    Returns data from VirusTotal and AbuseIPDB
    """
    try:
        result = threat_intel_service.check_ip(ip_address)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@threat_intel_bp.route('/threat-intel/batch', methods=['POST'])
def check_multiple_ips():
    """
    Check multiple IPs in batch
    Expects JSON body: {"ips": ["1.2.3.4", "5.6.7.8"]}
    """
    try:
        data = request.get_json()
        ip_list = data.get('ips', [])
        
        if not ip_list:
            return jsonify({'error': 'No IPs provided'}), 400
        
        if len(ip_list) > 50:
            return jsonify({'error': 'Maximum 50 IPs per request'}), 400
        
        results = threat_intel_service.check_multiple_ips(ip_list)
        
        return jsonify({
            'total': len(results),
            'results': results
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@threat_intel_bp.route('/threat-intel/status', methods=['GET'])
def get_service_status():
    """Get status of threat intelligence services"""
    try:
        status = threat_intel_service.get_service_status()
        return jsonify(status)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@threat_intel_bp.route('/threat-intel/pcap/<int:pcap_id>/scan', methods=['POST'])
def scan_pcap_ips(pcap_id):
    """
    Scan all IPs from a PCAP file using threat intelligence
    Returns threat analysis for all external IPs
    """
    try:
        from utils.db import get_db_connection
        
        # Get all unique external IPs from the PCAP
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get external IPs (not private ranges)
            cursor.execute("""
                SELECT DISTINCT ip 
                FROM (
                    SELECT src_ip as ip FROM flows WHERE pcap_id = ?
                    UNION
                    SELECT dst_ip as ip FROM flows WHERE pcap_id = ?
                ) 
                WHERE ip NOT LIKE '192.168.%' 
                AND ip NOT LIKE '10.%' 
                AND ip NOT LIKE '172.16.%'
                AND ip NOT LIKE '172.17.%'
                AND ip NOT LIKE '172.18.%'
                AND ip NOT LIKE '172.19.%'
                AND ip NOT LIKE '172.20.%'
                AND ip NOT LIKE '172.21.%'
                AND ip NOT LIKE '172.22.%'
                AND ip NOT LIKE '172.23.%'
                AND ip NOT LIKE '172.24.%'
                AND ip NOT LIKE '172.25.%'
                AND ip NOT LIKE '172.26.%'
                AND ip NOT LIKE '172.27.%'
                AND ip NOT LIKE '172.28.%'
                AND ip NOT LIKE '172.29.%'
                AND ip NOT LIKE '172.30.%'
                AND ip NOT LIKE '172.31.%'
                AND ip NOT LIKE '127.%'
                LIMIT 100
            """, (pcap_id, pcap_id))
            
            ips = [row[0] for row in cursor.fetchall()]
        
        if not ips:
            return jsonify({
                'message': 'No external IPs found in this PCAP',
                'total': 0,
                'results': []
            })
        
        # Scan the IPs
        results = threat_intel_service.check_multiple_ips(ips)
        
        # Categorize results
        threats = [r for r in results if r.get('is_malicious', False)]
        suspicious = [r for r in results if r.get('threat_score', 0) >= 40 and not r.get('is_malicious', False)]
        clean = [r for r in results if r.get('threat_score', 0) < 40]
        
        return jsonify({
            'total': len(results),
            'threats_found': len(threats),
            'suspicious_found': len(suspicious),
            'clean': len(clean),
            'results': results,
            'summary': {
                'critical': len([r for r in results if r.get('threat_level') == 'critical']),
                'high': len([r for r in results if r.get('threat_level') == 'high']),
                'medium': len([r for r in results if r.get('threat_level') == 'medium']),
                'low': len([r for r in results if r.get('threat_level') == 'low']),
                'clean': len([r for r in results if r.get('threat_level') == 'clean'])
            }
        })
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
