"""
IP Investigation Routes - Deep analysis of specific IP addresses

Provides comprehensive reporting on IP behavior, connections, and security analysis.
"""

from flask import Blueprint, jsonify, request
import sqlite3
from datetime import datetime
from typing import Dict, Any, List

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from utils.db import get_db_connection

investigation_bp = Blueprint('investigation', __name__)


def _pcap_exists(conn, pcap_id: int) -> bool:
    """Check if PCAP exists."""
    cur = conn.cursor()
    cur.execute('SELECT 1 FROM pcaps WHERE id = ?', (pcap_id,))
    return cur.fetchone() is not None


@investigation_bp.route('/investigation/<int:pcap_id>/<ip_address>', methods=['GET'])
def investigate_ip(pcap_id: int, ip_address: str):
    """
    Get comprehensive investigation report for a specific IP address.
    
    Returns:
    - IP overview (MAC, first/last seen, duration)
    - Traffic statistics (packets, bytes, protocols)
    - Domains accessed by this IP
    - Connection flows (incoming/outgoing)
    - Security analysis (with Gemini AI)
    """
    try:
        with get_db_connection() as conn:
            if not _pcap_exists(conn, pcap_id):
                return jsonify({"error": "PCAP not found"}), 404
            
            cur = conn.cursor()
            
            # 1. Get IP Overview from devices table
            device_row = cur.execute(
                'SELECT ip, mac, hostname, first_seen, last_seen FROM devices WHERE pcap_id = ? AND ip = ?',
                (pcap_id, ip_address)
            ).fetchone()
            
            if not device_row:
                return jsonify({"error": "IP address not found in this PCAP"}), 404
            
            ip, mac, hostname, first_seen, last_seen = device_row
            duration_sec = (last_seen - first_seen) if (first_seen and last_seen) else 0
            
            # 2. Get Traffic Statistics from ip_observations
            ip_obs_row = cur.execute(
                'SELECT count FROM ip_observations WHERE pcap_id = ? AND ip = ?',
                (pcap_id, ip_address)
            ).fetchone()
            
            total_packets = ip_obs_row[0] if ip_obs_row else 0
            
            # 3. Get Flow Statistics (outgoing and incoming)
            # Outgoing flows (this IP as source)
            outgoing_flows = cur.execute(
                'SELECT dst_ip, dst_port, protocol, packet_count, byte_count, first_seen, last_seen '
                'FROM flows WHERE pcap_id = ? AND src_ip = ? ORDER BY byte_count DESC LIMIT 50',
                (pcap_id, ip_address)
            ).fetchall()
            
            # Incoming flows (this IP as destination)
            incoming_flows = cur.execute(
                'SELECT src_ip, src_port, protocol, packet_count, byte_count, first_seen, last_seen '
                'FROM flows WHERE pcap_id = ? AND dst_ip = ? ORDER BY byte_count DESC LIMIT 50',
                (pcap_id, ip_address)
            ).fetchall()
            
            # Calculate traffic stats
            outgoing_packets = sum(f[3] for f in outgoing_flows)
            outgoing_bytes = sum(f[4] for f in outgoing_flows)
            incoming_packets = sum(f[3] for f in incoming_flows)
            incoming_bytes = sum(f[4] for f in incoming_flows)
            
            # Protocol breakdown
            protocols = {}
            for flow in outgoing_flows:
                proto = flow[2]
                protocols[proto] = protocols.get(proto, 0) + flow[3]
            
            # 4. Get Domains accessed by this IP
            domains = cur.execute(
                'SELECT domain, source, count, verdict, explanation '
                'FROM domains WHERE pcap_id = ? AND ip = ? ORDER BY count DESC',
                (pcap_id, ip_address)
            ).fetchall()
            
            # Count verdicts
            safe_count = sum(1 for d in domains if d[3] == 'safe')
            suspicious_count = sum(1 for d in domains if d[3] == 'suspicious')
            malicious_count = sum(1 for d in domains if d[3] == 'malicious')
            unknown_count = sum(1 for d in domains if not d[3] or d[3] == 'unknown')
            
            # Get suspicious/malicious domain details
            risky_domains = [
                {'domain': d[0], 'verdict': d[3], 'explanation': d[4], 'count': d[2]}
                for d in domains if d[3] in ['suspicious', 'malicious']
            ]
            
            # 5. Top connections
            top_connections = []
            for flow in outgoing_flows[:10]:  # Top 10
                dst_ip, dst_port, protocol, pkt_count, byte_count, f_first, f_last = flow
                duration = (f_last - f_first) if (f_first and f_last) else 0
                top_connections.append({
                    'destination': dst_ip,
                    'port': dst_port,
                    'protocol': protocol,
                    'packets': pkt_count,
                    'bytes': byte_count,
                    'duration_sec': duration
                })
            
            # 6. Build comprehensive report
            report = {
                'success': True,
                'pcap_id': pcap_id,
                'ip_address': ip_address,
                
                # Overview
                'overview': {
                    'ip': ip,
                    'mac': mac,
                    'hostname': hostname,
                    'first_seen': first_seen,
                    'last_seen': last_seen,
                    'duration_sec': duration_sec,
                    'total_packets': total_packets
                },
                
                # Traffic Statistics
                'traffic': {
                    'outgoing': {
                        'packets': outgoing_packets,
                        'bytes': outgoing_bytes
                    },
                    'incoming': {
                        'packets': incoming_packets,
                        'bytes': incoming_bytes
                    },
                    'total': {
                        'packets': outgoing_packets + incoming_packets,
                        'bytes': outgoing_bytes + incoming_bytes
                    },
                    'protocols': protocols
                },
                
                # Domains
                'domains': {
                    'total': len(domains),
                    'safe': safe_count,
                    'suspicious': suspicious_count,
                    'malicious': malicious_count,
                    'unknown': unknown_count,
                    'risky_domains': risky_domains,
                    'all_domains': [
                        {'domain': d[0], 'count': d[2], 'verdict': d[3], 'explanation': d[4]}
                        for d in domains
                    ]
                },
                
                # Connections
                'connections': {
                    'outgoing_count': len(outgoing_flows),
                    'incoming_count': len(incoming_flows),
                    'top_connections': top_connections
                }
            }
            
            # 7. Generate AI Analysis using Gemini
            try:
                from services.ip_investigator import analyze_ip_behavior
                ai_analysis = analyze_ip_behavior(report)
                report['ai_analysis'] = ai_analysis
            except Exception as e:
                print(f"Gemini analysis failed: {e}")
                report['ai_analysis'] = {
                    'error': 'AI analysis unavailable',
                    'risk_level': 'unknown'
                }
            
            return jsonify(report), 200
            
    except Exception as e:
        import traceback
        print(f"Investigation error: {e}")
        print(traceback.format_exc())
        return jsonify({"error": f"Investigation failed: {str(e)}"}), 500


@investigation_bp.route('/investigation/<int:pcap_id>/ips', methods=['GET'])
def list_ips_for_investigation(pcap_id: int):
    """
    Get list of all IPs in a PCAP for investigation selection.
    """
    try:
        with get_db_connection() as conn:
            if not _pcap_exists(conn, pcap_id):
                return jsonify({"error": "PCAP not found"}), 404
            
            cur = conn.cursor()
            rows = cur.execute(
                'SELECT ip, count FROM ip_observations WHERE pcap_id = ? ORDER BY count DESC',
                (pcap_id,)
            ).fetchall()
            
            ips = [{'ip': r[0], 'packet_count': r[1]} for r in rows]
            
            return jsonify({
                'success': True,
                'pcap_id': pcap_id,
                'total': len(ips),
                'ips': ips
            }), 200
            
    except Exception as e:
        print(f"List IPs error: {e}")
        return jsonify({"error": f"Failed to list IPs: {str(e)}"}), 500
