"""
Network Graph Route
Provides network topology data for visualization
"""

from flask import Blueprint, jsonify, request
from utils.db import get_db_connection

network_bp = Blueprint('network', __name__)

@network_bp.route('/network-graph/<int:pcap_id>', methods=['GET'])
def get_network_graph(pcap_id):
    """
    Get network graph data showing device relationships and traffic flows
    Returns nodes (devices/IPs) and edges (connections) for visualization
    """
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get all unique IPs and their traffic stats from flows
            cursor.execute("""
                SELECT 
                    ip,
                    SUM(total_packets) as total_packets,
                    SUM(total_bytes) as total_bytes
                FROM (
                    SELECT src_ip as ip, SUM(packet_count) as total_packets, SUM(byte_count) as total_bytes
                    FROM flows
                    WHERE pcap_id = ?
                    GROUP BY src_ip
                    UNION ALL
                    SELECT dst_ip as ip, SUM(packet_count) as total_packets, SUM(byte_count) as total_bytes
                    FROM flows
                    WHERE pcap_id = ?
                    GROUP BY dst_ip
                )
                GROUP BY ip
            """, (pcap_id, pcap_id))
            
            ip_stats = {}
            for row in cursor.fetchall():
                ip_stats[row[0]] = {
                    'packets': row[1] or 0,
                    'bytes': row[2] or 0
                }
            
            # Get device information
            cursor.execute("""
                SELECT ip, mac, hostname, first_seen, last_seen
                FROM devices
                WHERE pcap_id = ?
            """, (pcap_id,))
            
            devices = {}
            for row in cursor.fetchall():
                devices[row[0]] = {
                    'mac': row[1],
                    'hostname': row[2],
                    'first_seen': row[3],
                    'last_seen': row[4]
                }
            
            # Get flows (connections between IPs)
            cursor.execute("""
                SELECT 
                    src_ip,
                    dst_ip,
                    protocol,
                    SUM(packet_count) as packet_count,
                    SUM(byte_count) as total_bytes,
                    GROUP_CONCAT(DISTINCT src_port) as src_ports,
                    GROUP_CONCAT(DISTINCT dst_port) as dst_ports
                FROM flows
                WHERE pcap_id = ?
                GROUP BY src_ip, dst_ip, protocol
                ORDER BY total_bytes DESC
                LIMIT 500
            """, (pcap_id,))
            
            edges = []
            for row in cursor.fetchall():
                edges.append({
                    'from': row[0],
                    'to': row[1],
                    'protocol': row[2],
                    'packets': row[3] or 0,
                    'bytes': row[4] or 0,
                    'src_ports': row[5],
                    'dst_ports': row[6]
                })
            
            # Get domain access information
            cursor.execute("""
                SELECT 
                    ip,
                    domain,
                    verdict,
                    count
                FROM domains
                WHERE pcap_id = ? AND ip IS NOT NULL
            """, (pcap_id,))
            
            domain_access = {}
            for row in cursor.fetchall():
                ip = row[0]
                if ip not in domain_access:
                    domain_access[ip] = []
                domain_access[ip].append({
                    'domain': row[1],
                    'verdict': row[2],
                    'count': row[3]
                })
            
            # Build nodes list
            all_ips = set(ip_stats.keys())
            for edge in edges:
                all_ips.add(edge['from'])
                all_ips.add(edge['to'])
            
            nodes = []
            for ip in all_ips:
                stats = ip_stats.get(ip, {'packets': 0, 'bytes': 0})
                device = devices.get(ip, {})
                domains = domain_access.get(ip, [])
                
                # Determine node type
                is_internal = (ip.startswith('192.168.') or 
                             ip.startswith('10.') or 
                             ip.startswith('172.16.') or
                             ip.startswith('172.17.') or
                             ip.startswith('172.18.') or
                             ip.startswith('172.19.') or
                             ip.startswith('172.20.') or
                             ip.startswith('172.21.') or
                             ip.startswith('172.22.') or
                             ip.startswith('172.23.') or
                             ip.startswith('172.24.') or
                             ip.startswith('172.25.') or
                             ip.startswith('172.26.') or
                             ip.startswith('172.27.') or
                             ip.startswith('172.28.') or
                             ip.startswith('172.29.') or
                             ip.startswith('172.30.') or
                             ip.startswith('172.31.'))
                
                node_type = 'internal' if is_internal else 'external'
                
                # Check if this IP accessed malicious/suspicious domains
                threat_level = 'safe'
                for d in domains:
                    verdict = (d.get('verdict') or 'unknown').lower()
                    if verdict == 'malicious':
                        threat_level = 'malicious'
                        break
                    elif verdict == 'suspicious' and threat_level != 'malicious':
                        threat_level = 'suspicious'
                
                nodes.append({
                    'id': ip,
                    'label': device.get('hostname') or ip,
                    'ip': ip,
                    'mac': device.get('mac'),
                    'hostname': device.get('hostname'),
                    'type': node_type,
                    'threat_level': threat_level,
                    'connections': len([e for e in edges if e['from'] == ip or e['to'] == ip]),
                    'bytes': stats['bytes'],
                    'packets': stats['packets'],
                    'domains': domains
                })
            
            return jsonify({
                'nodes': nodes,
                'edges': edges,
                'stats': {
                    'total_nodes': len(nodes),
                    'total_edges': len(edges),
                    'internal_nodes': len([n for n in nodes if n['type'] == 'internal']),
                    'external_nodes': len([n for n in nodes if n['type'] == 'external']),
                    'threats': len([n for n in nodes if n['threat_level'] in ['malicious', 'suspicious']])
                }
            })
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
