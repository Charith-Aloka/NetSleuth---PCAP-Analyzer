"""
Analysis Routes - Domain assessment stubs using placeholder logic

Implements endpoints referenced in README so the app can start end-to-end.
You can later replace the stub with real Scapy/Gemini-powered analysis.
"""

from flask import Blueprint, jsonify, request
import sqlite3
from datetime import datetime
import json
import os
import sys

# Ensure we can import utils when running as module
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from utils.db import get_db_connection  # type: ignore
from services.analyzer import analyze_pcap  # type: ignore
# Domain assessment via Gemini removed per request

analyze_bp = Blueprint('analyze', __name__)

# Fix for Windows colorama issue - use simple log to stderr
def log(msg):
    """Safe logging that works on Windows"""
    try:
        sys.stderr.write(f"{msg}\n")
        sys.stderr.flush()
    except:
        pass


def _pcap_exists(conn, pcap_id: int) -> bool:
    cur = conn.cursor()
    cur.execute('SELECT 1 FROM pcaps WHERE id = ?', (pcap_id,))
    return cur.fetchone() is not None


@analyze_bp.route('/analysis/<int:pcap_id>/assess_domains', methods=['POST'])
def assess_domains(pcap_id: int):
    """Classify domains using Gemini AI and update verdicts in database."""
    try:
        from services.gemini_service import classify_domains, GeminiUnavailable
        
        # Get optional limit parameter (default to 100 for comprehensive assessment, max 500)
        requested_limit = request.json.get('limit', 100) if request.json else 100
        limit = min(requested_limit, 500)  # Hard cap at 500 domains
        
        log(f"[ASSESS] Starting domain assessment for PCAP {pcap_id} (limit: {limit})")
        
        with get_db_connection() as conn:
            if not _pcap_exists(conn, pcap_id):
                return jsonify({"error": "PCAP not found"}), 404
            
            cur = conn.cursor()
            
            # Clear old "unknown" or "Blocked by safety filter" verdicts before reassessing
            log("[ASSESS] Clearing old blocked/unknown verdicts...")
            cur.execute('''
                UPDATE domains 
                SET verdict = NULL, explanation = NULL 
                WHERE pcap_id = ? AND (
                    verdict = 'unknown' OR 
                    explanation LIKE '%Blocked by safety filter%' OR
                    explanation LIKE '%API error%'
                )
            ''', (pcap_id,))
            conn.commit()
            
            # Get top N domains by count (most accessed first)
            # This prioritizes important/frequently accessed domains
            rows = cur.execute('''
                SELECT domain, SUM(count) as total_count 
                FROM domains 
                WHERE pcap_id = ? AND domain IS NOT NULL 
                GROUP BY domain 
                ORDER BY total_count DESC 
                LIMIT ?
            ''', (pcap_id, limit)).fetchall()
            
            domain_list = [row[0] for row in rows]
            total_domains = cur.execute(
                'SELECT COUNT(DISTINCT domain) FROM domains WHERE pcap_id = ? AND domain IS NOT NULL',
                (pcap_id,)
            ).fetchone()[0]
            
            log(f"[ASSESS] Found {total_domains} total domains, assessing top {len(domain_list)}")
            
            if not domain_list:
                return jsonify({
                    "success": True,
                    "message": "No domains to assess",
                    "assessed": 0,
                    "total_domains": total_domains,
                    "skipped": total_domains
                }), 200
            
            # Classify domains with Gemini (with timeout protection)
            log(f"[ASSESS] Sending {len(domain_list)} domains to Gemini for classification...")
            log(f"[ASSESS] Estimated time: {len(domain_list) * 0.5:.0f}-{len(domain_list):.0f} seconds")
            
            try:
                import time
                start_time = time.time()
                
                verdicts = classify_domains(domain_list)
                
                elapsed = time.time() - start_time
                log(f"[ASSESS] Received {len(verdicts)} verdicts from Gemini in {elapsed:.1f} seconds")
                
            except GeminiUnavailable as e:
                log(f"[ASSESS] ERROR: Gemini unavailable - {e}")
                return jsonify({
                    "error": f"Gemini API unavailable: {str(e)}",
                    "suggestion": "Check your GEMINI_API_KEY in .env file"
                }), 503
            except Exception as e:
                log(f"[ASSESS] ERROR: Gemini classification failed - {e}")
                import traceback
                traceback.print_exc()
                return jsonify({
                    "error": f"Classification failed: {str(e)}",
                    "suggestion": f"Try reducing the limit. Current: {len(domain_list)} domains. Try 25-50 instead."
                }), 500
            
            # Update verdicts and explanations in database for all matching domain entries
            log("[ASSESS] Updating database with verdicts...")
            assessed_count = 0
            for domain, result in verdicts.items():
                # Handle both old format (string) and new format (dict)
                if isinstance(result, dict):
                    verdict = result.get('verdict', 'unknown')
                    explanation = result.get('explanation', '')
                    cur.execute(
                        'UPDATE domains SET verdict = ?, explanation = ? WHERE pcap_id = ? AND domain = ?',
                        (verdict, explanation, pcap_id, domain)
                    )
                else:
                    # Backward compatibility with old string format
                    cur.execute(
                        'UPDATE domains SET verdict = ? WHERE pcap_id = ? AND domain = ?',
                        (result, pcap_id, domain)
                    )
                assessed_count += cur.rowcount
            
            conn.commit()
            log(f"[ASSESS] Database updated, {assessed_count} rows affected")
            
            # Count results by verdict
            malicious = sum(1 for v in verdicts.values() if (v.get('verdict') if isinstance(v, dict) else v) == 'malicious')
            suspicious = sum(1 for v in verdicts.values() if (v.get('verdict') if isinstance(v, dict) else v) == 'suspicious')
            safe = sum(1 for v in verdicts.values() if (v.get('verdict') if isinstance(v, dict) else v) == 'safe')
            unknown = sum(1 for v in verdicts.values() if (v.get('verdict') if isinstance(v, dict) else v) == 'unknown')
            
            skipped = total_domains - len(domain_list)
            
            log("[ASSESS] Assessment complete:")
            log(f"  - Total domains in PCAP: {total_domains}")
            log(f"  - Assessed: {len(domain_list)}")
            log(f"  - Skipped (low priority): {skipped}")
            log(f"  - Malicious: {malicious}, Suspicious: {suspicious}, Safe: {safe}, Unknown: {unknown}")
            
            return jsonify({
                "success": True,
                "message": f"Assessed top {len(domain_list)} of {total_domains} domains",
                "assessed": len(domain_list),
                "total_domains": total_domains,
                "skipped": skipped,
                "updated_rows": assessed_count,
                "verdicts": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "safe": safe,
                    "unknown": unknown
                }
            }), 200
            
    except Exception as e:
        import traceback
        import sys
        # Write errors to file instead of console to avoid colorama issues
        try:
            with open('error.log', 'a') as f:
                f.write(f"Assess domains error: {e}\n")
                f.write(traceback.format_exc())
        except:
            pass
        return jsonify({"error": f"Failed to assess domains: {str(e)}"}), 500


@analyze_bp.route('/analysis/<int:pcap_id>/assessments', methods=['GET'])
def get_assessments(pcap_id: int):
    """Return stored assessments (if any) for a PCAP."""
    try:
        with get_db_connection() as conn:
            if not _pcap_exists(conn, pcap_id):
                return jsonify({"error": "PCAP not found"}), 404

            cur = conn.cursor()
            row = cur.execute('SELECT id, analyzed_at, notes FROM analysis_runs WHERE pcap_id = ?', (pcap_id,)).fetchone()
            if not row:
                return jsonify({"success": True, "pcap_id": pcap_id, "assessments": [], "created": None})

            try:
                notes_obj = json.loads(row[2]) if row[2] else {"assessments": [], "created": row[1]}
            except Exception:
                notes_obj = {"assessments": [], "created": row[1]}

            return jsonify({
                "success": True,
                "run_id": row[0],
                "pcap_id": pcap_id,
                **notes_obj
            })
    except Exception as e:
        log(f"Get assessments error: {e}")
        return jsonify({"error": f"Failed to fetch assessments: {str(e)}"}), 500


# -------- New endpoints for full analysis and retrieval --------

def _pagination_params():
    try:
        page = int(request.args.get('page', '1'))
        page = max(1, page)
    except Exception:
        page = 1
    try:
        page_size = int(request.args.get('page_size', '10'))
        page_size = max(1, min(100, page_size))
    except Exception:
        page_size = 10
    offset = (page - 1) * page_size
    return page, page_size, offset


@analyze_bp.route('/analyze/<int:pcap_id>', methods=['POST'])
def run_analysis(pcap_id: int):
    """Trigger analysis for a PCAP and store results in DB."""
    try:
        with get_db_connection() as conn:
            if not _pcap_exists(conn, pcap_id):
                return jsonify({"error": "PCAP not found"}), 404
        
        # Run PCAP analysis
        notes = analyze_pcap(pcap_id)
        
        # Automatically assess domains with Gemini after analysis
        log(f"[ANALYZE] Starting automatic Gemini assessment for PCAP {pcap_id}")
        try:
            from services.gemini_service import classify_domains, GeminiUnavailable
            
            with get_db_connection() as conn:
                cur = conn.cursor()
                
                # Get unique domains
                rows = cur.execute(
                    'SELECT DISTINCT domain FROM domains WHERE pcap_id = ? AND domain IS NOT NULL',
                    (pcap_id,)
                ).fetchall()
                
                domain_list = [row[0] for row in rows]
                log(f"[ANALYZE] Found {len(domain_list)} unique domains to assess")
                
                if domain_list:
                    # Classify domains with Gemini
                    log(f"[ANALYZE] Calling Gemini API for classification...")
                    verdicts = classify_domains(domain_list)
                    log(f"[ANALYZE] Gemini returned {len(verdicts)} verdicts")
                    
                    # Update database with verdicts and explanations
                    updated_count = 0
                    for domain, result in verdicts.items():
                        if isinstance(result, dict):
                            verdict = result.get('verdict', 'unknown')
                            explanation = result.get('explanation', '')
                            cur.execute(
                                'UPDATE domains SET verdict = ?, explanation = ? WHERE pcap_id = ? AND domain = ?',
                                (verdict, explanation, pcap_id, domain)
                            )
                            updated_count += 1
                    
                    conn.commit()
                    log(f"[ANALYZE] Updated {updated_count} domains with verdicts")
                    notes['domains_assessed'] = len(domain_list)
                    notes['domains_updated'] = updated_count
                else:
                    log("[ANALYZE] No domains found to assess")
                    notes['domains_assessed'] = 0
                    
        except GeminiUnavailable as e:
            log(f"[ANALYZE] Gemini API unavailable: {e}")
            notes['domains_assessed'] = 0
            notes['gemini_error'] = 'Gemini API not available'
        except Exception as e:
            log(f"[ANALYZE] Gemini assessment error: {e}")
            notes['domains_assessed'] = 0
            notes['gemini_error'] = str(e)
        
        return jsonify({"success": True, "pcap_id": pcap_id, **notes}), 201
    except Exception as e:
        log(f"Run analysis error: {e}")
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500


@analyze_bp.route('/analysis/<int:pcap_id>/summary', methods=['GET'])
def get_summary(pcap_id: int):
    """Return analysis summary (captureSummary and related stats)."""
    try:
        with get_db_connection() as conn:
            if not _pcap_exists(conn, pcap_id):
                return jsonify({"error": "PCAP not found"}), 404
            cur = conn.cursor()
            row = cur.execute('SELECT analyzed_at, duration_ms, notes FROM analysis_runs WHERE pcap_id = ?', (pcap_id,)).fetchone()
            if not row:
                return jsonify({"error": "No analysis found for this PCAP"}), 404
            analyzed_at, duration_ms, notes_json = row
            try:
                notes = json.loads(notes_json) if notes_json else {}
            except Exception:
                notes = {}
            return jsonify({
                "success": True,
                "pcap_id": pcap_id,
                "analyzed_at": analyzed_at,
                "duration_ms": duration_ms,
                **notes
            })
    except Exception as e:
        log(f"Get summary error: {e}")
        return jsonify({"error": f"Failed to fetch summary: {str(e)}"}), 500


@analyze_bp.route('/analysis/<int:pcap_id>/ips', methods=['GET'])
def list_ips(pcap_id: int):
    """Paginated list of IP observations with first/last seen and duration."""
    try:
        page, page_size, offset = _pagination_params()
        with get_db_connection() as conn:
            if not _pcap_exists(conn, pcap_id):
                return jsonify({"error": "PCAP not found"}), 404
            cur = conn.cursor()
            total = cur.execute('SELECT COUNT(*) FROM ip_observations WHERE pcap_id = ?', (pcap_id,)).fetchone()[0]
            rows = cur.execute(
                'SELECT io.ip, io.count, d.first_seen, d.last_seen, '
                'COALESCE(SUM(f.byte_count), 0) AS bytes_sent '
                'FROM ip_observations io '
                'LEFT JOIN devices d ON d.pcap_id = io.pcap_id AND d.ip = io.ip '
                'LEFT JOIN flows f ON f.pcap_id = io.pcap_id AND f.src_ip = io.ip '
                'WHERE io.pcap_id = ? '
                'GROUP BY io.ip, io.count, d.first_seen, d.last_seen '
                'ORDER BY io.count DESC LIMIT ? OFFSET ?',
                (pcap_id, page_size, offset)
            ).fetchall()
            return jsonify({
                "success": True,
                "total": total,
                "page": page,
                "page_size": page_size,
                "items": [{
                    "ip": r[0],
                    "count": r[1],
                    "first_seen": r[2],
                    "last_seen": r[3],
                    "bytes_sent": r[4],
                    "duration_sec": (float(r[3]) - float(r[2])) if (r[2] is not None and r[3] is not None) else None
                } for r in rows]
            })
    except Exception as e:
        log(f"List IPs error: {e}")
        return jsonify({"error": f"Failed to list IPs: {str(e)}"}), 500


# Removed older domains route (with Gemini/joins)


@analyze_bp.route('/analysis/<int:pcap_id>/domains', methods=['GET'])
def list_domains(pcap_id: int):
    """Paginated list of domains observed. No classification; preserves NULLs."""
    try:
        page, page_size, offset = _pagination_params()
        with get_db_connection() as conn:
            if not _pcap_exists(conn, pcap_id):
                return jsonify({"error": "PCAP not found"}), 404
            cur = conn.cursor()
            total = cur.execute('SELECT COUNT(*) FROM domains WHERE pcap_id = ?', (pcap_id,)).fetchone()[0]
            rows = cur.execute(
                'SELECT domain, source, ip, count, verdict, explanation FROM domains '
                'WHERE pcap_id = ? ORDER BY count DESC LIMIT ? OFFSET ?',
                (pcap_id, page_size, offset)
            ).fetchall()

            # Helper to decode bytes but keep NULLs intact
            def _decode(v):
                if v is None:
                    return None
                if isinstance(v, (bytes, bytearray)):
                    try:
                        return v.decode('utf-8', 'ignore')
                    except Exception:
                        return str(v)
                return v

            items = []
            for r in rows:
                domain, source, ip, cnt, verdict, explanation = r[0], r[1], r[2], r[3], r[4], r[5]
                items.append({
                    'domain': _decode(domain),
                    'source': _decode(source),
                    'ip': _decode(ip),
                    'count': int(cnt) if cnt is not None else 0,
                    'verdict': _decode(verdict),  # may be None → becomes null in JSON
                    'explanation': _decode(explanation),  # may be None → becomes null in JSON
                })

            return jsonify({
                'success': True,
                'total': total,
                'page': page,
                'page_size': page_size,
                'items': items,
            })
    except Exception as e:
        import traceback
        log(f"List domains error: {e}")
        print(traceback.format_exc())
        return jsonify({'error': f'Failed to list domains: {str(e)}'}), 500


@analyze_bp.route('/analysis/<int:pcap_id>/devices', methods=['GET'])
def list_devices(pcap_id: int):
    """Paginated list of devices observed."""
    try:
        page, page_size, offset = _pagination_params()
        with get_db_connection() as conn:
            if not _pcap_exists(conn, pcap_id):
                return jsonify({"error": "PCAP not found"}), 404
            cur = conn.cursor()
            total = cur.execute('SELECT COUNT(*) FROM devices WHERE pcap_id = ?', (pcap_id,)).fetchone()[0]
            rows = cur.execute(
                'SELECT ip, mac, hostname, first_seen, last_seen FROM devices '
                'WHERE pcap_id = ? ORDER BY first_seen LIMIT ? OFFSET ?',
                (pcap_id, page_size, offset)
            ).fetchall()
            
            items = []
            for r in rows:
                items.append({
                    'ip': r[0],
                    'mac': r[1] if r[1] else '',
                    'hostname': r[2] if r[2] else '',
                    'first_seen': r[3] if r[3] else '',
                    'last_seen': r[4] if r[4] else '',
                })
            
            return jsonify({
                'success': True,
                'total': total,
                'page': page,
                'page_size': page_size,
                'items': items,
            })
    except Exception as e:
        import traceback
        log(f"List devices error: {e}")
        print(traceback.format_exc())
        return jsonify({'error': f'Failed to list devices: {str(e)}'}), 500


@analyze_bp.route('/analysis/<int:pcap_id>/flows', methods=['GET'])
def list_flows(pcap_id: int):
    """Paginated list of network flows."""
    try:
        page, page_size, offset = _pagination_params()
        with get_db_connection() as conn:
            if not _pcap_exists(conn, pcap_id):
                return jsonify({"error": "PCAP not found"}), 404
            cur = conn.cursor()
            total = cur.execute('SELECT COUNT(*) FROM flows WHERE pcap_id = ?', (pcap_id,)).fetchone()[0]
            rows = cur.execute(
                'SELECT src_ip, src_port, dst_ip, dst_port, protocol, packet_count, byte_count, first_seen, last_seen '
                'FROM flows WHERE pcap_id = ? ORDER BY packet_count DESC LIMIT ? OFFSET ?',
                (pcap_id, page_size, offset)
            ).fetchall()
            
            items = []
            for r in rows:
                items.append({
                    'src_ip': r[0],
                    'src_port': r[1] if r[1] else 0,
                    'dst_ip': r[2],
                    'dst_port': r[3] if r[3] else 0,
                    'protocol': r[4] if r[4] else '',
                    'packet_count': r[5],
                    'byte_count': r[6],
                    'first_seen': r[7] if r[7] else '',
                    'last_seen': r[8] if r[8] else '',
                })
            
            return jsonify({
                'success': True,
                'total': total,
                'page': page,
                'page_size': page_size,
                'items': items,
            })
    except Exception as e:
        import traceback
        log(f"List flows error: {e}")
        print(traceback.format_exc())
        return jsonify({'error': f'Failed to list flows: {str(e)}'}), 500
