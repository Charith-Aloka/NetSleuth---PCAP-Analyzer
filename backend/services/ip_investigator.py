"""
IP Investigator Service - AI-powered IP behavior analysis using Gemini

Analyzes IP activity patterns and generates human-readable security reports.
"""

import json
from typing import Dict, Any

try:
    import google.generativeai as genai
    from config.gemini_config import GEMINI_API_KEY
    GEMINI_AVAILABLE = bool(GEMINI_API_KEY)
except ImportError:
    GEMINI_AVAILABLE = False
    print("Warning: google-generativeai not installed")


class GeminiUnavailable(Exception):
    """Raised when Gemini API is not available."""
    pass


def analyze_ip_behavior(report_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze IP behavior using Gemini AI and return security assessment.
    
    Args:
        report_data: Complete IP investigation report
        
    Returns:
        dict with:
        - summary: Human-readable summary
        - risk_level: low/medium/high/critical
        - findings: List of notable observations
        - recommendations: List of action items
    """
    if not GEMINI_AVAILABLE:
        raise GeminiUnavailable("Gemini API not configured")
    
    try:
        # Configure Gemini
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel('gemini-2.0-flash-exp')
        
        # Extract key information
        ip = report_data.get('ip_address', 'Unknown')
        overview = report_data.get('overview', {})
        traffic = report_data.get('traffic', {})
        domains = report_data.get('domains', {})
        connections = report_data.get('connections', {})
        
        # Format traffic info
        total_packets = traffic.get('total', {}).get('packets', 0)
        total_bytes = traffic.get('total', {}).get('bytes', 0)
        total_mb = round(total_bytes / (1024 * 1024), 2)
        
        outgoing_bytes = traffic.get('outgoing', {}).get('bytes', 0)
        incoming_bytes = traffic.get('incoming', {}).get('bytes', 0)
        
        # Protocol breakdown
        protocols = traffic.get('protocols', {})
        protocol_summary = ', '.join([f"{k}: {v}" for k, v in protocols.items()]) if protocols else "N/A"
        
        # Domain summary
        total_domains = domains.get('total', 0)
        safe_domains = domains.get('safe', 0)
        suspicious_domains = domains.get('suspicious', 0)
        malicious_domains = domains.get('malicious', 0)
        risky_domains = domains.get('risky_domains', [])
        
        # Top connections
        top_conns = connections.get('top_connections', [])[:5]
        
        # Build prompt for Gemini
        prompt = f"""You are a network security analyst. Analyze this IP address behavior and provide a security assessment.

IP ADDRESS: {ip}
MAC ADDRESS: {overview.get('mac', 'Unknown')}
ACTIVITY DURATION: {overview.get('duration_sec', 0):.0f} seconds

TRAFFIC STATISTICS:
- Total Packets: {total_packets:,}
- Total Data: {total_mb} MB
- Upload: {outgoing_bytes:,} bytes
- Download: {incoming_bytes:,} bytes
- Protocols: {protocol_summary}

DOMAINS ACCESSED:
- Total: {total_domains}
- Safe: {safe_domains}
- Suspicious: {suspicious_domains}
- Malicious: {malicious_domains}

RISKY DOMAINS:
{chr(10).join([f"- {d['domain']} ({d['verdict']}): {d['explanation']}" for d in risky_domains[:10]]) if risky_domains else "None"}

TOP CONNECTIONS:
{chr(10).join([f"- {c['destination']}:{c['port']} ({c['protocol']}) - {c['packets']} packets, {c['bytes']} bytes" for c in top_conns]) if top_conns else "None"}

ANALYSIS REQUIRED:
1. Provide a 2-3 sentence summary of this IP's behavior
2. Assign a risk level: LOW, MEDIUM, HIGH, or CRITICAL
3. List 3-5 key findings (bullet points)
4. Provide 3-5 security recommendations
5. Identify any suspicious patterns or anomalies

Format your response as JSON:
{{
  "summary": "Brief overview of IP behavior...",
  "risk_level": "low/medium/high/critical",
  "risk_score": 0-100,
  "findings": [
    "Finding 1",
    "Finding 2",
    ...
  ],
  "recommendations": [
    "Recommendation 1",
    "Recommendation 2",
    ...
  ],
  "anomalies": [
    "Anomaly 1 (if any)",
    ...
  ]
}}

Respond ONLY with valid JSON, no markdown formatting."""

        # Call Gemini API with safety settings
        safety_settings = [
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
        ]
        
        response = model.generate_content(prompt, safety_settings=safety_settings)
        
        if not response or not response.text:
            raise Exception("Empty response from Gemini")
        
        # Parse JSON response
        response_text = response.text.strip()
        
        # Remove markdown code blocks if present
        if response_text.startswith('```'):
            lines = response_text.split('\n')
            response_text = '\n'.join(lines[1:-1])
        
        analysis = json.loads(response_text)
        
        # Validate required fields
        if 'summary' not in analysis or 'risk_level' not in analysis:
            raise Exception("Invalid response format from Gemini")
        
        # Normalize risk level
        analysis['risk_level'] = analysis['risk_level'].lower()
        
        # Add metadata
        analysis['generated_at'] = __import__('datetime').datetime.utcnow().isoformat()
        analysis['model'] = 'gemini-2.0-flash-exp'
        
        return analysis
        
    except json.JSONDecodeError as e:
        return {
            'summary': 'AI analysis completed but response format was invalid.',
            'risk_level': 'unknown',
            'risk_score': 50,
            'findings': ['Unable to parse AI response'],
            'recommendations': ['Manual review recommended'],
            'anomalies': [],
            'error': 'JSON parse error'
        }
    
    except Exception as e:
        return {
            'summary': f'AI analysis failed: {str(e)}',
            'risk_level': 'unknown',
            'risk_score': 50,
            'findings': ['AI analysis unavailable'],
            'recommendations': ['Manual review recommended'],
            'anomalies': [],
            'error': str(e)
        }


def batch_analyze_ips(pcap_id: int, ip_addresses: list) -> Dict[str, Dict[str, Any]]:
    """
    Analyze multiple IPs and return summary comparison.
    
    Args:
        pcap_id: PCAP file ID
        ip_addresses: List of IP addresses to analyze
        
    Returns:
        Dictionary mapping IP -> analysis result
    """
    results = {}
    
    for ip in ip_addresses:
        try:
            # This would need to call the investigation endpoint
            # For now, return placeholder
            results[ip] = {
                'summary': f'Analysis for {ip}',
                'risk_level': 'unknown'
            }
        except Exception as e:
            results[ip] = {
                'error': str(e),
                'risk_level': 'unknown'
            }
    
    return results
