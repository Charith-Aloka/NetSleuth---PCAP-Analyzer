"""
Threat Intelligence Service
Integrates with VirusTotal and AbuseIPDB for IP reputation checking
"""

import requests
import time
from datetime import datetime, timedelta
from config.threat_intel_config import (
    VIRUSTOTAL_API_KEY, VIRUSTOTAL_BASE_URL,
    ABUSEIPDB_API_KEY, ABUSEIPDB_BASE_URL,
    CACHE_EXPIRY_HOURS
)

# Simple in-memory cache (consider Redis for production)
_cache = {}

class ThreatIntelligenceService:
    """Service for querying threat intelligence APIs"""
    
    def __init__(self):
        self.vt_enabled = bool(VIRUSTOTAL_API_KEY)
        self.abuseipdb_enabled = bool(ABUSEIPDB_API_KEY)
        self.last_vt_request = 0
        self.vt_rate_limit = 15  # 15 seconds between requests (4 per minute)
    
    def check_ip(self, ip_address):
        """
        Check IP reputation across all available services
        Returns combined threat intelligence data
        """
        # Check cache first
        cache_key = f"ip_{ip_address}"
        if cache_key in _cache:
            cached_data, cached_time = _cache[cache_key]
            if datetime.now() - cached_time < timedelta(hours=CACHE_EXPIRY_HOURS):
                return cached_data
        
        results = {
            'ip': ip_address,
            'timestamp': datetime.now().isoformat(),
            'sources': []
        }
        
        # Query VirusTotal
        if self.vt_enabled:
            vt_data = self._check_virustotal(ip_address)
            if vt_data:
                results['sources'].append(vt_data)
        
        # Query AbuseIPDB
        if self.abuseipdb_enabled:
            abuse_data = self._check_abuseipdb(ip_address)
            if abuse_data:
                results['sources'].append(abuse_data)
        
        # Calculate overall threat score
        results['threat_score'] = self._calculate_threat_score(results['sources'])
        results['threat_level'] = self._get_threat_level(results['threat_score'])
        results['is_malicious'] = results['threat_score'] >= 70
        
        # Cache results
        _cache[cache_key] = (results, datetime.now())
        
        return results
    
    def _check_virustotal(self, ip_address):
        """Query VirusTotal API for IP reputation"""
        try:
            # Rate limiting
            current_time = time.time()
            time_since_last = current_time - self.last_vt_request
            if time_since_last < self.vt_rate_limit:
                time.sleep(self.vt_rate_limit - time_since_last)
            
            url = f"{VIRUSTOTAL_BASE_URL}/ip_addresses/{ip_address}"
            headers = {
                'x-apikey': VIRUSTOTAL_API_KEY
            }
            
            response = requests.get(url, headers=headers, timeout=10)
            self.last_vt_request = time.time()
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})
                
                total_votes = sum(stats.values())
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                
                # Calculate score (0-100)
                if total_votes > 0:
                    score = ((malicious * 2 + suspicious) / (total_votes * 2)) * 100
                else:
                    score = 0
                
                return {
                    'source': 'VirusTotal',
                    'score': round(score, 2),
                    'malicious_count': malicious,
                    'suspicious_count': suspicious,
                    'harmless_count': stats.get('harmless', 0),
                    'undetected_count': stats.get('undetected', 0),
                    'total_engines': total_votes,
                    'country': attributes.get('country'),
                    'asn': attributes.get('asn'),
                    'as_owner': attributes.get('as_owner'),
                    'details': f"{malicious} malicious, {suspicious} suspicious out of {total_votes} engines"
                }
            elif response.status_code == 404:
                return {
                    'source': 'VirusTotal',
                    'score': 0,
                    'details': 'No data available',
                    'malicious_count': 0
                }
            else:
                return {
                    'source': 'VirusTotal',
                    'error': f"API error: {response.status_code}",
                    'score': 0
                }
                
        except Exception as e:
            return {
                'source': 'VirusTotal',
                'error': str(e),
                'score': 0
            }
    
    def _check_abuseipdb(self, ip_address):
        """Query AbuseIPDB API for IP abuse reports"""
        try:
            url = f"{ABUSEIPDB_BASE_URL}/check"
            headers = {
                'Key': ABUSEIPDB_API_KEY,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                ip_data = data.get('data', {})
                
                abuse_score = ip_data.get('abuseConfidenceScore', 0)
                total_reports = ip_data.get('totalReports', 0)
                
                return {
                    'source': 'AbuseIPDB',
                    'score': abuse_score,
                    'abuse_confidence_score': abuse_score,
                    'total_reports': total_reports,
                    'num_distinct_users': ip_data.get('numDistinctUsers', 0),
                    'last_reported': ip_data.get('lastReportedAt'),
                    'country': ip_data.get('countryCode'),
                    'is_whitelisted': ip_data.get('isWhitelisted', False),
                    'usage_type': ip_data.get('usageType'),
                    'isp': ip_data.get('isp'),
                    'domain': ip_data.get('domain'),
                    'details': f"Abuse confidence: {abuse_score}% ({total_reports} reports)"
                }
            else:
                return {
                    'source': 'AbuseIPDB',
                    'error': f"API error: {response.status_code}",
                    'score': 0
                }
                
        except Exception as e:
            return {
                'source': 'AbuseIPDB',
                'error': str(e),
                'score': 0
            }
    
    def _calculate_threat_score(self, sources):
        """Calculate overall threat score from multiple sources"""
        if not sources:
            return 0
        
        # Weight the scores (you can adjust these weights)
        weights = {
            'VirusTotal': 0.6,
            'AbuseIPDB': 0.4
        }
        
        total_score = 0
        total_weight = 0
        
        for source in sources:
            if 'error' not in source and 'score' in source:
                source_name = source['source']
                weight = weights.get(source_name, 0.5)
                total_score += source['score'] * weight
                total_weight += weight
        
        if total_weight > 0:
            return round(total_score / total_weight, 2)
        return 0
    
    def _get_threat_level(self, score):
        """Convert score to threat level"""
        if score >= 80:
            return 'critical'
        elif score >= 60:
            return 'high'
        elif score >= 40:
            return 'medium'
        elif score >= 20:
            return 'low'
        else:
            return 'clean'
    
    def check_multiple_ips(self, ip_list):
        """Check multiple IPs (useful for batch scanning)"""
        results = []
        for ip in ip_list:
            result = self.check_ip(ip)
            results.append(result)
            # Small delay between requests to avoid rate limiting
            time.sleep(0.5)
        return results
    
    def get_service_status(self):
        """Get status of threat intelligence services"""
        return {
            'virustotal': {
                'enabled': self.vt_enabled,
                'configured': bool(VIRUSTOTAL_API_KEY)
            },
            'abuseipdb': {
                'enabled': self.abuseipdb_enabled,
                'configured': bool(ABUSEIPDB_API_KEY)
            },
            'cache_size': len(_cache)
        }

# Create singleton instance
threat_intel_service = ThreatIntelligenceService()
