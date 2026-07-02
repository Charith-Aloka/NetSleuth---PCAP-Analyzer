"""
Threat Intelligence Configuration
API keys for VirusTotal and AbuseIPDB
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Get the directory of this config file
config_dir = Path(__file__).resolve().parent
# Go up one level to backend directory where .env is
backend_dir = config_dir.parent
env_path = backend_dir / '.env'

# Load environment variables from .env file
load_dotenv(dotenv_path=env_path)

# VirusTotal API Configuration
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
VIRUSTOTAL_BASE_URL = 'https://www.virustotal.com/api/v3'

# AbuseIPDB API Configuration
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', '')
ABUSEIPDB_BASE_URL = 'https://api.abuseipdb.com/api/v2'

# Rate limiting settings
VIRUSTOTAL_REQUESTS_PER_MINUTE = 4  # Free tier limit
ABUSEIPDB_REQUESTS_PER_DAY = 1000   # Free tier limit

# Cache settings
CACHE_EXPIRY_HOURS = 24  # Cache results for 24 hours

def is_configured():
    """Check if threat intelligence APIs are configured"""
    return bool(VIRUSTOTAL_API_KEY or ABUSEIPDB_API_KEY)

def get_available_services():
    """Get list of available threat intelligence services"""
    services = []
    if VIRUSTOTAL_API_KEY:
        services.append('virustotal')
    if ABUSEIPDB_API_KEY:
        services.append('abuseipdb')
    return services
