## Threat Assessment with Gemini

This backend can classify domains seen in a PCAP using Google Gemini.

Setup:
- Install deps: pip install -r requirements.txt
- Set API key: on PowerShell, $env:GEMINI_API_KEY = "<your_api_key>"
- Run backend: python app.py

API endpoints:
- POST /api/analysis/<pcap_id>/assess_domains — triggers classification and stores results
- GET /api/analysis/<pcap_id>/assessments — fetch stored results

