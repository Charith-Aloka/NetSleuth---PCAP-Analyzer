"""
NetSleuth PCAP Analyzer - Main Flask Application
Simple upload and delete functionality
"""

from flask import Flask, jsonify
from flask_cors import CORS
from routes.ingest import ingest_bp
from routes.analyze import analyze_bp
from utils.db import init_database
import os

# Create Flask app
app = Flask(__name__)
CORS(app)

# Configuration
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max file size
DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'database', 'netsleuth.db')

# Initialize database
init_database(DB_PATH)

# Register routes
app.register_blueprint(ingest_bp, url_prefix='/api')
app.register_blueprint(analyze_bp, url_prefix='/api')

@app.route('/')
def index():
    """Health check endpoint"""
    return jsonify({
        'message': 'NetSleuth PCAP Analyzer Backend',
        'status': 'running',
        'version': '1.0.0'
    })

@app.route('/health')
def health():
    """Health check for monitoring"""
    return jsonify({'status': 'healthy'})

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    # Run the application
    app.run(host='0.0.0.0', port=5000, debug=True)
