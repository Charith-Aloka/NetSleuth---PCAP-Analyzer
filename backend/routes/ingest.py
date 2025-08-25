"""
Ingest Routes - Handle PCAP file uploads and deletions
"""

import hashlib
from flask import Blueprint, request, jsonify, send_file
from werkzeug.utils import secure_filename
from datetime import datetime
from io import BytesIO
import os
import sys

# Add parent directory to path to import utils
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from utils.db import get_db_connection

ingest_bp = Blueprint('ingest', __name__)

# Allowed PCAP file extensions
ALLOWED_EXTENSIONS = {
    'pcap', 'pcapng', 'cap', 'dmp', 'dump', 'eth', 'fdc', 'pcap1',
    'pcapx', 'snoop', 'cap1', 'cap2', 'trc', 'trace', 'out'
}

def allowed_file(filename):
    """Check if file has allowed extension"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@ingest_bp.route('/upload', methods=['POST'])
def upload_file():
    """Upload and store PCAP file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file selected'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({
                'error': 'Invalid file type', 
                'message': 'Please select a PCAP file (.pcap, .pcapng, .cap, etc.)'
            }), 400
        
        # Read file data
        file_data = file.read()
        if len(file_data) == 0:
            return jsonify({'error': 'Empty file'}), 400
        
        # Generate file metadata
        original_filename = file.filename
        safe_filename = secure_filename(original_filename)
        file_size = len(file_data)
        sha256_hash = hashlib.sha256(file_data).hexdigest()
        mime_type = file.mimetype or 'application/octet-stream'
        uploaded_at = datetime.utcnow().isoformat()
        
        # Store in database
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Check if file already exists (by hash)
            cursor.execute('SELECT id, filename FROM pcaps WHERE sha256 = ?', (sha256_hash,))
            existing = cursor.fetchone()
            
            if existing:
                return jsonify({
                    'error': 'File already exists',
                    'message': f'This file already exists as "{existing[1]}"',
                    'existing_id': existing[0]
                }), 409
            
            # Insert new file
            cursor.execute('''
                INSERT INTO pcaps (filename, original_filename, size, sha256, mime_type, uploaded_at, file_data)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (safe_filename, original_filename, file_size, sha256_hash, mime_type, uploaded_at, file_data))
            
            file_id = cursor.lastrowid
            conn.commit()
        
        return jsonify({
            'success': True,
            'message': 'File uploaded successfully!',
            'file': {
                'id': file_id,
                'filename': safe_filename,
                'original_filename': original_filename,
                'size': file_size,
                'sha256': sha256_hash,
                'uploaded_at': uploaded_at
            }
        }), 201
        
    except Exception as e:
        print(f"Upload error: {str(e)}")
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500

@ingest_bp.route('/files', methods=['GET'])
def list_files():
    """List all uploaded PCAP files"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, filename, original_filename, size, sha256, mime_type, uploaded_at
                FROM pcaps 
                ORDER BY uploaded_at DESC
            ''')
            
            files = []
            for row in cursor.fetchall():
                # Format file size
                size = row[3]
                if size < 1024:
                    size_str = f"{size} B"
                elif size < 1024 * 1024:
                    size_str = f"{size / 1024:.1f} KB"
                elif size < 1024 * 1024 * 1024:
                    size_str = f"{size / (1024 * 1024):.1f} MB"
                else:
                    size_str = f"{size / (1024 * 1024 * 1024):.1f} GB"
                
                files.append({
                    'id': row[0],
                    'filename': row[1],
                    'original_filename': row[2],
                    'size': size,
                    'size_formatted': size_str,
                    'sha256': row[4],
                    'mime_type': row[5],
                    'uploaded_at': row[6]
                })
            
            return jsonify({
                'success': True,
                'files': files,
                'total_count': len(files)
            })
            
    except Exception as e:
        print(f"List files error: {str(e)}")
        return jsonify({'error': f'Failed to list files: {str(e)}'}), 500

@ingest_bp.route('/download/<int:file_id>', methods=['GET'])
def download_file(file_id):
    """Download a PCAP file by ID"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT original_filename, mime_type, file_data 
                FROM pcaps 
                WHERE id = ?
            ''', (file_id,))
            
            row = cursor.fetchone()
            if not row:
                return jsonify({'error': 'File not found'}), 404
            
            filename, mime_type, file_data = row
            
            return send_file(
                BytesIO(file_data),
                as_attachment=True,
                download_name=filename,
                mimetype=mime_type
            )
            
    except Exception as e:
        print(f"Download error: {str(e)}")
        return jsonify({'error': f'Download failed: {str(e)}'}), 500

@ingest_bp.route('/delete/<int:file_id>', methods=['DELETE'])
def delete_file(file_id):
    """Delete a PCAP file"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Check if file exists and get filename
            cursor.execute('SELECT original_filename FROM pcaps WHERE id = ?', (file_id,))
            row = cursor.fetchone()
            
            if not row:
                return jsonify({'error': 'File not found'}), 404
            
            filename = row[0]
            
            # Delete the file
            cursor.execute('DELETE FROM pcaps WHERE id = ?', (file_id,))
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': f'File "{filename}" deleted successfully'
            })
            
    except Exception as e:
        print(f"Delete error: {str(e)}")
        return jsonify({'error': f'Delete failed: {str(e)}'}), 500

@ingest_bp.route('/file/<int:file_id>/info', methods=['GET'])
def get_file_info(file_id):
    """Get detailed information about a file"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, filename, original_filename, size, sha256, mime_type, uploaded_at
                FROM pcaps 
                WHERE id = ?
            ''', (file_id,))
            
            row = cursor.fetchone()
            if not row:
                return jsonify({'error': 'File not found'}), 404
            
            file_info = {
                'id': row[0],
                'filename': row[1],
                'original_filename': row[2],
                'size': row[3],
                'sha256': row[4],
                'mime_type': row[5],
                'uploaded_at': row[6]
            }
            
            return jsonify({
                'success': True,
                'file': file_info
            })
            
    except Exception as e:
        print(f"Get file info error: {str(e)}")
        return jsonify({'error': f'Failed to get file info: {str(e)}'}), 500
