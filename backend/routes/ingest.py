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
    """Upload and store PCAP file. Accepts 'file' or 'files' (multiple)."""
    try:
        # Accept either 'file' or 'files'
        files_list = []
        if 'files' in request.files:
            files_list = request.files.getlist('files')
        elif 'file' in request.files:
            files_list = [request.files['file']]
        else:
            return jsonify({'error': 'No file selected'}), 400

        saved = []
        with get_db_connection() as conn:
            cursor = conn.cursor()
            for file in files_list:
                if file.filename == '':
                    continue
                if not allowed_file(file.filename):
                    continue
                data = file.read()
                if not data:
                    continue
                original_filename = file.filename
                safe_filename = secure_filename(original_filename)
                size = len(data)
                sha256_hash = hashlib.sha256(data).hexdigest()
                mime_type = file.mimetype or 'application/octet-stream'
                uploaded_at = datetime.utcnow().isoformat()
                # skip duplicates by hash
                cursor.execute('SELECT id, filename FROM pcaps WHERE sha256 = ?', (sha256_hash,))
                existing = cursor.fetchone()
                if existing:
                    saved.append({'id': existing[0], 'filename': existing[1], 'original_filename': original_filename, 'size': size, 'sha256': sha256_hash, 'uploaded_at': uploaded_at, 'duplicate': True})
                    continue
                cursor.execute('''
                    INSERT INTO pcaps (filename, original_filename, size, sha256, mime_type, uploaded_at, file_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (safe_filename, original_filename, size, sha256_hash, mime_type, uploaded_at, data))
                file_id = cursor.lastrowid
                saved.append({'id': file_id, 'filename': safe_filename, 'original_filename': original_filename, 'size': size, 'sha256': sha256_hash, 'uploaded_at': uploaded_at})
            conn.commit()

        if not saved:
            return jsonify({'error': 'No valid files to upload'}), 400

        return jsonify({'success': True, 'message': 'Upload completed', 'files': saved}), 201
        
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

@ingest_bp.route('/files', methods=['DELETE'])
def delete_all_files():
    """Delete all PCAP files"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM pcaps')
            conn.commit()
        return jsonify({'success': True, 'message': 'All files deleted'})
    except Exception as e:
        print(f"Delete all files error: {str(e)}")
        return jsonify({'error': f'Delete all failed: {str(e)}'}), 500

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
