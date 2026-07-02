"""
Chat API Routes - Natural language interface endpoints
"""

from flask import Blueprint, request, jsonify
from services.chat_service import get_chat_service
import asyncio

chat_bp = Blueprint('chat', __name__, url_prefix='/api/chat')


@chat_bp.route('/message', methods=['POST'])
def send_message():
    """
    Send a message to the AI chatbot.
    
    Request JSON:
        {
            "message": "What are the top threats?",
            "pcap_id": 1  // optional - for context-specific queries
        }
    
    Response JSON:
        {
            "response": "AI response text",
            "data": {...},  // relevant data/statistics
            "timestamp": "2024-01-01T12:00:00"
        }
    """
    try:
        data = request.get_json()
        
        if not data or 'message' not in data:
            return jsonify({
                'error': 'Missing required field: message'
            }), 400
        
        message = data['message'].strip()
        if not message:
            return jsonify({
                'error': 'Message cannot be empty'
            }), 400
        
        pcap_id = data.get('pcap_id')
        
        # Get chat service and process message
        chat_service = get_chat_service()
        
        # Run async function in sync context
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(
            chat_service.process_message(message, pcap_id)
        )
        loop.close()
        
        from datetime import datetime
        result['timestamp'] = datetime.utcnow().isoformat()
        
        return jsonify(result), 200
        
    except Exception as e:
        return jsonify({
            'error': f'Failed to process message: {str(e)}'
        }), 500


@chat_bp.route('/history', methods=['GET'])
def get_history():
    """
    Get conversation history.
    
    Response JSON:
        {
            "history": [
                {"role": "user", "content": "..."},
                {"role": "assistant", "content": "..."}
            ]
        }
    """
    try:
        chat_service = get_chat_service()
        history = chat_service.get_history()
        
        return jsonify({
            'history': history
        }), 200
        
    except Exception as e:
        return jsonify({
            'error': f'Failed to get history: {str(e)}'
        }), 500


@chat_bp.route('/clear', methods=['POST'])
def clear_history():
    """
    Clear conversation history.
    
    Response JSON:
        {
            "success": true,
            "message": "History cleared"
        }
    """
    try:
        chat_service = get_chat_service()
        chat_service.clear_history()
        
        return jsonify({
            'success': True,
            'message': 'Conversation history cleared'
        }), 200
        
    except Exception as e:
        return jsonify({
            'error': f'Failed to clear history: {str(e)}'
        }), 500


@chat_bp.route('/suggestions', methods=['GET'])
def get_suggestions():
    """
    Get suggested questions based on available data.
    
    Query params:
        pcap_id: Optional PCAP ID for context-specific suggestions
    
    Response JSON:
        {
            "suggestions": ["question 1", "question 2", ...]
        }
    """
    try:
        pcap_id = request.args.get('pcap_id', type=int)
        
        # Basic suggestions
        suggestions = [
            "What are the top threats in my network?",
            "Show me the most active IP addresses",
            "Which protocols are being used?",
            "Are there any suspicious domains?",
            "What's the overall security status?",
            "Explain the traffic patterns",
            "Which IPs have the most connections?",
            "Are there any DNS anomalies?"
        ]
        
        if pcap_id:
            # Add context-specific suggestions
            suggestions.extend([
                "Summarize this PCAP file",
                "What are the key findings in this capture?",
                "Are there any security issues here?"
            ])
        
        return jsonify({
            'suggestions': suggestions
        }), 200
        
    except Exception as e:
        return jsonify({
            'error': f'Failed to get suggestions: {str(e)}'
        }), 500
