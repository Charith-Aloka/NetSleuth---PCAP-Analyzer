"""
AI Chat Service - Natural language interface for network analysis
Uses Gemini AI to answer questions about network traffic data
"""

from typing import Dict, Any, List
import json
from services.gemini_service import generate_text, GeminiUnavailable
from utils.db import get_db_connection


class ChatService:
    """Service for handling AI chat interactions"""
    
    def __init__(self):
        self.conversation_history = []
    
    async def process_message(self, message: str, pcap_id: int = None) -> Dict[str, Any]:
        """
        Process a user message and generate an AI response.
        
        Args:
            message: User's question/message
            pcap_id: Optional PCAP ID for context-specific queries
            
        Returns:
            Dict with 'response', 'data', and 'query_executed' fields
        """
        try:
            # Get relevant context from database
            context = self._get_context(pcap_id)
            
            # Build system prompt with context
            system_prompt = self._build_system_prompt(context)
            
            # Generate response using Gemini
            response = await generate_text(
                prompt=message,
                system=system_prompt,
                temperature=0.3,
                max_output_tokens=2048
            )
            
            # Store in conversation history
            self.conversation_history.append({
                'role': 'user',
                'content': message
            })
            self.conversation_history.append({
                'role': 'assistant',
                'content': response
            })
            
            return {
                'response': response,
                'data': context.get('summary', {}),
                'query_executed': True
            }
            
        except GeminiUnavailable as e:
            return {
                'response': f'❌ AI service unavailable: {str(e)}',
                'data': {},
                'query_executed': False
            }
        except Exception as e:
            return {
                'response': f'❌ Error processing message: {str(e)}',
                'data': {},
                'query_executed': False
            }
    
    def _get_context(self, pcap_id: int = None) -> Dict[str, Any]:
        """
        Gather relevant context from the database.
        
        Returns summary statistics, recent threats, top talkers, etc.
        """
        context = {
            'pcaps_available': [],
            'summary': {},
            'recent_threats': [],
            'top_sources': [],
            'top_destinations': [],
            'protocols': {}
        }
        
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                # Get available PCAP files
                cursor.execute("""
                    SELECT id, original_filename, uploaded_at 
                    FROM pcaps 
                    ORDER BY uploaded_at DESC 
                    LIMIT 10
                """)
                context['pcaps_available'] = [
                    {
                        'id': row[0],
                        'filename': row[1],
                        'uploaded_at': row[2]
                    }
                    for row in cursor.fetchall()
                ]
                
                if pcap_id:
                    # Get flows summary for specific PCAP
                    cursor.execute("""
                        SELECT 
                            COUNT(*) as total_flows,
                            COUNT(DISTINCT src_ip) as unique_sources,
                            COUNT(DISTINCT dst_ip) as unique_destinations,
                            SUM(packet_count) as total_packets,
                            SUM(byte_count) as total_bytes
                        FROM flows
                        WHERE pcap_id = ?
                    """, (pcap_id,))
                    row = cursor.fetchone()
                    if row:
                        context['summary'] = {
                            'total_flows': row[0],
                            'unique_sources': row[1],
                            'unique_destinations': row[2],
                            'total_packets': row[3],
                            'total_bytes': row[4]
                        }
                    
                    # Get protocol distribution
                    cursor.execute("""
                        SELECT protocol, COUNT(*) as count, SUM(packet_count) as packets
                        FROM flows
                        WHERE pcap_id = ?
                        GROUP BY protocol
                        ORDER BY count DESC
                    """, (pcap_id,))
                    context['protocols'] = {
                        row[0]: {'count': row[1], 'packets': row[2]}
                        for row in cursor.fetchall()
                    }
                    
                    # Get top source IPs
                    cursor.execute("""
                        SELECT src_ip, COUNT(*) as flows, SUM(packet_count) as packets
                        FROM flows
                        WHERE pcap_id = ?
                        GROUP BY src_ip
                        ORDER BY flows DESC
                        LIMIT 10
                    """, (pcap_id,))
                    context['top_sources'] = [
                        {'ip': row[0], 'flows': row[1], 'packets': row[2]}
                        for row in cursor.fetchall()
                    ]
                    
                    # Get top destination IPs
                    cursor.execute("""
                        SELECT dst_ip, COUNT(*) as flows, SUM(packet_count) as packets
                        FROM flows
                        WHERE pcap_id = ?
                        GROUP BY dst_ip
                        ORDER BY flows DESC
                        LIMIT 10
                    """, (pcap_id,))
                    context['top_destinations'] = [
                        {'ip': row[0], 'flows': row[1], 'packets': row[2]}
                        for row in cursor.fetchall()
                    ]
                    
                    # Get malicious/suspicious domains
                    cursor.execute("""
                        SELECT domain, verdict, explanation, count
                        FROM domains
                        WHERE pcap_id = ? AND verdict IN ('malicious', 'suspicious')
                        ORDER BY count DESC
                        LIMIT 20
                    """, (pcap_id,))
                    context['recent_threats'] = [
                        {
                            'domain': row[0],
                            'verdict': row[1],
                            'explanation': row[2],
                            'count': row[3]
                        }
                        for row in cursor.fetchall()
                    ]
        
        except Exception as e:
            print(f"Error gathering context: {e}")
        
        return context
    
    def _build_system_prompt(self, context: Dict[str, Any]) -> str:
        """
        Build a comprehensive system prompt with network data context.
        """
        prompt_parts = [
            "You are NetSleuth AI, an expert network security analyst assistant.",
            "You help users understand their network traffic by answering questions about PCAP files.",
            "",
            "**Your Capabilities:**",
            "- Explain network traffic patterns and anomalies",
            "- Identify potential security threats",
            "- Analyze IP addresses, protocols, and flows",
            "- Provide insights about domains and DNS queries",
            "- Help investigate suspicious activity",
            "",
            "**Guidelines:**",
            "- Be concise but informative (2-4 sentences typical)",
            "- Use security terminology appropriately",
            "- Highlight threats and anomalies clearly",
            "- Provide actionable recommendations when relevant",
            "- Use emojis sparingly for emphasis (🔴 for threats, ✅ for safe, ⚠️ for warnings)",
            "",
            "**Current Network Context:**"
        ]
        
        # Add PCAP files available
        if context.get('pcaps_available'):
            prompt_parts.append(f"\n📁 **Available PCAP Files:** {len(context['pcaps_available'])} files")
            for pcap in context['pcaps_available'][:3]:
                prompt_parts.append(f"  - {pcap['filename']} (uploaded: {pcap['uploaded_at']})")
        
        # Add summary statistics
        if context.get('summary'):
            summary = context['summary']
            prompt_parts.extend([
                "\n📊 **Traffic Summary:**",
                f"  - Total flows: {summary.get('total_flows', 0):,}",
                f"  - Unique sources: {summary.get('unique_sources', 0)}",
                f"  - Unique destinations: {summary.get('unique_destinations', 0)}",
                f"  - Total packets: {summary.get('total_packets', 0):,}",
                f"  - Total bytes: {summary.get('total_bytes', 0):,}"
            ])
        
        # Add protocol distribution
        if context.get('protocols'):
            prompt_parts.append("\n🔌 **Protocols:**")
            for proto, data in list(context['protocols'].items())[:5]:
                prompt_parts.append(f"  - {proto}: {data['count']} flows, {data['packets']} packets")
        
        # Add top talkers
        if context.get('top_sources'):
            prompt_parts.append("\n📤 **Top Source IPs:**")
            for src in context['top_sources'][:5]:
                prompt_parts.append(f"  - {src['ip']}: {src['flows']} flows")
        
        if context.get('top_destinations'):
            prompt_parts.append("\n📥 **Top Destination IPs:**")
            for dst in context['top_destinations'][:5]:
                prompt_parts.append(f"  - {dst['ip']}: {dst['flows']} flows")
        
        # Add threat information
        if context.get('recent_threats'):
            prompt_parts.append("\n🔴 **Detected Threats:**")
            for threat in context['recent_threats'][:5]:
                emoji = "🔴" if threat['verdict'] == 'malicious' else "⚠️"
                prompt_parts.append(
                    f"  {emoji} {threat['domain']} - {threat['explanation']} ({threat['count']} queries)"
                )
        
        prompt_parts.extend([
            "",
            "Answer the user's question based on this context. If you don't have enough information, say so clearly."
        ])
        
        return "\n".join(prompt_parts)
    
    def clear_history(self):
        """Clear conversation history"""
        self.conversation_history = []
    
    def get_history(self) -> List[Dict[str, str]]:
        """Get conversation history"""
        return self.conversation_history.copy()


# Singleton instance for maintaining conversation state
_chat_service_instance = None

def get_chat_service() -> ChatService:
    """Get or create the chat service singleton"""
    global _chat_service_instance
    if _chat_service_instance is None:
        _chat_service_instance = ChatService()
    return _chat_service_instance
