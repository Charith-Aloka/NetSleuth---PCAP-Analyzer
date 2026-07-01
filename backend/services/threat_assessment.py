from typing import List
from utils.db import get_db_connection
from services.gemini_client import GeminiClient


def get_distinct_domains(pcap_id: int) -> List[str]:
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute('SELECT DISTINCT domain FROM domains WHERE pcap_id = ? ORDER BY domain', (pcap_id,))
        return [r['domain'] for r in cur.fetchall() if r['domain']]


def store_assessments(pcap_id: int, results: List[dict]):
    with get_db_connection() as conn:
        cur = conn.cursor()
        # ensure table exists (idempotent)
        cur.execute('''
            CREATE TABLE IF NOT EXISTS domain_assessments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pcap_id INTEGER NOT NULL,
                domain TEXT NOT NULL,
                verdict TEXT NOT NULL,
                reasons TEXT,
                assessed_at TEXT NOT NULL,
                UNIQUE(pcap_id, domain),
                FOREIGN KEY(pcap_id) REFERENCES pcaps(id) ON DELETE CASCADE
            )
        ''')
        import datetime
        now = datetime.datetime.utcnow().isoformat()
        for item in results:
            cur.execute('''
                INSERT INTO domain_assessments (pcap_id, domain, verdict, reasons, assessed_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(pcap_id, domain) DO UPDATE SET verdict=excluded.verdict, reasons=excluded.reasons, assessed_at=excluded.assessed_at
            ''', (pcap_id, item['domain'], item.get('verdict','unknown'), item.get('reasons',''), now))
        conn.commit()


def assess_pcap_domains(pcap_id: int, prompt_template: str = None) -> dict:
    domains = get_distinct_domains(pcap_id)
    if not domains:
        return { 'count': 0, 'message': 'No domains found in this PCAP file' }
    
    print(f"Found {len(domains)} unique domains to assess")
    
    # Test API connectivity first with a single domain
    client = GeminiClient()
    print("🔌 Testing API connectivity with single domain...")
    try:
        test_result = client.classify_domains([domains[0]], prompt_template=prompt_template)
        if test_result:
            print("✅ API connectivity test passed")
            results.extend(test_result)  # Add the test result
            remaining_domains = domains[1:]  # Skip the tested domain
        else:
            print("❌ API connectivity test failed - no results")
            return { 'count': 0, 'message': 'API connectivity test failed' }
    except Exception as e:
        error_msg = str(e)
        print(f"💥 API connectivity test failed: {error_msg}")
        if 'timeout' in error_msg.lower():
            return { 'count': 0, 'message': f'API timeout during connectivity test: {error_msg}' }
        else:
            return { 'count': 0, 'message': f'API error during connectivity test: {error_msg}' }
    
    # Process remaining domains if any
    if len(remaining_domains) == 0:
        print("✅ Only one domain - connectivity test completed assessment")
        store_assessments(pcap_id, results)
        return {
            'count': len(results),
            'total_domains': len(domains),
            'malicious': sum(1 for r in results if r['verdict'] == 'malicious'),
            'suspicious': sum(1 for r in results if r['verdict'] == 'suspicious'),
            'benign': sum(1 for r in results if r['verdict'] == 'benign'),
            'unknown': sum(1 for r in results if r['verdict'] == 'unknown'),
            'success_rate': "100.0%",
            'chunks_processed': 1
        }
    
    results = []
    
    # Use ultra-small chunk size for maximum reliability (5 domains per request)
    chunk_size = min(5, len(remaining_domains))  # Reduced from 10 to 5 for ultimate stability
    total_chunks = (len(remaining_domains) + chunk_size - 1) // chunk_size
    
    print(f"Processing remaining {len(remaining_domains)} domains in {total_chunks} chunks of {chunk_size}")
    
    for i in range(0, len(remaining_domains), chunk_size):
        batch = remaining_domains[i:i+chunk_size]
        chunk_num = (i // chunk_size) + 1
        print(f"Processing chunk {chunk_num}/{total_chunks} ({len(batch)} domains)")
        
        max_chunk_retries = 2  # Retry failed chunks up to 2 times
        chunk_success = False
        
        for chunk_attempt in range(max_chunk_retries):
            try:
                batch_results = client.classify_domains(batch, prompt_template=prompt_template)
                results.extend(batch_results)
                print(f"✅ Chunk {chunk_num} completed: {len(batch_results)} results")
                chunk_success = True
                break
                
            except Exception as e:
                error_msg = str(e)
                print(f"❌ Chunk {chunk_num} attempt {chunk_attempt + 1} failed: {error_msg}")
                
                if chunk_attempt < max_chunk_retries - 1:
                    if 'timeout' in error_msg.lower():
                        print("⏱️ Timeout detected - waiting 20 seconds before retry...")
                        import time
                        time.sleep(20)  # Increased from 15 to 20 seconds
                    else:
                        print("⏳ Waiting 10 seconds before retry...")
                        import time
                        time.sleep(10)  # Increased from 5 to 10 seconds
                else:
                    print(f"💥 Chunk {chunk_num} failed all retries, adding fallback results")
        
        # If chunk failed completely, add fallback results
        if not chunk_success:
            fallback_results = [
                {'domain': domain, 'verdict': 'unknown', 'reasons': f'Processing failed after retries: timeout or network error'} 
                for domain in batch
            ]
            results.extend(fallback_results)
            
        # Add longer delay between chunks to avoid overwhelming the API
        if chunk_num < total_chunks:  
            import time
            time.sleep(5)  # Increased to 5 seconds delay between chunks
    
    store_assessments(pcap_id, results)
    
    # Provide detailed summary
    malicious = sum(1 for r in results if r['verdict'] == 'malicious')
    suspicious = sum(1 for r in results if r['verdict'] == 'suspicious')
    benign = sum(1 for r in results if r['verdict'] == 'benign')
    unknown = sum(1 for r in results if r['verdict'] == 'unknown')
    
    success_count = len(results) - unknown
    success_rate = (success_count / len(results) * 100) if results else 0
    
    print(f"📊 Final summary: {len(results)} domains processed, {success_rate:.1f}% success rate")
    
    return { 
        'count': len(results),
        'total_domains': len(domains),
        'malicious': malicious,
        'suspicious': suspicious, 
        'benign': benign,
        'unknown': unknown,
        'success_rate': f"{success_rate:.1f}%",
        'chunks_processed': total_chunks
    }
