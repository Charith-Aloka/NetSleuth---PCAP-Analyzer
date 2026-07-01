import os
from typing import Optional
import google.generativeai as genai
import threading
import time
import json


class TimeoutException(Exception):
    pass


class GeminiClient:
    """Thin wrapper to configure and use the Gemini API."""

    def __init__(self, api_key: Optional[str] = None, model: str = 'gemini-1.5-flash'):
        # Prefer explicit arg, then env var, then optional local config file
        key = api_key or os.getenv('GEMINI_API_KEY')
        if not key:
            try:
                from backend.config.gemini_config import GEMINI_API_KEY as LOCAL_KEY  # type: ignore
            except Exception:
                try:
                    from config.gemini_config import GEMINI_API_KEY as LOCAL_KEY  # fallback when run from backend/
                except Exception:
                    LOCAL_KEY = None
            key = LOCAL_KEY
        self.api_key = key
        if not self.api_key:
            raise RuntimeError('GEMINI_API_KEY is not set')
        genai.configure(api_key=self.api_key)
        self.model_name = model
        self._model = genai.GenerativeModel(self.model_name)

    def _make_api_call_with_timeout(self, prompt, timeout_seconds=20):
        """Make API call with timeout protection using threading."""
        result = None
        exception = None
        
        def api_call():
            nonlocal result, exception
            try:
                result = self._model.generate_content(prompt)
            except Exception as e:
                exception = e
        
        # Run API call in thread with timeout
        thread = threading.Thread(target=api_call)
        thread.daemon = True
        thread.start()
        thread.join(timeout=timeout_seconds)
        
        if thread.is_alive():
            # Thread is still running - timeout occurred
            raise TimeoutException(f"API call timed out after {timeout_seconds} seconds")
        
        if exception:
            raise exception
            
        if result is None:
            raise Exception("API call completed but returned no result")
            
        return result

    def classify_domains(self, domains: list[str], prompt_template: str = None) -> list[dict]:
        """Send domains to Gemini and get safety assessment labels.

        Returns list of dicts: { domain, verdict, reasons }
        prompt_template: Optional string with {domains} placeholder.
        """
        if not domains:
            return []
            
        # Limit batch size to prevent API issues  
        if len(domains) > 50:
            print(f"⚠️ Large batch of {len(domains)} domains. Consider using smaller chunks (recommended: 10 domains)")
            
        if prompt_template is None:
            prompt_template = (
                "You are a cybersecurity expert. Analyze these domain names and classify each as malicious, suspicious, or benign.\n\n"
                "IMPORTANT: Respond with ONLY a valid JSON array. No explanations, no markdown, no code blocks.\n\n"
                "For each domain, provide:\n"
                "- domain: the exact domain name\n"
                "- verdict: exactly one of 'malicious', 'suspicious', or 'benign'\n"
                "- reasons: brief explanation for the classification\n\n"
                "Example format:\n"
                '[{{"domain": "example.com", "verdict": "benign", "reasons": "Legitimate website"}}, '
                '{{"domain": "malware.site", "verdict": "malicious", "reasons": "Known malware distribution"}}]\n\n'
                "Analyze these domains:\n{domains}"
            )
        domain_list = '\n'.join(domains)
        prompt = prompt_template.format(domains=domain_list)
        
        # Use shorter timeout for small batches, longer for larger batches
        api_timeout = min(15 + (len(domains) * 0.5), 30)  # 15s base + 0.5s per domain, max 30s
        max_retries = 2  # Reduced retries to fail faster
        
        for attempt in range(max_retries):
            try:
                print(f"🤖 Sending {len(domains)} domains to Gemini (attempt {attempt + 1}, {api_timeout}s timeout)")
                start_time = time.time()
                
                # Use timeout wrapper for API call
                resp = self._make_api_call_with_timeout(prompt, timeout_seconds=api_timeout)
                
                elapsed_time = time.time() - start_time
                print(f"✅ Request completed in {elapsed_time:.1f} seconds")
                
                text = resp.text or ''
                print(f"📝 Gemini response: {len(text)} characters")
                
                # Clean the response - remove markdown code blocks if present
                text = text.strip()
                if text.startswith('```json'):
                    text = text[7:]
                if text.startswith('```'):
                    text = text[3:]
                if text.endswith('```'):
                    text = text[:-3]
                text = text.strip()
                
                # Try to parse JSON
                data = json.loads(text)
                
                if isinstance(data, list):
                    out = []
                    for item in data:
                        if isinstance(item, dict):
                            domain = str(item.get('domain', '')).strip()
                            verdict = str(item.get('verdict', 'unknown')).lower().strip()
                            reasons = str(item.get('reasons', '')).strip()
                            
                            # Ensure verdict is valid
                            if verdict not in ['malicious', 'suspicious', 'benign']:
                                verdict = 'unknown'
                                reasons = f"Invalid verdict: {item.get('verdict', 'none')}"
                                
                            out.append({
                                'domain': domain,
                                'verdict': verdict,
                                'reasons': reasons or 'No reason provided',
                            })
                    
                    # Verify we got results for all domains
                    if len(out) >= len(domains):
                        print(f"✅ Successfully classified {len(out)} domains")
                        return out[:len(domains)]  # Trim to exact count if needed
                    else:
                        print(f"⚠️ Expected {len(domains)} results, got {len(out)} - filling missing")
                        # Fill missing domains
                        processed_domains = {r['domain'] for r in out}
                        for domain in domains:
                            if domain not in processed_domains:
                                out.append({
                                    'domain': domain,
                                    'verdict': 'unknown', 
                                    'reasons': 'Missing from API response'
                                })
                        return out
                        
            except TimeoutException as e:
                print(f"⏱️ TIMEOUT: {e} (attempt {attempt + 1})")
                if attempt < max_retries - 1:
                    print(f"⏳ Waiting 10 seconds before retry...")
                    time.sleep(10)
                    continue
                    
            except json.JSONDecodeError as e:
                print(f"❌ JSON parsing error (attempt {attempt + 1}): {e}")
                if attempt < max_retries - 1:
                    delay = 3
                    print(f"⏳ Retrying in {delay} seconds...")
                    time.sleep(delay)
                    continue
                    
            except Exception as e:
                error_msg = str(e)
                print(f"💥 API error (attempt {attempt + 1}): {error_msg}")
                
                # Check for specific timeout/rate limit errors
                if 'timeout' in error_msg.lower() or 'time' in error_msg.lower():
                    print("⏱️ TIMEOUT DETECTED - API request took too long")
                    if attempt < max_retries - 1:
                        print("⏳ Waiting 10 seconds before retry...")
                        time.sleep(10)
                        continue
                elif 'rate' in error_msg.lower() or 'quota' in error_msg.lower():
                    print("🚫 RATE LIMIT DETECTED - API quota exceeded")
                    if attempt < max_retries - 1:
                        print("⏳ Waiting 15 seconds for rate limit reset...")
                        time.sleep(15)
                        continue
                else:
                    if attempt < max_retries - 1:
                        delay = 5
                        print(f"⏳ Retrying in {delay} seconds...")
                        time.sleep(delay)
                        continue
            
                    continue
                    
        # All retries failed - try simple fallback
        print("🔄 All API attempts failed, trying simplified fallback method")
        try:
            simple_prompt = f"Are these domains safe or dangerous? Just say 'safe' or 'dangerous' for each:\n{domain_list}"
            resp = self._model.generate_content(simple_prompt)
            fallback_text = resp.text or ''
            print("📝 Fallback method got response, parsing...")
            
            # Simple text-based parsing
            results = []
            lines = fallback_text.lower().split('\n')
            for i, domain in enumerate(domains):
                verdict = 'benign'  # Default
                reason = 'Fallback analysis'
                
                # Look for domain-specific results in response
                for line in lines:
                    if domain.lower() in line:
                        if 'dangerous' in line or 'malicious' in line or 'bad' in line:
                            verdict = 'malicious'
                            reason = 'Flagged as dangerous by fallback analysis'
                        elif 'suspicious' in line or 'risky' in line:
                            verdict = 'suspicious' 
                            reason = 'Flagged as suspicious by fallback analysis'
                        break
                        
                results.append({
                    'domain': domain,
                    'verdict': verdict,
                    'reasons': reason
                })
            
            print(f"✅ Fallback method classified {len(results)} domains")
            return results
            
        except Exception as e:
            print(f"💥 Fallback also failed: {e}")
            
        # Final fallback: return unknown for all
        print("⚠️ All analysis methods failed, marking all domains as unknown")
        return [{'domain': d, 'verdict': 'unknown', 'reasons': 'All API attempts failed - possible timeout or network issue'} for d in domains]
