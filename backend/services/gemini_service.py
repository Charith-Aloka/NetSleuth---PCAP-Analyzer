from __future__ import annotations

import json
import sys
from typing import Iterable, Dict, Any

import google.generativeai as genai  # type: ignore

try:
    from config.gemini_config import GEMINI_API_KEY  # type: ignore
except Exception:  # pragma: no cover
    GEMINI_API_KEY = None  # type: ignore

# Defaults for model and generation settings
# Using stable Gemini 2.5 Flash model
DEFAULT_MODEL_NAME = "gemini-2.5-flash"
DEFAULT_GENERATION_CONFIG: Dict[str, Any] = {
    "temperature": 0.2,
    "top_p": 0.9,
    "top_k": 40,
    "max_output_tokens": 1024,
}

# Fix for Windows colorama issue - use simple log to stderr
def log(msg):
    """Safe logging that works on Windows"""
    try:
        sys.stderr.write(f"{msg}\n")
        sys.stderr.flush()
    except:
        pass


class GeminiUnavailable(Exception):
    pass


def _get_client_and_model():
    api_key = GEMINI_API_KEY
    if not api_key:
        raise GeminiUnavailable('GEMINI_API_KEY is not configured')
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(DEFAULT_MODEL_NAME)
    return model


async def generate_text(prompt: str, system: str | None = None, **params) -> str:
    """Generate text for a single prompt.

    Returns the response text. Raises GeminiUnavailable on missing config.
    """
    model = _get_client_and_model()
    config = {**DEFAULT_GENERATION_CONFIG, **(params or {})}
    # google-generativeai is sync; keep API consistent
    # Note: google-generativeai expects either a string or a list of content parts
    content = prompt if not system else f"System: {system}\n\nUser: {prompt}"
    resp = model.generate_content(content, generation_config=config)
    return resp.text or ""


def classify_domains(domains: Iterable[str]) -> Dict[str, Dict[str, str]]:
    """Classify a list of domains into malicious/suspicious/safe using Gemini.

    Returns a mapping { domain: {"verdict": "...", "explanation": "..."} }
    with verdict in {malicious,suspicious,safe,unknown}.
    This is synchronous for simplicity and to avoid introducing async plumbing.
    """
    model = _get_client_and_model()
    config = DEFAULT_GENERATION_CONFIG.copy()
    
    # Add safety settings to allow classification of potentially harmful domains
    safety_settings = [
        {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
        {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
        {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
        {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
    ]
    
    dom_list = [d for d in domains if isinstance(d, str) and d.strip()]
    if not dom_list:
        return {}
    
    def _extract_json(text: str) -> Dict[str, Any]:
        """Extract JSON from Gemini response, handling code fences."""
        t = text.strip()
        if t.startswith("```"):
            # Remove code fence markers
            lines = t.splitlines()
            filtered_lines = [line for line in lines if not line.strip().startswith("```") and not line.strip() == "json"]
            t = "\n".join(filtered_lines).strip()
        # Try direct JSON
        try:
            return json.loads(t)
        except Exception:
            pass
        # Try to find first JSON object substring
        start = t.find('{')
        end = t.rfind('}')
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(t[start:end+1])
            except Exception:
                pass
        return {}
    
    # Use smaller batches for stability with large domain lists
    batch_size = 8
    all_verdicts = {}
    total_batches = (len(dom_list) + batch_size - 1) // batch_size
    
    log(f"[GEMINI] Classifying {len(dom_list)} domains in {total_batches} batches of {batch_size}")
    log(f"[GEMINI] Estimated time: {total_batches * 1.5:.0f}-{total_batches * 3:.0f} seconds")
    
    import time
    
    def _process_single_domain(domain: str) -> Dict[str, str]:
        """Process a single domain when batch fails."""
        try:
            instruction = (
                "You are a security analyst reviewing network traffic domains. "
                f"Analyze this domain: {domain}\n\n"
                "Classify it as 'safe', 'suspicious', or 'malicious' based on:\n"
                "- Known malicious patterns\n"
                "- Suspicious characteristics (random strings, typosquatting, etc.)\n"
                "- Legitimate business/service domains\n\n"
                "Respond ONLY with JSON: {\"verdict\": \"<safe/suspicious/malicious>\", \"explanation\": \"<brief reason>\"}"
            )
            
            resp = model.generate_content(
                instruction,
                generation_config=config,
                safety_settings=safety_settings
            )
            
            if not resp.candidates or not resp.candidates[0].content.parts:
                # Try one more time with even simpler prompt
                simple_prompt = f"Is the domain '{domain}' safe, suspicious, or malicious? Reply with JSON: {{\"verdict\":\"safe/suspicious/malicious\",\"explanation\":\"reason\"}}"
                resp = model.generate_content(
                    simple_prompt,
                    generation_config=config,
                    safety_settings=safety_settings
                )
            
            if resp.candidates and resp.candidates[0].content.parts:
                text = resp.text or "{}"
                data = _extract_json(text)
                verdict = str(data.get('verdict', 'safe')).lower()
                explanation = str(data.get('explanation', 'Analyzed individually'))
                
                if verdict not in ('malicious', 'suspicious', 'safe'):
                    verdict = 'safe'
                    
                return {'verdict': verdict, 'explanation': explanation}
        except Exception as e:
            log(f"[GEMINI] Single domain error for {domain}: {str(e)[:50]}")
        
        # Default to safe if we can't classify
        return {'verdict': 'safe', 'explanation': 'Unable to classify, assuming safe'}
    
    for batch_num, i in enumerate(range(0, len(dom_list), batch_size), 1):
        batch = dom_list[i:i+batch_size]
        
        if batch_num % 5 == 0 or batch_num == total_batches:
            log(f"[GEMINI] Processing batch {batch_num}/{total_batches}...")
        
        # Add small delay between batches to avoid rate limiting
        if batch_num > 1:
            time.sleep(1)
        
        instruction = (
            "You are a network security analyst reviewing DNS traffic. "
            "Classify each domain as 'safe', 'suspicious', or 'malicious'.\n"
            "Safe: legitimate businesses, known services, established websites\n"
            "Suspicious: unusual patterns, typosquatting, random strings, uncommon TLDs\n"
            "Malicious: known threats, malware distribution, phishing sites\n\n"
            "Provide brief explanations (max 8 words each).\n"
            f"Return ONLY valid JSON: {{\"domain1\": {{\"verdict\": \"safe\", \"explanation\": \"reason\"}}, \"domain2\": ...}}\n\n"
            f"Domains to analyze: {json.dumps(batch)}"
        )
        
        prompt = instruction
        
        retry_count = 0
        max_retries = 2
        batch_blocked = False
        
        while retry_count <= max_retries:
            try:
                resp = model.generate_content(
                    prompt,
                    generation_config=config,
                    safety_settings=safety_settings
                )
                
                # Check if response was blocked
                if not resp.candidates or not resp.candidates[0].content.parts:
                    log(f"[GEMINI] Batch {batch_num} blocked by safety filters, processing individually...")
                    batch_blocked = True
                    break
                
                # Success - process the response
                break
                
            except Exception as api_error:
                retry_count += 1
                if retry_count <= max_retries:
                    log(f"[GEMINI] API error in batch {batch_num}, retrying ({retry_count}/{max_retries})...")
                    time.sleep(2)
                    continue
                else:
                    log(f"[GEMINI] Batch {batch_num} failed after {max_retries} retries, processing individually...")
                    batch_blocked = True
                    break
        
        # If batch was blocked or failed, process domains individually
        if batch_blocked or retry_count > max_retries or (not resp.candidates or not resp.candidates[0].content.parts):
            log(f"[GEMINI] Processing {len(batch)} domains individually...")
            for domain in batch:
                time.sleep(0.5)  # Small delay between individual requests
                all_verdicts[domain] = _process_single_domain(domain)
            continue
        
        # Process successful batch response
        try:
            text = (resp.text or "{}")
            data = _extract_json(text)
            
            # Add results for this batch
            for d in batch:
                result = data.get(d, {})
                # Handle both old format (string) and new format (dict)
                if isinstance(result, str):
                    verdict = result.lower()
                    explanation = 'No explanation provided'
                elif isinstance(result, dict):
                    verdict = str(result.get('verdict', 'safe')).lower()
                    explanation = str(result.get('explanation', 'No explanation provided'))
                else:
                    # If domain not in response, process individually
                    all_verdicts[d] = _process_single_domain(d)
                    continue
                
                # Validate verdict
                if verdict not in ('malicious', 'suspicious', 'safe'):
                    verdict = 'safe'
                
                all_verdicts[d] = {'verdict': verdict, 'explanation': explanation}
                
        except Exception as e:
            log(f"[GEMINI] Error parsing batch {batch_num}: {str(e)[:100]}")
            # Process each domain individually
            for d in batch:
                if d not in all_verdicts:
                    all_verdicts[d] = _process_single_domain(d)
    
    log(f"[GEMINI] Classification complete: {len(all_verdicts)} domains classified")
    return all_verdicts
