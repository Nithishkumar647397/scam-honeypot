"""
Groq LLM agent for generating honeypot responses
Owner: Member A

Features:
- Security hardened
- Self-correction
- Rich agent notes (with Sophistication Scoring)
- Metadata-aware language detection
- Honey Token Injection Strategy
"""

from typing import List, Dict, Optional
import threading
import time
import re
import atexit
import logging
from groq import Groq
import httpx
from src.config import Config

logger = logging.getLogger(__name__)

# Thread-safe client
_client: Optional[Groq] = None
_http_client: Optional[httpx.Client] = None
_client_lock = threading.Lock()

def _cleanup():
    global _http_client
    if _http_client:
        try:
            _http_client.close()
        except:
            pass
atexit.register(_cleanup)

def _get_client() -> Groq:
    global _client, _http_client
    with _client_lock:
        if _client is None:
            if not Config.GROQ_API_KEY:
                raise ValueError("GROQ_API_KEY is not configured")
            _http_client = httpx.Client(timeout=30.0)
            _client = Groq(api_key=Config.GROQ_API_KEY, http_client=_http_client)
    return _client

MAX_INPUT_LENGTH = 2000
MAX_HISTORY_MESSAGES = 6
MIN_RESPONSE_LENGTH = 5

def _sanitize_input(text: str) -> str:
    if not text: return ""
    text = text[:MAX_INPUT_LENGTH]
    dangerous = [r'ignore\s+previous', r'system:', r'assistant:', r'<\|im_start\|>']
    sanitized = text
    for p in dangerous:
        sanitized = re.sub(p, '[FILTERED]', sanitized, flags=re.IGNORECASE)
    return sanitized

def _sanitize_indicators(indicators: List[str]) -> List[str]:
    if not indicators: return []
    return [re.sub(r'[^\w\s-]', '', str(i))[:50] for i in indicators[:10]]

def _call_with_retry(func, max_attempts=3):
    for i in range(max_attempts):
        try:
            return func()
        except Exception as e:
            if i == max_attempts - 1: raise
            time.sleep(1)

def _extract_reply_safe(response) -> str:
    try:
        return response.choices[0].message.content.strip()
    except:
        return ""

def detect_language(text: str) -> str:
    text = text.lower()
    if any(c in 'अआइईउऊएऐओऔकखगघचछजझटठडढणतथदधनपफबभमयरलवशषसह' for c in text): return 'hindi'
    hinglish_words = ['aapka', 'kya', 'hai', 'nahi', 'karo', 'bhejo', 'jaldi', 'paisa']
    if sum(1 for w in hinglish_words if w in text) >= 2: return 'hinglish'
    return 'english'

def get_dominant_language(history, current, metadata=None) -> str:
    if metadata:
        lang = metadata.get("language", "").lower()
        if "hindi" in lang: return "hindi"
    
    counts = {'english': 0, 'hindi': 0, 'hinglish': 0}
    for msg in history:
        if msg.get("sender") == "scammer":
            counts[detect_language(msg.get("text", ""))] += 1
    counts[detect_language(current)] += 1
    
    return max(counts, key=counts.get)

def get_conversation_phase(message_count: int) -> str:
    if message_count <= 2: return 'initial'
    elif message_count <= 4: return 'trust_building'
    elif message_count <= 7: return 'information_gathering'
    else: return 'extraction'

def build_system_prompt(language='english', phase='initial'):
    prompt = """You are Mrs. Kamala Devi, 67, retired teacher from Delhi.
Traits: Tech-unsavvy, worried about money, polite but confused.
Constraints: Short responses (<40 words). No asterisks (*actions*).
Self-Correction: If you say something suspicious or contradict yourself, say "Sorry, I got confused."

STRATEGY - HONEY TOKENS (Fake Data):
- If asked for account: Give partial fake ("Starts with 3748... can't read rest").
- If asked for OTP: Pretend to read it wrong ("Is it 84... wait screen off").
- Never give complete valid data. Stall them with partial info.
"""
    
    phases = {
        'initial': "\nPhase: Initial. Act confused. Ask who they are.",
        'trust_building': "\nPhase: Trust. Show concern. Ask about the problem.",
        'information_gathering': "\nPhase: Info. Ask clarifying questions. Stall.",
        'extraction': "\nPhase: Extraction. Ask where to send money (UPI/Bank)."
    }
    prompt += phases.get(phase, phases['initial'])
    
    langs = {
        'hindi': "\nLanguage: Hindi (Devanagari). Example: अरे नहीं!",
        'hinglish': "\nLanguage: Hinglish. Example: Arey nahi! Kya hua?",
        'english': "\nLanguage: Simple English. Example: Oh no! What happened?"
    }
    prompt += langs.get(language, langs['english'])
    return prompt

def generate_agent_reply(current_message, conversation_history, scam_indicators=None, metadata=None):
    sanitized = _sanitize_input(current_message)
    try:
        client = _get_client()
        lang = get_dominant_language(conversation_history, sanitized, metadata)
        phase = get_conversation_phase(len(conversation_history))
        safe_inds = _sanitize_indicators(scam_indicators)
        
        messages = [{"role": "system", "content": build_system_prompt(lang, phase)}]
        if safe_inds: messages[0]['content'] += f"\nScam detected: {', '.join(safe_inds)}"
        
        for msg in conversation_history[-MAX_HISTORY_MESSAGES:]:
            role = "user" if msg.get("sender") == "scammer" else "assistant"
            messages.append({"role": role, "content": _sanitize_input(msg.get("text", ""))})
        messages.append({"role": "user", "content": sanitized})
        
        resp = _call_with_retry(lambda: client.chat.completions.create(
            model=Config.GROQ_MODEL, messages=messages, max_tokens=150, temperature=Config.GROQ_TEMPERATURE
        ))
        
        reply = _extract_reply_safe(resp)
        reply = re.sub(r'\*[^*]+\*', '', reply).strip()
        reply = re.sub(r'^As Kamala: ', '', reply).strip()
        
        if not reply: return "I don't understand."
        return reply
        
    except Exception as e:
        logger.error(f"Agent error: {e}")
        return "Hello? Who is this?"

def analyze_tactics(history, indicators):
    text = " ".join([m.get("text", "").lower() for m in history if m.get("sender") == "scammer"])
    tactics = []
    if any(w in text for w in ['urgent', 'now']): tactics.append("urgency")
    if any(w in text for w in ['police', 'blocked']): tactics.append("fear")
    if any(w in text for w in ['otp', 'pin']): tactics.append("credential_harvesting")
    if any(w in text for w in ['won', 'lottery']): tactics.append("greed")
    return tactics

def calculate_sophistication(tactics, intel):
    score = 0
    score += len(tactics)
    score += len(intel.get("upiIds", [])) * 2
    score += len(intel.get("bankAccounts", [])) * 2
    
    if score < 2: return "Low"
    if score < 5: return "Medium"
    return "High"

def generate_agent_notes(conversation_history, scam_indicators, extracted_intelligence, emails_found=None):
    tactics = analyze_tactics(conversation_history, scam_indicators)
    intel = extracted_intelligence
    sophistication = calculate_sophistication(tactics, intel)
    
    notes = []
    
    # Sentence 1: Analysis
    if tactics:
        notes.append(f"Scammer used {', '.join(tactics)} tactics.")
    
    # Sentence 2: Sophistication
    notes.append(f"Sophistication Level: {sophistication}.")
    
    # Sentence 3: Extraction Detail
    extracted = []
    if intel.get("upiIds"): extracted.append(f"UPIs: {', '.join(intel['upiIds'][:3])}")
    if intel.get("phoneNumbers"): extracted.append(f"Phones: {', '.join(intel['phoneNumbers'][:3])}")
    if intel.get("bankAccounts"): extracted.append(f"Banks: {', '.join(intel['bankAccounts'][:3])}")
    if emails_found: extracted.append(f"Emails: {', '.join(emails_found[:3])}")
    
    if extracted:
        notes.append(f"Extracted: {'; '.join(extracted)}.")
    else:
        notes.append("No actionable intel extracted.")
        
    return " ".join(notes)
