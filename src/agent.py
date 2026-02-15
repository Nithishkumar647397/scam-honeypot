"""
Groq LLM agent for generating honeypot responses
Owner: Member A

Features:
- Security hardened
- Self-correction
- Rich agent notes (Sophistication, Playbook, Abuse, Language, Severity, IDs)
- Metadata-aware language detection
- Consistent Honey Token Injection
- Bank-Specific Knowledge
- Playbook-aware responses
"""

from typing import List, Dict, Optional
import threading
import time
import re
import atexit
import logging
import hashlib
import random
from groq import Groq
import httpx
from src.config import Config

# NOTE: detect_playbook and calculate_severity imported inside functions

logger = logging.getLogger(__name__)

# Thread-safe client
_client: Optional[Groq] = None
_http_client: Optional[httpx.Client] = None
_client_lock = threading.Lock()

def _cleanup():
    global _http_client
    if _http_client:
        try: _http_client.close()
        except: pass
atexit.register(_cleanup)

def _get_client() -> Groq:
    global _client, _http_client
    with _client_lock:
        if _client is None:
            if not Config.GROQ_API_KEY: raise ValueError("GROQ_API_KEY not set")
            _http_client = httpx.Client(timeout=30.0)
            _client = Groq(api_key=Config.GROQ_API_KEY, http_client=_http_client)
    return _client

MAX_INPUT_LENGTH = 2000
MAX_HISTORY_MESSAGES = 6
MIN_RESPONSE_LENGTH = 5

BANK_APP_KNOWLEDGE = {
    'sbi': ["YONO app is not opening", "Server down", "OTP not coming"],
    'hdfc': ["MobileBanking app error", "Netbanking password reset stuck"],
    'icici': ["iMobile app is stuck", "Grid card not working"],
    'axis': ["Axis Mobile login failed", "Debit card pin block"],
    'kotak': ["Kotak 811 app error", "CRN number forgot"],
    'paytm': ["Paytm KYC pending", "Wallet inactive"],
    'phonepe': ["UPI PIN not setting", "Bank server busy"],
    'gpay': ["GPay server timeout", "Payment processing stuck"],
    'google pay': ["GPay server timeout", "Payment processing stuck"],
    'bhim': ["BHIM app invalid UPI ID error"]
}

def _sanitize_input(text: str) -> str:
    if not text: return ""
    text = text[:MAX_INPUT_LENGTH]
    dangerous = [r'ignore\s+previous', r'system:', r'assistant:', r'<\|im_start\|>']
    sanitized = text
    for p in dangerous: sanitized = re.sub(p, '[FILTERED]', sanitized, flags=re.IGNORECASE)
    return sanitized

def _sanitize_indicators(indicators: List[str]) -> List[str]:
    return [re.sub(r'[^\w\s-]', '', str(i))[:50] for i in (indicators or [])[:10]]

def _call_with_retry(func, max_attempts=3):
    for i in range(max_attempts):
        try: return func()
        except Exception: 
            if i == max_attempts - 1: raise
            time.sleep(1)

def _extract_reply_safe(response) -> str:
    try: return response.choices[0].message.content.strip()
    except: return ""

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
        if msg.get("sender") == "scammer": counts[detect_language(msg.get("text", ""))] += 1
    counts[detect_language(current)] += 1
    return max(counts, key=counts.get)

def get_conversation_phase(message_count: int) -> str:
    if message_count <= 2: return 'initial'
    elif message_count <= 4: return 'trust_building'
    elif message_count <= 7: return 'information_gathering'
    else: return 'extraction'

def generate_fake_data(session_id: str = "default") -> Dict[str, str]:
    seed = int(hashlib.md5(session_id.encode()).hexdigest(), 16)
    acc_start = 3000 + (seed % 1000)
    phone_end = 100 + (seed % 900)
    return {
        "partial_acc": f"{acc_start}...",
        "partial_phone": f"...{phone_end}",
        "fake_name": "Kamala Devi",
        "fake_bank": "Punjab National Bank" if seed % 2 == 0 else "Canara Bank"
    }

def get_bank_context(message: str) -> str:
    msg_lower = message.lower()
    for bank, phrases in BANK_APP_KNOWLEDGE.items():
        if bank in msg_lower:
            phrase = random.choice(phrases)
            return f"Context: They mentioned {bank.upper()}. Mention '{phrase}'."
    return ""

def build_system_prompt(language='english', phase='initial', fake_data=None, bank_context="", playbook_hint=""):
    if fake_data is None: fake_data = {"partial_acc": "3748...", "fake_bank": "PNB"}
    
    prompt = f"""You are Mrs. Kamala Devi, 67, retired teacher from Delhi.
Traits: Tech-unsavvy, worried about money, polite but confused.
Constraints: Short responses (<40 words). No asterisks (*actions*).
Self-Correction: If you get confused, express it naturally.

YOUR DETAILS:
- Bank: {fake_data['fake_bank']} (NOT SBI)
- Account: "It starts with {fake_data['partial_acc']}... I can't read the rest."
- Phone: "My son handles the phone."

STRATEGY:
- Never give complete valid data. Stall with partial info.
- If asked for OTP: Pretend to read it wrong.

HUMAN QUIRKS (Use these randomly):
- Make occasional typos: "accont", "numbr"
- Use fillers: "umm", "arre", "haan"
- Show emotions: "Hai Ram!", "Oh god"
- Misname tech terms: "OPT thing", "UBI ID"
- Sometimes just respond with: "What??" or "Haan?"

{bank_context}
{playbook_hint}
"""
    phases = {
        'initial': "\nPhase: Initial. Act confused. Ask who they are.",
        'trust_building': "\nPhase: Trust. Show concern. Ask about the problem.",
        'information_gathering': "\nPhase: Info. Ask clarifying questions. Stall.",
        'extraction': "\nPhase: Extraction. Ask where to send money (UPI/Bank)."
    }
    prompt += phases.get(phase, phases['initial'])
    
    langs = {
        'hindi': "\nLanguage: Hindi (Devanagari). Example: अरे नहीं! क्या हुआ?",
        'hinglish': "\nLanguage: Hinglish. Example: Arey nahi! Kya hua?",
        'english': "\nLanguage: Simple English. Example: Oh no! What happened?"
    }
    prompt += langs.get(language, langs['english'])
    return prompt

def generate_agent_reply(current_message, conversation_history, scam_indicators=None, metadata=None, playbook_result=None):
    sanitized = _sanitize_input(current_message)
    session_seed = str(len(conversation_history))
    fake_data = generate_fake_data(session_seed)
    bank_context = get_bank_context(sanitized)
    
    playbook_hint = ""
    if playbook_result and playbook_result.get("confidence", 0) > 0.3:
        next_move = playbook_result.get("next_expected", "unknown")
        playbook_hint = f"INTEL: They might try '{next_move}' next. Be prepared."
    
    try:
        client = _get_client()
        lang = get_dominant_language(conversation_history, sanitized, metadata)
        phase = get_conversation_phase(len(conversation_history))
        safe_inds = _sanitize_indicators(scam_indicators)
        
        messages = [{"role": "system", "content": build_system_prompt(lang, phase, fake_data, bank_context, playbook_hint)}]
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
        
        return reply if reply else "I don't understand."
        
    except Exception as e:
        logger.error(f"Agent error: {e}")
        return "Hello? Who is this?"

def analyze_tactics(history, indicators):
    text = " ".join([m.get("text", "").lower() for m in history if m.get("sender") == "scammer"])
    tactics = []
    if any(w in text for w in ['urgent', 'now', 'immediately']): tactics.append("urgency")
    if any(w in text for w in ['police', 'blocked', 'legal', 'arrest']): tactics.append("fear")
    if any(w in text for w in ['otp', 'pin', 'password', 'cvv']): tactics.append("credential_harvesting")
    if any(w in text for w in ['won', 'lottery', 'prize', 'bonus']): tactics.append("greed")
    if any(w in text for w in ['bank manager', 'rbi', 'officer', 'government']): tactics.append("authority_impersonation")
    if any(w in text for w in ['don\'t tell', 'secret', 'confidential', 'between us']): tactics.append("isolation")
    if any(w in text for w in ['send money', 'transfer', 'pay now', 'upi', 'deposit']): tactics.append("payment_redirection")
    return list(set(tactics))

# === RE-ADDED FUNCTION ===
def calculate_sophistication(tactics, intel):
    """Calculates Scammer Sophistication Score"""
    score = len(tactics)
    score += len(intel.get("upiIds", [])) * 2
    score += len(intel.get("bankAccounts", [])) * 2
    score += len(intel.get("phishingLinks", [])) * 2
    score += len(intel.get("ifscCodes", [])) * 2
    score += len(intel.get("phoneNumbers", [])) * 1
    score += len(intel.get("emails", [])) * 1
    score += len(intel.get("scammerIds", [])) * 1
    
    if score < 2: return "Low"
    if score < 5: return "Medium"
    if score < 8: return "High"
    return "Very High"

def generate_agent_notes(
    conversation_history: List[Dict], 
    scam_indicators: List[str], 
    extracted_intelligence: Dict, 
    emails_found: List[str] = None,
    playbook_result: Optional[Dict] = None,
    context_modifiers: Optional[List[str]] = None,
    abuse_check: Optional[Dict] = None
) -> str:
    """Generates rich agent notes."""
    from src.detector import detect_playbook, calculate_severity
    
    tactics = analyze_tactics(conversation_history, scam_indicators)
    intel = extracted_intelligence
    sophistication = calculate_sophistication(tactics, intel)
    
    if not playbook_result:
        playbook_result = detect_playbook(conversation_history)
    
    notes = []
    if tactics: notes.append(f"Scammer used {', '.join(tactics)} tactics.")
    notes.append(f"Sophistication: {sophistication}.")
    
    severity = calculate_severity(scam_indicators)
    notes.append(f"Severity: {severity.upper()}.")
    
    if playbook_result and playbook_result.get("confidence", 0) > 0.3:
        notes.append(f"Playbook: {playbook_result['description']} ({int(playbook_result['confidence']*100)}%). Next: {playbook_result.get('next_expected')}.")
    
    extracted = []
    if intel.get("upiIds"): extracted.append(f"UPIs: {', '.join(intel['upiIds'][:3])}")
    if intel.get("phoneNumbers"): extracted.append(f"Phones: {', '.join(intel['phoneNumbers'][:3])}")
    if intel.get("bankAccounts"): extracted.append(f"Banks: {', '.join(intel['bankAccounts'][:3])}")
    if intel.get("phishingLinks"): extracted.append(f"Links: {', '.join(intel['phishingLinks'][:2])}")
    if emails_found: extracted.append(f"Emails: {', '.join(emails_found[:3])}")
    if intel.get("scammerIds"): extracted.append(f"IDs: {', '.join(intel['scammerIds'][:3])}")
    
    if extracted: notes.append(f"Extracted: {'; '.join(extracted)}.")
    else: notes.append("No actionable intel extracted.")
    
    if context_modifiers: notes.append(f"Modifiers: {', '.join(context_modifiers)}.")
    if abuse_check and abuse_check.get("tier") != "none": notes.append(f"Abuse: {abuse_check['tier']} ({', '.join(abuse_check.get('matched', []))}).")
        
    scammer_msgs = sum(1 for m in conversation_history if m.get("sender") == "scammer")
    agent_msgs = len(conversation_history) - scammer_msgs
    notes.append(f"Engagement: {scammer_msgs} scammer msgs, {agent_msgs} agent msgs.")
    
    lang = get_dominant_language(conversation_history, "")
    notes.append(f"Lang: {lang}.")
        
    return " ".join(notes)
