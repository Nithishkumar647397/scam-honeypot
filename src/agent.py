"""
Groq LLM agent for generating honeypot responses
Owner: Member A

Features:
- Security hardened
- Self-correction
- Rich agent notes
- Metadata-aware language detection
- Consistent Honey Token Injection (Fixed)
- Bank-Specific Knowledge
- Playbook-aware responses
- Humanized Persona
- Active Probing Strategy
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


def count_questions(text: str) -> int:
    """Count question marks in agent reply"""
    return text.count('?')


def is_investigative_question(text: str) -> bool:
    """Check if text contains investigative question keywords"""
    keywords = [
        "employee id", "branch", "callback number", "landline",
        "helpline", "manager", "website", "email", "office"
    ]
    return any(k in text.lower() for k in keywords)


logger = logging.getLogger(__name__)

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

# FIX: Phase calculation based on Turns (Message Count / 2)
def get_conversation_phase(message_count: int) -> str:
    turn = message_count // 2
    if turn <= 1: return 'initial'
    elif turn <= 3: return 'trust_building'
    elif turn <= 6: return 'probing'
    else: return 'extraction'

# FIX: Fake Data Seed using Session ID (Requires session_id passed or default)
def generate_fake_data(session_id: str = "default") -> Dict[str, str]:
    seed = int(hashlib.md5(str(session_id).encode()).hexdigest(), 16)
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

STRATEGY - ACTIVE PROBING:
- Don't just answer; ASK questions that force them to reveal info.
- If they ask for payment: "This app isn't working, do you have another UPI ID?"
- If they ask for OTP: "I didn't get it. Can you call me from the bank's landline?"
- Ask for "Employee ID", "Branch Name", or "Manager's Number" to verify them.

CONVERSATION QUALITY REQUIREMENTS:

Ask at least 2 questions per reply (use ? marks)
Include investigative questions like: "What is your employee ID?",
"Which branch are you calling from?", "What is your callback number?",
"Can you give me your helpline number?", "Which manager should I speak to?"
Naturally mention red flags you notice in the conversation

HUMAN QUIRKS:
- Typos: "accont", "numbr"
- Fillers: "umm", "arre", "wait wait"
- Emotions: "Hai Ram!", "Oh god"

{bank_context}
{playbook_hint}
"""
    
    # FIX: Updated Probing Prompt with Fallback
    phases = {
        'initial': "\nPhase: Initial. Act confused. Ask who they are and WHERE they are calling from.",
        'trust_building': "\nPhase: Trust. Show concern. Ask for their Name and Employee ID.",
        'probing': "\nPhase: Probing. Pretend to try but fail. Ask for ALTERNATIVE UPI or Account. Fallback: Ask for Branch Manager's number.",
        'extraction': "\nPhase: Extraction. Say app asks for 'Beneficiary Name'. Ask them to confirm details."
    }
    prompt += phases.get(phase, phases['initial'])
    
    langs = {
        'hindi': "\nLanguage: Hindi (Devanagari). Example: अरे नहीं! क्या हुआ?",
        'hinglish': "\nLanguage: Hinglish. Example: Arey nahi! Kya hua?",
        'english': "\nLanguage: Simple English. Example: Oh no! What happened?"
    }
    prompt += langs.get(language, langs['english'])
    return prompt

def generate_agent_reply(current_message, conversation_history, scam_indicators=None, metadata=None, playbook_result=None, session_id="default"):
    sanitized = _sanitize_input(current_message)
    
    # FIX: Use session_id for consistent fake data
    fake_data = generate_fake_data(session_id)
    bank_context = get_bank_context(sanitized)
    
    playbook_hint = ""
    if playbook_result and playbook_result.get("confidence", 0) > 0.3:
        next_move = playbook_result.get("next_expected", "unknown")
        playbook_hint = f"INTEL: They might try '{next_move}' next. Delay them."
    
    try:
        client = _get_client()
        lang = get_dominant_language(conversation_history, sanitized, metadata)
        phase = get_conversation_phase(len(conversation_history)) # Now calculates turns correctly inside function
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
        reply = _clean_reply(reply)
        
        return reply if reply else "I don't understand."
        
    except Exception as e:
        logger.error(f"Agent error: {e}")
        return "Hello? Who is this?"

def _clean_reply(reply: str) -> str:
    if not reply: return ""
    reply = re.sub(r'\*[^*]+\*', '', reply)
    reply = re.sub(r'\([a-zA-Z\s]+\)', '', reply)
    reply = re.sub(r'\[[^\]]+\]', '', reply)
    for prefix in ["As Mrs. Kamala", "Mrs. Kamala", "Kamala:", "Kamala Devi:"]:
        if reply.lower().startswith(prefix.lower()):
            reply = reply[len(prefix):].lstrip(' :,')
    reply = reply.strip('"\'')
    reply = re.sub(r'\s+', ' ', reply).strip()
    return reply

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

def calculate_sophistication(tactics, intel):
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
    if intel.get("scammerIds"): extracted.append(f"Scammer IDs: {', '.join(intel['scammerIds'][:3])}")

    if extracted:
        notes.append(f"Extracted Intel: {'; '.join(extracted)}.")
    else:
        notes.append("No actionable intel extracted yet.")

    # Red flag behavioral indicators
    red_flags = []
    scammer_texts = [m.get("text", "").lower() for m in conversation_history if m.get("sender") == "scammer"]
    if len(scammer_texts) >= 3:
        urgency_recent = sum(1 for t in scammer_texts[-3:] if any(w in t for w in ['urgent', 'now', 'hurry', 'immediately']))
        if urgency_recent >= 2: red_flags.append("escalating_pressure")
    payment_count = sum(1 for t in scammer_texts if any(w in t for w in ['send', 'pay', 'transfer', '₹']))
    if payment_count >= 3: red_flags.append("persistent_payment_demands")
    if len(set(intel.get("upiIds", []))) >= 2: red_flags.append("multiple_mule_accounts")
    if len(set(intel.get("phoneNumbers", []))) >= 2: red_flags.append("multiple_contact_numbers")

    if red_flags:
        notes.append(f"Red Flags: {', '.join(red_flags)}.")

    # Context modifiers and abuse
    if context_modifiers: notes.append(f"Context Modifiers: {', '.join(context_modifiers)}.")
    if abuse_check and abuse_check.get("tier") != "none":
        notes.append(f"Abuse Detected: {abuse_check['tier']} tier ({', '.join(abuse_check.get('matched', []))}).")

    # Engagement stats
    scammer_msg_count = sum(1 for m in conversation_history if m.get("sender") == "scammer")
    agent_msg_count = len(conversation_history) - scammer_msg_count
    notes.append(f"Engagement: {scammer_msg_count} scammer msgs, {agent_msg_count} agent responses.")

    # Conversation quality metrics (single clean block)
    agent_replies = [m.get("text", "") for m in conversation_history if m.get("sender") != "scammer"]
    total_questions = sum(count_questions(reply) for reply in agent_replies)
    investigative_questions = sum(1 for reply in agent_replies if is_investigative_question(reply))
    notes.append(f"Quality: Asked {total_questions} questions ({investigative_questions} investigative).")

    lang = get_dominant_language(conversation_history, "")
    notes.append(f"Language: {lang}.")

    return " ".join(notes)
