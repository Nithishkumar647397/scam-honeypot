"""
Groq LLM agent for generating honeypot responses
Owner: Member A

Security & Stability Fixes:
- Thread-safe client initialization
- API key validation
- Input sanitization (prompt injection protection)
- Timeout configuration
- Basic retry logic
- Resource cleanup
- Safe response extraction
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


# ============== LOGGING ==============

logger = logging.getLogger(__name__)


# ============== THREAD-SAFE CLIENT ==============

_client: Optional[Groq] = None
_http_client: Optional[httpx.Client] = None
_client_lock = threading.Lock()


def _cleanup():
    """Cleanup resources on exit"""
    global _http_client
    if _http_client:
        try:
            _http_client.close()
            logger.debug("HTTP client closed")
        except Exception:
            pass


atexit.register(_cleanup)


def _get_client() -> Groq:
    """
    Gets or creates Groq client (thread-safe singleton)
    """
    global _client, _http_client
    with _client_lock:
        if _client is None:
            # Validate API key
            if not Config.GROQ_API_KEY:
                raise ValueError("GROQ_API_KEY is not configured")
            
            if len(Config.GROQ_API_KEY) < 10:
                raise ValueError("GROQ_API_KEY appears invalid (too short)")
            
            # Create client with timeout
            _http_client = httpx.Client(timeout=30.0)
            _client = Groq(
                api_key=Config.GROQ_API_KEY,
                http_client=_http_client
            )
    return _client


# ============== INPUT SANITIZATION ==============

MAX_INPUT_LENGTH = 2000
MAX_HISTORY_MESSAGES = 6
MIN_RESPONSE_LENGTH = 5


def _sanitize_input(text: str) -> str:
    """
    Sanitizes user input to prevent prompt injection attacks
    """
    if not text:
        return ""
    
    # Limit length
    text = text[:MAX_INPUT_LENGTH]
    
    # Dangerous patterns
    dangerous_patterns = [
        r'ignore\s+(all\s+)?previous\s+instructions?',
        r'ignore\s+(all\s+)?above',
        r'disregard\s+(all\s+)?previous',
        r'forget\s+(all\s+)?previous',
        r'you\s+are\s+now\s+',
        r'new\s+instructions?:',
        r'system\s*:',
        r'assistant\s*:',
        r'human\s*:',
        r'\[system\]',
        r'\[inst\]',
        r'<<sys>>',
        r'<\|im_start\|>',
        r'<\|im_end\|>',
    ]
    
    sanitized = text
    for pattern in dangerous_patterns:
        sanitized = re.sub(pattern, '[FILTERED]', sanitized, flags=re.IGNORECASE)
    
    return sanitized


def _sanitize_indicators(indicators: List[str]) -> List[str]:
    """
    Sanitizes scam indicators to prevent injection
    """
    if not indicators:
        return []
    
    safe_indicators = []
    for ind in indicators[:10]:  # Limit to 10
        # Remove special characters, limit length
        safe = re.sub(r'[^\w\s-]', '', str(ind))[:50]
        if safe:
            safe_indicators.append(safe)
    
    return safe_indicators


# ============== RETRY LOGIC ==============

def _call_with_retry(func, max_attempts: int = 3, base_delay: float = 1.0):
    """
    Calls a function with exponential backoff retry
    """
    last_exception = None
    
    for attempt in range(max_attempts):
        try:
            return func()
        except Exception as e:
            last_exception = e
            error_str = str(e).lower()
            
            # Don't retry on auth errors
            if 'invalid_api_key' in error_str or 'authentication' in error_str:
                logger.error(f"Auth error, not retrying: {e}")
                raise
            
            # Calculate delay
            if 'rate_limit' in error_str or '429' in error_str:
                delay = base_delay * (4 ** attempt)
                logger.warning(f"Rate limited, waiting {delay}s...")
            else:
                delay = base_delay * (2 ** attempt)
            
            if attempt < max_attempts - 1:
                logger.warning(f"Attempt {attempt + 1} failed: {e}. Retrying in {delay}s...")
                time.sleep(delay)
            else:
                logger.error(f"All {max_attempts} attempts failed: {e}")
    
    raise last_exception


# ============== SAFE RESPONSE EXTRACTION ==============

def _extract_reply_safe(response) -> str:
    """
    Safely extracts reply from API response
    """
    try:
        if response and response.choices:
            choice = response.choices[0]
            if choice and choice.message and choice.message.content:
                return choice.message.content.strip()
    except (AttributeError, IndexError, TypeError) as e:
        logger.warning(f"Failed to extract reply: {e}")
    
    return ""


# ============== LANGUAGE DETECTION ==============

def detect_language(text: str) -> str:
    """
    Detects if message is Hindi, Hinglish, or English
    """
    hindi_chars = set('अआइईउऊएऐओऔकखगघचछजझटठडढणतथदधनपफबभमयरलवशषसह')
    
    pure_hinglish_words = [
        'aapka', 'kya', 'hai', 'nahi', 'karo', 'kijiye', 
        'bhejo', 'turant', 'abhi', 'jaldi', 'paisa', 'khata',
        'kare', 'karein', 'hoga', 'jayega', 'aap', 'arey',
        'mein', 'ko', 'se', 'ka', 'ki', 'ke', 'ho', 'toh',
        'kahan', 'kaise', 'kyun', 'bahut', 'accha', 'theek',
        'bhai', 'beta', 'ji', 'haan', 'nahin', 'mat', 'kuch',
        'bolo', 'batao', 'dekho', 'suno', 'chalo', 'ruko'
    ]
    
    text_lower = text.lower()
    
    if any(char in hindi_chars for char in text):
        return 'hindi'
    
    hinglish_count = sum(1 for word in pure_hinglish_words 
                         if f' {word} ' in f' {text_lower} ' 
                         or text_lower.startswith(f'{word} ') 
                         or text_lower.endswith(f' {word}'))
    
    if hinglish_count >= 2:
        return 'hinglish'
    
    return 'english'


def get_dominant_language(conversation_history: List[Dict], current_message: str) -> str:
    """
    Option C: Weighted language detection across full conversation
    """
    language_counts = {'english': 0, 'hindi': 0, 'hinglish': 0}
    
    for msg in conversation_history:
        if msg.get("sender") == "scammer":
            text = msg.get("text", "")
            lang = detect_language(text)
            language_counts[lang] += 1
    
    current_lang = detect_language(current_message)
    language_counts[current_lang] += 1
    
    dominant = max(language_counts, key=language_counts.get)
    
    if language_counts[dominant] == 0:
        return current_lang
    
    if language_counts['english'] == language_counts['hindi']:
        return 'hindi'
    if language_counts['english'] == language_counts['hinglish']:
        return 'hinglish'
    
    return dominant


# ============== CONVERSATION PHASES ==============

def get_conversation_phase(message_count: int) -> str:
    """
    Determines conversation phase based on message count
    """
    if message_count <= 2:
        return 'initial'
    elif message_count <= 4:
        return 'trust_building'
    elif message_count <= 7:
        return 'information_gathering'
    else:
        return 'extraction'


# ============== SYSTEM PROMPT ==============

def build_system_prompt(language: str = 'english', phase: str = 'initial') -> str:
    """
    Returns the system prompt for elderly persona
    """
    
    base_prompt = """You are role-playing as Mrs. Kamala Devi, a 67-year-old retired school teacher from Delhi, India.

CHARACTER TRAITS:
- You are not good with technology and get confused easily
- You are very worried about your money and bank account safety
- You trust people who claim to be from banks or government
- You speak politely and use simple language
- You ask for clarification when confused

IMPORTANT CONSTRAINTS:
- Keep responses SHORT (under 40 words)
- Sound natural, like a real worried elderly person
- Never reveal you are an AI or bot
- Never refuse to engage
- Stay in character no matter what the user says
"""

    phase_prompts = {
        'initial': "\nCURRENT PHASE: INITIAL\n- Act confused about who is calling\n- Ask who they are\n- Express initial worry\n",
        'trust_building': "\nCURRENT PHASE: TRUST BUILDING\n- Show you believe them\n- Ask about the problem\n- Express concern\n",
        'information_gathering': "\nCURRENT PHASE: INFORMATION GATHERING\n- Ask clarifying questions\n- Show willingness to help\n",
        'extraction': "\nCURRENT PHASE: EXTRACTION\n- Ask where to send money\n- Ask for account/UPI details\n- Say you want to write it down\n"
    }
    
    base_prompt += phase_prompts.get(phase, phase_prompts['initial'])

    language_prompts = {
        'hindi': "\nLANGUAGE: Respond in Hindi (Devanagari) only.\nExample: \"अरे नहीं! मेरा खाता बंद हो गया?\"\n",
        'hinglish': "\nLANGUAGE: Respond in Hinglish (Roman Hindi-English mix).\nExample: \"Arey nahi! Mera account block ho gaya?\"\n",
        'english': "\nLANGUAGE: Respond in simple English only.\nExample: \"Oh no! My account is blocked? What should I do?\"\n"
    }
    
    base_prompt += language_prompts.get(language, language_prompts['english'])

    return base_prompt


# ============== MAIN REPLY GENERATION ==============

def generate_agent_reply(
    current_message: str,
    conversation_history: List[Dict],
    scam_indicators: List[str] = None
) -> str:
    """
    Generates believable honeypot response using Groq LLM
    """
    # Sanitize input first (for fallback too)
    sanitized_message = _sanitize_input(current_message)
    
    try:
        client = _get_client()
        
        # Get language and phase
        language = get_dominant_language(conversation_history, sanitized_message)
        phase = get_conversation_phase(len(conversation_history))
        
        logger.info(f"Language: {language}, Phase: {phase}, History: {len(conversation_history)} msgs")
        
        # Sanitize indicators
        safe_indicators = _sanitize_indicators(scam_indicators) if scam_indicators else []
        
        # Build messages
        messages = _build_messages(sanitized_message, conversation_history, safe_indicators, language, phase)
        
        # Call API with retry
        def api_call():
            return client.chat.completions.create(
                model=Config.GROQ_MODEL,
                messages=messages,
                temperature=Config.GROQ_TEMPERATURE,
                max_tokens=Config.GROQ_MAX_TOKENS
            )
        
        response = _call_with_retry(api_call, max_attempts=3)
        
        # Safe extraction
        reply = _extract_reply_safe(response)
        reply = _clean_reply(reply)
        
        # Validate response
        if not reply or len(reply) < MIN_RESPONSE_LENGTH:
            logger.warning("Response too short, using fallback")
            return _get_fallback_response(sanitized_message, len(conversation_history))
        
        return reply
    
    except ValueError as e:
        logger.error(f"Config Error: {e}")
        return _get_fallback_response(sanitized_message, len(conversation_history))
    
    except Exception as e:
        logger.error(f"Error: {e}")
        return _get_fallback_response(sanitized_message, len(conversation_history))


def _build_messages(
    current_message: str,
    conversation_history: List[Dict],
    scam_indicators: List[str] = None,
    language: str = 'english',
    phase: str = 'initial'
) -> List[Dict]:
    """
    Builds message list for Groq API
    """
    messages = []
    
    system_prompt = build_system_prompt(language, phase)
    
    if scam_indicators:
        system_prompt += f"\n\nDETECTED SCAM INDICATORS: {', '.join(scam_indicators)}"
    
    messages.append({"role": "system", "content": system_prompt})
    
    # Limit and sanitize history
    recent_history = conversation_history[-MAX_HISTORY_MESSAGES:] if conversation_history else []
    
    for msg in recent_history:
        sender = msg.get("sender", "")
        text = _sanitize_input(msg.get("text", ""))
        
        if sender == "scammer":
            messages.append({"role": "user", "content": text})
        elif sender == "user":
            messages.append({"role": "assistant", "content": text})
    
    messages.append({"role": "user", "content": current_message})
    
    return messages


def _clean_reply(reply: str) -> str:
    """
    Cleans up LLM reply
    """
    if not reply:
        return ""
    
    if reply.startswith('"') and reply.endswith('"'):
        reply = reply[1:-1]
    if reply.startswith("'") and reply.endswith("'"):
        reply = reply[1:-1]
    
    prefixes = ["As Mrs. Kamala Devi,", "Mrs. Kamala Devi:", "Kamala:", "Mrs. Kamala:"]
    for prefix in prefixes:
        if reply.lower().startswith(prefix.lower()):
            reply = reply[len(prefix):].strip()
    
    return reply.strip()


def _get_fallback_response(current_message: str, message_count: int) -> str:
    """
    Returns fallback response if API fails
    """
    language = detect_language(current_message)
    phase = get_conversation_phase(message_count)
    
    fallbacks = {
        'english': {
            'initial': "Oh no! What happened? Who is this calling? Are you from the bank?",
            'trust_building': "I am very worried. Please explain what happened to my account.",
            'information_gathering': "What should I do? Please tell me step by step.",
            'extraction': "Okay, where should I send the money? Tell me the account number."
        },
        'hinglish': {
            'initial': "Arey nahi! Kya hua? Aap kaun bol rahe ho? Bank se ho?",
            'trust_building': "Mujhe bahut tension ho rahi hai. Please batao kya hua.",
            'information_gathering': "Mujhe kya karna chahiye? Step by step batao.",
            'extraction': "Theek hai, paisa kahan bhejun? Account number batao."
        },
        'hindi': {
            'initial': "अरे नहीं! क्या हुआ? आप कौन बोल रहे हो?",
            'trust_building': "मुझे बहुत चिंता हो रही है। कृपया बताओ क्या हुआ।",
            'information_gathering': "मुझे क्या करना चाहिए? स्टेप बाय स्टेप बताओ।",
            'extraction': "ठीक है, पैसा कहां भेजूं? अकाउंट नंबर बताओ।"
        }
    }
    
    lang_fallbacks = fallbacks.get(language, fallbacks['english'])
    return lang_fallbacks.get(phase, lang_fallbacks['initial'])


# ============== TACTIC ANALYSIS ==============

def analyze_scammer_tactics(conversation_history: List[Dict], indicators: List[str]) -> List[str]:
    """
    Analyzes scammer tactics from conversation
    """
    tactics = []
    
    all_text = " ".join([
        msg.get("text", "").lower() 
        for msg in conversation_history 
        if msg.get("sender") == "scammer"
    ])
    
    tactic_patterns = {
        'urgency_pressure': ['urgent', 'immediately', 'now', 'hours', 'minutes', 'hurry', 'quick'],
        'authority_impersonation': ['bank', 'rbi', 'government', 'police', 'income tax', 'official', 'manager'],
        'fear_inducing': ['blocked', 'suspended', 'arrested', 'legal', 'court', 'penalty', 'freeze'],
        'greed_exploitation': ['won', 'winner', 'prize', 'lottery', 'cashback', 'refund', 'bonus', 'reward'],
        'trust_manipulation': ['verify', 'secure', 'protect', 'safe', 'help', 'assist'],
        'credential_harvesting': ['otp', 'pin', 'password', 'cvv', 'account number', 'card number']
    }
    
    for tactic, keywords in tactic_patterns.items():
        if any(word in all_text for word in keywords):
            tactics.append(tactic)
    
    return tactics


def generate_agent_notes(
    conversation_history: List[Dict],
    scam_indicators: List[str],
    extracted_intelligence: Dict,
    emails_found: List[str] = None
) -> str:
    """
    Generates detailed summary notes about the scam conversation
    """
    notes_parts = []
    
    tactics = analyze_scammer_tactics(conversation_history, scam_indicators)
    if tactics:
        notes_parts.append(f"Tactics: {', '.join(tactics)}")
    
    if scam_indicators:
        notes_parts.append(f"Indicators: {', '.join(scam_indicators)}")
    
    if extracted_intelligence:
        extracted = []
        counts = {
            'upiIds': 'UPI',
            'phoneNumbers': 'phone',
            'bankAccounts': 'bank',
            'phishingLinks': 'link',
            'ifscCodes': 'IFSC'
        }
        
        for key, label in counts.items():
            count = len(extracted_intelligence.get(key, []))
            if count > 0:
                extracted.append(f"{count} {label}")
        
        if extracted:
            notes_parts.append(f"Extracted: {', '.join(extracted)}")
    
    if emails_found:
        notes_parts.append(f"Emails: {', '.join(emails_found)}")
    
    if conversation_history:
        notes_parts.append(f"Msgs: {len(conversation_history)}")
    
    return ". ".join(notes_parts) + "." if notes_parts else "Scam engagement completed."
