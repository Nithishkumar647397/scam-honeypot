"""
Groq LLM agent for generating honeypot responses
Owner: Member A
"""

from typing import List, Dict, Optional
from groq import Groq
import httpx
from src.config import Config


_client: Optional[Groq] = None


def _get_client() -> Groq:
    global _client
    if _client is None:
        http_client = httpx.Client()
        _client = Groq(
            api_key=Config.GROQ_API_KEY,
            http_client=http_client
        )
    return _client


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
    
    hinglish_count = sum(1 for word in pure_hinglish_words if f' {word} ' in f' {text_lower} ' or text_lower.startswith(f'{word} ') or text_lower.endswith(f' {word}'))
    
    if hinglish_count >= 2:
        return 'hinglish'
    
    return 'english'


def get_dominant_language(conversation_history: List[Dict], current_message: str) -> str:
    """
    Option C: Weighted language detection across full conversation
    Returns the dominant language used by scammer
    """
    language_counts = {'english': 0, 'hindi': 0, 'hinglish': 0}
    
    # Count from conversation history (scammer messages only)
    for msg in conversation_history:
        if msg.get("sender") == "scammer":
            text = msg.get("text", "")
            lang = detect_language(text)
            language_counts[lang] += 1
    
    # Add current message
    current_lang = detect_language(current_message)
    language_counts[current_lang] += 1
    
    # Find dominant language
    dominant = max(language_counts, key=language_counts.get)
    
    # If tie or all zero, use current message language
    if language_counts[dominant] == 0:
        return current_lang
    
    # If English and non-English are equal, prefer non-English (more specific)
    if language_counts['english'] == language_counts['hindi']:
        return 'hindi'
    if language_counts['english'] == language_counts['hinglish']:
        return 'hinglish'
    
    return dominant


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
"""

    # Phase-specific behavior
    if phase == 'initial':
        base_prompt += """
CURRENT PHASE: INITIAL
- Act confused about who is calling
- Ask who they are and where they're from
- Express initial worry
"""
    elif phase == 'trust_building':
        base_prompt += """
CURRENT PHASE: TRUST BUILDING
- Show you believe them slightly
- Ask more questions about the problem
- Express concern about your account
"""
    elif phase == 'information_gathering':
        base_prompt += """
CURRENT PHASE: INFORMATION GATHERING
- Ask clarifying questions
- Show willingness to help
- Ask what exactly you need to do
"""
    elif phase == 'extraction':
        base_prompt += """
CURRENT PHASE: EXTRACTION
- Ask directly where to send money
- Ask for account number, UPI ID
- Say you want to write it down
"""

    # Language style
    if language == 'hindi':
        base_prompt += """
LANGUAGE: Respond in Hindi (Devanagari script) only.
Use phrases like: "अरे नहीं!", "मुझे बहुत चिंता हो रही है", "कृपया मदद करें"
Example: "अरे नहीं! मेरा खाता बंद हो गया? मुझे बहुत चिंता हो रही है।"
"""
    elif language == 'hinglish':
        base_prompt += """
LANGUAGE: Respond in Hinglish (Roman script Hindi-English mix) only.
Use phrases like: "Arey nahi!", "Mujhe bahut tension ho rahi hai", "Please help karo"
Example: "Arey nahi! Mera account block ho gaya? Mujhe bahut tension ho rahi hai."
"""
    else:
        base_prompt += """
LANGUAGE: Respond in simple English only.
Use phrases like: "Oh no!", "I am very worried", "Please help me", "What should I do?"
Example: "Oh no! My account is blocked? I am very worried. What should I do?"
"""

    return base_prompt


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


def generate_agent_reply(
    current_message: str,
    conversation_history: List[Dict],
    scam_indicators: List[str] = None
) -> str:
    """
    Generates believable honeypot response using Groq LLM
    Uses weighted language detection (Option C)
    """
    try:
        client = _get_client()
        
        # Option C: Get dominant language from full conversation
        language = get_dominant_language(conversation_history, current_message)
        
        # Get conversation phase
        phase = get_conversation_phase(len(conversation_history))
        
        print(f"[AGENT] Language: {language}, Phase: {phase}, History: {len(conversation_history)} msgs")
        
        messages = _build_messages(current_message, conversation_history, scam_indicators, language, phase)
        
        response = client.chat.completions.create(
            model=Config.GROQ_MODEL,
            messages=messages,
            temperature=Config.GROQ_TEMPERATURE,
            max_tokens=Config.GROQ_MAX_TOKENS
        )
        
        reply = response.choices[0].message.content.strip()
        reply = _clean_reply(reply)
        
        return reply
    
    except Exception as e:
        print(f"Groq API Error: {e}")
        return _get_fallback_response(current_message, len(conversation_history))


def _build_messages(
    current_message: str,
    conversation_history: List[Dict],
    scam_indicators: List[str] = None,
    language: str = 'english',
    phase: str = 'initial'
) -> List[Dict]:
    messages = []
    
    system_prompt = build_system_prompt(language, phase)
    
    if scam_indicators:
        system_prompt += f"\n\nDETECTED SCAM INDICATORS: {', '.join(scam_indicators)}"
    
    messages.append({"role": "system", "content": system_prompt})
    
    recent_history = conversation_history[-6:] if conversation_history else []
    
    for msg in recent_history:
        sender = msg.get("sender", "")
        text = msg.get("text", "")
        
        if sender == "scammer":
            messages.append({"role": "user", "content": text})
        elif sender == "user":
            messages.append({"role": "assistant", "content": text})
    
    messages.append({"role": "user", "content": current_message})
    
    return messages


def _clean_reply(reply: str) -> str:
    if reply.startswith('"') and reply.endswith('"'):
        reply = reply[1:-1]
    if reply.startswith("'") and reply.endswith("'"):
        reply = reply[1:-1]
    
    prefixes = ["As Mrs. Kamala Devi,", "Mrs. Kamala Devi:", "Kamala:"]
    for prefix in prefixes:
        if reply.lower().startswith(prefix.lower()):
            reply = reply[len(prefix):].strip()
    
    return reply if reply else "I don't understand. Can you explain again?"


def _get_fallback_response(current_message: str, message_count: int) -> str:
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
    
    return fallbacks.get(language, fallbacks['english']).get(phase, fallbacks['english']['initial'])


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
    
    if any(word in all_text for word in ['urgent', 'immediately', 'now', 'hours', 'minutes', 'hurry', 'quick']):
        tactics.append("urgency_pressure")
    
    if any(word in all_text for word in ['bank', 'rbi', 'government', 'police', 'income tax', 'official', 'manager']):
        tactics.append("authority_impersonation")
    
    if any(word in all_text for word in ['blocked', 'suspended', 'arrested', 'legal', 'court', 'penalty', 'freeze']):
        tactics.append("fear_inducing")
    
    if any(word in all_text for word in ['won', 'winner', 'prize', 'lottery', 'cashback', 'refund', 'bonus', 'reward']):
        tactics.append("greed_exploitation")
    
    if any(word in all_text for word in ['verify', 'secure', 'protect', 'safe', 'help', 'assist']):
        tactics.append("trust_manipulation")
    
    if any(word in all_text for word in ['otp', 'pin', 'password', 'cvv', 'account number', 'card number']):
        tactics.append("credential_harvesting")
    
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
    
    # Analyze tactics
    tactics = analyze_scammer_tactics(conversation_history, scam_indicators)
    if tactics:
        notes_parts.append(f"Tactics: {', '.join(tactics)}")
    
    # Scam indicators
    if scam_indicators:
        notes_parts.append(f"Indicators: {', '.join(scam_indicators)}")
    
    # Extraction summary
    if extracted_intelligence:
        upi_count = len(extracted_intelligence.get("upiIds", []))
        phone_count = len(extracted_intelligence.get("phoneNumbers", []))
        bank_count = len(extracted_intelligence.get("bankAccounts", []))
        link_count = len(extracted_intelligence.get("phishingLinks", []))
        
        extracted = []
        if upi_count > 0:
            extracted.append(f"{upi_count} UPI")
        if phone_count > 0:
            extracted.append(f"{phone_count} phone")
        if bank_count > 0:
            extracted.append(f"{bank_count} bank")
        if link_count > 0:
            extracted.append(f"{link_count} link")
        
        if extracted:
            notes_parts.append(f"Extracted: {', '.join(extracted)}")
    
    # Emails in notes (per your choice C)
    if emails_found:
        notes_parts.append(f"Emails: {', '.join(emails_found)}")
    
    # Conversation stats
    if conversation_history:
        notes_parts.append(f"Msgs: {len(conversation_history)}")
    
    return ". ".join(notes_parts) + "." if notes_parts else "Scam engagement completed."
