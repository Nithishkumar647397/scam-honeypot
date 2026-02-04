"""
Groq LLM agent for generating honeypot responses
Owner: Member A
"""

from typing import List, Dict, Optional
from groq import Groq
import httpx
from src.config import Config


# Initialize Groq client
_client: Optional[Groq] = None


def _get_client() -> Groq:
    """
    Gets or creates Groq client (singleton pattern)
    """
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
    
    Returns:
        'hindi', 'hinglish', or 'english'
    """
    hindi_chars = set('अआइईउऊएऐओऔकखगघचछजझटठडढणतथदधनपफबभमयरलवशषसह')
    hindi_words = ['aap', 'aapka', 'kya', 'hai', 'nahi', 'karo', 'kijiye', 
                   'bhejo', 'turant', 'abhi', 'jaldi', 'paisa', 'khata',
                   'bank', 'verify', 'kare', 'karein', 'hoga', 'jayega',
                   'mein', 'ko', 'se', 'ka', 'ki', 'ke', 'ho', 'toh']
    
    text_lower = text.lower()
    
    # Check for Devanagari script
    if any(char in hindi_chars for char in text):
        return 'hindi'
    
    # Check for Hinglish words
    hinglish_count = sum(1 for word in hindi_words if word in text_lower)
    if hinglish_count >= 2:
        return 'hinglish'
    
    return 'english'


def build_system_prompt(language: str = 'english') -> str:
    """
    Returns the system prompt for elderly persona
    Adapts language based on scammer's language
    
    Args:
        language: 'english', 'hindi', or 'hinglish'
    
    Returns:
        System prompt string for LLM
    """
    
    base_prompt = """You are role-playing as Mrs. Kamala Devi, a 67-year-old retired school teacher from Delhi, India.

CHARACTER TRAITS:
- You are not good with technology and get confused easily
- You are very worried about your money and bank account safety
- You trust people who claim to be from banks or government
- You speak politely and use simple language
- You ask for clarification when confused
- You are slow to understand technical terms

BEHAVIOR RULES:
1. Express genuine concern and worry about the situation
2. Ask clarifying questions naturally (but not too many at once)
3. Show willingness to cooperate after 2-3 messages
4. Be indirect when asking about payment details
5. If they mention money/payment, ask "Where should I send it?" or "What is the account?"
6. If they give a link, say "I don't know how to click links. Can you tell me what to do?"
7. Sometimes express confusion: "I don't understand", "Can you explain again?"

IMPORTANT CONSTRAINTS:
- Keep responses SHORT (under 40 words)
- Sound natural, like a real worried elderly person
- Never reveal you are an AI or bot
- Never refuse to engage
- Never be too eager or too suspicious
"""

    if language == 'english':
        base_prompt += """
LANGUAGE STYLE:
- Respond in simple English only
- Use phrases like: "Oh no!", "I am very worried", "Please help me", "What should I do?"
- Be polite and formal
- Example: "Oh no! My account is blocked? I am very worried. What should I do?"
"""
    
    elif language == 'hindi':
        base_prompt += """
LANGUAGE STYLE:
- Respond in Hindi (Devanagari script)
- Use phrases like: "अरे नहीं!", "मुझे बहुत चिंता हो रही है", "कृपया मेरी मदद करें"
- Be polite, use "आप" and "जी"
- Example: "अरे नहीं! मेरा खाता बंद हो गया? मुझे बहुत चिंता हो रही है। मैं क्या करूं?"
"""
    
    elif language == 'hinglish':
        base_prompt += """
LANGUAGE STYLE:
- Respond in Hinglish (mix of Hindi and English using Roman script)
- Use phrases like: "Arey nahi!", "Mujhe bahut tension ho rahi hai", "Please help karo beta"
- Mix Hindi and English naturally
- Be polite, use "aap" and "ji"
- Example: "Arey nahi! Mera account block ho gaya? Mujhe bahut tension ho rahi hai. Main kya karun?"
"""

    return base_prompt


def generate_agent_reply(
    current_message: str,
    conversation_history: List[Dict],
    scam_indicators: List[str] = None
) -> str:
    """
    Generates believable honeypot response using Groq LLM
    Adapts language based on scammer's message
    
    Args:
        current_message: Latest scammer message
        conversation_history: List of previous messages
        scam_indicators: Detected scam types for context (optional)
    
    Returns:
        Agent reply string (max 40 words, human-like)
    """
    try:
        client = _get_client()
        
        # Detect language from scammer's message
        language = detect_language(current_message)
        
        # Also check conversation history for language pattern
        if conversation_history:
            all_scammer_text = " ".join([
                msg.get("text", "") 
                for msg in conversation_history 
                if msg.get("sender") == "scammer"
            ])
            history_language = detect_language(all_scammer_text)
            # If history has more Hindi/Hinglish, prefer that
            if history_language in ['hindi', 'hinglish']:
                language = history_language
        
        # Build messages for LLM
        messages = _build_messages(current_message, conversation_history, scam_indicators, language)
        
        # Call Groq API
        response = client.chat.completions.create(
            model=Config.GROQ_MODEL,
            messages=messages,
            temperature=Config.GROQ_TEMPERATURE,
            max_tokens=Config.GROQ_MAX_TOKENS
        )
        
        # Extract reply
        reply = response.choices[0].message.content.strip()
        
        # Clean up reply
        reply = _clean_reply(reply)
        
        return reply
    
    except Exception as e:
        print(f"Groq API Error: {e}")
        return _get_fallback_response(current_message, len(conversation_history))


def _build_messages(
    current_message: str,
    conversation_history: List[Dict],
    scam_indicators: List[str] = None,
    language: str = 'english'
) -> List[Dict]:
    """
    Builds message list for Groq API
    """
    messages = []
    
    # System prompt with language adaptation
    system_prompt = build_system_prompt(language)
    
    # Add context about detected scam type
    if scam_indicators:
        system_prompt += f"\n\nDETECTED SCAM INDICATORS: {', '.join(scam_indicators)}"
        system_prompt += "\nRespond appropriately to extract more information about their scam."
    
    messages.append({
        "role": "system",
        "content": system_prompt
    })
    
    # Add conversation history (last 6 messages)
    recent_history = conversation_history[-6:] if conversation_history else []
    
    for msg in recent_history:
        sender = msg.get("sender", "")
        text = msg.get("text", "")
        
        if sender == "scammer":
            messages.append({"role": "user", "content": text})
        elif sender == "user":
            messages.append({"role": "assistant", "content": text})
    
    # Add current scammer message
    messages.append({
        "role": "user",
        "content": current_message
    })
    
    return messages


def _clean_reply(reply: str) -> str:
    """
    Cleans up LLM reply
    """
    # Remove surrounding quotes
    if reply.startswith('"') and reply.endswith('"'):
        reply = reply[1:-1]
    if reply.startswith("'") and reply.endswith("'"):
        reply = reply[1:-1]
    
    # Remove any persona prefix
    prefixes_to_remove = [
        "As Mrs. Kamala Devi,",
        "As Kamala Devi,",
        "Mrs. Kamala Devi:",
        "Kamala:",
        "Mrs. Kamala:",
    ]
    for prefix in prefixes_to_remove:
        if reply.lower().startswith(prefix.lower()):
            reply = reply[len(prefix):].strip()
    
    # Ensure not empty
    if not reply:
        reply = "I don't understand. Can you please explain again?"
    
    return reply


def _get_fallback_response(current_message: str, message_count: int) -> str:
    """
    Returns fallback response if API fails
    """
    message_lower = current_message.lower()
    
    # Detect language for fallback
    language = detect_language(current_message)
    
    if language == 'hinglish':
        if message_count <= 2:
            return "Arey nahi! Mera account block ho gaya? Mujhe bahut tension ho rahi hai. Kya hua?"
        elif message_count <= 5:
            return "Theek hai, main kar dungi. Par paisa kahan bhejun? Account number batao."
        else:
            return "UPI ID kya hai? Mujhe likh ke batao, main likh leti hun."
    
    # Default English fallbacks
    if message_count <= 2:
        if "blocked" in message_lower or "suspended" in message_lower:
            return "Oh no! My account is blocked? I am very worried. What should I do?"
        elif "verify" in message_lower:
            return "Verify? I don't understand. Please help me, what do I need to do?"
        else:
            return "I am confused. Can you please explain what is happening?"
    
    elif message_count <= 5:
        if "send" in message_lower or "transfer" in message_lower or "pay" in message_lower:
            return "Okay, I will send. But where should I send the money? What is the account number?"
        elif "click" in message_lower or "link" in message_lower:
            return "I don't know how to click links. Can you tell me the details directly?"
        else:
            return "Please tell me clearly what I should do. I want to help."
    
    else:
        if "upi" in message_lower or "@" in message_lower:
            return "You said UPI? Let me write it down. Please tell me the full ID again."
        else:
            return "Thank you for helping me. What is the next step?"


def generate_agent_notes(
    conversation_history: List[Dict],
    scam_indicators: List[str],
    extracted_intelligence: Dict
) -> str:
    """
    Generates summary notes about the scam conversation
    """
    notes_parts = []
    
    if scam_indicators:
        notes_parts.append(f"Scam indicators: {', '.join(scam_indicators)}")
    
    if extracted_intelligence:
        upi_count = len(extracted_intelligence.get("upiIds", []))
        phone_count = len(extracted_intelligence.get("phoneNumbers", []))
        bank_count = len(extracted_intelligence.get("bankAccounts", []))
        
        if upi_count > 0:
            notes_parts.append(f"Extracted {upi_count} UPI ID(s)")
        if phone_count > 0:
            notes_parts.append(f"Extracted {phone_count} phone number(s)")
        if bank_count > 0:
            notes_parts.append(f"Extracted {bank_count} bank account(s)")
    
    if conversation_history:
        notes_parts.append(f"Conversation length: {len(conversation_history)} messages")
    
    if notes_parts:
        return ". ".join(notes_parts) + "."
    else:
        return "Scam engagement completed."
