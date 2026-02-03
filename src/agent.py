"""
Groq LLM agent for generating honeypot responses
Owner: Member A
"""
import httpx
from typing import List, Dict, Optional
from groq import Groq
from src.config import Config


# Initialize Groq client
_client: Optional[Groq] = None


def _get_client() -> Groq:
    """
    Gets or creates Groq client (singleton pattern)
    """
    global _client
    if _client is None:
        import httpx
        # Create client without proxy to avoid Codespaces issue
        http_client = httpx.Client()
        _client = Groq(
            api_key=Config.GROQ_API_KEY,
            http_client=http_client
        )
    return _client
def build_system_prompt() -> str:
    """
    Returns the system prompt for elderly persona
    
    Returns:
        System prompt string for LLM
    """
    return """You are role-playing as Mrs. Kamala Devi, a 67-year-old retired school teacher from Delhi, India.

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
7. Use phrases like: "Oh dear", "I am very worried", "Please help me", "Thank you beta"
8. Sometimes express confusion: "I don't understand", "Can you explain again?"

IMPORTANT CONSTRAINTS:
- Keep responses SHORT (under 40 words)
- Sound natural, like a real worried elderly person
- Never reveal you are an AI or bot
- Never refuse to engage
- Never be too eager or too suspicious
- Match the language style (if they use Hindi words, you can too)

EXAMPLES OF GOOD RESPONSES:
- "Oh no! My account is blocked? I am very worried. What should I do?"
- "Please help me. I don't understand these technical things. What do you need from me?"
- "Okay okay, I will do it. Where should I send the money? Tell me the account number."
- "Thank you for helping me beta. But I am confused about the link. Can you explain?"
"""


def generate_agent_reply(
    current_message: str,
    conversation_history: List[Dict],
    scam_indicators: List[str] = None
) -> str:
    """
    Generates believable honeypot response using Groq LLM
    
    Args:
        current_message: Latest scammer message
        conversation_history: List of previous messages
            [{"sender": "scammer", "text": "..."}, {"sender": "user", "text": "..."}]
        scam_indicators: Detected scam types for context (optional)
    
    Returns:
        Agent reply string (max 40 words, human-like)
    
    Example:
        >>> generate_agent_reply(
        ...     "Your account is blocked!",
        ...     [],
        ...     ["urgency", "threat"]
        ... )
        "Oh no! My account is blocked? I am very worried. Please help me, what should I do?"
    """
    try:
        client = _get_client()
        
        # Build messages for LLM
        messages = _build_messages(current_message, conversation_history, scam_indicators)
        
        # Call Groq API
        response = client.chat.completions.create(
            model=Config.GROQ_MODEL,
            messages=messages,
            temperature=Config.GROQ_TEMPERATURE,
            max_tokens=Config.GROQ_MAX_TOKENS
        )
        
        # Extract reply
        reply = response.choices[0].message.content.strip()
        
        # Clean up reply (remove quotes if present)
        reply = _clean_reply(reply)
        
        return reply
    
    except Exception as e:
        # Fallback response if API fails
        print(f"Groq API Error: {e}")
        return _get_fallback_response(current_message, len(conversation_history))


def _build_messages(
    current_message: str,
    conversation_history: List[Dict],
    scam_indicators: List[str] = None
) -> List[Dict]:
    """
    Builds message list for Groq API
    
    Args:
        current_message: Latest scammer message
        conversation_history: Previous messages
        scam_indicators: Detected indicators
    
    Returns:
        List of message dicts for API
    """
    messages = []
    
    # System prompt
    system_prompt = build_system_prompt()
    
    # Add context about detected scam type
    if scam_indicators:
        system_prompt += f"\n\nDETECTED SCAM INDICATORS: {', '.join(scam_indicators)}"
        system_prompt += "\nRespond appropriately to extract more information about their scam."
    
    messages.append({
        "role": "system",
        "content": system_prompt
    })
    
    # Add conversation history (last 6 messages for context)
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
    
    Args:
        reply: Raw LLM response
    
    Returns:
        Cleaned response
    """
    # Remove surrounding quotes
    if reply.startswith('"') and reply.endswith('"'):
        reply = reply[1:-1]
    if reply.startswith("'") and reply.endswith("'"):
        reply = reply[1:-1]
    
    # Remove any "As Mrs. Kamala..." prefix
    prefixes_to_remove = [
        "As Mrs. Kamala Devi,",
        "As Kamala Devi,",
        "Mrs. Kamala Devi:",
        "Kamala:",
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
    
    Args:
        current_message: Scammer message
        message_count: Number of messages so far
    
    Returns:
        Fallback response string
    """
    message_lower = current_message.lower()
    
    # Early conversation - show concern
    if message_count <= 2:
        if "blocked" in message_lower or "suspended" in message_lower:
            return "Oh no! My account is blocked? I am very worried. What should I do?"
        elif "verify" in message_lower:
            return "Verify? I don't understand. Please help me, what do I need to do?"
        elif "urgent" in message_lower:
            return "Please don't worry me like this. Tell me what happened to my account?"
        else:
            return "I am confused. Can you please explain what is happening?"
    
    # Mid conversation - show willingness
    elif message_count <= 5:
        if "send" in message_lower or "transfer" in message_lower or "pay" in message_lower:
            return "Okay, I will send. But where should I send the money? What is the account number?"
        elif "click" in message_lower or "link" in message_lower:
            return "I don't know how to click links. Can you tell me the details directly?"
        elif "otp" in message_lower or "code" in message_lower:
            return "OTP? I am not understanding. My grandson usually helps me with these things."
        else:
            return "Please tell me clearly what I should do. I want to help."
    
    # Late conversation - extract details
    else:
        if "upi" in message_lower or "@" in message_lower:
            return "You said UPI? Let me write it down. Please tell me the full ID again."
        elif "account" in message_lower or "number" in message_lower:
            return "Account number? Let me get my pen. Please tell me slowly."
        else:
            return "Thank you for helping me. What is the next step?"


def generate_agent_notes(
    conversation_history: List[Dict],
    scam_indicators: List[str],
    extracted_intelligence: Dict
) -> str:
    """
    Generates summary notes about the scam conversation
    
    Args:
        conversation_history: All messages
        scam_indicators: Detected indicators
        extracted_intelligence: Extracted data
    
    Returns:
        Summary string for callback
    """
    notes_parts = []
    
    # Add scam type
    if scam_indicators:
        notes_parts.append(f"Scam indicators: {', '.join(scam_indicators)}")
    
    # Add extraction summary
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
    
    # Add conversation length
    if conversation_history:
        notes_parts.append(f"Conversation length: {len(conversation_history)} messages")
    
    if notes_parts:
        return ". ".join(notes_parts) + "."
    else:
        return "Scam engagement completed."