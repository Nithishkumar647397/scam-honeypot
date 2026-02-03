"""
Scam detection module
Owner: Member A
"""

from typing import List, Tuple
from src.patterns import (
    find_upi_ids,
    find_bank_accounts,
    find_phone_numbers,
    find_urls,
    find_scam_keywords,
    SCAM_KEYWORDS,
    HINGLISH_KEYWORDS
)


# Weights for confidence calculation
INDICATOR_WEIGHTS = {
    "urgency": 0.15,
    "threat": 0.20,
    "authority_impersonation": 0.15,
    "payment_request": 0.25,
    "suspicious_link": 0.20,
    "personal_info_request": 0.20,
    "prize_offer": 0.15,
    "contains_upi": 0.10,
    "contains_phone": 0.05,
    "hinglish_scam": 0.10
}


def detect_scam(message: str, conversation_history: list = None) -> Tuple[bool, float, List[str]]:
    """
    Analyzes message for scam intent
    
    Args:
        message: Current scammer message text
        conversation_history: List of previous messages (optional)
    
    Returns:
        Tuple of:
            - is_scam (bool): True if scam detected
            - confidence (float): 0.0 to 1.0
            - indicators (List[str]): List of detected scam indicators
    
    Example:
        >>> detect_scam("URGENT! Your account is blocked! Send money now!")
        (True, 0.85, ["urgency", "threat", "payment_request"])
    """
    if not message:
        return (False, 0.0, [])
    
    message_lower = message.lower()
    indicators = []
    confidence = 0.0
    
    # Check for urgency indicators
    urgency_words = ["urgent", "immediately", "now", "today", "hurry", 
                     "last chance", "expire", "act now", "quickly", "fast"]
    if any(word in message_lower for word in urgency_words):
        indicators.append("urgency")
        confidence += INDICATOR_WEIGHTS["urgency"]
    
    # Check for threat indicators
    threat_words = ["blocked", "suspended", "terminated", "deactivated", 
                    "frozen", "illegal", "arrested", "police", "legal action",
                    "account closed", "permanently blocked"]
    if any(word in message_lower for word in threat_words):
        indicators.append("threat")
        confidence += INDICATOR_WEIGHTS["threat"]
    
    # Check for authority impersonation
    authority_words = ["bank manager", "rbi", "reserve bank", "government",
                       "income tax", "official", "security team", "customer care",
                       "support team", "verification team"]
    if any(word in message_lower for word in authority_words):
        indicators.append("authority_impersonation")
        confidence += INDICATOR_WEIGHTS["authority_impersonation"]
    
    # Check for payment requests
    payment_words = ["send money", "transfer", "pay now", "payment", 
                     "deposit", "₹", "rupees", "rs.", "rs ", "inr"]
    if any(word in message_lower for word in payment_words):
        indicators.append("payment_request")
        confidence += INDICATOR_WEIGHTS["payment_request"]
    
    # Check for suspicious links
    urls = find_urls(message)
    if urls:
        indicators.append("suspicious_link")
        confidence += INDICATOR_WEIGHTS["suspicious_link"]
    
    # Check for personal info requests
    info_words = ["otp", "pin", "cvv", "password", "card number", 
                  "account number", "aadhaar", "pan card", "share details"]
    if any(word in message_lower for word in info_words):
        indicators.append("personal_info_request")
        confidence += INDICATOR_WEIGHTS["personal_info_request"]
    
    # Check for prize/lottery offers
    prize_words = ["winner", "won", "prize", "lottery", "lucky", 
                   "congratulations", "selected", "reward", "gift", "bonus"]
    if any(word in message_lower for word in prize_words):
        indicators.append("prize_offer")
        confidence += INDICATOR_WEIGHTS["prize_offer"]
    
    # Check for UPI IDs in message
    upi_ids = find_upi_ids(message)
    if upi_ids:
        indicators.append("contains_upi")
        confidence += INDICATOR_WEIGHTS["contains_upi"]
    
    # Check for phone numbers
    phones = find_phone_numbers(message)
    if phones:
        indicators.append("contains_phone")
        confidence += INDICATOR_WEIGHTS["contains_phone"]
    
    # Check for Hinglish scam patterns
    hinglish_words = ["turant", "abhi", "jaldi", "khata", "paisa bhejo",
                      "verify karo", "block ho", "band ho jayega"]
    if any(word in message_lower for word in hinglish_words):
        indicators.append("hinglish_scam")
        confidence += INDICATOR_WEIGHTS["hinglish_scam"]
    
    # Analyze conversation history for patterns
    if conversation_history:
        history_confidence = _analyze_history(conversation_history)
        confidence += history_confidence
    
    # Cap confidence at 1.0
    confidence = min(1.0, confidence)
    
    # Determine if scam (threshold: 0.3)
    is_scam = confidence >= 0.3 or len(indicators) >= 2
    
    return (is_scam, round(confidence, 2), indicators)


def _analyze_history(conversation_history: list) -> float:
    """
    Analyzes conversation history for escalating scam patterns
    
    Args:
        conversation_history: List of previous messages
    
    Returns:
        Additional confidence score (0.0 to 0.2)
    """
    if not conversation_history:
        return 0.0
    
    extra_confidence = 0.0
    
    # Get all scammer messages
    scammer_messages = [
        msg.get("text", "") 
        for msg in conversation_history 
        if msg.get("sender") == "scammer"
    ]
    
    if not scammer_messages:
        return 0.0
    
    # Check for escalation pattern (more urgent over time)
    urgency_count = 0
    for msg in scammer_messages:
        msg_lower = msg.lower()
        if any(word in msg_lower for word in ["urgent", "now", "immediately"]):
            urgency_count += 1
    
    if urgency_count >= 2:
        extra_confidence += 0.1
    
    # Check for repeated payment requests
    payment_count = 0
    for msg in scammer_messages:
        msg_lower = msg.lower()
        if any(word in msg_lower for word in ["send", "transfer", "pay"]):
            payment_count += 1
    
    if payment_count >= 2:
        extra_confidence += 0.1
    
    return extra_confidence


def get_scam_type(indicators: List[str]) -> str:
    """
    Determines the primary scam type based on indicators
    
    Args:
        indicators: List of detected indicators
    
    Returns:
        Scam type string
    """
    if "prize_offer" in indicators:
        return "lottery_scam"
    elif "authority_impersonation" in indicators and "threat" in indicators:
        return "impersonation_scam"
    elif "payment_request" in indicators:
        return "payment_scam"
    elif "suspicious_link" in indicators:
        return "phishing_scam"
    elif "personal_info_request" in indicators:
        return "data_theft_scam"
    elif indicators:
        return "general_scam"
    else:
        return "unknown"