"""
Scam detection module
Owner: Member A

Fixes Applied:
- Consistent indicator names (credential_request)
- Input validation with max length
- Consolidated keywords with Hinglish support
- Logging framework
- Magic numbers replaced with constants
- Error handling
- Optimized pattern matching
"""

from typing import List, Dict, Tuple, Optional
import logging
from src.patterns import (
    find_upi_ids,
    find_bank_accounts,
    find_phone_numbers,
    find_urls,
)


logger = logging.getLogger(__name__)


# ============== CONSTANTS ==============

MAX_MESSAGE_LENGTH = 10000
SCAM_THRESHOLD = 0.3
MIN_INDICATORS_FOR_SCAM = 2

# Confidence weights
WEIGHTS = {
    'urgency': 0.15,
    'threat': 0.20,
    'authority_impersonation': 0.15,
    'payment_request': 0.25,
    'suspicious_link': 0.20,
    'credential_request': 0.20,
    'prize_offer': 0.15,
    'contains_upi': 0.10,
    'contains_phone': 0.05,
    'contains_bank_account': 0.10,
}

# Consolidated keyword lists (English + Hinglish)
DETECTION_PATTERNS = {
    'urgency': [
        # English
        "urgent", "immediately", "right now", "hurry", "last chance",
        "expire", "act now", "quickly", "fast", "within 24 hours",
        "within 1 hour", "limited time", "deadline",
        # Hinglish
        "turant", "abhi", "jaldi", "foren", "jald karo"
    ],
    'threat': [
        "blocked", "suspended", "terminated", "deactivated", "frozen",
        "illegal", "arrested", "police", "legal action", "account closed",
        "permanently blocked", "seized", "court", "penalty",
        # Hinglish
        "band ho jayega", "block ho gaya", "arrest", "kanoon", "jail"
    ],
    'authority': [
        "bank manager", "rbi", "reserve bank", "government", "income tax",
        "official", "security team", "customer care", "support team",
        "verification team", "cyber cell", "officer",
        # Hinglish
        "sarkari", "adhikari", "bank wale", "manager sahab"
    ],
    'payment': [
        "send money", "transfer", "pay now", "payment", "deposit",
        "₹", "rupees", "rs.", "rs ", "inr", "fee", "charge",
        # Hinglish
        "paisa bhejo", "payment karo", "transfer karo", "paise do"
    ],
    'credential': [
        "otp", "pin", "cvv", "password", "card number", "account number",
        "aadhaar", "pan card", "share details", "verify details",
        # Hinglish
        "otp batao", "pin batao", "password do", "details do"
    ],
    'prize': [
        "winner", "won", "prize", "lottery", "lucky", "congratulations",
        "selected", "reward", "gift", "bonus", "jackpot", "lucky draw",
        # Hinglish
        "jeet gaye", "inaam", "badhai ho", "inaam mila"
    ]
}

# Severity rules - MUST match indicator names exactly
SEVERITY_RULES = {
    'high': ['credential_request', 'payment_request', 'contains_upi', 'contains_bank_account'],
    'medium': ['urgency', 'threat', 'authority_impersonation'],
    'low': ['suspicious_link', 'contains_phone', 'prize_offer']
}

# Scam type definitions
SCAM_TYPES = {
    'bank_fraud': {
        'keywords': ['account blocked', 'account suspended', 'bank', 'sbi',
                     'hdfc', 'icici', 'axis', 'kyc', 'pan', 'aadhaar',
                     'khata band', 'account band'],
        'weight': 1.0
    },
    'lottery_scam': {
        'keywords': ['won', 'winner', 'prize', 'lottery', 'lucky draw',
                     'congratulations', 'claim', 'reward', 'jeet gaye', 'inaam'],
        'weight': 1.0
    },
    'phishing': {
        'keywords': ['click here', 'click link', 'verify', 'update',
                     'login', 'password', 'otp', 'link', 'url'],
        'weight': 0.8
    },
    'impersonation': {
        'keywords': ['rbi', 'reserve bank', 'police', 'cyber cell',
                     'income tax', 'government', 'official', 'manager',
                     'sarkari', 'adhikari'],
        'weight': 1.0
    },
    'payment_fraud': {
        'keywords': ['send money', 'transfer', 'pay', 'upi', 'paytm',
                     'phonepe', 'gpay', 'refund', 'cashback', 'paisa bhejo'],
        'weight': 0.9
    },
    'tech_support': {
        'keywords': ['computer', 'virus', 'malware', 'microsoft', 'apple',
                     'support', 'remote access', 'teamviewer', 'anydesk'],
        'weight': 0.8
    },
    'job_scam': {
        'keywords': ['job', 'work from home', 'part time', 'earn money',
                     'income', 'salary', 'hiring', 'recruitment', 'naukri'],
        'weight': 0.8
    },
    'investment_scam': {
        'keywords': ['invest', 'trading', 'bitcoin', 'crypto', 'forex',
                     'stock', 'returns', 'profit', 'double money', 'paisa double'],
        'weight': 0.9
    }
}


# ============== HELPER FUNCTIONS ==============

def _check_patterns(text: str, patterns: List[str]) -> bool:
    """Helper to check if any pattern matches"""
    return any(pattern in text for pattern in patterns)


def _find_matching_patterns(text: str, patterns: List[str]) -> List[str]:
    """Returns list of matching patterns"""
    return [p for p in patterns if p in text]


# ============== MAIN DETECTION ==============

def detect_scam(
    message: str,
    conversation_history: Optional[List[Dict]] = None
) -> Tuple[bool, float, List[str]]:
    """
    Analyzes message for scam intent
    
    Args:
        message: Text to analyze
        conversation_history: Previous messages
    
    Returns:
        Tuple of (is_scam, confidence, indicators)
    """
    if not message:
        return (False, 0.0, [])
    
    # Input validation
    if len(message) > MAX_MESSAGE_LENGTH:
        message = message[:MAX_MESSAGE_LENGTH]
        logger.warning(f"Message truncated to {MAX_MESSAGE_LENGTH} chars")
    
    message_lower = message.lower()
    indicators = []
    confidence = 0.0
    
    try:
        # Pattern-based detection
        if _check_patterns(message_lower, DETECTION_PATTERNS['urgency']):
            indicators.append("urgency")
            confidence += WEIGHTS['urgency']
        
        if _check_patterns(message_lower, DETECTION_PATTERNS['threat']):
            indicators.append("threat")
            confidence += WEIGHTS['threat']
        
        if _check_patterns(message_lower, DETECTION_PATTERNS['authority']):
            indicators.append("authority_impersonation")
            confidence += WEIGHTS['authority_impersonation']
        
        if _check_patterns(message_lower, DETECTION_PATTERNS['payment']):
            indicators.append("payment_request")
            confidence += WEIGHTS['payment_request']
        
        if _check_patterns(message_lower, DETECTION_PATTERNS['credential']):
            indicators.append("credential_request")
            confidence += WEIGHTS['credential_request']
        
        if _check_patterns(message_lower, DETECTION_PATTERNS['prize']):
            indicators.append("prize_offer")
            confidence += WEIGHTS['prize_offer']
        
        # Entity-based detection
        if find_urls(message):
            indicators.append("suspicious_link")
            confidence += WEIGHTS['suspicious_link']
        
        if find_upi_ids(message):
            indicators.append("contains_upi")
            confidence += WEIGHTS['contains_upi']
        
        if find_phone_numbers(message):
            indicators.append("contains_phone")
            confidence += WEIGHTS['contains_phone']
        
        if find_bank_accounts(message):
            indicators.append("contains_bank_account")
            confidence += WEIGHTS['contains_bank_account']
        
        # History analysis
        if conversation_history:
            history_confidence = _analyze_history(conversation_history)
            confidence += history_confidence
        
    except Exception as e:
        logger.error(f"Detection error: {e}")
    
    # Cap confidence
    confidence = min(1.0, confidence)
    
    # Determine if scam
    is_scam = confidence >= SCAM_THRESHOLD or len(indicators) >= MIN_INDICATORS_FOR_SCAM
    
    logger.debug(f"Scam detection: {is_scam}, confidence: {confidence}, indicators: {indicators}")
    
    return (is_scam, round(confidence, 2), indicators)


def _analyze_history(conversation_history: List[Dict]) -> float:
    """
    Analyzes conversation history for escalating scam patterns
    """
    if not conversation_history:
        return 0.0
    
    extra_confidence = 0.0
    
    scammer_messages = [
        msg.get("text", "").lower()
        for msg in conversation_history
        if msg.get("sender") == "scammer"
    ]
    
    if not scammer_messages:
        return 0.0
    
    # Check for urgency escalation
    urgency_count = sum(
        1 for msg in scammer_messages
        if _check_patterns(msg, DETECTION_PATTERNS['urgency'][:8])
    )
    if urgency_count >= 2:
        extra_confidence += 0.1
    
    # Check for repeated payment requests
    payment_count = sum(
        1 for msg in scammer_messages
        if _check_patterns(msg, ["send", "transfer", "pay", "bhejo"])
    )
    if payment_count >= 2:
        extra_confidence += 0.1
    
    return extra_confidence


# ============== CLASSIFICATION ==============

def classify_scam_type(
    message: str,
    conversation_history: Optional[List[Dict]] = None
) -> Dict:
    """
    Classifies the type of scam based on message content
    
    Returns:
        dict with primary_type, all_types, severity
    """
    if not message and not conversation_history:
        return {
            "primary_type": "unknown",
            "all_types": [],
            "severity": "low"
        }
    
    # Combine messages
    all_text = (message or "").lower()
    if conversation_history:
        for msg in conversation_history:
            if msg.get("sender") == "scammer":
                all_text += " " + msg.get("text", "").lower()
    
    if not all_text.strip():
        return {
            "primary_type": "unknown",
            "all_types": [],
            "severity": "low"
        }
    
    # Score each type
    type_scores = {}
    for scam_type, config in SCAM_TYPES.items():
        score = sum(1 for kw in config['keywords'] if kw in all_text)
        if score > 0:
            type_scores[scam_type] = score * config['weight']
    
    # Sort by score
    sorted_types = sorted(type_scores.items(), key=lambda x: x[1], reverse=True)
    
    # Get severity
    _, _, indicators = detect_scam(message or "", conversation_history)
    severity = _calculate_severity(indicators)
    
    return {
        "primary_type": sorted_types[0][0] if sorted_types else "unknown",
        "all_types": [{"type": t, "score": round(s, 2)} for t, s in sorted_types],
        "severity": severity
    }


def _calculate_severity(indicators: List[str]) -> str:
    """Calculates scam severity based on indicators"""
    for indicator in indicators:
        if indicator in SEVERITY_RULES['high']:
            return "high"
    
    for indicator in indicators:
        if indicator in SEVERITY_RULES['medium']:
            return "medium"
    
    return "low"


def get_scam_type(indicators: List[str]) -> str:
    """Simple scam type (backward compatible)"""
    if "prize_offer" in indicators:
        return "lottery_scam"
    elif "authority_impersonation" in indicators and "threat" in indicators:
        return "impersonation_scam"
    elif "payment_request" in indicators:
        return "payment_fraud"
    elif "suspicious_link" in indicators:
        return "phishing"
    elif "credential_request" in indicators:
        return "credential_theft"
    elif indicators:
        return "general_scam"
    return "unknown"
