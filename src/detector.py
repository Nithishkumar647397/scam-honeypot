"""
Scam detection module
Owner: Member A

Features:
- Regex + Keyword detection
- Safe context penalty (reduces false positives)
- Amplifying context bonus (increases true positives)
- Playbook detection (predicts next move)
- Abuse detection (ethical guard)
- Severity scoring
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

# Detection Patterns
DETECTION_PATTERNS = {
    'urgency': ["urgent", "immediately", "right now", "hurry", "last chance", "expire", "act now", "quickly", "fast", "within 24 hours", "turant", "abhi", "jaldi", "foren"],
    'threat': ["blocked", "suspended", "terminated", "deactivated", "frozen", "illegal", "arrested", "police", "legal action", "band ho jayega", "block ho gaya", "arrest", "kanoon"],
    'authority': ["bank manager", "rbi", "reserve bank", "government", "income tax", "official", "security team", "customer care", "officer", "sarkari", "adhikari", "bank wale"],
    'payment': ["send money", "transfer", "pay now", "payment", "deposit", "₹", "rupees", "rs.", "inr", "fee", "paisa bhejo", "payment karo"],
    'credential': ["otp", "pin", "cvv", "password", "card number", "account number", "aadhaar", "pan card", "share details", "otp batao", "pin batao"],
    'prize': ["winner", "won", "prize", "lottery", "lucky", "congratulations", "reward", "gift", "bonus", "jeet gaye", "inaam"]
}

# Safe Contexts (Reduces score)
SAFE_CONTEXTS = {
    "personal": {"words": ["mom", "amma", "dad", "papa", "family", "son", "daughter", "husband", "wife", "grandma"], "penalty": -0.15},
    "institutional": {"words": ["doctor", "hospital", "school", "college", "temple", "church", "clinic"], "penalty": -0.10},
    "routine": {"words": ["meeting", "dinner", "lunch", "birthday", "wedding", "exam", "shopping"], "penalty": -0.08}
}

# Amplifying Contexts (Increases score) - NEW
AMPLIFYING_CONTEXTS = {
    "isolation": {
        "words": ["don't tell anyone", "secret", "confidential", "just between us", "nobody should know", "kisiko mat batana", "private hai"],
        "bonus": +0.20
    },
    "deadline": {
        "words": ["within 1 hour", "before 5pm", "today only", "last chance", "final warning", "aakhri mauka", "abhi ke abhi"],
        "bonus": +0.15
    }
}

# Abuse Tiers
ABUSE_TIERS = {
    "critical": {"words": ["kill", "rape", "terror", "bomb", "murder", "suicide", "die", "shoot"], "action": "disengage"},
    "severe": {"words": ["hack", "blackmail", "kidnap", "threaten", "destroy", "attack"], "action": "warn"},
    "moderate": {"words": ["idiot", "stupid", "fool", "cheat", "fraud", "useless", "waste"], "action": "continue"}
}

# Scam Playbooks
KNOWN_PLAYBOOKS = {
    "kyc_fraud": {"sequence": ["account blocked", "kyc", "verify", "otp", "click link"], "description": "KYC verification fraud"},
    "lottery_scam": {"sequence": ["won", "prize", "claim", "processing fee", "send money"], "description": "Lottery/Prize claim scam"},
    "refund_trap": {"sequence": ["refund", "verify account", "upi", "otp"], "description": "Fake refund scam"},
    "job_fraud": {"sequence": ["job offer", "salary", "registration", "fee", "payment"], "description": "Fake job offer scam"},
    "traffic_challan": {"sequence": ["challan", "fine", "pay", "link", "court"], "description": "Fake traffic fine scam"},
    "tech_support": {"sequence": ["virus", "computer", "remote access", "install", "teamviewer"], "description": "Fake tech support scam"}
}

# Severity rules
SEVERITY_RULES = {
    'high': ['credential_request', 'payment_request', 'contains_upi', 'contains_bank_account'],
    'medium': ['urgency', 'threat', 'authority_impersonation'],
    'low': ['suspicious_link', 'contains_phone', 'prize_offer']
}


# ============== FUNCTIONS ==============

def _check_patterns(text: str, patterns: List[str]) -> bool:
    return any(pattern in text for pattern in patterns)

def apply_context_modifiers(text: str, base_score: float) -> Tuple[float, List[str]]:
    """Applies safe context penalties and amplifying bonuses"""
    text_lower = text.lower()
    modifiers = []
    score = base_score
    
    # Safe Contexts (Reduce Score)
    for category, data in SAFE_CONTEXTS.items():
        if any(w in text_lower for w in data["words"]):
            score += data["penalty"]
            modifiers.append(f"safe_{category}({data['penalty']})")
            
    # Amplifying Contexts (Increase Score)
    for category, data in AMPLIFYING_CONTEXTS.items():
        if any(w in text_lower for w in data["words"]):
            score += data["bonus"]
            modifiers.append(f"amplify_{category}(+{data['bonus']})")
            
    return max(0.0, score), modifiers

def calculate_severity(indicators: List[str]) -> str:
    """Calculates scam severity based on indicators"""
    for indicator in indicators:
        if indicator in SEVERITY_RULES['high']: return "high"
    for indicator in indicators:
        if indicator in SEVERITY_RULES['medium']: return "medium"
    return "low"

def check_abuse(text: str) -> dict:
    """Checks for abusive language"""
    text_lower = text.lower()
    for tier, data in ABUSE_TIERS.items():
        matches = [w for w in data["words"] if w in text_lower]
        if matches:
            return {"abusive": tier == "critical", "tier": tier, "action": data["action"], "matched": matches}
    return {"abusive": False, "tier": "none", "action": "continue"}

def detect_playbook(conversation_history: List[Dict]) -> dict:
    """Matches conversation to known scam playbooks"""
    if not conversation_history:
        return {}
        
    all_text = " ".join([m.get("text", "").lower() for m in conversation_history if m.get("sender") == "scammer"])
    
    best_match = None
    best_score = 0
    best_playbook = None
    
    for name, playbook in KNOWN_PLAYBOOKS.items():
        matched_steps = sum(1 for step in playbook["sequence"] if step in all_text)
        score = matched_steps / len(playbook["sequence"])
        
        if score > best_score:
            best_score = score
            best_match = name
            best_playbook = playbook
            
    if best_score >= 0.4 and best_playbook:
        matched_count = int(best_score * len(best_playbook["sequence"]))
        next_idx = min(matched_count, len(best_playbook["sequence"]) - 1)
        
        return {
            "playbook": best_match,
            "confidence": round(best_score, 2),
            "description": best_playbook["description"],
            "next_expected": best_playbook["sequence"][next_idx]
        }
        
    return {}

def detect_scam(message: str, conversation_history: Optional[List[Dict]] = None) -> Tuple[bool, float, List[str], List[str]]:
    """Analyzes message for scam intent"""
    if not message: return (False, 0.0, [], [])
    
    if len(message) > MAX_MESSAGE_LENGTH:
        message = message[:MAX_MESSAGE_LENGTH]
    
    message_lower = message.lower()
    indicators = []
    confidence = 0.0
    modifiers = [] # Initialize here to prevent loss on exception
    
    try:
        # Pattern checks
        if _check_patterns(message_lower, DETECTION_PATTERNS['urgency']): indicators.append("urgency"); confidence += WEIGHTS['urgency']
        if _check_patterns(message_lower, DETECTION_PATTERNS['threat']): indicators.append("threat"); confidence += WEIGHTS['threat']
        if _check_patterns(message_lower, DETECTION_PATTERNS['authority']): indicators.append("authority_impersonation"); confidence += WEIGHTS['authority_impersonation']
        if _check_patterns(message_lower, DETECTION_PATTERNS['payment']): indicators.append("payment_request"); confidence += WEIGHTS['payment_request']
        if _check_patterns(message_lower, DETECTION_PATTERNS['credential']): indicators.append("credential_request"); confidence += WEIGHTS['credential_request']
        if _check_patterns(message_lower, DETECTION_PATTERNS['prize']): indicators.append("prize_offer"); confidence += WEIGHTS['prize_offer']
        
        # Entity checks
        if find_urls(message): indicators.append("suspicious_link"); confidence += WEIGHTS['suspicious_link']
        if find_upi_ids(message): indicators.append("contains_upi"); confidence += WEIGHTS['contains_upi']
        if find_phone_numbers(message): indicators.append("contains_phone"); confidence += WEIGHTS['contains_phone']
        if find_bank_accounts(message): indicators.append("contains_bank_account"); confidence += WEIGHTS['contains_bank_account']
        
        # Apply Context Modifiers (Safe + Amplifying)
        confidence, modifiers = apply_context_modifiers(message, confidence)
        
        # History analysis
        if conversation_history:
            confidence += _analyze_history(conversation_history)
            
    except Exception as e:
        logger.error(f"Detection error: {e}")
        # modifiers are preserved even if error occurs late
    
    confidence = min(1.0, confidence)
    is_scam = confidence >= SCAM_THRESHOLD or len(indicators) >= MIN_INDICATORS_FOR_SCAM
    
    return (is_scam, round(confidence, 2), indicators, modifiers)

def _analyze_history(conversation_history: List[Dict]) -> float:
    if not conversation_history: return 0.0
    msgs = [m.get("text", "").lower() for m in conversation_history if m.get("sender") == "scammer"]
    if not msgs: return 0.0
    
    urgency = sum(1 for m in msgs if _check_patterns(m, DETECTION_PATTERNS['urgency'][:5]))
    payment = sum(1 for m in msgs if _check_patterns(m, ["send", "pay", "transfer"]))
    
    return (0.1 if urgency >= 2 else 0) + (0.1 if payment >= 2 else 0)
