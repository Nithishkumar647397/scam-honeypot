"""
Scam detection module with multi-indicator weighted scoring.

Detects scam patterns using keyword matching, financial identifier extraction,
context modifiers (safe/amplifying), abuse tier classification, and known
playbook sequence matching.

Owner: Member A
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

MAX_MESSAGE_LENGTH = 10000
SCAM_THRESHOLD = 0.3
MIN_INDICATORS_FOR_SCAM = 2

# Weights for each indicator category in confidence scoring
WEIGHTS = {
    'urgency': 0.15, 'threat': 0.20, 'authority_impersonation': 0.15,
    'payment_request': 0.25, 'suspicious_link': 0.20, 'credential_request': 0.20,
    'prize_offer': 0.15, 'contains_upi': 0.10, 'contains_phone': 0.05,
    'contains_bank_account': 0.10,
}

# Keyword patterns for each scam indicator category
DETECTION_PATTERNS = {
    'urgency': ["urgent", "immediately", "right now", "hurry", "last chance", "expire", "act now", "quickly", "fast", "within 24 hours", "turant", "abhi", "jaldi", "foren", "limited time", "deadline"],
    'threat': ["blocked", "suspended", "terminated", "deactivated", "frozen", "illegal", "arrested", "police", "legal action", "band ho jayega", "block ho gaya", "arrest", "kanoon", "lock", "compromised", "penalty", "court", "warrant"],
    'authority': ["bank manager", "rbi", "reserve bank", "government", "income tax", "official", "security team", "customer care", "officer", "sarkari", "adhikari", "bank wale", "cyber cell", "fraud department", "compliance"],
    'payment': ["send money", "transfer", "pay now", "payment", "deposit", "₹", "rupees", "rs.", "inr", "fee", "paisa bhejo", "payment karo", "processing fee", "registration fee", "charges"],
    'credential': ["otp", "pin", "cvv", "password", "card number", "account number", "aadhaar", "pan card", "share details", "otp batao", "pin batao", "identity", "login", "credentials", "grid value"],
    'prize': ["winner", "won", "prize", "lottery", "lucky", "congratulations", "reward", "gift", "bonus", "jeet gaye", "inaam", "selected", "cashback"]
}

# Contexts that reduce scam confidence (false positive protection)
SAFE_CONTEXTS = {
    "personal": {"words": ["mom", "amma", "dad", "papa", "family", "son", "daughter", "husband", "wife", "grandma"], "penalty": -0.15},
    "institutional": {"words": ["doctor", "hospital", "school", "college", "temple", "church", "clinic"], "penalty": -0.10},
    "routine": {"words": ["meeting", "dinner", "lunch", "birthday", "wedding", "exam", "shopping"], "penalty": -0.08}
}

# Contexts that amplify scam confidence
AMPLIFYING_CONTEXTS = {
    "isolation": {"words": ["don't tell anyone", "secret", "confidential", "just between us", "nobody should know", "kisiko mat batana", "private hai"], "bonus": +0.20},
    "deadline": {"words": ["within 1 hour", "before 5pm", "today only", "last chance", "final warning", "aakhri mauka", "abhi ke abhi"], "bonus": +0.15},
    "emotional_manipulation": {"words": ["your family will suffer", "think of your children", "you will lose everything", "no one can help you"], "bonus": +0.15}
}

# Tiered abuse classification for safety
ABUSE_TIERS = {
    "critical": {"words": ["kill", "rape", "terror", "bomb", "murder", "suicide", "die", "shoot"], "action": "disengage"},
    "severe": {"words": ["hack", "blackmail", "kidnap", "threaten", "destroy", "attack"], "action": "warn"},
    "moderate": {"words": ["idiot", "stupid", "fool", "cheat", "fraud", "useless", "waste"], "action": "continue"}
}

# Known scam playbook sequences for pattern matching
KNOWN_PLAYBOOKS = {
    "account_block": {"sequence": ["compromised", "blocked", "verify", "otp", "identity"], "description": "Account block threat"},
    "kyc_fraud": {"sequence": ["account blocked", "kyc", "verify", "otp", "click link"], "description": "KYC verification fraud"},
    "lottery_scam": {"sequence": ["won", "prize", "claim", "processing fee", "send money"], "description": "Lottery/Prize claim scam"},
    "refund_trap": {"sequence": ["refund", "verify account", "upi", "otp"], "description": "Fake refund scam"},
    "job_fraud": {"sequence": ["job offer", "salary", "registration", "fee", "payment"], "description": "Fake job offer scam"},
    "traffic_challan": {"sequence": ["challan", "fine", "pay", "link", "court"], "description": "Fake traffic fine scam"},
    "tech_support": {"sequence": ["virus", "computer", "remote access", "install", "teamviewer"], "description": "Fake tech support scam"},
    "customs_scam": {"sequence": ["parcel", "customs", "seized", "fine", "pay"], "description": "Fake customs/parcel scam"},
    "investment_fraud": {"sequence": ["invest", "returns", "guaranteed", "deposit", "profit"], "description": "Fake investment scheme"}
}

# Maps indicators to severity tiers for classification
SEVERITY_RULES = {
    'high': ['credential_request', 'payment_request', 'contains_upi', 'contains_bank_account'],
    'medium': ['urgency', 'threat', 'authority_impersonation'],
    'low': ['suspicious_link', 'contains_phone', 'prize_offer']
}

# Granular behavioral red flags detected across a conversation
RED_FLAG_PATTERNS = {
    'escalating_pressure': {
        'description': 'Scammer is increasing urgency over time',
        'keywords': ['urgent', 'immediately', 'now', 'hurry', 'last chance'],
        'min_occurrences': 2
    },
    'identity_switching': {
        'description': 'Scammer claims multiple authority roles',
        'keywords': ['bank', 'police', 'rbi', 'government', 'officer', 'manager', 'customer care', 'cyber cell'],
        'min_occurrences': 2
    },
    'multiple_payment_channels': {
        'description': 'Scammer provides multiple payment methods (organized operation)',
        'keywords': ['upi', 'account number', 'paytm', 'phonepe', 'gpay', 'bank transfer'],
        'min_occurrences': 2
    },
    'verification_evasion': {
        'description': 'Scammer avoids providing own identity details when asked',
        'keywords': [],  # Detected by conversation analysis, not keywords
        'min_occurrences': 0
    },
    'rapid_payment_escalation': {
        'description': 'Scammer pushes payment in multiple consecutive messages',
        'keywords': ['send', 'pay', 'transfer', '₹', 'rupees'],
        'min_occurrences': 3
    }
}

def _check_patterns(text: str, patterns: List[str]) -> bool:
    """Check if any pattern from the list appears in the text."""
    return any(pattern in text for pattern in patterns)

def apply_context_modifiers(text: str, base_score: float) -> Tuple[float, List[str]]:
    """Apply safe (penalty) and amplifying (bonus) context modifiers to the base confidence score.

    Returns:
        Tuple of (adjusted_score, list_of_modifier_descriptions)
    """
    text_lower = text.lower()
    modifiers = []
    score = base_score
    for category, data in SAFE_CONTEXTS.items():
        if any(w in text_lower for w in data["words"]):
            score += data["penalty"]
            modifiers.append(f"safe_{category}({data['penalty']})")
    for category, data in AMPLIFYING_CONTEXTS.items():
        if any(w in text_lower for w in data["words"]):
            score += data["bonus"]
            modifiers.append(f"amplify_{category}(+{data['bonus']})")
    return max(0.0, score), modifiers

def calculate_severity(indicators: List[str]) -> str:
    """Classify overall severity as high/medium/low based on the most severe indicator present."""
    if not indicators:
        return "low"
    for indicator in indicators:
        if indicator in SEVERITY_RULES['high']: return "high"
    for indicator in indicators:
        if indicator in SEVERITY_RULES['medium']: return "medium"
    return "low"

def check_abuse(text: str) -> dict:
    """Check text for abusive content across critical/severe/moderate tiers.

    Returns:
        Dict with keys: abusive (bool), tier (str), action (str), matched (list)
    """
    if not text:
        return {"abusive": False, "tier": "none", "action": "continue", "matched": []}
    text_lower = text.lower()
    for tier, data in ABUSE_TIERS.items():
        matches = [w for w in data["words"] if w in text_lower]
        if matches:
            return {"abusive": tier == "critical", "tier": tier, "action": data["action"], "matched": matches}
    return {"abusive": False, "tier": "none", "action": "continue", "matched": []}

def detect_red_flags(conversation_history: List[Dict]) -> List[Dict]:
    """Detect granular behavioral red flags from conversation history.

    Analyzes scammer behavior patterns across the full conversation to identify
    organized operation indicators, escalation patterns, and evasion tactics.

    Returns:
        List of dicts with 'flag', 'description', and 'evidence' keys
    """
    if not conversation_history:
        return []

    scammer_msgs = [m.get("text", "").lower() for m in conversation_history if m.get("sender") == "scammer"]
    agent_msgs = [m.get("text", "").lower() for m in conversation_history if m.get("sender") == "user"]
    all_scammer_text = " ".join(scammer_msgs)
    flags = []

    # Escalating pressure: urgency in recent messages
    if len(scammer_msgs) >= 3:
        recent = scammer_msgs[-3:]
        urgency_words = RED_FLAG_PATTERNS['escalating_pressure']['keywords']
        urgency_count = sum(1 for t in recent if any(w in t for w in urgency_words))
        if urgency_count >= 2:
            flags.append({
                'flag': 'escalating_pressure',
                'description': RED_FLAG_PATTERNS['escalating_pressure']['description'],
                'evidence': f'{urgency_count} urgency signals in last 3 messages'
            })

    # Identity switching: multiple authority claims
    authority_claims = set()
    for keyword in RED_FLAG_PATTERNS['identity_switching']['keywords']:
        if keyword in all_scammer_text:
            authority_claims.add(keyword)
    if len(authority_claims) >= 2:
        flags.append({
            'flag': 'identity_switching',
            'description': RED_FLAG_PATTERNS['identity_switching']['description'],
            'evidence': f'Claims: {", ".join(sorted(authority_claims))}'
        })

    # Multiple payment channels
    payment_channels = set()
    for keyword in RED_FLAG_PATTERNS['multiple_payment_channels']['keywords']:
        if keyword in all_scammer_text:
            payment_channels.add(keyword)
    if len(payment_channels) >= 2:
        flags.append({
            'flag': 'multiple_payment_channels',
            'description': RED_FLAG_PATTERNS['multiple_payment_channels']['description'],
            'evidence': f'Channels: {", ".join(sorted(payment_channels))}'
        })

    # Verification evasion: agent asked for ID but scammer didn't provide
    verification_asks = ['employee id', 'badge', 'branch', 'reference number', 'ticket', 'your name']
    verification_responses = ['id is', 'badge number', 'reference:', 'ref:', 'ticket:', 'my name is', 'i am']
    asked = any(any(v in t for v in verification_asks) for t in agent_msgs)
    responded = any(any(v in t for v in verification_responses) for t in scammer_msgs)
    if asked and not responded and len(conversation_history) >= 6:
        flags.append({
            'flag': 'verification_evasion',
            'description': RED_FLAG_PATTERNS['verification_evasion']['description'],
            'evidence': 'Agent asked for identification but scammer did not provide'
        })

    # Rapid payment escalation: payment demands in consecutive messages
    payment_words = RED_FLAG_PATTERNS['rapid_payment_escalation']['keywords']
    payment_msg_count = sum(1 for t in scammer_msgs if any(w in t for w in payment_words))
    if payment_msg_count >= 3:
        flags.append({
            'flag': 'rapid_payment_escalation',
            'description': RED_FLAG_PATTERNS['rapid_payment_escalation']['description'],
            'evidence': f'{payment_msg_count} messages with payment demands'
        })

    return flags

def detect_playbook(conversation_history: List[Dict]) -> dict:
    """Match conversation against known scam playbook sequences.

    Returns:
        Dict with playbook name, confidence, description, and next expected step.
        Empty dict if no playbook matches above threshold.
    """
    if not conversation_history: return {}
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
    """Detect scam indicators in a message with weighted confidence scoring.

    Checks message text against keyword patterns, financial identifier patterns,
    and applies context modifiers. Also considers conversation history for
    repeated pattern detection.

    Args:
        message: The current message text to analyze
        conversation_history: Previous messages in the conversation

    Returns:
        Tuple of (is_scam, confidence, indicators, context_modifiers)
    """
    if not message: return (False, 0.0, [], [])
    if len(message) > MAX_MESSAGE_LENGTH: message = message[:MAX_MESSAGE_LENGTH]
    message_lower = message.lower()
    indicators = []
    confidence = 0.0
    modifiers = []

    # Keyword pattern matching
    try:
        if _check_patterns(message_lower, DETECTION_PATTERNS['urgency']): indicators.append("urgency"); confidence += WEIGHTS['urgency']
    except Exception as e:
        logger.warning(f"Urgency detection error: {e}")

    try:
        if _check_patterns(message_lower, DETECTION_PATTERNS['threat']): indicators.append("threat"); confidence += WEIGHTS['threat']
    except Exception as e:
        logger.warning(f"Threat detection error: {e}")

    try:
        if _check_patterns(message_lower, DETECTION_PATTERNS['authority']): indicators.append("authority_impersonation"); confidence += WEIGHTS['authority_impersonation']
    except Exception as e:
        logger.warning(f"Authority detection error: {e}")

    try:
        if _check_patterns(message_lower, DETECTION_PATTERNS['payment']): indicators.append("payment_request"); confidence += WEIGHTS['payment_request']
    except Exception as e:
        logger.warning(f"Payment detection error: {e}")

    try:
        if _check_patterns(message_lower, DETECTION_PATTERNS['credential']): indicators.append("credential_request"); confidence += WEIGHTS['credential_request']
    except Exception as e:
        logger.warning(f"Credential detection error: {e}")

    try:
        if _check_patterns(message_lower, DETECTION_PATTERNS['prize']): indicators.append("prize_offer"); confidence += WEIGHTS['prize_offer']
    except Exception as e:
        logger.warning(f"Prize detection error: {e}")

    # Financial identifier extraction
    try:
        if find_urls(message): indicators.append("suspicious_link"); confidence += WEIGHTS['suspicious_link']
    except Exception as e:
        logger.warning(f"URL extraction error: {e}")

    try:
        if find_upi_ids(message): indicators.append("contains_upi"); confidence += WEIGHTS['contains_upi']
    except Exception as e:
        logger.warning(f"UPI extraction error: {e}")

    try:
        if find_phone_numbers(message): indicators.append("contains_phone"); confidence += WEIGHTS['contains_phone']
    except Exception as e:
        logger.warning(f"Phone extraction error: {e}")

    try:
        if find_bank_accounts(message): indicators.append("contains_bank_account"); confidence += WEIGHTS['contains_bank_account']
    except Exception as e:
        logger.warning(f"Bank account extraction error: {e}")

    # Apply context modifiers
    try:
        confidence, modifiers = apply_context_modifiers(message, confidence)
    except Exception as e:
        logger.warning(f"Context modifier error: {e}")

    # Analyze conversation history for repeated patterns
    try:
        if conversation_history:
            confidence += _analyze_history(conversation_history)
    except Exception as e:
        logger.warning(f"History analysis error: {e}")

    confidence = min(1.0, confidence)
    is_scam = confidence >= SCAM_THRESHOLD or len(indicators) >= MIN_INDICATORS_FOR_SCAM
    return (is_scam, round(confidence, 2), indicators, modifiers)

def _analyze_history(conversation_history: List[Dict]) -> float:
    """Analyze conversation history for repeated scam patterns.

    Gives bonus confidence for repeated urgency, payment demands, and
    credential requests across multiple messages.

    Returns:
        Additional confidence score (0.0 to 0.3)
    """
    if not conversation_history: return 0.0
    msgs = [m.get("text", "").lower() for m in conversation_history if m.get("sender") == "scammer"]
    if not msgs: return 0.0

    bonus = 0.0

    urgency = sum(1 for m in msgs if _check_patterns(m, DETECTION_PATTERNS['urgency'][:5]))
    if urgency >= 2: bonus += 0.1

    payment = sum(1 for m in msgs if _check_patterns(m, ["send", "pay", "transfer", "₹", "rupees"]))
    if payment >= 2: bonus += 0.1

    credential = sum(1 for m in msgs if _check_patterns(m, ["otp", "pin", "cvv", "password", "aadhaar"]))
    if credential >= 2: bonus += 0.1

    return min(0.3, bonus)
