"""
Intelligence extraction module
Owner: Member A

Improvements:
- Import at top level
- Logging added
- Input validation
- Extended number words (English + Hindi)
- Better type hints
- Constants for thresholds
"""

import re
import logging
from typing import Dict, List, Optional

from src.patterns import (
    find_upi_ids,
    find_bank_accounts,
    find_phone_numbers,
    find_ifsc_codes,
    find_urls,
    find_scam_keywords,
    find_emails,
    find_scammer_ids
)


logger = logging.getLogger(__name__)


# ============== CONSTANTS ==============

MAX_MESSAGE_LENGTH = 50000
DEFAULT_INTELLIGENCE_THRESHOLD = 2

# Number words mapping (English)
NUMBER_WORDS_EN: Dict[str, str] = {
    'zero': '0', 'one': '1', 'two': '2', 'three': '3',
    'four': '4', 'five': '5', 'six': '6', 'seven': '7',
    'eight': '8', 'nine': '9', 'ten': '10',
    'eleven': '11', 'twelve': '12', 'thirteen': '13',
    'fourteen': '14', 'fifteen': '15', 'sixteen': '16',
    'seventeen': '17', 'eighteen': '18', 'nineteen': '19',
    'twenty': '20', 'thirty': '30', 'forty': '40', 'fifty': '50',
    'sixty': '60', 'seventy': '70', 'eighty': '80', 'ninety': '90',
}

# Number words mapping (Hindi/Hinglish)
NUMBER_WORDS_HI: Dict[str, str] = {
    'ek': '1', 'do': '2', 'teen': '3', 'char': '4',
    'paanch': '5', 'panch': '5', 'chhe': '6', 'cheh': '6',
    'saat': '7', 'aath': '8', 'nau': '9', 'das': '10',
    'shunya': '0', 'sifar': '0'
}

# Combine all number words
NUMBER_WORDS: Dict[str, str] = {**NUMBER_WORDS_EN, **NUMBER_WORDS_HI}

# Intelligence keys (high value)
HIGH_VALUE_KEYS: List[str] = [
    "upiIds", "bankAccounts", "phoneNumbers",
    "ifscCodes", "phishingLinks", "emails"
]


# ============== NORMALIZATION ==============

def normalize_text(text: str) -> str:
    """
    Normalizes obfuscated text for better extraction
    """
    if not text:
        return ""
    
    normalized = text.lower()
    
    # Replace number words (longer words first to avoid partial matches)
    sorted_words = sorted(NUMBER_WORDS.keys(), key=len, reverse=True)
    for word in sorted_words:
        normalized = normalized.replace(word, NUMBER_WORDS[word])
    
    # "at" to "@" (for emails/UPIs)
    normalized = re.sub(r'\s+at\s+', '@', normalized, flags=re.IGNORECASE)
    
    # Remove spaces between digits (9 8 7 6 → 9876)
    normalized = re.sub(r'(\d)\s+(?=\d)', r'\1', normalized)
    
    # Remove common separators in numbers (9-8-7-6 → 9876)
    normalized = re.sub(r'(\d)[-.\s]+(?=\d)', r'\1', normalized)
    
    return normalized


# ============== CORE EXTRACTION ==============

def extract_intelligence(message: str) -> Dict[str, List[str]]:
    """
    Extracts scam intelligence from a single message
    Applies normalization for obfuscated text
    """
    if not message:
        return _empty_intelligence()
    
    # Input validation
    if len(message) > MAX_MESSAGE_LENGTH:
        logger.debug(f"Message truncated from {len(message)} to {MAX_MESSAGE_LENGTH}")
        message = message[:MAX_MESSAGE_LENGTH]
    
    try:
        # Extract from original text
        original_intel = _extract_from_text(message)
        
        # Also extract from normalized text (for obfuscated data)
        normalized = normalize_text(message)
        if normalized != message.lower():
            normalized_intel = _extract_from_text(normalized)
            original_intel = merge_intelligence(original_intel, normalized_intel)
        
        # Remove False Positives from UPIs (Extra safety layer)
        if 'upiIds' in original_intel:
            # src/patterns.py already filters, but double check against common English words
            invalid_upis = {'still@risk', 'unavailable@the', 'is@risk'}
            original_intel['upiIds'] = [
                upi for upi in original_intel['upiIds'] 
                if upi.lower() not in invalid_upis and not upi.endswith('@the')
            ]
        
        item_count = count_intelligence_items(original_intel)
        if item_count > 0:
            logger.debug(f"Extracted {item_count} intelligence items")
        
        return original_intel
    
    except Exception as e:
        logger.error(f"Extraction error: {e}")
        return _empty_intelligence()


def _extract_from_text(text: str) -> Dict[str, List[str]]:
    """
    Core extraction logic
    """
    return {
        "upiIds": find_upi_ids(text),
        "bankAccounts": find_bank_accounts(text),
        "phoneNumbers": find_phone_numbers(text),
        "ifscCodes": find_ifsc_codes(text),
        "phishingLinks": find_urls(text),
        "suspiciousKeywords": find_scam_keywords(text),
        "emails": find_emails(text),
        "scammerIds": find_scammer_ids(text)
    }


def extract_from_conversation(
    conversation_history: List[Dict[str, str]]
) -> Dict[str, List[str]]:
    """
    Extracts intelligence from entire conversation history
    """
    if not conversation_history:
        return _empty_intelligence()
    
    aggregated = _empty_intelligence()
    
    for message in conversation_history:
        sender = message.get("sender", "")
        text = message.get("text", "")
        
        # Only extract from scammer messages
        if sender == "scammer" and text:
            intel = extract_intelligence(text)
            aggregated = merge_intelligence(aggregated, intel)
    
    return aggregated


# ============== MERGE & UTILITIES ==============

def merge_intelligence(
    intel1: Optional[Dict[str, List[str]]],
    intel2: Optional[Dict[str, List[str]]]
) -> Dict[str, List[str]]:
    """
    Merges two intelligence dictionaries, removing duplicates
    """
    if not intel1:
        return intel2 or _empty_intelligence()
    if not intel2:
        return intel1
    
    merged = _empty_intelligence()
    
    for key in merged:
        combined = intel1.get(key, []) + intel2.get(key, [])
        # Remove duplicates while preserving some order
        merged[key] = list(dict.fromkeys(combined))
    
    return merged


def count_intelligence_items(intelligence: Optional[Dict[str, List[str]]]) -> int:
    """
    Counts total number of extracted high-value intelligence items
    """
    if not intelligence:
        return 0
    
    total = 0
    for key in HIGH_VALUE_KEYS:
        total += len(intelligence.get(key, []))
    
    return total


def has_sufficient_intelligence(
    intelligence: Optional[Dict[str, List[str]]],
    threshold: int = DEFAULT_INTELLIGENCE_THRESHOLD
) -> bool:
    """
    Checks if enough intelligence has been gathered
    """
    return count_intelligence_items(intelligence) >= threshold


# ============== FORMATTING ==============

def format_intelligence_summary(intelligence: Optional[Dict[str, List[str]]]) -> str:
    """
    Creates human-readable summary of extracted intelligence
    """
    if not intelligence:
        return "No intelligence extracted"
    
    parts = []
    
    labels = {
        "upiIds": "UPI IDs",
        "bankAccounts": "Bank Accounts",
        "phoneNumbers": "Phone Numbers",
        "ifscCodes": "IFSC Codes",
        "phishingLinks": "Links",
        "emails": "Emails"
    }
    
    for key, label in labels.items():
        items = intelligence.get(key, [])
        if items:
            parts.append(f"{label}: {', '.join(items)}")
    
    return " | ".join(parts) if parts else "No actionable intelligence extracted"


def get_emails_for_notes(intelligence: Optional[Dict[str, List[str]]]) -> List[str]:
    """
    Returns emails for inclusion in agent notes
    """
    if not intelligence:
        return []
    return intelligence.get("emails", [])


def _empty_intelligence() -> Dict[str, List[str]]:
    """
    Returns empty intelligence structure
    """
    return {
        "upiIds": [],
        "bankAccounts": [],
        "phoneNumbers": [],
        "ifscCodes": [],
        "phishingLinks": [],
        "suspiciousKeywords": [],
        "emails": [],
        "scammerIds": []
    }
