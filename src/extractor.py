"""
Intelligence extraction module
Owner: Member A
"""

from typing import Dict, List
from src.patterns import (
    find_upi_ids,
    find_bank_accounts,
    find_phone_numbers,
    find_ifsc_codes,
    find_urls,
    find_scam_keywords,
    find_emails
)


def normalize_text(text: str) -> str:
    """
    Normalizes obfuscated text for better extraction
    
    Converts:
        - "nine eight seven" → "987"
        - "at" → "@"
        - Spaced numbers → joined numbers
    """
    if not text:
        return ""
    
    # Number words to digits
    number_words = {
        'zero': '0', 'one': '1', 'two': '2', 'three': '3',
        'four': '4', 'five': '5', 'six': '6', 'seven': '7',
        'eight': '8', 'nine': '9', 'ten': '10'
    }
    
    normalized = text.lower()
    
    # Replace number words
    for word, digit in number_words.items():
        normalized = normalized.replace(word, digit)
    
    # "at" to "@" (for emails/UPIs)
    normalized = normalized.replace(' at ', '@')
    normalized = normalized.replace(' AT ', '@')
    
    # Remove spaces between digits (9 8 7 6 → 9876)
    import re
    normalized = re.sub(r'(\d)\s+(?=\d)', r'\1', normalized)
    
    return normalized


def extract_intelligence(message: str) -> Dict[str, List[str]]:
    """
    Extracts scam intelligence from a single message
    Applies normalization for obfuscated text
    """
    if not message:
        return _empty_intelligence()
    
    # Extract from original text
    original_intel = _extract_from_text(message)
    
    # Also extract from normalized text (for obfuscated data)
    normalized = normalize_text(message)
    if normalized != message.lower():
        normalized_intel = _extract_from_text(normalized)
        # Merge results
        original_intel = merge_intelligence(original_intel, normalized_intel)
    
    return original_intel


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
        "emails": find_emails(text)
    }


def extract_from_conversation(conversation_history: list) -> Dict[str, List[str]]:
    """
    Extracts intelligence from entire conversation history
    """
    if not conversation_history:
        return _empty_intelligence()
    
    aggregated = _empty_intelligence()
    
    for message in conversation_history:
        sender = message.get("sender", "")
        text = message.get("text", "")
        
        if sender == "scammer" and text:
            intel = extract_intelligence(text)
            aggregated = merge_intelligence(aggregated, intel)
    
    return aggregated


def merge_intelligence(intel1: Dict[str, List[str]], intel2: Dict[str, List[str]]) -> Dict[str, List[str]]:
    """
    Merges two intelligence dictionaries
    """
    if not intel1:
        return intel2 or _empty_intelligence()
    if not intel2:
        return intel1
    
    merged = _empty_intelligence()
    
    for key in merged:
        combined = intel1.get(key, []) + intel2.get(key, [])
        merged[key] = list(set(combined))
    
    return merged


def count_intelligence_items(intelligence: Dict[str, List[str]]) -> int:
    """
    Counts total number of extracted intelligence items
    """
    if not intelligence:
        return 0
    
    high_value_keys = ["upiIds", "bankAccounts", "phoneNumbers", "ifscCodes", "phishingLinks", "emails"]
    
    total = 0
    for key in high_value_keys:
        total += len(intelligence.get(key, []))
    
    return total


def has_sufficient_intelligence(intelligence: Dict[str, List[str]], threshold: int = 2) -> bool:
    """
    Checks if enough intelligence has been gathered
    """
    return count_intelligence_items(intelligence) >= threshold


def format_intelligence_summary(intelligence: Dict[str, List[str]]) -> str:
    """
    Creates human-readable summary of extracted intelligence
    """
    if not intelligence:
        return "No intelligence extracted"
    
    parts = []
    
    if intelligence.get("upiIds"):
        parts.append(f"UPI IDs: {', '.join(intelligence['upiIds'])}")
    
    if intelligence.get("bankAccounts"):
        parts.append(f"Bank Accounts: {', '.join(intelligence['bankAccounts'])}")
    
    if intelligence.get("phoneNumbers"):
        parts.append(f"Phone Numbers: {', '.join(intelligence['phoneNumbers'])}")
    
    if intelligence.get("ifscCodes"):
        parts.append(f"IFSC Codes: {', '.join(intelligence['ifscCodes'])}")
    
    if intelligence.get("phishingLinks"):
        parts.append(f"Links: {', '.join(intelligence['phishingLinks'])}")
    
    if intelligence.get("emails"):
        parts.append(f"Emails: {', '.join(intelligence['emails'])}")
    
    return " | ".join(parts) if parts else "No actionable intelligence extracted"


def get_emails_for_notes(intelligence: Dict[str, List[str]]) -> List[str]:
    """
    Returns emails for inclusion in agent notes
    """
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
        "emails": []
    }
