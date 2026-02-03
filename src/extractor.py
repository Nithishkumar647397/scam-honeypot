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
    find_scam_keywords
)


def extract_intelligence(message: str) -> Dict[str, List[str]]:
    """
    Extracts scam intelligence from a single message
    
    Args:
        message: Text to analyze
    
    Returns:
        Dict with extracted intelligence:
            - upiIds: List of UPI IDs found
            - bankAccounts: List of bank account numbers
            - phoneNumbers: List of phone numbers
            - ifscCodes: List of IFSC codes
            - phishingLinks: List of suspicious URLs
            - suspiciousKeywords: List of scam-related keywords
    
    Example:
        >>> extract_intelligence("Send money to fraud@paytm or call 9876543210")
        {
            "upiIds": ["fraud@paytm"],
            "bankAccounts": [],
            "phoneNumbers": ["9876543210"],
            "ifscCodes": [],
            "phishingLinks": [],
            "suspiciousKeywords": ["send money"]
        }
    """
    if not message:
        return _empty_intelligence()
    
    return {
        "upiIds": find_upi_ids(message),
        "bankAccounts": find_bank_accounts(message),
        "phoneNumbers": find_phone_numbers(message),
        "ifscCodes": find_ifsc_codes(message),
        "phishingLinks": find_urls(message),
        "suspiciousKeywords": find_scam_keywords(message)
    }


def extract_from_conversation(conversation_history: list) -> Dict[str, List[str]]:
    """
    Extracts intelligence from entire conversation history
    
    Args:
        conversation_history: List of message dicts with 'sender' and 'text'
            Example: [
                {"sender": "scammer", "text": "Your account is blocked"},
                {"sender": "user", "text": "What should I do?"}
            ]
    
    Returns:
        Aggregated intelligence dict (same format as extract_intelligence)
        Deduplicates across all messages
    
    Example:
        >>> history = [
        ...     {"sender": "scammer", "text": "Send to fraud@paytm"},
        ...     {"sender": "scammer", "text": "Or call 9876543210"}
        ... ]
        >>> extract_from_conversation(history)
        {
            "upiIds": ["fraud@paytm"],
            "phoneNumbers": ["9876543210"],
            ...
        }
    """
    if not conversation_history:
        return _empty_intelligence()
    
    # Aggregate all intelligence
    aggregated = _empty_intelligence()
    
    for message in conversation_history:
        # Only extract from scammer messages
        sender = message.get("sender", "")
        text = message.get("text", "")
        
        if sender == "scammer" and text:
            intel = extract_intelligence(text)
            
            # Merge into aggregated
            for key in aggregated:
                aggregated[key].extend(intel[key])
    
    # Deduplicate all lists
    for key in aggregated:
        aggregated[key] = list(set(aggregated[key]))
    
    return aggregated


def merge_intelligence(intel1: Dict[str, List[str]], intel2: Dict[str, List[str]]) -> Dict[str, List[str]]:
    """
    Merges two intelligence dictionaries
    
    Args:
        intel1: First intelligence dict
        intel2: Second intelligence dict
    
    Returns:
        Merged and deduplicated intelligence dict
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
    
    Args:
        intelligence: Intelligence dict
    
    Returns:
        Total count of all items
    
    Example:
        >>> intel = {"upiIds": ["a@b"], "phoneNumbers": ["123", "456"], ...}
        >>> count_intelligence_items(intel)
        3
    """
    if not intelligence:
        return 0
    
    # Only count high-value items (not keywords)
    high_value_keys = ["upiIds", "bankAccounts", "phoneNumbers", "ifscCodes", "phishingLinks"]
    
    total = 0
    for key in high_value_keys:
        total += len(intelligence.get(key, []))
    
    return total


def has_sufficient_intelligence(intelligence: Dict[str, List[str]], threshold: int = 2) -> bool:
    """
    Checks if enough intelligence has been gathered
    
    Args:
        intelligence: Intelligence dict
        threshold: Minimum items required (default: 2)
    
    Returns:
        True if sufficient intelligence gathered
    """
    return count_intelligence_items(intelligence) >= threshold


def format_intelligence_summary(intelligence: Dict[str, List[str]]) -> str:
    """
    Creates human-readable summary of extracted intelligence
    
    Args:
        intelligence: Intelligence dict
    
    Returns:
        Formatted string summary
    
    Example:
        >>> intel = {"upiIds": ["fraud@paytm"], "phoneNumbers": ["9876543210"], ...}
        >>> format_intelligence_summary(intel)
        "UPI IDs: fraud@paytm | Phone Numbers: 9876543210"
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
    
    if not parts:
        return "No actionable intelligence extracted"
    
    return " | ".join(parts)


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
        "suspiciousKeywords": []
    }