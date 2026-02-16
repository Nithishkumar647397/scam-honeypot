"""
Intelligence extraction module for capturing scammer financial identifiers.

Extracts UPI IDs, bank accounts, phone numbers, IFSC codes, URLs, emails,
and scammer IDs from messages. Handles obfuscated input through normalization
(number words, spaced digits, etc.) and merges intel across conversation turns.

Owner: Member A
"""

from typing import Dict, List
import re
import logging
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

# English number words to digits
NUMBER_WORDS = {
    'zero': '0', 'one': '1', 'two': '2', 'three': '3',
    'four': '4', 'five': '5', 'six': '6', 'seven': '7',
    'eight': '8', 'nine': '9', 'ten': '10'
}

# Hindi number words to digits
HINDI_NUMBER_WORDS = {
    'sunya': '0', 'ek': '1', 'do': '2', 'teen': '3',
    'char': '4', 'paanch': '5', 'chhah': '6', 'saat': '7',
    'aath': '8', 'nau': '9', 'das': '10'
}


def normalize_text(text: str) -> str:
    """Normalize obfuscated text for better extraction.

    Handles:
        - English number words: "nine eight seven" -> "987"
        - Hindi number words: "nau aath saat" -> "987"
        - "at"/"AT" -> "@" for UPI/email obfuscation
        - Spaced digits: "9 8 7 6" -> "9876"
        - Dot-separated digits: "9.8.7.6" -> "9876"

    Args:
        text: Raw message text

    Returns:
        Normalized text suitable for pattern extraction
    """
    if not text:
        return ""

    normalized = text.lower()

    # Replace English number words
    for word, digit in NUMBER_WORDS.items():
        normalized = normalized.replace(word, digit)

    # Replace Hindi number words
    for word, digit in HINDI_NUMBER_WORDS.items():
        # Use word boundary matching to avoid partial replacements
        normalized = re.sub(r'\b' + re.escape(word) + r'\b', digit, normalized)

    # "at" to "@" (for emails/UPIs)
    normalized = normalized.replace(' at ', '@')
    normalized = normalized.replace(' AT ', '@')

    # Remove spaces between digits (9 8 7 6 -> 9876)
    normalized = re.sub(r'(\d)\s+(?=\d)', r'\1', normalized)

    # Remove dots between single digits (9.8.7.6 -> 9876) but not decimals
    normalized = re.sub(r'(\d)\.(?=\d(?:\D|$))', r'\1', normalized)

    return normalized


def extract_intelligence(message: str) -> Dict[str, List[str]]:
    """Extract scam intelligence from a single message.

    Runs extraction on both the original text and a normalized version
    (to catch obfuscated numbers, UPIs, etc.) and merges results.

    Args:
        message: Raw message text from scammer

    Returns:
        Dict with lists of extracted identifiers by category
    """
    if not message:
        return _empty_intelligence()

    # Extract from original text
    try:
        original_intel = _extract_from_text(message)
    except Exception as e:
        logger.error(f"Extraction failed on original text: {e}")
        original_intel = _empty_intelligence()

    # Also extract from normalized text (for obfuscated data)
    try:
        normalized = normalize_text(message)
        if normalized != message.lower():
            normalized_intel = _extract_from_text(normalized)
            original_intel = merge_intelligence(original_intel, normalized_intel)
    except Exception as e:
        logger.error(f"Extraction failed on normalized text: {e}")

    return original_intel


def _extract_from_text(text: str) -> Dict[str, List[str]]:
    """Core extraction logic - run all pattern extractors on text.

    Each extractor is called independently so a failure in one
    doesn't prevent extraction by others.
    """
    result = _empty_intelligence()

    extractors = {
        "upiIds": find_upi_ids,
        "bankAccounts": find_bank_accounts,
        "phoneNumbers": find_phone_numbers,
        "ifscCodes": find_ifsc_codes,
        "phishingLinks": find_urls,
        "suspiciousKeywords": find_scam_keywords,
        "emails": find_emails,
        "scammerIds": find_scammer_ids,
    }

    for key, extractor in extractors.items():
        try:
            result[key] = extractor(text)
        except Exception as e:
            logger.warning(f"Extractor '{key}' failed: {e}")
            result[key] = []

    return result


def extract_from_conversation(conversation_history: list) -> Dict[str, List[str]]:
    """Extract intelligence from the entire conversation history.

    Only processes scammer messages (not agent replies) and merges
    all extracted intel into a single deduplicated result.

    Args:
        conversation_history: List of message dicts with 'sender' and 'text' keys

    Returns:
        Aggregated intelligence dict
    """
    if not conversation_history:
        return _empty_intelligence()

    aggregated = _empty_intelligence()

    for idx, message in enumerate(conversation_history):
        sender = message.get("sender", "")
        text = message.get("text", "")

        if sender == "scammer" and text:
            try:
                intel = extract_intelligence(text)
                aggregated = merge_intelligence(aggregated, intel)
            except Exception as e:
                logger.warning(f"Extraction failed for message {idx}: {e}")

    return aggregated


def merge_intelligence(intel1: Dict[str, List[str]], intel2: Dict[str, List[str]]) -> Dict[str, List[str]]:
    """Merge two intelligence dictionaries, deduplicating entries.

    Args:
        intel1: First intelligence dict
        intel2: Second intelligence dict

    Returns:
        Merged dict with deduplicated lists for each category
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
    """Count total high-value extracted intelligence items.

    Counts UPIs, bank accounts, phones, IFSC codes, links, emails,
    and scammer IDs. Excludes keywords from the count.
    """
    if not intelligence:
        return 0

    high_value_keys = ["upiIds", "bankAccounts", "phoneNumbers", "ifscCodes", "phishingLinks", "emails", "scammerIds"]

    total = 0
    for key in high_value_keys:
        total += len(intelligence.get(key, []))

    return total


def has_sufficient_intelligence(intelligence: Dict[str, List[str]], threshold: int = 2) -> bool:
    """Check if enough high-value intelligence items have been gathered.

    Args:
        intelligence: Extracted intelligence dict
        threshold: Minimum number of items required (default: 2)
    """
    return count_intelligence_items(intelligence) >= threshold


def format_intelligence_summary(intelligence: Dict[str, List[str]]) -> str:
    """Create a human-readable summary of all extracted intelligence.

    Returns a pipe-separated string of all categories with extracted items.
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

    if intelligence.get("scammerIds"):
        parts.append(f"Scammer IDs: {', '.join(intelligence['scammerIds'])}")

    return " | ".join(parts) if parts else "No actionable intelligence extracted"


def get_emails_for_notes(intelligence: Dict[str, List[str]]) -> List[str]:
    """Extract email addresses from intelligence for inclusion in agent notes."""
    return intelligence.get("emails", [])


def _empty_intelligence() -> Dict[str, List[str]]:
    """Return a fresh empty intelligence structure with all expected keys."""
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
