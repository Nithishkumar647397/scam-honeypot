"""
Regex patterns for Indian financial data extraction
Owner: Member A
"""

import re
from typing import List


# ============== REGEX PATTERNS ==============

# UPI ID: name@bank or mobile@bank
# Examples: ramesh@oksbi, 9876543210@paytm, fraud@ybl
UPI_PATTERN = r'[a-zA-Z0-9._-]+@[a-zA-Z]{3,}'

# Bank Account: 9-18 digits
# Examples: 123456789012, 50100123456789
BANK_ACCOUNT_PATTERN = r'\b\d{9,18}\b'

# Indian Phone: 10 digits starting with 6-9
# Examples: 9876543210, 8765432109
PHONE_PATTERN = r'\b[6-9]\d{9}\b'

# IFSC Code: 4 letters + 0 + 6 alphanumeric
# Examples: SBIN0001234, HDFC0009999
IFSC_PATTERN = r'\b[A-Z]{4}0[A-Z0-9]{6}\b'

# URLs: http or https links
# Examples: https://fake-bank.com, http://bit.ly/scam
URL_PATTERN = r'https?://[^\s<>"{}|\\^`\[\]]+'

# Shortened URL domains (suspicious)
SHORTENED_URL_PATTERN = r'\b(?:bit\.ly|tinyurl\.com|goo\.gl|t\.co|short\.link)/[a-zA-Z0-9]+'


# ============== SCAM KEYWORDS ==============

SCAM_KEYWORDS = [
    # Urgency
    "urgent", "immediately", "now", "today", "expire", "hurry",
    "last chance", "final notice", "act now", "don't delay",
    
    # Threats
    "blocked", "suspended", "terminated", "deactivated", "frozen",
    "illegal", "fraud detected", "unauthorized", "security alert",
    
    # Authority
    "bank manager", "rbi", "reserve bank", "police", "cyber cell",
    "income tax", "government", "official", "verified",
    
    # Money/Payment
    "verify", "confirm", "update", "link aadhaar", "kyc",
    "transfer", "send money", "pay now", "refund", "cashback",
    
    # Prizes/Offers
    "winner", "congratulations", "prize", "lottery", "lucky",
    "selected", "reward", "gift", "free", "bonus",
    
    # Requests
    "click here", "click link", "otp", "pin", "cvv", "password",
    "card number", "account number", "share details"
]

# Hindi/Hinglish scam keywords
HINGLISH_KEYWORDS = [
    "turant", "abhi", "jaldi", "bank khata", "paisa bhejo",
    "verify karo", "block ho jayega", "aapka account"
]


# ============== EXTRACTION FUNCTIONS ==============

def find_upi_ids(text: str) -> List[str]:
    """
    Extract UPI IDs from text
    
    Args:
        text: Input text to search
    
    Returns:
        List of unique UPI IDs found
    
    Example:
        >>> find_upi_ids("Pay to fraud@paytm or scam@ybl")
        ['fraud@paytm', 'scam@ybl']
    """
    if not text:
        return []
    
    matches = re.findall(UPI_PATTERN, text, re.IGNORECASE)
    
    # Filter out email-like patterns (containing common email domains)
    email_domains = ['gmail', 'yahoo', 'hotmail', 'outlook', 'email']
    filtered = []
    
    for match in matches:
        domain = match.split('@')[1].lower()
        if not any(email_dom in domain for email_dom in email_domains):
            filtered.append(match.lower())
    
    # Return unique values
    return list(set(filtered))


def find_bank_accounts(text: str) -> List[str]:
    """
    Extract bank account numbers from text
    
    Args:
        text: Input text to search
    
    Returns:
        List of unique bank account numbers found
    
    Example:
        >>> find_bank_accounts("Transfer to 123456789012")
        ['123456789012']
    """
    if not text:
        return []
    
    matches = re.findall(BANK_ACCOUNT_PATTERN, text)
    
    # Filter out phone numbers (10 digits starting with 6-9)
    filtered = []
    for match in matches:
        # Skip if it's likely a phone number
        if len(match) == 10 and match[0] in '6789':
            continue
        # Skip if it's likely a timestamp (13 digits)
        if len(match) == 13:
            continue
        filtered.append(match)
    
    return list(set(filtered))


def find_phone_numbers(text: str) -> List[str]:
    """
    Extract Indian phone numbers from text
    
    Args:
        text: Input text to search
    
    Returns:
        List of unique phone numbers found
    
    Example:
        >>> find_phone_numbers("Call 9876543210 now")
        ['9876543210']
    """
    if not text:
        return []
    
    matches = re.findall(PHONE_PATTERN, text)
    return list(set(matches))


def find_ifsc_codes(text: str) -> List[str]:
    """
    Extract IFSC codes from text
    
    Args:
        text: Input text to search
    
    Returns:
        List of unique IFSC codes found
    
    Example:
        >>> find_ifsc_codes("IFSC: SBIN0001234")
        ['SBIN0001234']
    """
    if not text:
        return []
    
    matches = re.findall(IFSC_PATTERN, text, re.IGNORECASE)
    # Uppercase for consistency
    return list(set([m.upper() for m in matches]))


def find_urls(text: str) -> List[str]:
    """
    Extract URLs from text
    
    Args:
        text: Input text to search
    
    Returns:
        List of unique URLs found
    
    Example:
        >>> find_urls("Click https://fake-bank.com now")
        ['https://fake-bank.com']
    """
    if not text:
        return []
    
    # Find regular URLs
    matches = re.findall(URL_PATTERN, text, re.IGNORECASE)
    
    # Also find shortened URLs without http
    shortened = re.findall(SHORTENED_URL_PATTERN, text, re.IGNORECASE)
    
    # Combine and deduplicate
    all_urls = matches + ['https://' + s if not s.startswith('http') else s for s in shortened]
    
    return list(set(all_urls))


def find_scam_keywords(text: str) -> List[str]:
    """
    Find scam-related keywords in text
    
    Args:
        text: Input text to search
    
    Returns:
        List of scam keywords found
    
    Example:
        >>> find_scam_keywords("URGENT! Your account is blocked!")
        ['urgent', 'blocked']
    """
    if not text:
        return []
    
    text_lower = text.lower()
    found = []
    
    # Check English keywords
    for keyword in SCAM_KEYWORDS:
        if keyword.lower() in text_lower:
            found.append(keyword.lower())
    
    # Check Hinglish keywords
    for keyword in HINGLISH_KEYWORDS:
        if keyword.lower() in text_lower:
            found.append(keyword.lower())
    
    return list(set(found))

# Email pattern
EMAIL_PATTERN = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'

def find_emails(text: str) -> List[str]:
    """
    Extract email addresses from text
    
    Args:
        text: Input text to search
    
    Returns:
        List of unique emails found
    
    Example:
        >>> find_emails("Contact scammer@gmail.com for details")
        ['scammer@gmail.com']
    """
    if not text:
        return []
    
    matches = re.findall(EMAIL_PATTERN, text, re.IGNORECASE)
    
    # Filter out UPI IDs (they look like emails but use bank domains)
    upi_domains = ['paytm', 'ybl', 'oksbi', 'okaxis', 'okhdfcbank', 'okicici', 'upi', 'gpay', 'phonepe']
    
    filtered = []
    for email in matches:
        domain = email.split('@')[1].lower().split('.')[0]
        if domain not in upi_domains:
            filtered.append(email.lower())
    
    return list(set(filtered))
