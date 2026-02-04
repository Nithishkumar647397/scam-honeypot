"""
Regex patterns for Indian financial data extraction
Owner: Member A

Improvements:
- Specific UPI domain matching
- Input length validation
- Logging
- Consolidated constants
- Consistent output formatting
"""

import re
import logging
from typing import List, Set

logger = logging.getLogger(__name__)


# ============== CONSTANTS ==============

MAX_TEXT_LENGTH = 50000

# Known UPI handle domains
UPI_DOMAINS: Set[str] = {
    'paytm', 'ybl', 'oksbi', 'okaxis', 'okhdfcbank', 'okicici',
    'upi', 'gpay', 'phonepe', 'apl', 'rapl', 'ibl', 'sbi',
    'axisbank', 'hdfcbank', 'icici', 'kotak', 'indus', 'yesbank',
    'rbl', 'federal', 'boi', 'pnb', 'canara', 'unionbank',
    'idfcbank', 'aubank', 'jupiteraxis', 'freecharge', 'amazonpay',
    'airtel', 'jio', 'postbank', 'dbs', 'hsbc', 'citi', 'sc',
    'abfspay', 'axl', 'barodampay', 'centralbank', 'cub', 'dlb',
    'equitas', 'ezeepay', 'fbl', 'finobank', 'idfcfirst', 'ikwik',
    'imobile', 'iob', 'jkb', 'karb', 'kaypay', 'kbl', 'kvb',
    'lvb', 'mahb', 'obc', 'okbizaxis', 'payzapp', 'psb', 'rajgovhdfcbank',
    'rblbank', 'sib', 'srcb', 'tmb', 'ubi', 'uboi', 'uco', 'vijb', 'yapl'
}

# Email domains (to filter out from UPI)
EMAIL_DOMAINS: Set[str] = {
    'gmail', 'yahoo', 'hotmail', 'outlook', 'email', 'mail',
    'proton', 'protonmail', 'icloud', 'aol', 'rediff', 'live',
    'zoho', 'yandex', 'inbox', 'fastmail', 'tutanota', 'gmx',
    'mail', 'mailinator', 'tempmail', 'guerrillamail'
}

# Shortened URL domains
SHORTENED_DOMAINS: List[str] = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'short.link',
    'cutt.ly', 'rebrand.ly', 'is.gd', 'v.gd', 'shorturl.at',
    'tiny.cc', 'bc.vc', 'ow.ly', 'buff.ly'
]


# ============== REGEX PATTERNS ==============

# UPI ID: name@bank
UPI_PATTERN = r'[a-zA-Z0-9._-]+@[a-zA-Z]{2,}'

# Bank Account: 9-18 digits (not starting with 0)
BANK_ACCOUNT_PATTERN = r'\b[1-9]\d{8,17}\b'

# Indian Phone: 10 digits starting with 6-9
PHONE_PATTERN = r'\b[6-9]\d{9}\b'

# IFSC Code: 4 letters + 0 + 6 alphanumeric
IFSC_PATTERN = r'\b[A-Z]{4}0[A-Z0-9]{6}\b'

# URLs (improved to handle trailing punctuation)
URL_PATTERN = r'https?://[^\s<>"{}|\\^`\[\]]+(?<![.,;:!?\)\]])'

# Shortened URLs pattern
SHORTENED_URL_PATTERN = r'\b(?:' + '|'.join(re.escape(d) for d in SHORTENED_DOMAINS) + r')/[a-zA-Z0-9]+'

# Email
EMAIL_PATTERN = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'


# ============== SCAM KEYWORDS ==============

SCAM_KEYWORDS: List[str] = [
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

HINGLISH_KEYWORDS: List[str] = [
    "turant", "abhi", "jaldi", "bank khata", "paisa bhejo",
    "verify karo", "block ho jayega", "aapka account",
    "otp batao", "pin batao", "jaldi karo", "paise do",
    "band ho jayega", "foren", "fatafat"
]


# ============== HELPER ==============

def _prepare_text(text: str) -> str:
    """Validate and prepare text for processing"""
    if not text:
        return ""
    if len(text) > MAX_TEXT_LENGTH:
        logger.debug(f"Text truncated from {len(text)} to {MAX_TEXT_LENGTH}")
        return text[:MAX_TEXT_LENGTH]
    return text


# ============== EXTRACTION FUNCTIONS ==============

def find_upi_ids(text: str) -> List[str]:
    """
    Extract UPI IDs from text
    
    Returns:
        List of unique UPI IDs (lowercased)
    
    Example:
        >>> find_upi_ids("Pay to fraud@paytm or scam@ybl")
        ['fraud@paytm', 'scam@ybl']
    """
    text = _prepare_text(text)
    if not text:
        return []
    
    matches = re.findall(UPI_PATTERN, text, re.IGNORECASE)
    
    filtered = []
    for match in matches:
        parts = match.split('@')
        if len(parts) != 2:
            continue
        
        domain = parts[1].lower()
        
        # Check if it's a known UPI domain
        if domain in UPI_DOMAINS:
            filtered.append(match.lower())
        # Check if domain contains a known UPI suffix
        elif any(upi_dom in domain for upi_dom in UPI_DOMAINS):
            filtered.append(match.lower())
        # Check if it's NOT an email domain (could be new UPI provider)
        elif domain not in EMAIL_DOMAINS and not any(email_dom in domain for email_dom in EMAIL_DOMAINS):
            # Only include if it doesn't look like an email (no .com, .in, etc at end)
            if not re.search(r'\.(com|in|org|net|co|io)$', domain):
                filtered.append(match.lower())
    
    return list(set(filtered))


def find_bank_accounts(text: str) -> List[str]:
    """
    Extract bank account numbers from text
    
    Returns:
        List of unique account numbers
    
    Example:
        >>> find_bank_accounts("Transfer to 50100123456789")
        ['50100123456789']
    """
    text = _prepare_text(text)
    if not text:
        return []
    
    matches = re.findall(BANK_ACCOUNT_PATTERN, text)
    
    filtered = []
    for match in matches:
        # Skip phone numbers (10 digits starting with 6-9)
        if len(match) == 10 and match[0] in '6789':
            continue
        # Skip timestamps (13 digits starting with 1)
        if len(match) == 13 and match.startswith('1'):
            continue
        # Skip obvious dates (8 digits that could be DDMMYYYY or YYYYMMDD)
        if len(match) == 8:
            continue
        
        filtered.append(match)
    
    return list(set(filtered))


def find_phone_numbers(text: str) -> List[str]:
    """
    Extract Indian phone numbers from text
    
    Returns:
        List of unique phone numbers
    
    Example:
        >>> find_phone_numbers("Call 9876543210")
        ['9876543210']
    """
    text = _prepare_text(text)
    if not text:
        return []
    
    matches = re.findall(PHONE_PATTERN, text)
    return list(set(matches))


def find_ifsc_codes(text: str) -> List[str]:
    """
    Extract IFSC codes from text
    
    Returns:
        List of unique IFSC codes (uppercased)
    
    Example:
        >>> find_ifsc_codes("IFSC: SBIN0001234")
        ['SBIN0001234']
    """
    text = _prepare_text(text)
    if not text:
        return []
    
    matches = re.findall(IFSC_PATTERN, text, re.IGNORECASE)
    return list(set(m.upper() for m in matches))


def find_urls(text: str) -> List[str]:
    """
    Extract URLs from text
    
    Returns:
        List of unique URLs
    
    Example:
        >>> find_urls("Click https://fake-bank.com now")
        ['https://fake-bank.com']
    """
    text = _prepare_text(text)
    if not text:
        return []
    
    all_urls = []
    
    # Regular URLs
    matches = re.findall(URL_PATTERN, text, re.IGNORECASE)
    all_urls.extend(matches)
    
    # Shortened URLs
    shortened = re.findall(SHORTENED_URL_PATTERN, text, re.IGNORECASE)
    for s in shortened:
        if not s.startswith('http'):
            all_urls.append('https://' + s)
        else:
            all_urls.append(s)
    
    # Clean trailing punctuation
    cleaned = []
    for url in all_urls:
        url = url.rstrip('.,;:!?)]>\'\"')
        if url:
            cleaned.append(url)
    
    return list(set(cleaned))


def find_emails(text: str) -> List[str]:
    """
    Extract email addresses from text (excluding UPI IDs)
    
    Returns:
        List of unique emails (lowercased)
    
    Example:
        >>> find_emails("Contact scammer@gmail.com")
        ['scammer@gmail.com']
    """
    text = _prepare_text(text)
    if not text:
        return []
    
    matches = re.findall(EMAIL_PATTERN, text, re.IGNORECASE)
    
    filtered = []
    for email in matches:
        parts = email.split('@')
        if len(parts) != 2:
            continue
        
        domain = parts[1].lower()
        domain_base = domain.split('.')[0]
        
        # Exclude if it's a UPI domain
        if domain_base in UPI_DOMAINS:
            continue
        if any(upi_dom in domain_base for upi_dom in UPI_DOMAINS):
            continue
        
        filtered.append(email.lower())
    
    return list(set(filtered))


def find_scam_keywords(text: str) -> List[str]:
    """
    Find scam-related keywords in text
    
    Returns:
        List of keywords found (lowercased)
    
    Example:
        >>> find_scam_keywords("URGENT! Account blocked!")
        ['urgent', 'blocked']
    """
    text = _prepare_text(text)
    if not text:
        return []
    
    text_lower = text.lower()
    found = set()
    
    # Check English keywords
    for keyword in SCAM_KEYWORDS:
        if keyword.lower() in text_lower:
            found.add(keyword.lower())
    
    # Check Hinglish keywords
    for keyword in HINGLISH_KEYWORDS:
        if keyword.lower() in text_lower:
            found.add(keyword.lower())
    
    return list(found)
