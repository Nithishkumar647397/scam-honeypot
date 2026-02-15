"""
Regex patterns for Indian financial data extraction
Owner: Member A
"""

import re
import logging
from typing import List, Set

logger = logging.getLogger(__name__)

MAX_TEXT_LENGTH = 50000

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
    'rblbank', 'sib', 'srcb', 'tmb', 'ubi', 'uboi', 'uco', 'vijb', 'yapl',
    'fakebank'
}

EMAIL_DOMAINS: Set[str] = {
    'gmail', 'yahoo', 'hotmail', 'outlook', 'email', 'mail',
    'proton', 'protonmail', 'icloud', 'aol', 'rediff', 'live',
    'zoho', 'yandex', 'inbox', 'fastmail', 'tutanota', 'gmx',
    'mail', 'mailinator', 'tempmail', 'guerrillamail'
}

FALSE_POSITIVE_UPI_PREFIXES = {
    'is', 'at', 'or', 'and', 'to', 'from', 'by', 'with', 'for', 'in', 'on', 'my', 'your'
}

SHORTENED_DOMAINS: List[str] = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'short.link',
    'cutt.ly', 'rebrand.ly', 'is.gd', 'v.gd', 'shorturl.at',
    'tiny.cc', 'bc.vc', 'ow.ly', 'buff.ly'
]

UPI_PATTERN = r'[a-zA-Z0-9._-]+@[a-zA-Z]{2,}'
BANK_ACCOUNT_PATTERN = r'\b[1-9]\d{8,17}\b'
PHONE_PATTERN = r'\b[6-9]\d{9}\b'
IFSC_PATTERN = r'\b[A-Z]{4}0[A-Z0-9]{6}\b'
URL_PATTERN = r'https?://[^\s<>"{}|\\^`\[\]]+(?<![.,;:!?\)\]])'
SHORTENED_URL_PATTERN = r'\b(?:' + '|'.join(re.escape(d) for d in SHORTENED_DOMAINS) + r')/[a-zA-Z0-9]+'
EMAIL_PATTERN = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'

SCAM_KEYWORDS: List[str] = [
    "urgent", "immediately", "now", "today", "expire", "hurry",
    "last chance", "final notice", "act now", "don't delay",
    "blocked", "suspended", "terminated", "deactivated", "frozen",
    "illegal", "fraud detected", "unauthorized", "security alert",
    "bank manager", "rbi", "reserve bank", "police", "cyber cell",
    "income tax", "government", "official", "verified",
    "verify", "confirm", "update", "link aadhaar", "kyc",
    "transfer", "send money", "pay now", "refund", "cashback",
    "winner", "congratulations", "prize", "lottery", "lucky",
    "selected", "reward", "gift", "free", "bonus",
    "click here", "click link", "otp", "pin", "cvv", "password",
    "card number", "account number", "share details"
]

HINGLISH_KEYWORDS: List[str] = [
    "turant", "abhi", "jaldi", "bank khata", "paisa bhejo",
    "verify karo", "block ho jayega", "aapka account",
    "otp batao", "pin batao", "jaldi karo", "paise do",
    "band ho jayega", "foren", "fatafat"
]

def _prepare_text(text: str) -> str:
    if not text: return ""
    return text[:MAX_TEXT_LENGTH]

def find_upi_ids(text: str) -> List[str]:
    text = _prepare_text(text)
    if not text: return []
    matches = re.findall(UPI_PATTERN, text, re.IGNORECASE)
    filtered = []
    for match in matches:
        parts = match.split('@')
        if len(parts) != 2: continue
        prefix = parts[0].lower()
        domain = parts[1].lower()
        if prefix in FALSE_POSITIVE_UPI_PREFIXES: continue
        is_valid_domain = False
        if domain in UPI_DOMAINS: is_valid_domain = True
        elif any(upi_dom in domain for upi_dom in UPI_DOMAINS): is_valid_domain = True
        elif 'bank' in domain and domain not in EMAIL_DOMAINS: is_valid_domain = True
        if is_valid_domain: filtered.append(match.lower())
    return list(set(filtered))

def find_bank_accounts(text: str) -> List[str]:
    text = _prepare_text(text)
    if not text: return []
    matches = re.findall(BANK_ACCOUNT_PATTERN, text)
    filtered = []
    for match in matches:
        if len(match) == 10 and match[0] in '6789': continue
        if len(match) == 13 and match.startswith('1') and not match.startswith('1234'): continue
        if len(match) == 8: continue
        filtered.append(match)
    return list(set(filtered))

def find_phone_numbers(text: str) -> List[str]:
    text = _prepare_text(text)
    if not text: return []
    return list(set(re.findall(PHONE_PATTERN, text)))

def find_ifsc_codes(text: str) -> List[str]:
    text = _prepare_text(text)
    if not text: return []
    return list(set(m.upper() for m in re.findall(IFSC_PATTERN, text, re.IGNORECASE)))

def find_urls(text: str) -> List[str]:
    text = _prepare_text(text)
    if not text: return []
    all_urls = []
    matches = re.findall(URL_PATTERN, text, re.IGNORECASE)
    all_urls.extend(matches)
    shortened = re.findall(SHORTENED_URL_PATTERN, text, re.IGNORECASE)
    for s in shortened:
        if not s.startswith('http'): all_urls.append('https://' + s)
        else: all_urls.append(s)
    cleaned = []
    for url in all_urls:
        url = url.rstrip('.,;:!?)]>\'\"')
        if url: cleaned.append(url)
    return list(set(cleaned))

def find_emails(text: str) -> List[str]:
    text = _prepare_text(text)
    if not text: return []
    matches = re.findall(EMAIL_PATTERN, text, re.IGNORECASE)
    filtered = []
    for email in matches:
        parts = email.split('@')
        if len(parts) != 2: continue
        domain = parts[1].lower().split('.')[0]
        if domain in UPI_DOMAINS: continue
        if any(upi_dom in domain for upi_dom in UPI_DOMAINS): continue
        filtered.append(email.lower())
    return list(set(filtered))

def find_scam_keywords(text: str) -> List[str]:
    text = _prepare_text(text)
    if not text: return []
    text_lower = text.lower()
    found = set()
    for k in SCAM_KEYWORDS + HINGLISH_KEYWORDS:
        if k.lower() in text_lower: found.add(k.lower())
    return list(found)
