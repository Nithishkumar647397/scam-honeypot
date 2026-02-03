"""
Regex patterns for Indian financial data
Owner: Member A
"""
import re
from typing import List

# UPI ID patterns
UPI_PATTERN = r'[a-zA-Z0-9._-]+@[a-zA-Z]{3,}'

# Bank account pattern (9-18 digits)
BANK_ACCOUNT_PATTERN = r'\b\d{9,18}\b'

# Indian phone number (10 digits starting with 6-9)
PHONE_PATTERN = r'\b[6-9]\d{9}\b'

# IFSC code pattern
IFSC_PATTERN = r'\b[A-Z]{4}0[A-Z0-9]{6}\b'

# URL pattern
URL_PATTERN = r'https?://[^\s]+'

# Scam keywords
SCAM_KEYWORDS = [
    "urgent", "verify", "blocked", "suspended", "immediately",
    "prize", "winner", "lottery", "claim", "expire",
    "otp", "cvv", "pin", "password", "account blocked"
]


def find_upi_ids(text: str) -> List[str]:
    """Returns list of UPI IDs found in text"""
    pass  # Member A implements


def find_bank_accounts(text: str) -> List[str]:
    """Returns list of bank account numbers found in text"""
    pass  # Member A implements


def find_phone_numbers(text: str) -> List[str]:
    """Returns list of phone numbers found in text"""
    pass  # Member A implements


def find_ifsc_codes(text: str) -> List[str]:
    """Returns list of IFSC codes found in text"""
    pass  # Member A implements


def find_urls(text: str) -> List[str]:
    """Returns list of URLs found in text"""
    pass  # Member A implements


def find_scam_keywords(text: str) -> List[str]:
    """Returns list of scam keywords found in text"""
    pass  # Member A implements