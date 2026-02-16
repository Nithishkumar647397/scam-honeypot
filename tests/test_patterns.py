"""
Tests for the regex pattern extraction module (src/patterns.py).

Covers: find_upi_ids, find_bank_accounts, find_phone_numbers,
find_ifsc_codes, find_urls, find_emails, find_scam_keywords, find_scammer_ids.
"""

import pytest
from src.patterns import (
    find_upi_ids,
    find_bank_accounts,
    find_phone_numbers,
    find_ifsc_codes,
    find_urls,
    find_emails,
    find_scam_keywords,
    find_scammer_ids,
)


class TestFindUpiIds:

    def test_standard_upi(self):
        assert "fraud@paytm" in find_upi_ids("Send to fraud@paytm")

    def test_ybl_domain(self):
        result = find_upi_ids("Pay 9876543210@ybl")
        assert "9876543210@ybl" in result

    def test_no_upi(self):
        assert find_upi_ids("Hello world") == []

    def test_filters_false_positives(self):
        result = find_upi_ids("Send it to@him")
        assert len(result) == 0

    def test_empty_text(self):
        assert find_upi_ids("") == []

    def test_multiple_upis(self):
        result = find_upi_ids("Send to a@paytm or b@ybl")
        assert len(result) == 2


class TestFindBankAccounts:

    def test_standard_account(self):
        result = find_bank_accounts("Account: 123456789012")
        assert "123456789012" in result

    def test_no_account(self):
        assert find_bank_accounts("Hello world") == []

    def test_excludes_phone_numbers(self):
        result = find_bank_accounts("Call 9876543210")
        assert "9876543210" not in result

    def test_empty_text(self):
        assert find_bank_accounts("") == []


class TestFindPhoneNumbers:

    def test_standard_phone(self):
        result = find_phone_numbers("Call 9876543210")
        assert "9876543210" in result

    def test_with_country_code(self):
        result = find_phone_numbers("Call +91-9876543210")
        assert any("9876543210" in p for p in result)

    def test_no_phone(self):
        assert find_phone_numbers("Hello") == []

    def test_empty_text(self):
        assert find_phone_numbers("") == []


class TestFindIfscCodes:

    def test_standard_ifsc(self):
        result = find_ifsc_codes("IFSC: SBIN0001234")
        assert "SBIN0001234" in result

    def test_hdfc_ifsc(self):
        result = find_ifsc_codes("Code is HDFC0001234")
        assert "HDFC0001234" in result

    def test_no_ifsc(self):
        assert find_ifsc_codes("Hello") == []

    def test_empty_text(self):
        assert find_ifsc_codes("") == []


class TestFindUrls:

    def test_https_url(self):
        result = find_urls("Visit https://fake-bank.com/verify")
        assert any("fake-bank.com" in u for u in result)

    def test_http_url(self):
        result = find_urls("Click http://scam.site/login")
        assert len(result) >= 1

    def test_shortened_url(self):
        result = find_urls("Click bit.ly/abc123")
        assert len(result) >= 1

    def test_no_url(self):
        assert find_urls("Hello world") == []

    def test_empty_text(self):
        assert find_urls("") == []


class TestFindEmails:

    def test_standard_email(self):
        result = find_emails("Contact scammer@gmail.com")
        assert "scammer@gmail.com" in result

    def test_excludes_upi_domains(self):
        result = find_emails("fraud@paytm")
        assert len(result) == 0

    def test_no_email(self):
        assert find_emails("Hello world") == []

    def test_empty_text(self):
        assert find_emails("") == []


class TestFindScamKeywords:

    def test_english_keywords(self):
        result = find_scam_keywords("URGENT! Verify your account immediately!")
        assert "urgent" in result
        assert "verify" in result

    def test_hinglish_keywords(self):
        result = find_scam_keywords("Jaldi karo, turant payment karo!")
        assert "jaldi" in result or "turant" in result

    def test_no_keywords(self):
        result = find_scam_keywords("Good morning, how are you?")
        assert len(result) == 0

    def test_empty_text(self):
        assert find_scam_keywords("") == []


class TestFindScammerIds:

    def test_employee_id(self):
        result = find_scammer_ids("My Employee ID: EMP12345")
        assert "EMP12345" in result

    def test_reference_number(self):
        result = find_scammer_ids("Reference: REF789012")
        assert "REF789012" in result

    def test_filters_common_words(self):
        result = find_scammer_ids("ID: CARD")
        assert "CARD" not in result

    def test_no_ids(self):
        assert find_scammer_ids("Hello") == []

    def test_empty_text(self):
        assert find_scammer_ids("") == []
