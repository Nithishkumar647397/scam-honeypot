"""
Tests for the intelligence extraction module (src/extractor.py).

Covers: extract_intelligence, extract_from_conversation, merge_intelligence,
normalize_text, count_intelligence_items, has_sufficient_intelligence,
format_intelligence_summary.
"""

import pytest
from src.extractor import (
    extract_intelligence,
    extract_from_conversation,
    merge_intelligence,
    normalize_text,
    count_intelligence_items,
    has_sufficient_intelligence,
    format_intelligence_summary,
    get_emails_for_notes,
    _empty_intelligence,
)


# ─── normalize_text ──────────────────────────────────────────────────

class TestNormalizeText:

    def test_english_number_words(self):
        result = normalize_text("nine eight seven six five")
        assert "98765" in result

    def test_hindi_number_words(self):
        result = normalize_text("nau aath saat chhah paanch")
        assert "98765" in result

    def test_at_to_symbol(self):
        result = normalize_text("fraud at paytm")
        assert "fraud@paytm" in result

    def test_spaced_digits(self):
        result = normalize_text("9 8 7 6 5 4 3 2 1 0")
        assert "9876543210" in result

    def test_empty_string(self):
        assert normalize_text("") == ""

    def test_no_change_needed(self):
        assert normalize_text("hello world") == "hello world"


# ─── extract_intelligence ────────────────────────────────────────────

class TestExtractIntelligence:

    def test_extract_upi(self):
        intel = extract_intelligence("Send to fraud@paytm")
        assert "fraud@paytm" in intel["upiIds"]

    def test_extract_phone(self):
        intel = extract_intelligence("Call 9876543210")
        assert "9876543210" in intel["phoneNumbers"]

    def test_extract_ifsc(self):
        intel = extract_intelligence("IFSC: SBIN0001234")
        assert "SBIN0001234" in intel["ifscCodes"]

    def test_extract_bank_account(self):
        intel = extract_intelligence("Account: 123456789012")
        assert "123456789012" in intel["bankAccounts"]

    def test_extract_url(self):
        intel = extract_intelligence("Click https://fake-site.com/verify")
        assert any("fake-site.com" in u for u in intel["phishingLinks"])

    def test_extract_multiple_types(self):
        intel = extract_intelligence(
            "Send Rs 500 to fraud@paytm or call 9876543210. IFSC: SBIN0001234"
        )
        assert len(intel["upiIds"]) >= 1
        assert len(intel["phoneNumbers"]) >= 1
        assert len(intel["ifscCodes"]) >= 1

    def test_empty_message(self):
        intel = extract_intelligence("")
        assert intel == _empty_intelligence()

    def test_obfuscated_number_extraction(self):
        intel = extract_intelligence("Number is nine eight seven six five four three two one zero")
        assert len(intel["phoneNumbers"]) >= 1

    def test_extract_email(self):
        intel = extract_intelligence("Contact me at scammer@gmail.com for details")
        assert "scammer@gmail.com" in intel["emails"]

    def test_extract_scammer_id(self):
        intel = extract_intelligence("My Employee ID: EMP12345")
        assert "EMP12345" in intel["scammerIds"]


# ─── extract_from_conversation ───────────────────────────────────────

class TestExtractFromConversation:

    def test_aggregates_across_messages(self):
        history = [
            {"sender": "scammer", "text": "Send to fraud@paytm"},
            {"sender": "user", "text": "Okay, what next?"},
            {"sender": "scammer", "text": "Also send to 9876543210@ybl"},
            {"sender": "scammer", "text": "Account: 123456789012"},
        ]
        intel = extract_from_conversation(history)
        assert "fraud@paytm" in intel["upiIds"]
        assert "9876543210@ybl" in intel["upiIds"]
        assert "123456789012" in intel["bankAccounts"]

    def test_only_extracts_from_scammer(self):
        history = [
            {"sender": "user", "text": "My UPI is user@paytm"},
            {"sender": "scammer", "text": "Send to scammer@ybl"},
        ]
        intel = extract_from_conversation(history)
        assert "scammer@ybl" in intel["upiIds"]
        assert "user@paytm" not in intel["upiIds"]

    def test_empty_history(self):
        assert extract_from_conversation([]) == _empty_intelligence()

    def test_deduplicates_results(self):
        history = [
            {"sender": "scammer", "text": "Send to fraud@paytm"},
            {"sender": "scammer", "text": "Again, send to fraud@paytm"},
        ]
        intel = extract_from_conversation(history)
        assert intel["upiIds"].count("fraud@paytm") == 1


# ─── merge_intelligence ──────────────────────────────────────────────

class TestMergeIntelligence:

    def test_merge_combines_lists(self):
        intel1 = {"upiIds": ["a@paytm"], "bankAccounts": [], "phoneNumbers": [],
                  "ifscCodes": [], "phishingLinks": [], "suspiciousKeywords": [],
                  "emails": [], "scammerIds": []}
        intel2 = {"upiIds": ["b@ybl"], "bankAccounts": ["123456789012"],
                  "phoneNumbers": [], "ifscCodes": [], "phishingLinks": [],
                  "suspiciousKeywords": [], "emails": [], "scammerIds": []}
        merged = merge_intelligence(intel1, intel2)
        assert "a@paytm" in merged["upiIds"]
        assert "b@ybl" in merged["upiIds"]
        assert "123456789012" in merged["bankAccounts"]

    def test_merge_deduplicates(self):
        intel1 = {"upiIds": ["a@paytm"], "bankAccounts": [], "phoneNumbers": [],
                  "ifscCodes": [], "phishingLinks": [], "suspiciousKeywords": [],
                  "emails": [], "scammerIds": []}
        intel2 = {"upiIds": ["a@paytm"], "bankAccounts": [], "phoneNumbers": [],
                  "ifscCodes": [], "phishingLinks": [], "suspiciousKeywords": [],
                  "emails": [], "scammerIds": []}
        merged = merge_intelligence(intel1, intel2)
        assert len(merged["upiIds"]) == 1

    def test_merge_with_empty(self):
        intel = {"upiIds": ["a@paytm"], "bankAccounts": [], "phoneNumbers": [],
                 "ifscCodes": [], "phishingLinks": [], "suspiciousKeywords": [],
                 "emails": [], "scammerIds": []}
        assert merge_intelligence(intel, None) == intel
        assert merge_intelligence(None, intel) == intel


# ─── count_intelligence_items ────────────────────────────────────────

class TestCountIntelligence:

    def test_counts_high_value_items(self):
        intel = {"upiIds": ["a@paytm"], "bankAccounts": ["123"], "phoneNumbers": ["9876543210"],
                 "ifscCodes": [], "phishingLinks": [], "suspiciousKeywords": ["urgent", "blocked"],
                 "emails": [], "scammerIds": []}
        assert count_intelligence_items(intel) == 3  # keywords not counted

    def test_empty_intel(self):
        assert count_intelligence_items(_empty_intelligence()) == 0

    def test_none_input(self):
        assert count_intelligence_items(None) == 0


# ─── has_sufficient_intelligence ─────────────────────────────────────

class TestHasSufficientIntelligence:

    def test_above_threshold(self):
        intel = {"upiIds": ["a@paytm", "b@ybl"], "bankAccounts": [], "phoneNumbers": [],
                 "ifscCodes": [], "phishingLinks": [], "suspiciousKeywords": [],
                 "emails": [], "scammerIds": []}
        assert has_sufficient_intelligence(intel, threshold=2) is True

    def test_below_threshold(self):
        intel = {"upiIds": ["a@paytm"], "bankAccounts": [], "phoneNumbers": [],
                 "ifscCodes": [], "phishingLinks": [], "suspiciousKeywords": [],
                 "emails": [], "scammerIds": []}
        assert has_sufficient_intelligence(intel, threshold=2) is False


# ─── format_intelligence_summary ─────────────────────────────────────

class TestFormatSummary:

    def test_formats_all_categories(self):
        intel = {"upiIds": ["fraud@paytm"], "bankAccounts": ["123456789012"],
                 "phoneNumbers": ["9876543210"], "ifscCodes": ["SBIN0001234"],
                 "phishingLinks": ["https://fake.com"], "suspiciousKeywords": [],
                 "emails": ["scam@gmail.com"], "scammerIds": ["EMP123"]}
        summary = format_intelligence_summary(intel)
        assert "UPI IDs" in summary
        assert "Bank Accounts" in summary
        assert "Phone Numbers" in summary
        assert "IFSC Codes" in summary
        assert "Emails" in summary
        assert "Scammer IDs" in summary

    def test_empty_intel(self):
        summary = format_intelligence_summary(_empty_intelligence())
        assert "No actionable" in summary

    def test_none_intel(self):
        assert "No intelligence" in format_intelligence_summary(None)


# ─── get_emails_for_notes ────────────────────────────────────────────

class TestGetEmails:

    def test_returns_emails(self):
        intel = {"emails": ["a@gmail.com", "b@yahoo.com"]}
        assert get_emails_for_notes(intel) == ["a@gmail.com", "b@yahoo.com"]

    def test_no_emails(self):
        assert get_emails_for_notes({"emails": []}) == []
        assert get_emails_for_notes({}) == []
