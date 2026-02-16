"""
Tests for the scam detection module (src/detector.py).

Covers: detect_scam, check_abuse, detect_playbook, detect_red_flags,
apply_context_modifiers, calculate_severity.
"""

import pytest
from src.detector import (
    detect_scam,
    check_abuse,
    detect_playbook,
    detect_red_flags,
    apply_context_modifiers,
    calculate_severity,
)


# ─── detect_scam ──────────────────────────────────────────────────────

class TestDetectScam:

    def test_obvious_scam_detected(self):
        is_scam, confidence, indicators, _ = detect_scam(
            "URGENT! Your account is blocked! Send Rs 500 to verify!"
        )
        assert is_scam is True
        assert confidence >= 0.3
        assert len(indicators) >= 2

    def test_non_scam_message(self):
        is_scam, confidence, indicators, _ = detect_scam(
            "Good morning! Hope you have a nice day."
        )
        assert is_scam is False
        assert confidence < 0.3
        assert len(indicators) == 0

    def test_hinglish_scam_detected(self):
        is_scam, confidence, indicators, _ = detect_scam(
            "Aapka khata block ho jayega! Turant verify karo!"
        )
        assert is_scam is True
        assert "threat" in indicators or "urgency" in indicators

    def test_credential_request_detected(self):
        is_scam, confidence, indicators, _ = detect_scam(
            "Please share your OTP and PIN for verification."
        )
        assert is_scam is True
        assert "credential_request" in indicators

    def test_payment_request_detected(self):
        is_scam, confidence, indicators, _ = detect_scam(
            "Send Rs 500 to this account immediately."
        )
        assert is_scam is True
        assert "payment_request" in indicators

    def test_upi_in_message_detected(self):
        is_scam, confidence, indicators, _ = detect_scam(
            "Pay to fraud@paytm for verification."
        )
        assert "contains_upi" in indicators

    def test_url_in_message_detected(self):
        is_scam, confidence, indicators, _ = detect_scam(
            "Click https://fake-bank.example.com to verify."
        )
        assert "suspicious_link" in indicators

    def test_empty_message(self):
        is_scam, confidence, indicators, modifiers = detect_scam("")
        assert is_scam is False
        assert confidence == 0.0
        assert indicators == []

    def test_history_boosts_confidence(self):
        history = [
            {"sender": "scammer", "text": "Send money now!"},
            {"sender": "scammer", "text": "Pay immediately!"},
            {"sender": "scammer", "text": "Transfer urgent!"},
        ]
        _, conf_no_hist, _, _ = detect_scam("Send Rs 500 now.")
        _, conf_with_hist, _, _ = detect_scam("Send Rs 500 now.", history)
        assert conf_with_hist >= conf_no_hist

    def test_returns_four_elements(self):
        result = detect_scam("Test message")
        assert len(result) == 4

    def test_prize_offer_detected(self):
        is_scam, _, indicators, _ = detect_scam(
            "Congratulations! You have won a prize of Rs 50000!"
        )
        assert "prize_offer" in indicators

    def test_multiple_indicators_combined(self):
        is_scam, confidence, indicators, _ = detect_scam(
            "URGENT! Your SBI account is blocked! Send OTP to officer@bank. Pay Rs 1000 to unblock. fraud@paytm"
        )
        assert is_scam is True
        assert confidence >= 0.5
        assert len(indicators) >= 3


# ─── apply_context_modifiers ──────────────────────────────────────────

class TestContextModifiers:

    def test_safe_context_reduces_score(self):
        score, modifiers = apply_context_modifiers(
            "My mom said the hospital appointment is urgent", 0.5
        )
        assert score < 0.5
        assert any("safe_" in m for m in modifiers)

    def test_amplifying_context_boosts_score(self):
        score, modifiers = apply_context_modifiers(
            "Don't tell anyone, this is confidential", 0.3
        )
        assert score > 0.3
        assert any("amplify_" in m for m in modifiers)

    def test_no_modifiers_on_neutral_text(self):
        score, modifiers = apply_context_modifiers("Hello there", 0.5)
        assert score == 0.5
        assert modifiers == []

    def test_score_never_negative(self):
        score, _ = apply_context_modifiers("My mom said hello from school", 0.05)
        assert score >= 0.0


# ─── calculate_severity ──────────────────────────────────────────────

class TestCalculateSeverity:

    def test_high_severity(self):
        assert calculate_severity(["credential_request", "urgency"]) == "high"

    def test_medium_severity(self):
        assert calculate_severity(["urgency", "threat"]) == "medium"

    def test_low_severity(self):
        assert calculate_severity(["contains_phone"]) == "low"

    def test_empty_indicators(self):
        assert calculate_severity([]) == "low"

    def test_high_takes_precedence(self):
        assert calculate_severity(["contains_phone", "payment_request", "urgency"]) == "high"


# ─── check_abuse ──────────────────────────────────────────────────────

class TestCheckAbuse:

    def test_critical_abuse(self):
        result = check_abuse("I will kill you")
        assert result["abusive"] is True
        assert result["tier"] == "critical"
        assert result["action"] == "disengage"

    def test_severe_abuse(self):
        result = check_abuse("I will hack your account")
        assert result["tier"] == "severe"
        assert result["action"] == "warn"

    def test_moderate_abuse(self):
        result = check_abuse("You are an idiot")
        assert result["tier"] == "moderate"
        assert result["action"] == "continue"

    def test_no_abuse(self):
        result = check_abuse("Hello, how are you?")
        assert result["abusive"] is False
        assert result["tier"] == "none"

    def test_empty_text(self):
        result = check_abuse("")
        assert result["abusive"] is False


# ─── detect_playbook ──────────────────────────────────────────────────

class TestDetectPlaybook:

    def test_account_block_playbook(self):
        history = [
            {"sender": "scammer", "text": "Your account is compromised and blocked"},
            {"sender": "scammer", "text": "Verify your identity with OTP"},
        ]
        result = detect_playbook(history)
        assert result.get("playbook") == "account_block"
        assert result.get("confidence", 0) >= 0.4

    def test_lottery_scam_playbook(self):
        history = [
            {"sender": "scammer", "text": "You have won a prize!"},
            {"sender": "scammer", "text": "Claim now, pay processing fee"},
        ]
        result = detect_playbook(history)
        assert result.get("playbook") == "lottery_scam"

    def test_no_playbook_match(self):
        history = [
            {"sender": "scammer", "text": "Hello, good morning"},
        ]
        result = detect_playbook(history)
        assert result == {} or result.get("confidence", 0) < 0.4

    def test_empty_history(self):
        assert detect_playbook([]) == {}

    def test_kyc_fraud_playbook(self):
        history = [
            {"sender": "scammer", "text": "Your account blocked due to KYC"},
            {"sender": "scammer", "text": "Verify with OTP, click link to update"},
        ]
        result = detect_playbook(history)
        assert result.get("playbook") == "kyc_fraud"

    def test_returns_next_expected(self):
        history = [
            {"sender": "scammer", "text": "Your account is compromised and blocked"},
            {"sender": "scammer", "text": "Verify your identity"},
        ]
        result = detect_playbook(history)
        assert "next_expected" in result


# ─── detect_red_flags ────────────────────────────────────────────────

class TestDetectRedFlags:

    def test_escalating_pressure(self):
        history = [
            {"sender": "scammer", "text": "This is urgent, act now!"},
            {"sender": "scammer", "text": "Hurry up immediately!"},
            {"sender": "scammer", "text": "Do it now or face consequences!"},
        ]
        flags = detect_red_flags(history)
        flag_names = [f['flag'] for f in flags]
        assert 'escalating_pressure' in flag_names

    def test_identity_switching(self):
        history = [
            {"sender": "scammer", "text": "I am the bank manager"},
            {"sender": "scammer", "text": "This is from the police department"},
        ]
        flags = detect_red_flags(history)
        flag_names = [f['flag'] for f in flags]
        assert 'identity_switching' in flag_names

    def test_multiple_payment_channels(self):
        history = [
            {"sender": "scammer", "text": "Send via UPI to verify"},
            {"sender": "scammer", "text": "Or transfer to bank account number"},
        ]
        flags = detect_red_flags(history)
        flag_names = [f['flag'] for f in flags]
        assert 'multiple_payment_channels' in flag_names

    def test_verification_evasion(self):
        history = [
            {"sender": "scammer", "text": "Your account is blocked"},
            {"sender": "user", "text": "What is your employee ID?"},
            {"sender": "scammer", "text": "Just send the OTP"},
            {"sender": "user", "text": "I need your badge number"},
            {"sender": "scammer", "text": "Send money quickly"},
            {"sender": "user", "text": "Give me reference number"},
        ]
        flags = detect_red_flags(history)
        flag_names = [f['flag'] for f in flags]
        assert 'verification_evasion' in flag_names

    def test_rapid_payment_escalation(self):
        history = [
            {"sender": "scammer", "text": "Send Rs 500 now"},
            {"sender": "scammer", "text": "Pay the fee immediately"},
            {"sender": "scammer", "text": "Transfer the amount to verify"},
        ]
        flags = detect_red_flags(history)
        flag_names = [f['flag'] for f in flags]
        assert 'rapid_payment_escalation' in flag_names

    def test_empty_history_no_flags(self):
        assert detect_red_flags([]) == []

    def test_clean_conversation_no_flags(self):
        history = [
            {"sender": "scammer", "text": "Hello, good morning"},
            {"sender": "user", "text": "Hello, who is this?"},
        ]
        flags = detect_red_flags(history)
        assert len(flags) == 0

    def test_flags_have_required_keys(self):
        history = [
            {"sender": "scammer", "text": "This is urgent, act now!"},
            {"sender": "scammer", "text": "Hurry up immediately!"},
            {"sender": "scammer", "text": "Do it now!"},
        ]
        flags = detect_red_flags(history)
        for flag in flags:
            assert 'flag' in flag
            assert 'description' in flag
            assert 'evidence' in flag
