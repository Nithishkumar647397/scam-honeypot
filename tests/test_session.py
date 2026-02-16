"""
Tests for the session management module (src/session.py).

Covers: create_session, get_session, update_session, delete_session,
should_send_callback, clear_all_sessions.
"""

import pytest
from src.session import (
    create_session,
    get_session,
    update_session,
    delete_session,
    should_send_callback,
    clear_all_sessions,
    get_all_sessions,
)


@pytest.fixture(autouse=True)
def cleanup_sessions():
    """Clear all sessions before and after each test."""
    clear_all_sessions()
    yield
    clear_all_sessions()


class TestCreateSession:

    def test_creates_session(self):
        session = create_session("test-001")
        assert session.session_id == "test-001"
        assert session.message_count == 0
        assert session.scam_detected is False

    def test_session_retrievable(self):
        create_session("test-002")
        session = get_session("test-002")
        assert session is not None
        assert session.session_id == "test-002"


class TestGetSession:

    def test_returns_none_for_unknown(self):
        assert get_session("nonexistent") is None

    def test_returns_existing_session(self):
        create_session("existing")
        assert get_session("existing") is not None


class TestUpdateSession:

    def test_updates_scam_detected(self):
        create_session("test-upd")
        session = update_session("test-upd", scam_detected=True, confidence=0.8)
        assert session.scam_detected is True
        assert session.confidence == 0.8

    def test_appends_message(self):
        create_session("test-msg")
        session = update_session("test-msg", new_message={"sender": "scammer", "text": "hello"})
        assert len(session.conversation_history) == 1
        assert session.message_count == 1

    def test_merges_indicators(self):
        create_session("test-ind")
        update_session("test-ind", indicators=["urgency"])
        session = update_session("test-ind", indicators=["threat"])
        assert "urgency" in session.indicators
        assert "threat" in session.indicators

    def test_merges_intelligence(self):
        create_session("test-intel")
        update_session("test-intel", extracted_intelligence={"upiIds": ["a@paytm"], "bankAccounts": [],
                        "phoneNumbers": [], "ifscCodes": [], "phishingLinks": [],
                        "suspiciousKeywords": [], "emails": [], "scammerIds": []})
        session = update_session("test-intel", extracted_intelligence={"upiIds": ["b@ybl"], "bankAccounts": [],
                        "phoneNumbers": [], "ifscCodes": [], "phishingLinks": [],
                        "suspiciousKeywords": [], "emails": [], "scammerIds": []})
        assert "a@paytm" in session.extracted_intelligence["upiIds"]
        assert "b@ybl" in session.extracted_intelligence["upiIds"]

    def test_creates_session_if_missing(self):
        session = update_session("auto-create", scam_detected=True)
        assert session is not None
        assert session.scam_detected is True


class TestDeleteSession:

    def test_deletes_existing(self):
        create_session("del-me")
        assert delete_session("del-me") is True
        assert get_session("del-me") is None

    def test_delete_nonexistent(self):
        assert delete_session("nonexistent") is False


class TestShouldSendCallback:

    def test_no_callback_without_scam(self):
        session = create_session("no-scam")
        assert should_send_callback(session) is False

    def test_no_callback_too_early(self):
        session = create_session("early")
        session.scam_detected = True
        session.confidence = 0.5
        # Only 1 message, not enough
        session.conversation_history = [{"sender": "scammer", "text": "hi"}]
        assert should_send_callback(session) is False

    def test_callback_on_max_messages(self):
        session = create_session("max-msg")
        session.scam_detected = True
        session.confidence = 0.5
        session.conversation_history = [{"sender": "scammer", "text": f"msg {i}"} for i in range(15)]
        assert should_send_callback(session) is True

    def test_none_session(self):
        assert should_send_callback(None) is False


class TestClearAllSessions:

    def test_clears_all(self):
        create_session("a")
        create_session("b")
        count = clear_all_sessions()
        assert count == 2
        assert len(get_all_sessions()) == 0
