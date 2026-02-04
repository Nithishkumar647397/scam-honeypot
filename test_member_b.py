"""
Test Member B modules
"""

print("="*60)
print("TESTING MEMBER B MODULES")
print("="*60)

# Test 1: Auth
print("\n[1] Testing auth.py...")
try:
    from src.auth import validate_api_key
    print("    ✅ auth.py imported successfully")
except Exception as e:
    print(f"    ❌ Error: {e}")

# Test 2: Session
print("\n[2] Testing session.py...")
try:
    from src.session import (
        create_session,
        get_session,
        update_session,
        should_send_callback,
        delete_session
    )
    
    # Create session
    session = create_session("test-123")
    assert session.session_id == "test-123"
    print("    ✅ create_session works")
    
    # Get session
    retrieved = get_session("test-123")
    assert retrieved is not None
    print("    ✅ get_session works")
    
    # Update session
    updated = update_session(
        "test-123",
        message_count=5,
        scam_detected=True,
        extracted_intelligence={"upiIds": ["fraud@paytm"], "bankAccounts": [], "phoneNumbers": [], "ifscCodes": [], "phishingLinks": [], "suspiciousKeywords": []}
    )
    assert updated.message_count == 5
    assert updated.scam_detected == True
    assert "fraud@paytm" in updated.extracted_intelligence["upiIds"]
    print("    ✅ update_session works")
    
    # Should send callback
    assert should_send_callback(updated) == False  # Only 1 item, need 2
    update_session("test-123", extracted_intelligence={"upiIds": [], "bankAccounts": [], "phoneNumbers": ["9876543210"], "ifscCodes": [], "phishingLinks": [], "suspiciousKeywords": []})
    assert should_send_callback(get_session("test-123")) == True  # Now 2 items
    print("    ✅ should_send_callback works")
    
    # Delete session
    assert delete_session("test-123") == True
    assert get_session("test-123") is None
    print("    ✅ delete_session works")
    
except Exception as e:
    print(f"    ❌ Error: {e}")

# Test 3: Callback
print("\n[3] Testing callback.py...")
try:
    from src.callback import build_callback_payload, generate_default_notes
    from src.session import create_session, update_session
    
    # Create test session
    session = create_session("callback-test")
    update_session(
        "callback-test",
        message_count=8,
        scam_detected=True,
        confidence=0.85,
        indicators=["urgency", "threat"],
        extracted_intelligence={"upiIds": ["fraud@paytm"], "bankAccounts": ["123456789012"], "phoneNumbers": [], "ifscCodes": [], "phishingLinks": [], "suspiciousKeywords": ["urgent"]}
    )
    
    session = get_session("callback-test")
    
    # Build payload
    payload = build_callback_payload(session)
    assert payload["sessionId"] == "callback-test"
    assert payload["scamDetected"] == True
    assert payload["totalMessagesExchanged"] == 8
    assert "fraud@paytm" in payload["extractedIntelligence"]["upiIds"]
    print("    ✅ build_callback_payload works")
    
    # Generate notes
    notes = generate_default_notes(session)
    assert "urgency" in notes.lower() or "scam" in notes.lower()
    print(f"    Notes: {notes}")
    print("    ✅ generate_default_notes works")
    
    # Cleanup
    delete_session("callback-test")
    
except Exception as e:
    print(f"    ❌ Error: {e}")

print("\n" + "="*60)
print("MEMBER B TESTS COMPLETED!")
print("="*60)
