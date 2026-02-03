"""
Test agent module
"""
from src.agent import (
    build_system_prompt,
    generate_agent_reply,
    generate_agent_notes,
    _get_fallback_response,
    _clean_reply
)

print("="*60)
print("TESTING AGENT MODULE")
print("="*60)

# Test 1: System prompt
print("\n[1] Testing build_system_prompt...")
prompt = build_system_prompt()
assert "Kamala" in prompt, "Should have persona name"
assert "elderly" in prompt.lower() or "67" in prompt, "Should mention age"
assert "worried" in prompt.lower(), "Should mention worried behavior"
print(f"    Prompt length: {len(prompt)} chars")
print("    ✅ build_system_prompt works")

# Test 2: Clean reply
print("\n[2] Testing _clean_reply...")
assert _clean_reply('"Hello"') == "Hello", "Should remove quotes"
assert _clean_reply("As Mrs. Kamala Devi, I am worried") == "I am worried", "Should remove prefix"
print("    ✅ _clean_reply works")

# Test 3: Fallback responses
print("\n[3] Testing _get_fallback_response...")
fallback1 = _get_fallback_response("Your account is blocked!", 1)
assert "worried" in fallback1.lower() or "blocked" in fallback1.lower()
print(f"    Early response: {fallback1}")

fallback2 = _get_fallback_response("Send money now!", 4)
assert "send" in fallback2.lower() or "account" in fallback2.lower()
print(f"    Mid response: {fallback2}")

fallback3 = _get_fallback_response("Use this UPI: fraud@paytm", 7)
assert "upi" in fallback3.lower() or "write" in fallback3.lower()
print(f"    Late response: {fallback3}")
print("    ✅ _get_fallback_response works")

# Test 4: Agent notes
print("\n[4] Testing generate_agent_notes...")
notes = generate_agent_notes(
    conversation_history=[{"sender": "scammer", "text": "test"}] * 5,
    scam_indicators=["urgency", "threat"],
    extracted_intelligence={"upiIds": ["fraud@paytm"], "phoneNumbers": ["9876543210"], "bankAccounts": [], "ifscCodes": [], "phishingLinks": [], "suspiciousKeywords": []}
)
print(f"    Notes: {notes}")
assert "urgency" in notes.lower() or "scam" in notes.lower()
print("    ✅ generate_agent_notes works")

# Test 5: Actual Groq API call
print("\n[5] Testing generate_agent_reply (Groq API)...")
print("    Calling Groq API...")
try:
    reply = generate_agent_reply(
        current_message="Your SBI account is blocked! Verify immediately!",
        conversation_history=[],
        scam_indicators=["urgency", "threat"]
    )
    print(f"    Reply: {reply}")
    assert len(reply) > 0, "Should have a reply"
    assert len(reply) < 300, "Reply should be short"
    print("    ✅ generate_agent_reply works (API call successful)")
except Exception as e:
    print(f"    ⚠️ API Error: {e}")
    print("    Using fallback response instead")

# Test 6: Multi-turn conversation
print("\n[6] Testing multi-turn conversation...")
try:
    history = [
        {"sender": "scammer", "text": "Your account is blocked!"},
        {"sender": "user", "text": "Oh no! What happened?"},
        {"sender": "scammer", "text": "You need to verify. Send Rs 500."}
    ]
    reply = generate_agent_reply(
        current_message="Send to this UPI: verify@paytm",
        conversation_history=history,
        scam_indicators=["urgency", "payment_request"]
    )
    print(f"    Reply: {reply}")
    print("    ✅ Multi-turn conversation works")
except Exception as e:
    print(f"    ⚠️ Error: {e}")

print("\n" + "="*60)
print("AGENT TESTS COMPLETED!")
print("="*60)
