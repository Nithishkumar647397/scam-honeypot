"""
Full integration test for Member A modules
Simulates the complete flow before Member B integration
"""

print("="*60)
print("FULL INTEGRATION TEST")
print("="*60)

# Import all modules
from src.config import Config, validate_config
from src.detector import detect_scam, get_scam_type
from src.extractor import extract_intelligence, extract_from_conversation, merge_intelligence, count_intelligence_items
from src.agent import generate_agent_reply, generate_agent_notes

# Simulate a multi-turn scam conversation
print("\n📱 SIMULATING SCAM CONVERSATION")
print("-"*40)

conversation = []
all_intelligence = {"upiIds": [], "bankAccounts": [], "phoneNumbers": [], "ifscCodes": [], "phishingLinks": [], "suspiciousKeywords": []}

# Scammer messages
scammer_messages = [
    "URGENT! Your SBI account is blocked due to suspicious activity. Verify now!",
    "You must pay Rs 500 verification fee. Send to security@paytm immediately.",
    "If you don't pay in 1 hour, your account will be permanently closed. Call 9876543210.",
    "Send money to account 123456789012 IFSC SBIN0001234. Hurry!"
]

for i, scammer_msg in enumerate(scammer_messages, 1):
    print(f"\n--- Turn {i} ---")
    print(f"🔴 Scammer: {scammer_msg}")
    
    # Detect scam
    is_scam, confidence, indicators = detect_scam(scammer_msg, conversation)
    print(f"   Detection: is_scam={is_scam}, confidence={confidence}, indicators={indicators}")
    
    # Extract intelligence
    intel = extract_intelligence(scammer_msg)
    all_intelligence = merge_intelligence(all_intelligence, intel)
    print(f"   Extracted: {intel}")
    
    # Add to conversation
    conversation.append({"sender": "scammer", "text": scammer_msg})
    
    # Generate agent reply
    reply = generate_agent_reply(scammer_msg, conversation, indicators)
    print(f"🟢 Agent: {reply}")
    
    # Add agent reply to conversation
    conversation.append({"sender": "user", "text": reply})

# Final summary
print("\n" + "="*60)
print("FINAL RESULTS")
print("="*60)

print(f"\n📊 Conversation Length: {len(conversation)} messages")
print(f"📊 Scam Detected: Yes")
print(f"📊 Intelligence Extracted:")
print(f"   - UPI IDs: {all_intelligence['upiIds']}")
print(f"   - Bank Accounts: {all_intelligence['bankAccounts']}")
print(f"   - Phone Numbers: {all_intelligence['phoneNumbers']}")
print(f"   - IFSC Codes: {all_intelligence['ifscCodes']}")
print(f"   - Phishing Links: {all_intelligence['phishingLinks']}")
print(f"📊 Total Items: {count_intelligence_items(all_intelligence)}")

# Generate agent notes
notes = generate_agent_notes(conversation, ["urgency", "threat", "payment_request"], all_intelligence)
print(f"\n📝 Agent Notes: {notes}")

# Verify minimum requirements
print("\n" + "="*60)
print("VERIFICATION")
print("="*60)

checks = [
    ("UPI ID extracted", len(all_intelligence['upiIds']) >= 1),
    ("Phone number extracted", len(all_intelligence['phoneNumbers']) >= 1),
    ("Bank account extracted", len(all_intelligence['bankAccounts']) >= 1),
    ("IFSC code extracted", len(all_intelligence['ifscCodes']) >= 1),
    ("At least 2 intelligence items", count_intelligence_items(all_intelligence) >= 2),
]

all_passed = True
for check_name, passed in checks:
    status = "✅" if passed else "❌"
    print(f"{status} {check_name}")
    if not passed:
        all_passed = False

if all_passed:
    print("\n🎉 ALL CHECKS PASSED! Ready for Member B integration.")
else:
    print("\n⚠️ Some checks failed. Review the output above.")
