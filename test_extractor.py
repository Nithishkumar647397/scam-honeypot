"""
Test extractor module
"""
from src.extractor import (
    extract_intelligence,
    extract_from_conversation,
    merge_intelligence,
    count_intelligence_items,
    has_sufficient_intelligence,
    format_intelligence_summary
)

print("="*60)
print("TESTING EXTRACTOR MODULE")
print("="*60)

# Test 1: Single message extraction
print("\n[1] Testing extract_intelligence...")
msg = "Send Rs 500 to fraud@paytm or call 9876543210. IFSC: SBIN0001234"
intel = extract_intelligence(msg)
print(f"    Message: {msg}")
print(f"    Extracted: {intel}")
assert "fraud@paytm" in intel["upiIds"], "Should find UPI"
assert "9876543210" in intel["phoneNumbers"], "Should find phone"
assert "SBIN0001234" in intel["ifscCodes"], "Should find IFSC"
print("    ✅ extract_intelligence works")

# Test 2: Empty message
print("\n[2] Testing empty message...")
empty_intel = extract_intelligence("")
assert empty_intel["upiIds"] == [], "Should be empty"
print("    ✅ Handles empty message")

# Test 3: Conversation extraction
print("\n[3] Testing extract_from_conversation...")
history = [
    {"sender": "scammer", "text": "Send to fraud@paytm"},
    {"sender": "user", "text": "Okay, what next?"},
    {"sender": "scammer", "text": "Also send to 9876543210@ybl"},
    {"sender": "scammer", "text": "Account: 123456789012"}
]
conv_intel = extract_from_conversation(history)
print(f"    Conversation: {len(history)} messages")
print(f"    Extracted: {conv_intel}")
assert "fraud@paytm" in conv_intel["upiIds"], "Should find first UPI"
assert "9876543210@ybl" in conv_intel["upiIds"], "Should find second UPI"
assert "123456789012" in conv_intel["bankAccounts"], "Should find bank account"
print("    ✅ extract_from_conversation works")

# Test 4: Merge intelligence
print("\n[4] Testing merge_intelligence...")
intel1 = {"upiIds": ["a@paytm"], "bankAccounts": [], "phoneNumbers": [], "ifscCodes": [], "phishingLinks": [], "suspiciousKeywords": []}
intel2 = {"upiIds": ["b@ybl"], "bankAccounts": ["123456789012"], "phoneNumbers": [], "ifscCodes": [], "phishingLinks": [], "suspiciousKeywords": []}
merged = merge_intelligence(intel1, intel2)
print(f"    Merged: {merged}")
assert "a@paytm" in merged["upiIds"], "Should have first UPI"
assert "b@ybl" in merged["upiIds"], "Should have second UPI"
assert "123456789012" in merged["bankAccounts"], "Should have bank account"
print("    ✅ merge_intelligence works")

# Test 5: Count items
print("\n[5] Testing count_intelligence_items...")
count = count_intelligence_items(merged)
print(f"    Count: {count}")
assert count == 3, f"Should be 3, got {count}"
print("    ✅ count_intelligence_items works")

# Test 6: Sufficient intelligence check
print("\n[6] Testing has_sufficient_intelligence...")
assert has_sufficient_intelligence(merged, threshold=2) == True
assert has_sufficient_intelligence(intel1, threshold=2) == False
print("    ✅ has_sufficient_intelligence works")

# Test 7: Format summary
print("\n[7] Testing format_intelligence_summary...")
summary = format_intelligence_summary(merged)
print(f"    Summary: {summary}")
assert "UPI IDs" in summary
print("    ✅ format_intelligence_summary works")

print("\n" + "="*60)
print("ALL EXTRACTOR TESTS PASSED! ✅")
print("="*60)
