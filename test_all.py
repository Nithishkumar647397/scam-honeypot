"""
Comprehensive test for all modules created so far
"""

print("="*60)
print("TESTING ALL MODULES")
print("="*60)

# ============== TEST 1: CONFIG ==============
print("\n[1] Testing config.py...")
try:
    from src.config import Config, validate_config
    validate_config()
    print("    ✅ Config loaded successfully")
    print(f"    ✅ GROQ_API_KEY set: {bool(Config.GROQ_API_KEY)}")
    print(f"    ✅ API_SECRET_KEY set: {bool(Config.API_SECRET_KEY)}")
    print(f"    ✅ MAX_MESSAGES: {Config.MAX_MESSAGES}")
except Exception as e:
    print(f"    ❌ Config Error: {e}")

# ============== TEST 2: PATTERNS ==============
print("\n[2] Testing patterns.py...")
try:
    from src.patterns import (
        find_upi_ids,
        find_bank_accounts,
        find_phone_numbers,
        find_ifsc_codes,
        find_urls,
        find_scam_keywords
    )
    
    # Test UPI
    upi_result = find_upi_ids("Send to fraud@paytm")
    assert upi_result == ["fraud@paytm"], f"UPI test failed: {upi_result}"
    print("    ✅ find_upi_ids works")
    
    # Test Bank Account
    bank_result = find_bank_accounts("Account: 123456789012")
    assert "123456789012" in bank_result, f"Bank test failed: {bank_result}"
    print("    ✅ find_bank_accounts works")
    
    # Test Phone
    phone_result = find_phone_numbers("Call 9876543210")
    assert "9876543210" in phone_result, f"Phone test failed: {phone_result}"
    print("    ✅ find_phone_numbers works")
    
    # Test IFSC
    ifsc_result = find_ifsc_codes("IFSC: SBIN0001234")
    assert "SBIN0001234" in ifsc_result, f"IFSC test failed: {ifsc_result}"
    print("    ✅ find_ifsc_codes works")
    
    # Test URLs
    url_result = find_urls("Click https://fake.com")
    assert "https://fake.com" in url_result, f"URL test failed: {url_result}"
    print("    ✅ find_urls works")
    
    # Test Keywords
    keyword_result = find_scam_keywords("URGENT! Verify now!")
    assert "urgent" in keyword_result, f"Keyword test failed: {keyword_result}"
    print("    ✅ find_scam_keywords works")
    
except AssertionError as e:
    print(f"    ❌ Pattern Test Failed: {e}")
except Exception as e:
    print(f"    ❌ Pattern Error: {e}")

# ============== TEST 3: DETECTOR ==============
print("\n[3] Testing detector.py...")
try:
    from src.detector import detect_scam, get_scam_type
    
    # Test obvious scam
    is_scam, confidence, indicators = detect_scam(
        "URGENT! Your account is blocked! Send Rs 500 to verify!"
    )
    assert is_scam == True, "Should detect as scam"
    assert confidence > 0.3, f"Confidence too low: {confidence}"
    assert len(indicators) >= 2, f"Should have indicators: {indicators}"
    print("    ✅ Detects obvious scam correctly")
    
    # Test non-scam
    is_scam2, confidence2, indicators2 = detect_scam(
        "Good morning! Hope you have a nice day."
    )
    assert is_scam2 == False, f"Should NOT be scam, got indicators: {indicators2}"
    print("    ✅ Identifies non-scam correctly")
    
    # Test scam type
    scam_type = get_scam_type(["prize_offer", "payment_request"])
    assert scam_type == "lottery_scam", f"Wrong type: {scam_type}"
    print("    ✅ get_scam_type works")
    
except AssertionError as e:
    print(f"    ❌ Detector Test Failed: {e}")
except Exception as e:
    print(f"    ❌ Detector Error: {e}")

# ============== TEST 4: INTEGRATION ==============
print("\n[4] Testing Integration (all modules together)...")
try:
    # Simulate real scam message
    scam_message = "Your SBI account will be blocked! Send Rs 1000 to verify@paytm. Call 9876543210. IFSC: HDFC0001234"
    
    # Extract intelligence
    upi_ids = find_upi_ids(scam_message)
    phones = find_phone_numbers(scam_message)
    bank_accounts = find_bank_accounts(scam_message)
    ifsc_codes = find_ifsc_codes(scam_message)
    keywords = find_scam_keywords(scam_message)
    
    # Detect scam
    is_scam, confidence, indicators = detect_scam(scam_message)
    
    print(f"    Message: {scam_message[:50]}...")
    print(f"    Is Scam: {is_scam}")
    print(f"    Confidence: {confidence}")
    print(f"    Indicators: {indicators}")
    print(f"    Extracted UPI: {upi_ids}")
    print(f"    Extracted Phones: {phones}")
    print(f"    Extracted IFSC: {ifsc_codes}")
    print(f"    Keywords: {keywords}")
    
    # Verify all extracted correctly
    assert is_scam == True
    assert "verify@paytm" in upi_ids
    assert "9876543210" in phones
    assert "HDFC0001234" in ifsc_codes
    print("    ✅ Integration test passed!")
    
except AssertionError as e:
    print(f"    ❌ Integration Test Failed: {e}")
except Exception as e:
    print(f"    ❌ Integration Error: {e}")

# ============== SUMMARY ==============
print("\n" + "="*60)
print("TEST SUMMARY")
print("="*60)
print("""
Files Tested:
  ✅ src/config.py
  ✅ src/patterns.py  
  ✅ src/detector.py

Next Files to Create:
  ⏳ src/extractor.py
  ⏳ src/agent.py
  ⏳ src/auth.py (Member B)
  ⏳ src/session.py (Member B)
  ⏳ src/callback.py (Member B)
  ⏳ src/app.py (Member B)
""")
