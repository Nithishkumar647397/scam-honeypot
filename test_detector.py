from src.detector import detect_scam, get_scam_type

# Test cases
test_cases = [
    "Your bank account will be blocked today. Verify immediately.",
    "Congratulations! You won Rs 50,000 lottery! Click here to claim.",
    "URGENT! Send Rs 500 to 9876543210@paytm to verify your account.",
    "Hello, how are you today?",
    "Your SBI account is frozen. Contact customer care now. Transfer Rs 1000 to avoid legal action.",
    "Aapka khata block ho jayega! Turant verify karo!"
]

print("="*60)
print("SCAM DETECTOR TESTS")
print("="*60)

for i, msg in enumerate(test_cases, 1):
    is_scam, confidence, indicators = detect_scam(msg)
    scam_type = get_scam_type(indicators)
    
    print(f"\nTest {i}: {msg[:50]}...")
    print(f"  Is Scam: {is_scam}")
    print(f"  Confidence: {confidence}")
    print(f"  Indicators: {indicators}")
    print(f"  Scam Type: {scam_type}")
    print("-"*40)
