from src.patterns import (
    find_upi_ids,
    find_bank_accounts,
    find_phone_numbers,
    find_ifsc_codes,
    find_urls,
    find_scam_keywords
)

test1 = "Send money to fraud@paytm or call 9876543210"
test2 = "Transfer to account 123456789012, IFSC: SBIN0001234"
test3 = "URGENT! Click https://fake-bank.com to verify"

print("Test 1:", test1)
print("  UPI IDs:", find_upi_ids(test1))
print("  Phones:", find_phone_numbers(test1))

print("\nTest 2:", test2)
print("  Bank Accounts:", find_bank_accounts(test2))
print("  IFSC Codes:", find_ifsc_codes(test2))

print("\nTest 3:", test3)
print("  URLs:", find_urls(test3))
print("  Keywords:", find_scam_keywords(test3))
