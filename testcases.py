import requests
import json
import time
import uuid
import threading
from datetime import datetime
from flask import Flask, request, jsonify

# ─── CONFIGURE ────────────────────────────────────────────────────────────────
ENDPOINT_URL  = "https://scam-honeypot-y77x.onrender.com/honeypot"
API_KEY       = "my_secret_key_123"
WEBHOOK_PORT  = 9999
WEBHOOK_HOST  = "0.0.0.0"
CALLBACK_WAIT = 25      # seconds to wait for async callback
TURN_DELAY    = 1.5     # seconds between turns
TEST_DELAY    = 4       # seconds between scenarios
MAX_TURNS     = 6       # keep short — enough to trigger callback
# ──────────────────────────────────────────────────────────────────────────────

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

HEADERS = {
    "Content-Type": "application/json",
    "x-api-key": API_KEY
}

# ─── WEBHOOK SERVER ────────────────────────────────────────────────────────────
app = Flask(__name__)
received_callbacks = {}   # sessionId → finalOutput
webhook_lock = threading.Lock()

@app.route("/webhook", methods=["POST"])
def webhook():
    data = request.get_json(force=True, silent=True) or {}
    session_id = data.get("sessionId", "unknown")
    with webhook_lock:
        received_callbacks[session_id] = data
    print(f"\n  {CYAN}📥 CALLBACK RECEIVED for session {session_id[:8]}...{RESET}")
    return jsonify({"status": "ok"}), 200

@app.route("/webhook", methods=["GET"])
def webhook_health():
    return jsonify({"status": "webhook_alive"}), 200

def start_webhook():
    import logging
    log = logging.getLogger("werkzeug")
    log.setLevel(logging.ERROR)
    app.run(host=WEBHOOK_HOST, port=WEBHOOK_PORT, threaded=True)

# ─── 8 GAP DEFINITIONS ────────────────────────────────────────────────────────
GAP_CHECKS = [
    {
        "id": "gap1",
        "name": "GAP 1 — engagementMetrics object exists",
        "check": lambda fo: "engagementMetrics" in fo,
        "fix": "Add engagementMetrics: {} to finalOutput"
    },
    {
        "id": "gap2",
        "name": "GAP 2 — engagementDurationSeconds tracked",
        "check": lambda fo: fo.get("engagementMetrics", {}).get("engagementDurationSeconds", 0) > 0,
        "fix": "Track session start time, compute elapsed seconds"
    },
    {
        "id": "gap3",
        "name": "GAP 3 — totalMessagesExchanged not frozen",
        "check": lambda fo: fo.get("engagementMetrics", {}).get("totalMessagesExchanged", 0) >= 5,
        "fix": "Counter must update dynamically from conversationHistory.length"
    },
    {
        "id": "gap4",
        "name": "GAP 4 — status field present",
        "check": lambda fo: "status" in fo and fo["status"],
        "fix": "Add status: 'completed' to finalOutput"
    },
    {
        "id": "gap5",
        "name": "GAP 5 — emailAddresses extracted",
        "check": lambda fo: isinstance(fo.get("extractedIntelligence", {}).get("emailAddresses"), list),
        "fix": "Add email regex extraction, store in extractedIntelligence.emailAddresses"
    },
    {
        "id": "gap6",
        "name": "GAP 6 — phone stored with +91- prefix",
        "check": lambda fo: any(
            str(v).startswith("+91") or str(v).startswith("+91-")
            for v in fo.get("extractedIntelligence", {}).get("phoneNumbers", [])
        ),
        "fix": "Store phones as +91-XXXXXXXXXX not just 10 digits"
    },
    {
        "id": "gap7",
        "name": "GAP 7 — non-whitelisted UPI handles extracted",
        "check": lambda fo: any(
            "@fakebank" in str(v) or "@fakeupi" in str(v)
            for v in fo.get("extractedIntelligence", {}).get("upiIds", [])
        ),
        "fix": "Allow any @handle in scam context, not just whitelisted ones"
    },
    {
        "id": "gap8",
        "name": "GAP 8 — engagementMetrics has data (not empty)",
        "check": lambda fo: bool(fo.get("engagementMetrics")),
        "fix": "engagementMetrics must contain actual values, not empty object"
    },
]

# ─── SCORING (exact official algorithm) ───────────────────────────────────────
def score_final_output(final_output, expected_intel, expect_scam):
    score = {
        "scamDetection": 0,
        "intelligenceExtraction": 0,
        "engagementQuality": 0,
        "responseStructure": 0,
        "total": 0,
        "lines": []
    }

    # 1. Scam Detection (20 pts)
    detected = final_output.get("scamDetected", False)
    if detected == expect_scam:
        score["scamDetection"] = 20
        score["lines"].append(f"  {GREEN}✅ scamDetected={detected} (correct) → 20/20{RESET}")
    else:
        score["lines"].append(f"  {RED}❌ scamDetected={detected} (expected {expect_scam}) → 0/20{RESET}")

    # 2. Intelligence Extraction (40 pts)
    extracted = final_output.get("extractedIntelligence", {})
    key_map = {
        "phoneNumbers":    "phoneNumbers",
        "bankAccounts":    "bankAccounts",
        "upiIds":          "upiIds",
        "phishingLinks":   "phishingLinks",
        "emailAddresses":  "emailAddresses",
    }
    for intel_type, expected_vals in expected_intel.items():
        out_key = key_map.get(intel_type, intel_type)
        extracted_vals = extracted.get(out_key, [])
        matched = any(ev in str(xv) for ev in expected_vals for xv in extracted_vals)
        if matched:
            score["intelligenceExtraction"] += 10
            score["lines"].append(f"  {GREEN}✅ {intel_type}: matched → +10 pts{RESET}")
        else:
            score["lines"].append(
                f"  {RED}❌ {intel_type}: NOT matched "
                f"(expected {expected_vals}, got {extracted_vals}) → 0 pts{RESET}"
            )
    score["intelligenceExtraction"] = min(score["intelligenceExtraction"], 40)

    # 3. Engagement Quality (20 pts)
    metrics  = final_output.get("engagementMetrics", {})
    duration = metrics.get("engagementDurationSeconds", 0)
    messages = metrics.get("totalMessagesExchanged", 0)

    for condition, pts, label in [
        (duration > 0,   5, f"duration > 0 ({duration}s)"),
        (duration > 60,  5, f"duration > 60s ({duration}s)"),
        (messages > 0,   5, f"messages > 0 ({messages})"),
        (messages >= 5,  5, f"messages >= 5 ({messages})"),
    ]:
        if condition:
            score["engagementQuality"] += pts
            score["lines"].append(f"  {GREEN}✅ {label} → +{pts} pts{RESET}")
        else:
            score["lines"].append(f"  {RED}❌ {label} → 0 pts{RESET}")

    # 4. Response Structure (20 pts)
    for field, pts in [("status",5),("scamDetected",5),("extractedIntelligence",5)]:
        if field in final_output:
            score["responseStructure"] += pts
            score["lines"].append(f"  {GREEN}✅ '{field}' present → +{pts} pts{RESET}")
        else:
            score["lines"].append(f"  {RED}❌ '{field}' MISSING → 0 pts{RESET}")
    for field in ["engagementMetrics", "agentNotes"]:
        if field in final_output and final_output[field]:
            score["responseStructure"] += 2.5
            score["lines"].append(f"  {GREEN}✅ '{field}' present → +2.5 pts{RESET}")
        else:
            score["lines"].append(f"  {YELLOW}⚠️  '{field}' missing → 0 pts{RESET}")
    score["responseStructure"] = min(score["responseStructure"], 20)

    score["total"] = (score["scamDetection"] + score["intelligenceExtraction"] +
                      score["engagementQuality"] + score["responseStructure"])
    return score


# ─── GAP VALIDATOR ────────────────────────────────────────────────────────────
def validate_gaps(final_output):
    results = []
    for gap in GAP_CHECKS:
        try:
            passed = gap["check"](final_output)
        except Exception:
            passed = False
        results.append({
            "id":     gap["id"],
            "name":   gap["name"],
            "passed": passed,
            "fix":    gap["fix"]
        })
    return results


# ─── SCENARIOS ────────────────────────────────────────────────────────────────
SCENARIOS = [
    {
        "id": "bank_fraud",
        "name": "CONFIRMED — Bank Fraud (SBI)",
        "channel": "SMS", "language": "English",
        "messages": [
            "URGENT: Your SBI account has been compromised. Your account will be blocked in 2 hours. Share your account number and OTP immediately to verify your identity.",
            "I am from SBI fraud prevention. Your account 1234567890123456 is at risk. Share OTP.",
            "Call back on +91-9876543210 immediately to secure your account.",
            "Last warning — also send verification fee to scammer.fraud@fakebank",
            "Your time is running out. OTP needed now.",
            "Account will be blocked unless you verify with us."
        ],
        "expectedIntel": {
            "phoneNumbers":  ["+91-9876543210"],
            "bankAccounts":  ["1234567890123456"],
            "upiIds":        ["scammer.fraud@fakebank"],
        },
        "expectScam": True,
        "gaps_tested": ["gap6 (phone prefix)", "gap7 (fake UPI handle)", "gap3 (msg count)"]
    },
    {
        "id": "upi_fraud",
        "name": "CONFIRMED — UPI Fraud (Paytm Cashback)",
        "channel": "WhatsApp", "language": "English",
        "messages": [
            "Congratulations! You have won a cashback of Rs. 5000 from Paytm. To claim, verify your UPI details. This is from official customer support.",
            "Please send Re.1 to cashback.scam@fakeupi to verify your account.",
            "Our agent number is +91-8765432109. Call to complete verification.",
            "Offer expires soon. Confirm your UPI ID to receive Rs. 5000.",
            "We are waiting for your confirmation. UPI: cashback.scam@fakeupi",
            "Final reminder — call +91-8765432109 now."
        ],
        "expectedIntel": {
            "upiIds":        ["cashback.scam@fakeupi"],
            "phoneNumbers":  ["+91-8765432109"],
        },
        "expectScam": True,
        "gaps_tested": ["gap7 (non-whitelisted UPI)", "gap6 (phone prefix)"]
    },
    {
        "id": "phishing_link",
        "name": "CONFIRMED — Phishing + Email Extraction",
        "channel": "Email", "language": "English",
        "messages": [
            "You have been selected for iPhone 15 Pro at just Rs. 999! Click: http://amaz0n-deals.fake-site.com/claim?id=12345. Offer expires in 10 minutes!",
            "Visit http://amaz0n-deals.fake-site.com/claim?id=12345 to complete your order.",
            "For support contact offers@fake-amazon-deals.com",
            "Pay Rs. 999 to amazon.offer@paytm to confirm your iPhone order.",
            "Your order is reserved at http://amaz0n-deals.fake-site.com/claim?id=12345",
            "Contact offers@fake-amazon-deals.com if you have questions."
        ],
        "expectedIntel": {
            "phishingLinks":  ["http://amaz0n-deals.fake-site.com/claim?id=12345"],
            "emailAddresses": ["offers@fake-amazon-deals.com"],
        },
        "expectScam": True,
        "gaps_tested": ["gap5 (email extraction)"]
    },
    {
        "id": "engagement_duration",
        "name": "GAP 2+3 — Engagement Duration & Message Count",
        "channel": "SMS", "language": "English",
        "messages": [
            "Your bank account will be suspended. Call +91-9111222333 immediately.",
            "This is from RBI fraud department. Share your account details.",
            "Pay small fee to kyc.verify@okaxis to prevent suspension.",
            "Call +91-9111222333 or lose access to your funds.",
            "Account 9876001234567890 will be blocked in one hour.",
            "Final warning — respond now to avoid suspension."
        ],
        "expectedIntel": {
            "phoneNumbers": ["+91-9111222333"],
        },
        "expectScam": True,
        "gaps_tested": ["gap2 (duration > 60s)", "gap3 (messages >= 5)"]
    },
    {
        "id": "non_scam_check",
        "name": "EDGE — False Positive (Non-Scam)",
        "channel": "SMS", "language": "English",
        "messages": [
            "Hi, can we reschedule our meeting to 3pm tomorrow?",
        ],
        "expectedIntel": {},
        "expectScam": False,
        "gaps_tested": ["false positive detection"]
    },
    {
        "id": "hindi_scam",
        "name": "EDGE — Hindi/Hinglish Scam",
        "channel": "WhatsApp", "language": "Hindi",
        "messages": [
            "Aapka bank account aaj block ho jayega. Abhi verify karo. +91-9876543210 par call karo ya fraud.agent@paytm pe paisa bhejo.",
            "Jaldi karo! fraud.agent@paytm pe Rs.1 bhejo verification ke liye.",
            "Hamara agent +91-9876543210 pe available hai abhi.",
            "Account block hone wala hai — abhi respond karo.",
        ],
        "expectedIntel": {
            "phoneNumbers": ["+91-9876543210"],
            "upiIds":       ["fraud.agent@paytm"],
        },
        "expectScam": True,
        "gaps_tested": ["hindi language handling", "gap6", "gap7"]
    },
    {
        "id": "structure_check",
        "name": "GAP 4+8 — Status Field & Full Structure",
        "channel": "SMS", "language": "English",
        "messages": [
            "URGENT: Your account at HDFC Bank will be blocked. OTP needed immediately to prevent loss.",
            "Call our helpline +91-9000000001 to verify.",
            "Send Rs.1 to hdfc.verify@okicici to confirm your KYC.",
            "Account 1122334455667788 is flagged. Verify now.",
            "Last chance — respond in 5 minutes.",
        ],
        "expectedIntel": {
            "phoneNumbers": ["+91-9000000001"],
        },
        "expectScam": True,
        "gaps_tested": ["gap4 (status field)", "gap1 (engagementMetrics key)", "gap8 (non-empty metrics)"]
    },
]

# ─── EDGE TESTS ───────────────────────────────────────────────────────────────
def run_edge_tests():
    print(f"\n{BOLD}{CYAN}━━━ EDGE CASE TESTS ━━━{RESET}")
    results = []

    # GET /honeypot
    print(f"\n  {BOLD}GET /honeypot (must return 200, not 405){RESET}")
    try:
        r = requests.get(ENDPOINT_URL, headers=HEADERS, timeout=10)
        ok = r.status_code == 200
        symbol = f"{GREEN}✅ PASS{RESET}" if ok else f"{RED}❌ FAIL (HTTP {r.status_code}){RESET}"
        print(f"    {symbol}")
        results.append(("GET /honeypot", ok, f"HTTP {r.status_code}"))
    except Exception as e:
        print(f"    {RED}❌ ERROR: {e}{RESET}")
        results.append(("GET /honeypot", False, str(e)))

    # Empty POST
    print(f"\n  {BOLD}Empty POST (must return 200, not 422/500){RESET}")
    try:
        r = requests.post(ENDPOINT_URL, headers=HEADERS, data="", timeout=10)
        ok = r.status_code == 200
        symbol = f"{GREEN}✅ PASS{RESET}" if ok else f"{RED}❌ FAIL (HTTP {r.status_code}){RESET}"
        print(f"    {symbol}")
        results.append(("Empty POST", ok, f"HTTP {r.status_code}"))
    except Exception as e:
        print(f"    {RED}❌ ERROR: {e}{RESET}")
        results.append(("Empty POST", False, str(e)))

    # POST missing sessionId
    print(f"\n  {BOLD}POST missing sessionId (must not crash){RESET}")
    try:
        r = requests.post(ENDPOINT_URL, headers=HEADERS,
                         json={"message": {"sender": "scammer", "text": "test", "timestamp": 0}},
                         timeout=10)
        ok = r.status_code == 200
        symbol = f"{GREEN}✅ PASS{RESET}" if ok else f"{YELLOW}⚠️  HTTP {r.status_code}{RESET}"
        print(f"    {symbol}")
        results.append(("POST no sessionId", ok, f"HTTP {r.status_code}"))
    except Exception as e:
        print(f"    {RED}❌ ERROR: {e}{RESET}")
        results.append(("POST no sessionId", False, str(e)))

    # Response time check
    print(f"\n  {BOLD}Response time (<30s limit){RESET}")
    try:
        start = time.time()
        r = requests.post(ENDPOINT_URL, headers=HEADERS, json={
            "sessionId": str(uuid.uuid4()),
            "message": {"sender": "scammer", "text": "Your account is blocked.", "timestamp": int(time.time()*1000)},
            "conversationHistory": [],
            "metadata": {"channel": "SMS", "language": "English", "locale": "IN"}
        }, timeout=30)
        elapsed = time.time() - start
        ok = elapsed < 30 and r.status_code == 200
        color = GREEN if elapsed < 10 else (YELLOW if elapsed < 20 else RED)
        print(f"    {color}{'✅' if ok else '⚠️ '} {elapsed:.2f}s{RESET}")
        results.append(("Response time", ok, f"{elapsed:.2f}s"))
    except Exception as e:
        print(f"    {RED}❌ TIMEOUT/ERROR: {e}{RESET}")
        results.append(("Response time", False, str(e)))

    return results


# ─── RUN ONE SCENARIO ─────────────────────────────────────────────────────────
def run_scenario(scenario):
    session_id = str(uuid.uuid4())
    history = []
    start_time = time.time()

    print(f"\n{BOLD}{BLUE}━━━ {scenario['name']} ━━━{RESET}")
    print(f"  Session : {session_id[:8]}...")
    print(f"  Testing : {', '.join(scenario['gaps_tested'])}")

    # Send all messages
    for i, text in enumerate(scenario["messages"][:MAX_TURNS]):
        msg = {"sender": "scammer", "text": text, "timestamp": int(time.time() * 1000)}
        body = {
            "sessionId": session_id,
            "message": msg,
            "conversationHistory": history,
            "metadata": {
                "channel":  scenario.get("channel", "SMS"),
                "language": scenario.get("language", "English"),
                "locale":   "IN"
            }
        }
        try:
            r = requests.post(ENDPOINT_URL, headers=HEADERS, json=body, timeout=30)
            if r.status_code != 200:
                print(f"  {RED}❌ Turn {i+1} HTTP {r.status_code}{RESET}")
                break
            data = r.json()
            reply = (data.get("reply") or data.get("message") or
                     data.get("text") or data.get("data", {}).get("reply", ""))
            if i == 0:
                print(f"  {GREEN}Turn 1 reply:{RESET} {reply[:100]}...")
            history.append(msg)
            history.append({"sender": "user", "text": reply or "ok",
                            "timestamp": int(time.time() * 1000)})
        except Exception as e:
            print(f"  {RED}❌ Turn {i+1} error: {e}{RESET}")
            break
        time.sleep(TURN_DELAY)

    # Wait for async callback
    print(f"  {YELLOW}⏳ Waiting up to {CALLBACK_WAIT}s for async callback...{RESET}")
    waited = 0
    final_output = None
    while waited < CALLBACK_WAIT:
        with webhook_lock:
            if session_id in received_callbacks:
                final_output = received_callbacks.pop(session_id)
                break
        time.sleep(1)
        waited += 1

    elapsed = int(time.time() - start_time)

    if not final_output:
        print(f"  {YELLOW}⚠️  No callback received in {CALLBACK_WAIT}s{RESET}")
        print(f"  {YELLOW}    Check: Is your callback URL pointing here? "
              f"(http://localhost:{WEBHOOK_PORT}/webhook){RESET}")
        return None, session_id

    print(f"  {GREEN}✅ Callback received after {waited}s{RESET}")

    # Score it
    scores = score_final_output(
        final_output,
        scenario.get("expectedIntel", {}),
        scenario["expectScam"]
    )

    # Validate gaps
    gap_results = validate_gaps(final_output)

    # Print score breakdown
    print(f"\n  {BOLD}📊 Scoring:{RESET}")
    for line in scores["lines"]:
        print(f"  {line}")

    color = GREEN if scores["total"] >= 80 else (YELLOW if scores["total"] >= 50 else RED)
    print(f"\n  {BOLD}{color}TOTAL: {scores['total']}/100{RESET}  "
          f"[Det:{scores['scamDetection']} | "
          f"Intel:{scores['intelligenceExtraction']} | "
          f"Engage:{scores['engagementQuality']} | "
          f"Struct:{scores['responseStructure']}]")

    # Print gap validation
    print(f"\n  {BOLD}🔍 Gap Validation:{RESET}")
    for g in gap_results:
        sym = f"{GREEN}✅ FIXED{RESET}" if g["passed"] else f"{RED}❌ STILL BROKEN — {g['fix']}{RESET}"
        print(f"  {sym}  {g['name']}")

    return scores["total"], session_id


# ─── MAIN ─────────────────────────────────────────────────────────────────────
def main():
    print(f"\n{BOLD}{BLUE}{'━'*65}{RESET}")
    print(f"{BOLD}{BLUE}  GUVI BUILDATHON 2026 — GAP VALIDATION SUITE v2{RESET}")
    print(f"{BOLD}{BLUE}  (Captures real async callbacks — no simulated output){RESET}")
    print(f"{BOLD}{BLUE}  Endpoint : {ENDPOINT_URL}{RESET}")
    print(f"{BOLD}{BLUE}  Webhook  : http://localhost:{WEBHOOK_PORT}/webhook{RESET}")
    print(f"{BOLD}{BLUE}  Time     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    print(f"{BOLD}{BLUE}{'━'*65}{RESET}")

    print(f"\n{YELLOW}⚠️  IMPORTANT: Set your API's callback URL to:{RESET}")
    print(f"{BOLD}    http://localhost:{WEBHOOK_PORT}/webhook{RESET}")
    print(f"{YELLOW}    (or your machine's LAN IP if API is remote){RESET}")

    # Start webhook
    wt = threading.Thread(target=start_webhook, daemon=True)
    wt.start()
    time.sleep(1.5)
    print(f"\n{GREEN}✅ Webhook listener started on port {WEBHOOK_PORT}{RESET}")

    # Warmup
    print(f"\n{YELLOW}🔥 Warming up Render instance...{RESET}")
    try:
        r = requests.get(ENDPOINT_URL, timeout=40)
        print(f"{GREEN}✅ Alive (HTTP {r.status_code}){RESET}")
    except Exception as e:
        print(f"{YELLOW}⚠️  Warmup: {e} — continuing{RESET}")
    time.sleep(2)

    # Edge tests
    edge_results = run_edge_tests()

    # Scenario tests
    all_scores = []
    for scenario in SCENARIOS:
        result = run_scenario(scenario)
        if result[0] is not None:
            all_scores.append((scenario["id"], scenario["name"], result[0]))
        else:
            all_scores.append((scenario["id"], scenario["name"], None))
        time.sleep(TEST_DELAY)

    # ── FINAL REPORT ──────────────────────────────────────────────────────────
    print(f"\n\n{'━'*65}")
    print(f"{BOLD}{BLUE}FINAL REPORT{RESET}")
    print(f"{'━'*65}")

    print(f"\n{BOLD}Edge Tests:{RESET}")
    for name, passed, detail in edge_results:
        sym = f"{GREEN}PASS{RESET}" if passed else f"{RED}FAIL{RESET}"
        print(f"  {sym}  {name:<30} {detail}")

    print(f"\n{BOLD}Scenario Results:{RESET}")
    scored = [s for s in all_scores if s[2] is not None]
    no_callback = [s for s in all_scores if s[2] is None]

    for sid, name, score in scored:
        color = GREEN if score >= 80 else (YELLOW if score >= 50 else RED)
        bar = "█" * int((score or 0) // 5) + "░" * (20 - int((score or 0) // 5))
        print(f"  {color}{score:>3}/100{RESET}  {bar}  {name}")

    if no_callback:
        print(f"\n{YELLOW}  ⚠️  No callback received for:{RESET}")
        for sid, name, _ in no_callback:
            print(f"     - {name}")
        print(f"{YELLOW}  → Point your callback URL to http://localhost:{WEBHOOK_PORT}/webhook{RESET}")

    if scored:
        avg = sum(s[2] for s in scored) / len(scored)
        color = GREEN if avg >= 80 else (YELLOW if avg >= 50 else RED)
        print(f"\n{BOLD}  Average Score: {color}{avg:.1f}/100{RESET}")

    # 8 Gap Summary
    print(f"\n{BOLD}8 Gap Status (from last callback received):{RESET}")
    print(f"  If all scenarios show ✅ FIXED → you are ready to submit")
    print(f"  Any ❌ STILL BROKEN → fix that specific gap before finale")

    print(f"\n{BOLD}{GREEN}Done!{RESET}\n")


if __name__ == "__main__":
    main()