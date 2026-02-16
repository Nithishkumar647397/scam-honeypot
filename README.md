# Agentic Honey-Pot for Scam Detection & Intelligence Extraction

**GUVI | HCL Hackathon 2026 - Problem Statement 2**

![Python](https://img.shields.io/badge/Python-3.10+-blue) ![Flask](https://img.shields.io/badge/Flask-3.x-green) ![Groq](https://img.shields.io/badge/LLM-Llama--3.1--8b-orange) ![Render](https://img.shields.io/badge/Deploy-Render-purple) ![Tests](https://img.shields.io/badge/Tests-179%20passed-brightgreen)

---

## Overview

Traditional scam prevention is reactive (block & warn). This system is **proactive** -- it detects scam intent, engages scammers in multi-turn conversation, and extracts actionable cyber-threat intelligence.

The Agentic Honey-Pot adopts the persona of a gullible elderly victim ("Mrs. Kamala Devi") to:

- **Waste scammer time** -- preventing them from targeting real victims
- **Extract actionable intelligence** -- UPI IDs, bank accounts, phone numbers, phishing links
- **Detect behavioral red flags** -- escalating pressure, identity switching, verification evasion
- **Report findings** via secure callback to the GUVI evaluation endpoint

---

## Architecture

```
                         REQUEST FLOW

  Scammer Message
        |
        v
  POST /honeypot -----> Auth Check (x-api-key)
        |                    |
        |              [401 if invalid]
        v
  Abuse Check (detector.py)
        |
        +--- critical ---> Disengage (empty reply)
        |
        v
  Scam Detection (detector.py)
        |--- Keyword pattern matching (urgency, threat, payment, etc.)
        |--- Financial identifier extraction (UPI, bank, phone, URL)
        |--- Context modifiers (safe contexts reduce, amplifying boost)
        |--- Conversation history analysis
        |
        v
  Intelligence Extraction (extractor.py)
        |--- Current message extraction
        |--- Conversation history re-extraction
        |--- Merge & deduplicate
        |
        v
  Session Update (session.py)
        |--- Append message to history
        |--- Merge indicators & intelligence
        |--- Update confidence score
        |
        v
  Playbook Detection (detector.py)
        |--- Match against 9 known scam sequences
        |--- Predict next expected scammer action
        |
        v
  Red Flag Detection (detector.py)
        |--- Escalating pressure
        |--- Identity switching
        |--- Multiple payment channels
        |--- Verification evasion
        |--- Rapid payment escalation
        |
        v
  Agent Reply Generation (agent.py)
        |--- Select conversation phase (initial/trust/probing/extraction)
        |--- Choose probing question per playbook type
        |--- Build red flag context
        |--- LLM generates in-character response via Groq
        |--- Clean & sanitize output
        |
        v
  Callback Check (session.py + callback.py)
        |--- First callback: max messages / intel threshold / high confidence
        |--- Update callback: new intel / engagement depth
        |
        v
  JSON Response { status, reply }
```

### Inter-Module Data Flow

```
patterns.py          Regex extractors (UPI, bank, phone, IFSC, URL, email)
     |
     v
extractor.py         Normalizes text, runs extractors, merges intelligence
     |
     v
detector.py          Uses patterns for detection + adds keyword scoring,
     |                abuse tiers, playbook matching, red flags
     v
agent.py             Consumes detection results + intel to build LLM prompt,
     |                selects probing questions, generates persona reply
     v
session.py           Stores conversation state, tracks callback triggers
     |
     v
callback.py          Formats payload, sends async POST to GUVI endpoint
     |
     v
app.py               Flask routes, orchestrates the full pipeline
```

---

## Module Reference

### `src/app.py` -- Flask Application & API Routes

The main entry point. Orchestrates the request pipeline from auth through detection, extraction, reply generation, and callback.

**Routes:**
| Route | Methods | Description |
|---|---|---|
| `/` | GET, POST, OPTIONS | Root -- GET returns service info, POST processes messages |
| `/honeypot` | GET, POST, OPTIONS | Primary API endpoint for scam message processing |
| `/health` | GET | Health check (returns `{"status": "healthy"}`) |
| `/dashboard` | GET | Serves the monitoring dashboard HTML page |
| `/chat` | GET | Serves the WhatsApp-style chat testing UI |
| `/test` | GET | Serves the test page |
| `/debug/dashboard` | GET | Returns all active sessions as JSON (auth required) |
| `/debug/session/<id>` | GET | Returns a single session's full state (auth required) |

### `src/agent.py` -- LLM Persona Engine

Manages the AI persona, conversation phases, and LLM interaction via Groq.

**Key functions:**
| Function | Description |
|---|---|
| `generate_agent_reply()` | Main entry -- builds prompt, calls Groq LLM, returns cleaned reply |
| `generate_agent_notes()` | Produces structured analysis notes for the callback payload |
| `build_system_prompt()` | Constructs the LLM system prompt with persona, phase, probing context |
| `analyze_tactics()` | Detects 14 tactic types from conversation history |
| `calculate_sophistication()` | Rates scammer sophistication as low/medium/high |
| `_select_probing_question()` | Picks context-aware probing question per playbook + phase |
| `_build_red_flag_context()` | Summarizes behavioral red flags for prompt injection |
| `detect_language()` | Classifies text as english/hindi/hinglish |
| `get_conversation_phase()` | Returns current phase based on message count |
| `generate_fake_data()` | Creates deterministic honey tokens to bait scammers |

**Conversation Phases:**
| Phase | Messages | Strategy |
|---|---|---|
| `initial` | 0-2 | Panic, confusion, build rapport |
| `trust_building` | 3-5 | Show willingness, ask clarifying questions |
| `probing` | 6-9 | Ask for identity verification, delay with excuses |
| `extraction` | 10+ | Stall aggressively, ask for alternate accounts/numbers |

**Playbook-Specific Probing:** The agent selects from 7 sets of scenario-specific questions (account_block, kyc_fraud, lottery_scam, refund_trap, job_fraud, traffic_challan, tech_support) plus 4 generic categories (identity_verification, contact_elicitation, authority_challenge, stalling).

### `src/detector.py` -- Scam Detection Engine

Multi-indicator weighted scoring with context modifiers, abuse classification, playbook matching, and behavioral red flags.

**Key functions:**
| Function | Description |
|---|---|
| `detect_scam()` | Returns `(is_scam, confidence, indicators, modifiers)` |
| `check_abuse()` | Classifies abuse tier: critical/severe/moderate/none |
| `detect_playbook()` | Matches conversation against 9 known scam playbook sequences |
| `detect_red_flags()` | Detects 5 behavioral patterns across conversation history |
| `apply_context_modifiers()` | Adjusts confidence for safe/amplifying context |
| `calculate_severity()` | Maps indicators to high/medium/low severity |

**Indicator Weights:**
| Indicator | Weight | Trigger Examples |
|---|---|---|
| `payment_request` | 0.25 | "send money", "pay now", "rs.", "deposit" |
| `threat` | 0.20 | "blocked", "arrested", "legal action" |
| `credential_request` | 0.20 | "otp", "pin", "cvv", "aadhaar" |
| `suspicious_link` | 0.20 | Any URL detected in message |
| `urgency` | 0.15 | "immediately", "hurry", "last chance" |
| `authority_impersonation` | 0.15 | "bank manager", "rbi", "officer" |
| `prize_offer` | 0.15 | "winner", "lottery", "congratulations" |
| `contains_upi` | 0.10 | UPI ID pattern detected |
| `contains_bank_account` | 0.10 | Bank account number pattern |
| `contains_phone` | 0.05 | Phone number pattern |

**Scam threshold:** `confidence >= 0.3` OR `indicators >= 2`

**Known Playbooks:** account_block, kyc_fraud, lottery_scam, refund_trap, job_fraud, traffic_challan, tech_support, customs_scam, investment_fraud

**Red Flags (conversation-level):**
| Flag | Description |
|---|---|
| `escalating_pressure` | Urgency in 2+ of last 3 messages |
| `identity_switching` | Claims 2+ authority roles |
| `multiple_payment_channels` | Provides 2+ payment methods |
| `verification_evasion` | Ignores agent's identity verification questions |
| `rapid_payment_escalation` | Payment demands in 3+ messages |

### `src/extractor.py` -- Intelligence Extraction

Extracts financial identifiers with text normalization for obfuscated data.

**Key functions:**
| Function | Description |
|---|---|
| `extract_intelligence()` | Extracts all identifier types from a single message |
| `extract_from_conversation()` | Aggregates intelligence across conversation history |
| `merge_intelligence()` | Merges two intelligence dicts with deduplication |
| `normalize_text()` | Converts obfuscated text (number words, spaced digits) to digits |
| `count_intelligence()` | Counts high-value items for callback trigger decisions |
| `has_sufficient_intelligence()` | Checks if extraction meets minimum threshold |
| `format_intelligence_summary()` | Formats intelligence for human-readable notes |

**Normalization pipeline:**
1. English number words ("nine eight seven") to digits
2. Hindi number words ("nau aath saat") to digits
3. "at"/"AT" to "@" symbol
4. Dot-separated digits ("9.8.7.6") to contiguous digits
5. Spaced single digits ("9 8 7 6") to contiguous digits

**Extracted categories:** UPI IDs, bank accounts, phone numbers, IFSC codes, phishing links, emails, scammer IDs, suspicious keywords

### `src/patterns.py` -- Regex Pattern Library

All regex extractors for Indian financial identifiers.

**Extractors:**
| Function | Pattern | Examples |
|---|---|---|
| `find_upi_ids()` | `user@provider` with known UPI domains | `fraud@paytm`, `scam@ybl` |
| `find_bank_accounts()` | 9-18 digit numbers (excluding phone-length) | `12345678901234` |
| `find_phone_numbers()` | Indian mobile numbers with optional +91 | `+919876543210` |
| `find_ifsc_codes()` | 4 letters + 0 + 6 alphanumeric | `SBIN0001234` |
| `find_urls()` | HTTP/HTTPS URLs + known shorteners | `https://fake-bank.com` |
| `find_emails()` | Standard email format (excludes UPI domains) | `scammer@gmail.com` |
| `find_scam_keywords()` | English + Hinglish scam vocabulary | "urgent", "block", "otp batao" |
| `find_scammer_ids()` | Employee IDs, reference numbers, badge numbers | `EMP12345` |

### `src/session.py` -- Session Management

Thread-safe in-memory session store with auto-expiry.

**Key functions:**
| Function | Description |
|---|---|
| `create_session()` | Creates new session with default state |
| `get_session()` | Retrieves session (returns None if expired or missing) |
| `update_session()` | Updates session fields, appends messages, merges intelligence |
| `delete_session()` | Removes a session |
| `should_send_callback()` | Determines if callback should fire based on triggers |
| `clear_all_sessions()` | Clears all sessions (used in tests) |

**Session expiry:** 1 hour of inactivity

**Callback triggers:**
| Trigger | Condition |
|---|---|
| Max messages | `message_count >= MAX_MESSAGES (10)` |
| Intel + engagement | `intel_count >= 2 AND messages >= 6` |
| High confidence | `confidence >= 0.8 AND messages >= 8` |
| Fast fail | `confidence >= 0.9 AND intel >= 1 AND messages >= 4` |
| Update: new intel | `current_intel > last_callback_intel` |
| Update: engagement | `messages >= last_callback_messages + 2` |

### `src/callback.py` -- GUVI Callback Integration

Sends structured intelligence payloads to the GUVI evaluation endpoint asynchronously.

### `src/auth.py` -- API Authentication

Validates `x-api-key` header against `Config.API_SECRET_KEY`. Supports header and query parameter authentication.

### `src/config.py` -- Configuration

Loads settings from environment variables with defaults.

| Setting | Default | Description |
|---|---|---|
| `GROQ_API_KEY` | (required) | Groq API key for LLM access |
| `API_SECRET_KEY` | (required) | API authentication key |
| `GUVI_CALLBACK_URL` | GUVI endpoint | Callback destination URL |
| `MAX_MESSAGES` | 10 | Max messages before forced callback |
| `MIN_INTELLIGENCE_FOR_CALLBACK` | 2 | Min intel items for early callback |
| `GROQ_MODEL` | `llama-3.1-8b-instant` | LLM model identifier |
| `GROQ_MAX_TOKENS` | 150 | Max tokens per LLM response |
| `GROQ_TEMPERATURE` | 0.7 | LLM temperature (creativity) |
| `DEBUG_MODE` | false | Enable debug logging |

---

## API Reference

### `POST /honeypot`

Process a scam message and return the agent's response.

**Headers:**
| Header | Value | Required |
|---|---|---|
| `Content-Type` | `application/json` | Yes |
| `x-api-key` | Your secret key | Yes |

**Request Body:**

```json
{
  "sessionId": "unique-session-id",
  "message": {
    "sender": "scammer",
    "text": "URGENT! Your account is blocked. Send Rs 500 to verify@paytm.",
    "timestamp": 1234567890
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "WhatsApp",
    "language": "English",
    "locale": "IN"
  }
}
```

| Field | Type | Description |
|---|---|---|
| `sessionId` | string | Unique session identifier from platform |
| `message.sender` | string | `"scammer"` or `"user"` |
| `message.text` | string | Message content |
| `message.timestamp` | number | Epoch time in milliseconds |
| `conversationHistory` | array | Previous messages (empty for first message) |
| `metadata.channel` | string | SMS / WhatsApp / Email / Chat |
| `metadata.language` | string | Language used |
| `metadata.locale` | string | Country or region code |

**Also accepts:** flat `{"text": "..."}` and string `{"message": "..."}` formats for flexibility.

**Responses:**

```json
// 200 OK
{ "status": "success", "reply": "Oh no! My account is blocked? What should I do beta?" }

// 401 Unauthorized
{ "status": "error", "message": "Unauthorized" }

// 500 Internal Error
{ "status": "error", "message": "Internal Server Error" }
```

### `GET /health`

Returns `{"status": "healthy"}` with 200 status.

### `GET /debug/dashboard`

Returns all active sessions. Requires `x-api-key` header.

```json
{
  "status": "success",
  "count": 3,
  "sessions": {
    "session-001": {
      "session_id": "session-001",
      "message_count": 8,
      "scam_detected": true,
      "confidence": 0.65,
      "indicators": ["urgency", "threat", "payment_request"],
      "extracted_intelligence": { "upiIds": ["fraud@paytm"], "phoneNumbers": ["9876543210"] },
      "conversation_history": ["...last 10 messages..."],
      "last_activity": "2026-02-16 10:30:00"
    }
  }
}
```

### `GET /debug/session/<session_id>`

Returns a single session's full state. Requires `x-api-key` header.

---

## Callback Payload

The system sends structured intelligence to the GUVI evaluation endpoint using a **Smart Progressive** callback strategy.

```json
{
  "sessionId": "abc123-session-id",
  "scamDetected": true,
  "totalMessagesExchanged": 14,
  "extractedIntelligence": {
    "bankAccounts": ["XXXX-XXXX-7842"],
    "upiIds": [
      {"value": "scammer@ybl", "confidence": 0.95, "source": "message_4"},
      {"value": "backup@paytm", "confidence": 0.78, "source": "message_11"}
    ],
    "phishingLinks": ["http://malicious-link.example"],
    "phoneNumbers": ["+919876543210"],
    "suspiciousKeywords": ["urgent", "verify now", "account blocked"]
  },
  "scammerProfile": {
    "scamType": "UPI_FRAUD",
    "severity": "HIGH",
    "sophisticationLevel": "medium",
    "tacticsObserved": ["urgency", "authority_impersonation", "fear"],
    "languageUsed": "Hinglish",
    "multipleAccountsProvided": true
  },
  "agentNotes": "Scammer posed as SBI officer. Used urgency tactics..."
}
```

---

## Installation & Setup

### Prerequisites

- Python 3.10+
- Groq API Key ([Get one here](https://console.groq.com))

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/scam-honeypot.git
cd scam-honeypot
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure Environment

Create a `.env` file in the root directory:

```env
GROQ_API_KEY=your_groq_api_key_here
API_SECRET_KEY=my_secret_key_123
GUVI_CALLBACK_URL=https://hackathon.guvi.in/api/updateHoneyPotFinalResult
```

### 4. Run Locally

```bash
python -m src.app
```

Access the API at `http://localhost:5000`.

### 5. Run with Gunicorn (Production)

```bash
gunicorn -w 4 -b 0.0.0.0:5000 src.app:app
```

---

## Project Structure

```
scam-honeypot/
├── src/
│   ├── app.py              # Flask application & API routes
│   ├── agent.py            # LLM persona engine, probing strategy, reply generation
│   ├── detector.py         # Scam detection, playbooks, abuse tiers, red flags
│   ├── extractor.py        # Intelligence extraction, normalization, merging
│   ├── patterns.py         # Regex extractors for Indian financial identifiers
│   ├── session.py          # Thread-safe session management with auto-expiry
│   ├── callback.py         # GUVI callback integration (async POST)
│   ├── auth.py             # API key validation
│   ├── config.py           # Configuration (env variables + defaults)
│   └── templates/
│       ├── chat.html       # WhatsApp-style interactive chat UI
│       ├── dashboard.html  # Session monitoring dashboard
│       └── test.html       # API test page
├── tests/
│   ├── test_agent.py       # 54 tests: persona, phases, probing, tactics, notes
│   ├── test_detector.py    # 40 tests: detection, abuse, playbooks, red flags
│   ├── test_extractor.py   # 33 tests: extraction, normalization, merging
│   ├── test_patterns.py    # 36 tests: all regex extractors
│   ├── test_session.py     # 16 tests: session CRUD, callbacks
│   └── __init__.py
├── requirements.txt
├── render.yaml             # Render deployment config
├── Procfile
├── .env.example
└── README.md
```

---

## Testing

### Run All Tests

```bash
python -m pytest tests/ -v
```

**179 tests** across 5 modules, covering:
- Scam detection accuracy (keyword matching, confidence scoring, thresholds)
- Abuse tier classification (critical, severe, moderate)
- Playbook sequence matching (9 known scam types)
- Behavioral red flag detection (5 conversation-level patterns)
- Intelligence extraction (UPI, bank accounts, phones, IFSC, URLs, emails)
- Text normalization (English/Hindi number words, obfuscated digits)
- Agent persona and conversation phases
- Probing question selection (playbook-specific + generic)
- Session lifecycle (create, update, delete, expiry)
- Callback trigger logic (first callback + update callbacks)

### Run Specific Test Suites

```bash
python -m pytest tests/test_detector.py -v    # Scam detection
python -m pytest tests/test_extractor.py -v   # Intelligence extraction
python -m pytest tests/test_agent.py -v       # Agent logic
python -m pytest tests/test_patterns.py -v    # Regex patterns
python -m pytest tests/test_session.py -v     # Session management
```

### Manual API Test

```bash
curl -X POST https://scam-honeypot-y77x.onrender.com/honeypot \
  -H "Content-Type: application/json" \
  -H "x-api-key: your_secret_key" \
  -d '{
    "sessionId": "test-001",
    "message": {
      "sender": "scammer",
      "text": "Your SBI account KYC expired. Update now or account will be blocked.",
      "timestamp": 1770005528731
    },
    "conversationHistory": [],
    "metadata": {"channel": "SMS", "language": "English", "locale": "IN"}
  }'
```

---

## Tech Stack

| Component | Technology | Why |
|---|---|---|
| Language | Python 3.10+ | Rich NLP ecosystem, fast development |
| Framework | Flask + Gunicorn | Lightweight, production-ready |
| AI Model | Llama-3.1-8b via Groq API | Ultra-fast inference (~300ms), free tier |
| Data Extraction | Regex + NLP patterns | Reliable, no external dependencies |
| Session Store | In-memory (thread-safe dict) | Zero latency, sufficient for hackathon scale |
| Deployment | Render Cloud | Free tier, auto-deploy from Git |

---

## Live Demo

- **API Endpoint:** `https://scam-honeypot-y77x.onrender.com/honeypot`
- **Dashboard:** `https://scam-honeypot-y77x.onrender.com/dashboard`
- **Chat Tester:** `https://scam-honeypot-y77x.onrender.com/chat`

---

## Ethical Considerations

| Principle | Implementation |
|---|---|
| No Impersonation | Uses fictional persona "Mrs. Kamala Devi" -- not a real individual |
| No Illegal Instructions | Agent never provides real financial credentials or performs transactions |
| No Harassment | Agent remains polite and non-threatening at all times |
| Responsible Data Handling | No persistent storage -- session data held in memory only |
| Safe Engagement | Agent never shares real personal data |

---

## Limitations

- In-memory session storage (non-persistent across restarts)
- Dependent on LLM API availability (Groq)
- Regex-based extraction may miss novel obfuscation patterns

---

## Contributors

- **Member A** -- AI Agent Logic, LLM Integration, Intelligence Extraction Engine
- **Member B** -- Infrastructure, API Design, Session Management, Deployment

<p align="center"><b>Built for India AI Impact Buildathon</b></p>
