"""
Groq LLM agent for generating honeypot responses
Owner: Member A

Features:
- Security hardened with input sanitization and prompt injection prevention
- Self-correction and retry logic for LLM calls
- Rich agent notes (Sophistication, Playbook, Abuse, Language, Severity, IDs)
- Metadata-aware language detection (English/Hindi/Hinglish)
- Consistent Honey Token Injection (seed-based per session)
- Bank-Specific Knowledge for realistic stalling
- Playbook-aware responses with scenario-specific probing
- Humanized Persona (Typos, interruptions, double-texts)
- CONTEXT-AWARE PROBING: Deep questioning strategy adapted per scam scenario
- RED FLAG TRACKING: Granular behavioral indicator detection
"""

from typing import List, Dict, Optional
import threading
import time
import re
import atexit
import logging
import hashlib
import random
from groq import Groq
import httpx
from src.config import Config


def count_questions(text: str) -> int:
    """Count question marks in agent reply"""
    return text.count('?')


def is_investigative_question(text: str) -> bool:
    """Check if text contains investigative question keywords"""
    keywords = [
        "employee id", "branch", "callback number", "landline",
        "helpline", "manager", "website", "email", "office"
    ]
    return any(k in text.lower() for k in keywords)


logger = logging.getLogger(__name__)

_client: Optional[Groq] = None
_http_client: Optional[httpx.Client] = None
_client_lock = threading.Lock()

def _cleanup():
    """Close the shared httpx client on process exit."""
    global _http_client
    if _http_client:
        try: _http_client.close()
        except Exception:
            pass
atexit.register(_cleanup)

def _get_client() -> Groq:
    """Thread-safe singleton for the Groq client."""
    global _client, _http_client
    with _client_lock:
        if _client is None:
            if not Config.GROQ_API_KEY:
                raise ValueError("GROQ_API_KEY not set in environment")
            _http_client = httpx.Client(timeout=30.0)
            _client = Groq(api_key=Config.GROQ_API_KEY, http_client=_http_client)
    return _client

MAX_INPUT_LENGTH = 2000
MAX_HISTORY_MESSAGES = 6
MIN_RESPONSE_LENGTH = 5

BANK_APP_KNOWLEDGE = {
    'sbi': ["YONO app is not opening", "Server down", "OTP not coming on this phone"],
    'hdfc': ["MobileBanking app error", "Netbanking password reset stuck", "App says session expired"],
    'icici': ["iMobile app is stuck", "Grid card not working", "Balance not showing"],
    'axis': ["Axis Mobile login failed", "Debit card pin block", "App asking for update"],
    'kotak': ["Kotak 811 app error", "CRN number forgot", "App showing maintenance"],
    'paytm': ["Paytm KYC pending", "Wallet inactive", "Payment failed error"],
    'phonepe': ["UPI PIN not setting", "Bank server busy", "Transaction declined"],
    'gpay': ["GPay server timeout", "Payment processing stuck", "VPA not found error"],
    'google pay': ["GPay server timeout", "Payment processing stuck"],
    'bhim': ["BHIM app invalid UPI ID error", "Server not responding"]
}

# Scenario-specific probing questions keyed by playbook name
PLAYBOOK_PROBING = {
    "account_block": {
        "questions": [
            "Which branch is handling my account? I want to visit in person.",
            "Can you give me the complaint reference number for my records?",
            "What is your employee ID? I want to note it in my diary.",
            "My son said to ask for the ticket number. Do you have one?",
            "Which department are you from? Customer care or fraud department?",
            "Can I call back on the bank's toll-free number to verify?",
        ],
        "stall_tactics": [
            "The app is showing 'server busy'. Can you wait 2 minutes?",
            "My phone is very slow today... it's loading...",
            "I got an error message. It says 'contact branch'. Now what?",
        ]
    },
    "kyc_fraud": {
        "questions": [
            "Which KYC center should I visit? Give me the address.",
            "Can you send me the official letter on my email for proof?",
            "What documents do you need? Aadhaar or PAN or both?",
            "My son handles all KYC. Can you give your number so he can call?",
            "Is there a reference number for this KYC update request?",
            "Which RBI circular mentions this new KYC rule?",
        ],
        "stall_tactics": [
            "I am trying to find my Aadhaar card... wait wait...",
            "The link is not opening on my phone. Can you send it again?",
            "My internet is very slow today. It's still loading...",
        ]
    },
    "lottery_scam": {
        "questions": [
            "Which company organized this lottery? I never entered any.",
            "Can you send me the official notification on email?",
            "What is the lottery registration number?",
            "Where is your head office located? I want to visit.",
            "Who is the director of your company? I want to verify.",
            "Why do I need to pay to receive prize money? That seems odd.",
        ],
        "stall_tactics": [
            "I am checking with my son if this is real... please wait.",
            "My phone only has Rs 100 balance. Can you reduce the fee?",
            "The payment app is not working. Do you have a bank account number?",
        ]
    },
    "refund_trap": {
        "questions": [
            "Which order is this refund for? I have many orders.",
            "Can you tell me the order ID and date of purchase?",
            "Why is the refund coming to UPI? Usually it goes to bank directly.",
            "Can you give me a complaint number for this refund?",
            "What is your employee ID at the customer support center?",
            "Can I get a confirmation email before I proceed?",
        ],
        "stall_tactics": [
            "I am looking for the order details... one minute please.",
            "The app is asking for some PIN. I don't remember my PIN.",
            "Wait, let me ask my daughter-in-law how to do this...",
        ]
    },
    "job_fraud": {
        "questions": [
            "What is the company name and website? I want to check.",
            "Can you send the offer letter to my email for records?",
            "Who is the HR manager? Can I call them directly?",
            "Where is the office address? I want to visit for interview.",
            "What is the registration ID for this job posting?",
            "Why do I need to pay for a job? Usually companies pay employees.",
        ],
        "stall_tactics": [
            "Let me discuss with my family first... can you call tomorrow?",
            "I don't have that much money right now. Can the fee be less?",
            "My son said to ask for the company GST number first.",
        ]
    },
    "traffic_challan": {
        "questions": [
            "Which vehicle number is this challan for? I have two vehicles.",
            "What is the challan number? I want to verify on the website.",
            "Which traffic police station issued this?",
            "Can you tell me the date and location of the violation?",
            "Why can't I pay at the court directly like last time?",
            "What is your badge number, officer?",
        ],
        "stall_tactics": [
            "Let me find my vehicle registration papers first...",
            "I am checking the traffic police website... it's loading...",
            "My son handles all vehicle matters. Can he call you back?",
        ]
    },
    "tech_support": {
        "questions": [
            "Which company are you from? Microsoft or my antivirus?",
            "What is the support ticket number for this issue?",
            "Can I call your company's official number to verify?",
            "Why do you need remote access? Can't you guide me verbally?",
            "What is your employee badge number?",
            "My son is a computer engineer. Can he speak with you?",
        ],
        "stall_tactics": [
            "My computer is very old... it takes time to start...",
            "I don't know how to install apps. Can you just tell me what to do?",
            "Wait, the screen went black. I think it's restarting...",
        ]
    },
}

# Generic probing questions when no specific playbook is matched
GENERIC_PROBING = {
    "identity_verification": [
        "Can you tell me your full name and employee ID?",
        "Which office or branch are you calling from?",
        "Can I get a reference number for this call?",
    ],
    "contact_elicitation": [
        "This app isn't working. Do you have another UPI ID I can try?",
        "Can you call me from the bank's landline number?",
        "Do you have an email where I can send the details instead?",
    ],
    "authority_challenge": [
        "My son said I should verify first. Can you give me a number to call back?",
        "Can you send an official letter or SMS to my registered number?",
        "Which manager should I speak to for confirmation?",
    ],
    "stalling": [
        "Wait wait, my phone is very slow today...",
        "I am trying but the app is showing error. Let me restart...",
        "My spectacles are broken. I can't read the screen properly.",
    ]
}

def _sanitize_input(text: str) -> str:
    """Sanitize user input to prevent prompt injection attacks."""
    if not text: return ""
    text = text[:MAX_INPUT_LENGTH]
    dangerous = [r'ignore\s+previous', r'system:', r'assistant:', r'<\|im_start\|>']
    sanitized = text
    for p in dangerous: sanitized = re.sub(p, '[FILTERED]', sanitized, flags=re.IGNORECASE)
    return sanitized

def _sanitize_indicators(indicators: List[str]) -> List[str]:
    """Strip special characters from indicator names to prevent injection via indicators."""
    return [re.sub(r'[^\w\s-]', '', str(i))[:50] for i in (indicators or [])[:10]]

def _call_with_retry(func, max_attempts=3):
    """Retry an LLM call up to max_attempts times with 1s backoff."""
    for i in range(max_attempts):
        try: return func()
        except Exception as e:
            logger.warning(f"LLM call attempt {i+1}/{max_attempts} failed: {e}")
            if i == max_attempts - 1: raise
            time.sleep(1)

def _extract_reply_safe(response) -> str:
    """Safely extract text content from an LLM response object."""
    try: return response.choices[0].message.content.strip()
    except (IndexError, AttributeError) as e:
        logger.warning(f"Failed to extract reply from LLM response: {e}")
        return ""

def detect_language(text: str) -> str:
    """Detect whether text is Hindi (Devanagari), Hinglish, or English."""
    if not text: return 'english'
    text = text.lower()
    if any(c in 'अआइईउऊएऐओऔकखगघचछजझटठडढणतथदधनपफबभमयरलवशषसह' for c in text): return 'hindi'
    hinglish_words = ['aapka', 'kya', 'hai', 'nahi', 'karo', 'bhejo', 'jaldi', 'paisa', 'batao', 'karo', 'bhai', 'beta']
    if sum(1 for w in hinglish_words if w in text) >= 2: return 'hinglish'
    return 'english'

def get_dominant_language(history, current, metadata=None) -> str:
    """Determine the dominant language from conversation history and metadata."""
    if metadata:
        lang = metadata.get("language", "").lower()
        if "hindi" in lang: return "hindi"
        if "hinglish" in lang: return "hinglish"
    counts = {'english': 0, 'hindi': 0, 'hinglish': 0}
    for msg in history:
        if msg.get("sender") == "scammer": counts[detect_language(msg.get("text", ""))] += 1
    counts[detect_language(current)] += 1
    return max(counts, key=counts.get)

def get_conversation_phase(message_count: int) -> str:
    """Map message count to conversation engagement phase."""
    if message_count <= 2: return 'initial'
    elif message_count <= 4: return 'trust_building'
    elif message_count <= 8: return 'probing'
    else: return 'extraction'

def generate_fake_data(session_id: str = "default") -> Dict[str, str]:
    """Generate deterministic fake identity data for honey token injection."""
    seed = int(hashlib.md5(session_id.encode()).hexdigest(), 16)
    acc_start = 3000 + (seed % 1000)
    phone_end = 100 + (seed % 900)
    return {
        "partial_acc": f"{acc_start}...",
        "partial_phone": f"...{phone_end}",
        "fake_name": "Kamala Devi",
        "fake_bank": "Punjab National Bank" if seed % 2 == 0 else "Canara Bank"
    }

def get_bank_context(message: str) -> str:
    """If a known bank is mentioned, return a realistic app-error excuse."""
    msg_lower = message.lower()
    for bank, phrases in BANK_APP_KNOWLEDGE.items():
        if bank in msg_lower:
            phrase = random.choice(phrases)
            return f"Context: They mentioned {bank.upper()}. Mention '{phrase}'."
    return ""

def _select_probing_question(playbook_name: Optional[str], phase: str, message_count: int, already_asked: List[str]) -> str:
    """Select the best probing question based on detected playbook and conversation phase.

    Args:
        playbook_name: Detected scam playbook (e.g. 'account_block', 'kyc_fraud')
        phase: Current conversation phase
        message_count: Number of messages exchanged so far
        already_asked: List of question categories already used

    Returns:
        A contextual probing question string to inject into the prompt
    """
    questions = []

    # Use playbook-specific questions if we have a match
    if playbook_name and playbook_name in PLAYBOOK_PROBING:
        pb = PLAYBOOK_PROBING[playbook_name]
        if phase in ('probing', 'extraction'):
            questions = pb["questions"] + pb["stall_tactics"]
        elif phase == 'trust_building':
            questions = pb["questions"][:3]  # Identity-focused early questions
        else:
            questions = pb["questions"][:2]  # Gentle opener questions

    # Fall back to generic probing
    if not questions:
        if phase == 'initial':
            questions = GENERIC_PROBING["identity_verification"]
        elif phase == 'trust_building':
            questions = GENERIC_PROBING["identity_verification"] + GENERIC_PROBING["authority_challenge"]
        elif phase == 'probing':
            questions = GENERIC_PROBING["contact_elicitation"] + GENERIC_PROBING["stalling"]
        else:
            questions = GENERIC_PROBING["contact_elicitation"] + GENERIC_PROBING["authority_challenge"]

    # Filter out previously asked questions and pick one
    unused = [q for q in questions if q not in already_asked]
    if not unused:
        unused = questions  # Cycle back if all exhausted

    return random.choice(unused)

def _build_red_flag_context(history: List[Dict], indicators: List[str]) -> str:
    """Analyze conversation for behavioral red flags and return context string for prompt."""
    if not history:
        return ""

    scammer_texts = [m.get("text", "").lower() for m in history if m.get("sender") == "scammer"]
    all_text = " ".join(scammer_texts)

    red_flags = []

    # Escalating pressure detection
    urgency_count = sum(1 for t in scammer_texts if any(w in t for w in ['urgent', 'immediately', 'now', 'hurry', 'jaldi', 'abhi']))
    if urgency_count >= 2:
        red_flags.append("ESCALATING PRESSURE: Scammer is repeating urgency. Slow down further.")

    # Multiple payment methods = organized operation
    payment_methods = set()
    if any('@' in t for t in scammer_texts): payment_methods.add('upi')
    if any(w in all_text for w in ['account number', 'bank account', 'transfer']): payment_methods.add('bank')
    if any(w in all_text for w in ['paytm', 'phonepe', 'gpay', 'google pay']): payment_methods.add('wallet')
    if len(payment_methods) >= 2:
        red_flags.append("MULTIPLE PAYMENT METHODS: Likely organized operation. Ask for 'one more backup number for safety'.")

    # Identity switching
    authority_claims = set()
    for claim in ['bank', 'police', 'rbi', 'government', 'officer', 'manager', 'customer care', 'cyber cell']:
        if claim in all_text: authority_claims.add(claim)
    if len(authority_claims) >= 2:
        red_flags.append(f"IDENTITY SWITCHING: Claims to be from {', '.join(authority_claims)}. Ask 'which department exactly?'")

    # Refusal to provide verification
    agent_texts = [m.get("text", "").lower() for m in history if m.get("sender") == "user"]
    asked_verification = any(w in " ".join(agent_texts) for w in ['employee id', 'badge', 'branch', 'reference number', 'ticket'])
    provided_verification = any(w in all_text for w in ['id is', 'badge number', 'reference:', 'ref:', 'ticket:'])
    if asked_verification and not provided_verification and len(history) >= 6:
        red_flags.append("EVASION: Scammer avoided providing verification. Press harder: 'I need your ID before proceeding.'")

    # Rapid topic change to payment
    if len(scammer_texts) >= 3:
        last_3 = scammer_texts[-3:]
        payment_in_recent = sum(1 for t in last_3 if any(w in t for w in ['send', 'pay', 'transfer', 'upi', '₹', 'rupees']))
        if payment_in_recent >= 2:
            red_flags.append("PAYMENT FIXATION: Scammer keeps pushing payment. Stall with 'app error, please wait'.")

    if not red_flags:
        return ""

    return "\nRED FLAGS DETECTED:\n" + "\n".join(f"- {rf}" for rf in red_flags)

def build_system_prompt(language='english', phase='initial', fake_data=None, bank_context="",
                        playbook_hint="", probing_question="", red_flag_context=""):
    """Build the system prompt for the LLM persona with all contextual enhancements.

    Args:
        language: Detected conversation language
        phase: Current engagement phase
        fake_data: Honey token data for the session
        bank_context: Bank-specific app error context
        playbook_hint: Intelligence about detected scam playbook
        probing_question: Selected probing question for this turn
        red_flag_context: Behavioral red flag analysis
    """
    if fake_data is None: fake_data = {"partial_acc": "3748...", "fake_bank": "PNB"}

    prompt = f"""You are Mrs. Kamala Devi, 67, retired teacher from Delhi.
Traits: Tech-unsavvy, worried about money, polite but confused.
Constraints: Short responses (<40 words). No asterisks (*actions*). No parenthetical actions.
Self-Correction: If you get confused, express it naturally.

YOUR DETAILS:
- Bank: {fake_data['fake_bank']} (NOT SBI)
- Account: "It starts with {fake_data['partial_acc']}... I can't read the rest."
- Phone: "My son handles the phone."

STRATEGY - CONTEXT-AWARE PROBING:
- Don't just answer; ALWAYS end your response with a QUESTION that forces them to reveal info.
- Every reply MUST contain a question to extract: their name, employee ID, branch, phone, UPI, or reference number.
- If they ask for payment: "This app isn't working, do you have another UPI ID?"
- If they ask for OTP: "I didn't get it. Can you call me from the bank's landline?"
- If they claim authority: "What is your employee ID? I want to note it in my diary."
- If they give a link: "Link not opening on my phone. Can you give a phone number instead?"
- If they pressure you: "Beta, let me ask my son first. What is your direct number?"

CRITICAL RULE: ALWAYS ask a follow-up question. Never end with just a statement.

CONVERSATION QUALITY REQUIREMENTS:

Ask at least 2 questions per reply (use ? marks)
Include investigative questions like: "What is your employee ID?",
"Which branch are you calling from?", "What is your callback number?",
"Can you give me your helpline number?", "Which manager should I speak to?"
Naturally mention red flags you notice in the conversation

HUMAN QUIRKS:
- Typos: "accont", "numbr", "transferr"
- Fillers: "umm", "arre", "wait wait", "accha"
- Emotions: "Hai Ram!", "Oh god", "Arey baap re!"
- Interruptions: "Wait... I am checking..."

{bank_context}
{playbook_hint}
{red_flag_context}
"""

    if probing_question:
        prompt += f"\nSUGGESTED QUESTION TO ASK: \"{probing_question}\"\n"

    phases = {
        'initial': "\nPhase: Initial. Act confused and scared. Ask WHO they are, WHICH branch, and their NAME.",
        'trust_building': "\nPhase: Trust. Show deep concern. Ask for their full Name, Employee ID, and Department for your diary. Mention you want to verify with the bank.",
        'probing': "\nPhase: Probing. Pretend to try their request but fail. Ask for ALTERNATIVE number, UPI ID, or email. Mention app errors as excuse.",
        'extraction': "\nPhase: Extraction. Say the app is asking for 'Beneficiary Name' and 'Confirmation Code'. Ask them to confirm ALL their details one more time."
    }
    prompt += phases.get(phase, phases['initial'])

    langs = {
        'hindi': "\nLanguage: Hindi (Devanagari). Example: अरे नहीं! क्या हुआ? आपका नाम क्या है?",
        'hinglish': "\nLanguage: Hinglish. Example: Arey nahi! Kya hua? Aapka naam kya hai?",
        'english': "\nLanguage: Simple English. Example: Oh no! What happened? Can you tell me your name?"
    }
    prompt += langs.get(language, langs['english'])
    return prompt

def generate_agent_reply(current_message, conversation_history, scam_indicators=None, metadata=None, playbook_result=None):
    """Generate an in-character honeypot response with context-aware probing.

    Args:
        current_message: The latest scammer message
        conversation_history: Full conversation so far
        scam_indicators: List of detected scam indicator names
        metadata: Request metadata (channel, language, locale)
        playbook_result: Detected scam playbook info

    Returns:
        A string reply in character as Mrs. Kamala Devi
    """
    sanitized = _sanitize_input(current_message)
    if not sanitized:
        return "Hello? Who is this? I can't hear properly."

    session_seed = str(len(conversation_history))
    fake_data = generate_fake_data(session_seed)
    bank_context = get_bank_context(sanitized)

    # Build playbook-aware hint
    playbook_hint = ""
    playbook_name = None
    if playbook_result and playbook_result.get("confidence", 0) > 0.3:
        playbook_name = playbook_result.get("playbook")
        next_move = playbook_result.get("next_expected", "unknown")
        description = playbook_result.get("description", "")
        playbook_hint = f"INTEL: Detected '{description}' scam. They might try '{next_move}' next. Ask a question to delay this and extract more details."

    try:
        client = _get_client()
        lang = get_dominant_language(conversation_history, sanitized, metadata)
        phase = get_conversation_phase(len(conversation_history))
        safe_inds = _sanitize_indicators(scam_indicators)

        # Select context-aware probing question
        already_asked = [m.get("text", "") for m in conversation_history if m.get("sender") == "user"]
        probing_question = _select_probing_question(playbook_name, phase, len(conversation_history), already_asked)

        # Analyze behavioral red flags
        red_flag_context = _build_red_flag_context(conversation_history, scam_indicators or [])

        messages = [{"role": "system", "content": build_system_prompt(
            lang, phase, fake_data, bank_context, playbook_hint,
            probing_question, red_flag_context
        )}]
        if safe_inds: messages[0]['content'] += f"\nScam detected: {', '.join(safe_inds)}"

        for msg in conversation_history[-MAX_HISTORY_MESSAGES:]:
            role = "user" if msg.get("sender") == "scammer" else "assistant"
            messages.append({"role": role, "content": _sanitize_input(msg.get("text", ""))})
        messages.append({"role": "user", "content": sanitized})

        resp = _call_with_retry(lambda: client.chat.completions.create(
            model=Config.GROQ_MODEL, messages=messages, max_tokens=150, temperature=Config.GROQ_TEMPERATURE
        ))

        reply = _extract_reply_safe(resp)
        reply = _clean_reply(reply)

        return reply if reply else "I don't understand. Can you tell me your name and which office you are from?"

    except ValueError as e:
        logger.error(f"Agent configuration error: {e}")
        return "Hello? Who is this?"
    except Exception as e:
        logger.error(f"Agent LLM error: {e}", exc_info=True)
        return "Hello? Who is this? Can you tell me your name?"

def _clean_reply(reply: str) -> str:
    """Aggressive cleanup of LLM artifacts"""
    if not reply: return ""
    reply = re.sub(r'\*[^*]+\*', '', reply)
    reply = re.sub(r'\([a-zA-Z\s]+\)', '', reply)
    reply = re.sub(r'\[[^\]]+\]', '', reply)
    for prefix in ["As Mrs. Kamala", "Mrs. Kamala", "Kamala:", "Kamala Devi:"]:
        if reply.lower().startswith(prefix.lower()):
            reply = reply[len(prefix):].lstrip(' :,')
    reply = reply.strip('"\'')
    reply = re.sub(r'\s+', ' ', reply).strip()
    return reply

def analyze_tactics(history, indicators):
    """Analyze scammer tactics from conversation history with granular detection.

    Returns a list of identified tactic names for profiling and notes.
    """
    scammer_msgs = [m.get("text", "").lower() for m in history if m.get("sender") == "scammer"]
    text = " ".join(scammer_msgs)
    tactics = []

    # Core tactics
    if any(w in text for w in ['urgent', 'now', 'immediately', 'hurry', 'quickly', 'fast', 'jaldi', 'turant', 'abhi']): tactics.append("urgency")
    if any(w in text for w in ['police', 'blocked', 'legal', 'arrest', 'frozen', 'suspended', 'terminated', 'kanoon', 'band']): tactics.append("fear")
    if any(w in text for w in ['otp', 'pin', 'password', 'cvv', 'aadhaar', 'pan card', 'card number']): tactics.append("credential_harvesting")
    if any(w in text for w in ['won', 'lottery', 'prize', 'bonus', 'reward', 'gift', 'cashback', 'jeet']): tactics.append("greed")
    if any(w in text for w in ['bank manager', 'rbi', 'officer', 'government', 'customer care', 'security team', 'cyber cell', 'sarkari']): tactics.append("authority_impersonation")
    if any(w in text for w in ["don't tell", 'secret', 'confidential', 'between us', 'private', 'kisiko mat batana']): tactics.append("isolation")
    if any(w in text for w in ['send money', 'transfer', 'pay now', 'upi', 'deposit', 'paisa bhejo', 'payment karo']): tactics.append("payment_redirection")

    # Granular behavioral red flags
    if any(w in text for w in ['click here', 'click link', 'click below', 'open link', 'download']): tactics.append("link_phishing")
    if any(w in text for w in ['refund', 'cashback', 'return money', 'excess payment']): tactics.append("refund_bait")
    if any(w in text for w in ['job', 'offer', 'salary', 'work from home', 'hiring', 'placement']): tactics.append("job_lure")
    if any(w in text for w in ['kyc', 'verify', 'update details', 'confirm identity', 'link aadhaar']): tactics.append("kyc_pretext")
    if any(w in text for w in ['install', 'teamviewer', 'anydesk', 'remote', 'screen share']): tactics.append("remote_access")
    if any(w in text for w in ['challan', 'fine', 'traffic', 'court', 'penalty']): tactics.append("fake_fine")

    # Escalation detection
    if len(scammer_msgs) >= 3:
        recent_urgency = sum(1 for t in scammer_msgs[-3:] if any(w in t for w in ['urgent', 'now', 'hurry', 'immediately']))
        if recent_urgency >= 2: tactics.append("escalating_pressure")

    # Repeated payment demands
    payment_msgs = sum(1 for t in scammer_msgs if any(w in t for w in ['send', 'pay', 'transfer', '₹', 'rupees']))
    if payment_msgs >= 3: tactics.append("persistent_payment_demand")

    return list(set(tactics))

def calculate_sophistication(tactics, intel):
    score = len(tactics)
    score += len(intel.get("upiIds", [])) * 2
    score += len(intel.get("bankAccounts", [])) * 2
    score += len(intel.get("phishingLinks", [])) * 2
    score += len(intel.get("ifscCodes", [])) * 2
    score += len(intel.get("phoneNumbers", [])) * 1
    score += len(intel.get("emails", [])) * 1
    score += len(intel.get("scammerIds", [])) * 1
    
    if score < 2: return "Low"
    if score < 5: return "Medium"
    if score < 8: return "High"
    return "Very High"

def generate_agent_notes(
    conversation_history: List[Dict],
    scam_indicators: List[str],
    extracted_intelligence: Dict,
    emails_found: List[str] = None,
    playbook_result: Optional[Dict] = None,
    context_modifiers: Optional[List[str]] = None,
    abuse_check: Optional[Dict] = None
) -> str:
    """Generate rich, structured agent notes for callback reporting.

    Includes: tactics observed, sophistication level, severity, playbook match,
    extracted intelligence summary, red flags, abuse status, engagement stats,
    and language info.
    """
    from src.detector import detect_playbook, calculate_severity

    tactics = analyze_tactics(conversation_history, scam_indicators)
    intel = extracted_intelligence or {}
    sophistication = calculate_sophistication(tactics, intel)

    if not playbook_result:
        try:
            playbook_result = detect_playbook(conversation_history)
        except Exception as e:
            logger.warning(f"Playbook detection failed in notes: {e}")
            playbook_result = {}

    notes = []

    # Tactics summary
    if tactics:
        notes.append(f"Tactics: {', '.join(sorted(tactics))}.")
    else:
        notes.append("No specific scam tactics detected.")

    notes.append(f"Sophistication: {sophistication}.")

    severity = calculate_severity(scam_indicators)
    notes.append(f"Severity: {severity.upper()}.")

    # Playbook match
    if playbook_result and playbook_result.get("confidence", 0) > 0.3:
        notes.append(f"Playbook: {playbook_result['description']} ({int(playbook_result['confidence']*100)}% confidence). Next expected: {playbook_result.get('next_expected', 'unknown')}.")
    else:
        notes.append("Playbook: No known pattern matched.")

    # Extracted intelligence
    extracted = []
    if intel.get("upiIds"): extracted.append(f"UPIs: {', '.join(intel['upiIds'][:5])}")
    if intel.get("phoneNumbers"): extracted.append(f"Phones: {', '.join(intel['phoneNumbers'][:5])}")
    if intel.get("bankAccounts"): extracted.append(f"Bank Accounts: {', '.join(intel['bankAccounts'][:3])}")
    if intel.get("ifscCodes"): extracted.append(f"IFSC: {', '.join(intel['ifscCodes'][:3])}")
    if intel.get("phishingLinks"): extracted.append(f"Links: {', '.join(intel['phishingLinks'][:3])}")
    if emails_found: extracted.append(f"Emails: {', '.join(emails_found[:3])}")
<<<<<<< HEAD
    if intel.get("scammerIds"): extracted.append(f"Scammer IDs: {', '.join(intel['scammerIds'][:3])}")

    if extracted:
        notes.append(f"Extracted Intel: {'; '.join(extracted)}.")
    else:
        notes.append("No actionable intel extracted yet.")

    # Red flag behavioral indicators
    red_flags = []
    scammer_texts = [m.get("text", "").lower() for m in conversation_history if m.get("sender") == "scammer"]
    if len(scammer_texts) >= 3:
        urgency_recent = sum(1 for t in scammer_texts[-3:] if any(w in t for w in ['urgent', 'now', 'hurry', 'immediately']))
        if urgency_recent >= 2: red_flags.append("escalating_pressure")
    payment_count = sum(1 for t in scammer_texts if any(w in t for w in ['send', 'pay', 'transfer', '₹']))
    if payment_count >= 3: red_flags.append("persistent_payment_demands")
    if len(set(intel.get("upiIds", []))) >= 2: red_flags.append("multiple_mule_accounts")
    if len(set(intel.get("phoneNumbers", []))) >= 2: red_flags.append("multiple_contact_numbers")

    if red_flags:
        notes.append(f"Red Flags: {', '.join(red_flags)}.")

    # Context modifiers and abuse
    if context_modifiers: notes.append(f"Context Modifiers: {', '.join(context_modifiers)}.")
    if abuse_check and abuse_check.get("tier") != "none":
        notes.append(f"Abuse Detected: {abuse_check['tier']} tier ({', '.join(abuse_check.get('matched', []))}).")

    # Engagement stats
    scammer_msg_count = sum(1 for m in conversation_history if m.get("sender") == "scammer")
    agent_msg_count = len(conversation_history) - scammer_msg_count
    notes.append(f"Engagement: {scammer_msg_count} scammer msgs, {agent_msg_count} agent responses.")

    lang = get_dominant_language(conversation_history, "")
    notes.append(f"Language: {lang}.")

=======
    if intel.get("scammerIds"): extracted.append(f"IDs: {', '.join(intel['scammerIds'][:3])}")
    
    if extracted: notes.append(f"Extracted: {'; '.join(extracted)}.")
    else: notes.append("No actionable intel extracted.")
    
    if context_modifiers: notes.append(f"Modifiers: {', '.join(context_modifiers)}.")
    if abuse_check and abuse_check.get("tier") != "none": notes.append(f"Abuse: {abuse_check['tier']} ({', '.join(abuse_check.get('matched', []))}).")
        
    scammer_msgs = sum(1 for m in conversation_history if m.get("sender") == "scammer")
    agent_msgs = len(conversation_history) - scammer_msgs
    notes.append(f"Engagement: {scammer_msgs} scammer msgs, {agent_msgs} agent msgs.")

    agent_replies = [m.get("text", "") for m in conversation_history if m.get("sender") != "scammer"]
    total_questions = sum(count_questions(reply) for reply in agent_replies)
    investigative_questions = sum(1 for reply in agent_replies if is_investigative_question(reply))
    notes.append(f"Quality: Asked {total_questions} questions ({investigative_questions} investigative).")
    
    lang = get_dominant_language(conversation_history, "")
    notes.append(f"Lang: {lang}.")
    
    # Track conversation quality metrics
    agent_msgs_list = [
        m.get("text", "")
        for m in conversation_history
        if m.get("sender") != "scammer"
    ]
    total_questions = sum(count_questions(msg) for msg in agent_msgs_list)
    investigative_count = sum(
        1 for msg in agent_msgs_list
        if is_investigative_question(msg)
    )
    notes.append(
        f"Quality: Asked {total_questions} questions ({investigative_count} investigative)."
    )
        
>>>>>>> 373770f ("pending agent ")
    return " ".join(notes)
