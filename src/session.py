"""
Session management for multi-turn conversations
Owner: Member B
"""

import threading
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from src.config import Config


logger = logging.getLogger(__name__)


@dataclass
class SessionData:
    session_id: str
    created_at: datetime
    message_count: int = 0
    scam_detected: bool = False
    confidence: float = 0.0
    conversation_history: List[Dict] = field(default_factory=list)
    extracted_intelligence: Dict = field(default_factory=lambda: {
        "upiIds": [],
        "bankAccounts": [],
        "phoneNumbers": [],
        "ifscCodes": [],
        "phishingLinks": [],
        "suspiciousKeywords": [],
        "emails": []
    })
    indicators: List[str] = field(default_factory=list)
    callback_sent: bool = False
    last_activity: datetime = field(default_factory=datetime.now)


_sessions: Dict[str, SessionData] = {}
_sessions_lock = threading.Lock()
SESSION_EXPIRY_HOURS = 1


def get_session(session_id: str) -> Optional[SessionData]:
    with _sessions_lock:
        session = _sessions.get(session_id)
        if session:
            if datetime.now() > session.last_activity + timedelta(hours=SESSION_EXPIRY_HOURS):
                del _sessions[session_id]
                return None
            session.last_activity = datetime.now()
        return session


def create_session(session_id: str) -> SessionData:
    with _sessions_lock:
        _cleanup_expired_sessions()
        session = SessionData(
            session_id=session_id,
            created_at=datetime.now(),
            last_activity=datetime.now()
        )
        _sessions[session_id] = session
        return session


def update_session(
    session_id: str,
    message_count: int = None,
    scam_detected: bool = None,
    confidence: float = None,
    new_message: Dict = None,
    extracted_intelligence: Dict = None,
    indicators: List[str] = None
) -> SessionData:
    with _sessions_lock:
        session = _sessions.get(session_id)
        
        if session is None:
            session = SessionData(
                session_id=session_id,
                created_at=datetime.now(),
                last_activity=datetime.now()
            )
            _sessions[session_id] = session
        
        session.last_activity = datetime.now()
        
        if message_count is not None:
            session.message_count = message_count
        if scam_detected is not None:
            session.scam_detected = scam_detected
        if confidence is not None:
            session.confidence = confidence
        if new_message is not None:
            session.conversation_history.append(new_message)
        if extracted_intelligence is not None:
            _merge_intelligence(session, extracted_intelligence)
        if indicators is not None:
            existing = set(session.indicators)
            session.indicators = list(existing.union(set(indicators)))
        
        return session


def _merge_intelligence(session: SessionData, new_intel: Dict):
    for key in session.extracted_intelligence:
        if key in new_intel and new_intel[key]:
            existing = set(session.extracted_intelligence[key])
            session.extracted_intelligence[key] = list(existing.union(set(new_intel[key])))


def should_send_callback(session: SessionData) -> bool:
    """
    ONE callback only. Triggers:
    1. Max messages (10)
    2. Intel (2+) + engagement (6+ msgs)
    3. High confidence (0.8+) + engagement (8+ msgs)
    4. FAST FAIL: Very high confidence (0.9+) + any intel + 3+ msgs
    """
    if session is None:
        return False
    if session.callback_sent:
        return False
    if not session.scam_detected:
        return False
    
    intel = session.extracted_intelligence
    total_items = (
        len(intel.get("upiIds", [])) +
        len(intel.get("bankAccounts", [])) +
        len(intel.get("phoneNumbers", [])) +
        len(intel.get("ifscCodes", [])) +
        len(intel.get("phishingLinks", [])) +
        len(intel.get("emails", []))
    )
    
    max_messages = getattr(Config, 'MAX_MESSAGES', 10)
    min_intel = getattr(Config, 'MIN_INTELLIGENCE_FOR_CALLBACK', 2)
    
    # Trigger 1: Max messages
    if session.message_count >= max_messages:
        logger.info(f"Callback: max msgs ({session.message_count})")
        session.callback_sent = True
        return True
    
    # Trigger 2: Good intel + decent engagement
    if total_items >= min_intel and session.message_count >= 6:
        logger.info(f"Callback: intel ({total_items}) + msgs ({session.message_count})")
        session.callback_sent = True
        return True
    
    # Trigger 3: High confidence + good engagement
    if session.confidence >= 0.8 and session.message_count >= 8:
        logger.info(f"Callback: confidence ({session.confidence}) + msgs ({session.message_count})")
        session.callback_sent = True
        return True
    
    # Trigger 4: FAST FAIL - obvious scam with intel, short conversation
    if session.confidence >= 0.9 and total_items >= 1 and session.message_count >= 3:
        logger.info(f"Callback: fast-fail ({session.confidence}, {total_items} intel, {session.message_count} msgs)")
        session.callback_sent = True
        return True
    
    return False


def _cleanup_expired_sessions():
    now = datetime.now()
    expired = [sid for sid, s in _sessions.items()
               if now > s.last_activity + timedelta(hours=SESSION_EXPIRY_HOURS)]
    for sid in expired:
        del _sessions[sid]


def delete_session(session_id: str) -> bool:
    with _sessions_lock:
        if session_id in _sessions:
            del _sessions[session_id]
            return True
        return False


def get_all_sessions() -> Dict[str, SessionData]:
    with _sessions_lock:
        return _sessions.copy()


def clear_all_sessions() -> int:
    with _sessions_lock:
        count = len(_sessions)
        _sessions.clear()
        return count
