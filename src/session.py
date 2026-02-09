"""
Session management for multi-turn conversations
Owner: Member B

UPDATED: Multiple callbacks enabled - sends updates when new intel found
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
    callback_count: int = 0
    last_callback_intel_count: int = 0
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


def _count_intel(session: SessionData) -> int:
    intel = session.extracted_intelligence
    return (
        len(intel.get("upiIds", [])) +
        len(intel.get("bankAccounts", [])) +
        len(intel.get("phoneNumbers", [])) +
        len(intel.get("ifscCodes", [])) +
        len(intel.get("phishingLinks", [])) +
        len(intel.get("emails", []))
    )


def should_send_callback(session: SessionData) -> bool:
    """
    Smart callback: First callback + updates when new intel found.
    """
    if session is None:
        return False
    if not session.scam_detected:
        return False
    
    current_intel_count = _count_intel(session)
    max_messages = getattr(Config, 'MAX_MESSAGES', 10)
    min_intel = getattr(Config, 'MIN_INTELLIGENCE_FOR_CALLBACK', 2)
    
    # FIRST callback
    if not session.callback_sent:
        # Trigger 1: Max messages
        if session.message_count >= max_messages:
            logger.info(f"First callback: max msgs ({session.message_count})")
            session.callback_sent = True
            session.last_callback_intel_count = current_intel_count
            session.callback_count += 1
            return True
        
        # Trigger 2: Intel + engagement
        if current_intel_count >= min_intel and session.message_count >= 6:
            logger.info(f"First callback: intel ({current_intel_count}) + msgs ({session.message_count})")
            session.callback_sent = True
            session.last_callback_intel_count = current_intel_count
            session.callback_count += 1
            return True
        
        # Trigger 3: High confidence
        if session.confidence >= 0.8 and session.message_count >= 8:
            logger.info(f"First callback: confidence ({session.confidence})")
            session.callback_sent = True
            session.last_callback_intel_count = current_intel_count
            session.callback_count += 1
            return True
        
        # Trigger 4: Fast fail
        if session.confidence >= 0.9 and current_intel_count >= 1 and session.message_count >= 4:
            logger.info(f"First callback: fast-fail")
            session.callback_sent = True
            session.last_callback_intel_count = current_intel_count
            session.callback_count += 1
            return True
        
        return False
    
    # UPDATE callback: New intel found after first callback
    if current_intel_count > session.last_callback_intel_count:
        logger.info(f"Update callback: new intel ({session.last_callback_intel_count} -> {current_intel_count})")
        session.last_callback_intel_count = current_intel_count
        session.callback_count += 1
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
