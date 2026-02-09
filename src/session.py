"""
Session management for multi-turn conversations
Owner: Member B

Fixes:
- Added callback_sent flag (prevents duplicates)
- Added emails to intelligence
- Fixed should_send_callback per GUVI spec
- Added thread safety
- Added logging
"""

import threading
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from src.config import Config


logger = logging.getLogger(__name__)


@dataclass
class SessionData:
    """Data stored for each conversation session"""
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
        "emails": []  # Added emails field
    })
    indicators: List[str] = field(default_factory=list)
    callback_sent: bool = False  # Added callback flag


# Thread-safe session storage
_sessions: Dict[str, SessionData] = {}
_sessions_lock = threading.Lock()


def get_session(session_id: str) -> Optional[SessionData]:
    """Retrieves session by ID"""
    with _sessions_lock:
        return _sessions.get(session_id, None)


def create_session(session_id: str) -> SessionData:
    """Creates new session"""
    with _sessions_lock:
        session = SessionData(
            session_id=session_id,
            created_at=datetime.now()
        )
        _sessions[session_id] = session
        logger.info(f"Created session: {session_id}")
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
    """Updates existing session with new data"""
    with _sessions_lock:
        session = _sessions.get(session_id)
        
        if session is None:
            session = SessionData(
                session_id=session_id,
                created_at=datetime.now()
            )
            _sessions[session_id] = session
        
        if message_count is not None:
            session.message_count = message_count
        
        if scam_detected is not None:
            session.scam_detected = scam_detected
        
        if confidence is not None:
            session.confidence = confidence
        
        if new_message is not None:
            session.conversation_history.append(new_message)
        
        if extracted_intelligence is not None:
            for key in session.extracted_intelligence:
                if key in extracted_intelligence:
                    existing = set(session.extracted_intelligence[key])
                    new_items = set(extracted_intelligence[key])
                    session.extracted_intelligence[key] = list(existing.union(new_items))
        
        if indicators is not None:
            existing = set(session.indicators)
            new_items = set(indicators)
            session.indicators = list(existing.union(new_items))
        
        return session


def should_send_callback(session: SessionData) -> bool:
    """
    Determines if callback should be sent to GUVI
    """
    if session is None:
        return False
    
    # 1. Don't send duplicates
    if session.callback_sent:
        return False
    
    # 2. Must be a scam (GUVI Requirement)
    if not session.scam_detected:
        return False
    
    # 3. Check triggers
    # Max messages
    max_messages = getattr(Config, 'MAX_MESSAGES', 10)
    if session.message_count >= max_messages:
        logger.info(f"Callback trigger: Max messages ({session.message_count})")
        session.callback_sent = True
        return True
    
    # Intelligence threshold
    intel = session.extracted_intelligence
    total_items = (
        len(intel.get("upiIds", [])) +
        len(intel.get("bankAccounts", [])) +
        len(intel.get("phoneNumbers", [])) +
        len(intel.get("ifscCodes", [])) +
        len(intel.get("phishingLinks", [])) +
        len(intel.get("emails", []))
    )
    
    min_intel = getattr(Config, 'MIN_INTELLIGENCE_FOR_CALLBACK', 2)
    if total_items >= min_intel:
        logger.info(f"Callback trigger: Intelligence found ({total_items} items)")
        session.callback_sent = True
        return True
    
    # High confidence trigger
    if session.confidence >= 0.7 and session.message_count >= 4:
        logger.info(f"Callback trigger: High confidence ({session.confidence})")
        session.callback_sent = True
        return True
    
    return False


def delete_session(session_id: str) -> bool:
    """Removes session from storage"""
    with _sessions_lock:
        if session_id in _sessions:
            del _sessions[session_id]
            logger.debug(f"Deleted session: {session_id}")
            return True
        return False


def get_all_sessions() -> Dict[str, SessionData]:
    """Returns all active sessions"""
    with _sessions_lock:
        return _sessions.copy()


def clear_all_sessions() -> int:
    """Clears all sessions"""
    with _sessions_lock:
        count = len(_sessions)
        _sessions.clear()
        logger.info(f"Cleared {count} sessions")
        return count
