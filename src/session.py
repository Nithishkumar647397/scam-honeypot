"""
Session management for multi-turn conversations
Owner: Member B
"""

from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from src.config import Config


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
        "suspiciousKeywords": []
    })
    indicators: List[str] = field(default_factory=list)


# In-memory session storage
_sessions: Dict[str, SessionData] = {}


def get_session(session_id: str) -> Optional[SessionData]:
    """
    Retrieves session by ID
    
    Args:
        session_id: Unique session identifier
    
    Returns:
        SessionData if exists, None otherwise
    """
    return _sessions.get(session_id, None)


def create_session(session_id: str) -> SessionData:
    """
    Creates new session
    
    Args:
        session_id: Unique session identifier
    
    Returns:
        New SessionData object
    """
    session = SessionData(
        session_id=session_id,
        created_at=datetime.now()
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
    """
    Updates existing session with new data
    
    Args:
        session_id: Session to update
        Other args: Fields to update (None = don't change)
    
    Returns:
        Updated SessionData
    """
    session = get_session(session_id)
    
    if session is None:
        session = create_session(session_id)
    
    if message_count is not None:
        session.message_count = message_count
    
    if scam_detected is not None:
        session.scam_detected = scam_detected
    
    if confidence is not None:
        session.confidence = confidence
    
    if new_message is not None:
        session.conversation_history.append(new_message)
    
    if extracted_intelligence is not None:
        # Merge new intelligence with existing
        for key in session.extracted_intelligence:
            if key in extracted_intelligence:
                # Add new items, avoid duplicates
                existing = set(session.extracted_intelligence[key])
                new_items = set(extracted_intelligence[key])
                session.extracted_intelligence[key] = list(existing.union(new_items))
    
    if indicators is not None:
        # Merge indicators, avoid duplicates
        existing = set(session.indicators)
        new_items = set(indicators)
        session.indicators = list(existing.union(new_items))
    
    return session


def should_send_callback(session: SessionData) -> bool:
    """
    Determines if conversation is complete enough for callback
    
    Rules:
        - Message count >= MAX_MESSAGES (10), OR
        - Extracted intelligence items >= MIN_INTELLIGENCE_FOR_CALLBACK (2)
    
    Args:
        session: Current session data
    
    Returns:
        True if should send callback, False otherwise
    """
    # Check message count
    if session.message_count >= Config.MAX_MESSAGES:
        return True
    
    # Count total extracted items (excluding keywords)
    intel = session.extracted_intelligence
    total_items = (
        len(intel.get("upiIds", [])) +
        len(intel.get("bankAccounts", [])) +
        len(intel.get("phoneNumbers", [])) +
        len(intel.get("ifscCodes", [])) +
        len(intel.get("phishingLinks", []))
    )
    
    if total_items >= Config.MIN_INTELLIGENCE_FOR_CALLBACK:
        return True
    
    return False


def delete_session(session_id: str) -> bool:
    """
    Removes session from storage
    
    Args:
        session_id: Session to delete
    
    Returns:
        True if deleted, False if not found
    """
    if session_id in _sessions:
        del _sessions[session_id]
        return True
    return False


def get_all_sessions() -> Dict[str, SessionData]:
    """
    Returns all active sessions (for debugging)
    
    Returns:
        Dictionary of all sessions
    """
    return _sessions.copy()


def clear_all_sessions() -> int:
    """
    Clears all sessions (for testing)
    
    Returns:
        Number of sessions cleared
    """
    count = len(_sessions)
    _sessions.clear()
    return count
