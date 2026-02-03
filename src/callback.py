"""
GUVI callback module
Owner: Member B
"""
import requests
from typing import Dict
from src.config import Config
from src.session import SessionData

def send_final_callback(session: SessionData, agent_notes: str = "") -> bool:
    """
    Sends final intelligence to GUVI evaluation endpoint
    
    Args:
        session: Completed session data
        agent_notes: Summary of scammer behavior
    
    Returns:
        True if callback successful, False otherwise
    
    Payload format:
        {
            "sessionId": "...",
            "scamDetected": true,
            "totalMessagesExchanged": 18,
            "extractedIntelligence": {...},
            "agentNotes": "..."
        }
    """
    pass  # Member B implements


def build_callback_payload(session: SessionData, agent_notes: str) -> Dict:
    """
    Builds the callback payload from session data
    
    Args:
        session: Session data
        agent_notes: Notes about scammer
    
    Returns:
        Dict ready for JSON serialization
    """
    pass  # Member B implements