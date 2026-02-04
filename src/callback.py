"""
GUVI callback module
Owner: Member B
"""

import requests
from typing import Dict
from src.config import Config
from src.session import SessionData


def build_callback_payload(session: SessionData, agent_notes: str = "") -> Dict:
    """
    Builds the callback payload from session data
    
    Args:
        session: Session data
        agent_notes: Notes about scammer
    
    Returns:
        Dict ready for JSON serialization
    """
    return {
        "sessionId": session.session_id,
        "scamDetected": session.scam_detected,
        "totalMessagesExchanged": session.message_count,
        "extractedIntelligence": {
            "bankAccounts": session.extracted_intelligence.get("bankAccounts", []),
            "upiIds": session.extracted_intelligence.get("upiIds", []),
            "phishingLinks": session.extracted_intelligence.get("phishingLinks", []),
            "phoneNumbers": session.extracted_intelligence.get("phoneNumbers", []),
            "suspiciousKeywords": session.extracted_intelligence.get("suspiciousKeywords", [])
        },
        "agentNotes": agent_notes if agent_notes else generate_default_notes(session)
    }


def generate_default_notes(session: SessionData) -> str:
    """
    Generates default agent notes from session data
    
    Args:
        session: Session data
    
    Returns:
        Generated notes string
    """
    notes_parts = []
    
    # Add indicators
    if session.indicators:
        notes_parts.append(f"Scam indicators: {', '.join(session.indicators)}")
    
    # Add extraction counts
    intel = session.extracted_intelligence
    if intel.get("upiIds"):
        notes_parts.append(f"Extracted {len(intel['upiIds'])} UPI ID(s)")
    if intel.get("phoneNumbers"):
        notes_parts.append(f"Extracted {len(intel['phoneNumbers'])} phone number(s)")
    if intel.get("bankAccounts"):
        notes_parts.append(f"Extracted {len(intel['bankAccounts'])} bank account(s)")
    if intel.get("phishingLinks"):
        notes_parts.append(f"Extracted {len(intel['phishingLinks'])} phishing link(s)")
    
    # Add confidence
    if session.confidence > 0:
        notes_parts.append(f"Confidence: {session.confidence:.0%}")
    
    if notes_parts:
        return ". ".join(notes_parts) + "."
    else:
        return "Scam engagement completed."


def send_final_callback(session: SessionData, agent_notes: str = "") -> bool:
    """
    Sends final intelligence to GUVI evaluation endpoint
    
    Args:
        session: Completed session data
        agent_notes: Summary of scammer behavior
    
    Returns:
        True if callback successful, False otherwise
    """
    try:
        # Build payload
        payload = build_callback_payload(session, agent_notes)
        
        # Send to GUVI endpoint
        response = requests.post(
            Config.GUVI_CALLBACK_URL,
            json=payload,
            timeout=10,
            headers={"Content-Type": "application/json"}
        )
        
        # Check response
        if response.status_code == 200:
            print(f"[CALLBACK] Success for session {session.session_id}")
            return True
        else:
            print(f"[CALLBACK] Failed with status {response.status_code}: {response.text}")
            return False
    
    except requests.exceptions.Timeout:
        print(f"[CALLBACK] Timeout for session {session.session_id}")
        return False
    
    except requests.exceptions.RequestException as e:
        print(f"[CALLBACK] Error for session {session.session_id}: {e}")
        return False


def send_callback_async(session: SessionData, agent_notes: str = "") -> None:
    """
    Sends callback without blocking (fire and forget)
    
    Args:
        session: Completed session data
        agent_notes: Summary of scammer behavior
    """
    try:
        send_final_callback(session, agent_notes)
    except Exception as e:
        print(f"[CALLBACK] Async error: {e}")
