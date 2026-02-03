"""
Scam detection module
Owner: Member A
"""
from typing import Tuple, List

def detect_scam(message: str, conversation_history: list = None) -> Tuple[bool, float, List[str]]:
    """
    Analyzes message for scam intent
    
    Args:
        message: Current scammer message text
        conversation_history: List of previous messages (optional)
    
    Returns:
        Tuple of:
            - is_scam (bool): True if scam detected
            - confidence (float): 0.0 to 1.0
            - indicators (List[str]): List of detected scam indicators
                e.g., ["urgency", "authority_impersonation", "payment_request"]
    
    Example:
        >>> detect_scam("Your account is blocked! Verify now!")
        (True, 0.85, ["urgency", "account_threat"])
    """
    pass  # Member A implements