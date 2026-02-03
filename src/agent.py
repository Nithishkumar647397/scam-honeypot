"""
Groq LLM agent for generating responses
Owner: Member A
"""
from typing import List, Dict

def generate_agent_reply(
    current_message: str,
    conversation_history: List[Dict],
    scam_indicators: List[str] = None
) -> str:
    """
    Generates believable honeypot response using Groq LLM
    
    Args:
        current_message: Latest scammer message
        conversation_history: List of previous messages
            [{"sender": "scammer", "text": "..."}, {"sender": "user", "text": "..."}]
        scam_indicators: Detected scam types (for context)
    
    Returns:
        Agent reply string (max 100 words, human-like)
    
    Example:
        >>> generate_agent_reply(
        ...     "Your account is blocked!",
        ...     [],
        ...     ["urgency", "account_threat"]
        ... )
        "Oh no! What happened to my account? I'm very worried..."
    """
    pass  # Member A implements


def build_system_prompt() -> str:
    """
    Returns the system prompt for elderly persona
    """
    pass  # Member A implements