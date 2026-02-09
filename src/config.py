"""
Configuration management
Owner: Member A
"""

import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Central configuration for the honeypot application."""
    
    # API Keys
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    API_SECRET_KEY: str = os.getenv("API_SECRET_KEY", "")
    
    # GUVI Callback
    GUVI_CALLBACK_URL: str = os.getenv(
        "GUVI_CALLBACK_URL", 
        "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
    )
    
    # Conversation Settings
    MAX_MESSAGES: int = 10
    MIN_INTELLIGENCE_FOR_CALLBACK: int = 2
    
    # Groq Settings
    GROQ_MODEL: str = "llama-3.1-8b-instant"
    GROQ_MAX_TOKENS: int = 150
    GROQ_TEMPERATURE: float = 0.7
    
    # Debug Mode
    DEBUG_MODE: bool = os.getenv("DEBUG_MODE", "false").lower() == "true"


def validate_config() -> bool:
    """Validates required config values at startup."""
    errors = []
    
    if not Config.GROQ_API_KEY:
        errors.append("GROQ_API_KEY is not set")
    
    if not Config.API_SECRET_KEY:
        errors.append("API_SECRET_KEY is not set")
    
    if errors:
        raise ValueError(f"Configuration errors: {', '.join(errors)}")
    
    return True
