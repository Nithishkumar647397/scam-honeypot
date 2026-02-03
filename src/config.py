"""
Configuration management
Owner: Member A
Created: [Current Date]
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class Config:
    """
    Central configuration for the honeypot application.
    All settings are loaded from environment variables.
    """
    
    # API Keys
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    API_SECRET_KEY: str = os.getenv("API_SECRET_KEY", "")
    
    # GUVI Callback
    GUVI_CALLBACK_URL: str = os.getenv(
        "GUVI_CALLBACK_URL", 
        "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
    )
    
    # Conversation Settings
    MAX_MESSAGES: int = 10  # Send callback after this many messages
    MIN_INTELLIGENCE_FOR_CALLBACK: int = 2  # Or after extracting this many items
    
    # Groq Settings
    GROQ_MODEL: str = "llama-3.1-8b-instant"  # Fast and free
    GROQ_MAX_TOKENS: int = 150
    GROQ_TEMPERATURE: float = 0.7


# Validation function
def validate_config() -> bool:
    """
    Validates that required config values are set.
    Call this at app startup.
    
    Returns:
        True if valid, raises error if not
    """
    errors = []
    
    if not Config.GROQ_API_KEY:
        errors.append("GROQ_API_KEY is not set")
    
    if not Config.API_SECRET_KEY:
        errors.append("API_SECRET_KEY is not set")
    
    if errors:
        raise ValueError(f"Configuration errors: {', '.join(errors)}")
    
    return True