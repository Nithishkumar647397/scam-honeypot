"""
Configuration management
Owner: Member A
"""
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    API_SECRET_KEY: str = os.getenv("API_SECRET_KEY", "")
    GUVI_CALLBACK_URL: str = os.getenv("GUVI_CALLBACK_URL", "https://hackathon.guvi.in/api/updateHoneyPotFinalResult")
    
    # Conversation settings
    MAX_MESSAGES: int = 10
    MIN_INTELLIGENCE_FOR_CALLBACK: int = 2