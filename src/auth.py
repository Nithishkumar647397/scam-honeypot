"""
API authentication module
Owner: Member B
"""

from flask import Request
from src.config import Config


def validate_api_key(request: Request) -> bool:
    """
    Validates x-api-key header against stored secret
    
    Args:
        request: Flask request object
    
    Returns:
        True if valid, False otherwise
    
    Example:
        if not validate_api_key(request):
            return {"status": "error", "message": "Unauthorized"}, 401
    """
    # Get API key from request header
    provided_key = request.headers.get("x-api-key", "")
    
    # Check if key is provided
    if not provided_key:
        return False
    
    # Compare with stored secret
    if provided_key == Config.API_SECRET_KEY:
        return True
    
    return False


def get_api_key_from_request(request: Request) -> str:
    """
    Extracts API key from request headers
    
    Args:
        request: Flask request object
    
    Returns:
        API key string or empty string if not found
    """
    return request.headers.get("x-api-key", "")