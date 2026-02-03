from src.config import Config, validate_config

validate_config()
print("Config OK!")
print(f"Groq Key Set: {bool(Config.GROQ_API_KEY)}")
print(f"API Secret Set: {bool(Config.API_SECRET_KEY)}")