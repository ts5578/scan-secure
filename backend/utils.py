import os
import logging

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('scansecure.log'),
            logging.StreamHandler()
        ]
    )

def validate_env_vars():
    required_vars = [
        'FLASK_SECRET_KEY',
        'GITHUB_CLIENT_ID',
        'GITHUB_CLIENT_SECRET',
        'GITHUB_REDIRECT_URI',
        'GEMINI_API_KEY'
    ]
    
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    if missing_vars:
        raise EnvironmentError(f"Missing required environment variables: {', '.join(missing_vars)}")