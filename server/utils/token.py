from flask import current_app, url_for
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime, timedelta

# Define token types for clarity
TOKEN_EMAIL_CONFIRM = 'email-confirm'
TOKEN_PASSWORD_CONFIRM = 'password-confirm'

def generate_confirmation_token(user_id, token_type, expires_in_seconds=3600):
    """Generates a secure, timed token for email/password confirmation."""
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY']) # Use app's secret key
    token_data = {'user_id': user_id, 'type': token_type}
    token = serializer.dumps(token_data, salt=token_type) # Use type as salt
    expiration = datetime.utcnow() + timedelta(seconds=expires_in_seconds)
    return token, expiration

def verify_confirmation_token(token, token_type, max_age_seconds=3600):
    """Verifies a confirmation token and returns the user ID if valid."""
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        token_data = serializer.loads(
            token,
            salt=token_type, # Ensure salt matches the type used during generation
            max_age=max_age_seconds
        )
    except Exception as e: # Catches SignatureExpired, BadSignature, etc.
        current_app.logger.warning(f"Token verification failed ({token_type}): {e}")
        return None # Token is invalid or expired
    
    # Additional check: Ensure the type embedded in the token matches expected type
    if token_data.get('type') != token_type:
        current_app.logger.warning(f"Token type mismatch. Expected '{token_type}', got '{token_data.get('type')}'")
        return None
        
    return token_data.get('user_id')

def generate_confirmation_url(token, endpoint):
    """Generates the full confirmation URL for email links."""
    # Ensure endpoint is relative to the API base URL, not the frontend URL
    # The frontend will need to handle these routes and call the API
    # Alternatively, pass the full frontend URL base here if needed.
    return url_for(endpoint, token=token, _external=True) 