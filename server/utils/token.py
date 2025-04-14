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
    """Generates the full confirmation URL pointing to the frontend."""
    frontend_base_url = current_app.config.get("FRONTEND_BASE_URL")
    if not frontend_base_url:
        current_app.logger.error(
            "FRONTEND_BASE_URL is not configured in the application. "
            "Cannot generate confirmation URL."
        )
        # Depending on strictness, could raise an error or return None/placeholder
        return "#config-error-frontend-url-not-set"

    # Map the Flask endpoint name to the frontend path
    # This assumes endpoint names match route functions like 'confirm_email'
    if endpoint == TOKEN_EMAIL_CONFIRM: # Assuming endpoint matches the salt/type used
        frontend_path = '/confirm-email'
    elif endpoint == TOKEN_PASSWORD_CONFIRM:
        frontend_path = '/confirm-password'
    else:
        # Handle unknown endpoints if necessary, maybe log a warning
        current_app.logger.warning(f"generate_confirmation_url called with unexpected endpoint: {endpoint}")
        # Fallback or raise error - using a generic path for now
        frontend_path = '/confirm' # Or perhaps raise ValueError("Invalid endpoint for confirmation URL")

    # Construct the URL: base + path + query parameter
    confirmation_url = f"{frontend_base_url.rstrip('/')}{frontend_path}?token={token}"
    return confirmation_url 