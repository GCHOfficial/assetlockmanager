from flask import current_app
from flask_mail import Message
from threading import Thread
# from server.app import mail # Removed - access mail via app context

def send_async_email(app, msg):
    """Sends email asynchronously in a separate thread."""
    with app.app_context():
        # Access mail instance from the app context
        mail_instance = current_app.extensions.get('mail')
        if not mail_instance:
            current_app.logger.error("Flask-Mail extension not found in app context.")
            return
        
        try:
            # Check if mail is enabled in config before sending
            mail_enabled = current_app.config.get('MAIL_ENABLED', False)
            if not mail_enabled:
                current_app.logger.info(f"Email system disabled by MAIL_ENABLED config. Would send to {msg.recipients}")
                return False # Indicate email was not sent because system is disabled
            
            # Check MAIL_SUPPRESS_SEND, often used for testing
            # if current_app.config.get('MAIL_SUPPRESS_SEND', False):
            #     current_app.logger.info(f"Email sending suppressed by MAIL_SUPPRESS_SEND config. Would send to {msg.recipients}")
            #     return True # Indicate email was handled (suppressed), not an error

            # Use the retrieved mail instance
            mail_instance.send(msg)
            current_app.logger.info(f"Successfully sent email to {msg.recipients} with subject '{msg.subject}'")
        except Exception as e:
            current_app.logger.error(f"Failed to send email to {msg.recipients} with subject '{msg.subject}': {e}", exc_info=True)

def send_email(subject, recipients, text_body, html_body=None):
    """Prepares and sends an email using an asynchronous thread."""
    app = current_app._get_current_object() # Get the current Flask app instance correctly
    sender = app.config.get('MAIL_DEFAULT_SENDER', 'noreply@example.com')
    msg = Message(subject, sender=sender, recipients=recipients)
    msg.body = text_body
    msg.html = html_body
    thr = Thread(target=send_async_email, args=[app, msg])
    thr.start()
    return thr 