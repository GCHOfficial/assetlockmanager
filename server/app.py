#!/usr/bin/env python3
import os
from datetime import datetime, timedelta # Ensure timedelta is imported early
import atexit
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore # Import SQLAlchemyJobStore

from flask import Flask, request, jsonify, url_for, current_app, has_app_context # Add has_app_context import
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate # Import Migrate
from sqlalchemy.exc import SQLAlchemyError # Import SQLAlchemyError
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity,
)
from werkzeug.security import generate_password_hash, check_password_hash
from pydantic import BaseModel, ValidationError, EmailStr # Import EmailStr for email validation
from typing import Optional, List # Import List for output schema
from flask_limiter import Limiter # Import Limiter
from flask_limiter.util import get_remote_address # Import get_remote_address
from functools import wraps # Needed for admin decorator
import logging # Import logging earlier for config messages
from flask_cors import CORS, cross_origin # Import CORS and cross_origin
from flask_mail import Mail, Message # Import Flask-Mail

# Import the email utility function
from utils.email import send_email
from utils.token import (
    generate_confirmation_token,
    generate_confirmation_url,
    TOKEN_EMAIL_CONFIRM,
    TOKEN_PASSWORD_CONFIRM
)

# Import click for CLI commands
import click

# ----------------------------
# Application Configuration
# ----------------------------
app = Flask(__name__)
# Keep global CORS for general handling, but can use decorator for specifics
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

# -- Load Configuration from Environment Variables --
jwt_secret_key = os.environ.get("JWT_SECRET_KEY")
database_uri = os.environ.get("DATABASE_URI")
ratelimit_storage_uri = os.environ.get("RATELIMIT_STORAGE_URI")

if not jwt_secret_key:
    # JWT_SECRET_KEY is mandatory for security
    raise RuntimeError("Missing required environment variable: JWT_SECRET_KEY")

# Construct default DATABASE_URI if not provided (useful for local dev/testing)
if not database_uri:
    postgres_user = os.environ.get("POSTGRES_USER", "locks_user")
    postgres_password = os.environ.get("POSTGRES_PASSWORD", "password")
    postgres_db = os.environ.get("POSTGRES_DB", "locks_db")
    # Default to service name 'postgres' for Docker, 'localhost' if FLASK_DEBUG=1
    postgres_host = "localhost" if os.environ.get("FLASK_DEBUG") == "1" else "alm-postgres"
    database_uri = f"postgresql://{postgres_user}:{postgres_password}@{postgres_host}:5432/{postgres_db}"
    # Use print here as logger might not be configured yet
    print(f"INFO: DATABASE_URI not provided; constructed default: {database_uri}")

# Construct default RATELIMIT_STORAGE_URI if not provided
if not ratelimit_storage_uri:
    # Default to service name 'redis' for Docker, 'localhost' if FLASK_DEBUG=1
    redis_host = "localhost" if os.environ.get("FLASK_DEBUG") == "1" else "alm-redis"
    ratelimit_storage_uri = f"redis://{redis_host}:6379/0"
    print(f"INFO: RATELIMIT_STORAGE_URI not provided; constructed default: {ratelimit_storage_uri}")

app.config["JWT_SECRET_KEY"] = jwt_secret_key
app.config["SECRET_KEY"] = jwt_secret_key # Also set the standard Flask SECRET_KEY for itsdangerous
app.config["SQLALCHEMY_DATABASE_URI"] = database_uri
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# -- Auto Lock Release Configuration --
# Load from environment variables, providing defaults if not set
app.config["AUTO_RELEASE_ENABLED"] = os.environ.get("AUTO_RELEASE_ENABLED", "false").lower() in ("true", "1", "t")
app.config["AUTO_RELEASE_HOURS"] = int(os.environ.get("AUTO_RELEASE_HOURS", "72")) # Default 72 hours
# Basic validation for hours
if app.config["AUTO_RELEASE_HOURS"] < 1:
    app.logger.warning("AUTO_RELEASE_HOURS is set to less than 1, defaulting to 1 hour.")
    app.config["AUTO_RELEASE_HOURS"] = 1

# -- Email Configuration --
app.config["MAIL_SERVER"] = os.environ.get("MAIL_SERVER")
app.config["MAIL_PORT"] = int(os.environ.get("MAIL_PORT", 587))
app.config["MAIL_USE_TLS"] = os.environ.get("MAIL_USE_TLS", "false").lower() in ("true", "1", "t")
app.config["MAIL_USE_SSL"] = os.environ.get("MAIL_USE_SSL", "false").lower() in ("true", "1", "t")
app.config["MAIL_USERNAME"] = os.environ.get("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.environ.get("MAIL_DEFAULT_SENDER", "Asset Lock Manager <noreply@example.com>")
app.config["MAIL_ENABLED"] = os.environ.get("MAIL_ENABLED", "false").lower() in ("true", "1", "t")

# -- Frontend URL Configuration --
app.config["FRONTEND_BASE_URL"] = os.environ.get("FRONTEND_BASE_URL")
if not app.config["FRONTEND_BASE_URL"]:
    # Use print/log warning if critical for features like email confirmation
    print("WARNING: FRONTEND_BASE_URL environment variable not set. Email links might be incorrect.")
    # Provide a default or raise an error depending on requirements
    # For now, let it be None, but dependent features should handle this.

# Configure optional JWT Expiration from environment variable
try:
    jwt_expires_minutes_str = os.environ.get("JWT_ACCESS_TOKEN_EXPIRES_MINUTES")
    if jwt_expires_minutes_str:
        jwt_expires_minutes = int(jwt_expires_minutes_str)
        # Treat 0 or negative as infinite (False)
        if jwt_expires_minutes > 0:
            app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=jwt_expires_minutes)
            print(f"INFO: JWT access tokens set to expire in {jwt_expires_minutes} minutes.")
        else:
            app.config["JWT_ACCESS_TOKEN_EXPIRES"] = False
            print("INFO: JWT access tokens set to never expire (JWT_ACCESS_TOKEN_EXPIRES_MINUTES <= 0).")
    else:
        # Default to no expiration if env var is not set
        app.config["JWT_ACCESS_TOKEN_EXPIRES"] = False
        print("INFO: JWT access tokens set to never expire (JWT_ACCESS_TOKEN_EXPIRES_MINUTES not set).")
except ValueError:
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = False
    print("WARNING: Invalid value for JWT_ACCESS_TOKEN_EXPIRES_MINUTES. JWT tokens set to never expire.")

# Configure ProxyFix for accurate IP identification behind reverse proxies (e.g., for rate limiting)
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

# -- Initialize Extensions --
db = SQLAlchemy(app)
jwt = JWTManager(app)
migrate = Migrate(app, db)
mail = Mail(app) # Initialize Flask-Mail
limiter = Limiter(
    get_remote_address, # Use client IP address for rate limiting
    app=app,
    # default_limits=["200 per day", "50 per hour"], # Temporarily disable default limits
    storage_uri=ratelimit_storage_uri,
    strategy="fixed-window"
)

# ----------------------------
# Scheduled Tasks (Auto Lock Release)
# ----------------------------

# Configure Job Store
jobstores = {
    'default': SQLAlchemyJobStore(url=app.config['SQLALCHEMY_DATABASE_URI'])
}

# Initialize Scheduler with the job store
scheduler = BackgroundScheduler(jobstores=jobstores, daemon=True)

def delete_old_locks():
    """Background job to delete locks older than the configured threshold."""
    with app.app_context():
        # Use effective value for auto release enabled check
        auto_release_enabled = get_effective_config_value(CONFIG_AUTO_RELEASE_ENABLED, "AUTO_RELEASE_ENABLED", bool, False)
        
        if not auto_release_enabled:
            app.logger.info("Auto-release disabled via config. Skipping delete_old_locks job.")
            return

        # Use effective value for hours
        hours_threshold = get_effective_config_value(CONFIG_AUTO_RELEASE_HOURS, "AUTO_RELEASE_HOURS", int, 72)
        if hours_threshold < 1:
            app.logger.warning(f"Effective auto-release hours ({hours_threshold}) is less than 1, using 1 hour.")
            hours_threshold = 1 # Safety check

        threshold_time = datetime.utcnow() - timedelta(hours=hours_threshold)
        try:
            old_locks = Lock.query.filter(Lock.timestamp < threshold_time).all()
            if old_locks:
                for lock in old_locks:
                    app.logger.info(f"Auto-releasing lock ID {lock.id} for path '{lock.asset_path}' (older than {hours_threshold} hours). Held by '{lock.locked_by}'.")
                    db.session.delete(lock)
                db.session.commit()
            else:
                app.logger.info("No old locks found to auto-release.")
        except SQLAlchemyError as e:
            db.session.rollback()
            app.logger.error(f"Database error during auto-release job: {e}", exc_info=True)
        except Exception as e:
            app.logger.error(f"Unexpected error during auto-release job: {e}", exc_info=True)

# Add job to run every hour (adjust interval as needed)
# The job store ensures this job is added only once across multiple processes/workers
scheduler.add_job(delete_old_locks, 'interval', hours=1, id='delete_old_locks_job', replace_existing=True)

# Start scheduler
# No longer need the check for app.debug or WERKZEUG_RUN_MAIN, the job store handles concurrency.
try:
    scheduler.start()
    # Ensure scheduler shuts down cleanly when app exits
    atexit.register(lambda: scheduler.shutdown())
    app.logger.info("BackgroundScheduler started with SQLAlchemyJobStore for auto lock release.")
except Exception as e:
    app.logger.error(f"Failed to start BackgroundScheduler: {e}", exc_info=True)

# ----------------------------
# Pydantic Validation Schemas
# ----------------------------
# These schemas define the expected structure and types for incoming JSON payloads.

class LoginSchema(BaseModel):
    """Schema for login request."""
    username: str
    password: str

class CreateLockSchema(BaseModel):
    """Schema for creating a new lock."""
    asset_path: str
    branch: str
    comment: Optional[str] = None

class AutoReleaseSchema(BaseModel):
    """Schema for auto-releasing locks by branch."""
    branch: str

# --- Schema for Notify Message ---
class NotifyMessageSchema(BaseModel):
    """Schema for the optional message in notify request body."""
    message: Optional[str] = None

# Schemas for Admin User Management
class CreateUserSchema(BaseModel):
    """Schema for admin creating a new user."""
    username: str
    password: str
    email: EmailStr

class AdminChangePasswordSchema(BaseModel):
    """Schema for admin changing another user's password."""
    new_password: str

class AdminChangeEmailSchema(BaseModel):
    """Schema for admin changing another user's email."""
    new_email: EmailStr

class UpdateUserStatusSchema(BaseModel):
    """Schema for admin updating a user's admin status."""
    is_admin: bool

# Schema for User Output (filtering sensitive data)
class UserOutputSchema(BaseModel):
    """Schema for safe user data output (omits password hash)."""
    id: int
    username: str
    email: EmailStr
    is_admin: bool

    # Pydantic v2 config to allow creating schema from ORM model
    model_config = {"from_attributes": True}

# Schemas for User Self-Service
class ChangePasswordSchema(BaseModel):
    """Schema for user changing their own password."""
    current_password: str
    new_password: str

class ChangeEmailSchema(BaseModel):
    """Schema for user changing their own email."""
    new_email: EmailStr
    current_password: str


# ----------------------------
# Database Models
# ----------------------------

class User(db.Model):
    """Represents a user in the system."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False) # The currently confirmed email
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

    # Fields for email/password change confirmation
    pending_email = db.Column(db.String(120), nullable=True, unique=True) # Store pending email change
    pending_password_hash = db.Column(db.String(256), nullable=True) # Store pending password change
    confirmation_token = db.Column(db.String(256), nullable=True, unique=True, index=True) # Store confirmation token
    token_expiration = db.Column(db.DateTime, nullable=True) # Expiration time for the token

    @classmethod
    def create(cls, username, password, email, is_admin=False):
        """Creates a new user instance, hashes password, and attempts commit."""
        user = cls(
            username=username,
            password_hash=generate_password_hash(password),
            email=email,
            is_admin=is_admin
        )
        try:
            db.session.add(user)
            db.session.commit()
            return user # Return created user object on success
        except SQLAlchemyError as e:
            db.session.rollback()
            # Use app logger if available (i.e., within app context)
            logger = app.logger if app else logging.getLogger(__name__)
            logger.error(f"Database error creating user {username}: {e}", exc_info=True)
            return None # Indicate failure

    def check_password(self, password):
        """Verifies a given password against the stored hash."""
        return check_password_hash(self.password_hash, password)


class Lock(db.Model):
    """Represents an active lock on an asset."""
    id = db.Column(db.Integer, primary_key=True)
    # Normalized asset path relative to repository root
    asset_path = db.Column(db.String, unique=True, nullable=False)
    # Username of the user holding the lock
    locked_by = db.Column(db.String, nullable=False)
    # Git branch associated with the lock
    branch = db.Column(db.String, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    comment = db.Column(db.String, nullable=True)

    @staticmethod
    def normalize_path(path):
        """Normalizes file paths to use forward slashes and remove duplicates."""
        path = path.strip('/')
        path = path.replace('\\', '/')
        while '//' in path:
            path = path.replace('//', '/')
        return path

    # Class method Lock.create removed - direct object creation handled in route
    # This avoids potential circular dependencies or complex error handling return types

    @classmethod
    def find_by_path(cls, asset_path):
        """Finds a lock by its normalized asset path."""
        normalized_path = cls.normalize_path(asset_path)
        return cls.query.filter_by(asset_path=normalized_path).first()

class Configuration(db.Model):
    """Stores key-value configuration settings."""
    key = db.Column(db.String(80), primary_key=True)
    value = db.Column(db.String, nullable=True) # Store values as strings

    @classmethod
    def get(cls, key, default=None):
        """Retrieve a config value by key."""
        config = cls.query.get(key)
        return config.value if config else default

    @classmethod
    def set(cls, key, value):
        """Set or update a config value."""
        config = cls.query.get(key)
        if config:
            config.value = str(value) # Ensure value is stored as string
        else:
            config = cls(key=key, value=str(value))
            db.session.add(config)
        try:
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            logger = app.logger if app else logging.getLogger(__name__)
            logger.error(f"Database error setting config {key}: {e}", exc_info=True)
            raise # Re-raise after logging

# ----------------------------
# Helper Functions & Decorators
# ----------------------------

def get_db_config_value(key, default=None, value_type=str):
    """Helper to get config value from DB with type casting."""
    str_value = Configuration.get(key)
    if str_value is None:
        return default
    try:
        if value_type == bool:
            # Handle boolean strings explicitly
            return str_value.lower() in ('true', '1', 'yes', 't')
        return value_type(str_value)
    except (ValueError, TypeError):
        logger = app.logger if app else logging.getLogger(__name__)
        logger.warning(f"Could not cast config value for key '{key}' ('{str_value}') to type {value_type}. Returning default.")
        return default

# --- Helper function to get config value from DB, falling back to App Config (Env Default) ---
def get_effective_config_value(db_key, app_config_key, value_type=str, default_value=None):
    """Gets a config value, checking DB first, then app.config (env var default)."""
    db_value = get_db_config_value(db_key, value_type=value_type)
    if db_value is not None:
        return db_value
    # Fallback to app.config (environment variable default)
    # Ensure we are in an app context to access current_app
    if has_app_context(): 
        return current_app.config.get(app_config_key, default_value)
    else:
        # Fallback if no context (should not happen in normal request/CLI flow but safer)
        # This might require loading config manually if needed outside context
        # For simplicity, returning default here. Adjust if needed.
        return default_value
# ----------------------------------------------------------------------------------------

# -- Admin Required Decorator --
def admin_required(fn):
    """Decorator to ensure the requesting user has admin privileges."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        # Assumes @jwt_required() is also applied to the route
        current_user_identity = get_jwt_identity()
        user = User.query.filter_by(username=current_user_identity).first()

        if not user:
            # This case should ideally not happen if JWT is valid and user exists
            return jsonify({"msg": "Admin access required, user not found."}), 403

        if not user.is_admin:
            return jsonify({"msg": "Admin access required."}), 403

        return fn(*args, **kwargs)
    return wrapper


# ----------------------------
# Database Initialization / Migration Notes
# ----------------------------
# Database table creation and schema migrations are handled by Flask-Migrate.
# Use `flask db init` (once), `flask db migrate`, and `flask db upgrade`.


# ----------------------------
# Authentication Endpoint
# ----------------------------
@app.route("/login", methods=["POST", "OPTIONS"])
@cross_origin(supports_credentials=True)
@limiter.limit("10/minute") # Apply rate limiting
def login():
    """Authenticates a user and returns a JWT access token.

    Expects JSON:
      {
         "username": "<username>",
         "password": "<password>"
      }
    Returns:
        JSON with access_token and username on success (200).
        JSON with error message on failure (400, 401).
    """
    json_data = request.get_json()
    if not json_data:
        return jsonify({"msg": "Missing JSON body"}), 400

    try:
        validated_data = LoginSchema(**json_data)
    except ValidationError as e:
        return jsonify({"msg": "Validation Error", "details": e.errors()}), 400

    user = User.query.filter_by(username=validated_data.username).first()
    if user and user.check_password(validated_data.password):
        # Determine token expiry using effective values
        expiry_enabled = get_effective_config_value(CONFIG_JWT_EXPIRY_ENABLED, "JWT_EXPIRY_ENABLED_DEFAULT", bool, False)
        expiry_minutes = get_effective_config_value(CONFIG_JWT_EXPIRY_MINUTES, "JWT_EXPIRY_MINUTES_DEFAULT", int, 0)
        expires_delta = timedelta(minutes=expiry_minutes) if expiry_enabled and expiry_minutes > 0 else False
        
        access_token = create_access_token(
            identity=user.username,
            additional_claims={"is_admin": user.is_admin},
            expires_delta=expires_delta
        )
        # Return username along with token
        return jsonify(access_token=access_token, username=user.username), 200

    return jsonify({"msg": "Bad username or password"}), 401

# ----------------------------
# Current User Endpoint
# ----------------------------
@app.route("/currentuser", methods=["GET", "OPTIONS"])
@cross_origin(supports_credentials=True)
@jwt_required()
def get_current_user():
    """Returns details for the currently authenticated user.

    Requires a valid JWT in the Authorization header.
    Returns:
        JSON User object (excluding password) on success (200).
        JSON error message if user not found (404).
    """
    current_user_identity = get_jwt_identity() # This is the username
    user = User.query.filter_by(username=current_user_identity).first()
    
    if not user:
        # Should not happen with a valid token, but handle defensively
        return jsonify({"message": "User not found for current token"}), 404

    # Use Pydantic schema to serialize user data safely
    try:
        user_data = UserOutputSchema.model_validate(user)
        return jsonify(user_data.model_dump()), 200
    except ValidationError as e:
        app.logger.error(f"Error serializing current user data for {current_user_identity}: {e}", exc_info=True)
        return jsonify({"message": "Error processing user data"}), 500


# ----------------------------
# Lock Management Endpoints
# ----------------------------
@app.route("/locks", methods=["GET", "OPTIONS"])
@cross_origin(origins="*", methods=["GET", "OPTIONS"], headers=["Content-Type", "Authorization"], supports_credentials=True)
@jwt_required()
def list_locks():
    """Lists all currently active locks.

    Requires a valid JWT.
    Returns:
        JSON list of lock objects on success (200).
    """
    locks = Lock.query.all()
    results = []
    for lock in locks:
        results.append({
            "id": lock.id,
            "asset_path": lock.asset_path,
            "locked_by": lock.locked_by,
            "branch": lock.branch,
            "timestamp": lock.timestamp.isoformat(),
            "comment": lock.comment
        })
    return jsonify(results), 200


@app.route("/locks", methods=["POST", "OPTIONS"])
@cross_origin(supports_credentials=True)
@jwt_required()
def create_lock():
    """Creates a new lock for the requesting user on an asset.

    Expects JSON:
      {
         "asset_path": "<path/to/asset>",
         "branch": "<branch_name>",
         "comment": "<optional comment>"
      }
    Returns:
        JSON with lock details on success (201 Created).
        JSON with error message on failure (400, 409 Conflict, 500).
    """
    json_data = request.get_json()
    if not json_data:
        return jsonify({"msg": "Missing JSON body"}), 400

    try:
        validated_data = CreateLockSchema(**json_data)
    except ValidationError as e:
        return jsonify({"msg": "Validation Error", "details": e.errors()}), 400

    asset_path = validated_data.asset_path # Use validated data
    branch = validated_data.branch
    comment = validated_data.comment

    if Lock.query.filter_by(asset_path=asset_path).first():
        return jsonify({"msg": "Asset is already locked"}), 409

    current_user_username = get_jwt_identity()
    # Check if user exists (redundant if JWT is valid, but safe)
    locking_user = User.query.filter_by(username=current_user_username).first()
    if not locking_user:
        return jsonify({"msg": "Locking user not found"}), 400 # Or 401/404

    new_lock = Lock(
        asset_path=asset_path,
        locked_by=current_user_username,
        branch=branch,
        comment=comment
    )
    try:
        db.session.add(new_lock)
        db.session.commit()

        # --- Send Lock Notification Email --- 
        try:
            # Find all users *except* the one who just locked the file
            other_users = User.query.filter(User.username != current_user_username).all()
            recipient_emails = [user.email for user in other_users if user.email] # Collect valid emails
            
            if recipient_emails:
                app.logger.info(f"Sending lock notification for '{asset_path}' to: {recipient_emails}")
                send_email(
                    subject=f"Asset Locked: {asset_path}",
                    recipients=recipient_emails,
                    text_body=f"Hello,\n\nThe asset '{asset_path}' was locked by user '{current_user_username}'.\nComment: {comment if comment else 'N/A'}",
                    html_body=f"<p>Hello,</p>" 
                              f"<p>The asset <code>{asset_path}</code> was locked by user <strong>{current_user_username}</strong>.</p>" 
                              f"<p>Comment: <i>{comment if comment else 'N/A'}</i></p>"
                )
            else:
                app.logger.info(f"No other users found to notify about lock on '{asset_path}'")
        except Exception as email_error:
            app.logger.error(f"Failed to send lock notification email for {asset_path}: {email_error}", exc_info=True)
            # Log error but do not fail the lock creation
        # --- End Lock Notification --- 

    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Database error acquiring lock for {asset_path}: {e}", exc_info=True)
        return jsonify({"msg": "Database error occurred while acquiring lock."}), 500
    return jsonify({
        "msg": "Lock acquired",
        "lock": {
            "asset_path": new_lock.asset_path,
            "locked_by": new_lock.locked_by,
            "branch": new_lock.branch,
            "timestamp": new_lock.timestamp.isoformat(),
            "comment": new_lock.comment
        }
    }), 201


@app.route("/locks/<path:asset_path>", methods=["GET", "OPTIONS"])
@cross_origin(supports_credentials=True)
@jwt_required()
def get_lock(asset_path):
    """Retrieves details for a specific lock by asset path.

    Requires a valid JWT.
    Returns:
        JSON with lock details on success (200).
        JSON {"msg": "Lock not found"} if not found (404).
    """
    lock = Lock.query.filter_by(asset_path=asset_path).first()
    if not lock:
        return jsonify({"msg": "Lock not found"}), 404

    return jsonify({
        "asset_path": lock.asset_path,
        "locked_by": lock.locked_by,
        "branch": lock.branch,
        "timestamp": lock.timestamp.isoformat(),
        "comment": lock.comment
    }), 200


@app.route("/locks/<path:asset_path>", methods=["DELETE", "OPTIONS"])
@cross_origin(supports_credentials=True)
@jwt_required()
def delete_lock(asset_path):
    """Deletes a lock for a specific asset path.

    Requires a valid JWT. User must be the owner of the lock.
    Returns:
        JSON {"msg": "Lock released"} on success (200).
        JSON with error message on failure (403 Forbidden, 404 Not Found, 500).
    """
    lock = Lock.query.filter_by(asset_path=asset_path).first()
    if not lock:
        return jsonify({"msg": "Lock not found"}), 404

    current_user = get_jwt_identity()
    if lock.locked_by != current_user:
        return jsonify({"msg": "You do not have permission to release this lock"}), 403

    try:
        db.session.delete(lock)
        db.session.commit()
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Database error releasing lock for {asset_path}: {e}", exc_info=True)
        return jsonify({"msg": "Database error occurred while releasing lock."}), 500
    return jsonify({"msg": "Lock released"}), 200


@app.route("/locks/auto-release", methods=["POST", "OPTIONS"])
@cross_origin(supports_credentials=True)
@jwt_required()
def auto_release():
    """Deletes all locks associated with a specific Git branch.

    Expects JSON:
      {
         "branch": "<branch_name>"
      }
    Returns:
        JSON {"msg": "Auto-released N locks..."} on success (200).
        JSON with error message on failure (400, 500).
    """
    json_data = request.get_json()
    if not json_data:
        return jsonify({"msg": "Missing JSON body"}), 400

    try:
        validated_data = AutoReleaseSchema(**json_data)
    except ValidationError as e:
        return jsonify({"msg": "Validation Error", "details": e.errors()}), 400

    branch = validated_data.branch # Use validated data
    locks = Lock.query.filter_by(branch=branch).all()
    count = len(locks)
    for lock in locks:
        db.session.delete(lock)
    try:
        db.session.commit()
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Database error during auto-release commit for branch {branch}: {e}", exc_info=True)
        return jsonify({"msg": "Database error occurred during auto-release commit."}), 500
    return jsonify({"msg": f"Auto-released {count} locks for branch {branch}"}), 200

# --- Notify Lock Holder Endpoint ---
@app.route("/locks/path/<path:asset_path>/notify", methods=["POST", "OPTIONS"])
@cross_origin(supports_credentials=True)
@jwt_required()
def notify_lock_holder(asset_path):
    """Sends an email notification to the holder of a specific lock.

    Triggered by another authenticated user clicking the 'Notify' button.
    Requires a valid JWT.
    Returns:
        JSON {"msg": "Notification sent successfully."} on success (200).
        JSON with error message on failure (400, 404, 500).
    """
    notifier_username = get_jwt_identity()
    notification_message = None # Default to no message

    # Attempt to parse optional JSON body for a message
    json_data = request.get_json(silent=True) # Use silent=True to not raise error if no body
    if json_data:
        try:
            validated_data = NotifyMessageSchema(**json_data)
            notification_message = validated_data.message # Can be None if not provided
        except ValidationError as e:
            # If body exists but doesn't match schema, return validation error
            return jsonify({"msg": "Validation Error in request body", "details": e.errors()}), 400

    normalized_path = Lock.normalize_path(asset_path)
    lock = Lock.query.filter_by(asset_path=normalized_path).first()

    if not lock:
        return jsonify({"msg": "Lock not found for the specified asset path."}), 404

    lock_holder_username = lock.locked_by

    if notifier_username == lock_holder_username:
        return jsonify({"msg": "You cannot notify yourself about your own lock."}), 400

    # Find the lock holder user to get their email
    lock_holder_user = User.query.filter_by(username=lock_holder_username).first()
    if not lock_holder_user:
        app.logger.error(f"Could not find user object for lock holder '{lock_holder_username}' during notification attempt for '{normalized_path}'.")
        # Don't expose user existence details, return a generic error
        return jsonify({"msg": "Could not process notification request."}), 500
    if not lock_holder_user.email:
        app.logger.warning(f"Lock holder '{lock_holder_username}' does not have an email address. Cannot send notification for '{normalized_path}'.")
        return jsonify({"msg": f"User '{lock_holder_username}' has no email address configured. Notification not sent."}), 400

    # Check if mail system is enabled
    is_mail_enabled = get_effective_config_value(CONFIG_MAIL_ENABLED, "MAIL_ENABLED", bool, False)
    if not is_mail_enabled:
        app.logger.info(f"Mail system disabled. Skipping notification from {notifier_username} to {lock_holder_username} for {normalized_path}.")
        return jsonify({"msg": "Email system is currently disabled. Notification not sent."}), 400 # Or maybe 200 with this message? Let's use 400 for clarity.

    # Proceed to send email
    try:
        text_body_content = f"Hello {lock_holder_username},\n\nUser '{notifier_username}' has sent a notification regarding your lock on the asset: {normalized_path}"
        html_body_content = f"<p>Hello {lock_holder_username},</p>" \
                          f"<p>User <strong>{notifier_username}</strong> has sent a notification regarding your lock on the asset:</p>" \
                          f"<p><code>{normalized_path}</code></p>"

        # Append optional message if provided
        if notification_message:
            text_body_content += f"\n\nMessage from {notifier_username}:\n{notification_message}"
            html_body_content += f"<p><strong>Message from {notifier_username}:</strong></p><p style=\"white-space: pre-wrap;\">{notification_message}</p>" # Use pre-wrap for formatting

        text_body_content += f"\n\nPlease check the Asset Lock Manager dashboard."
        html_body_content += f"<p>Please check the Asset Lock Manager dashboard.</p>"

        send_email(
            subject=f"Asset Lock Notification: {normalized_path}",
            recipients=[lock_holder_user.email],
            text_body=text_body_content,
            html_body=html_body_content
        )
        app.logger.info(f"Notification email sent successfully from {notifier_username} to {lock_holder_username} ({lock_holder_user.email}) for asset {normalized_path}.")
        return jsonify({"msg": "Notification sent successfully."}), 200
    except Exception as e:
        app.logger.error(f"Failed to send notification email from {notifier_username} to {lock_holder_username} for {normalized_path}: {e}", exc_info=True)
        return jsonify({"msg": "Failed to send notification email due to a server error."}), 500

# ----------------------------
# Public Configuration Status Endpoint
# ----------------------------
@app.route("/config/status", methods=["GET", "OPTIONS"])
@cross_origin(supports_credentials=True)
@jwt_required() # Requires login, but not admin
def get_public_config_status():
    """Retrieve essential public configuration status (e.g., mail enabled)."""
    try:
        # Get effective mail enabled status (DB override -> Env Default)
        # Uses the same logic as the admin endpoint but only retrieves this one value
        db_mail_enabled = get_db_config_value(CONFIG_MAIL_ENABLED, value_type=bool) 
        is_mail_enabled = db_mail_enabled if db_mail_enabled is not None else app.config.get("MAIL_ENABLED", False)
        
        # Log the determined status for debugging
        app.logger.debug(f"Public config status check: mail_enabled={is_mail_enabled} (DB: {db_mail_enabled}, App Default: {app.config.get('MAIL_ENABLED')})")

        return jsonify({"mail_enabled": is_mail_enabled}), 200
    except Exception as e:
        app.logger.error(f"Error fetching public config status: {e}", exc_info=True)
        # Return a default state (e.g., mail disabled) to prevent frontend errors?
        # Or a specific error? Let's return an error for now.
        return jsonify({"message": "Failed to retrieve configuration status"}), 500

# ----------------------------
# Admin User Management Endpoints
# ----------------------------
@app.route("/admin/users", methods=["GET", "OPTIONS"])
@cross_origin(supports_credentials=True)
@jwt_required()
@admin_required
def list_users():
    """(Admin) Lists all registered users.

    Requires admin privileges.
    Returns:
        JSON list of user objects (using UserOutputSchema) on success (200).
        JSON with error message on failure (500).
    """
    try:
        users = User.query.all()
        # Serialize using Pydantic schema to control output
        result = [UserOutputSchema.from_orm(user).dict() for user in users]
        return jsonify(result), 200
    except Exception as e:
        app.logger.error(f"Error listing users: {e}", exc_info=True)
        return jsonify({"msg": "Error listing users."}), 500

@app.route("/admin/users", methods=["POST", "OPTIONS"])
@cross_origin(supports_credentials=True)
@jwt_required()
@admin_required
def create_user_admin():
    """(Admin) Creates a new non-admin user.

    Requires admin privileges.
    Expects JSON (CreateUserSchema).
    Returns:
        JSON user object (UserOutputSchema) on success (201 Created).
        JSON with error message on failure (400, 409 Conflict, 500).
    """
    json_data = request.get_json()
    if not json_data:
        return jsonify({"msg": "Missing JSON body"}), 400

    try:
        validated_data = CreateUserSchema(**json_data)
    except ValidationError as e:
        return jsonify({"msg": "Validation Error", "details": e.errors()}), 400

    # Check for existing username or email
    existing_user = User.query.filter(
        (User.username == validated_data.username) | (User.email == validated_data.email)
    ).first()
    if existing_user:
        field = "username" if existing_user.username == validated_data.username else "email"
        return jsonify({"msg": f"Conflict: {field} already exists."}), 409

    # Call the updated create method
    new_user = User.create(
        username=validated_data.username,
        password=validated_data.password,
        email=validated_data.email,
        is_admin=False # Explicitly create as non-admin
    )

    if new_user is None:
        # User.create already logged the SQLAlchemyError
        return jsonify({"msg": "Database error occurred while creating user."}), 500

    # Serialize output to control fields returned
    try:
        # Use Pydantic v2 syntax
        user_output = UserOutputSchema.model_validate(new_user)
        return jsonify(user_output.model_dump()), 201 # 201 Created
    except ValidationError as e: # Catch potential Pydantic validation/serialization errors
        app.logger.error(f"Error serializing created user {new_user.username}: {e}", exc_info=True)
        # Technically user was created, but we can't return the data as expected.
        return jsonify({"msg": "User created, but encountered error preparing response."}), 500

@app.route("/admin/users/<int:user_id>/password", methods=["PUT", "OPTIONS"])
@cross_origin(supports_credentials=True)
@jwt_required()
@admin_required
def admin_change_user_password(user_id):
    """(Admin) Changes a specific user's password.

    Requires admin privileges.
    Expects JSON (AdminChangePasswordSchema).
    Returns:
        JSON confirmation message on success (200).
        JSON with error message on failure (400, 404 Not Found, 500).
    """
    user = User.query.get(user_id)
    if not user:
        return jsonify({"msg": "User not found."}), 404

    json_data = request.get_json()
    if not json_data:
        return jsonify({"msg": "Missing JSON body"}), 400

    try:
        validated_data = AdminChangePasswordSchema(**json_data)
    except ValidationError as e:
        return jsonify({"msg": "Validation Error", "details": e.errors()}), 400

    try:
        user.password_hash = generate_password_hash(validated_data.new_password)
        db.session.commit()
        return jsonify({"msg": f"Password for user {user.username} updated successfully."}), 200
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Database error updating password for user {user.username} (ID: {user_id}): {e}", exc_info=True)
        return jsonify({"msg": "Database error occurred while updating password."}), 500
    except Exception as e:
        app.logger.error(f"Error updating password for user {user_id}: {e}", exc_info=True)
        return jsonify({"msg": "An unexpected error occurred while updating password."}), 500

@app.route("/admin/users/<int:user_id>/email", methods=["PUT", "OPTIONS"])
@cross_origin(supports_credentials=True)
@jwt_required()
@admin_required
def admin_change_user_email(user_id):
    """(Admin) Changes a specific user's email.

    Requires admin privileges.
    Expects JSON (AdminChangeEmailSchema).
    Checks for email conflicts.
    Returns:
        JSON confirmation message on success (200).
        JSON with error message on failure (400, 404 Not Found, 409 Conflict, 500).
    """
    user = User.query.get(user_id)
    if not user:
        return jsonify({"msg": "User not found."}), 404

    json_data = request.get_json()
    if not json_data:
        return jsonify({"msg": "Missing JSON body"}), 400

    try:
        validated_data = AdminChangeEmailSchema(**json_data)
    except ValidationError as e:
        return jsonify({"msg": "Validation Error", "details": e.errors()}), 400

    # Check if the new email is already taken by another user
    existing_email_user = User.query.filter(
        User.email == validated_data.new_email,
        User.id != user_id # Exclude the current user being modified
    ).first()
    if existing_email_user:
        return jsonify({"msg": "Conflict: Email already in use by another user."}), 409

    try:
        user.email = validated_data.new_email
        db.session.commit()
        return jsonify({"msg": f"Email for user {user.username} updated successfully."}), 200
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Database error updating email for user {user.username} (ID: {user_id}): {e}", exc_info=True)
        return jsonify({"msg": "Database error occurred while updating email."}), 500
    except Exception as e:
        app.logger.error(f"Error updating email for user {user_id}: {e}", exc_info=True)
        return jsonify({"msg": "An unexpected error occurred while updating email."}), 500

@app.route("/admin/users/<int:user_id>/status", methods=["PUT", "OPTIONS"])
@cross_origin(supports_credentials=True)
@jwt_required()
@admin_required
def admin_change_user_status(user_id):
    """(Admin) Changes a specific user's admin status.

    Requires admin privileges.
    Prevents admin from changing their own status via this endpoint.
    Expects JSON (UpdateUserStatusSchema).
    Returns:
        JSON updated user object (UserOutputSchema) on success (200).
        JSON with error message on failure (400, 403 Forbidden, 404 Not Found, 500).
    """
    user_to_modify = User.query.get(user_id)
    if not user_to_modify:
        return jsonify({"msg": "User not found."}), 404

    # Prevent admin from changing their own status via this endpoint
    current_admin_username = get_jwt_identity()
    current_admin = User.query.filter_by(username=current_admin_username).first()
    # Ensure current_admin is not None before accessing id
    if current_admin and current_admin.id == user_id:
        return jsonify({"msg": "Cannot change your own admin status via this endpoint."}), 403

    json_data = request.get_json()
    if not json_data:
        return jsonify({"msg": "Missing JSON body"}), 400

    try:
        validated_data = UpdateUserStatusSchema(**json_data)
    except ValidationError as e:
        return jsonify({"msg": "Validation Error", "details": e.errors()}), 400

    try:
        user_to_modify.is_admin = validated_data.is_admin
        db.session.commit()
        # Return updated user info
        user_output = UserOutputSchema.from_orm(user_to_modify).dict()
        return jsonify(user_output), 200
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Database error updating status for user {user_to_modify.username} (ID: {user_id}): {e}", exc_info=True)
        return jsonify({"msg": "Database error occurred while updating status."}), 500
    except Exception as e:
        app.logger.error(f"Error updating status for user {user_id}: {e}", exc_info=True)
        return jsonify({"msg": "An unexpected error occurred while updating status."}), 500

@app.route("/admin/users/<int:user_id>", methods=["DELETE", "OPTIONS"])
@cross_origin(supports_credentials=True)
@jwt_required()
@admin_required
def admin_delete_user(user_id):
    """(Admin) Deletes a specific user and their associated locks.

    Requires admin privileges.
    Prevents admin from deleting themselves.
    Returns:
        Empty response on success (204 No Content).
        JSON with error message on failure (403 Forbidden, 404 Not Found, 500).
    """
    user_to_delete = User.query.get(user_id)
    if not user_to_delete:
        return jsonify({"msg": "User not found."}), 404

    # Prevent admin from deleting themselves
    current_admin_username = get_jwt_identity()
    current_admin = User.query.filter_by(username=current_admin_username).first()
    # Ensure current_admin is not None before accessing id
    if current_admin and current_admin.id == user_id:
        return jsonify({"msg": "Cannot delete your own account."}), 403

    try:
        # Delete locks associated with the user first
        locks_to_delete = Lock.query.filter_by(locked_by=user_to_delete.username).all()
        if locks_to_delete:
            app.logger.info(f"Deleting {len(locks_to_delete)} locks associated with user {user_to_delete.username} (ID: {user_id}).")
            for lock in locks_to_delete:
                db.session.delete(lock)

        # Now delete the user
        db.session.delete(user_to_delete)

        # Commit transaction (covers both lock and user deletion)
        db.session.commit()
        app.logger.info(f"Successfully deleted user {user_to_delete.username} (ID: {user_id}) and associated locks.")
        return '', 204 # No Content success status
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Database error deleting user {user_id}: {e}", exc_info=True)
        return jsonify({"msg": "Database error occurred while deleting user."}), 500
    except Exception as e:
        app.logger.error(f"Error deleting user {user_id}: {e}", exc_info=True)
        return jsonify({"msg": "An unexpected error occurred while deleting user."}), 500


# ----------------------------
# User Self-Service Endpoints
# ----------------------------
@app.route("/users/me/password", methods=["PUT", "OPTIONS"])
@cross_origin(supports_credentials=True)
@jwt_required()
def change_password_self():
    """Initiates the password change process for the currently authenticated user.

    Sends a confirmation email to the user's *current confirmed* address.
    Does *not* change the password immediately.
    Requires valid JWT. Expects JSON (ChangePasswordSchema).
    Verifies current password.
    Returns:
        JSON confirmation message on success (200).
        JSON with error message on failure (400, 401, 404, 500).
    """
    current_user_username = get_jwt_identity()
    user = User.query.filter_by(username=current_user_username).first()

    if not user:
        return jsonify({"msg": "User not found."}), 404

    json_data = request.get_json()
    if not json_data:
        return jsonify({"msg": "Missing JSON body"}), 400

    try:
        validated_data = ChangePasswordSchema(**json_data)
    except ValidationError as e:
        return jsonify({"msg": "Validation Error", "details": e.errors()}), 400

    # Verify current password
    if not check_password_hash(user.password_hash, validated_data.current_password):
        return jsonify({"msg": "Invalid current password."}), 401

    # --- Check if email confirmation should be skipped ---
    # Use effective value for mail enabled check
    skip_confirmation = not get_effective_config_value(CONFIG_MAIL_ENABLED, "MAIL_ENABLED", bool, False)
    
    if skip_confirmation:
        try:
            # Directly update the password hash
            user.password_hash = generate_password_hash(validated_data.new_password)
            # Clear any potentially stale confirmation fields
            user.pending_password_hash = None
            user.confirmation_token = None
            user.token_expiration = None
            db.session.commit()
            app.logger.info(f"User {current_user_username} changed password directly (email disabled).")
            # Note: Consider sending an in-app notification if available
            return jsonify({"msg": "Password updated successfully."}), 200
        except SQLAlchemyError as e:
            db.session.rollback()
            app.logger.error(f"Database error directly updating password for user {current_user_username}: {e}", exc_info=True)
            return jsonify({"msg": "Database error occurred while updating password."}), 500
        except Exception as e:
            app.logger.error(f"Unexpected error directly updating password for user {current_user_username}: {e}", exc_info=True)
            return jsonify({"msg": "An unexpected error occurred."}), 500
    else:
        # Generate token and store pending change (original logic)
        try:
            token, expiration = generate_confirmation_token(user.id, TOKEN_PASSWORD_CONFIRM)
            user.pending_password_hash = generate_password_hash(validated_data.new_password)
            user.confirmation_token = token
            user.token_expiration = expiration
            db.session.commit()

            # Send confirmation email to the user's *current confirmed* email address
            try:
                send_email(
                    subject="Confirm Your Password Change",
                    recipients=[user.email], # Send to current confirmed email
                    text_body=f"Hello {user.username},\n\nPlease click the following link to confirm your password change for the Asset Lock Manager: {generate_confirmation_url(token, TOKEN_PASSWORD_CONFIRM)}\n\nThis link will expire at {expiration.isoformat()} UTC. If you did not request this change, please ignore this email or contact an administrator.",
                    html_body=f"<p>Hello {user.username},</p><p>Please click the link below to confirm your password change for the Asset Lock Manager:</p><p><a href=\"{generate_confirmation_url(token, TOKEN_PASSWORD_CONFIRM)}\">{generate_confirmation_url(token, TOKEN_PASSWORD_CONFIRM)}</a></p><p>This link will expire at {expiration.isoformat()} UTC.</p><p>If you did not request this change, please ignore this email or contact an administrator.</p>"
                )
                app.logger.info(f"Sent password change confirmation link to {user.email} for user {user.username}")
            except Exception as email_error:
                db.session.rollback() # Rollback token/pending hash storage if email fails
                app.logger.error(f"Failed to send password change confirmation to {user.email}: {email_error}", exc_info=True)
                return jsonify({"msg": "Failed to send confirmation email. Please try again later."}), 500

            return jsonify({"msg": f"Confirmation email sent to {user.email}. Please check your inbox to complete the change."}), 200

        except SQLAlchemyError as e:
            db.session.rollback()
            app.logger.error(f"Database error confirming password for user ID {user.id}: {e}", exc_info=True)
            return jsonify({"msg": "Database error occurred during confirmation."}), 500
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error confirming password for user ID {user.id}: {e}", exc_info=True)
            return jsonify({"msg": "An unexpected error occurred during confirmation."}), 500

    # This function should always return a response from one of the branches
    app.logger.error("Reached end of change_passworsd_self without returning a response.")
    return jsonify({"msg": "Internal server error."}), 500

@app.route("/users/me/email", methods=["PUT", "OPTIONS"])
@cross_origin(supports_credentials=True)
@jwt_required()
def change_email_self():
    """Initiates the email change process for the currently authenticated user.

    Sends a confirmation email to the *new* address.
    Does *not* change the email immediately.
    Requires valid JWT. Expects JSON (ChangeEmailSchema).
    Verifies current password. Checks for email conflicts (pending or confirmed).
    Returns:
        JSON confirmation message on success (200).
        JSON with error message on failure (400, 401, 404, 409, 500).
    """
    current_user_username = get_jwt_identity()
    user = User.query.filter_by(username=current_user_username).first()

    if not user:
        return jsonify({"msg": "User not found."}), 404

    json_data = request.get_json()
    if not json_data:
        return jsonify({"msg": "Missing JSON body"}), 400

    try:
        validated_data = ChangeEmailSchema(**json_data)
    except ValidationError as e:
        return jsonify({"msg": "Validation Error", "details": e.errors()}), 400

    if not user.check_password(validated_data.current_password):
        return jsonify({"msg": "Invalid current password."}), 401

    new_email = validated_data.new_email

    # Prevent setting the same email
    if user.email == new_email:
        return jsonify({"msg": "New email cannot be the same as the current email."}), 400

    # Check if the new email is already taken (or pending) by *another* user
    existing_user = User.query.filter(
        (User.email == new_email) | (User.pending_email == new_email),
        User.id != user.id
    ).first()
    if existing_user:
        return jsonify({"msg": "Conflict: Email already in use or pending confirmation by another user."}), 409

    # --- Check if email confirmation should be skipped ---
    # Use effective value for mail enabled check
    skip_confirmation = not get_effective_config_value(CONFIG_MAIL_ENABLED, "MAIL_ENABLED", bool, False)

    if skip_confirmation:
        try:
            # Directly update the email
            user.email = new_email
            # Clear any potentially stale confirmation fields
            user.pending_email = None
            user.confirmation_token = None
            user.token_expiration = None
            db.session.commit()
            app.logger.info(f"User {current_user_username} changed email to {new_email} directly (email disabled).")
            # Note: Consider sending an in-app notification if available
            return jsonify({"msg": "Email updated successfully."}), 200
        except SQLAlchemyError as e:
            db.session.rollback()
            app.logger.error(f"Database error directly updating email for user {current_user_username}: {e}", exc_info=True)
            return jsonify({"msg": "Database error occurred while updating email."}), 500
        except Exception as e:
            app.logger.error(f"Unexpected error directly updating email for user {current_user_username}: {e}", exc_info=True)
            return jsonify({"msg": "An unexpected error occurred."}), 500

    # Generate token and store pending change (original logic if MAIL_ENABLED is True)
    try:
        token, expiration = generate_confirmation_token(user.id, TOKEN_EMAIL_CONFIRM)
        user.pending_email = new_email
        user.confirmation_token = token
        user.token_expiration = expiration
        # Do NOT change user.email yet
        db.session.commit()

        # Send confirmation email to the *new* address
        confirmation_url = generate_confirmation_url(token, TOKEN_EMAIL_CONFIRM)
        try:
            send_email(
                subject="Confirm Your Email Address Change",
                recipients=[new_email], # Send to the new email
                text_body=f"Hello {user.username},\n\nPlease click the following link to confirm your email address change for the Asset Lock Manager: {confirmation_url}\n\nThis link will expire at {expiration.isoformat()} UTC.",
                html_body=f"<p>Hello {user.username},</p><p>Please click the link below to confirm your email address change for the Asset Lock Manager:</p><p><a href=\"{confirmation_url}\">{confirmation_url}</a></p><p>This link will expire at {expiration.isoformat()} UTC.</p>"
            )
            app.logger.info(f"Sent email change confirmation link to {new_email} for user {user.username}")
        except Exception as email_error:
            # Rollback DB changes if email fails? Or just log?
            # Log for now, user can try again. Consider rollback if critical.
            db.session.rollback() # Rollback token/pending email storage if email fails
            app.logger.error(f"Failed to send email change confirmation to {new_email}: {email_error}", exc_info=True)
            return jsonify({"msg": "Failed to send confirmation email. Please try again later."}), 500

        return jsonify({"msg": f"Confirmation email sent to {new_email}. Please check your inbox to complete the change."}), 200

    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Database error initiating email change for user {current_user_username}: {e}", exc_info=True)
        return jsonify({"msg": "Database error occurred while initiating email change."}), 500
    except Exception as e:
        # Catch potential token generation errors etc.
        db.session.rollback()
        app.logger.error(f"Error initiating email change for user {current_user_username}: {e}", exc_info=True)
        return jsonify({"msg": "An unexpected error occurred."}), 500


# Removed duplicate definition of change_email_self endpoint


# Removed duplicate definition of admin_delete_user endpoint


# ----------------------------
# Admin Configuration API Routes
# ----------------------------

# Define keys for configuration settings
CONFIG_JWT_EXPIRY_ENABLED = "jwt.expiry.enabled"
CONFIG_JWT_EXPIRY_MINUTES = "jwt.expiry.minutes"
CONFIG_AUTO_RELEASE_ENABLED = "auto_release.enabled"
CONFIG_AUTO_RELEASE_HOURS = "auto_release.hours"
# Re-adding mail enabled constant for DB override
CONFIG_MAIL_ENABLED = "mail.enabled"

@app.route("/admin/config", methods=["GET", "OPTIONS"])
@cross_origin(supports_credentials=True)
@jwt_required()
@admin_required
def get_admin_config():
    """Retrieve the current admin-configurable settings, applying DB overrides over env defaults."""
    try:
        STARTUP_MAIL_TEST_STATUS_KEY = "system.startup.mail_test_status"
        config_data = {}

        # JWT Settings (DB override Env)
        db_jwt_enabled = get_db_config_value(CONFIG_JWT_EXPIRY_ENABLED, value_type=bool) # Returns None if not in DB
        config_data["jwt_expiry_enabled"] = db_jwt_enabled if db_jwt_enabled is not None else app.config.get("JWT_EXPIRY_ENABLED_DEFAULT", False)
        
        db_jwt_minutes = get_db_config_value(CONFIG_JWT_EXPIRY_MINUTES, value_type=int)
        config_data["jwt_expiry_minutes"] = db_jwt_minutes if db_jwt_minutes is not None else app.config.get("JWT_EXPIRY_MINUTES_DEFAULT", 0)

        # Auto Release Settings (DB override Env)
        db_auto_release_enabled = get_db_config_value(CONFIG_AUTO_RELEASE_ENABLED, value_type=bool)
        config_data["auto_release_enabled"] = db_auto_release_enabled if db_auto_release_enabled is not None else app.config.get("AUTO_RELEASE_ENABLED", False)
        
        db_auto_release_hours = get_db_config_value(CONFIG_AUTO_RELEASE_HOURS, value_type=int)
        config_data["auto_release_hours"] = db_auto_release_hours if db_auto_release_hours is not None else app.config.get("AUTO_RELEASE_HOURS", 72)

        # Mail Enabled Setting (DB override Env) - For display/control
        db_mail_enabled = get_db_config_value(CONFIG_MAIL_ENABLED, value_type=bool)
        config_data["mail_enabled"] = db_mail_enabled if db_mail_enabled is not None else app.config.get("MAIL_ENABLED", False)

        # Add startup mail test status from DB (no env default for this)
        config_data["startup_mail_test_status"] = get_db_config_value(STARTUP_MAIL_TEST_STATUS_KEY, default="UNKNOWN")

        return jsonify(config_data), 200
    except Exception as e:
        app.logger.error(f"Error fetching admin configuration: {e}", exc_info=True)
        return jsonify({"message": "Failed to retrieve configuration"}), 500

class AdminUpdateConfigSchema(BaseModel):
    """Schema for updating admin configuration."""
    jwt_expiry_enabled: Optional[bool] = None
    jwt_expiry_minutes: Optional[int] = None
    auto_release_enabled: Optional[bool] = None
    auto_release_hours: Optional[int] = None
    # Restoring mail_enabled
    mail_enabled: Optional[bool] = None

@app.route("/admin/config", methods=["PUT", "OPTIONS"])
@cross_origin(supports_credentials=True)
@jwt_required()
@admin_required
def update_admin_config():
    """Update admin-configurable settings."""
    json_data = request.get_json()
    if not json_data:
        return jsonify({"msg": "Missing JSON body"}), 400

    try:
        config_update = AdminUpdateConfigSchema(**json_data)
    except ValidationError as e:
        return jsonify({"msg": "Validation Error", "details": e.errors()}), 400

    try:
        # Identify keys we might update
        keys_to_update = [
            CONFIG_JWT_EXPIRY_ENABLED,
            CONFIG_JWT_EXPIRY_MINUTES,
            CONFIG_AUTO_RELEASE_ENABLED,
            CONFIG_AUTO_RELEASE_HOURS,
            CONFIG_MAIL_ENABLED
        ]
        
        # Fetch existing config values beforehand
        existing_configs = {c.key: c for c in Configuration.query.filter(Configuration.key.in_(keys_to_update)).all()}

        with db.session.begin_nested():
            # Helper to update or create config
            def update_or_create_config(key, value_str):
                if key in existing_configs:
                    existing_configs[key].value = value_str
                else:
                    # Need to add the new object to the dict as well in case it's referenced later in the same transaction?
                    # For now, just add to session. If there are dependencies, pre-fetching might need refinement.
                    new_config = Configuration(key=key, value=value_str)
                    db.session.add(new_config)
                    # Add to dict to avoid trying to create again if set twice in payload (unlikely)
                    existing_configs[key] = new_config 

            # JWT Settings
            if config_update.jwt_expiry_enabled is not None:
                update_or_create_config(CONFIG_JWT_EXPIRY_ENABLED, str(config_update.jwt_expiry_enabled))
            if config_update.jwt_expiry_minutes is not None:
                if config_update.jwt_expiry_minutes < 0:
                   raise ValueError("JWT expiry minutes cannot be negative.")
                update_or_create_config(CONFIG_JWT_EXPIRY_MINUTES, str(config_update.jwt_expiry_minutes))

            # Auto Release Settings
            if config_update.auto_release_enabled is not None:
                update_or_create_config(CONFIG_AUTO_RELEASE_ENABLED, str(config_update.auto_release_enabled))
            if config_update.auto_release_hours is not None:
                if config_update.auto_release_hours < 1:
                    raise ValueError("Auto-release hours must be at least 1.")
                update_or_create_config(CONFIG_AUTO_RELEASE_HOURS, str(int(config_update.auto_release_hours)))

            # Mail Enabled Setting
            if config_update.mail_enabled is not None:
                update_or_create_config(CONFIG_MAIL_ENABLED, str(config_update.mail_enabled))

        # Nested transaction commits here if no error
        
        db.session.commit() # Commit the main transaction

        return jsonify({"message": "Configuration updated successfully"}), 200
    except ValueError as ve:
        db.session.rollback() # Rollback main transaction
        app.logger.warning(f"Configuration update validation error: {ve}")
        return jsonify({"msg": "Validation Error", "details": str(ve)}), 400
    except SQLAlchemyError as e:
        db.session.rollback() # Rollback main transaction
        app.logger.error(f"Database error updating configuration: {e}", exc_info=True)
        return jsonify({"message": "Database error occurred during update."}), 500
    except Exception as e:
        db.session.rollback() # Rollback main transaction
        app.logger.error(f"Unexpected error updating configuration: {e}", exc_info=True)
        return jsonify({"message": "An unexpected error occurred."}), 500


# ----------------------------
# Error Handlers
# ----------------------------
@app.errorhandler(400)
def bad_request(error):
    # Pydantic validation errors are already handled in routes,
    # this catches other potential bad requests.
    response = jsonify({"msg": "Bad Request", "details": str(error)})
    response.status_code = 400
    return response

@app.errorhandler(401)
def unauthorized(error):
    # Specific handling for JWT errors might be needed via @jwt.unauthorized_loader etc.
    # This is a general handler.
    response = jsonify({"msg": "Unauthorized", "details": str(error)})
    response.status_code = 401
    return response

@app.errorhandler(403)
def forbidden(error):
    response = jsonify({"msg": "Forbidden", "details": str(error)})
    response.status_code = 403
    return response

@app.errorhandler(404)
def not_found(error):
    response = jsonify({"msg": "Not Found", "details": str(error)})
    response.status_code = 404
    return response

@app.errorhandler(409)
def conflict(error):
    # Specific conflict messages are handled in routes (e.g., lock already exists)
    # This is a general handler.
    response = jsonify({"msg": "Conflict", "details": str(error)})
    response.status_code = 409
    return response

@app.errorhandler(500)
def internal_server_error(error):
    # Log the error details server-side
    app.logger.error(f"Internal Server Error: {error}", exc_info=True)
    response = jsonify({"msg": "Internal Server Error"})
    response.status_code = 500
    return response

# ----------------------------
# Request Logging
# ----------------------------
@app.before_request
def log_request_info():
    user_identity = None
    try:
        # Attempt to get identity only if Authorization header might be present
        if request.headers.get('Authorization'):
            # verify=False prevents errors if token is invalid/expired, we just want identity if available
            user_identity = get_jwt_identity()
    except Exception:
        # Ignore exceptions if token is invalid or not present
        pass

    log_message = f"Request: {request.method} {request.path} from {request.remote_addr}"
    if user_identity:
        log_message += f" (User: {user_identity})"
    app.logger.info(log_message)

    # Optional detailed logging (consider performance/security implications)
    # app.logger.debug(f"Headers: {request.headers}")
    # if request.is_json:
    #     try:
    #         # Limit body size logged?
    #         app.logger.debug(f"Body: {request.get_json()}")
    #     except Exception:
    #         app.logger.warning("Could not parse request JSON for logging.")


# Add basic logging configuration (can be expanded in Step 6)
import logging
if not app.debug:
    # Example: Log to stderr in production
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.INFO)
    app.logger.addHandler(stream_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Asset Lock API startup')

# ----------------------------
# Custom CLI Commands
# ----------------------------

@app.cli.command("create-admin")
def create_admin_command():
    """Creates the initial admin user from environment variables if set and user doesn't exist."""
    initial_admin_user = os.environ.get("INITIAL_ADMIN_USERNAME")
    initial_admin_pass = os.environ.get("INITIAL_ADMIN_PASSWORD")
    initial_admin_email = os.environ.get("INITIAL_ADMIN_EMAIL")

    if initial_admin_user and initial_admin_pass and initial_admin_email:
        app.logger.info("Attempting initial admin user creation via CLI command...")
        try:
            # Ensure tables exist first
            # This might be redundant if migrations ran, but safe to include
            try:
                db.create_all()
            except Exception as e_create:
                 app.logger.error(f"Error ensuring database tables exist during admin creation: {e_create}")
                 # Decide if we should proceed or not

            # Check if user or email already exists
            existing_user = User.query.filter(
                (User.username == initial_admin_user) | (User.email == initial_admin_email)
            ).first()

            if not existing_user:
                created_admin = User.create( # Check return value
                    username=initial_admin_user,
                    password=initial_admin_pass,
                    email=initial_admin_email,
                    is_admin=True
                )
                if created_admin is None: # Handle potential creation failure
                    app.logger.error(f"Failed to create initial admin user '{initial_admin_user}' due to database error.")
                else:
                    app.logger.info(f"Initial admin user '{initial_admin_user}' created successfully.")
            else:
                app.logger.info(f"Initial admin user '{initial_admin_user}' or email '{initial_admin_email}' already exists. Skipping creation.")
        except Exception as e:
            # Catch potential errors during user creation (e.g., DB connection issues)
            db.session.rollback() # Rollback any partial transaction
            app.logger.error(f"Error during initial admin user creation command: {e}", exc_info=True)
    else:
        app.logger.info("Initial admin user environment variables not fully set. Skipping creation via CLI command.")

# --- New CLI command for testing email ---
@app.cli.command("test-email")
def test_email_command():
    """Sends a test email to the first admin user found in the database."""
    with app.app_context(): # Ensure we are in app context for DB access etc.
        # Check MAIL_ENABLED inside the context
        if not current_app.config.get('MAIL_ENABLED', False):
            print("Email sending is disabled (MAIL_ENABLED=False in config). Skipping test.")
            return
            
        # Find the first user marked as admin
        admin_user = User.query.filter_by(is_admin=True).first()
        if not admin_user:
            print("Error: No admin user found in the database.")
            return
        if not admin_user.email:
            print(f"Error: Admin user '{admin_user.username}' (ID {admin_user.id}) does not have an email address configured.")
            return

        print(f"Attempting to send test email to admin '{admin_user.username}' at {admin_user.email}...")
        try:
            # Use the existing send_email utility
            send_email(
                subject="Asset Lock Manager - Email System Test Successful",
                recipients=[admin_user.email],
                text_body=f"Hello {admin_user.username},\n\nThis email confirms that the email system for the Asset Lock Manager is configured correctly and operational.\n\nTest initiated via 'flask test-email' command.",
                html_body=f"<p>Hello {admin_user.username},</p>" \
                          f"<p>This email confirms that the email system for the Asset Lock Manager is configured correctly and operational.</p>" \
                          f"<p><i>Test initiated via <code>flask test-email</code> command.</i></p>"
            )
            # Note: send_email is async, so success here means the task was queued.
            # We rely on logs from send_async_email for actual send status.
            print("Test email task queued successfully. Check server logs for send status.")
        except Exception as e:
            print(f"Error queuing test email: {e}")
            current_app.logger.error(f"Error encountered in test-email command: {e}", exc_info=True)

# --- End new CLI command ---

# --- New CLI command for setting configuration ---
@app.cli.command("set-config")
@click.argument("key")
@click.argument("value")
def set_config_command(key, value):
    """Sets or updates a configuration key in the database."""
    with app.app_context():
        try:
            Configuration.set(key, value)
            print(f"Configuration key '{key}' set to '{value}'.")
        except Exception as e:
            print(f"Error setting configuration key '{key}': {e}")
            # Optionally exit with non-zero status
            # import sys
            # sys.exit(1)
# --- End new CLI command ---

# Run the application
if __name__ == "__main__":
    app.run(debug=app.debug, host="0.0.0.0", port=5001)
