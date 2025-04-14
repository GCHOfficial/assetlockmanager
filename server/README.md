# 🖥️ Asset Lock Manager - Server

This directory contains the Flask-based API server for the Asset Lock Manager system.

--- 

## 🎯 Purpose

The server acts as the central authority for managing file/asset locks, especially useful for preventing conflicts with binary files like those in **Unreal Engine projects**. It provides a RESTful API for clients (web frontend, CLI, UE plugin) to:

*   Authenticate users (JWT).
*   Create, view, and release locks.
*   Manage users (admin CRUD) and user self-service (password/email changes).
*   Manage system configuration (auto-release, JWT expiry, SMTP settings).
*   Handle email/password change confirmations.
*   Send email notifications (confirmations, lock alerts).

--- 

## 🛠️ Tech Stack & Key Libraries

*   **Framework:** Flask
*   **Database:** PostgreSQL (via Flask-SQLAlchemy)
*   **Database Migrations:** Flask-Migrate
*   **Authentication:** JWT (via Flask-JWT-Extended)
*   **Caching/Rate Limiting:** Redis (via Flask-Limiter)
*   **Validation:** Pydantic (for request/response schemas)
*   **Email:** Flask-Mail
*   **Scheduled Tasks:** APScheduler + SQLAlchemyJobStore (for auto-releasing old locks)
*   **WSGI Server:** Gunicorn (used in Dockerfile)

--- 

## ⚙️ Configuration

The API server relies heavily on environment variables for configuration, especially when run via Docker Compose. These are typically loaded from a `.env` file in the project root.

Key environment variables:

*   `DATABASE_URI`: Connection string (automatically constructed in `docker-compose.yml` from `POSTGRES_*` vars).
*   `JWT_SECRET_KEY`: **Required** for signing JWTs.
*   `MAIL_SERVER`, `MAIL_PORT`, `MAIL_USE_TLS`, `MAIL_USE_SSL`, `MAIL_USERNAME`, `MAIL_PASSWORD`, `MAIL_DEFAULT_SENDER`: **Required** if `MAIL_ENABLED` is true. These configure the SMTP server connection.
*   `MAIL_ENABLED`: Master switch (`true`/`false`) to enable/disable all email functionality.
*   `AUTO_RELEASE_ENABLED`: Default (`true`/`false`) for enabling automatic lock release.
*   `AUTO_RELEASE_HOURS`: Default hours (e.g., `72`) after which inactive locks are released.
*   `JWT_ACCESS_TOKEN_EXPIRES_MINUTES`: Default token expiry time in minutes (e.g., `60`). Use `0` or omit for no expiry.
*   `INITIAL_ADMIN_USER`, `INITIAL_ADMIN_EMAIL`, `INITIAL_ADMIN_PASSWORD`: Optional. If set, an admin user with these credentials will be created on first startup if they don't already exist.
*   `FRONTEND_BASE_URL`: **Required** for generating correct email confirmation links. Should be the public URL of your frontend.
*   `RATELIMIT_STORAGE_URI`: **Required** Redis connection string (e.g., `redis://redis:6379/0`) for rate limiting.

### Database Overrides

While environment variables provide defaults and essential connection details, certain settings can be configured via the Admin UI. These are stored in the `configuration` database table and override the corresponding environment variable defaults at runtime:

*   `jwt.expiry.enabled` (boolean)
*   `jwt.expiry.minutes` (integer)
*   `auto_release.enabled` (boolean)
*   `auto_release.hours` (integer)
*   `mail.enabled` (boolean) - Note: This overrides the default for *generating* confirmation emails. The master `MAIL_ENABLED` env var still controls whether the mail system attempts to *send* anything.

### Startup Email Test

If the `MAIL_ENABLED` environment variable is set to `true`, the `entrypoint.sh` script will automatically trigger the `flask test-email` command on startup. This sends a test email to the first admin user found and records the result (`SUCCESS`, `FAILED`, or `SKIPPED`) in the database under the key `system.startup.mail_test_status`.

## API Endpoints

Key endpoints include:
*   `/api/login` (POST): Authenticate user, returns JWT.
*   `/api/currentuser` (GET): Get details of the currently authenticated user.
*   `/api/locks` (GET): List all active locks.
*   `/api/locks` (POST): Acquire a new lock (requires `asset_path`, `branch`, optional `comment`).
*   `/api/locks/<path:asset_path>` (GET): Get details of a specific lock.
*   `/api/locks/<path:asset_path>` (DELETE): Release a specific lock (user must be owner).
*   `/api/locks/path/<path:asset_path>/notify` (POST): Send a notification email to the lock holder (optional `message` in JSON body).
*   `/api/locks/auto-release` (POST): Release all locks for a given `branch` (requires `branch` in JSON body).
*   `/api/config/status` (GET): Get public configuration status (currently `mail_enabled`). Requires authentication.
*   `/api/users/me/password` (PUT): User changes their own password.
*   `/api/users/me/email` (PUT): User requests to change their own email.
*   `/api/confirm-email/<token>` (GET): Endpoint visited from email link to confirm email change.
*   `/api/confirm-password/<token>` (GET): Endpoint visited from email link to confirm password change.
*   `/api/admin/users` (GET, POST): Admin manages users.
*   `/api/admin/users/<id>` (DELETE): Admin deletes a user.
*   `/api/admin/users/<id>/password` (PUT): Admin changes a user's password.
*   `/api/admin/users/<id>/email` (PUT): Admin changes a user's email.
*   `/api/admin/users/<id>/status` (PUT): Admin changes a user's admin status.
*   `/api/admin/config` (GET, PUT): Admin manages system configuration overrides.

See OpenAPI documentation (TODO: Add link/generation instructions) or inspect the route definitions in `app.py` and associated Pydantic schemas (`LoginSchema`, `CreateLockSchema`, `NotifyMessageSchema`, `CreateUserSchema`, etc.) for detailed request/response specifications.

## Background Jobs

*   **`delete_old_locks`**: Runs periodically (default: hourly) via APScheduler. Checks the effective `auto_release.enabled` and `auto_release.hours` configuration (DB->Env fallback) and deletes locks older than the threshold.

## CLI Commands

Additional Flask CLI commands are available:

*   `flask db migrate`: Generate database migration scripts.
*   `flask db upgrade`: Apply database migrations.
*   `flask create-admin`: Creates the initial admin user (used by `entrypoint.sh`).
*   `flask test-email`: Sends a test email to the first admin user.
*   `flask set-config <key> <value>`: Sets a key-value pair in the `configuration` table.

--- 

## ▶️ Running the Server (Docker Compose)

This server is designed to be run as part of the main Docker Compose setup in the **repository root directory**.

1.  **Prerequisites:** Docker and Docker Compose installed.
2.  **Configure Root `.env**:** Ensure the `.env` file in the root directory is configured (see root `README.md`).
3.  **Run from Root:**
    ```bash
    # Build and run all services (recommended)
    docker compose build
    docker compose up -d 

    # --- OR --- 

    # Build and run only the api and its direct dependencies
    docker compose up -d --build alm-api alm-postgres alm-redis
    ```

    > **Note:** To deploy using pre-built Docker images (e.g., from GitHub Container Registry), see the **Deployment Options** section in the main [root README.md](../README.md).

The API server listens on port 5000 *inside* the Docker container. It is typically accessed via the Nginx proxy running in the `frontend` container (e.g., `http://localhost:8080/api/...`). Direct access from the host is usually not required or configured.

--- 

## 📦 Database Migrations

Database schema changes are managed using Flask-Migrate. Migration scripts are stored in `server/migrations/`.

*   **Automatic Application:** The `entrypoint.sh` script used in the Docker container **automatically applies** any pending migrations on startup (`flask db upgrade`). You usually don't need to run migrations manually when using Docker Compose.
*   **Creating New Migrations:** If you modify the database models in `app.py` (e.g., adding a new column to the `User` table), you need to generate a new migration script. This typically requires a local Python environment matching the server:
    1.  Set up a local Python virtual environment.
    2.  Install dependencies: `pip install -r requirements.txt`
    3.  Ensure necessary environment variables (like `DATABASE_URI`) are set locally for Flask-Migrate to connect to a database (could be a temporary local one or the running Docker DB).
    4.  Run the migrate command from the `server/` directory:
        ```bash
        # Example command - requires local setup
        flask db migrate -m "Your short description of schema changes"
        ```
    5.  This generates a new script in `server/migrations/versions/`.
    6.  **Commit this new migration script** to your Git repository.
    7.  The next time the Docker container starts, the `entrypoint.sh` script will automatically apply this new migration.

--- 

## ⏰ Scheduled Tasks (Auto Lock Release)

APScheduler runs automatically in the background within the API container. It uses the `SQLAlchemyJobStore`, persisting job information in the main PostgreSQL database to ensure reliability across restarts. Its primary task is to periodically check for and delete locks older than the configured duration (set via the Admin Configuration UI).

--- 

## 📚 API Documentation

Currently, there is no automatically generated API documentation (e.g., Swagger/OpenAPI). API endpoints and their expected request/response formats must be inferred from:

*   The `@app.route(...)` definitions in `app.py`.
*   The Pydantic schemas defined in `app.py`.
*   How the clients (frontend, CLI) interact with the API. 