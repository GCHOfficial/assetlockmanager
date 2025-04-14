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

The server is primarily configured via environment variables loaded from the `.env` file in the **repository root directory**. Key variables include:

*   `DATABASE_URI` (or `POSTGRES_*` vars)
*   `JWT_SECRET_KEY`
*   `RATELIMIT_STORAGE_URI`
*   `MAIL_*` variables (for email notifications)
*   `FRONTEND_BASE_URL` (for generating confirmation links)
*   `INITIAL_ADMIN_*` (optional, for first startup)

See the root `.env.example` file for a full list and descriptions.

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
    docker compose up -d --build api postgres redis
    ```

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