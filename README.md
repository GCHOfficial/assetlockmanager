# Asset Lock Manager (Open Source Core)

**Prevents simultaneous edits and merge conflicts for binary assets in Git.**

This repository contains the open-source core components of the Asset Lock Manager system:

*   **Server:** A Flask-based API server (in `server/`) that manages lock information using a PostgreSQL database and Redis cache.
*   **Client:** A Python CLI tool (in `client/`) for users to interact with the server (login, lock, unlock, check, list).
*   **Hook:** A Git pre-commit hook (in `hooks/`) that uses the client to prevent commits of assets locked by others.
*   **Frontend:** A React/TypeScript web interface (in `frontend/`) providing user login, dashboard (lock lists), user settings (password/email change), admin panels (user management, configuration), and user-to-user lock notifications. Served via Nginx which also acts as a proxy to the backend API.

**Note:** The Unreal Engine 5 editor plugin (`AssetLockManager/` directory in the original workspace) provides in-engine integration but is **not** part of this open-source release under this license. It may be offered separately.

## Features

*   Centralized lock management via REST API.
*   JWT-based authentication.
*   Secure email/password change confirmation via email tokens.
*   Email notifications (lock alerts, user-to-user "poke" notifications).
*   User management with admin roles and self-service.
*   Web UI (React/TypeScript) for dashboard, settings, and admin tasks.
*   Python CLI for easy interaction and scripting.
*   Git pre-commit hook integration.
*   Docker Compose setup for easy deployment (Frontend + Backend API + DB + Cache).

## Architecture

Client-Server architecture. The Flask API (`server/`) serves as the central server managing state in a PostgreSQL database. The React Frontend (`frontend/`) provides the primary user interface and is served by an Nginx container. Nginx also acts as a reverse proxy, forwarding API requests (e.g., `/api/*`) from the frontend to the Flask API container. Other clients include the Python CLI (`client/`) and the Git hook (`hooks/`). Communication is via HTTP requests.

## Quick Start (Docker Compose)

1.  **Prerequisites:** Docker and Docker Compose.
2.  **Clone:** Clone this repository.
3.  **Configure:**
    *   Copy `.env.example` to `.env`.
    *   Edit `.env` and set a strong `JWT_SECRET_KEY`, secure `POSTGRES_PASSWORD`, and your SMTP server details (`MAIL_*` variables) if you want email notifications enabled initially.
    *   Set `FRONTEND_BASE_URL` in `.env` to the URL you will access the frontend from (e.g., `http://localhost` or `http://localhost:8080` if you map a different port in `docker-compose.yml`). This is used for generating email confirmation links.
    *   Optionally configure `INITIAL_ADMIN_USERNAME`, `INITIAL_ADMIN_PASSWORD`, `INITIAL_ADMIN_EMAIL` to create an admin user on first startup.
4.  **Build & Run:**
    ```bash
    docker compose build
    docker compose up -d
    ```
    The frontend should now be accessible via the `FRONTEND_BASE_URL` (e.g., `http://localhost` or `http://localhost:8080`). The backend API is proxied via `/api` and is **not** directly accessible on port 5000 from the host.
5.  **Use Frontend:** Access the application via your `FRONTEND_BASE_URL` in a web browser.
6.  **Use Client:** See `client/README.md` for instructions on using the Python CLI (requires configuring its backend URL, potentially via `python client/asset_lock_manager.py config set backend_url <FRONTEND_BASE_URL>/api`).
7.  **Install Hook:** See `hooks/README.md` for instructions on setting up the Git hook in your target repository.

## Configuration

See `.env.example` for details on configuring the server environment variables.

## Contributing

Please see `CONTRIBUTING.md`.

## Code of Conduct

Please see `CODE_OF_CONDUCT.md`.

## License

This project is licensed under the MIT License - see the `LICENSE` file for details. 