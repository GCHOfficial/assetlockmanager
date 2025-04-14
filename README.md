# 🔒 Asset Lock Manager (Open Source Core)

**GitHub Repository:** [https://github.com/GCHOfficial/assetlockmanager/](https://github.com/GCHOfficial/assetlockmanager/)

**Prevents simultaneous edits and merge conflicts for binary assets in Git, especially useful for Unreal Engine projects.**

This repository contains the open-source core components of the Asset Lock Manager system, designed to help teams working with large binary files (like `.uasset` and `.umap` files in Unreal Engine) avoid painful merge conflicts.

--- 

## ✨ Core Components

*   **🖥️ Server:** A Flask-based API server (in `server/`) that manages lock information using a PostgreSQL database and Redis cache.
*   **⌨️ Client:** A Python CLI tool (in `client/`) for users to interact with the server (login, lock, unlock, check, list).
*   **🎣 Hook:** A Git pre-commit hook (in `hooks/`) that uses the client to prevent commits of assets locked by others.
*   **🌐 Frontend:** A React/TypeScript web interface (in `frontend/`) providing user login, dashboard (lock lists), user settings (password/email change), admin panels (user management, configuration), and user-to-user lock notifications. Served via Nginx which also acts as a proxy to the backend API.

--- 

## ⭐ Features

*   Centralized lock management via REST API.
*   JWT-based authentication.
*   Secure email/password change confirmation via email tokens.
*   Email notifications (lock alerts, user-to-user "poke" notifications).
*   User management with admin roles and self-service.
*   Web UI (React/TypeScript) for dashboard, settings, and admin tasks.
*   Python CLI for easy interaction and scripting.
*   Git pre-commit hook integration to prevent committing locked files.
*   🐳 Docker Compose setup for easy deployment (Frontend + Backend API + DB + Cache).

--- 

## 🏗️ Architecture

Client-Server architecture. The Flask API (`server/`) serves as the central server managing state in a PostgreSQL database. The React Frontend (`frontend/`) provides the primary user interface and is served by an Nginx container. Nginx also acts as a reverse proxy, forwarding API requests (e.g., `/api/*`) from the frontend to the Flask API container. Other clients include the Python CLI (`client/`) and the Git hook (`hooks/`). Communication is via HTTP requests.

--- 

## 🚀 Quick Start (Docker Compose)

1.  **Prerequisites:** [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/).
2.  **Clone:**
    ```bash
    git clone <repository_url>
    cd asset-lock-manager 
    ```
3.  **Configure:**
    *   Copy `.env.example` to `.env`:
        *   Linux/macOS: `cp .env.example .env`
        *   Windows (Command Prompt): `copy .env.example .env`
        *   Windows (PowerShell): `Copy-Item .env.example .env`
    *   Edit `.env` with a text editor and set:
        *   A strong, unique `JWT_SECRET_KEY`.
        *   A secure `POSTGRES_PASSWORD`.
        *   Your SMTP server details (`MAIL_*` variables) if you want email features.
        *   `FRONTEND_BASE_URL` (defaults to `http://localhost:8080` which matches Docker Compose).
    *   *(Optional)* Configure `INITIAL_ADMIN_*` variables to create an admin user on first startup.
4.  **Build & Run:**
    ```bash
    # This command works on Linux, macOS, and Windows
    docker compose build
    docker compose up -d
    ```
    *(Wait a moment for the database and services to initialize).* 
5.  **Access Frontend:** Open your web browser to `http://localhost:8080`.
6.  **Use Client:** See `client/README.md` for instructions. You'll need to configure its backend URL:
    ```bash
    # Example (adjust python command if needed)
    python client/asset_lock_manager.py config set backend_url http://localhost:8080/api
    ```
7.  **Install Hook:** See `hooks/README.md` for instructions on setting up the Git hook in your target Unreal Engine (or other) project repository.

--- 

## ⚙️ Configuration Details

Configuration is primarily handled via environment variables loaded from a `.env` file in the project root when using Docker Compose.

Key settings include:

*   `DATABASE_URI`: Connection string for PostgreSQL.
*   `JWT_SECRET_KEY`: Secret key for signing JWTs.
*   `MAIL_*` variables: Settings for the email server (host, port, user, password, TLS/SSL, sender address).
*   `MAIL_ENABLED`: Master switch (`true`/`false`) to enable/disable all email functionality.
*   `AUTO_RELEASE_ENABLED`: Default (`true`/`false`) for enabling automatic lock release.
*   `AUTO_RELEASE_HOURS`: Default hours after which inactive locks are released.
*   `JWT_ACCESS_TOKEN_EXPIRES_MINUTES`: Default token expiry time in minutes (0 for no expiry).
*   `INITIAL_ADMIN_*`: Optional variables to create an initial admin user on first startup.
*   `FRONTEND_BASE_URL`: Base URL for the frontend (used for generating email confirmation links).
*   `RATELIMIT_STORAGE_URI`: Redis connection string for rate limiting.

**Admin UI Overrides:**
Certain configuration settings can be modified by administrators via the web UI (`Admin -> Configuration`). These settings are stored in the database and **override** the default values provided by the corresponding environment variables at runtime:
*   JWT Expiry Enable/Disable
*   JWT Expiry Minutes
*   Auto Lock Release Enable/Disable
*   Auto Lock Release Hours
*   Mail Enabled (Overrides `MAIL_ENABLED` default for generating confirmation emails, but the master `MAIL_ENABLED` env var still controls actual sending)

**Startup Email Test:**
If `MAIL_ENABLED` is `true` in the environment, the system attempts to send a test email to the first admin user on startup. The result (`SUCCESS`, `FAILED`, `SKIPPED`) is visible in the Admin Configuration UI.

See `.env.example` for a full list and descriptions.

--- 

## 🚀 Deployment Options

There are two main ways to run the Asset Lock Manager using Docker Compose:

1.  **Using Pre-built Images (Recommended for Deployment)**
    *   This method uses pre-built Docker images from GitHub Container Registry (GHCR), avoiding the need to build the images locally.
    *   The project includes a GitHub Actions workflow (`.github/workflows/docker-publish.yml`) that automatically builds and pushes images to GHCR (`ghcr.io/gchofficial/assetlockmanager/frontend` and `ghcr.io/gchofficial/assetlockmanager/api`) whenever changes are pushed to the `main` branch.
    *   **Instructions:**
        1.  **Configure `.env`:** Ensure your `.env` file is configured with database credentials, JWT secret, etc., as described in the Quick Start.
        2.  **Set Image Variables:** Before running `docker compose up`, you need to tell Docker Compose which images to use by setting environment variables. Use the image names provided above, and select a `:tag` (e.g., `:latest` or a specific commit SHA like `:sha-a1b2c3d`).

            *   **Option A: Export Variables (Linux/macOS/WSL)**
                ```bash
                export FRONTEND_IMAGE=ghcr.io/gchofficial/assetlockmanager/frontend:latest
                export API_IMAGE=ghcr.io/gchofficial/assetlockmanager/api:latest
                # Or use a specific commit tag:
                # export FRONTEND_IMAGE=ghcr.io/gchofficial/assetlockmanager/frontend:sha-a1b2c3d
                # export API_IMAGE=ghcr.io/gchofficial/assetlockmanager/api:sha-a1b2c3d
                
                docker compose -f docker-compose.yml up -d 
                ```
            *   **Option B: Set Variables (Windows Command Prompt)**
                ```cmd
                set FRONTEND_IMAGE=ghcr.io/gchofficial/assetlockmanager/frontend:latest
                set API_IMAGE=ghcr.io/gchofficial/assetlockmanager/api:latest
                docker compose -f docker-compose.yml up -d
                ```
            *   **Option C: Set Variables (Windows PowerShell)**
                ```powershell
                $env:FRONTEND_IMAGE="ghcr.io/gchofficial/assetlockmanager/frontend:latest"
                $env:API_IMAGE="ghcr.io/gchofficial/assetlockmanager/api:latest"
                docker compose -f docker-compose.yml up -d
                ```
            *   **Option D: Modify `.env` (Not Recommended for Secrets)**
                You *could* uncomment and set the `FRONTEND_IMAGE` and `API_IMAGE` variables directly in your `.env` file. This is simpler but less flexible.

        3.  **Using with Portainer:**
            *   Navigate to "Stacks" > "Add stack".
            *   Give your stack a name.
            *   Choose "Git Repository" as the build method.
            *   Enter the repository URL (`https://github.com/GCHOfficial/assetlockmanager/`), reference name (e.g., `refs/heads/main`), and compose path (`docker-compose.yml`).
            *   Scroll down to "Environment variables".
            *   Click "Add environment variable" twice.
            *   Set the `name` to `FRONTEND_IMAGE` and `value` to the full image path (e.g., `ghcr.io/gchofficial/assetlockmanager/frontend:latest`).
            *   Set the `name` to `API_IMAGE` and `value` to the full image path (e.g., `ghcr.io/gchofficial/assetlockmanager/api:latest`).
            *   Add any other necessary environment variables from your `.env` file here (like `POSTGRES_PASSWORD`, `JWT_SECRET_KEY`, etc.). **Important:** Do not commit your `.env` file to Git; manage secrets appropriately within Portainer or your deployment environment.
            *   Click "Deploy the stack". Portainer will pull the specified images and start the services.

        4.  **Using with Podman / `podman-compose`:**
            *   Ensure you have `podman` and `podman-compose` installed.
            *   Set the environment variables as shown in Option A, B, or C above.
            *   Run:
                ```bash
                podman-compose -f docker-compose.yml up -d
                ```
            *   *(Note: Podman networking and volume handling might differ slightly from Docker. Refer to Podman documentation if you encounter issues.)*

2.  **Local Build (Development / Alternative)**
    *   This method builds the Docker images for the `frontend` and `api` services locally using the Dockerfiles in their respective directories.
    *   Use this if you are developing locally or cannot access the pre-built images.
    *   **Instructions:** Follow the **Quick Start** guide above. Ensure the `FRONTEND_IMAGE` and `API_IMAGE` environment variables are **unset** or empty. Then simply run:
        ```bash
        # Ensure you have configured your .env file
        docker compose build
        docker compose up -d
        ```

--- 

## 🤝 Contributing

Please see `CONTRIBUTING.md`.

--- 

## 📜 Code of Conduct

Please see `CODE_OF_CONDUCT.md`.

--- 

## 📄 License

This project is licensed under the MIT License - see the `LICENSE` file for details. 