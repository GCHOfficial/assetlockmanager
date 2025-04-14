# 🔒 Asset Lock Manager (Open Source Core)

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

See `.env.example` for detailed explanations of all environment variables.

--- 

## 🤝 Contributing

Please see `CONTRIBUTING.md`.

--- 

## 📜 Code of Conduct

Please see `CODE_OF_CONDUCT.md`.

--- 

## 📄 License

This project is licensed under the MIT License - see the `LICENSE` file for details. 