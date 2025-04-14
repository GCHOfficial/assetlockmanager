# 🌐 Asset Lock Manager - Frontend

This directory contains the React/TypeScript web interface for the Asset Lock Manager.

--- 

## ✨ Features

*   **🔐 Authentication:** User Login/Logout.
*   **📊 Dashboard:** View locks held by you and others.
*   **🔓 Lock Management:** Release your own locks, notify ("poke") holders of other locks.
*   **⚙️ User Settings:** Change password and email address (with email confirmation).
*   **🛠️ Admin Panel:**
    *   User Management: List, search, create, edit, delete users.
    *   Configuration Management: View/update system settings (JWT, Auto Release, SMTP).
*   **🎨 Styling:** Uses Shadcn UI components and Tailwind CSS.
*   **🔌 Backend Communication:** Talks to the backend API (proxied via Nginx in Docker setup).

--- 

## 💻 Tech Stack

*   React
*   TypeScript
*   Vite (Build Tool)
*   react-router-dom (Routing)
*   Axios (HTTP Client)
*   Shadcn UI / Radix UI (Component Library)
*   Tailwind CSS (Styling)
*   Lucide Icons

--- 

## ▶️ Running the Frontend

This frontend is designed to be run as part of the main Docker Compose setup in the **root directory**.

1.  **Prerequisites:** Docker & Docker Compose installed.
2.  **Configure Root `.env**:** Ensure the `.env` file in the root directory is configured (see root `README.md`).
3.  **Run from Root:**
    ```bash
    # From the root directory of the repository
    docker compose build
    docker compose up -d
    ```
4.  **Access:** Open `http://localhost:8080` in your browser.

--- 

## 🔧 Standalone Development (Optional)

For faster frontend iteration *without* rebuilding the Docker image constantly:

1.  **Ensure Backend Running:** Start the necessary backend services via Docker Compose from the **root** directory:
    ```bash
    docker compose up -d api postgres redis
    ```
2.  **Navigate:** `cd frontend`
3.  **Install Dependencies:**
    *   Requires `pnpm` (`npm install -g pnpm` if you don't have it).
    *   `pnpm install`
4.  **Configure API URL:** Since Nginx isn't used here, tell the dev server where the API is. Choose one:
    *   **Environment Variable:**
        *   Linux/macOS: `export VITE_API_BASE_URL=http://localhost:5000`
        *   Windows (Command Prompt): `set VITE_API_BASE_URL=http://localhost:5000`
        *   Windows (PowerShell): `$env:VITE_API_BASE_URL="http://localhost:5000"`
    *   **.env file:** Create a `.env` file *inside this `frontend` directory* with the line:
        `VITE_API_BASE_URL=http://localhost:5000`
5.  **Modify `src/services/api.ts` (Temporary):**
    *   Comment out the line: `const API_BASE_URL = '/api';`
    *   Uncomment the line: `const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000';`
6.  **Run Dev Server:**
    ```bash
    pnpm dev
    ```
7.  **Access:** Open the local URL provided by the `pnpm dev` output (usually `http://localhost:5173` or similar).
8.  **IMPORTANT:** Remember to **revert the changes** in `src/services/api.ts` before committing or building the production Docker image.

## Configuration

The frontend itself requires minimal configuration. It connects to the backend API via a relative path (`/api`) which is proxied by the Nginx server running in the same container (see `nginx.conf` and `Dockerfile`).

The crucial backend configuration affecting the frontend (like the `FRONTEND_BASE_URL` needed for email links) is managed via the **server's** environment variables (`.env` file in the project root).

### Admin Panel

The Admin Configuration page allows administrators to view and modify certain backend settings:

*   **JWT Expiry:** Enable/disable token expiry and set the duration (minutes).
*   **Auto Lock Release:** Enable/disable the automatic release of old locks and set the age threshold (hours).
*   **Mail Enabled:** Enable/disable the generation of confirmation emails for password/email changes.
*   **Mail Status:** View the master email system status (from `MAIL_ENABLED` env var) and the result of the last startup email test.

Settings modified here are saved to the backend database and override the default values set by the backend's environment variables.
