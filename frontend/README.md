# Asset Lock Manager - Frontend

This directory contains the React/TypeScript frontend application for the Asset Lock Manager.

## Features

*   User Login/Logout
*   Dashboard displaying locks held by the current user and others.
*   Ability to release locks held by the current user.
*   Ability to send a notification ("poke") to the holder of a lock.
*   User Settings page for changing password and email address (requires email confirmation).
*   Admin Panel:
    *   User Management: List, search, create, edit (email, password, admin status), delete users.
    *   Configuration Management: View and update system settings (JWT Expiry, Auto Lock Release, SMTP server details).
*   Uses Shadcn UI components and Tailwind CSS for styling.
*   Communicates with the backend API (proxied via Nginx).

## Tech Stack

*   React
*   TypeScript
*   Vite
*   react-router-dom
*   Axios
*   Shadcn UI / Radix UI / Tailwind CSS
*   Lucide Icons

## Running the Frontend

This frontend is designed to be run as part of the main Docker Compose setup in the root directory.

1.  Ensure Docker and Docker Compose are installed.
2.  Configure the root `.env` file (copy from `.env.example`) with your backend settings (`JWT_SECRET_KEY`, `POSTGRES_PASSWORD`, `MAIL_*` variables, `FRONTEND_BASE_URL`).
3.  From the **root directory** of the repository, run:
    ```bash
    docker compose build
    docker compose up -d
    ```
4.  Access the frontend in your browser at `http://localhost:8080` (or the host port mapped in `docker-compose.yml`).

### Standalone Development (Optional - Requires Backend Running Separately)

If you need to run the frontend development server directly (e.g., for faster hot-reloading during focused frontend work), you can:

1.  Ensure the backend API (including DB and Redis) is running (e.g., via `docker compose up -d api postgres redis` from the root).
2.  Navigate to this `frontend` directory.
3.  Install dependencies: `pnpm install` (requires pnpm: `npm install -g pnpm`).
4.  Set the API base URL environment variable (since the Nginx proxy won't be used):
    ```bash
    export VITE_API_BASE_URL=http://localhost:5000 
    # Or use a .env file in the frontend directory with VITE_API_BASE_URL=http://localhost:5000
    ```
5.  Run the development server:
    ```bash
    pnpm dev
    ```
    *(Note: This requires temporarily uncommenting the `VITE_API_BASE_URL` logic in `src/services/api.ts` and commenting out the `/api` relative path.)*
