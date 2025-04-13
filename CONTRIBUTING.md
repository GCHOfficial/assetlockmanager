# Contributing to Asset Lock Manager

We welcome contributions to the Asset Lock Manager core system! Please follow these guidelines.

## How to Contribute

*   **Reporting Bugs:** Use the GitHub Issues tracker. Provide detailed steps to reproduce, expected behavior, and actual behavior.
*   **Suggesting Enhancements:** Use the GitHub Issues tracker. Clearly describe the enhancement and the motivation for it.
*   **Pull Requests:**
    1.  Fork the repository.
    2.  Create a new branch for your feature or bug fix (`git checkout -b feature/your-feature-name` or `bugfix/issue-number`).
    3.  Make your changes.
    4.  Ensure your code adheres to the project's style (details TBD - e.g., use a linter like Flake8 for Python).
    5.  Add tests for your changes if applicable.
    6.  Commit your changes with clear, descriptive messages.
    7.  Push your branch to your fork (`git push origin feature/your-feature-name`).
    8.  Open a Pull Request against the `main` branch of the original repository.
    9.  Clearly describe the changes in the Pull Request description.

## Development Setup

The primary development workflow uses Docker Compose.

1.  **Prerequisites:** Git, Docker, Docker Compose, Node.js >= 18, pnpm.
2.  **Clone:** `git clone <repository-url>`
3.  **Configure:** Copy `.env.example` to `.env` and customize secrets/settings.
4.  **Build & Run:** `docker compose build && docker compose up -d`
5.  **Access:** Frontend will be available at `http://localhost` (or the port mapped in `docker-compose.yml`).

For specific component development:

*   **Backend (Python):** Code in `server/`. Uses Flask, SQLAlchemy. See `server/requirements.txt`.
*   **Client (Python):** Code in `client/`. See `client/requirements.txt`.
*   **Frontend (React/TS):** Code in `frontend/`. Uses Vite, React, TypeScript, TailwindCSS, shadcn/ui. Run `pnpm install` in `frontend/` for type checking/linting setup.

## Code Style

While formal linting/formatting rules are not yet strictly enforced:

*   **Python:** Please follow general PEP 8 guidelines.
*   **TypeScript/React:** Follow standard React/TypeScript best practices. Consistency with existing code is preferred.

(Future work may involve adding automated linting and formatting checks.)

## Code of Conduct

Please note that this project is released with a Contributor Code of Conduct (`CODE_OF_CONDUCT.md`). By participating in this project you agree to abide by its terms. 