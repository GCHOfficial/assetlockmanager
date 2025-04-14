# Asset Lock Manager Client

This directory contains the Python command-line interface (CLI) client (`asset_lock_manager.py`) for interacting with the Asset Lock Manager API.

## Usage

Run the client from your terminal:

```bash
python asset_lock_manager.py --help
```

**Important:** Before using commands like `acquire`, `release`, `list`, etc., you must configure the backend API URL.

## Configuration

The client determines the backend API URL using the following priority:

1.  **`--backend <URL>` Command-line Argument:** Overrides all other settings.
    ```bash
    # Example using the default Docker setup
    python asset_lock_manager.py --backend http://localhost:8080/api list
    ```
2.  **`ASSET_LOCK_BACKEND_URL` Environment Variable:** Set this variable in your shell.
    ```bash
    # Example using the default Docker setup
    export ASSET_LOCK_BACKEND_URL="http://localhost:8080/api"
    python asset_lock_manager.py list
    ```
3.  **Repository Configuration File (`.git/asset_lock_config.json`):** Set the URL specifically for this repository clone using the `configure` command:
    ```bash
    # Example using the default Docker setup
    python asset_lock_manager.py configure --backend http://localhost:8080/api
    ```
    This creates/updates `.git/asset_lock_config.json` with the URL. This file is ignored by Git.

If no URL is found via these methods, the client will display an error.

Common commands:

*   `login --username <your_username>` (prompts for password)
*   `logout`
*   `acquire <path/to/asset.uasset>`
*   `release <path/to/asset.uasset>`
*   `check <path/to/asset.uasset>`
*   `list`
*   `notify <path/to/asset.uasset>` (Send notification to lock holder)
*   `auto-release [--branch <branch_name>]`

Use the `--repo <path_to_repo>` argument if running the client from outside the repository root.

## Authentication Token

Upon successful login, the client saves a JWT authentication token *within the repository's* `.git` *directory* to:

`.git/asset_lock_token.json`

This makes the login specific to this repository clone.

**Security Note:** Although stored within `.git` (which is typically not committed), this file contains your authentication token for this specific project. Ensure your filesystem permissions restrict access appropriately.

## Prerequisites

*   Python 3.x
*   `requests` Python library (`pip install requests`)
*   `git` command-line tool

## Git Hook Integration

The pre-commit hook located in `hooks/pre-commit` utilizes this client script to check for locked assets before allowing a commit. 