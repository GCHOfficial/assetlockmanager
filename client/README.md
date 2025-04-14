# ⌨️ Asset Lock Manager - Client CLI

This directory contains the Python command-line interface (CLI) client (`asset_lock_manager.py`) for interacting with the Asset Lock Manager API.

**❗ Recommended Usage:** Copy *this script* (`asset_lock_manager.py`) to the **root directory** of your target project repository (e.g., your Unreal Engine project). This makes it easy for the Git Hook (see below) and all users to access it consistently.

This tool is essential for:
*   Scripting lock operations.
*   Integrating lock checks into other systems (like the provided Git Hook).
*   Users who prefer a command-line workflow, often common in game development (e.g., with Unreal Engine projects).

--- 

## ▶️ Usage

Assuming you have copied `asset_lock_manager.py` to your project root, run it from the **root of your project repository**:

```bash
python asset_lock_manager.py --help 
```

**❗ Important:** Before using commands like `acquire`, `release`, `list`, etc., you must configure the backend API URL (see below, run configuration from your project root).

--- 

## ⚙️ Configuration: Setting the Backend URL

The client needs to know where the Asset Lock Manager server API is running. Configure this **from the root of your target project repository** using one of the following methods (priority order):

1.  **`--backend <URL>` Command-line Argument (Highest Priority):**
    *   Overrides all other settings for a single command execution.
    ```bash
    # Example using the default Docker setup, run from project root
    python asset_lock_manager.py --backend http://localhost:8080/api list
    ```

2.  **`ASSET_LOCK_BACKEND_URL` Environment Variable:**
    *   Set this variable in your shell for the current session or persistently.
    *   **Linux/macOS (.bashrc, .zshrc, etc.):**
        ```bash
        export ASSET_LOCK_BACKEND_URL="http://localhost:8080/api"
        ```
    *   **Windows (Command Prompt - Current Session):**
        ```cmd
        set ASSET_LOCK_BACKEND_URL=http://localhost:8080/api
        ```
    *   **Windows (PowerShell - Current Session):**
        ```powershell
        $env:ASSET_LOCK_BACKEND_URL="http://localhost:8080/api"
        ```
    *   *(To set environment variables persistently on Windows, use the System Properties > Environment Variables dialog.)*
    *   Once set, you can run commands directly (from project root):
        ```bash
        python asset_lock_manager.py list
        ```

3.  **Repository Configuration File (`.git/asset_lock_config.json`) (Lowest Priority):**
    *   Stores the backend URL specifically for the current Git repository clone.
    *   Recommended for shared projects where the server URL is consistent for all users of that repo.
    *   Use the `configure` command (*run from your project root*):
        ```bash
        # Example using the default Docker setup, run from project root
        python asset_lock_manager.py configure --backend http://localhost:8080/api
        ```
    *   This creates/updates `.git/asset_lock_config.json` (which is ignored by Git by default).

If no URL is found via these methods, the client will display an error message.

--- 

## 🚀 Common Commands

*(Run these from your **project repository root**)*

*   `login --username <your_username>` (prompts for password)
*   `logout`
*   `acquire <path/to/asset.uasset>`
*   `release <path/to/asset.uasset>`
*   `check <path/to/asset.uasset>` (Checks lock status)
*   `list` (Lists all current locks)
*   `notify <path/to/asset.uasset> [-m <message>]` (Sends an email notification to the lock holder, optionally including a message)
*   `auto-release [--branch <branch_name>]` (Releases locks on a specific branch, useful for CI/CD)

Use `python asset_lock_manager.py <command> --help` for details on specific commands.

--- 

## 🔑 Authentication Token

Upon successful login, the client saves a JWT authentication token to a file named `.git/asset_lock_token.json` *within the specific Git repository you are operating on*.

This makes your login session specific to that repository clone.

**⚠️ Security Note:** Although stored within `.git` (which is typically not committed), this file contains your authentication token. Ensure your local filesystem permissions restrict access appropriately.

--- 

## ✅ Prerequisites

*   **Python:** Version 3.x
*   **Requests Library:** `pip install requests` (or `pip3 install requests`)
*   **Git:** Command-line tool (used for finding repo root and storing config/token).

--- 

## 🎣 Git Hook Integration

The pre-commit hook located in the main repository's `hooks/` directory utilizes this client script (`asset_lock_manager.py`) to check for locked assets before allowing a commit. See `hooks/README.md` for installation instructions. 