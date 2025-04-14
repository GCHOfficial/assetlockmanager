# Asset Lock Manager - Git Pre-Commit Hook

This directory contains the `pre-commit` script that integrates with the Asset Lock Manager system.

## Purpose

This hook automatically checks files being committed against the Asset Lock Manager server. If any staged file is found to be locked by *another* user, the commit is aborted to prevent potential merge conflicts or overwriting locked work.

## Prerequisites

Before installing this hook in your target repository, ensure:

1.  **Python 3.x is installed** on the system where you will be committing.
2.  **The `requests` library is installed** for Python (`pip install requests`).
3.  **The Asset Lock Manager Client (`client/asset_lock_manager.py`) is accessible:**
    *   The easiest way is often to place the `client/` directory (or a symlink to it) somewhere accessible and ensure the hook script knows where to find `asset_lock_manager.py` (see Installation Option 2 below).
    *   Alternatively, ensure `client/asset_lock_manager.py` is in the system's PATH.
4.  **The Asset Lock Manager Client is configured:** The client script needs to know the URL of your running Asset Lock Manager backend API. Configure this *within your target repository clone* using one of the methods described in `client/README.md` (e.g., `python /path/to/client/asset_lock_manager.py configure --backend http://localhost:8080/api`).

## Installation

Choose **one** of the following methods to install the hook into the Git repository where you want to enforce lock checking:

**Option 1: Simple Copy (Requires Client in PATH or Edit Hook)**

1.  Navigate to your target repository:
    ```bash
    cd /path/to/your/project/repository
    ```
2.  Copy the `pre-commit` script from this `hooks` directory into your repository's `.git/hooks/` directory:
    ```bash
    # Adjust path to this hooks directory as needed
    cp /path/to/asset-lock-manager/hooks/pre-commit .git/hooks/pre-commit
    ```
3.  Make the hook executable:
    ```bash
    chmod +x .git/hooks/pre-commit
    ```
4.  **Important:** If the `asset_lock_manager.py` client script is *not* in your system's PATH, you **must edit** the `.git/hooks/pre-commit` script and change the `CLIENT_SCRIPT_CMD` variable near the top to the full path of the `asset_lock_manager.py` script (e.g., `CLIENT_SCRIPT_CMD="python /path/to/asset-lock-manager/client/asset_lock_manager.py"`).

**Option 2: Symlink (Recommended if client location is stable)**

1.  Navigate to your target repository:
    ```bash
    cd /path/to/your/project/repository
    ```
2.  Create a symbolic link from the `pre-commit` script in this `hooks` directory to your repository's `.git/hooks/` directory:
    ```bash
    # Adjust path to this hooks directory as needed
    ln -s /path/to/asset-lock-manager/hooks/pre-commit .git/hooks/pre-commit 
    ```
    *(Note: Ensure the source path in the `ln -s` command is correct relative to where you run it, or use an absolute path)*.
3.  **Important:** Ensure the `CLIENT_SCRIPT_CMD` variable near the top of the *original* `hooks/pre-commit` script points correctly to your `client/asset_lock_manager.py` (e.g., using a relative path from the hook's location if appropriate, or an absolute path).

## How it Works

When you run `git commit`, Git executes the `.git/hooks/pre-commit` script.

1.  The script finds all staged files.
2.  It iterates through the staged files and calls `python /path/to/client/asset_lock_manager.py --repo . check -- <file>` for each one.
3.  The client script communicates with the API server to check the lock status.
4.  If a file is locked by *another* user, the client script exits with a non-zero status code.
5.  The hook script detects the non-zero exit code, prints an error message listing the locked file(s), and exits non-zero, which aborts the commit.

Files locked by the *current* user (based on the logged-in user for the client script in that repository) do **not** block the commit. 