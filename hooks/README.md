# 🎣 Asset Lock Manager - Git Pre-Commit Hook

This directory contains the `pre-commit` script that integrates with the Asset Lock Manager system.

--- 

## 🎯 Purpose

This Git hook automatically checks files being committed against the Asset Lock Manager server. If any staged file is found to be locked by **another** user, the commit is **aborted** to prevent potential merge conflicts or overwriting locked work. This is particularly crucial for binary assets like those found in **Unreal Engine projects** (`.uasset`, `.umap`) where merging is difficult or impossible.

--- 

## ✅ Prerequisites

Before setting up this hook in your target repository (e.g., your Unreal project repo), ensure:

1.  **🐍 Python 3.x is installed** on the system where you will be committing.
2.  **📦 The `requests` library is installed** for Python:
    ```bash
    pip install requests 
    # or 
    pip3 install requests
    ```
3.  **⌨️ The Asset Lock Manager Client (`client/asset_lock_manager.py`) is placed at the ROOT** of your target repository.
    *   Copy the `client/asset_lock_manager.py` file from the main `asset-lock-manager` repository into the root directory of your target project repository.
4.  **⚙️ The Asset Lock Manager Client is configured:** The client script (now at your repo root) needs the URL of your running Asset Lock Manager backend API. Configure this *within your target repository clone* using one of the methods described in `client/README.md` (run from your repo root):
    ```bash
    # Example: Configure backend URL using the client script at the repo root
    python asset_lock_manager.py configure --backend http://localhost:8080/api
    ```

--- 

## 💾 Installation (Recommended)

This method places the hook script within your repository, making it easily shareable with the team.

1.  **Create Directory:** In the **root** of your target repository (e.g., your Unreal project repo), create a directory named `.githooks`:
    ```bash
    # Run from your target repository root
    mkdir .githooks
    ```
2.  **Copy Hook:** Copy the `pre-commit` script from *this* `hooks` directory into the new `.githooks` directory in your target repository:
    *   **Linux/macOS:**
        ```bash
        cp /path/to/asset-lock-manager/hooks/pre-commit .githooks/pre-commit
        ```
    *   **Windows (Command Prompt):**
        ```cmd
        copy "\path\to\asset-lock-manager\hooks\pre-commit" ".githooks\pre-commit"
        ```
    *   **Windows (PowerShell):**
        ```powershell
        Copy-Item "/path/to/asset-lock-manager/hooks/pre-commit" -Destination ".githooks/pre-commit"
        ```
        *(Adjust source paths as needed)*
3.  **Make Executable (Linux/macOS):**
    ```bash
    chmod +x .githooks/pre-commit
    ```
    *(Windows/Git for Windows usually handles this, but apply if needed)*.
4.  **Configure Git:** Tell Git to use this new hooks directory. **Each user needs to run this once per clone** of the target repository:
    ```bash
    # Run from your target repository root
    git config core.hooksPath .githooks
    ```
5.  **Verify Hook Script:** Ensure the `CLIENT_SCRIPT_CMD` variable near the top of the `.githooks/pre-commit` script is set correctly. It should now default to assuming `asset_lock_manager.py` is at the repository root (e.g., `CLIENT_SCRIPT_CMD="python ./asset_lock_manager.py"`). See step 2 in the next section.

--- 

## 🤔 How it Works

When you run `git commit` in your target repository:

1.  Git executes the `.githooks/pre-commit` script (because of `git config core.hooksPath`).
2.  The script finds all **staged** files (`git diff --cached --name-only`).
3.  It iterates through these files and calls `python ./asset_lock_manager.py check -- <file>` (assuming the client is at the root).
4.  The client script contacts the API server to get the lock status.
5.  If a file is locked by **another user**, the client script exits with an error code.
6.  The hook script catches this error, prints a message listing the conflicting locked file(s), and **aborts the commit** (by exiting with a non-zero status).

✅ Files locked by **you** (the user logged in via the client in that repo) do **not** block the commit. 