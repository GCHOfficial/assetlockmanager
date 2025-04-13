#!/usr/bin/env python3
import os
import sys
import json
import argparse
import requests
import subprocess
import getpass
from pathlib import Path

TOKEN_FILENAME = "asset_lock_token.json"
CONFIG_FILENAME = "asset_lock_config.json"
ENV_VAR_BACKEND_URL = "ASSET_LOCK_BACKEND_URL"

def get_git_dir(repo_root_str):
    """Finds the .git directory path using git command."""
    try:
        repo_root = Path(repo_root_str).resolve()
        if not repo_root.is_dir():
            return None

        result = subprocess.run(
            ["git", "rev-parse", "--git-dir"],
            capture_output=True, text=True, check=True,
            cwd=str(repo_root),
            encoding='utf-8'
        )
        git_dir_rel = result.stdout.strip()
        git_dir_abs = (repo_root / git_dir_rel).resolve()
        return git_dir_abs
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    except Exception as e:
        return None

def get_config_path(repo_root_str):
    """Gets the full path to the config file inside the .git directory."""
    git_dir = get_git_dir(repo_root_str)
    if git_dir and git_dir.is_dir():
        return git_dir / CONFIG_FILENAME
    # Don't raise error here, config file is optional source
    return None

def load_config(repo_root):
    """Loads configuration from the config file."""
    config_path = get_config_path(repo_root)
    if not config_path or not config_path.exists():
        return {}
    try:
        with open(config_path, "r") as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        print(f"Warning: Could not read or parse config file at {config_path}: {e}", file=sys.stderr)
        return {}

def save_config(config_data, repo_root):
    """Saves configuration to the config file."""
    config_path = get_config_path(repo_root)
    if not config_path:
        print(f"Error: Could not determine config file path in .git directory for '{repo_root}'.", file=sys.stderr)
        return False # Indicate failure
    try:
        with open(config_path, "w") as f:
            json.dump(config_data, f, indent=4)
        # Set restricted permissions
        try:
            os.chmod(config_path, 0o600)
        except OSError:
            pass # Ignore permission errors
        return True # Indicate success
    except IOError as e:
        print(f"Error: Could not write config file to {config_path}: {e}", file=sys.stderr)
        return False # Indicate failure

def get_configured_backend_url(repo_root):
    """Gets backend URL from environment variable or config file."""
    # 1. Check Environment Variable
    env_url = os.environ.get(ENV_VAR_BACKEND_URL)
    if env_url:
        return env_url.rstrip("/")

    # 2. Check Config File
    config = load_config(repo_root)
    config_url = config.get("backend_url")
    if config_url:
        return config_url.rstrip("/")

    return None # Not found in env var or config

def get_token_path(repo_root_str):
    """Gets the full path to the token file inside the .git directory."""
    git_dir = get_git_dir(repo_root_str)
    if git_dir and git_dir.is_dir():
        return git_dir / TOKEN_FILENAME
    # Don't print error here, handled in main()
    return None

def save_token(token, repo_root):
    token_path = get_token_path(repo_root)
    if not token_path:
        sys.exit(3)
    data = {"access_token": token}
    try:
        with open(token_path, "w") as f:
            json.dump(data, f)
        try:
            os.chmod(token_path, 0o600)
        except OSError:
            pass
    except IOError as e:
        print(f"Error: Could not write token file to {token_path}: {e}", file=sys.stderr)
        sys.exit(1)

def load_token(repo_root):
    token_path = get_token_path(repo_root)
    if not token_path or not token_path.exists():
        return None
    try:
        with open(token_path, "r") as f:
            data = json.load(f)
            return data.get("access_token")
    except (IOError, json.JSONDecodeError) as e:
        print(f"Error: Could not read or parse token file at {token_path}: {e}", file=sys.stderr)
        return None

def remove_token(repo_root):
    token_path = get_token_path(repo_root)
    if token_path and token_path.exists():
        try:
            os.remove(token_path)
        except OSError as e:
             print(f"Error: Could not remove token file at {token_path}: {e}", file=sys.stderr)

def get_current_branch():
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, check=True,
        )
        branch = result.stdout.strip()
        return branch if branch != "HEAD" else "detached_HEAD"
    except subprocess.CalledProcessError:
        return "unknown_branch"

def normalize_path(path):
    """Normalize a path to be consistent across all interfaces"""
    path = path.strip('/')
    path = path.replace('\\', '/')
    while '//' in path:
        path = path.replace('//', '/')
    return path

def _normalize_asset_path(repo_root, asset_path):
    """Convert asset path to normalized form relative to repo root"""
    try:
        full_path = (Path(repo_root) / asset_path).resolve()
        relative_path = full_path.relative_to(Path(repo_root).resolve())
        return normalize_path(str(relative_path))
    except Exception as e:
        print(f"Error resolving asset path: {e}")
        return normalize_path(asset_path)

def login(backend_url, username, password, repo_root):
    url = f"{backend_url}/login"
    response = requests.post(url, json={"username": username, "password": password})
    if response.status_code == 200:
        token = response.json().get("access_token")
        if token:
            save_token(token, repo_root)
            print("Login successful, token saved.")
        else:
            print("Error: No token received.")
            sys.exit(1)
    else:
        print(f"Login failed: {response.json().get('msg', 'Unknown error')}")
        sys.exit(1)

def logout(repo_root):
    remove_token(repo_root)
    print("Token removed. User logged out.")

def acquire_lock(backend_url, asset_path, comment, repo_root="."):
    token = load_token(repo_root)
    if not token:
        print("Error: No token found. Please login first.")
        sys.exit(1)
    branch = get_current_branch()
    normalized_path = _normalize_asset_path(repo_root, asset_path)
    url = f"{backend_url}/locks"
    headers = {"Authorization": f"Bearer {token}"}
    payload = {"asset_path": normalized_path, "branch": branch}
    if comment:
        payload["comment"] = comment
    response = requests.post(url, json=payload, headers=headers)
    if response.status_code == 201:
        print("Lock acquired successfully.")
    else:
        print(f"Error acquiring lock: {response.json().get('msg', 'Unknown error')}")
        sys.exit(1)

def release_lock(backend_url, asset_path, repo_root="."):
    token = load_token(repo_root)
    if not token:
        print("Error: No token found. Please login first.")
        sys.exit(1)
    normalized_path = _normalize_asset_path(repo_root, asset_path)
    url = f"{backend_url}/locks/{normalized_path}"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.delete(url, headers=headers)
    if response.status_code == 200:
        print("Lock released successfully.")
    else:
        print(f"Error releasing lock: {response.json().get('msg', 'Unknown error')}")
        sys.exit(1)

def get_currentuser(backend_url, repo_root):
    token = load_token(repo_root)
    if not token:
        print("Error: No token found. Please login first.", file=sys.stderr)
        sys.exit(2)
    url = f"{backend_url}/currentuser"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        user_data = response.json()
        username = user_data.get("username")
        print(username)
        return 0
    except requests.exceptions.RequestException as e:
        print(f"Network error fetching current user: {e}", file=sys.stderr)
        sys.exit(2)
    except json.JSONDecodeError:
        print("Error: Invalid JSON response from user endpoint.", file=sys.stderr)
        sys.exit(2)

def check_lock(backend_url, asset_path, repo_root="."):
    token = load_token(repo_root)
    if not token:
        print("Error: No token found. Please login first.", file=sys.stderr)
        sys.exit(2)
    normalized_path = _normalize_asset_path(repo_root, asset_path)
    url = f"{backend_url}/locks/{normalized_path}"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            result = {
                "is_locked": True,
                "asset_path": data.get('asset_path'),
                "locked_by": data.get('locked_by'),
                "branch": data.get('branch'),
                "timestamp": data.get('timestamp'),
                "comment": data.get('comment')
            }
            print(json.dumps(result))
            return 0
        elif response.status_code == 404:
            result = {"is_locked": False}
            print(json.dumps(result))
            return 0
        else:
            print(f"Error checking lock: {response.json().get('msg', 'Unknown error')}", file=sys.stderr)
            sys.exit(2)
    except requests.exceptions.RequestException as e:
        print(f"Network error checking lock: {e}", file=sys.stderr)
        sys.exit(2)
    except json.JSONDecodeError:
        print("Error: Invalid JSON response from server.", file=sys.stderr)
        sys.exit(2)

def list_locks(backend_url, repo_root):
    token = load_token(repo_root)
    if not token:
        print("Error: No token found. Please login first.")
        sys.exit(1)
    url = f"{backend_url}/locks"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        locks = response.json()
        if not locks:
            print("No active locks.")
        else:
            for lock in locks:
                print(f"Asset: {lock.get('asset_path')}")
                print(f"  Locked by: {lock.get('locked_by')}")
                print(f"  Branch: {lock.get('branch')}")
                print(f"  Timestamp: {lock.get('timestamp')}")
                if lock.get('comment'):
                    print(f"  Comment: {lock.get('comment')}")
                print("-" * 20)
    else:
        print(f"Error listing locks: {response.json().get('msg', 'Unknown error')}")
        sys.exit(1)

def auto_release(backend_url, branch, repo_root):
    token = load_token(repo_root)
    if not token:
        print("Error: No token found. Please login first.")
        sys.exit(1)
    url = f"{backend_url}/locks/auto-release"
    headers = {"Authorization": f"Bearer {token}"}
    payload = {"branch": branch}
    response = requests.post(url, json=payload, headers=headers)
    if response.status_code == 200:
        print(response.json().get("msg"))
    else:
        print(f"Error auto-releasing locks: {response.json().get('msg', 'Unknown error')}")
        sys.exit(1)

def notify_lock_holder(backend_url, asset_path, repo_root="."):
    """Sends a notification request to the API for the holder of a specific lock."""
    token = load_token(repo_root)
    if not token:
        print("Error: No token found. Please login first.")
        sys.exit(1)
    
    normalized_path = _normalize_asset_path(repo_root, asset_path)
    # Ensure the path doesn't start with a slash for URL construction
    url_path = normalized_path.lstrip('/')
    url = f"{backend_url}/locks/path/{url_path}/notify"
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        response = requests.post(url, headers=headers)
        response.raise_for_status() # Raises HTTPError for 4xx/5xx
        
        # Check for specific success/failure messages from the API
        response_data = response.json()
        print(response_data.get("msg", "Notification request sent successfully."))
        sys.exit(0) # Success
        
    except requests.exceptions.HTTPError as errh:
        try:
            error_data = errh.response.json()
            print(f"Error sending notification: {error_data.get('msg', errh)}", file=sys.stderr)
        except json.JSONDecodeError:
            print(f"Error sending notification: {errh}", file=sys.stderr)
        sys.exit(1) # Failure
    except requests.exceptions.RequestException as err:
        print(f"Network error sending notification: {err}", file=sys.stderr)
        sys.exit(1) # Failure

def main():
    parser = argparse.ArgumentParser(description="Asset Lock Manager CLI")
    parser.add_argument("--repo-root", default=".", help="Path to the repository root.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Login
    login_parser = subparsers.add_parser("login", help="Login to the asset lock server.")
    login_parser.add_argument("-u", "--username", required=False, help="Username.")
    login_parser.add_argument("-p", "--password", required=False, help="Password (will be prompted if not provided).")
    login_parser.add_argument("--url", help="Backend server URL (overrides config/env var).")

    # Logout
    logout_parser = subparsers.add_parser("logout", help="Logout from the asset lock server.")

    # Config
    config_parser = subparsers.add_parser("config", help="Configure CLI settings.")
    config_subparsers = config_parser.add_subparsers(dest="config_command", required=True)
    config_set_parser = config_subparsers.add_parser("set", help="Set a configuration value.")
    config_set_parser.add_argument("key", choices=["backend_url"], help="Configuration key to set.")
    config_set_parser.add_argument("value", help="Value to set for the key.")
    config_get_parser = config_subparsers.add_parser("get", help="Get a configuration value.")
    config_get_parser.add_argument("key", choices=["backend_url"], help="Configuration key to get.")

    # Lock
    lock_parser = subparsers.add_parser("lock", help="Acquire a lock on an asset.")
    lock_parser.add_argument("asset_path", help="Path to the asset relative to repo root.")
    lock_parser.add_argument("-m", "--message", "--comment", dest="comment", help="Optional comment for the lock.")

    # Unlock
    unlock_parser = subparsers.add_parser("unlock", help="Release a lock on an asset.")
    unlock_parser.add_argument("asset_path", help="Path to the asset relative to repo root.")

    # Check
    check_parser = subparsers.add_parser("check", help="Check lock status of an asset.")
    check_parser.add_argument("asset_path", help="Path to the asset relative to repo root.")
    check_parser.add_argument("--json", action="store_true", help="Output status as JSON.")

    # List
    list_parser = subparsers.add_parser("list", help="List all active locks.")
    list_parser.add_argument("--json", action="store_true", help="Output list as JSON.")

    # Auto-Release (for hooks)
    auto_release_parser = subparsers.add_parser("auto-release", help="Release all locks for the current branch.")

    # Current User (for hooks/scripts)
    current_user_parser = subparsers.add_parser("current-user", help="Print the currently logged-in username.")

    # Notify Lock Holder
    notify_parser = subparsers.add_parser("notify", help="Send a notification to the user holding the lock for an asset.")
    notify_parser.add_argument("asset_path", help="Path to the locked asset relative to repo root.")

    args = parser.parse_args()

    # Determine Backend URL (Priority: CLI arg > Env Var > Config File)
    backend_url = None
    if args.command == "login" and args.url:
        backend_url = args.url.rstrip("/")
    else:
        backend_url = get_configured_backend_url(args.repo_root)

    if not backend_url and args.command not in ["config", "logout"]:
        print(f"Error: Backend URL not configured. Set {ENV_VAR_BACKEND_URL} environment variable, use 'config set backend_url <URL>', or provide --url with login.", file=sys.stderr)
        sys.exit(1)

    # --- Command Execution --- 
    if args.command == "login":
        username = args.username
        password = getpass.getpass(prompt="Password: ")
        login(backend_url, username, password, args.repo_root)
    elif args.command == "logout":
        logout(args.repo_root)
    elif args.command == "config":
        config = load_config(args.repo_root)
        if args.config_command == "set":
            config[args.key] = args.value
            if save_config(config, args.repo_root):
                print(f"Configuration '{args.key}' set successfully for repository '{Path(args.repo_root).resolve()}'.")
                sys.exit(0)
            else:
                sys.exit(1)
        elif args.config_command == "get":
            config = load_config(args.repo_root)
            value = config.get(args.key)
            if value:
                print(value)
                sys.exit(0)
            else:
                print(f"Error: Configuration key '{args.key}' not found in repository '{Path(args.repo_root).resolve()}'.")
                sys.exit(1)
    elif args.command == "lock":
        acquire_lock(backend_url, args.asset_path, args.comment, args.repo_root)
    elif args.command == "unlock":
        release_lock(backend_url, args.asset_path, args.repo_root)
    elif args.command == "check":
        check_lock(backend_url, args.asset_path, args.repo_root)
    elif args.command == "list":
        list_locks(backend_url, args.repo_root)
    elif args.command == "auto-release":
        branch = get_current_branch()
        if branch == "unknown_branch" or branch == "detached_HEAD":
            print(f"Skipping auto-release on branch: {branch}", file=sys.stderr)
            sys.exit(0)
        auto_release(backend_url, branch, args.repo_root)
    elif args.command == "current-user":
        get_currentuser(backend_url, args.repo_root)
    elif args.command == "notify":
        notify_lock_holder(backend_url, args.asset_path, args.repo_root)
    else:
        # Should not happen due to required=True, but good practice
        parser.print_help()

if __name__ == "__main__":
    main()