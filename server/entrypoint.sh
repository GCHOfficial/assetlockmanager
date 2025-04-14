#!/bin/sh
# Exit immediately if a command exits with a non-zero status.
set -e

# --- Custom CA Certificate Installation (Generic) ---
# This script runs as root because the USER instruction was removed from the Dockerfile before ENTRYPOINT.
echo "ENTRYPOINT: Checking for custom CA certificate installation..."
if [ -n "${CUSTOM_CA_CERT_PATH}" ]; then
    echo "INFO: CUSTOM_CA_CERT_PATH is set to '${CUSTOM_CA_CERT_PATH}'."
    if [ -f "${CUSTOM_CA_CERT_PATH}" ]; then
        # Determine destination filename
        DEST_FILENAME=${CUSTOM_CA_CERT_FILENAME:-custom-ca.crt}
        DEST_DIR="/usr/local/share/ca-certificates"
        DEST_PATH="${DEST_DIR}/${DEST_FILENAME}"
        echo "INFO: Found custom CA certificate at '${CUSTOM_CA_CERT_PATH}'. Installing to '${DEST_PATH}'..."

        # Ensure destination directory exists
        mkdir -p "${DEST_DIR}"

        # Copy the certificate (running as root)
        cp "${CUSTOM_CA_CERT_PATH}" "${DEST_PATH}"

        # Update the system trust store (running as root)
        if command -v update-ca-certificates > /dev/null; then
            if update-ca-certificates; then
                echo "INFO: Ran update-ca-certificates successfully."
            else
                echo "ERROR: Failed to run update-ca-certificates." >&2
            fi
        else
            echo "WARNING: update-ca-certificates command not found. Cannot update system trust store."
        fi
    else
        echo "WARNING: CUSTOM_CA_CERT_PATH is set, but file not found at '${CUSTOM_CA_CERT_PATH}'. Skipping certificate installation."
    fi
else
    echo "INFO: CUSTOM_CA_CERT_PATH is not set. Skipping custom CA certificate installation."
fi
# --- End Custom CA Certificate Installation ---

# Apply database migrations first (as root)
echo "ENTRYPOINT: Running database migrations..."
if flask db upgrade; then
    echo "ENTRYPOINT: Database migrations complete."
else
    EXIT_CODE=$?
    echo "ENTRYPOINT: Database migrations FAILED with exit code $EXIT_CODE. Exiting."
    exit $EXIT_CODE
fi

# Create initial admin user if variables are set and user doesn't exist (as root)
if [ -n "${INITIAL_ADMIN_USER}" ] && [ -n "${INITIAL_ADMIN_EMAIL}" ] && [ -n "${INITIAL_ADMIN_PASSWORD}" ]; then
    echo "ENTRYPOINT: Checking for initial admin user..."
    flask create-admin
else
    echo "ENTRYPOINT: Initial admin user variables not set, skipping creation check."
fi

# Run email test if enabled (as root)
if [ "${MAIL_ENABLED}" = "true" ]; then
    echo "ENTRYPOINT: MAIL_ENABLED is true, attempting test email..."
    # Execute the command and capture its exit status explicitly
    flask test-email
    EMAIL_TEST_EXIT_CODE=$?

    if [ $EMAIL_TEST_EXIT_CODE -eq 0 ]; then
        echo "ENTRYPOINT: Startup email test command finished successfully (Exit Code: 0)."
        flask set-config system.startup.mail_test_status SUCCESS
    else
        # Error messages from flask test-email should already be on stderr
        echo "ERROR: Startup email test command failed (Exit Code: $EMAIL_TEST_EXIT_CODE). Check logs above for details." >&2
        flask set-config system.startup.mail_test_status FAILED
    fi
else
    echo "ENTRYPOINT: MAIL_ENABLED is not true, skipping email test."
    flask set-config system.startup.mail_test_status SKIPPED
fi

# Drop privileges and execute the command passed as arguments (CMD)
# Use 'gosu' for Debian-based images (like python:3.11-slim)
echo "ENTRYPOINT: Handing over execution to CMD ($@) as user 'filelockapiuser'..."
exec gosu filelockapiuser "$@" 