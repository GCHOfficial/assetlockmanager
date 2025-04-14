#!/bin/sh
# Exit immediately if a command exits with a non-zero status.
set -e

# --- Custom CA Certificate Installation (Generic) ---
echo "ENTRYPOINT: Checking for custom CA certificate installation..."
if [ -n "${CUSTOM_CA_CERT_PATH}" ]; then
    echo "INFO: CUSTOM_CA_CERT_PATH is set to '${CUSTOM_CA_CERT_PATH}'."
    if [ -f "${CUSTOM_CA_CERT_PATH}" ]; then
        # Determine destination filename
        DEST_FILENAME=${CUSTOM_CA_CERT_FILENAME:-custom-ca.crt}
        DEST_PATH="/usr/local/share/ca-certificates/${DEST_FILENAME}"
        echo "INFO: Found custom CA certificate at '${CUSTOM_CA_CERT_PATH}'. Installing to '${DEST_PATH}'..."
        
        # Ensure destination directory exists
        mkdir -p "/usr/local/share/ca-certificates"
        
        # Copy the certificate
        cp "${CUSTOM_CA_CERT_PATH}" "${DEST_PATH}"
        
        # Update the system trust store
        if command -v update-ca-certificates > /dev/null; then
            update-ca-certificates
            echo "INFO: Ran update-ca-certificates successfully."
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

# Apply database migrations first
echo "ENTRYPOINT: Running database migrations..."
if flask db upgrade; then
    echo "ENTRYPOINT: Database migrations complete."
else
    EXIT_CODE=$?
    echo "ENTRYPOINT: Database migrations FAILED with exit code $EXIT_CODE. Exiting."
    exit $EXIT_CODE
fi

# Create initial admin user if variables are set and user doesn't exist
if [ -n "${INITIAL_ADMIN_USER}" ] && [ -n "${INITIAL_ADMIN_EMAIL}" ] && [ -n "${INITIAL_ADMIN_PASSWORD}" ]; then
    echo "ENTRYPOINT: Checking for initial admin user..."
    flask create-admin
else
    echo "ENTRYPOINT: Initial admin user variables not set, skipping creation check."
fi

# Run email test if enabled
if [ "${MAIL_ENABLED}" = "true" ]; then
    echo "ENTRYPOINT: MAIL_ENABLED is true, attempting test email..."
    # Run in background or handle potential long timeout?
    # For now, run synchronously but capture status
    if flask test-email; then
        echo "ENTRYPOINT: Startup email test command succeeded."
        flask set-config system.startup.mail_test_status SUCCESS
    else
        echo "ERROR: Startup email test command failed." >&2 # Log error to stderr
        flask set-config system.startup.mail_test_status FAILED
    fi
else
    echo "ENTRYPOINT: MAIL_ENABLED is not true, skipping email test."
    flask set-config system.startup.mail_test_status SKIPPED
fi

# Now execute the command passed as arguments (which defaults to the Dockerfile CMD)
echo "ENTRYPOINT: Handing over execution to CMD ($@)..."
exec "$@" 