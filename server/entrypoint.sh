#!/bin/sh
# Exit immediately if a command exits with a non-zero status.
set -e

# Apply database migrations
echo "Applying database migrations..."
flask db upgrade
echo "Database migrations applied."

# Create initial admin user if env vars are set and user doesn't exist
echo "Checking for initial admin user creation..."
flask create-admin
echo "Initial admin user check complete."

# Run startup email test if enabled
echo "Checking for startup email test..."
if [ "$(echo "$MAIL_ENABLED" | tr '[:upper:]' '[:lower:]')" = "true" ]; then
  echo "MAIL_ENABLED is true, attempting startup email test..."
  # Run the command and capture exit status
  if flask test-email; then
    MAIL_TEST_STATUS="SUCCESS"
    echo "Startup email test command succeeded."
  else
    MAIL_TEST_STATUS="FAILED"
    echo "Warning: Startup email test command failed. Check logs."
  fi
else
  MAIL_TEST_STATUS="SKIPPED"
  echo "MAIL_ENABLED is not true, skipping startup email test."
fi

# Record status in DB
echo "Recording mail test status: $MAIL_TEST_STATUS"
flask set-config system.startup.mail_test_status "$MAIL_TEST_STATUS" || echo "Warning: Failed to record mail test status in database."

# Then exec the container's main process (what's set as CMD in the Dockerfile).
exec "$@" 