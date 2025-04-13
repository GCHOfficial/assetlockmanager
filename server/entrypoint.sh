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

# Then exec the container's main process (what's set as CMD in the Dockerfile).
exec "$@" 