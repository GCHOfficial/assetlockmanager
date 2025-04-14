# Use an official slim Python image.
FROM python:3.11-slim

WORKDIR /app

# Install gosu for privilege dropping
RUN apt-get update && apt-get install -y --no-install-recommends gosu && rm -rf /var/lib/apt/lists/*

# Create a non-root user and group
RUN groupadd -r filelockapiuser && useradd --no-log-init -r -g filelockapiuser filelockapiuser

# Copy and install dependencies.
COPY requirements.txt requirements.txt
# Ensure pip is up-to-date and install requirements
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy the application code.
# Copy as root first to ensure correct permissions, then change ownership
COPY . .

# Copy the entrypoint script and make it executable
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Change ownership *after* copying all files (entrypoint runs as root, needs access)
# We will drop privileges using gosu within the entrypoint itself for the final command
RUN chown -R filelockapiuser:filelockapiuser /app
# Keep entrypoint owned by root so it can execute as root
# RUN chown filelockapiuser:filelockapiuser /usr/local/bin/entrypoint.sh

# Expose port 5000 (can be exposed by non-root user).
EXPOSE 5000

# Set the entrypoint script (will run as root)
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# Switch to the non-root user *AFTER* entrypoint (applies only if entrypoint doesn't exec)
# USER filelockapiuser

# Use Gunicorn with 4 workers, and trust Traefik's forwarded headers.
# This command is passed to the entrypoint script, which will execute it as 'filelockapiuser' using gosu.
CMD ["gunicorn", "--forwarded-allow-ips", "*", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]