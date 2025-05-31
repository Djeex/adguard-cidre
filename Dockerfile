FROM python:3.11-slim

# Install curl and cron
RUN apt-get update && apt-get install -y curl cron && rm -rf /var/lib/apt/lists/*

# Install Python requests
RUN pip install --no-cache-dir requests

# Create adguard config dir
RUN mkdir -p /adguard

# Copy update-blocklist script
COPY update-blocklist.py /usr/local/bin/update-blocklist.py
RUN chmod +x /usr/local/bin/update-blocklist.py

# Copy entrypoint script (on next step)

# Setup cron config dir
RUN mkdir -p /etc/crontabs

ENTRYPOINT ["/usr/local/bin/entrypoint.py"]
