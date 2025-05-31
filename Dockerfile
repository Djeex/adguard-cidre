FROM python:3.11-slim

# Install required utilities
RUN apt-get update && apt-get install -y \
    curl \
    cron \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
RUN pip install --no-cache-dir requests

# Create crontabs directory (if needed)
RUN mkdir -p /etc/crontabs

# Copy scripts
COPY update-blocklist.py /usr/local/bin/update-blocklist.py
COPY entrypoint.py /usr/local/bin/entrypoint.py

# Make scripts executable
RUN chmod +x /usr/local/bin/update-blocklist.py /usr/local/bin/entrypoint.py

# Set default timezone (can be overridden with TZ env var)
ENV TZ=UTC

# Configure timezone (tzdata)
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/entrypoint.py"]
