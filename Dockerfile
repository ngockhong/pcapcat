# Use Ubuntu as base image (tshark requires it)
FROM ubuntu:22.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    tshark \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Allow non-root users to capture packets with tshark
RUN chmod +x /usr/bin/dumpcap

# Copy requirements first (for better caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ ./app/
COPY tests/ ./tests/
COPY README.md .

# Create data directories
RUN mkdir -p /app/data/pcaps /app/data

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Default command (shows help)
ENTRYPOINT ["python3", "-m", "app.cli"]
CMD ["--help"]