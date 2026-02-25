FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY honeypot/ ./honeypot/
COPY mcp_server/ ./mcp_server/
COPY scripts/ ./scripts/
COPY honeypot_config.yaml .

# Create data directory for persistence
RUN mkdir -p /app/data

# Create non-root user for security
RUN useradd -m -u 1000 honeypot && \
    chown -R honeypot:honeypot /app

# Switch to non-root user
USER honeypot

# Expose default ports (can be overridden in docker-compose)
# SSH: 2222, HTTP: 8000, LDAP: 3389, SMB: 4445
EXPOSE 2222 8000 3389 4445

# Set entrypoint
ENTRYPOINT ["python", "-m", "honeypot.main"]
CMD ["--config", "honeypot_config.yaml"]
