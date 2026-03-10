FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create directories
RUN mkdir -p data models logs

# Environment
ENV PYTHONUNBUFFERED=1
ENV CONFIG_PATH=/app/config/config.yaml

# Default command
CMD ["python", "-m", "pipeline.orchestrator"]
