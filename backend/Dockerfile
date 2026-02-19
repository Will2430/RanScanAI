# Universal Dockerfile for FastAPI Backend
# Works with: Railway, Render, Fly.io, Google Cloud Run, AWS ECS, Azure, DigitalOcean

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies for Python packages
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p temp_scans

# Expose port (most platforms use PORT env var)
EXPOSE 8000

# Health check (optional but recommended for production)
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/health', timeout=5)"

# Run the application
# Use PORT environment variable if set (required by some platforms), default to 8000
CMD uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}
