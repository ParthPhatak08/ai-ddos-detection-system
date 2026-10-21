# Multi-platform Python base image
FROM python:3.11-slim

# Prevent Python from writing .pyc files & buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies required for building psutil and networking packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Ensure directory for SQLite database persistence exists
RUN mkdir -p database

# Expose standard port
EXPOSE 5000

ENV PORT=5000

# Start production server using Gunicorn
CMD ["gunicorn", "app:app", "--workers", "2", "--timeout", "120", "--bind", "0.0.0.0:5000"]
