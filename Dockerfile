FROM python:3.11-slim

EXPOSE 8000

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install backend dependencies
COPY requirements.txt /app/requirements.txt
RUN python -m pip install --no-cache-dir -r /app/requirements.txt

# Copy backend
COPY backend /app/backend

# Run from backend directory so "from app..." imports work
WORKDIR /app/backend

# Create non-root user
RUN adduser --disabled-password --gecos "" appuser \
    && chown -R appuser:appuser /app

USER appuser

# Render provides PORT; fall back to 8000 locally
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-8000} -k uvicorn.workers.UvicornWorker app.main:app"]