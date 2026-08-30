FROM python:3.11-slim

# Render will provide the PORT environment variable.
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN python -m pip install --no-cache-dir -r requirements.txt

# Copy the backend application
COPY backend ./backend

# Render uses the PORT environment variable
EXPOSE 8000

# Start FastAPI from backend/app/main.py
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-8000} -k uvicorn.workers.UvicornWorker backend.app.main:app"]