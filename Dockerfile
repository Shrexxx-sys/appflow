# AppFlow Sentinel backend - container image.
# Build:  docker build -t appflow-backend .
# Run:    docker run --env-file .env -p 8000:8000 -v appflow-data:/data appflow-backend
FROM python:3.12-slim

# Don't write .pyc files; print logs immediately.
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies first: Docker caches this layer, so code changes rebuild fast.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY simulator.py .

# Database and PDFs live in /data, a volume, so they survive container restarts.
ENV DATABASE_URL=sqlite:////data/appflow.db \
    REPORTS_DIR=/data/reports
VOLUME /data

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
