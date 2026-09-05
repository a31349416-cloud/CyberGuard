FROM python:3.11-slim

WORKDIR /app

# System deps for lxml + curl for healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libxml2-dev libxslt1-dev curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -r requirements.txt

# Playwright для SPA краулера (опційно, 20 сторінок)
RUN pip install --no-cache-dir playwright && playwright install --with-deps chromium || echo "playwright install skipped"

COPY . .

# SQLite DB + reports dir + alembic stamp
RUN mkdir -p backend/reports && python -m alembic stamp head || true

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD curl -f http://localhost:8000/api/health || exit 1

CMD ["python", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
