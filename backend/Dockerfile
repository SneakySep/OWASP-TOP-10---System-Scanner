FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SEMGREP_SEND_METRICS=off

# System build tools needed by semgrep's dependencies.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    fastapi \
    uvicorn[standard] \
    python-multipart \
    semgrep

# Non-root user with write access to the scan directory, the history volume
# and the semgrep cache mount point (they must exist with correct ownership in
# the image, or the named volume mountpoint is created root-owned and the app
# can't write).
RUN useradd --create-home --shell /bin/bash appuser \
    && mkdir -p /tmp/scans /data /home/appuser/.semgrep \
    && chown -R appuser:appuser /tmp/scans /data /home/appuser

WORKDIR /app
COPY --chown=appuser:appuser main.py remediation.py autofix.py store.py reports.py ./

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
