FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

RUN useradd --create-home --uid 10001 appuser

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --upgrade pip && pip install -e .

# Writable state for the non-root user. In production, mount keys/ read-only and
# back data/ + logs/ with volumes.
RUN mkdir -p /app/logs /app/data /app/keys \
    && chown -R appuser:appuser /app/logs /app/data /app/keys

USER appuser

ENV MCP_HOST=0.0.0.0 \
    AS_HOST=0.0.0.0 \
    AUDIT_PATH=/app/logs/audit.jsonl \
    APPROVALS_DB=/app/data/approvals.db \
    KEYS_DIR=/app/keys \
    CLIENTS_FILE=/app/keys/clients.json

VOLUME ["/app/data", "/app/logs"]

EXPOSE 8000 9000

# Default command runs the governed MCP router. Run the authorization server with:
#   docker run ... python -m mcp_router.authorization_server
CMD ["python", "-m", "mcp_router.server"]
