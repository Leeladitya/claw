FROM python:3.12-slim

LABEL maintainer="Sahasra & Co."
LABEL description="Claw — Governance-First Browser Context API"

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy server code
COPY server/ ./server/

# Create audit log directory
RUN mkdir -p /app/logs

ENV CLAW_AUDIT_LOG=/app/logs/audit.jsonl
ENV PYTHONUNBUFFERED=1

EXPOSE 8787

CMD ["python", "-m", "server.app"]
