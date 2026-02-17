FROM python:3.12-slim

RUN groupadd -r claw && useradd -r -g claw -d /app -s /sbin/nologin claw

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server/ server/
COPY opa/ opa/

RUN mkdir -p data && chown -R claw:claw /app

USER claw
EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import httpx; r=httpx.get('http://localhost:8787/v1/health'); exit(0 if r.status_code==200 else 1)"

CMD ["uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "8787"]
