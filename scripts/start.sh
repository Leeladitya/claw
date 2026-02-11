#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
#  Claw — Quick Start (without Docker)
#
#  Starts OPA locally and then the Claw server.
#  Requires: opa binary, Python 3.11+, ANTHROPIC_API_KEY set
#
#  Usage:
#    chmod +x scripts/start.sh
#    export ANTHROPIC_API_KEY="sk-ant-..."
#    ./scripts/start.sh
# ─────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
AMBER='\033[0;33m'
NC='\033[0m'

echo -e "${AMBER}🦞 Claw — Starting...${NC}"
echo ""

# ── Check prerequisites ──────────────────────────────────────────

if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
  echo -e "${RED}✕ ANTHROPIC_API_KEY not set${NC}"
  echo "  export ANTHROPIC_API_KEY=\"sk-ant-...\""
  exit 1
fi
echo -e "${GREEN}✓${NC} API key configured"

if ! command -v python3 &> /dev/null; then
  echo -e "${RED}✕ python3 not found${NC}"
  exit 1
fi
echo -e "${GREEN}✓${NC} Python $(python3 --version | cut -d' ' -f2)"

# ── Install Python deps ─────────────────────────────────────────

echo -e "${AMBER}  Installing Python dependencies...${NC}"
pip install -q -r "$ROOT_DIR/requirements.txt" 2>/dev/null || \
pip install -q -r "$ROOT_DIR/requirements.txt" --break-system-packages 2>/dev/null

# ── Start OPA ────────────────────────────────────────────────────

if command -v opa &> /dev/null; then
  echo -e "${GREEN}✓${NC} OPA binary found"
  echo -e "${AMBER}  Starting OPA on :8181...${NC}"
  opa run --server --addr=localhost:8181 \
    "$ROOT_DIR/opa/policies" \
    "$ROOT_DIR/opa/data" &
  OPA_PID=$!
  sleep 1
  echo -e "${GREEN}✓${NC} OPA running (PID: $OPA_PID)"
else
  echo -e "${AMBER}⚠ OPA binary not found — trying Docker...${NC}"
  if command -v docker &> /dev/null; then
    docker run -d --rm --name claw-opa \
      -p 8181:8181 \
      -v "$ROOT_DIR/opa/policies:/policies" \
      -v "$ROOT_DIR/opa/data:/data" \
      openpolicyagent/opa:latest-static \
      run --server --addr=0.0.0.0:8181 /policies /data \
      > /dev/null
    echo -e "${GREEN}✓${NC} OPA running via Docker"
    OPA_PID=""
  else
    echo -e "${RED}✕ Neither 'opa' binary nor 'docker' found.${NC}"
    echo "  Install OPA: https://www.openpolicyagent.org/docs/latest/#1-download-opa"
    echo "  Or install Docker and run: docker compose up"
    exit 1
  fi
fi

# ── Start Claw Server ───────────────────────────────────────────

echo ""
echo -e "${AMBER}  Starting Claw server on :8787...${NC}"
echo ""

cd "$ROOT_DIR"
python3 -m server.app

# ── Cleanup ──────────────────────────────────────────────────────

if [ -n "${OPA_PID:-}" ]; then
  kill "$OPA_PID" 2>/dev/null || true
fi
