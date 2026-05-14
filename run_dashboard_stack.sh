#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

if [[ ! -x ".venv/bin/python" ]]; then
  echo "[error] Python venv not found at .venv/bin/python"
  echo "[hint] Create it first: python -m venv .venv && .venv/bin/pip install -r requirements.txt"
  exit 1
fi

ADAPTER_HOST="${ADAPTER_HOST:-127.0.0.1}"
ADAPTER_PORT="${ADAPTER_PORT:-9010}"
API_HOST="${API_HOST:-127.0.0.1}"
API_PORT="${API_PORT:-8000}"
DASHBOARD_HOST="${DASHBOARD_HOST:-127.0.0.1}"
DASHBOARD_PORT="${DASHBOARD_PORT:-8501}"

export UPSTREAM_AGENT_URL="${UPSTREAM_AGENT_URL:-${COPILOT_AGENT_URL:-http://${ADAPTER_HOST}:${ADAPTER_PORT}/infer}}"
export COPILOT_AGENT_URL="${COPILOT_AGENT_URL:-$UPSTREAM_AGENT_URL}"

export COPILOT_AUTH_TYPE="${COPILOT_AUTH_TYPE:-none}"
export COPILOT_REQUEST_MODE="${COPILOT_REQUEST_MODE:-prompt}"
export COPILOT_REQUEST_FIELD="${COPILOT_REQUEST_FIELD:-prompt}"
if [[ -n "${COPILOT_AUTH_VALUE:-}" ]]; then
  export COPILOT_AUTH_VALUE
fi

cleanup() {
  local exit_code=$?
  for pid in "${DASHBOARD_PID:-}" "${API_PID:-}" "${ADAPTER_PID:-}"; do
    if [[ -n "${pid:-}" ]] && kill -0 "$pid" >/dev/null 2>&1; then
      kill "$pid" >/dev/null 2>&1 || true
    fi
  done
  wait >/dev/null 2>&1 || true
  exit "$exit_code"
}

trap cleanup EXIT INT TERM

echo "[start] Vendor adapter"
PYTHONPATH=. .venv/bin/uvicorn app.copilot_vendor_adapter:app --host "$ADAPTER_HOST" --port "$ADAPTER_PORT" >/tmp/agentbench-adapter.log 2>&1 &
ADAPTER_PID=$!

echo "[start] AgentBench API"
PYTHONPATH=. .venv/bin/uvicorn app.main:app --host "$API_HOST" --port "$API_PORT" >/tmp/agentbench-api.log 2>&1 &
API_PID=$!

echo "[start] Streamlit dashboard"
PYTHONPATH=. .venv/bin/streamlit run dashboard/app.py --server.address "$DASHBOARD_HOST" --server.port "$DASHBOARD_PORT" >/tmp/agentbench-dashboard.log 2>&1 &
DASHBOARD_PID=$!

echo
echo "[ready] AgentBench services started"
echo "  - Adapter:   http://${ADAPTER_HOST}:${ADAPTER_PORT}/health"
echo "  - API:       http://${API_HOST}:${API_PORT}/health"
echo "  - Dashboard: http://${DASHBOARD_HOST}:${DASHBOARD_PORT}"
echo
echo "[info] Logs:"
echo "  - /tmp/agentbench-adapter.log"
echo "  - /tmp/agentbench-api.log"
echo "  - /tmp/agentbench-dashboard.log"
echo
echo "[info] Press Ctrl+C to stop all services"

wait "$DASHBOARD_PID"