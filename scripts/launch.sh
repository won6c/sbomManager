#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRONTEND_DIR="$ROOT_DIR/src/web/frontend"

BACKEND_HOST="${BACKEND_HOST:-127.0.0.1}"
BACKEND_PORT="${BACKEND_PORT:-8000}"
FRONTEND_HOST="${FRONTEND_HOST:-127.0.0.1}"
FRONTEND_PORT="${FRONTEND_PORT:-5173}"

export PYTHONPATH="$ROOT_DIR/src:${PYTHONPATH:-}"

BACKEND_PID=""
FRONTEND_PID=""

cleanup() {
  echo
  echo "[launch] stopping services..."
  if [[ -n "${FRONTEND_PID}" ]] && kill -0 "${FRONTEND_PID}" 2>/dev/null; then
    kill "${FRONTEND_PID}" 2>/dev/null || true
  fi
  if [[ -n "${BACKEND_PID}" ]] && kill -0 "${BACKEND_PID}" 2>/dev/null; then
    kill "${BACKEND_PID}" 2>/dev/null || true
  fi
  wait "${FRONTEND_PID}" 2>/dev/null || true
  wait "${BACKEND_PID}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[launch] missing required command: $1" >&2
    exit 1
  fi
}

require_cmd python
require_cmd npm

if [[ ! -f "$ROOT_DIR/src/main.py" ]]; then
  echo "[launch] backend entrypoint not found: $ROOT_DIR/src/main.py" >&2
  exit 1
fi

if [[ ! -f "$FRONTEND_DIR/package.json" ]]; then
  echo "[launch] frontend package.json not found: $FRONTEND_DIR/package.json" >&2
  exit 1
fi

if [[ ! -d "$FRONTEND_DIR/node_modules" ]]; then
  echo "[launch] frontend dependencies missing; running npm install..."
  (cd "$FRONTEND_DIR" && npm install)
fi

echo "[launch] backend:  http://${BACKEND_HOST}:${BACKEND_PORT}"
echo "[launch] frontend: http://${FRONTEND_HOST}:${FRONTEND_PORT}"
echo

echo "[launch] starting backend..."
(
  cd "$ROOT_DIR"
  python -m uvicorn main:app --reload --host "$BACKEND_HOST" --port "$BACKEND_PORT"
) &
BACKEND_PID=$!

echo "[launch] starting frontend..."
(
  cd "$FRONTEND_DIR"
  npm run dev -- --host "$FRONTEND_HOST" --port "$FRONTEND_PORT"
) &
FRONTEND_PID=$!

echo
 echo "[launch] services started. Press Ctrl+C to stop."
echo "[launch] backend PID:  ${BACKEND_PID}"
echo "[launch] frontend PID: ${FRONTEND_PID}"

wait -n "$BACKEND_PID" "$FRONTEND_PID"
EXIT_CODE=$?

echo "[launch] one service exited with code ${EXIT_CODE}; shutting down the other."
exit "$EXIT_CODE"
