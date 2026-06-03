#!/usr/bin/env bash
set -euo pipefail
export PYTHONPATH="${PYTHONPATH:-}:$(pwd)/src"
pytest evaluations/benchmarks -q
