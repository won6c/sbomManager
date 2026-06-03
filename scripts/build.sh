#!/usr/bin/env bash
set -euo pipefail
python -m py_compile src/main.py src/core/*.py src/plugins/*/*.py
