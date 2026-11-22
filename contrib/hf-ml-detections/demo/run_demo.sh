#!/usr/bin/env bash
set -euo pipefail

demo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ingest_url="${AISOC_DEMO_INGEST_URL:-http://127.0.0.1:8081}"
api_url="${AISOC_DEMO_API_URL:-http://127.0.0.1:8000}"

curl -fsS --max-time 5 "${ingest_url%/}/health" >/dev/null
curl -fsS --max-time 5 "${api_url%/}/health" >/dev/null

export OPENBLAS_NUM_THREADS="${AISOC_DEMO_CPU_THREADS:-2}"
export OMP_NUM_THREADS="${AISOC_DEMO_CPU_THREADS:-2}"
exec "${AISOC_DEMO_PYTHON:-$demo_dir/../.venv/bin/python}" "$demo_dir/demo_live.py" "$@"
