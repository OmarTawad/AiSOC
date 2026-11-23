#!/usr/bin/env bash
set -euo pipefail

demo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$demo_dir/../../.." && pwd)"
set +x
ingest_url="${AISOC_DEMO_INGEST_URL:-http://127.0.0.1:8081}"
api_url="${AISOC_DEMO_API_URL:-http://127.0.0.1:8000}"

curl -fsS --max-time 5 "${ingest_url%/}/health" >/dev/null
curl -fsS --max-time 5 "${api_url%/}/health" >/dev/null

# Preparation and dry runs do not send events.
needs_tokens=1
for arg in "$@"; do
    case "$arg" in --prepare|--dry-run|--help|-h) needs_tokens=0 ;; esac
done
if (( needs_tokens )); then
    if [[ -z ${AISOC_INGEST_TOKEN:-} ]]; then
        AISOC_INGEST_TOKEN="$(make -s -C "$repo_root" ingest-token ARGS=--quiet 2>/dev/null)" ||
            { echo "Could not mint the ingest token. Run demo/preflight.sh." >&2; exit 1; }
    fi
    if [[ -z ${AISOC_API_TOKEN:-} ]]; then
        AISOC_API_TOKEN="$(make -s -C "$repo_root" api-token ARGS=--quiet 2>/dev/null)" ||
            { echo "Could not mint the API token. Run demo/preflight.sh." >&2; exit 1; }
    fi
    if [[ -z $AISOC_INGEST_TOKEN || -z $AISOC_API_TOKEN ]]; then
        echo "Token mint returned an empty credential. Run demo/preflight.sh." >&2
        exit 1
    fi
    export AISOC_INGEST_TOKEN AISOC_API_TOKEN
fi

export OPENBLAS_NUM_THREADS="${AISOC_DEMO_CPU_THREADS:-2}"
export OMP_NUM_THREADS="${AISOC_DEMO_CPU_THREADS:-2}"
exec "${AISOC_DEMO_PYTHON:-$demo_dir/../.venv/bin/python}" "$demo_dir/demo_live.py" "$@"
