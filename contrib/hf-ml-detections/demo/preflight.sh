#!/usr/bin/env bash
# Read-only checks apart from normal smoke traffic and token minting.
set -uo pipefail
set +x

demo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$demo_dir/../../.." && pwd)"
cd "$repo_root" || exit 1
fixes=()
run() {
    local label=$1 fix=$2
    shift 2
    if "$@" >/dev/null 2>&1; then
        printf 'PASS %s\n' "$label"
    else
        printf 'FAIL %s\n' "$label"
        fixes+=("$label — $fix")
    fi
}

stack_healthy() {
    # Services without a Docker healthcheck must be running. The model
    # downloader is a one-shot job, so a successful exit is healthy.
    docker compose ps --all --format json |
        python3 -c '
import json, sys
raw = sys.stdin.read().strip()
rows = json.loads(raw) if raw.startswith("[") else [json.loads(line) for line in raw.splitlines()]
required = set("actions agents api connectors fusion ingest-worker kafka litellm ollama postgres qdrant realtime redis threatintel web zookeeper".split())
assert required <= {row["Service"] for row in rows}
for row in rows:
    if row["Service"] == "ollama-pull":
        assert row["State"] == "exited" and row["ExitCode"] == 0 or row["State"] == "running"
    else:
        assert row["State"] == "running" and row.get("Health", "") in {"", "healthy"}
'
}

pull_never() {
    docker compose config --format json |
        python3 -c 'import json,sys; s=json.load(sys.stdin)["services"]; assert all(s[n].get("pull_policy")=="never" for n in ("ingest-worker","fusion"))'
}

ingest_classes() {
    docker compose exec -T ingest-worker sh -c         'grep -aq hf_auth ./ingest-service && grep -aq hf_network ./ingest-service'
}

rules_present() {
    local id path
    id="$(docker compose ps -q fusion)" && [[ -n $id ]] || return 1
    path=/app/app/data/detection_ruleset_imported.json
    docker inspect "$id" |
        python3 -c 'import json,sys; assert any(m["Type"]=="bind" and m["Destination"]==sys.argv[1] and not m["RW"] for m in json.load(sys.stdin)[0]["Mounts"])' "$path" || return 1
    docker compose exec -T fusion cat "$path" |
        python3 -c '
import json, re, sys
rules = {r["id"]: r for r in json.load(sys.stdin)["rules"]}
assert all(rules[name].get("enabled", True) for name in ("det-hf-ml-005", "det-hf-ml-005-hi"))
# The native exporter omits disabled specs. Check their source state too.
assert not rules.get("det-hf-ml-002", {}).get("enabled", "det-hf-ml-002" in rules)
assert re.search(r"^enabled:\s*false\s*$", open("detections/hf-ml/hf-uc1-xgboost.yaml").read(), re.M)
'
}

cache_present() {
    local name
    for name in patator.parquet dos.parquet baselines.json; do
        [[ -s "$demo_dir/../data/demo/$name" ]] || return 1
    done
    [[ -s "$demo_dir/../data/cicids-models/uc1b.ubj" && -x "$demo_dir/../.venv/bin/python" ]]
}

tokens_mint() {
    local ingest api
    ingest="$(make -s ingest-token ARGS=--quiet)" &&
        api="$(make -s api-token ARGS=--quiet)" &&
        [[ -n $ingest && -n $api ]]
}

disk_ok() {
    df -Pk . | awk 'NR==2 { if ($4 > 1572864) ok=1 } END { exit !ok }'
}

run "Docker running" 'bash .devcontainer/start-docker.sh' docker info
run "AiSOC containers running and healthy where probes exist" '~/aisoc-start.sh' stack_healthy
run "AISOC_PULL_POLICY=never effective for ingest and Fusion" "sed -i '/^AISOC_PULL_POLICY=/d' .env && printf '\\nAISOC_PULL_POLICY=never\\n' >> .env" pull_never
run "Ingest binary contains hf_auth and hf_network" 'docker compose build ingest-worker && docker compose up -d --no-deps --force-recreate --pull never ingest-worker' ingest_classes
run "Fusion read-only ruleset has 005 and 005-hi active and 002 retired" 'python3 contrib/hf-ml-detections/demo/install_rules.py && docker compose up -d --no-deps --force-recreate --pull never fusion # Add the mount first as shown in contrib/hf-ml-detections/docs/codespaces-fixes.md' rules_present
run "Demo cache, frozen model, and virtual environment available" 'cd contrib/hf-ml-detections && python3 -m venv .venv && .venv/bin/python -m pip install --no-cache-dir -r requirements.txt && install -D "$FROZEN_MODEL" data/cicids-models/uc1b.ubj && ./demo/run_demo.sh --prepare # Set FROZEN_MODEL to the archived model path first' cache_present
run "Ingest and API tokens can be minted" 'make bootstrap && make -s ingest-token ARGS=--quiet >/dev/null && make -s api-token ARGS=--quiet >/dev/null' tokens_mint
run "Disk free > 1.5 GiB" 'df -h . && docker system df && docker image prune -f && df -h . # Free more space before rehearsing if still below the floor' disk_ok
run "Console answers on :3000" 'docker compose up -d --no-deps --pull never web' curl -fsSL --max-time 10 -o /dev/null http://127.0.0.1:3000
run "make smoke passes" 'make doctor && make smoke' make smoke

if (( ${#fixes[@]} )); then
    printf 'Fix before the demo:\n'
    printf '  %s\n' "${fixes[@]}"
    exit 1
fi
echo "READY FOR DEMO"
