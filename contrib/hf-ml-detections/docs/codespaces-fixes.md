# Codespaces workarounds

These are local settings from the Codespace setup that passed `make smoke`
10/10, as reported by the operator. Day 1 ran `make doctor` against that
running stack.

## Kafka memory limit

The local `docker-compose.override.yml` removes Kafka's `mem_limit`.
The Codespace's cgroup v2 setup rejected the setting with the error
`cannot enter cgroupv2 ... it is in threaded mode`.

## Docker forwarding

Kafka timed out connecting to Zookeeper when Docker's FORWARD policy dropped
traffic between containers. In this Codespace the operator applies the policy
on all three iptables backends:

```bash
sudo iptables -P FORWARD ACCEPT
sudo iptables-legacy -P FORWARD ACCEPT
sudo iptables-nft -P FORWARD ACCEPT
```

The local `~/aisoc-start.sh` applies those commands and then runs `make up`
and `make smoke`. Keep the script and Compose override local.

## ZooKeeper broker registration after restart

Kafka logged `KeeperErrorCode = NodeExists` during a restart when its
broker registration already existed. Allow the old session to expire.
If Kafka keeps restarting, recover in dependency order:

```bash
docker compose stop kafka
docker compose restart zookeeper
docker compose up -d --no-deps --pull never kafka
docker compose logs --tail 50 kafka
make smoke
```

Keep the existing volumes. If the error persists after the old session
expires, check for a second process claiming the same broker ID.

## Fresh Codespace

From the fork's repository root on `hf-ml-detections`, check space before
installing or building. A fresh copy needs the base images and enough
space for the local ingest image. Run this on the Codespace's nested
Docker daemon.

```bash
df -h .
docker system df
bash .devcontainer/start-docker.sh
for backend in iptables iptables-legacy iptables-nft; do
  sudo "$backend" -P FORWARD ACCEPT
done
```

On a fresh checkout, create the local override with this initial content.
On an existing Codespace, add the Kafka setting under its existing
`services` key.

```yaml
services:
  kafka:
    mem_limit: !reset null
```

Save it as `docker-compose.override.yml`. Fetch the base images on this
first start, then protect the local tag before building ingest.

```bash
make up
sed -i '/^AISOC_PULL_POLICY=/d' .env
printf '\nAISOC_PULL_POLICY=never\n' >> .env
docker compose build ingest-worker
docker compose up -d --no-deps --force-recreate --pull never ingest-worker
python3 contrib/hf-ml-detections/demo/install_rules.py
```

Add the following **under the same** `services` key, alongside `kafka`.
Recreate Fusion so Docker binds the new file.

```yaml
  fusion:
    volumes:
      - ./contrib/hf-ml-detections/data/fusion-imported-local.json:/app/app/data/detection_ruleset_imported.json:ro
```

```bash
docker compose up -d --no-deps --force-recreate --pull never fusion
make smoke
```

Save this local helper as `~/aisoc-start.sh` for future presentation days.
Use the actual repository workspace path if it differs.

```bash
#!/usr/bin/env bash
set -euo pipefail
cd /workspaces/AiSOC
for backend in iptables iptables-legacy iptables-nft; do
  sudo "$backend" -P FORWARD ACCEPT
done
make up
make smoke
```

```bash
chmod +x ~/aisoc-start.sh
cd contrib/hf-ml-detections
df -h .
docker system df
python3 -m venv .venv
.venv/bin/python -m pip install --no-cache-dir -r requirements.txt
mkdir -p data/cicids-models
```

Restore the frozen booster from the original Codespace. Set
`SOURCE_CODESPACE` to its name before running the copy command, or put the
same archived file at the destination. This artifact is intentionally
outside Git. A new Codespace needs access to that original or an archive
to replay the exact frozen model.

```bash
gh codespace cp -c "$SOURCE_CODESPACE" \
  remote:/workspaces/AiSOC/contrib/hf-ml-detections/data/cicids-models/uc1b.ubj \
  data/cicids-models/uc1b.ubj
printf '%s\n' '9dae2b65cb9857d331e3edc38c8d72077f840ee47b4df82f115c18d037f8acc5  data/cicids-models/uc1b.ubj' | sha256sum -c -
./demo/run_demo.sh --prepare
./demo/preflight.sh
./demo/run_demo.sh patator --source cache
```
