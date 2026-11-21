# AiSOC integration notes

## Batch ingest and authentication

Send JSON to `POST /v1/ingest/batch` on the ingest worker (port 8081).
The request contains `connector_id`, `connector_type`, `source_format`, and
`events`, an array of objects. The handler requires the first two fields, checks
the batch limit, and returns `accepted`, `rejected`, and `request_id` after
publishing accepted events. Inspect the counts even when the HTTP status is 200.
See `services/ingest/internal/handler/handler.go` and
`services/ingest/internal/server/server.go`.

Use `Authorization: Bearer <token>` with the token from
`make ingest-token ARGS=--quiet`. The Makefile calls
`services/api/app/scripts/mint_ingest_token.py` via Compose. It reuses the
active push token by default. Authentication precedes normalization and
determines the tenant. A tenant header can only narrow the authorized scope.
See `services/ingest/internal/ingestauth/authenticator.go`. Use a separate
`make api-token ARGS=--quiet` bearer to read `GET /api/v1/alerts` on port 8000.

## OCSF and the score path

In `services/ingest/internal/normalizer/normalizer.go`, `Normalize` resolves
connector aliases and selects a connector profile. An object containing
`source` and `raw_event` uses the canonical envelope mapping. The normalizer
sets OCSF class, category, time, severity, identity aliases, provenance, and
stable event ID, then serializes the entire input object into
`ocsf_event.raw_data` on the Kafka message. Unknown fields survive in this JSON
string. A score in an input event's `raw_event` appears at
`JSON.parse(message.ocsf_event.raw_data).raw_event.ml_anomaly_score`.
A score on the input event itself appears directly in the decoded object.

In `services/fusion/app/services/detection_engine.py`, Fusion decodes
`raw_data` and lifts the first level of `raw_event` into its flat field map.
Keys on the outer decoded object win on collision. The matcher therefore
uses `ml_anomaly_score` directly. It looks up literal flat keys. A dotted key
works if it exists literally in that map. Fusion also adds selected activity
location keys and derived fields from enrichment and tenant context. See
`services/fusion/app/services/raw_data.py` and
`services/fusion/app/services/detection_matcher.py`.

## Rule files and loading

Fusion scans no YAML folders. Native YAML under `detections/<category>/` is
generated from `scripts/detection_specs*.py` via
`scripts/generate_detections.py`. The generator and
`scripts/export_detection_ruleset.py` share
`detections/rule-ids.lock.json` to keep native rule IDs stable. The exporter
writes the runtime `services/fusion/app/data/detection_ruleset.json`. The
separate `scripts/compile_sigma_ruleset.py` compiles imported Sigma rules to
`detection_ruleset_imported.json`. Stateful rules have separate artifacts
loaded by `services/fusion/app/services/windowed_detection.py`.

For example,
`detections/threat-anomaly/ta-okta-rare-action-on-identity-provider.yaml`
uses metadata such as `id`, `severity`, `category`, and `log_source`,
plus a `detection.condition` containing
`event_type STARTSWITH "system.idp"` and `baseline_action_rarity >= 0.95`.
The stateless runtime schema uses a JSON object with a `rules` list. A rule
has `id`, `name`, `severity`, `category`, and `match_when`, for example
`{"ml_anomaly_score_gte": 0.9}`. The matcher also supports compound clauses
via `all_of` and `any_of`. The runtime evaluates every rule present in the
JSON corpus, so omit disabled rules from the artifact. The disabled spike
YAML in `detections/community/hf-ml/` records the intended rule.

`services/fusion/Dockerfile` copies `app/` into `/app/app/`. The base
Compose configuration has no rule mount. `services/fusion/app/main.py`
constructs the stateless engine at startup and its loader caches the corpus.
An image-based deployment needs a rebuild and container recreation to pick
up changed artifacts. A file already mounted or copied into the running
container's filesystem takes effect after a Fusion restart. Adding a mount
requires a Compose change and container recreation. The spike uses the
optional imported JSON inside the existing container.

Fusion evaluates rules independently of direct OCSF-to-alert promotion.
For the spike, a canonical envelope with `connector_type: auth0` selects
Authentication class 3002 and `severity: low` stays below the direct promotion
floor. An unknown custom connector type can fall back to Security Finding
class 2001, which is eligible for direct promotion even at low severity. This
could turn a low-scoring control into an unrelated alert. See
`services/ingest/internal/normalizer/ocsf_classes.go`,
`services/fusion/app/workers/consumer.py`, and
`services/fusion/app/services/promoter.py`. The Auth0 profile is a spike
fixture. A durable HF connector needs a deliberate classification choice.

## UEBA inputs

The full-profile UEBA service consumes `aisoc.raw_events` and publishes
`ueba.anomalies`. It decodes the normalized envelope and requires a tenant
UUID, an entity (user first, then host/device, then source IP), and at least one
numeric feature. Supply a stable `username`, an `event_type`, a timestamp,
and `outcome` on login records. UEBA can derive hour/day, a failure indicator,
severity ID when visible in the flat field map, and numerical features such as
byte and packet counts, durations, and sizes. It does not use the arbitrary
`ml_anomaly_score` field as a feature. The full profile is needed for the
built-in comparison. See `docker-compose.yml`,
`services/ueba/app/core/config.py`,
`services/ueba/app/services/feature_extraction.py`, and
`services/ueba/app/services/kafka_consumer.py`.

## Day 1 live spike

`make doctor` exited 0 with one warning (5 GB disk free) and no failures
when run with Docker socket access. Postgres, Redis, Kafka, ingest, Fusion,
and the API passed their checks.

The temporary compiled rule used
`{"spike_run_id": "spike-ml-score-test-6962e77d1f", "ml_anomaly_score_gte": 0.9}`.
The run ID constrained the rule to these two synthetic events. The alert
search returned zero before submission. Authenticated
`POST /v1/ingest/batch` returned HTTP 200, accepted 2, rejected 0, with
request ID `req-1795266286168781769`. Authenticated
`GET /api/v1/alerts?search=spike-ml-score-test-6962e77d1f` returned
HTTP 200 and one result, alert `238eedc4-809d-517e-b449-b11b0670c064`.
The high-score hostname query returned that same alert and the low-score
hostname query returned zero. The original imported ruleset was restored
and Fusion passed its health check after the second restart.

The request body was:

```json
{
  "connector_id": "hf-datasets",
  "connector_type": "auth0",
  "source_format": "json",
  "events": [
    {
      "source": "hf-datasets",
      "external_id": "spike-ml-score-test-6962e77d1f-high",
      "hostname": "spike-ml-score-test-6962e77d1f-high",
      "severity": "low",
      "title": "spike-ml-score-test-6962e77d1f-high",
      "raw_event": {
        "spike_run_id": "spike-ml-score-test-6962e77d1f",
        "ml_anomaly_score": 0.99
      }
    },
    {
      "source": "hf-datasets",
      "external_id": "spike-ml-score-test-6962e77d1f-low",
      "hostname": "spike-ml-score-test-6962e77d1f-low",
      "severity": "low",
      "title": "spike-ml-score-test-6962e77d1f-low",
      "raw_event": {
        "spike_run_id": "spike-ml-score-test-6962e77d1f",
        "ml_anomaly_score": 0.1
      }
    }
  ]
}
```

Use fresh external IDs and a fresh rule scope for a new spike run.

## Gap found

Rules created via `POST /api/v1/rules` are stored for the tenant and can
execute on demand via `POST /api/v1/rules/{id}/execute`.
The streaming engine gets candidates from its compiled corpus. The tenant
overlay SQL reads status, suppression configuration and severity floors
for tuning, and never reads `rule_body`.
See `services/api/app/api/v1/endpoints/detection_rules.py`,
`services/fusion/app/services/tenant_overlay.py`, and
`services/fusion/app/services/detection_engine.py`.

Day 2 control `spike-api-ml-score-9d392a4869` was created with HTTP 201 and
activated with HTTP 200. On-demand execution matched only the 0.99 score.
Batch request `req-1795266960327557933` accepted both the 0.99 and 0.1 events
using the original spike's `auth0` profile. The alerts API returned zero for
both hosts across six polls over 30 seconds. Fusion's consumer group caught
up to offset 6 with zero lag on `aisoc.raw_events`. Deleting the temporary API
rule returned 204, and a subsequent read returned 404.

## Day 2 native rule and local deployment

The repository spec in `scripts/detection_specs_index.py` generates
`detections/hf-ml/spike-ml-score-control.yaml` and rule `det-hf-ml-001`.
It requires the synthetic-only marker `hf_test_fixture: day2-score-control`
and a score of at least 0.9. The dataset mappers emit neither field.

For a normal deployment, regenerate both artifacts and build the images:

```bash
python3 scripts/generate_detections.py
python3 scripts/export_detection_ruleset.py
docker compose build ingest-worker fusion
docker compose up -d --no-deps --force-recreate --pull never ingest-worker fusion
```

The Day 2 ingest build succeeded. Fusion's build failed after repeated PyPI
timeouts while fetching Poetry. This Codespace uses the existing Fusion
image and a read-only mount of a merged imported ruleset. The merge takes
the control rule from the native exporter output and preserves the 1,770
rules in the existing imported corpus. The local mount survives recreation.

When setting up this fallback, copy the image's
`/app/app/data/detection_ruleset_imported.json` from an unmodified Fusion
container. Merge the exported control into the copied file by ID and update
its `count`. Save the result locally as
`contrib/hf-ml-detections/data/fusion-imported-local.json`. Add the following
under the existing `services` key in the local Compose override, then recreate
Fusion:

```yaml
  fusion:
    volumes:
      - ./contrib/hf-ml-detections/data/fusion-imported-local.json:/app/app/data/detection_ruleset_imported.json:ro
```

When deploying a rebuilt Fusion image containing the native rule, remove
the local mount before recreating Fusion so that the rule loads once.

After recreation, request `req-1795267650420090044` with
`connector_type: hf_auth` accepted both controls. The alerts API returned
one alert for the 0.99 control (`197f147c-95d1-5750-9895-d1498c942996`,
**HF ML score spike control**) and zero for the 0.1 hostname.
`make smoke` then passed 10/10 stages (run `dbad973859f4`).

### Dataset verification

The ingest CLI reports the sum of the batch API's accepted and rejected
counts. For each dataset, compare the authenticated alerts API before the
push and after Fusion has committed through the last Kafka offset. The
synthetic rule's marker is absent in the dataset payloads. The Kafka stream
also exposes the normalized events on CORE, where the optional event lake
is disabled. The verifier checks unique event IDs, connector provenance,
class, and severity across the complete ingest window.

Advanced SIEM accepted 5,000 and rejected 0. Kafka offsets 9 through 5,008
contained 5,000 distinct IDs, all in class 4001 with severity ID 2. Fusion
caught up at offset 5,009 with zero lag. The alerts API returned five alerts
before and after the run, a delta of zero.

Precinct6 accepted 5,000 and rejected 0. Kafka offsets 5,009 through 10,008
contained 5,000 distinct IDs, including 769 Authentication (3002) and
4,231 Network Activity (4001). All had severity ID 2. Fusion caught up at
offset 10,009 with zero lag. The alerts API again returned five alerts before
and after, with the same alert IDs.

Both datasets were verified on the Kafka consumer interface because
`GET /api/v1/lake/schema` returned HTTP 502 for the unavailable ClickHouse
backend on this CORE deployment.

The reviewer can open the synthetic control in the signed-in console at
`/alerts/197f147c-95d1-5750-9895-d1498c942996`. Its title is **HF ML score
spike control**, and its source type is `hf_auth`.
