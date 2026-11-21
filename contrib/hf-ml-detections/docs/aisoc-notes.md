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
