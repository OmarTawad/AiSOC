# Active rules created via the rules API are skipped by streaming Fusion

## Summary

A tenant can create and activate a valid detection with the Rules API.
On-demand execution evaluates the rule body. Fusion's streaming path
does not add the API-created rule to its candidate corpus.

## Reproduction

1. On a local stack, use an authenticated tenant to create a rule via
   `POST /api/v1/rules`. Use a unique run marker and the Sigma body below. Send the YAML as the
   `rule_body` string with `rule_language: sigma`, `category: anomaly`,
   and a unique `name`. Activate the rule with
   `PATCH /api/v1/rules/{id}` and `{"status":"active"}`.
2. Run the rule via `POST /api/v1/rules/{id}/execute` with two controls
   carrying the same run marker and scores of `0.99` and `0.1`. Verify
   the first control matches and the second does not.
3. Send those controls through `POST /v1/ingest/batch` with fresh external
   IDs and low-severity telemetry. The original control used the
   `auth0` profile so neither event could be promoted as a finding.
4. Wait for Fusion to consume both events and look for alerts by their
   unique hostnames.

Example body for the two event controls:

```yaml
title: Streaming API positive control
logsource:
  category: network_connection
detection:
  selection:
    raw_event.spike_run_id: streaming-api-control-unique
    raw_event.ml_anomaly_score: 0.99
  condition: selection
```

Use the same unique marker in each control's `raw_event.spike_run_id`
and send each score as a number in `raw_event.ml_anomaly_score`.

## Expected

The streaming engine evaluates the active tenant rule against both
events. Only the high-score control creates an alert.

## Actual

The rule creation returned HTTP 201 and activation returned HTTP 200.
The on-demand execution matched only the high-score control. Both events
were accepted in `req-1795266960327557933`, and Fusion caught up through
the batch. The alerts API returned zero matches across six polls over
30 seconds. A separate compiled native rule later produced one alert
with the same score controls.

## Code and suggested fix

- `services/api/app/api/v1/endpoints/detection_rules.py` creates tenant
  rules and uses their bodies for on-demand execution.
- `services/fusion/app/services/tenant_overlay.py` loads tenant status,
  suppressions and severity floors for known rules. Its query does not
  select `rule_body`.
- `services/fusion/app/services/detection_engine.py` builds streaming
  candidates from the compiled corpus.

Validate and compile supported API rule bodies into a tenant-scoped
streaming candidate set. Refresh or invalidate the set on writes and
preserve existing suppression behavior. If a body can only execute on
demand, surface that restriction in the API and console. Add an
integration check that ingests a matching event and a negative control,
and confirms that another tenant cannot see or run the rule.
