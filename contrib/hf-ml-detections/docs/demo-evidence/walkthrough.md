# Patator rehearsal evidence

The [full terminal output](patator.txt) is from
`./demo/run_demo.sh patator --source cache` in a clean shell without
`AISOC_*` overrides. [Preflight](preflight.txt) ended with
`READY FOR DEMO`. Run `f58c4421387c` took **113.2 seconds**, scored
**100,085** flows, sent **720** telemetry events, and confirmed **15/15**
alerts, including **12 High** alerts. All alert IDs are in the transcript
footer.

## High · SSH-Patator

Open `http://127.0.0.1:3000/alerts/5611fb1b-aa56-5e51-ac89-2b9925fd61d0`.
The console shows **High** severity for source `172.16.0.1`. The raw
event has these exact values:

| Field | Value |
|---|---|
| Severity | `high` |
| `raw_event.corroborated_by` | `uc1b` |
| `raw_event.top_reasons` | `auth_port_flows 102 vs baseline 0 (z=102.00); flows 102 vs baseline 1 (z=101.00); short_flow_share 0.49 vs baseline 0 (z=9.80)` |
| `raw_event.flow_count` | `479` |
| `raw_event.ml_entity_score` | `102` |

The confidence badge was **Medium Confidence**, score **45/100**. In
**Detection Confidence → Why this score**, the factors include High
severity, ML priority rank `0.90`, ML anomaly score `0.15`, and no
threat-intel match. **Verdict & feedback** had no verdict at capture time.
The local label check found all 479 source-window flows marked SSH-Patator.
Those labels were never sent to AiSOC.

## Medium · benign traffic increase

Open `http://127.0.0.1:3000/alerts/a4c70ab0-47ba-577c-a495-de780dbf19fa`.
The console shows **Medium** severity for source `54.192.37.234`.

| Field | Value |
|---|---|
| Severity | `medium` |
| `raw_event.corroborated_by` | `none` |
| `raw_event.top_reasons` | `flows 13 vs baseline 1 (z=12.00); distinct_dst_ports 8 vs baseline 1 (z=7.00); distinct_dst_ips 1 vs baseline 1 (z=0.00)` |
| `raw_event.flow_count` | `47` |
| `raw_event.ml_entity_score` | `12` |

The confidence badge was **Low Confidence**, score **25/100**. The local
label check found all 47 source-window flows marked benign. UC3 detected
a change in rate and port diversity. Without UC1b corroboration that
window stays Medium, and it counts as a false alert in evaluation.

## Recorded verdict

Open `http://127.0.0.1:3000/alerts/f5988a70-d1fd-5222-bf04-8e6c6af84ea9`
and show **Verdict & feedback**. This earlier High Patator alert has the
deterministic verdict `needs_review`. Its raw corroboration value is
`uc1b` and its raw explanation is
`auth_port_flows 102 vs baseline 0 (z=102.00); flows 102 vs baseline 1 (z=101.00); short_flow_share 0.49 vs baseline 0 (z=9.80)`.

## Local investigation timing

A short warm-up prompt to the existing local
`llama3.2:3b-instruct-q4_K_M` model did not return within 40 seconds.
The same two API calls used by **Start AI investigation** created case
`4dd0ba81-f80b-4244-b7dc-d365cc7c8cef` from the recorded Patator alert
and launched run `f62829a2-65f1-4fb1-b6c2-2b82a22ba893`. There was no
report after 123.0 seconds of polling. The Agents log then recorded
`investigation.budget_timeout` at its 120-second budget and closed the
ledger run as `failed`, with zero completed model calls recorded.
The console path therefore uses **Verdict & feedback** and **Detection
Confidence** during the live demo.
