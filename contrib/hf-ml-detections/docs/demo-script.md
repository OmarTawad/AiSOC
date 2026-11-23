# Five-minute live demo

## Setup checklist

- Start the local stack 15 minutes early with `~/aisoc-start.sh`. The local recovery steps are in [Codespaces setup](codespaces-fixes.md).
- From `contrib/hf-ml-detections`, run `./demo/run_demo.sh --prepare` if the cache has not been built. Mixed shares the same cache. The cache and the frozen model stay local.
- Run `./demo/preflight.sh` and wait for `READY FOR DEMO`. Resolve any failures using the commands it prints. The wrapper mints missing ingest and API tokens quietly.
- Open the console **Alerts** page with **15m** selected. Keep this guide and the [evidence walkthrough](demo-evidence/walkthrough.md) open locally. The time picker filters event time, and replay keeps the relative capture times. Some earlier alerts will be outside the 15-minute view. Open the exact terminal link to find them.

## What to say and show

| Time | Action and talking point |
|---|---|
| 0:00–0:30 | Show the [architecture](../README.md#architecture) and the preflight result. “We score real CIC-IDS2017 lab flows and send live telemetry through the normal AiSOC ingest and Fusion path.” |
| 0:30–2:30 | Run the command below. “Every flow is scored. We send up to eight flows per replayed minute to bound ingestion load.” Point to `suspicious`, then `ALERT pending, checking XGBoost corroboration…`, then `ALERT`. “After three consecutive qualifying minutes, the detector checks the adjacent five-minute windows. If XGBoost agrees, severity becomes High.” |
| 2:30–3:30 | Show **Alerts**, then open the first High link printed by the terminal. In **Raw** / **Raw Event Data**, expand `raw_event.top_reasons` and `raw_event.corroborated_by`. “This host had 102 auth-port flows in a minute against a Monday baseline of zero. UC1b corroboration raised the severity.” |
| 3:30–4:05 | Open **Detection Confidence** in the alert overview and **Verdict & feedback** under the investigation tab. Discuss the confidence factors separately from the High severity. Fresh alerts may still have no verdict. Use the historical Patator alert from the evidence walkthrough to show the recorded fallback verdict. |
| 4:05–4:35 | Show the first Medium link. “This benign source had a real traffic increase and no XGBoost corroboration. The alert is an expected cost of monitoring behavioural changes. We report false alerts explicitly and keep this case visible for review.” |
| 4:35–5:00 | Close on the README's [per-family comparison](../README.md#matched-entity-window-comparison). “XGBoost recall falls on unseen families. Behavioural detection passed the numeric workload gate on the Friday re-test, with lower recall and an approximate clock.” |

Run from `contrib/hf-ml-detections`:

```bash
./demo/run_demo.sh patator --source cache
```

The pacing target is 0.2 real seconds per capture minute. Scoring,
ingest and API checks also contribute to runtime. The final clean-shell
Patator rehearsal took **113.2 seconds** and confirmed **15/15** alerts.
The earlier default rehearsals took 163.1 seconds for DoS and 256.9
seconds for Mixed. The alert cap is 15 per command. Mixed reserves seven
for Patator and eight for DoS. [Full terminal transcript](demo-evidence/patator.txt)

The local CPU-only 3B model did not return during the warm-up. The single
investigation reached the agent's 120-second budget and failed without a
report. Keep the live walkthrough on the verdict panel and confidence
breakdown. [Investigation evidence](demo-evidence/walkthrough.md#local-investigation-timing)

Use `--dry-run` for a rehearsal without pushes. Ctrl+C prints the totals
collected so far. The optional `--presenter-notes` summary uses benchmark
labels locally. Keep it off in front of the audience.

## If the live path fails

If preflight fails, show its fix list and move to the saved evidence
unless the repair is immediate. If the terminal or console fails,
open the [transcript](demo-evidence/patator.txt) and
[walkthrough](demo-evidence/walkthrough.md). Explain clearly that these
are from the prior clean rehearsal. Use the IDs and exact fields to
walk the same High and Medium examples. The transcript and walkthrough
are the fallback for this live-only presentation.
