# CIC-IDS2017 live demo

## Before the audience joins

- Start AiSOC 15 minutes early. Confirm the Fusion ruleset contains both UC3 severity tiers and the Python environment can load the frozen UC1b model.
- Prepare the cached slices with `contrib/hf-ml-detections/demo/run_demo.sh --prepare`. The cache and reconstructed Monday baselines live under the gitignored `data/demo/`. Preparation checks the 1.5 GiB free-space floor and caps the combined cache at 100 MB. Mixed uses both cached slices without storing a second copy.
- Set `AISOC_INGEST_TOKEN` and `AISOC_API_TOKEN` in the demo shell. From the repository root, capture the tokens without echoing them:

  ```bash
  export AISOC_INGEST_TOKEN="$(make -s ingest-token ARGS=--quiet)"
  export AISOC_API_TOKEN="$(make -s api-token ARGS=--quiet)"
  ```

- Open the console Alerts page with **15m** selected. The replay shifts the last capture timestamp to the time playback starts while preserving flow spacing, so earlier replay events can fall outside a 15-minute **event time** filter. Open the direct URL printed by the replay or widen the picker to at least 4 hours for the Mixed list.
- Rehearse with the cache. Record a successful run showing the terminal and console together and keep the video available locally for the fallback.

## During the demo

Run from `contrib/hf-ml-detections`:

```bash
./demo/run_demo.sh patator --source cache
```

1. **Start the replay.** “These are CIC-IDS2017 flows captured during a lab exercise. The cached slice contains the same public dataset rows the Hugging Face mode reads. We score every flow as its capture minute is replayed, and send up to eight of those flows per minute as network telemetry.” The default pacing target is 0.2 real seconds per capture minute. Scoring, ingest, and API checks also contribute to runtime.
2. **Watch persistence build.** “The source has to exceed its Monday baseline for three consecutive minutes with at least five flows per minute. The pending message means we're checking the same or adjacent five-minute windows for XGBoost corroboration.” A summary is sent after the lookahead finishes. Each scenario command, including Mixed, sends at most 15 summaries. Mixed reserves seven for Patator and eight for DoS.
3. **Open a console link.** Prefer a High SSH-Patator alert with many auth-port flows. “UC3 raised the alert. XGBoost corroboration raised its severity.” In **Raw** / **Raw Event Data**, expand `raw_event.top_reasons` and point to the observed count, Monday baseline, and z-score. Use **Start AI investigation** to show the workflow. The local model timed out during Day 6, so continue the walkthrough if the investigation takes too long.
4. **Close on the summary.** Distinguish flows scored, telemetry accepted, and alerts confirmed by the API. The detector settings are frozen and the capture clock is approximate. Privately rerun with `--presenter-notes` to compare confirmed alerts with the dataset labels. Those labels stay in the replay process and never enter AiSOC.

Use `dos` for Wednesday's DoS slice, or `mixed` to play both slices consecutively. `patator --source hf` opens the pinned Hugging Face parquet and projects the required columns. The source has one row group, so the remote reader scans projected columns and retains only the requested slice. Allow about a minute for the remote read. Reduce `--telemetry-rate` if Fusion is already backlogged. Every flow is still scored. `--dry-run` scores and displays events without sending them. Ctrl+C stops playback and prints the totals collected so far.

## Verified rehearsal timings

These runs used the cache command above with each scenario and the defaults.

| Scenario | Wall time | Alerts confirmed |
|---|---:|---:|
| Patator | 112.0 s | 15/15 |
| DoS | 163.1 s | 15/15 |
| Mixed | 256.9 s | 15/15 |

## Fallback

If the Hugging Face read stalls, switch to the prepared cache. If local ingest, Fusion, or the console is unavailable, play the recorded rehearsal and identify it as a recording. Show the pending line, the console alert link, and the raw explanation.
