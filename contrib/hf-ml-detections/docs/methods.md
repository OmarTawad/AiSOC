# UC1 — Supervised scoring on Precinct6

The target is malicious versus benign under the published WitFoo automated
correlation labels. Suspicious events are scored separately. They can
contribute to feature history as unlabeled telemetry. The scored examples
can reproduce parts of the correlation engine's judgment without measuring
analyst-confirmed attack detection.

## Inputs and leakage controls

| Input | Decision and rationale |
|---|---|
| Source port | Include because clients and services use different port ranges. |
| Destination port | Include because the destination service is available at event time. |
| Protocol | Include because it describes the observed transport in the event. |
| Action | Include the observed action as telemetry and audit it for source and label association. |
| Hour and weekday | Include because event time is available when a record arrives. |
| Source and destination internal-IP flags | Include broad private-address indicators and omit raw addresses from the model. |
| Username presence | Include a flag without retaining the username as a model input. |
| Sanitized message | Include binary presence in 512 hash buckets from the first 512 characters of the sanitized event message. Text can still proxy for the source. |
| Prior-hour source event count | Include observations from the preceding hour in the sample, excluding the current timestamp and all later events. Use the organization to scope identity when available. |
| Message type | Ablation only because categories can encode a source-specific labelling convention. |
| Stream name | Ablation only because the VPC stream may be nearly or entirely single-class. |
| Vendor and product | Ablation only because the sensor deployment may correlate with the labels. |
| Organization | Use only to scope history and define holdouts. Omit it from model inputs. |
| Matched rules | Exclude because they expose rule decisions made by the correlation engine. |
| Incident IDs | Exclude because incident membership reveals correlation output. |
| Suspicion score | Exclude because it summarizes the upstream judgment. |
| Disposition | Exclude because it records incident handling. |
| Disposition category | Exclude because it classifies the handling decision. |
| Lifecycle stage | Exclude because it reflects downstream investigation state. |
| False-positive flag | Exclude because it supplies an upstream correctness judgment. |
| Status name | Exclude because it describes upstream case state. |
| MO name | Exclude because it names the inferred modus operandi. |
| Label confidence | Exclude because it directly qualifies the target label. |
| ATT&CK techniques | Exclude because these are correlation annotations. |
| ATT&CK tactics | Exclude because these are correlation annotations. |
| Defense techniques | Exclude because these are upstream annotations. |
| Set roles | Exclude because these are inferred in the correlation context. |
| Row ID, artifact ID, raw address and username | Exclude because identifiers can memorize entities and dataset layout. |
| Severity, vendor code and other unlisted fields | Exclude from both models to keep inputs within the reviewed event-time feature list. |

## Evaluation protocol

Split the mapped, non-VPC binary evaluation cohort chronologically near
70%, 15%, and 15%, keeping equal timestamps within a single window. The
initial split on all sample rows left 26 headline test rows and no positives.
The cohort-based split changes the test time window and is exploratory. Fit feature preprocessing on training only.
Compare a heuristic using action and port with logistic regression and
XGBoost. Use validation scores to choose the strongest F1 subject to a
maximum validation alert rate equivalent to 500 alerts per 10,000 events at
0.38% prevalence. This ceiling gives every method the same workload limit
while allowing a comparison of detection coverage. It is an experiment
budget. Evaluate once on the held-out time window. Report raw
test precision and precision standardized to 3.86% and 0.38% from TPR and
FPR. The latter assumes only prevalence changes.

Exclude VPC from headline training and evaluation if the population scan
finds essentially no benign VPC records. Report VPC scores separately and
report authentication and other network metrics independently. In each organization holdout, fit preprocessing and the classifier on other
organizations in the training window, choose the threshold on other
organizations in validation, and score the held organization in the test
window. Some holdouts may lack class or time coverage. Keep same-time events
out of every event's rolling counts. Report unsupported metrics for
single-class strata as unavailable.
