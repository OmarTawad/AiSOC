# Detection evaluation

## UC1 — Precinct6 shortcut audit

UC1 reproduced WitFoo's automated correlation verdicts on a narrow held-out
cohort. The action-and-port heuristic reached **AP 0.9953** versus **1.0000**
for XGBoost. Tree SHAP ranked `action=block` first. Both organization
holdouts with malicious examples had **zero recall** at their independently
chosen thresholds. The full VPC stream had **zero benign**, **15,063
suspicious**, and **4,156 malicious** rows.

The Day 3 replay matched **28,510 of 29,768** flows (95.77%) and produced
668 distinct alerts. The representative labels were 181 malicious and 487
suspicious (72.9%). This volume made the threshold unsuitable for deployment.
The apparent 100% precision among binary-labeled representatives excluded
suspicious rows and used automated labels.

Retraining without action, source port, or destination port on the same
source-agnostic splits still yielded pooled AP **1.0000** and recall
**99.70%**. The two positive-support organization holdouts still had zero
recall, with AP **0.0017** and **0.9852**. The latter matches its almost
all-positive base rate. Removing the explicit inputs left other proxies such
as sanitized message tokens and aggregate flow patterns available.

Together the evidence indicates that the labels largely encode firewall
decisions and source or organization context. It supports an audit of
WitFoo's verdicts rather than a claim that the classifier learned attack
behavior. A deployable evaluation would need independently analyst-verified
positives and negatives, representative benign traffic within each source,
a prospective organization holdout, and per-organization calibration
against explicit alert budgets.

The original chronological result and family metrics are in
[metrics.json](../ml/uc1_xgboost/metrics.json). The
[ablation](../ml/uc1_xgboost/shortcut-audit.json) and
[SHAP plot](../ml/uc1_xgboost/shap-top15.png) preserve the audit evidence.

Rule `det-hf-ml-002` is disabled in the generated YAML and removed from the
compiled and mounted corpora. After Fusion restarted, three fresh
above-threshold events were accepted with zero rejections (request
`req-1795356667957118960`). Fusion reached zero Kafka lag at offset 39,783.
The alerts API count remained **668 → 668**. The historical reviewer alert
is still available at `/alerts/7c097e38-45b0-5129-bb5d-2def4aa5425b`.

## UC1b — CIC-IDS2017 supervised evaluation

The primary generalization result is leave-one-attack-family-out. This
experiment uses a fixed, separately stratified split by day and original
label. The held family is excluded from fitting and threshold selection.
Each held test compares that family with the same benign reference flows.
The separate chronological run trains Monday through Wednesday, validates
Thursday, and tests Friday. All original Friday attack labels (Bot, DDoS,
PortScan) are absent from training. Wednesday does contain related
non-distributed DoS examples. Friday is an unseen-label test with a day
shift. The [label-by-day census](datasets.md#cic-ids2017-flow-subset)
describes the overlap.

The projected sample had 78,183 rows and no NaN or infinite numeric inputs.
Cleanup discarded 6,707 rows with conflicting labels on identical feature
vectors and 8,051 repeated vectors, leaving 63,425 rows. This is a
conservative feature-equivalence test. Some repeated observations may be
legitimate distinct flows.

The simple heuristic scores unusually high flow duration, byte rate, or
packet rate against benign training quantiles. Logistic regression uses
log-transformed features with training-only imputation and robust scaling.
XGBoost uses the same 25 numeric flow statistics. For all three, the
threshold maximizes validation F1 subject to at most 300 alerts per 10,000
validation flows.

### Chronological unseen-label test

| Model | AP | Precision | Recall | F1 | Alerts per 10k | TN / FP / FN / TP |
|---|---:|---:|---:|---:|---:|---|
| Heuristic | 0.3087 | 0.0682 | 0.0027 | 0.0052 | 136 | 8,356 / 164 / 4,452 / 12 |
| Logistic regression | 0.7903 | 0.8542 | 0.5589 | 0.6757 | 2,250 | 8,094 / 426 / 1,969 / 2,495 |
| XGBoost | 0.8636 | 0.8703 | 0.6163 | 0.7216 | 2,435 | 8,110 / 410 / 1,713 / 2,751 |

At the selected threshold of 0.0660742, XGBoost's recall was 74.59% on
DDoS, 40.28% on Bot, and 7.36% on PortScan.

### Leave-one-family-out

| Held family | Attack rows | Heuristic AP / recall | Logistic AP / recall | XGBoost AP / recall |
|---|---:|---:|---:|---:|
| DoS, DDoS and Heartbleed | 2,804 | 0.3740 / 0.96% | 0.2058 / 0% | 0.5267 / 0% |
| PortScan | 46 | 0.0100 / 6.52% | 0.0626 / 6.52% | 0.0229 / 0% |
| FTP and SSH Patator | 787 | 0.0987 / 0.13% | 0.0928 / 0% | 0.2486 / 0% |
| Web attacks | 402 | 0.0461 / 0% | 0.4592 / 0% | 0.2957 / 0% |

XGBoost emitted zero alerts on each held-family test at its
validation-selected threshold. AP shows some ranking signal, but the
operating point did not generalize. PortScan's surviving test support
was particularly small after duplicate cleanup.

![Mean absolute Tree SHAP values for the top 15 CIC-IDS2017 features](../ml/uc1b_xgboost_cicids/shap-top15.png)

The scorer can attach the three largest per-flow Tree SHAP contributions.
The deployment preview used the exact benign-majority Friday replay set of
12,984 flows (8,520 benign). There were **3,161 expected alerts (24.35%)**,
including 410 benign flows and 2,751 attack-labeled flows, versus the 5%
deployment ceiling. The benign-only false-positive rate was 4.81%, a
different denominator from the all-flow deployment gate. The Thursday
alert rate had been 2.98%. This is a measured workload shift across days.
The Friday labels were not used to retune the threshold.

**Original deployment decision.** The total-volume gate stopped the CIC
replay. The subsequent benign-FPR protocol below supersedes that gate.

[Model metrics](../ml/uc1b_xgboost_cicids/metrics.json) ·
[Deployment preflight](../ml/uc1b_xgboost_cicids/deployment-check.json)

From the contribution directory, use the existing project venv to reproduce
the sample and local evaluation:

```bash
.venv/bin/python ml/cicids/source.py census
.venv/bin/python ml/cicids/source.py sample
.venv/bin/python ml/uc1b_xgboost_cicids/train.py
.venv/bin/python ml/uc1b_xgboost_cicids/score.py
```

Model files and samples stay under the ignored `data/` directory.

### Benign-FPR protocol

The 24.35% replay result above used the original total-volume gate. The
revised experiment uses a fixed 1% validation benign FPR and a 2% Friday
benign FPR deployment gate. Before evaluating Friday, each model uses the
highest-attainable benign firing rate at or below 1% on validation. A score
tie that would cross the cap is excluded as a group. Thresholds are saved
before test scoring. The Friday cohort, training dates and numeric feature
allowlist stay fixed. Friday was previously inspected under the older
total-volume protocol, so the new measurement is a frozen-threshold
reanalysis of a known benchmark, not a new independent holdout.

For the family comparison, the existing separate stratified folds hold the
same test examples fixed for all models. The all-family XGBoost reference
can see each family in training. Each leave-one-family-out XGBoost excludes
that family from development. Isolation Forest fits only benign training
examples, using signed log transforms and benign-training median imputation.
That model uses 160 trees, seed 42, and no attack-labeled fitting or threshold
selection. Feature deviations from benign medians describe unusual inputs,
rather than decomposing the Isolation Forest score.

### Friday at the frozen benign-FPR thresholds

Isolation Forest used 25,677 benign flows from Monday through Wednesday.
Both models froze thresholds using 7,742 benign Thursday flows. Each
flagged 77, for a validation benign FPR of 0.995%. The Friday cohort
contained 8,520 benign and 4,464 attack-labeled flows.

| Model | Threshold | AP | Precision | Recall | F1 | Friday benign FPR | Alerts / 10k total | False alerts / 10k benign | TN / FP / FN / TP |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| XGBoost | 0.18090591 | 0.8636 | 89.64% | 43.59% | 0.5866 | 2.64% | 1,672 | 264 | 8,295 / 225 / 2,518 / 1,946 |
| Isolation Forest | 1.62411013 | 0.5480 | 3.64% | 0.52% | 0.0090 | 7.15% | 487 | 715 | 7,911 / 609 / 4,441 / 23 |

| Friday attack family | Rows | XGBoost recall | Isolation Forest recall |
|---|---:|---:|---:|
| Bot | 1,234 | 0.00% | 0.89% |
| DDoS | 2,999 | 64.49% | 0.30% |
| PortScan | 231 | 5.19% | 1.30% |

Both models exceeded the 2% Friday benign-FPR deployment gate. The rate
increased by 1.65 percentage points for XGBoost and 6.15 points for
Isolation Forest. Isolation Forest ranked attacks above benign flows
more often than chance overall, but its validation operating point mostly
flagged benign Friday flows. Neither threshold was adjusted after testing.
Rules `det-hf-ml-003` and `det-hf-ml-004` were not deployed, and neither
model sent CIC flow events. There are no new live alert IDs.

### Matched family-generalization comparison

Each row uses the same attack examples and 8,387 benign reference flows
across all three columns. Thresholds come from the benign portion of the
separate stratified validation fold. Isolation Forest trained on 25,165
benign flows in that fold's training partition.

| Test family | Attack rows | XGBoost with all families | XGBoost with this family held out | Isolation Forest |
|---|---:|---:|---:|---:|
| DoS, DDoS, Heartbleed | 2,804 | 97.11% | 7.42% | 14.51% |
| PortScan | 46 | 82.61% | 6.52% | 0.00% |
| FTP and SSH Patator | 787 | 99.36% | 0.00% | 0.00% |
| Web attacks | 402 | 95.02% | 1.49% | 0.00% |

Isolation Forest caught more unseen DoS-family examples than supervised
XGBoost in this comparison, but detected none of the other held families
at its frozen threshold. The large gap from the all-family reference shows
how a split that lets the supervised model see each attack family can
overstate coverage of novel attacks.

The [XGBoost metrics](../ml/uc1b_xgboost_cicids/metrics.json) and
[Isolation Forest metrics](../ml/uc2_iforest_cicids/metrics.json) retain the
exact calibration records. Run `.venv/bin/python ml/cicids/benign_fpr.py` once
after training the original chronological XGBoost model. The live scoring
entry points reuse the cached Friday scores. Their send checks prohibit a
replay when the recorded Friday FPR fails the gate.

## Day 5 — CIC-IDS2017 entity windows

The [preregistration](../ml/uc3_behaviour_cicids/prereg.json) was committed
as `a007ad0b` before any Friday entity results. Friday had already been
examined at flow level. The chronological UC1b and UC2 scores retain their
exact Day 4 thresholds. The three-hit, source-IP, five-minute aggregation
is the new test. The offline comparison counts an alert as false when its
source window contains no attack-labeled flow.

The projected scan processed all 2,827,677 source rows in batches of at
most 32,768. It kept repeated flows, which can contribute to volume
signals. No row was missing a parseable clock or source. The compact
window artifact was 612 KiB and remains under the ignored `data/`
directory. The nominal five-minute buckets are approximate because the
clock validation failed. Friday had no corrected row-order backsteps, but
the earlier days did and Tuesday SSH-Patator missed the schedule criterion.
The [dataset clock audit](datasets.md#day-5-clock-validation) gives the
day-by-day measurements and schedule source.

### Alerts per capture day

Each alert represents one source IP in one five-minute bucket.
UC3 and UEBA also ran on Thursday to give a same-day comparison.

| Day | Detector | Alerts | False alerts | Precision | Malicious windows detected |
|---|---|---:|---:|---:|---:|
| Tue | UC3 robust baseline | 299 | 273 | 8.70% | 26/29 (89.66%) |
| Tue | UEBA-equivalent | 1,501 | 1,497 | 0.27% | 4/29 (13.79%) |
| Wed | UC3 robust baseline | 204 | 183 | 10.29% | 21/27 (77.78%) |
| Wed | UEBA-equivalent | 1,646 | 1,628 | 1.09% | 18/27 (66.67%) |
| Thu | UC1b XGBoost | 611 | 597 | 2.29% | 14/31 (45.16%) |
| Thu | UC2 Isolation Forest | 351 | 337 | 3.99% | 14/31 (45.16%) |
| Thu | UC3 robust baseline | 167 | 140 | 16.17% | 27/31 (87.10%) |
| Thu | UEBA-equivalent | 1,636 | 1,625 | 0.67% | 11/31 (35.48%) |
| Fri | UC1b XGBoost | 575 | 536 | 6.78% | 39/197 (19.80%) |
| Fri | UC2 Isolation Forest | 367 | 321 | 12.53% | 46/197 (23.35%) |
| Fri | UC3 robust baseline | 165 | 129 | 21.82% | 36/197 (18.27%) |
| Fri | UEBA-equivalent | 1,566 | 1,511 | 3.51% | 55/197 (27.92%) |

| Full-stream attack family | Windows | UC1b recall | UC2 recall | UC3 recall | UEBA-equivalent recall |
|---|---:|---:|---:|---:|---:|
| Tue Patator | 29 | — | — | 89.66% | 13.79% |
| Wed DoS and Heartbleed | 27 | — | — | 77.78% | 66.67% |
| Thu web attacks | 16 | 18.75% | 0.00% | 93.75% | 0.00% |
| Thu infiltration | 15 | 73.33% | 93.33% | 80.00% | 73.33% |
| Fri Bot | 179 | 13.41% | 21.79% | 11.73% | 26.82% |
| Fri DDoS | 6 | 100.00% | 83.33% | 100.00% | 33.33% |
| Fri PortScan | 12 | 75.00% | 16.67% | 75.00% | 41.67% |

### Matched source-window holdouts

The diagnostic models used the fixed flow sample and source-window hash
partitions. Entire test source-windows were excluded from model development.
All-family and family-excluded XGBoost models used identical test windows.
The matched Isolation Forest likewise fit only benign development flows
from the same partition and calibrated on benign validation. It is
separate from the frozen chronological deployment candidate. UC3 and
UEBA use their original causal baselines. Small family denominators make
some of the percentages sensitive to a single window.

| Attack family | Matched test windows | UC1b all families | UC1b family held out | UC2 matched | UC3 | UEBA-equivalent |
|---|---:|---:|---:|---:|---:|---:|
| Bot | 39 | 94.87% | 5.13% | 12.82% | 7.69% | 23.08% |
| DoS, DDoS and Heartbleed | 6 | 100.00% | 16.67% | 83.33% | 83.33% | 66.67% |
| Infiltration | 3 | 66.67% | 66.67% | 100.00% | 100.00% | 100.00% |
| Patator | 10 | 100.00% | 0.00% | 0.00% | 80.00% | 20.00% |
| PortScan | 3 | 66.67% | 33.33% | 0.00% | 100.00% | 33.33% |
| Web attacks | 1 | 100.00% | 0.00% | 0.00% | 100.00% | 0.00% |

| False alerts in matched test windows | Tue | Wed | Thu | Fri |
|---|---:|---:|---:|---:|
| UC1b all families | 88 | 49 | 43 | 79 |
| UC1b family held out, range across six fits | 65–92 | 46–63 | 40–48 | 43–91 |
| UC2 matched | 105 | 91 | 82 | 86 |
| UC3 | 43 | 37 | 30 | 28 |
| UEBA-equivalent | 309 | 350 | 318 | 318 |

### Behaviour and deployment

UC3 fits frozen Monday medians and scaled MADs on five active-minute
features, with minimum scales for zero-MAD inputs. Monday contributed
45,617 active source-minutes from 8,234 sources. Pooled Monday baselines
scored 29,102 later minutes from sources absent on Monday. An example
PortScan-labeled bucket exceeded the threshold on short-flow share
(0.50 vs a baseline of 0.00, z=10). This is an explanation of the feature
deviation recorded for that bucket, not a live alert.

The offline UEBA reference matches the service's per-entity Welford
accumulation, minimum of 30 observations, omission of zero-variance
features, absolute sample-standard-deviation z-scores, root-sum-of-squares
capped at 10, threshold of 3, and score-before-update order. It feeds the
same five constructed minute features. Peer-group blending and service
transport are outside this comparison. The full AiSOC profile stayed off.
See `services/ueba/app/services/baseline.py` and
`services/ueba/app/services/scoring.py`.

**No detector qualified.** Each candidate exceeded 25 false Friday
alerts and had precision below 50%. The clock check independently blocks
deployment. No rules 003–005 were installed, and no summary events or
new console alert IDs were generated.

[Entity metrics and family details](../ml/uc3_behaviour_cicids/metrics.json)

To reproduce with the existing CIC model artifacts, run
`.venv/bin/python ml/uc3_behaviour_cicids/clock.py` first, then
`.venv/bin/python ml/uc3_behaviour_cicids/evaluate.py` from the contribution
directory. Both commands use remote parquet range reads.

## Final entity operating-point re-test

**Friday was examined in earlier rounds; this is a pre-registered re-test,
weaker evidence than a fresh day.**

Tuning used only Monday through Thursday. Monday supplied the source
allowlist ranks. The grid used top 0, 5, 10, or 25 sources by total observed
Monday benign flow volume, with ties resolved by source string. The chosen
25 ranged from 515 to 67,769 flows. These are volume-based exclusions.
The capture does not establish that they are DNS servers, domain
controllers, or gateways. The [frozen configuration](../ml/uc3_behaviour_cicids/prereg_v2.json)
records source hashes, Monday counts, and the reason for each entry.

The UC3 grid compared the existing two-minute trigger with three-minute
triggers and floors of 1, 5, or 10 flows in each qualifying minute.
Each setting was also tested with same-source UC1b-or-UC2 confirmation in
the same or an adjacent five-minute bucket on Thursday. Using the following
bucket would require waiting one extra bucket before emitting a confirmed
alert. Flow scores were available for Thursday within the tuning period.
Tuesday and Wednesday are additional UC3-only evidence. Thursday was the
common ranking cohort. Numeric gate pass took priority, followed by excess
false alerts, macro family recall, false alerts, and precision. The
[full tuning table](../ml/uc3_behaviour_cicids/tuning_v2.json) records all 40
candidates, including per-family counts.

| Development day | Configuration | False alerts | Precision | Malicious windows detected |
|---|---|---:|---:|---|
| Tue | UC3 original | 273 | 8.70% | Patator 26/29 |
| Tue | UC3 selected | 26 | 50.00% | Patator 26/29 |
| Wed | UC3 original | 183 | 10.29% | DoS 21/27 |
| Wed | UC3 selected | 24 | 44.19% | DoS 19/27 |
| Thu | UC1b original | 597 | 2.29% | Infiltration 11/15, web 3/16 |
| Thu | UC1b selected | 238 | 1.24% | Infiltration 0/15, web 3/16 |
| Thu | UC2 original | 337 | 3.99% | Infiltration 14/15, web 0/16 |
| Thu | UC2 selected | 62 | 0.00% | Infiltration 0/15, web 0/16 |
| Thu | UC3 original | 140 | 16.17% | Infiltration 12/15, web 15/16 |
| Thu | UC3 selected | 10 | 60.00% | Infiltration 0/15, web 15/16 |
| Thu | UC3 selected settings plus confirmation | 5 | 50.00% | Infiltration 0/15, web 5/16 |

### Frozen choices and single Friday re-test

Commit `62cbfa88` froze the exact `prereg_v2.json` before the Friday
command opened the Friday cohort. UC1b and UC2 retained their three-hit
five-minute rules and original model thresholds, adding only Monday's
top-25 exclusion. UC3 used that same exclusion, score ≥6, and at least
three consecutive qualifying minutes with ≥5 flows in each minute.
It did not require flow confirmation.

| Frozen detector | Friday alerts | False alerts | Precision | Recall | Numeric gate |
|---|---:|---:|---:|---:|---|
| UC1b | 216 | 202 | 6.48% | 14/197 (7.11%) | Fail |
| UC2 | 70 | 64 | 8.57% | 6/197 (3.05%) | Fail |
| UC3 | 25 | 9 | 64.00% | 16/197 (8.12%) | Pass |

UC3 detected 6/179 Bot, 5/6 DDoS and 5/12 PortScan windows. The selected
configuration reduced its false-alert count from 129 to 9 and reduced
malicious-window detections from 36 to 16. The numeric pass shows the
workload tradeoff on this replay. Clock validation remains failed under
the unchanged preregistration, so the nominal windows remain approximate
and no production rule was deployed. UC3 is the strongest operating point
for a demo. [Friday output](../ml/uc3_behaviour_cicids/friday_v2.json)

## Day 6 — Roles and controlled replay

The committed v2 thresholds, score models and Monday allowlist were
unchanged. UC3 is the sole HF alerting detector. The existing synthetic
control and Precinct6 rule are retired. The active Medium tier
`det-hf-ml-005` requires the exact `corroborated_by: none` value, and the
High tier `det-hf-ml-005-hi` requires `corroborated_by: uc1b`. Both require
the controlled-demo marker. This keeps the working demonstration separate
from production deployment while the capture clock remains unvalidated.
A source's unique summary ID is also used as its replay host identifier
so Fusion's alert deduplication preserves one row per source-window.

### Allowlist audit

The [25-source audit](../reports/allowlist-audit.md) lists each address,
Monday volume, distinct peers by direction, and the highest-volume
inbound service ports. The published DNS and domain controller is on the
list, along with lab workstations and server-like sources. The two
published firewall addresses (`172.16.0.1` and `205.174.165.80`),
`172.16.0.11`, and the named external attacker addresses are absent.
**`192.168.10.8` is on the list.** The lab used that workstation as a
simulated lateral-movement source on Thursday. Monday's benign label
cannot guarantee that a source remains benign on later days.
[UNB capture topology](https://www.unb.ca/cic/datasets/ids-2017.html)

Applying the frozen UC3 persistence and volume conditions, these attack
windows were suppressed solely by the allowlist:

| Attack family | Tue | Wed | Thu | Fri |
|---|---:|---:|---:|---:|
| Patator | 0 | 0 | 0 | 0 |
| DoS / DDoS / Heartbleed | 0 | 0 | 0 | 1 |
| Web attacks | 0 | 0 | 0 | 0 |
| Infiltration | 0 | 0 | 10 | 0 |
| Bot | 0 | 0 | 0 | 6 |
| PortScan | 0 | 0 | 0 | 0 |

### Corroboration and hunting

UC1b failed its standalone workload gate. Its frozen three-hit,
five-minute window test adds a High severity tier only if the same
source also has a UC3 alert in that bucket or an adjacent bucket.
The High summary carries the note “matches a known-attack model”.
Using the following bucket requires one additional bucket of latency.

| Friday UC3 alerts | Total | Attack-labeled | Benign-labeled | Precision |
|---|---:|---:|---:|---:|
| UC1b-corroborated | 11 | 10 | 1 | 90.91% |
| Uncorroborated | 14 | 6 | 8 | 42.86% |

UC2 also failed its standalone gate and produces a daily hunting report.
Each source is ranked by its maximum frozen Isolation Forest flow score
on that day. The explanation gives the three largest deviations from
benign training medians for that flow. A source counts as attack-labeled
if any source flow on that capture day carries an attack label. Monday
through Wednesday are descriptive on days used for model development.

| Capture day | Attack-labeled sources in top 20 | Report |
|---|---:|---|
| Monday | 0 | [Markdown](../reports/hunting_2017-07-03.md) · [CSV](../reports/hunting_2017-07-03.csv) |
| Tuesday | 0 | [Markdown](../reports/hunting_2017-07-04.md) · [CSV](../reports/hunting_2017-07-04.csv) |
| Wednesday | 1 | [Markdown](../reports/hunting_2017-07-05.md) · [CSV](../reports/hunting_2017-07-05.csv) |
| Thursday | 2 | [Markdown](../reports/hunting_2017-07-06.md) · [CSV](../reports/hunting_2017-07-06.csv) |
| Friday | 9 | [Markdown](../reports/hunting_2017-07-07.md) · [CSV](../reports/hunting_2017-07-07.csv) |

### Replay evidence

The replay covers Tuesday 13:50–15:20 and Wednesday 09:20–11:35 in
approximate capture-clock buckets. Wednesday includes 27 minutes before
the published 09:47 start after rounding to a five-minute bucket.
The Tuesday/Wednesday severity booster applies the frozen UC1b scorer
descriptively on days used for training. The separate Friday booster
counts are the holdout result. The bucket start is carried as a replay
timestamp with an explicit approximate-clock, unverified-timezone note.

| Dry-run expectation | High attack | High benign | Medium attack | Medium benign |
|---|---:|---:|---:|---:|
| Tuesday, Patator slice | 13 | 0 | 0 | 4 |
| Wednesday, DoS slice | 17 | 1 | 0 | 3 |

Request `req-1795359191119506907` accepted all 38 summaries and rejected
none. Alert details reconciled 38 distinct summary IDs to 38 alerts
(31 High and 7 Medium). Both the outbound summaries and the persisted
raw alert payloads passed the label-field checks. The benchmark labels
remain in a separate local ledger, joined back after triage. No label
field reached AiSOC from these summaries.

### Native image check

The single native Fusion build was tried with 3.0 GB free and
`PIP_DEFAULT_TIMEOUT=120` passed explicitly to pip through a temporary
Dockerfile build argument. The build command reached its 240-second
overall cap after repeated PyPI TLS EOF errors while fetching Poetry.
The verified read-only mount remains active. No volume was pruned.

### Triage and console

AiSOC normally auto-triages from `aisoc.alerts.fused`. The ordinary
`aisoc-agents-triage` group was 28,505 messages behind when work resumed.
The targeted run reads the existing 38 fused messages by reconciled alert
ID and invokes the same worker. It does not POST summaries again, publish
another Kafka message, or reset a consumer offset. The fused message
payloads were also checked for ground-truth fields before being handed to
the worker. The label ledger was joined only afterward.

No `OPENAI_API_KEY` was configured. The configured local model was
`llama3.2:3b-instruct-q4_K_M`. The normal gateway path repeatedly reported
60-second local-model failures, and a short, direct health inference timed
out while the ordinary queue was active. To prioritize the demo,
`triage_demo.py --isolated` temporarily stops the ordinary consumer and
runs its triage code in a temporary Agents container. The targeted run
uses the same pinned Ollama model directly, with one attempt per model
request, a 192-token response ceiling, and the triage stage only. The
helper restores the ordinary consumer without changing its offsets.

The first isolated pass used 50-second model timeouts. A 15-second
follow-up processed only alerts with no stored verdict. The verdict
ledger reconciled all 38 alerts. Every verdict came from the deterministic
fallback. Ollama produced zero recorded verdicts, so this replay measures
the fallback and leaves LLM triage quality unverified.

| Local benchmark label | Alerts | Needs review | Likely benign | Auto-closed |
|---|---:|---:|---:|---:|
| Attack | 30 | 30 | 0 | 0 |
| Benign | 8 | 1 | 7 | 0 |

In the console, open Alerts and select Patator true positive
`f5988a70-d1fd-5222-bf04-8e6c6af84ea9`. **Verdict & feedback** shows
`needs_review`. **Raw Event Data** shows the ML explanation under
`raw_event.top_reasons`, including 102 auth-port flows versus a baseline
of zero (z=102). The boosted DoS true positive is
`6894ea8b-6918-5d6f-9096-3730231a3527` and a benign false positive is
`edb96e1b-e45e-50ce-b774-eef77c784dd4`.
