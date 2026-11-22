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
