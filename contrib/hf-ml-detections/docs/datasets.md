# Datasets and ingest scope

## WitFoo Precinct6

[Precinct6](https://huggingface.co/datasets/witfoo/precinct6-cybersecurity)
is real SOC telemetry released under Apache-2.0. The repository contains
multiple configurations totaling about 8.4 GB. The sampler pins the source
revision and reads projected columns from its main `signals/signals.parquet`
file (117,056,748 bytes and 2,011,674 rows). The separate incident-linked
projection, graphs, and reports are outside this sample's population.

The sampler scans labels and event times before reading features. It keeps
every malicious row and uses seed 42 for sampling the other two classes by
UTC day of the published `timestamp`, with roughly half the remaining places allocated to suspicious
rows. The local JSON report records the population counts independently of
the enriched sample. Use population prevalence or a population-like test set
when reporting detection performance.

| Label | Full signals | Full share | Local sample | Sample share |
|---|---:|---:|---:|---:|
| Benign | 1,897,153 | 94.31% | 96,136 | 48.07% |
| Suspicious | 106,793 | 5.31% | 96,136 | 48.07% |
| Malicious | 7,728 | 0.38% | 7,728 | 3.86% |
| Total | 2,011,674 | 100% | 200,000 | 100% |

The full signal timestamps span 2024-07-26 11:10:23.729 UTC through
2024-08-01 06:00:03.240 UTC. The local sample spans 2024-07-26 11:10:23.729
UTC through 2024-08-01 05:59:24.076 UTC.

The published `timestamp` is based on the artifact time UUID and provides the
canonical UTC ingestion time. The optional vendor `event_time` is preserved
under `raw_event.hf_event_time`, with NaN encoded as JSON null.

The projected fields cover timestamps and row identity, normalized message
and stream names, vendor and product, network endpoints, hosts and users,
action, severity, and the available label and ATT&CK fields. Precinct6's
labels come from automated correlation. Label confidence and ATT&CK metadata
are retained for evaluation and are potential leakage if used to predict
their related targets.

### Event-family profile and mapping

Five 1,000-row slices came from the first, quarter, middle, three-quarter, and
last parquet row groups. The leading message types were `management_message`
(924), `security_audit_event` (764), `java_error` (601), and `firewall_action`
(349). The leading product and vendor values included AWS Instance Backup,
VMWare VCenter, Windows Logs, Windows Active Directory, ASA Firewall, Amazon
Web Services, VMWare, Microsoft, and Cisco. Product and vendor were blank
for 1,104 rows each. Action was blank for 4,007 rows. Observed action names
included `block` (349), `Filtering Platform Connection` (145), `Logon` (20),
`Logoff` (8), and `Credential Validation` (6).

| OCSF class | Included families |
|---|---|
| Authentication (`hf_auth`, 3002) | Explicit `auth_success`, `auth_failure`, `auth_event`, and `pam_event` message types, plus Windows security audit actions Logon, Logoff, Credential Validation, and Kerberos Authentication Service |
| Network Activity (`hf_network`, 4001) | `communication` on `network_communication`, `firewall_action` on `cisco_asa`, Windows Filtering Platform Connection, and `network_flow_data` on `aws_vpc_flow_log` |

The mapper skips unsupported families, including generic management,
diagnostic, and process records. These remain in the local sample.

## Advanced SIEM

[Advanced SIEM](https://huggingface.co/datasets/darkknight25/Advanced_SIEM_Dataset)
is MIT-licensed synthetic telemetry. The Hugging Face parquet conversion is
32,183,273 bytes. The local projection keeps all 100,000 rows and the fields
used for identity, timestamp, event family, severity, addresses, ports,
protocol, bytes, duration, `alert_type`, and `category`. Full data and
sample both span 2020-07-12 21:38:20 through 2030-07-10 06:49:21. The
timestamps are timezone-naive in the source and treated as UTC at ingest.
The future dates are a property of the generator.

Full and sample distributions are identical. In both, 87,500 rows have no
`alert_type` or `category`. The 12,500 labeled rows split into Exploit
2,448, Recon 2,509, Policy 2,534, Malware 2,453, and Evasion 2,556.
The full alert-type distribution is also recorded in `data/advanced-siem-sample.json`.

| Alert type | Full count | Sample count |
|---|---:|---:|
| (missing) | 87,500 | 87,500 |
| AI Model Poisoning | 698 | 698 |
| Brute Force | 749 | 749 |
| Cloud API Abuse | 711 | 711 |
| Container Escape | 702 | 702 |
| Credential Stuffing | 784 | 784 |
| DDoS | 735 | 735 |
| DNS Tunneling | 738 | 738 |
| Domain Fronting | 699 | 699 |
| Fileless Attack | 698 | 698 |
| ICS Attack | 716 | 716 |
| Living-off-the-Land | 728 | 728 |
| MFA Bypass | 791 | 791 |
| Port Scan | 744 | 744 |
| SQL Injection | 668 | 668 |
| Supply Chain Compromise | 767 | 767 |
| XSS | 762 | 762 |
| Zero-Day Exploit | 810 | 810 |

The push CLI maps `auth` (12,516 rows) to `hf_auth`. It maps `network`
(12,335), `firewall` (12,448), and `ids_alert` (12,500) to `hf_network`.
It skips the `ai`, `cloud`, `endpoint`, and `iot` families. Measure label
coverage for the model's exact evaluation slice.

## Shared envelope

The push CLI uses `connector_id: hf-datasets`, homogeneous connector types,
and low ingest severity (OCSF severity ID 2). Every selected source field
retains its original value under `raw_event.hf_*`. Stable external IDs use
the dataset name plus the pinned parquet row index for Precinct6 or
`event_id` for Advanced SIEM. AiSOC derives the same normalized ID on a
replay. Batch success counts reflect accepted requests, so a replay may be
accepted again with the same IDs.

## Excluded source

[HookProbe Edge IDS Threats](https://huggingface.co/datasets/hookprobe/edge-ids-threats)
was excluded because its verdict is derived from its own anomaly score,
which would leak the target. Its limited features and single-edge-node
origin also make it a weak basis for evaluating generalization.

## Local footprint

The generated Precinct6 and Advanced SIEM parquet projections were
5,954,747 and 5,239,479 bytes respectively, or 11,194,226 bytes combined.
The local sample reports record the measured dimensions and date ranges.

## CIC-IDS2017 flow subset

The Apache-2.0 [Hugging Face release](https://huggingface.co/datasets/rdpahalavan/CIC-IDS2017)
contains several modalities. This project uses only
`Network-Flows/CICIDS_Flow.parquet` at revision
`eee96b6abc2c4bb621fd67679a4aa24bddc4be6a`.
Its size is 369,814,810 bytes. The file has 2,827,677 rows in one row group.
A remote two-column census precedes a projected sample read. The source
file is never written locally. The sample has 78,183 rows and is 4,859,248
bytes. Seed 42 selects up to 10,000 benign rows per day, caps common attack
labels at 3,000 per day, and retains all rows of labels with at most 3,000
rows before duplicate cleanup.

| Label | Mon Jul 3 | Tue Jul 4 | Wed Jul 5 | Thu Jul 6 | Fri Jul 7 | Full | Raw sample |
|---|---:|---:|---:|---:|---:|---:|---:|
| BENIGN | 529,450 | 431,809 | 439,668 | 456,267 | 413,928 | 2,271,122 | 50,000 |
| FTP-Patator | 0 | 7,935 | 0 | 0 | 0 | 7,935 | 3,000 |
| SSH-Patator | 0 | 5,897 | 0 | 0 | 0 | 5,897 | 3,000 |
| DoS slowloris | 0 | 0 | 5,796 | 0 | 0 | 5,796 | 3,000 |
| DoS Slowhttptest | 0 | 0 | 5,499 | 0 | 0 | 5,499 | 3,000 |
| DoS Hulk | 0 | 0 | 230,123 | 0 | 0 | 230,123 | 3,000 |
| DoS GoldenEye | 0 | 0 | 10,293 | 0 | 0 | 10,293 | 3,000 |
| Heartbleed | 0 | 0 | 11 | 0 | 0 | 11 | 11 |
| Infiltration | 0 | 0 | 0 | 36 | 0 | 36 | 36 |
| Web Attack – Brute Force | 0 | 0 | 0 | 1,507 | 0 | 1,507 | 1,507 |
| Web Attack – XSS | 0 | 0 | 0 | 652 | 0 | 652 | 652 |
| Web Attack – Sql Injection | 0 | 0 | 0 | 21 | 0 | 21 | 21 |
| Bot | 0 | 0 | 0 | 0 | 1,956 | 1,956 | 1,956 |
| PortScan | 0 | 0 | 0 | 0 | 158,804 | 158,804 | 3,000 |
| DDoS | 0 | 0 | 0 | 0 | 128,025 | 128,025 | 3,000 |

All timestamps across Monday (529,450 rows), Tuesday (445,641),
Wednesday (691,390), Thursday (458,483), and Friday (702,713) parsed to
calendar dates in day/month/year order. On every day, all observed hours
were in the 1–12 range without AM/PM markers. There were zero invalid
dates. The clock cannot establish reliable intra-day order or a timezone.
The day split uses dates only. OCSF uses UTC midnight as a day-level
placeholder and preserves the original timestamp under `raw_event`.

Only the selected flow duration, packet and byte totals, rate, length,
inter-arrival, TCP flag, and active/idle statistics are model inputs.
Identifiers, addresses, ports, protocol string, timestamps, and the label
are excluded. Non-finite numeric values become missing. Duplicate feature
vectors are grouped before splitting, even across days, and label-conflict
groups are discarded. The earliest remaining representative keeps the
feature vector out of subsequent day splits. Logistic preprocessing learns
imputation and scaling from the respective training fold.

The mapper uses `hf_network`, retains `raw_event.hf_label`, and assigns
`cicids:<row-index>` scoped to the pinned release. The original labels are
benchmark annotations. Engelen, Rimmer and Joosen (2021) published
corrections to CIC-IDS2017 flow construction and labeling. This evaluation
uses the pinned Hugging Face file as published, and absolute scores should
be interpreted in light of those known errors.
[Published label-quality audit and corrections](https://intrusion-detection.distrinet-research.be/WTMC2021/)

### Day 5 clock validation

For the entity experiment, the candidate correction adds 12 hours to
unmarked hours below 8. Validation checked corrected source-row
timestamps for backsteps within each capture date before any sorting.
The full projected scan had zero unparseable rows.

| Capture day | Corrected clock range | Backward row steps | Largest backstep |
|---|---|---:|---:|
| Mon Jul 3 | 08:55:58–17:01:34 | 208,741 | 8h 03m |
| Tue Jul 4 | 08:53:00–17:00:00 | 159,376 | 8h 04m |
| Wed Jul 5 | 08:42:00–17:10:00 | 163,845 | 8h 22m |
| Thu Jul 6 | 08:59:00–17:04:00 | 1 | 8h 05m |
| Fri Jul 7 | 08:59:00–17:02:00 | 0 | — |

The correction placed FTP-Patator at 09:17–10:30. Of its 7,935 rows, 7,934
(99.99%) fell within five minutes of the published 09:20–10:20 interval.
It placed SSH-Patator at 14:09–15:11. Of its 5,897 rows, 5,454 (92.49%)
fell within five minutes of the published 14:00–15:00 interval, below
the preregistered 95% requirement. Export order may itself be imperfect.
The reversal counts measure the source order and do not identify which
individual timestamps are wrong. Friday's monotonicity alone does not
validate the correction for the training and comparison days.
[UNB capture schedule](https://www.unb.ca/cic/datasets/ids-2017.html)

Both validation checks were required. The Day 5 windows are approximate
corrected-clock buckets and cannot qualify a detector for deployment.
[Clock validation output](../ml/uc3_behaviour_cicids/clock-validation.json)
