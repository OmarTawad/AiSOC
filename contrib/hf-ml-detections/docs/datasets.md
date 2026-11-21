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
| Network Activity (`hf_network`, 4001) | `communication` on `network_communication`, `firewall_action` on `cisco_asa`, and Windows Filtering Platform Connection |

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

The `network` (12,335 rows) and `firewall` (12,448) families map to
`hf_network`. This ingest slice excludes IDS alert rows and other event
families. Measure label coverage again for the model's exact evaluation slice.

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
