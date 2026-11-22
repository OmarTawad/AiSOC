# CIC-IDS2017 Monday allowlist audit

The allowlist is the frozen top 25 by Monday source flow count. The inbound port
column counts flow rows whose destination was that IP and an audited service port.
A missing port is no evidence of a listening socket. Peer counts are distinct
opposite endpoints per direction. Observed roles are hypotheses.

| Source IP | Likely role | Monday source flows | Inbound peers | Outbound peers | Inbound ports (flows) |
|---|---|---:|---:|---:|---|
| 192.168.10.3 | DNS and domain controller (published) | 67,769 | 25 | 44 | 53 (147,651), 88 (1,207), 389 (1,206), 3268 (498) |
| 192.168.10.25 | Workstation-like client (lab inventory) | 58,152 | 1,917 | 2,127 | — |
| 192.168.10.5 | Workstation-like client (lab inventory) | 48,616 | 2,571 | 3,297 | 443 (5) |
| 192.168.10.12 | Workstation-like client (lab inventory) | 36,484 | 1,440 | 1,697 | 139 (447) |
| 192.168.10.9 | Workstation-like client (lab inventory) | 34,337 | 1,643 | 2,117 | 3268 (1), 3389 (1), 5355 (1), 5353 (1) |
| 192.168.10.14 | Workstation-like client (lab inventory) | 31,384 | 1,774 | 2,177 | — |
| 192.168.10.8 | Windows workstation; simulated lateral-movement source | 27,432 | 1,433 | 1,740 | 443 (4) |
| 192.168.10.16 | Workstation-like client (lab inventory) | 26,726 | 1,538 | 1,828 | — |
| 192.168.10.17 | Workstation-like client (lab inventory) | 24,709 | 1,325 | 1,722 | — |
| 192.168.10.51 | Web / Ubuntu server (published) | 22,441 | 1,526 | 1,956 | — |
| 192.168.10.15 | Workstation-like client (lab inventory) | 21,948 | 1,268 | 1,598 | — |
| 192.168.10.19 | Workstation-like client (lab inventory) | 18,851 | 1,127 | 1,484 | — |
| 192.168.10.50 | Web / Ubuntu server (published) | 7,093 | 17 | 58 | 22 (2,127), 21 (957) |
| 35.186.227.40 | Web service-like (observed) | 3,202 | 3 | 3 | 443 (2,410), 80 (2) |
| 162.208.20.178 | Web service-like (observed) | 1,763 | 3 | 3 | 443 (1,631), 80 (586) |
| 72.21.91.29 | Web service-like (observed) | 1,406 | 11 | 10 | 80 (1,981) |
| 23.111.11.111 | Web service-like (observed) | 1,335 | 1 | 1 | 443 (1,348) |
| 23.50.75.27 | Web service-like (observed) | 1,313 | 11 | 10 | 80 (3,559) |
| 23.194.182.12 | Web service-like (observed) | 1,036 | 3 | 3 | 443 (1,283), 80 (2) |
| 172.217.12.194 | Web service-like (observed) | 801 | 11 | 11 | 443 (786), 80 (62) |
| 35.186.253.0 | Web service-like (observed) | 727 | 3 | 3 | 443 (637) |
| 104.16.25.92 | Web service-like (observed) | 708 | 1 | 1 | 443 (628) |
| 23.61.187.27 | Web service-like (observed) | 698 | 11 | 11 | 80 (1,515) |
| 172.217.11.2 | Web service-like (observed) | 563 | 11 | 11 | 443 (573), 80 (56) |
| 104.88.89.135 | Web service-like (observed) | 515 | 11 | 11 | 443 (646), 80 (3) |

Neither published firewall address (172.16.0.1 or 205.174.165.80),
nor 172.16.0.11 or the published external attacker addresses, is on the list.
Windows host 192.168.10.8 is on the list and is also the published simulated
source of one Thursday lateral-movement scenario.
[UNB network inventory and capture schedule](https://www.unb.ca/cic/datasets/ids-2017.html)
