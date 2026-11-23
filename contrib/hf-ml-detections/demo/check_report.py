"""Compare the presentation deck's rounded figures with recorded evidence."""

import re
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVAL = "docs/evaluation.md"
EVIDENCE = "docs/demo-evidence/patator.txt"
evaluation = (ROOT / EVAL).read_text()
mismatches = []
checks = 0


def check(label, deck, source, path=EVAL):
    global checks
    checks += 1
    if isinstance(deck, str) and re.fullmatch(r"\d+(?:\.\d+)?", deck):
        scale = Decimal(deck)
        source = format(Decimal(str(source).replace(",", "").rstrip("%")).quantize(scale, rounding=ROUND_HALF_UP), "f")
    if str(deck) != str(source):
        mismatches.append(f"{label} — deck says {deck}, source says {source} ({path})")


def section(heading):
    start = evaluation.index(heading)
    return re.split(r"\n#{2,3} ", evaluation[start + len(heading) :], maxsplit=1)[0]


def table(heading):
    return [tuple(cell.strip() for cell in line.strip("|").split("|")) for line in section(heading).splitlines() if line.startswith("|")][
        2:
    ]


def extract(pattern, text):
    match = re.search(pattern, text)
    if not match:
        raise SystemExit(f"Can't locate report evidence matching {pattern}")
    return match.groups()


audit = section("## UC1 — Precinct6 shortcut audit")
heuristic, xgb = extract(r"AP ([\d.]+)\*\* versus \*\*([\d.]+)\*\*", audit)
check("Precinct6 heuristic AP", "0.995", heuristic)
check("Precinct6 XGBoost AP", "1.000", xgb)
check("Precinct6 org-holdout recall", "0", {"zero": 0}.get(extract(r"had \*\*(\w+) recall\*\*", audit)[0]))
check("Precinct6 leading SHAP feature", "action=block", extract(r"SHAP ranked `([^`]+)` first", audit)[0])
matches, alerts = extract(r"replay matched \*\*([\d,]+) of .*?\n([\d,]+) distinct alerts", audit)
check("Day 3 matches", "28510", matches)
check("Day 3 alerts", "668", alerts)

for cells, (name, expected) in zip(
    table("### Matched family-generalization comparison"),
    [("DoS", ("97.1", "7.4")), ("PortScan", ("82.6", "6.5")), ("Patator", ("99.4", "0.0")), ("Web", ("95.0", "1.5"))],
    strict=True,
):
    for role, deck, source in zip(("seen", "held-out"), expected, cells[2:4], strict=True):
        check(f"UC1b flow {name} {role} recall (%)", deck, source)

for cells, expected in zip(table("### Chronological unseen-label test"), ("0.309", "0.790", "0.864"), strict=True):
    check(f"Friday {cells[0]} AP", expected, cells[1])

friday = {row[1]: row for row in table("### Alerts per capture day") if row[0] == "Fri"}
for name, expected in {
    "UEBA-equivalent": "1511",
    "UC1b XGBoost": "536",
    "UC2 Isolation Forest": "321",
    "UC3 robust baseline": "129",
}.items():
    check(f"First Friday {name} false alerts", expected, friday[name][3])

families = [
    ("39", "94.9", "5.1", "12.8", "7.7", "23.1"),
    ("6", "100", "16.7", "83.3", "83.3", "66.7"),
    ("3", "66.7", "66.7", "100", "100", "100"),
    ("10", "100", "0", "0", "80", "20"),
    ("3", "66.7", "33.3", "0", "100", "33.3"),
    ("1", "100", "0", "0", "100", "0"),
]
for cells, expected in zip(table("### Matched source-window holdouts")[:6], families, strict=True):
    fields = ("windows", "UC1b seen", "UC1b unseen", "UC2", "UC3", "UEBA")
    for field, deck, source in zip(fields, expected, cells[1:], strict=True):
        check(f"Matched entity {cells[0]} {field}", deck, source)

for cells, expected in zip(
    table("### Frozen choices and single Friday re-test"),
    [
        ("216", "202", "6.5"),
        ("70", "64", "8.6"),
        ("25", "9", "64.0"),
    ],
    strict=True,
):
    for field, deck, source in zip(("alerts", "false alerts", "precision"), expected, cells[1:4], strict=True):
        check(f"Final Friday {cells[0]} {field}", deck, source)
    if cells[0] == "UC3":
        check("Final Friday UC3 recall", "16/197", cells[4].split()[0])

for cells, (fraction, precision) in zip(
    table("### Corroboration and hunting")[:2],
    [
        ("10/11", "90.9"),
        ("6/14", "42.9"),
    ],
    strict=True,
):
    check(f"{cells[0]} attack-labeled fraction", fraction, f"{cells[2]}/{cells[1]}")
    check(f"{cells[0]} precision", precision, cells[4])

expected, actual = extract(
    r"accepted all (\d+) summaries.*?reconciled (\d+) distinct summary IDs", section("### Replay evidence").replace("\n", " ")
)
check("Day 6 replay reconciliation", "38/38", f"{actual}/{expected}")
attack, benign = table("### Triage and console")
check("Triage attack alerts kept", "30/30", f"{int(attack[1]) - int(attack[4])}/{attack[1]}")
check("Triage benign alerts marked likely benign", "7/8", f"{benign[3]}/{benign[1]}")
check("Triage auto-closed", "0", int(attack[4]) + int(benign[4]))

runtime, flows, alerts = extract(
    r"Run [\da-f]+ \| ([\d.]+)s \| ([\d,]+) flows processed .*? \| (\d+) alerts confirmed", (ROOT / EVIDENCE).read_text()
)
check("Demo flows scored", "100085", flows, EVIDENCE)
check("Demo alerts", "15", alerts, EVIDENCE)
check("Demo approximate runtime", "~2 min", "~2 min" if round(float(runtime) / 60) == 2 else f"{runtime}s", EVIDENCE)
print(f"{checks} checks, {len(mismatches)} mismatches")
for mismatch in mismatches:
    print(mismatch)
raise SystemExit(bool(mismatches))
