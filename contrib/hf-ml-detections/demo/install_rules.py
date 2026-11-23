"""Prepare the local read-only Fusion ruleset without rebuilding its image."""

import json
import subprocess
import tempfile
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
REPO = PROJECT.parents[1]
RULE_PATH = "/app/app/data/detection_ruleset_imported.json"
ACTIVE = {"det-hf-ml-005", "det-hf-ml-005-hi"}
RETIRED = {"det-hf-ml-001", "det-hf-ml-002", "det-hf-ml-003", "det-hf-ml-004"}


def docker(*args):
    return subprocess.check_output(["docker", *args], cwd=REPO, text=True).strip()


def main():
    service = docker("compose", "ps", "-q", "fusion")
    if not service:
        raise SystemExit("Start Fusion first with ~/aisoc-start.sh")
    image = docker("inspect", "--format", "{{.Image}}", service)
    source = docker("create", image)
    try:
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "rules.json"
            docker("cp", f"{source}:{RULE_PATH}", str(file))
            imported = json.loads(file.read_text())
    finally:
        docker("rm", source)

    native = json.loads((REPO / "services/fusion/app/data/detection_ruleset.json").read_text())
    active = [rule for rule in native["rules"] if rule["id"] in ACTIVE and rule.get("enabled", True)]
    if {rule["id"] for rule in active} != ACTIVE:
        raise SystemExit("Both enabled UC3 rules must exist in the committed native corpus")
    imported["rules"] = [rule for rule in imported["rules"] if rule["id"] not in ACTIVE | RETIRED] + active
    imported["count"] = len(imported["rules"])
    target = PROJECT / "data/fusion-imported-local.json"
    target.parent.mkdir(exist_ok=True)
    temporary = target.with_suffix(".tmp")
    temporary.write_text(json.dumps(imported, indent=2) + "\n")
    temporary.replace(target)
    print(target)


if __name__ == "__main__":
    main()
