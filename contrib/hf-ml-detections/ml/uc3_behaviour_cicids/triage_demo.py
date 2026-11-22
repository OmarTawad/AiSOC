"""Process the reconciled demo alerts with AiSOC’s own triage worker.

Run from the repository root. The Kafka group checkpoint is left alone.
"""

import argparse
from contextlib import contextmanager
import json
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--isolated", action="store_true", help="Temporarily pause the Agents backlog while prioritizing demo alerts")
args = parser.parse_args()


@contextmanager
def target_agents():
    if not args.isolated:
        yield "aisoc-agents"
        return
    name = "aisoc-day6-triage-once"
    subprocess.run(["docker", "compose", "stop", "agents"], check=True)
    try:
        subprocess.run([
            "docker", "compose", "run", "-d", "--rm", "--no-deps",
            "--name", name, "--entrypoint", "sleep", "agents", "1200",
        ], check=True)
        yield name
    finally:
        try:
            subprocess.run(["docker", "stop", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        finally:
            subprocess.run(["docker", "compose", "up", "-d", "--no-deps", "--no-build", "--pull", "never", "agents"], check=True)


directory = Path('contrib/hf-ml-detections/data/day6')
expected = {row['alert_id'] for row in json.loads((directory/'reconciliation.json').read_text())['matched'].values()}
base = ['docker','compose','exec','-T','kafka']
topic = 'aisoc.alerts.fused'
offset = subprocess.check_output([*base,'kafka-get-offsets','--bootstrap-server','localhost:29092','--topic',topic],text=True)
end = int(next(line.rsplit(':',1)[1] for line in offset.splitlines() if line.startswith(topic+':0:')))
begin = max(0,end-150)
messages = subprocess.check_output([*base,'kafka-console-consumer','--bootstrap-server','localhost:29092',
    '--topic',topic,'--partition','0','--offset',str(begin),'--max-messages',str(end-begin),'--timeout-ms','15000'],text=True)
selected = {}
for line in messages.splitlines():
    value = json.loads(line)
    identifier = value.get('alert_row_id') or value.get('id')
    if identifier not in expected:
        continue
    raw = json.loads(value['alert']['raw_event']['raw_data'])
    assert not any(key.startswith('hf_label') or key in {'label','attack_label','label_binary'}
                   for source in (raw, raw['raw_event']) for key in source)
    selected[identifier] = value
assert set(selected) == expected
print(f'Selected {len(selected)} exact fused demo messages with no label fields', flush=True)
completed = subprocess.check_output([
    "docker", "compose", "exec", "-T", "postgres", "psql", "-U", "aisoc", "-d", "aisoc", "-At",
    "-c", "SELECT DISTINCT r.case_id::text FROM investigation_runs r "
    "JOIN investigation_events e ON e.run_id=r.id AND e.kind='triage_verdict' "
    "JOIN alerts a ON a.id::text=r.case_id::text "
    "WHERE a.rule_id IN ('det-hf-ml-005','det-hf-ml-005-hi')",
], text=True).splitlines()
selected = {identifier: message for identifier, message in selected.items() if identifier not in completed}
print(f"Targeting {len(selected)} demo alerts without a persisted verdict", flush=True)
program = """
import asyncio
import json
import os
import sys
from app.workers.fused_alert_consumer import FusedAlertTriageWorker

if os.getenv("DAY6_ISOLATED") == "1":
    os.environ["AISOC_AGENT_ESCALATE_TO_GRAPH"] = "0"
    from app.agents import auto_triage_agent
    from app.llm.factory import llm_override
    original = auto_triage_agent.make_chat_model

    def direct_local(role, **kwargs):
        # Preserve the triage prompt, parser, gates and pinned model. Bound
        # the local response, eliminate transport retries, and bypass the
        # overloaded gateway queue only within this one-off worker.
        kwargs.update(max_tokens=192, timeout=15, max_retries=0)
        with llm_override(model="llama3.2:3b-instruct-q4_K_M", base_url="http://ollama:11434/v1", api_key="ollama"):
            return original(role, **kwargs)

    auto_triage_agent.make_chat_model = direct_local

async def main():
    worker = FusedAlertTriageWorker(bootstrap_servers=os.environ["KAFKA_BOOTSTRAP_SERVERS"])
    messages = json.load(sys.stdin)
    print("DAY6_STAGE received="+str(len(messages)), flush=True)
    sem = asyncio.Semaphore(8 if os.getenv("DAY6_ISOLATED") == "1" else 4)
    async def execute(identifier, payload):
        async with sem:
            try:
                result = await worker.triage(payload)
                result = result or {}
                print("DAY6_RESULT "+json.dumps({"alert_id":identifier,"tier":result.get("tier"),
                      "verdict":result.get("verdict"),"run_id":result.get("run_id")}), flush=True)
            except Exception as error:
                print("DAY6_RESULT "+json.dumps({"alert_id":identifier,"error_type":type(error).__name__}), flush=True)
    await asyncio.gather(*(execute(key, value) for key, value in messages.items()))

asyncio.run(main())
"""
with target_agents() as container, tempfile.TemporaryFile(mode="w+t") as inputs, (directory/"triage-runs.jsonl").open("a") as evidence:
    command = ["docker", "exec", "-i", "-e", f"DAY6_ISOLATED={int(args.isolated)}",
               container, "python", "-u", "-c", program]
    json.dump(selected, inputs)
    inputs.seek(0)
    with subprocess.Popen(command, stdin=inputs, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) as proc:
        for line in proc.stdout:
            if line.startswith("DAY6_STAGE "):
                print(line.strip(), flush=True)
            if line.startswith("DAY6_RESULT "):
                row = json.loads(line.removeprefix("DAY6_RESULT "))
                evidence.write(json.dumps(row) + "\n")
                evidence.flush()
                print(row, flush=True)
        if proc.wait():
            raise RuntimeError("Targeted agents worker failed; only sanitized outcome lines were emitted")
