"""Process the reconciled demo alerts with AiSOC’s own triage worker.

Run from the repository root. The Kafka group checkpoint is left alone.
"""

import json
from pathlib import Path
import subprocess

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
print(f'Selected {len(selected)} exact fused demo messages with no label fields',flush=True)
program = """
import asyncio
import json
import os
import sys
from app.workers.fused_alert_consumer import FusedAlertTriageWorker

async def main():
    worker = FusedAlertTriageWorker(bootstrap_servers=os.environ["KAFKA_BOOTSTRAP_SERVERS"])
    messages = json.load(sys.stdin)
    sem = asyncio.Semaphore(4)
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
command = ['docker','compose','exec','-T','agents','python','-c',program]
with (directory/'triage-runs.jsonl').open('w') as evidence:
    with subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True) as proc:
        proc.stdin.write(json.dumps(selected))
        proc.stdin.close()
        for line in proc.stdout:
            if line.startswith('DAY6_RESULT '):
                row = json.loads(line.removeprefix('DAY6_RESULT '))
                evidence.write(json.dumps(row)+'\n')
                evidence.flush()
                print(row, flush=True)
        if proc.wait():
            raise RuntimeError("Targeted agents worker failed; only sanitized outcome lines were emitted")
