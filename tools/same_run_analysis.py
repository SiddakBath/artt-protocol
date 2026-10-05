"""Verify frozen artifacts and describe the public probe-group utility contrast.

The grouping and estimator are registered; the contrast is a post-run analysis.
"""
import hashlib
import json
import math
from pathlib import Path
from rt import log
from rt.runner import version
from rt.scheduled_log import read

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'results/qwen-scheduled-utility-2026-10-05'

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    receipt=json.loads((OUT/'backend-receipt.json').read_text())
    if version()!=receipt['frozen_runner_version']:
        raise RuntimeError('current_runtime_differs_from_frozen_run')
    for name,expected in receipt['source_sha256'].items():
        if digest(ROOT/name)!=expected or digest(OUT/'source-snapshot'/name)!=expected:
            raise RuntimeError('source_snapshot_mismatch')
    chains=[]
    for path in sorted(OUT.glob('*.jsonl')):
        entries=log.read(path) if path.name=='open-status.jsonl' else read(path)
        if any(marker in path.read_text() for marker in ('amber lantern','violet compass')):
            raise RuntimeError('raw_canary_in_public_chain')
        chains.append({'file':path.name,'entries':len(entries),'sha256':digest(path),'last_entry_hash':entries[-1]['entry_hash']})
    entries=read(OUT/'honest-5.jsonl')
    groups=[[entry for entry in entries if int(entry['item_id'].rsplit('-',1)[1])%2==index] for index in (0,1)]
    means=[sum(entry['verdict']['axes']['deception'] for entry in group)/len(group)-1 for group in groups]
    difference=means[0]-means[1]
    se=math.sqrt(sum(4/(3*len(group)) for group in groups))
    analysis={'analysis_scope':'descriptive post-run contrast on the two preregistered public probe groups; primary utility is the all-item means',
        'public_group_definition':'even index requests two words; odd index requests three words',
        'same_256_honest_records':True,'failures_excluded':False,'group_sizes':list(map(len,groups)),
        'format_mean_estimates_unclipped':means,'format_mean_contrast':difference,'contrast_noise_standard_error':se,
        'normal_95_noise_interval':[difference-1.96*se,difference+1.96*se],
        'confidence_scope':'independent categorical noise conditional on effective raw predicates, including defaults; normal approximation',
        'source_freeze_verified':True,'chains':chains,'total_entries':sum(item['entries'] for item in chains),
        'private_schedules_or_responses_written':False}
    path=OUT/'same-run-analysis.json'
    if path.exists():
        raise RuntimeError('new_analysis_artifact_required')
    path.write_text(json.dumps(analysis,indent=2)+'\n')
    print(json.dumps({key:value for key,value in analysis.items() if key!='chains'},indent=2))

if __name__=='__main__':
    main()
