"""Publish retained coding cohorts without changing any original evidence byte."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
from rt.bundle import sha
from rt.log import read as read_exact
from rt.scheduled_log import read as read_noisy
from demos.coding_agent.review_report import load_evidence
from demos.coding_agent.run import REPO, checkpoint, write_json
from demos.coding_agent.utility_run import evidence_hashes


COHORTS={'first':'coding-demo','utility':'coding-demo-utility','qwen':'coding-demo-qwen-02',
         'filings':'coding-demo-filings','useful-crash':'coding-demo-useful-crash-01'}


def publish(source,output):
    source,output=Path(source),Path(output)
    if output.exists():raise ValueError('new_publication_directory_required')
    originals={label:evidence_hashes(source/name) for label,name in COHORTS.items()}
    summaries={label:load_evidence(source/name)[0] for label,name in COHORTS.items()}
    for label,s in summaries.items():
        for filename,saved in s['checkpoints'].items():
            path=source/COHORTS[label]/filename
            first=json.loads(path.read_bytes().splitlines()[0])
            (read_noisy if first.get('schema')=='rt.release.v2' else read_exact)(path)
            if checkpoint(path)!=saved:raise ValueError('historical_checkpoint_mismatch')
    output.mkdir(parents=True)
    for label,name in COHORTS.items():
        shutil.copytree(source/name,output/label,ignore=shutil.ignore_patterns('__pycache__'))
        startpath=source/name/'start.json'
        start=json.loads(startpath.read_text(encoding='utf-8')) if startpath.exists() else {}
        # New supplementary archives do not alter the historical run directory.
        if 'source_sha256' in start:
            for filename,digest in start['source_sha256'].items():
                raw=subprocess.check_output(['git','show',start['git_commit']+':'+filename],cwd=REPO)
                if sha(raw)!=digest:raise ValueError('historical_source_commit_mismatch')
                dest=output/'source-archives'/label/filename
                dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(raw)
    if {label:evidence_hashes(source/name) for label,name in COHORTS.items()}!=originals:
        raise RuntimeError('original_evidence_changed')
    published={path.relative_to(output).as_posix():sha(path.read_bytes()) for path in sorted(output.rglob('*')) if path.is_file()}
    write_json(output/'publication-manifest.json',{'status':'verified','published_sha256':published,
        'original_corpus_hashes':originals,'source_location':'Portable corpus labels; original absolute metadata is preserved inside committed evidence.',
        'prior_evidence_preserved_byte_for_byte':True,'backend_accesses':0,'private_labels':'Discarded originally; not reconstructed.',
        'privacy':'Deliberately exposed comparator outcomes and diagnostics make the research transcript non-private.'})
    (output/'README.md').write_text('# Retained coding-agent evidence\n\nAll five original coding cohorts are published here with their original bytes and identities. The publication manifest verifies every listed evidence file and supplementary source archive. Hash-committed historical path strings remain intact; current launchers accept explicit portable model paths. Source archives reproduce the recorded committed bytes when a source manifest was retained. Private assignments were discarded originally, so recovery totals are trusted custodian aggregates. No new model or protected backend accesses occurred during publication.\n\nThe original shared budget ends at 5,008/5,008, with conservative noisy-channel epsilon 11,003.7007. These charges are not reset. Exact/status-visible comparisons make the full research transcript non-private.\n',encoding='utf-8')
    print(output.resolve())


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',default='scratch');parser.add_argument('--output',required=True)
    args=parser.parse_args();publish(args.source,args.output)


if __name__=='__main__':main()
