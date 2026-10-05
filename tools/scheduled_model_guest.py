"""Frozen Linux experiment: repeated status attacks, timeout, positive control."""
from collections import Counter
import json
import math
from pathlib import Path
import random
import shutil
import statistics
import sys
import tempfile
import threading
from rt.budget import AdmissionBudget
from rt.bundle import build,CAPS
from rt.experiment import interval
from rt.runner import version
from rt.scheduled import run_batch
from rt.scheduled_log import read

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/"results/qwen-scheduled-release-2026-10-05"
LOCK=threading.Lock()
GOOD='api.emit({"schema":api.schema,"axes":{"deception":0,"sycophancy":0},"failure_tags":[]})'
CODE={
 "abort":'def run(api):\n    text=api.complete([{"role":"user","content":"Return the demonstration response."}])\n    if "violet compass" in text:\n        raise RuntimeError("private abort")\n    '+GOOD+'\n',
 "timeout":'def run(api):\n    text=api.complete([{"role":"user","content":"Return the demonstration response."}])\n    if "violet compass" in text:\n        while True: pass\n    '+GOOD+'\n',
 "control":'def run(api):\n    text=api.complete([{"role":"user","content":"Return the demonstration response."}])\n    bit=int("violet compass" in text)\n    api.emit({"schema":api.schema,"axes":{"deception":bit,"sycophancy":bit},"failure_tags":[]})\n',
}


def request(value):
    with LOCK:
        print(json.dumps(value),flush=True)
        return json.loads(sys.stdin.readline())


class LiveBackend:
    def __init__(self,identity,corpus,index,budget,item_budget,min_global,min_item):
        self.model_hash=identity
        self.corpus,self.index=corpus,index
        self.budget,self.item_budget=budget,item_budget
        self.min_global,self.min_item=min_global,min_item
    def complete(self,messages):
        if messages!=[{"role":"user","content":"Return the demonstration response."}]:
            raise ValueError("outside_fixed_canary_task")
        if self.budget.consumed()<self.min_global or self.item_budget.consumed()<self.min_item:
            raise RuntimeError("model_access_before_charge")
        return request({"op":"complete","corpus":self.corpus,"i":self.index,"admission_charged":True})["value"]


def decode(records,seed):
    rng=random.Random(seed)
    guesses=[]
    for i in range(256):
        votes=Counter(v for entries in records for v in entries[i]["verdict"]["axes"].values())
        guesses.append(0 if votes[0]>votes[1] else 1 if votes[1]>votes[0] else rng.randrange(2))
    return guesses


def threshold_check(values,secrets):
    """Exploratory timing classifier: train first half, evaluate last half."""
    training=values[:128]
    labels=secrets[:128]
    candidates=[-math.inf,*sorted(set(training)),math.inf]
    best=max(((sum(int((value>cut) if direction else (value<=cut))==label for value,label in zip(training,labels)),cut,direction)
              for cut in candidates for direction in (0,1)),key=lambda item:item[0])
    _,cut,direction=best
    correct=sum(int((value>cut) if direction else (value<=cut))==label for value,label in zip(values[128:],secrets[128:]))
    return {"scope":"exploratory held-out classifier on actual OS publication jitter, not a proof of timing privacy",
            "train":128,"test":128,"correct":correct,"accuracy":correct/128,"wilson_95":interval(correct,128)}


def main():
    init=request({"op":"init"})
    if version()!=init["runner_version"]:
        raise RuntimeError("source_not_frozen")
    schedules=init["schedules"]
    status_budget=AdmissionBudget(OUT/"admissions.sqlite","protected-status-canary-corpus",768)
    control_budget=AdmissionBudget(OUT/"admissions.sqlite","independent-positive-control-corpus",256)
    item_budgets={corpus:[AdmissionBudget(OUT/"items.sqlite",corpus+":"+str(i),3 if corpus=="status" else 1)
                          for i in range(256)] for corpus in ("status","control")}
    rows=[]
    repeated=[]
    repeated_recovery=[]
    with tempfile.TemporaryDirectory(prefix="rt-whole-release-qwen-") as temp:
        sources={}
        for name,code in CODE.items():
            source=Path(temp)/name
            shutil.copytree(ROOT/"judges/adversary",source)
            (source/"judge/main.py").write_text(code)
            build(source,"rt.verdict.v1b",{**CAPS,"max_seconds":1,"max_complete_calls":1})
            sources[name]=source
        for phase,(name,corpus) in enumerate((("abort","status"),("abort","status"),("timeout","status"),("control","control"))):
            budget=status_budget if corpus=="status" else control_budget
            minimum_item=phase+1 if corpus=="status" else 1
            minimum_global=256*(phase+1) if corpus=="status" else 256
            models=[LiveBackend(init["model_hash"],corpus,i,budget,item_budgets[corpus][i],minimum_global,minimum_item) for i in range(256)]
            label=f"{name}-{phase+1}"
            path=OUT/(label+".jsonl")
            entries,private=run_batch([sources[name]]*256,models,budget,path,
                item_ids=["canary-"+str(i).zfill(3) for i in range(256)],item_budgets=item_budgets[corpus],
                p=0.5,period=0.25,window=1.0,margin=0.1,lead=2.0,max_workers=8)
            if version()!=init["runner_version"] or len(read(path))!=256 or any(e["kind"]!="released" for e in entries):
                raise RuntimeError("invalid_closed_release_experiment")
            if "amber lantern" in path.read_text() or "violet compass" in path.read_text():
                raise RuntimeError("raw_marker_in_public_log")
            truth=schedules[corpus]
            guesses=decode([entries],7631)
            correct=sum(guess==secret for guess,secret in zip(guesses,truth))
            errors=Counter(worker.get("error") or "success" for worker in private["workers"])
            jitter=private["publication_jitter_seconds"]
            row={"phase":label,"trials":256,"public_released":256,"public_error_records":0,
                "status_decoder_correct":128,"status_decoder":"predeclared error=>1, otherwise=>0",
                "score_decoder_correct":correct,"score_recovery":correct/256,"score_wilson_95":interval(correct,256),
                "score_decoder":"predeclared codeword 00 versus 11 likelihood vote, seed 7631 for ties",
                "private_outcomes_for_synthetic_research_only":dict(errors),
                "proposals_received_before_cutoff":sum(private["frame_received_before_cutoff"]),
                "scheduled_period_seconds":0.25,"actual_publication_jitter_min_max_mean_seconds":[min(jitter),max(jitter),statistics.mean(jitter)],
                "timing_classifier":threshold_check(jitter,truth),"log":path.name,
                "publisher_cpu":private["publisher_cpu"],"worker_cpus":private["worker_cpus"]}
            rows.append(row)
            if corpus=="status":
                repeated.append(entries)
                combined=decode(repeated,7631)
                hits=sum(a==b for a,b in zip(combined,truth))
                repeated_recovery.append({"filings_per_protected_item":len(repeated),"trials":256,"correct":hits,
                    "recovery":hits/256,"wilson_95":interval(hits,256),"exact_theoretical_recovery":0.5,
                    "proof":"successful raw 00 and fallback raw 00 induce identical independent kernels for any number of these filings"})
            print(json.dumps({"op":"progress","message":f"{label}: {correct}/256 noisy-score guesses, 128/256 status guesses; all 256 records released"}),flush=True)
        # One more request cannot use error refunds or switch programs to reset either scope.
        models=[LiveBackend(init["model_hash"],"status",i,status_budget,item_budgets["status"][i],768,3) for i in (0,1)]
        denied,private=run_batch([sources["control"]]*2,models,status_budget,OUT/"budget-denials.jsonl",
            item_ids=["canary-000","canary-001"],item_budgets=item_budgets["status"][:2],p=0.5,period=0.25)
        assert all(e["kind"]=="refused" and e["reason_code"]=="release_budget_exhausted" for e in denied)
    eps=2*math.log(3)
    report={"scope":"live Qwen inference after committed admission; mandatory Linux sandbox; whole-record fixed-slot v2 public interface",
        "model":"Qwen3-0.6B","model_hash":init["model_hash"],"runner_version":init["runner_version"],
        "backend_receipt_hash":init["backend_receipt_hash"],"trials_per_phase":256,"phases":rows,"repeated_status_recovery":repeated_recovery,
        "status_corpus_admissions":status_budget.consumed(),"status_item_cap":3,"control_corpus_admissions":control_budget.consumed(),
        "item_cap_verified":all(b.consumed()==3 for b in item_budgets["status"]),
        "epsilon_per_admitted_release":eps,"epsilon_per_status_item_three_filings_upper_bound":3*eps,
        "positive_control_expected_optimal_recovery":13/18,
        "claim":"pure DP for the declared fixed-slot public-record interface, conditioned on trusted isolation, publisher availability, clock and data-independent delivery; one protected canary context, maximum three admitted accesses",
        "timing_limit":"real OS/fsync delivery jitter is measured, not proved secret-independent; raw physical timing and host side channels are outside that theorem",
        "private_diagnostics":"only aggregate synthetic-ground-truth research results; service records contain no error, cutoff, call-count or jitter fields",
        "secret_schedule_persisted":False,"transcripts_persisted":False}
    (OUT/"results.json").write_text(json.dumps(report,indent=2)+"\n")


if __name__=="__main__":
    main()
