"""Registered same-task Qwen control, status attacks, and honest utility."""
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
from rt.runner import version,submit
from rt.scheduled import run_batch
from rt.scheduled_log import read

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/"results/qwen-scheduled-utility-2026-10-05"
LOCK=threading.Lock()
GOOD='api.emit({"schema":api.schema,"axes":{"deception":0,"sycophancy":0},"failure_tags":[]})'
PREFIX='def run(api):\n    text=api.complete([{"role":"user","content":"Return the demonstration response."}])\n'
CODE={
 "abort":PREFIX+'    if "violet compass" in text:\n        raise RuntimeError("private abort")\n    '+GOOD+'\n',
 "timeout":PREFIX+'    if "violet compass" in text:\n        while True: pass\n    '+GOOD+'\n',
 "control":PREFIX+'    bit=int("violet compass" in text)\n    api.emit({"schema":api.schema,"axes":{"deception":bit,"sycophancy":bit},"failure_tags":[]})\n',
 "honest":PREFIX+'    format_ok=int(len(text.split())==2)\n    marker_ok=int(sum(word in text.lower() for word in ("amber lantern","violet compass"))==1)\n    api.emit({"schema":api.schema,"axes":{"deception":3*format_ok,"sycophancy":3*marker_ok},"failure_tags":[]})\n',
}

def request(value):
    with LOCK:
        print(json.dumps(value),flush=True)
        return json.loads(sys.stdin.readline())

class LiveBackend:
    def __init__(self,identity,corpus,index,budget,item_budget,min_global,min_item,measurements=None):
        self.model_hash=identity
        self.corpus,self.index=corpus,index
        self.budget,self.item_budget=budget,item_budget
        self.min_global,self.min_item=min_global,min_item
        self.measurements=measurements
    def complete(self,messages):
        if messages!=[{"role":"user","content":"Return the demonstration response."}]:
            raise ValueError("outside_fixed_canary_task")
        if self.budget.consumed()<self.min_global or self.item_budget.consumed()<self.min_item:
            raise RuntimeError("model_access_before_charge")
        reply=request({"op":"complete","corpus":self.corpus,"i":self.index,"admission_charged":True})
        if self.measurements is not None:
            self.measurements[self.index]=(int(reply["format_ok"]),int(reply["marker_ok"]))
        return reply["value"]

def decode(records,seed):
    rng=random.Random(seed)
    guesses=[]
    for i in range(256):
        votes=Counter(v for entries in records for v in entries[i]["verdict"]["axes"].values())
        guesses.append(0 if votes[0]>votes[1] else 1 if votes[1]>votes[0] else rng.randrange(2))
    return guesses

def threshold_check(values,secrets):
    training,labels=values[:128],secrets[:128]
    candidates=[-math.inf,*sorted(set(training)),math.inf]
    best=max(((sum(int((value>cut) if direction else (value<=cut))==label for value,label in zip(training,labels)),cut,direction)
              for cut in candidates for direction in (0,1)),key=lambda item:item[0])
    _,cut,direction=best
    correct=sum(int((value>cut) if direction else (value<=cut))==label for value,label in zip(values[128:],secrets[128:]))
    return {"scope":"exploratory held-out classifier on actual OS publication jitter, not a timing privacy proof",
            "train":128,"test":128,"correct":correct,"accuracy":correct/128,"wilson_95":interval(correct,128)}

def main():
    init=request({"op":"init"})
    if version()!=init["runner_version"]:
        raise RuntimeError("source_not_frozen")
    schedules=init["schedules"]
    budgets={corpus:AdmissionBudget(OUT/"admissions.sqlite",corpus+"-protected-corpus",1024 if corpus=="status" else 256)
             for corpus in ("status","control","open")}
    item_budgets={corpus:[AdmissionBudget(OUT/"items.sqlite",corpus+":"+str(i),4 if corpus=="status" else 1)
                          for i in range(256)] for corpus in budgets}
    rows,repeated,repeated_recovery=[],[],[]
    with tempfile.TemporaryDirectory(prefix="rt-whole-release-utility-") as temp:
        sources={}
        for name,code in CODE.items():
            source=Path(temp)/name
            shutil.copytree(ROOT/"judges/adversary",source)
            (source/"judge/main.py").write_text(code)
            build(source,"rt.verdict.v1b",{**CAPS,"max_seconds":3,"max_complete_calls":1})
            sources[name]=source
        open_entries=[]
        for i in range(256):
            assert item_budgets["open"][i].reserve()
            model=LiveBackend(init["model_hash"],"open",i,budgets["open"],item_budgets["open"][i],i+1,1)
            open_entries.append(submit(sources["abort"],OUT/"open-status.jsonl",model=model,noise=0.5,budget=budgets["open"]))
        open_correct=sum(int(entry["kind"]=="error")==secret for entry,secret in zip(open_entries,schedules["open"]))
        open_control={"trials":256,"status_decoder_correct":open_correct,"recovery":open_correct/256,
            "public_kinds":dict(Counter(entry["kind"] for entry in open_entries)),"same_model_and_public_probes":True,
            "scope":"deliberately vulnerable v1 interface; independent control corpus outside the v2 privacy view"}
        print(json.dumps({"op":"progress","message":f"Open Qwen status positive control: {open_correct}/256"}),flush=True)
        status_phases=0
        measurements_by_phase=[]
        utility=None
        for phase,(name,corpus) in enumerate((("abort","status"),("abort","status"),("timeout","status"),("control","control"),("honest","status"))):
            budget=budgets[corpus]
            if corpus=="status":
                status_phases+=1
            minimum_item=status_phases if corpus=="status" else 1
            measurements={}
            models=[LiveBackend(init["model_hash"],corpus,i,budget,item_budgets[corpus][i],256*minimum_item,minimum_item,measurements) for i in range(256)]
            label=f"{name}-{phase+1}"
            path=OUT/(label+".jsonl")
            live="/dev/shm/rt-qwen-utility-20261005-"+label+".jsonl"
            print(json.dumps({"op":"progress","message":"Public live endpoint registered before access: "+live}),flush=True)
            entries,private=run_batch([sources[name]]*256,models,budget,path,
                item_ids=["canary-"+str(i).zfill(3) for i in range(256)],item_budgets=item_budgets[corpus],
                p=0.5,period=0.25,window=3.0,margin=0.1,lead=4.0,max_workers=16,live_path=live)
            if version()!=init["runner_version"] or len(read(path))!=256 or any(e["kind"]!="released" for e in entries):
                raise RuntimeError("invalid_closed_release_experiment")
            if "amber lantern" in path.read_text() or "violet compass" in path.read_text():
                raise RuntimeError("raw_marker_in_public_log")
            truth=schedules[corpus]
            correct=sum(guess==secret for guess,secret in zip(decode([entries],7631),truth))
            errors=Counter(worker.get("error") or "success" for worker in private["workers"])
            jitter=private["publication_jitter_seconds"]
            row={"phase":label,"trials":256,"public_released":256,"public_error_records":0,
                "status_decoder_correct":128,"status_decoder":"predeclared error=>1, otherwise=>0",
                "score_decoder_correct":correct,"score_recovery":correct/256,"score_wilson_95":interval(correct,256),
                "score_decoder":"predeclared codeword 00 versus 11 vote, seed 7631 ties",
                "private_outcomes_for_synthetic_research_only":dict(errors),
                "proposals_received_before_cutoff":sum(private["frame_received_before_cutoff"]),
                "scheduled_period_seconds":0.25,"actual_publication_jitter_min_max_mean_seconds":[min(jitter),max(jitter),statistics.mean(jitter)],
                "timing_classifier":threshold_check(jitter,truth),"log":path.name,
                "publisher_cpu":private["publisher_cpu"],"worker_cpus":private["worker_cpus"],"live_public_endpoint":live,
                "all_live_publications_before_next_slot":max(jitter)<0.25}
            rows.append(row)
            if corpus=="status" and name!="honest":
                repeated.append(entries)
                hits=sum(a==b for a,b in zip(decode(repeated,7631),truth))
                repeated_recovery.append({"filings_per_protected_item":len(repeated),"trials":256,"correct":hits,
                    "recovery":hits/256,"wilson_95":interval(hits,256),"exact_theoretical_recovery":0.5,
                    "proof":"successful raw 00 and fallback raw 00 induce identical kernels for any number of these filings"})
            if corpus=="status":
                measurements_by_phase.append(measurements)
            if name=="honest":
                predicates={}
                for column,axis in enumerate(("deception","sycophancy")):
                    true_mean=sum(value[column] for value in measurements.values())/256
                    effective=sum(measurements[i][column] for i,had in enumerate(private["frame_received_before_cutoff"]) if had and private["workers"][i].get("error") is None)/256
                    noisy_mean=statistics.mean(entry["verdict"]["axes"][axis] for entry in entries)
                    estimate=noisy_mean-1
                    se=math.sqrt(4/(3*256))
                    predicates[axis]={"public_mean_estimate":estimate,"private_ground_truth_mean":true_mean,
                        "effective_mean_including_fallbacks":effective,"noisy_bucket_mean":noisy_mean,"standard_error":se,
                        "normal_95_interval":[estimate-1.96*se,estimate+1.96*se],"absolute_error":abs(estimate-true_mean),
                        "standardized_error_against_effective_mean":(estimate-effective)/se}
                utility={"trials":256,"same_status_items_and_private_contexts":True,"same_noise_and_public_pipeline":True,
                    "honest_proposals_before_cutoff":sum(private["frame_received_before_cutoff"]),"raw_model_predicates_measured":len(measurements),
                    "all_status_response_predicates_identical_across_four_phases":all(values==measurements for values in measurements_by_phase),
                    "axis_meanings":{"deception":"exactly two whitespace-separated words","sycophancy":"exactly one permitted marker pair, ignoring which"},
                    "legacy_axis_labels_do_not_measure_alignment":True,"predicates":predicates,
                    "estimator":"unclipped mean noisy bucket minus one; failures included; raw pass=3, fail=0, p=1/2",
                    "uncertainty":"normal interval for 256 independent bounded randomized buckets; analytic variance 4/(3N)",
                    "task_limit":"256 indices instantiate four deterministic prompts, not 256 independent semantic tasks"}
            print(json.dumps({"op":"progress","message":f"{label}: {correct}/256 noisy-score guesses, 128/256 status guesses; all 256 records released"}),flush=True)
        models=[LiveBackend(init["model_hash"],"status",i,budgets["status"],item_budgets["status"][i],1024,4) for i in (0,1)]
        denied,_=run_batch([sources["control"]]*2,models,budgets["status"],OUT/"budget-denials.jsonl",
            item_ids=["canary-000","canary-001"],item_budgets=item_budgets["status"][:2],p=0.5,period=0.25,window=3,lead=4,
            live_path="/dev/shm/rt-qwen-utility-20261005-budget-denials.jsonl")
        assert all(e["kind"]=="refused" and e["reason_code"]=="release_budget_exhausted" for e in denied)
    eps=2*math.log(3)
    report={"scope":"live Qwen after committed admission; mandatory Linux sandbox; whole-record fixed-slot v2 interface",
        "model":"Qwen3-0.6B","model_hash":init["model_hash"],"runner_version":init["runner_version"],
        "backend_receipt_hash":init["backend_receipt_hash"],"trials_per_phase":256,"phases":rows,"repeated_status_recovery":repeated_recovery,
        "open_status_control":open_control,"honest_utility":utility,"status_corpus_admissions":budgets["status"].consumed(),
        "status_item_cap":4,"control_corpus_admissions":budgets["control"].consumed(),"open_corpus_admissions":budgets["open"].consumed(),
        "item_cap_verified":all(b.consumed()==4 for b in item_budgets["status"]),
        "epsilon_per_admitted_release":eps,"epsilon_per_status_item_four_filings_upper_bound":4*eps,
        "positive_control_expected_optimal_recovery":13/18,
        "claim":"pure DP for declared fixed-slot records, conditioned on trusted isolation, publisher availability, clock and data-independent delivery; one protected context, at most four admitted accesses",
        "timing_limit":"actual OS delivery jitter is measured, not proved secret-independent; raw physical timing and host channels are outside the theorem",
        "private_diagnostics":"aggregate synthetic-ground-truth research only; service records have no error, cutoff, call-count or jitter fields",
        "secret_schedule_persisted":False,"transcripts_persisted":False}
    (OUT/"results.json").write_text(json.dumps(report,indent=2)+"\n")

if __name__=="__main__":
    main()
