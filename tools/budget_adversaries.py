"""Exercise the real shared controller with renamed adversaries and restarts."""
import json
from pathlib import Path
import secrets
import shutil
import tempfile
from rt.budget import AdmissionBudget
from rt.bundle import build,CAPS
from rt.log import read
from rt.model import FixtureModel
from rt.runner import submit,version
from tools.upgrade_analysis import variant_sources

ROOT = Path(__file__).resolve().parents[1]


def main():
    out = ROOT/"results/budget-controller-2026-10-05"
    out.mkdir(exist_ok=False)
    secret = secrets.randbelow(2)
    model = FixtureModel(secret=secret)
    scope = "custodian-held-corpus:"+model.model_hash
    cap = 3
    hashes = []
    with tempfile.TemporaryDirectory(prefix="rt-budget-aliases-") as temp:
        for i,code in enumerate(variant_sources()):
            source = Path(temp)/str(i)
            shutil.copytree(ROOT/"judges/adversary",source)
            (source/"judge/main.py").write_text(code)
            manifest = build(source,"rt.verdict.v1b",{**CAPS,"max_complete_calls":1})
            hashes.append(manifest["program_hash"])
            # Reconstructing the controller simulates process restart; same persisted scope.
            budget = AdmissionBudget(out/"ledger.sqlite",scope,cap)
            entry = submit(source,out/"public.jsonl",model,noise=0.5,budget=budget)
            assert entry["kind"] == ("accepted" if i<cap else "refused")
            if i>=cap:
                assert entry["reason_code"]=="release_budget_exhausted"
    entries = read(out/"public.jsonl")
    assert len(set(hashes))==32
    report = {"scope":"implemented admission controller, fixture backend, real Linux sandbox for admitted judges",
        "runner_version":version(),"attempts":32,"unique_program_hashes":32,"cap":cap,
        "accepted":sum(e["kind"]=="accepted" for e in entries),
        "refused":sum(e["kind"]=="refused" for e in entries),
        "consumed_after_restarts":AdmissionBudget(out/"ledger.sqlite",scope,cap).consumed(),
        "model_hash":model.model_hash,"noise_probability":0.5,"budget_scope":scope,
        "privacy_claim":"count cap only; v1 errors, call metadata, and timing are not privatized; no whole-protocol DP claim",
        "secret_schedule_persisted":False,"transcripts_persisted":False}
    (out/"results.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report,indent=2))


if __name__ == "__main__":
    main()
