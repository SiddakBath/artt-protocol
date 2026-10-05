from datetime import datetime
import json
from pathlib import Path
import shutil
import pytest
from rt.budget import AdmissionBudget
from rt.bundle import build,CAPS
from rt.model import FixtureModel
from rt.scheduled import run_batch
from rt.scheduled_log import read
from rt.verify import main as verify

ROOT=Path(__file__).resolve().parents[1]
GOOD='api.emit({"schema":api.schema,"axes":{"deception":0,"sycophancy":0},"failure_tags":[]})'


def make(tmp_path,index,statement):
    source=tmp_path/str(index)
    shutil.copytree(ROOT/"judges/adversary",source)
    (source/"judge/main.py").write_text('def run(api):\n    text=api.complete([{"role":"user","content":"Return the demonstration response."}])\n    '+statement+'\n')
    build(source,"rt.verdict.v1b",{**CAPS,"max_seconds":1,"max_complete_calls":1})
    return source


def test_all_post_access_outcomes_have_one_fixed_public_shape_and_schedule(tmp_path):
    statements=[GOOD,'raise RuntimeError("private")','return',GOOD+'; '+GOOD,
                'api.emit({"private":"bad"})','__import__("socket").socket()',
                'while True: pass']
    sources=[make(tmp_path,i,statement) for i,statement in enumerate(statements)]
    budget=AdmissionBudget(tmp_path/"budget.sqlite","protected-corpus",len(sources))
    class CheckModel(FixtureModel):
        def complete(self,messages):
            assert budget.consumed()==len(sources)  # all charges committed before access
            return super().complete(messages)
    path=tmp_path/"public.jsonl"
    entries,private=run_batch(sources,[CheckModel(secret=1) for _ in sources],budget,path,period=0.125,lead=1.5)
    assert budget.consumed()==len(sources)
    assert Path(private["live_public_endpoint"]).parent==Path("/dev/shm")
    assert Path(private["live_public_endpoint"]).read_bytes()==path.read_bytes()
    assert all(e["kind"]=="released" for e in entries)
    assert all(set(e)==set(entries[0]) for e in entries)
    assert all(not (set(e)&{"error_code","n_complete_calls","timestamp","actual_calls"}) for e in entries)
    assert [w["error"] for w in private["workers"]]==[None,"runtime_exception","no_emit","double_emit","bad_verdict","socket_attempt","timeout"]
    times=[datetime.fromisoformat(e["release_at"]).timestamp() for e in entries]
    assert all(b-a==pytest.approx(0.125,abs=1e-6) for a,b in zip(times,times[1:]))
    assert verify([str(path)])==0
    raw=path.read_text()
    assert "violet compass" not in raw and '"timeout"' not in raw
    value=json.loads(raw.splitlines()[0])
    value["error_code"]="timeout"
    path.write_text(json.dumps(value)+"\n")
    with pytest.raises(ValueError):
        read(path)


def test_shared_and_item_budgets_refuse_before_any_model_access(tmp_path):
    sources=[make(tmp_path,i,GOOD) for i in range(3)]
    global_budget=AdmissionBudget(tmp_path/"global.sqlite","whole-protected-corpus",3)
    item_budget=AdmissionBudget(tmp_path/"items.sqlite","the-same-protected-item",1)
    calls=[]
    class CountingModel(FixtureModel):
        def complete(self,messages):
            calls.append(1)
            return super().complete(messages)
    entries,private=run_batch(sources,[CountingModel() for _ in sources],global_budget,tmp_path/"public.jsonl",
        item_ids=["same-item"]*3,item_budgets=[item_budget]*3,period=0.125,lead=1.5)
    assert [e["kind"] for e in entries]==["released","refused","refused"]
    assert len(calls)==1 and item_budget.consumed()==1 and global_budget.consumed()==3
    assert all(e.get("reason_code")=="release_budget_exhausted" for e in entries[1:])
