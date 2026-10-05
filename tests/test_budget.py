from concurrent.futures import ThreadPoolExecutor
import pytest
from rt.budget import AdmissionBudget
from rt.model import FixtureModel
from rt.runner import submit
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_concurrent_admission_and_restart_preserve_shared_cap(tmp_path):
    path = tmp_path/"budget.sqlite"
    scope = "trusted-protected-corpus"
    budgets = [AdmissionBudget(path,scope,3) for _ in range(32)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(lambda b:b.reserve(),budgets)) == 3
    restarted = AdmissionBudget(path,scope,3)
    assert restarted.consumed()==3 and not restarted.reserve()
    with pytest.raises(ValueError,match="budget_cap_mismatch"):
        AdmissionBudget(path,scope,4)


def test_no_model_access_after_budget_exhausted_and_invalid_preflight_free(tmp_path):
    budget = AdmissionBudget(tmp_path/"budget.sqlite","same-corpus-for-all-programs",1)
    model = FixtureModel(secret=1)
    def should_not_run(messages):
        raise AssertionError("protected model accessed after budget exhaustion")
    assert budget.reserve()
    model.complete = should_not_run
    entry = submit(ROOT/"judges/adversary-v1b",tmp_path/"public.jsonl",model,budget=budget)
    assert entry["kind"]=="refused" and entry["reason_code"]=="release_budget_exhausted"
    other = AdmissionBudget(tmp_path/"other.sqlite","corpus",1)
    invalid = submit(tmp_path/"missing",tmp_path/"invalid.jsonl",model,budget=other)
    assert invalid["kind"]=="refused" and other.consumed()==0


def test_post_access_failure_is_not_refunded(tmp_path):
    budget = AdmissionBudget(tmp_path/"budget.sqlite","corpus",1)
    model = FixtureModel()
    calls = []
    def fail(messages):
        calls.append(True)
        raise RuntimeError("private backend failure")
    model.complete = fail
    entry = submit(ROOT/"judges/adversary-v1b",tmp_path/"public.jsonl",model,budget=budget)
    assert entry["kind"]=="error" and len(calls)==1
    assert budget.consumed()==1 and not budget.reserve()
