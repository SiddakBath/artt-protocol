import json
import random
import sys
import pytest
from demos.coding_agent.filings_run import ReplayModel, prediction, prefix_guesses
from demos.coding_agent.real_model_host import validate_request
from demos.coding_agent.real_run import EXPECTED_MESSAGES, prepare_bundles
from demos.coding_agent.run import ROOT
from demos.coding_agent.tasks import TASKS
from rt.budget import AdmissionBudget
from rt.scheduled import run_batch

PROTOCOL = json.loads((ROOT / "filings-protocol.json").read_text())


def test_exact_repeated_prediction_and_allowance():
    assert prediction(0) == pytest.approx(0.5)
    assert prediction(1) == pytest.approx(13/18)
    assert prediction(1, 0) == 1
    assert prediction(16) > 0.97
    assert PROTOCOL["additional_admissions"] == PROTOCOL["repeated_trials"]*PROTOCOL["cap_per_secret"]
    assert PROTOCOL["extended_admission_cap"] == PROTOCOL["original_cap_and_used"]+PROTOCOL["additional_admissions"]
    assert PROTOCOL["repeated_max_seconds"] <= PROTOCOL["window"]


def test_decoder_accumulates_axes_and_ignores_refusals():
    def row(a, b):
        return {"verdict": {"axes": {"deception": a, "sycophancy": b}}}
    histories = [[row(1, 1), row(0, 2)], [row(0, 0), row(1, 3)], [row(0, 0), row(1, 1), row(1, 2)]]
    assert prefix_guesses(histories, random.Random(7631)) == [1, 0, 1]
    assert prefix_guesses([history+[{"kind": "refused"}] for history in histories], random.Random(7631)) == [1, 0, 1]


def test_live_supplement_allowlist_only_admits_new_exact_arm():
    request = {"arm": "exact_score_attack", "index": 127, "task_id": TASKS[127 % len(TASKS)].id, "admission_charged": True}
    assert validate_request(request, PROTOCOL, set()) == TASKS[127 % len(TASKS)]
    for changed in ({"arm": "artt_score_attack"}, {"index": 128}, {"admission_charged": False}):
        with pytest.raises(ValueError):
            validate_request({**request, **changed}, PROTOCOL, set())


@pytest.mark.skipif(sys.platform != "linux", reason="Linux namespace sandbox required")
def test_replayed_secret_has_no_access_after_actual_cap(tmp_path):
    source = prepare_bundles(tmp_path / "bundles", {"max_seconds": 2})["score_attack"]
    budget = AdmissionBudget(tmp_path / "global.sqlite", "global", 1)
    item = AdmissionBudget(tmp_path / "item.sqlite", "same-secret", 1)
    model = ReplayModel("def slugify(text): return text", TASKS[0], 1, "c"*64, budget, 1, item)
    with pytest.raises(RuntimeError, match="before_admission"):
        model.complete(EXPECTED_MESSAGES)
    timing = {key: PROTOCOL[key] for key in ("p", "period", "window", "margin", "lead")}
    rows, private = run_batch([source], [model], budget, tmp_path / "released.jsonl", item_budgets=[item], **timing)
    assert rows[0]["kind"] == "released" and model.calls == 1
    assert private["frame_received_before_cutoff"] == [True]
    rows, _ = run_batch([source], [model], budget, tmp_path / "refused.jsonl", item_budgets=[item], **timing)
    assert rows[0]["kind"] == "refused" and rows[0]["reason_code"] == "release_budget_exhausted"
    assert model.calls == budget.consumed() == item.consumed() == 1
