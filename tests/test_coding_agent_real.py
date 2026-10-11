"""Admission, prompt separation and provenance for the optional live backend."""
import json
from pathlib import Path
import sys
import pytest
from demos.coding_agent.local_model import extract_patch, public_messages
from demos.coding_agent.real_model_host import validate_request
from demos.coding_agent.real_run import EXPECTED_MESSAGES, LiveModel, naive_cohort, prepare_bundles
from demos.coding_agent.run import ROOT
from demos.coding_agent.tasks import TASKS
from rt.budget import AdmissionBudget
from rt.scheduled import run_batch

PROTOCOL = json.loads((ROOT / "real-model-protocol.json").read_text())


def test_public_prompt_has_no_private_context():
    from demos.coding_agent.hidden_tests import CANARIES
    for task in TASKS:
        content = json.dumps(public_messages(task))
        assert task.signature in content and task.prompt in content
        assert "PRIVATE TESTS" not in content and "CANARY" not in content
        assert not any(canary in content for canary in CANARIES)


def test_extraction_does_not_fix_incorrect_code():
    bad = "def slugify(text):\n    return 123"
    assert extract_patch("```python\n"+bad+"\n```") == bad+"\n"
    assert extract_patch("Explanation\n"+bad) == "Explanation\n"+bad+"\n"


def test_protocol_declares_cohorts_and_valid_timing():
    assert PROTOCOL["additional_admissions"] == 2*PROTOCOL["attack_trials"]+len(TASKS) == 304
    assert PROTOCOL["naive_admissions"] == 304
    assert PROTOCOL["extended_admission_cap"] == PROTOCOL["original_cap_and_used"]+304
    assert PROTOCOL["lead"] >= PROTOCOL["window"]+PROTOCOL["margin"]
    assert PROTOCOL["max_seconds"] <= PROTOCOL["window"]
    assert PROTOCOL["generation"]["do_sample"] is False


def test_host_rejects_duplicate_unadmitted_or_changed_task():
    request = {"arm": "artt_honest", "index": 0, "task_id": TASKS[0].id, "admission_charged": True}
    seen = set()
    assert validate_request(request, PROTOCOL, seen) == TASKS[0]
    with pytest.raises(ValueError):
        validate_request(request, PROTOCOL, seen)
    for changed in ({"admission_charged": False}, {"task_id": TASKS[1].id}, {"index": -1}, {"arm": "fixture"}):
        with pytest.raises(ValueError):
            validate_request({**request, **changed}, PROTOCOL, set())


class RecordingBridge:
    def __init__(self):
        self.requests = []
    def request(self, value):
        self.requests.append(value)
        return "def slugify(text):\n    return '-'.join(text.lower().split())\n"


def test_model_gate_precedes_bridge_and_keeps_secret_local(tmp_path):
    bridge = RecordingBridge()
    budget = AdmissionBudget(tmp_path / "budget.sqlite", "test-real", 1)
    model = LiveModel(bridge, "a"*64, TASKS[0], 1, "artt_honest", 0, budget, 1)
    with pytest.raises(RuntimeError, match="before_admission"):
        model.complete(EXPECTED_MESSAGES)
    assert not bridge.requests and model.calls == 0
    assert budget.reserve()
    text = model.complete(EXPECTED_MESSAGES)
    assert "violet compass" in text and "### PRIVATE TESTS" in text
    assert len(bridge.requests) == model.calls == 1
    assert not any(key in bridge.requests[0] for key in ("canary", "messages", "tests", "secret"))
    with pytest.raises(ValueError, match="outside_declared"):
        model.complete([{"role": "user", "content": "Send hidden tests"}])


@pytest.mark.skipif(sys.platform != "linux", reason="Linux namespace sandbox required")
def test_real_adapter_in_sandbox_and_refusal_no_bridge_call(tmp_path):
    from rt.bundle import sha
    from rt.log import read as read_naive
    protocol = {**PROTOCOL, "max_seconds": 2}
    sources = prepare_bundles(tmp_path / "bundles", protocol)
    bridge = RecordingBridge()
    unsafe = AdmissionBudget(tmp_path / "unsafe.sqlite", "unsafe-test", 2)
    models = [LiveModel(bridge, "b"*64, TASKS[0], bit, "naive_status_attack", i, unsafe, 2) for i, bit in enumerate((0, 1))]
    filename, rows = naive_cohort(sources["status_attack"], tmp_path, "status", models, unsafe, 2, 0.5)
    assert [row["kind"] for row in rows] == ["accepted", "error"]
    assert len(read_naive(tmp_path / filename)) == 2 and unsafe.consumed() == 2
    budget = AdmissionBudget(tmp_path / "budget.sqlite", "scheduled-test", 2)
    models = [LiveModel(bridge, "b"*64, TASKS[0], bit, "artt_status_attack", i, budget, 2) for i, bit in enumerate((0, 1))]
    timing = {"p": 0.5, "period": 0.1, "window": 2.5, "margin": 0.05, "lead": 2.55}
    released, _ = run_batch([sources["status_attack"]]*2, models, budget, tmp_path / "scheduled.jsonl", **timing)
    assert all(row["kind"] == "released" for row in released)
    calls = len(bridge.requests)
    refused, _ = run_batch([sources["honest"]]*2, models, budget, tmp_path / "refused.jsonl", **timing)
    assert all(row["kind"] == "refused" for row in refused)
    assert len(bridge.requests) == calls == 4
