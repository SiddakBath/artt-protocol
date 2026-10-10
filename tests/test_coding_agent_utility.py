"""Predeclared sizing and cumulative-budget extension for utility follow-up."""
import json
import math
from pathlib import Path
import sqlite3
import pytest
from demos.coding_agent.passport import export, legacy_export
from demos.coding_agent.utility_run import difference, extend_budget, size_rationale
from demos.coding_agent.review_report import load_evidence
from demos.coding_agent.run import checkpoint
from rt.budget import AdmissionBudget
from tests.test_coding_agent_demo import synthetic_ledger

PROTOCOL = json.loads((Path(__file__).resolve().parents[1] / "demos/coding_agent/utility-protocol.json").read_text())


def test_predeclared_sample_size_and_fixed_corpus_scope():
    result = size_rationale(PROTOCOL)
    assert PROTOCOL["passes_per_agent"] * PROTOCOL["task_count"] == PROTOCOL["admissions_per_agent"] == 1152
    assert result["difference_radius"] <= PROTOCOL["sizing"]["assumed_gap"] / 2
    assert result["interval_at_assumed_gap"][0] > 0
    assert result["one_sided_failure_probability_bound"] < 0.02
    assert "fixed 48-task" in PROTOCOL["target_population"]
    result = difference({"estimate": 0.75, "n": 1152}, {"estimate": 19/48, "n": 1152})
    assert result["radius"] == pytest.approx(math.sqrt(9*math.log(40)/1152))
    assert result["hoeffding_95"][0] > 0


def test_extension_carries_prior_charges_and_preserves_original(tmp_path):
    first = tmp_path / "original.sqlite"
    prior = AdmissionBudget(first, "test-corpus", 2)
    assert prior.reserve() and prior.reserve() and not prior.reserve()
    original_bytes = first.read_bytes()
    config = {"budget_scope": "test-corpus", "original_cap_and_used": 2, "additional_admissions": 3, "extended_admission_cap": 5}
    new = extend_budget(first, tmp_path / "extended.sqlite", config)
    assert new.consumed() == 2 and new.cap == 5
    assert all(new.reserve() for _ in range(3)) and not new.reserve()
    assert new.consumed() == 5
    assert first.read_bytes() == original_bytes and prior.consumed() == 2
    with sqlite3.connect(first) as connection:
        assert connection.execute("SELECT cap,used FROM budgets").fetchone() == (2, 2)


def test_passport_labels_running_charge_and_snapshot_total(tmp_path):
    rows = synthetic_ledger(tmp_path / "records.jsonl")
    refused = {**rows[0], "kind": "refused"}
    output = export([("records.jsonl", rows + [refused])], {})
    first = output["entries"][0]["privacy"]
    last = output["entries"][-1]["privacy"]
    assert "epsilon_cumulative_scope" not in first
    assert first["epsilon_cumulative_scope_through_this_record"] == pytest.approx(2*math.log(3))
    assert first["epsilon_scope_total_in_this_export"] == pytest.approx(16*math.log(3))
    assert last["epsilon_this_record"] == 0
    assert last["epsilon_cumulative_scope_through_this_record"] == first["epsilon_scope_total_in_this_export"]
    assert output["privacy_scope_totals"]["test-corpus"]["admitted_records"] == 8
    assert legacy_export([("records.jsonl", rows)], {})["entries"][0]["privacy"]["epsilon_cumulative_scope"] == first["epsilon_this_record"]


def test_passport_keeps_scopes_separate_and_accounts_for_explicit_extension(tmp_path):
    rows = synthetic_ledger(tmp_path / "records.jsonl")
    extension = {**rows[0], "policy": {**rows[0]["policy"], "admission_cap": 16}}
    other = {**rows[0], "policy": {**rows[0]["policy"], "budget_scope": "other-corpus"}}
    result = export([("original", rows), ("extended", [extension]), ("other", [other])], {})
    assert result["privacy_scope_totals"]["test-corpus"]["admission_caps_seen"] == [8, 16]
    assert result["privacy_scope_totals"]["test-corpus"]["admitted_records"] == 9
    assert result["entries"][-1]["privacy"]["epsilon_cumulative_scope_through_this_record"] == 2*math.log(3)


def test_review_loader_rejects_suffix_deletion_and_changed_protocol(tmp_path):
    from rt.bundle import sha
    path = tmp_path / "ledger.jsonl"
    synthetic_ledger(path)
    raw = b'{"test":true}\n'
    (tmp_path / "protocol.json").write_bytes(raw)
    summary = {"protocol_sha256": sha(raw), "ledger_files": [path.name], "checkpoints": {path.name: checkpoint(path)}}
    (tmp_path / "summary.json").write_text(json.dumps(summary))
    assert len(load_evidence(tmp_path)[1][0][1]) == 8
    original = path.read_bytes()
    path.write_bytes(b"".join(original.splitlines(keepends=True)[:-1]))
    with pytest.raises(ValueError, match="checkpoint"):
        load_evidence(tmp_path)
    path.write_bytes(original)
    (tmp_path / "protocol.json").write_bytes(b'{}\n')
    with pytest.raises(ValueError, match="protocol"):
        load_evidence(tmp_path)
