import json
import math
import pytest
from rt.bundle import sha
from demos.coding_agent.accounting import model_scopes, policy_history, verify_history
from demos.coding_agent.report import recovery_panel
from rt.experiment import interval


def row(model, cap, kind="released"):
    return {"model_hash": model, "kind": kind, "policy": {"budget_scope": "shared-asset", "admission_cap": cap, "epsilon_per_admitted_release": 2*math.log(3)}}


def cohort(label, before, cap, rows):
    protocol = {"budget_scope": "shared-asset", "original_cap_and_used": before, "extended_admission_cap": cap}
    source = json.dumps(protocol).encode()
    summary = {"protocol_sha256": sha(source), "protocol_commit": "a"*40, "budget": {"cap": cap}}
    return label, summary, source, [(label+".jsonl", rows)]


def test_model_attribution_carries_all_cohorts_and_excludes_refusal_charge():
    ledgers = [("old", [row("A", 2), row("B", 2)]), ("new-account", [row("A", 3), row("A", 3, "refused")])]
    before = json.dumps(ledgers, sort_keys=True)
    scopes = {s["model_commitment"]: s for s in model_scopes(ledgers)}
    assert scopes["A"]["admitted_records"] == 2
    assert scopes["A"]["refused_records"] == 1
    assert scopes["A"]["epsilon_model_total"] == pytest.approx(4*math.log(3))
    assert sum(s["epsilon_model_total"] for s in scopes.values()) == pytest.approx(6*math.log(3))
    assert scopes["A"]["historical_enforcement_scopes"] == ["shared-asset"]
    assert json.dumps(ledgers, sort_keys=True) == before


def test_history_rejects_reset_unlogged_allowance_and_source_tampering(tmp_path):
    cohorts = [cohort("first", 0, 2, [row("A", 2), row("B", 2)]), cohort("second", 2, 3, [row("A", 3)])]
    events = policy_history(cohorts)
    assert events[1]["charges_carried_forward"] == 2
    assert events[1]["additional_allowance_by_model"] == {"A": 1}
    with pytest.raises(ValueError, match="carried charges"):
        policy_history([cohorts[0], cohort("reset", 0, 1, [row("A", 1)])])
    with pytest.raises(ValueError, match="carried charges"):
        policy_history([cohorts[0], cohort("extra", 2, 4, [row("A", 4)])])
    with pytest.raises(ValueError, match="ledger policy"):
        policy_history([cohorts[0], cohort("wrong", 2, 3, [row("A", 4)])])
    (tmp_path / "policy-sources").mkdir()
    for label, _, source, _ in cohorts:
        (tmp_path / "policy-sources" / (label+".json")).write_bytes(source)
    path = tmp_path / "policy-changes.jsonl"
    lines = [json.dumps(e)+"\n" for e in events]
    path.write_text("".join(lines))
    (tmp_path / "policy-changes-checkpoint.json").write_text(json.dumps({"entries": 2, "last_entry_hash": events[-1]["entry_hash"]}))
    assert verify_history(tmp_path) == events
    path.write_text(lines[0])
    with pytest.raises(ValueError, match="checkpoint"):
        verify_history(tmp_path)
    path.write_text("".join(lines))
    (tmp_path / "policy-sources/second.json").write_text("{}")
    with pytest.raises(ValueError, match="source mismatch"):
        verify_history(tmp_path)


def test_main_chart_distinguishes_error_and_score_channels():
    def point(k):
        return {"correct": k, "n": 128, "rate": k/128, "wilson_95": interval(k, 128)}
    summary = {"recovery": {"naive_status_attack": {"status": point(128)}, "artt_status_attack": {"status": point(64)}, "artt_score_attack": {"score": point(96)}}}
    document = recovery_panel(summary, point(128))
    assert "Crash attack, before ARTT" in document and "Score attack, after ARTT" in document
    assert "hidden test suite" in document and "always guesses 0" in document
    assert "64/128" in document and "ARTT never publishes an error for an admitted evaluation" in document
    assert "same kind of record" in document and "not closed" in document
