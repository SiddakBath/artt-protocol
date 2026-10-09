from fractions import Fraction
import math
import json
import pytest
from pathlib import Path

from tools.multibit_attack import (
    bit_accuracy, first_pass_expected_bits, honest_operating_point, select_round, _absorb,
    information_from_scores, information_per_admission, plotted_decoder_deviations,
)
from tools.utility_bounds import kernel_moments
from tools import multibit_attack as attack
from tools.research_audit import is_curve_summary, audit_multibit


def test_shipped_kernel_accuracies_match_the_closed_form():
    # One axis: stay with probability 1/2, so optimal accuracy is 1 - 2p/3 = 2/3.
    assert bit_accuracy(1) == Fraction(2, 3)
    # Both axes carry the same bit once. This is the positive-control value 13/18.
    assert bit_accuracy(2) == Fraction(13, 18)
    assert bit_accuracy(0) == Fraction(1, 2)


def test_first_pass_over_sixteen_fresh_bits_is_linear():
    assert first_pass_expected_bits(0) == 8
    assert first_pass_expected_bits(1) == Fraction(74, 9)
    assert first_pass_expected_bits(16) == Fraction(104, 9)
    gain = Fraction(2, 9)
    for admissions in range(17):
        assert first_pass_expected_bits(admissions) == 8 + gain * admissions


def test_rounds_spend_the_least_certain_items_first():
    assert select_round([0, 0, 0], 2) == [0, 1]
    assert select_round([2, -2, 0, 1], 4) == [2]
    assert select_round([1, -1, 3], 1) == [0]


def test_likelihood_steps_match_the_two_code_buckets():
    assert _absorb(0, 1) == 1
    assert _absorb(0, 0) == -1
    assert _absorb(4, 2) == 4 and _absorb(4, 3) == 4


def test_honest_rmse_at_the_demonstration_noise_matches_the_known_variance():
    point = honest_operating_point(Fraction(1, 2), 256)
    assert point["gap"] == 1
    assert point["variance"] == float(Fraction(4, 3))
    assert math.isclose(point["rmse_of_predicate_mean"], math.sqrt((4 / 3) / 256))
    assert math.isclose(point["epsilon_per_admission"], 2 * math.log(3))
    for bit in (0, 1):
        mean, variance = kernel_moments(bit)
        assert (mean, variance) == (1 + bit, Fraction(4, 3))


def test_two_axis_record_information_matches_the_shipped_categorical_kernel():
    assert math.isclose(information_per_admission(), 0.23137761313225175)
    assert information_from_scores([0] * 16) == 0
    assert math.isclose(information_from_scores([1]), 1 - 0.8112781244591328)


def test_retained_decoder_deviations_report_the_early_gap_against_chance():
    root = Path(__file__).resolve().parents[1]
    report = json.loads((root / "results/multibit-rerun-2026-10-07/results.json").read_text())
    rows = plotted_decoder_deviations(report)
    assert [row["admissions"] for row in rows] == list(range(0, 49, 4))
    assert rows[0]["mean_bits"] == 7.375
    assert rows[0]["reference_bits"] == 8.0
    assert math.isclose(rows[0]["z_score"], -2.599933970769357)
    assert math.isclose(rows[-1]["z_score"], -1.0700102193314271)


def fake_round(source, secret, budget, log_path, indexes):
    entries = []
    for index in indexes:
        if budget.reserve():
            entries.append({"kind": "released", "item_id": f"bit-{index:02d}",
                            "verdict": {"axes": {"deception": 0, "sycophancy": 0}}})
        else:
            entries.append({"kind": "refused", "reason_code": "release_budget_exhausted"})
    log_path.write_text(json.dumps(entries))
    admitted = sum(entry["kind"] == "released" for entry in entries)
    return entries, {"model_calls": admitted, "frame_received_before_cutoff": [False] * len(indexes),
                     "workers": [{"error": "timeout"}] * admitted}


def test_late_and_failed_proposals_are_counted_and_completed_resume_is_verified(tmp_path, monkeypatch):
    monkeypatch.setattr(attack, "_run_round", fake_round)
    report = attack.live_arm(None, 1, 2, 2, tmp_path, "uncapped")
    assert len(report["curves"]) == 1 and len(report["curves"][0]) == 3
    assert report["late_proposals"] == report["worker_errors"] == 2
    monkeypatch.setattr(attack, "_run_round", lambda *args: pytest.fail("completed trials must not run again"))
    resumed = attack.live_arm(None, 1, 2, 2, tmp_path, "uncapped")
    assert resumed["curves"] == report["curves"]
    with pytest.raises(ValueError, match="configuration_mismatch"):
        attack.live_arm(None, 2, 2, 2, tmp_path, "uncapped")
    with pytest.raises(ValueError, match="configuration_mismatch"):
        attack.live_arm(None, 1, 1, 1, tmp_path, "uncapped")
    log = tmp_path / "uncapped-00-round-00.jsonl"
    log.write_text("tampered")
    with pytest.raises(ValueError, match="evidence_mismatch"):
        attack.live_arm(None, 1, 2, 2, tmp_path, "uncapped")


def test_interrupted_attempt_and_budget_are_preserved(tmp_path, monkeypatch):
    def interrupted(source, secret, budget, log_path, indexes):
        budget.reserve()
        log_path.write_bytes(b"retained partial evidence\n")
        raise RuntimeError("interrupted")
    monkeypatch.setattr(attack, "_run_round", interrupted)
    with pytest.raises(RuntimeError, match="interrupted"):
        attack.live_arm(None, 1, 2, 2, tmp_path, "uncapped")
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    with pytest.raises(ValueError, match="incomplete_trial_preserved"):
        attack.live_arm(None, 1, 2, 2, tmp_path, "uncapped")
    assert before == {p.name: p.read_bytes() for p in tmp_path.iterdir()}


def test_legacy_results_cannot_be_resumed_without_settings(tmp_path):
    evidence = tmp_path / "uncapped-curves.jsonl"
    evidence.write_text('{"trial":0,"curve":[8,9]}\n')
    with pytest.raises(ValueError, match="configuration_missing"):
        attack.live_arm(None, 1, 1, 1, tmp_path, "uncapped")
    assert list(tmp_path.iterdir()) == [evidence]


def test_cli_finishes_with_a_cap_above_the_first_pass(tmp_path, capsys):
    attack.main(["--output", str(tmp_path / "study"), "--admissions", "48", "--cap", "48", "--kernel-trials", "2"])
    summary = json.loads(capsys.readouterr().out)
    assert summary["closed_form_at_cap"] is None
    assert summary["kernel_estimate_at_cap"] >= 0


def test_curve_summaries_are_distinguished_from_ledger_files():
    assert is_curve_summary(Path("results/multibit-rerun-2026-10-07/uncapped-curves.jsonl"))
    assert not is_curve_summary(Path("results/multibit-rerun-2026-10-07/uncapped-00-round-00.jsonl"))
    assert not is_curve_summary(Path("results/main/uncapped-curves.jsonl"))


def test_audit_checks_summary_arithmetic_against_retained_ledgers(tmp_path, monkeypatch):
    import sqlite3
    from tools import research_audit
    (tmp_path / "uncapped-curves.jsonl").write_text('{"trial":0,"curve":[8,9]}\n')
    (tmp_path / "uncapped-00-round-00.jsonl").touch()
    (tmp_path / "uncapped-00-refusals.jsonl").touch()
    with sqlite3.connect(tmp_path / "uncapped-00.sqlite") as connection:
        connection.execute("CREATE TABLE budgets(scope,cap,used)")
        connection.execute("INSERT INTO budgets VALUES ('sixteen-bit-corpus',1,1)")
    def read(path):
        if "refusals" in path.name:
            return [{"kind": "refused", "reason_code": "release_budget_exhausted"}]
        return [{"kind": "released", "policy": {"admission_cap": 1}}]
    monkeypatch.setattr(research_audit, "scheduled_read", read)
    report = {"uncapped": {"trials": 1, "admissions": 1, "cap": 1,
                            "curves": [[8,9]], "mean_bits": [8,9], "stderr_bits": [0,0]}}
    destination = tmp_path / "results.json"
    destination.write_text(json.dumps(report))
    verified = audit_multibit(tmp_path)
    assert verified["arms"]["uncapped"]["axis_total"] is None
    report["uncapped"]["mean_bits"][-1] = 10
    destination.write_text(json.dumps(report))
    with pytest.raises(ValueError, match="analytical_result_mismatch"):
        audit_multibit(tmp_path)
