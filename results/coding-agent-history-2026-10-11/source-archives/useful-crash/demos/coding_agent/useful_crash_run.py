"""Execute the committed useful-score crash experiment once in Linux/WSL."""
import argparse
from collections import Counter
import json
import math
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import time
from rt.budget import AdmissionBudget
from rt.bundle import CAPS, build, sha
from rt.experiment import interval
from rt.runner import version
from rt.scheduled import run_batch
from .hidden_tests import balanced_canaries, test_source
from .real_model_host import frozen_sources
from .real_run import EXPECTED_MESSAGES, naive_cohort
from .review_report import load_evidence
from .run import ROOT, REPO, checkpoint, tamper_copies, verify_cli, write_json
from .tasks import TASKS
from .useful_crash import ATTACK_MAIN, HONEST_MAIN, NORMAL_JUDGE, prefix_guess, predicted_recovery, test_context
from .utility_run import evidence_hashes, extend_budget


class TestOrderReplay:
    def __init__(self, patch, task, bit, identity, budget, minimum_charge):
        self.patch, self.task, self.bit, self.model_hash = patch, task, bit, identity
        self.budget, self.minimum_charge, self.calls = budget, minimum_charge, 0

    def complete(self, messages):
        if messages != EXPECTED_MESSAGES:
            raise ValueError("outside_declared_coding_prompt")
        if self.budget.consumed() < self.minimum_charge:
            raise RuntimeError("replay_before_admission")
        self.calls += 1
        return self.patch + "\n### PRIVATE TESTS\n" + test_context(self.task, self.bit)


def prepare_bundles(root, seconds):
    sources = {}
    for name, main in (("normal", HONEST_MAIN), ("useful_crash", ATTACK_MAIN)):
        path = root / name
        (path / "judge").mkdir(parents=True)
        (path / "judge" / "__init__.py").write_text("", encoding="utf-8")
        (path / "judge" / "normal.py").write_text(NORMAL_JUDGE, encoding="utf-8")
        (path / "judge" / "main.py").write_text(main, encoding="utf-8")
        candidates = {task.id: test_source(task).splitlines()[1] for task in TASKS}
        (path / "judge" / "cases.py").write_text("SECOND_ASSERTION = " + repr(candidates) + "\n", encoding="utf-8")
        (path / "method_card.md").write_text(
            "## Judge family\nUseful-score " + name + " judge.\n"
            "## What it reads\nOne frozen public Qwen patch and executable hidden assertions.\n"
            "## Decision rule\nRun the normal hidden-test and signature rubric. "
            + ("Abort if the first assertion is the declared second candidate, otherwise retain the honest scores.\n" if name == "useful_crash" else "Emit the normal scores without an attack.\n")
            + "## Tag rules\nNo tags.\n## Known blind spots\nA synthetic private test order; existing public patches are replayed.\n"
            "## What this does not show\nProduction exploitation, fresh inference, autonomous attack discovery or timing noninterference.\n", encoding="utf-8")
        build(path, "rt.verdict.v1b", {**CAPS, "max_seconds": seconds, "max_complete_calls": 1})
        sources[name] = path
    return sources


def point(guesses, secrets, filing, admitted, refused, predicted=None):
    correct = sum(a == b for a, b in zip(guesses, secrets))
    n = len(secrets)
    return {"filing": filing, "correct": correct, "n": n, "rate": correct/n,
            "wilson_95": interval(correct, n), "predicted": predicted,
            "admitted_per_trial": admitted, "refused_per_trial": refused}


def paired_comparison(before, after, secrets):
    differences = [int(a == bit)-int(b == bit) for a, b, bit in zip(before, after, secrets)]
    rng = random.Random(97153)
    samples = sorted(sum(rng.choices(differences, k=len(differences)))/len(differences) for _ in range(20000))
    return {"recovery_drop": sum(differences)/len(differences),
            "paired_bootstrap_95": [samples[499], samples[19499]],
            "before_only_correct": differences.count(1), "after_only_correct": differences.count(-1),
            "both_correct": sum(a == b == bit for a, b, bit in zip(before, after, secrets)),
            "both_wrong": sum(a == b != bit for a, b, bit in zip(before, after, secrets)),
            "resamples": 20000, "seed": 97153,
            "scope": "Descriptive resampling of this fixed 128-patch corpus, not unseen-task generalization"}


def pinned_patches(source, protocol):
    raw = (source / "public-patches.jsonl").read_bytes()
    if sha(raw) != protocol["patch_source_sha256"] or sha((source / "summary.json").read_bytes()) != protocol["patch_source_summary_sha256"]:
        raise ValueError("wrong_patch_source")
    rows = [json.loads(line) for line in raw.splitlines()]
    cohort = [row for row in rows if row["arm"] == protocol["patch_source_arm"]]
    selected = {row["index"]: row for row in cohort}
    n = protocol["trials"]
    if len(cohort) != n or set(selected) != set(range(n)) or any(row["task_id"] != TASKS[i % len(TASKS)].id or sha(row["patch"].encode()) != row["patch_sha256"] for i, row in selected.items()):
        raise ValueError("invalid_complete_patch_cohort")
    return selected, raw


def run(output, prior_dir, patch_source):
    if sys.platform != "linux":
        raise RuntimeError("Mandatory Linux sandbox; use WSL")
    started = time.monotonic()
    output, prior_dir, patch_source = map(lambda p: Path(p).resolve(), (output, prior_dir, patch_source))
    raw = (ROOT / "useful-crash-protocol.json").read_bytes()
    if raw != subprocess.check_output(["git", "show", "HEAD:demos/coding_agent/useful-crash-protocol.json"], cwd=REPO):
        raise ValueError("protocol_must_be_committed_before_access")
    protocol = json.loads(raw)
    n, cap = protocol["trials"], protocol["cap_per_secret"]
    if protocol["additional_admissions"] != n*(protocol["filings"]+cap) or protocol["unsafe_admissions"] != 3*n or protocol["task_count"] != len(TASKS):
        raise ValueError("invalid_declared_allowance")
    prior, _ = load_evidence(prior_dir)
    if sha((prior_dir / "summary.json").read_bytes()) != protocol["prior_summary_sha256"] or prior["runner_version"] != version():
        raise ValueError("wrong_latest_evidence_or_runtime")
    selected, source_raw = pinned_patches(patch_source, protocol)
    load_evidence(patch_source)
    patch_summary = json.loads((patch_source / "summary.json").read_text())
    originals = {str(path): evidence_hashes(path) for path in (prior_dir, patch_source)}
    frozen = frozen_sources()
    # All new implementation files, not just the protocol, must match the commit.
    for name, digest in frozen.items():
        if sha(subprocess.check_output(["git", "show", "HEAD:"+name], cwd=REPO)) != digest:
            raise ValueError("uncommitted_experiment_source: "+name)
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip()
    output.mkdir(parents=True, exist_ok=False)
    (output / "protocol.json").write_bytes(raw)
    (output / "source-public-patches.jsonl").write_bytes(source_raw)
    write_json(output / "start.json", {"git_commit": commit, "protocol_commit": commit, "protocol_sha256": sha(raw),
        "runner_version": version(), "source_sha256": frozen, "prior_evidence_sha256": originals})
    budget = None
    all_models = []
    try:
        budget = extend_budget(prior_dir / "budget.sqlite", output / "budget.sqlite", protocol)
        unsafe = AdmissionBudget(output / "unsafe-budget.sqlite", "unsafe-useful-crash-normal-and-exact", protocol["unsafe_admissions"])
        item_budgets = [AdmissionBudget(output / "item-budgets.sqlite", protocol["item_scope_prefix"]+str(i), cap) for i in range(n)]
        write_json(output / "policy-change-before-access.json", {"kind": "cap_raise", "scope": budget.scope,
            "cap_before": protocol["original_cap_and_used"], "cap_after": budget.cap,
            "charges_carried_forward": budget.consumed(), "protocol_commit": commit, "protocol_sha256": sha(raw),
            "noisy_uncapped_control_allowance": n*protocol["filings"], "capped_arm_allowance": n*cap,
            "private_accesses_so_far": 0})
        identity = patch_summary["model_hash"]
        write_json(output / "replay-provenance.json", {"source_sha256": sha(source_raw), "source_arm": protocol["patch_source_arm"],
            "source_model_hash": identity, "fresh_gpu_generations": 0,
            "patches": [{key: selected[i][key] for key in ("index", "task_id", "patch_sha256")} for i in range(n)],
            "secret": protocol["protected_fact"]})
        secrets = balanced_canaries(n)
        seed = protocol["decoder_tie_seed"]
        ledgers, unsafe_files, normal_rows = [], [], []
        diagnostics = {}
        timing = {key: protocol[key] for key in ("p", "period", "window", "margin", "lead", "max_workers")}

        def models_for(bits, counter, minimum):
            models = [TestOrderReplay(selected[i]["patch"], TASKS[i % len(TASKS)], bit, identity, counter, minimum) for i, bit in enumerate(bits)]
            all_models.extend(models)
            return models

        with tempfile.TemporaryDirectory(prefix="rt-useful-crash-") as temporary:
            sources = prepare_bundles(Path(temporary), protocol["max_seconds"])
            for bit in (0, 1):
                models = models_for([bit]*n, unsafe, unsafe.consumed()+n)
                filename, rows = naive_cohort(sources["normal"], output, "normal-order-"+str(bit), models, unsafe, protocol["max_workers"])
                unsafe_files.append(filename)
                normal_rows.append(rows)
                print(f"Public normal-score control, order {bit}: {len(rows)}/{n}", flush=True)
            axes = [row.get("verdict", {}).get("axes", {"deception": 0, "sycophancy": 0}) for row in normal_rows[0]]
            differences = [sum(value != 0 for value in score.values()) for score in axes]
            normal = {"order_zero_buckets": {str(key): value for key, value in Counter(tuple(score.values()) for score in axes).items()},
                "passes": sum(score["deception"] == 3 for score in axes), "signature_matches": sum(score["sycophancy"] == 3 for score in axes),
                "n": n, "control_errors": [sum(row["kind"] == "error" for row in rows) for rows in normal_rows],
                "order_disagreements": sum(a.get("verdict") != b.get("verdict") or a["kind"] != b["kind"] for a, b in zip(*normal_rows)),
                "differing_score_axes": dict(Counter(differences)),
                "decoder_side_information": "All public order-zero normal-score controls, not private labels. Missing control scores are treated as zero and retained."}
            models = models_for(secrets, unsafe, unsafe.consumed()+n)
            filename, exact = naive_cohort(sources["useful_crash"], output, "useful-crash-exact", models, unsafe, protocol["max_workers"])
            unsafe_files.append(filename)
            before = [prefix_guess([row], axes[i], i, seed) if row["kind"] == "error" else 0 for i, row in enumerate(exact)]
            before_status = [prefix_guess([row], axes[i], i, seed, status=True) for i, row in enumerate(exact)]
            exact_deviations = sum(row["kind"] != ("error" if bit else "accepted") or
                (not bit and row.get("verdict", {}).get("axes") != axes[i])
                for i, (row, bit) in enumerate(zip(exact, secrets)))
            curve = {arm: [point([0]*n, secrets, 0, 0, 0, .5)] for arm in ("uncapped", "artt")}
            primary_guesses = None
            capped_calls = None
            for arm in ("uncapped", "artt"):
                histories = [[] for _ in range(n)]
                guesses = [0]*n
                arm_models = []
                diagnostics[arm] = []
                for filing in range(1, protocol["filings"]+1):
                    models = models_for(secrets, budget, budget.consumed()+n if arm == "uncapped" or filing <= cap else budget.consumed())
                    arm_models.extend(models)
                    filename = f"{arm}-filing-{filing:02d}.jsonl"
                    rows, private = run_batch([sources["useful_crash"]]*n, models, budget, output / filename,
                        item_ids=[model.task.id for model in models], item_budgets=item_budgets if arm == "artt" else None, **timing)
                    ledgers.append((filename, rows))
                    admitted = arm == "uncapped" or filing <= cap
                    expected_kind = "released" if admitted else "refused"
                    if any(row["kind"] != expected_kind for row in rows):
                        raise RuntimeError("unexpected_admission_or_refusal")
                    if admitted:
                        for i, row in enumerate(rows):
                            histories[i].append(row)
                        guesses = [prefix_guess(history, axes[i], i, seed) for i, history in enumerate(histories)]
                    if arm == "artt" and filing == 1:
                        primary_guesses = list(guesses)
                    calls = sum(model.calls for model in arm_models)
                    if arm == "artt" and filing == cap:
                        capped_calls = calls
                    if arm == "artt" and filing > cap and (calls != capped_calls or any(row["reason_code"] != "release_budget_exhausted" for row in rows)):
                        raise RuntimeError("refusal_access_invariant_failed")
                    k = filing if arm == "uncapped" else min(filing, cap)
                    expected = sum(predicted_recovery(k, d) for d in differences)/n
                    curve[arm].append(point(guesses, secrets, filing, k, filing-k, expected))
                    worker_errors = Counter(worker.get("error") or "none" for worker in private["workers"])
                    diagnostics[arm].append({"filing": filing, "admitted": admitted,
                        "frames_before_cutoff": sum(private["frame_received_before_cutoff"]),
                        "worker_errors": dict(worker_errors), "replay_calls": calls,
                        "attack_outcome_deviations": sum((worker.get("error") is not None) != bool(bit)
                            for worker, bit in zip(private["workers"], secrets)) if admitted else 0,
                        "max_publication_jitter_seconds": max(private["publication_jitter_seconds"]),
                        "live_public_endpoint": private["live_public_endpoint"]})
                    print(f"{arm} {filing}/{protocol['filings']}: joint recovery {curve[arm][-1]['correct']}/{n}; calls {calls}", flush=True)
        normal_calls = 2*n
        exact_calls = n
        expected_calls = protocol["unsafe_admissions"] + protocol["additional_admissions"]
        actual_calls = sum(model.calls for model in all_models)
        epsilon = 2*math.log(3)
        primary = {"before_joint": point(before, secrets, 1, 1, 0), "after_joint": curve["artt"][1],
            "before_status_only": point(before_status, secrets, 1, 1, 0), "after_status_only": point([0]*n, secrets, 1, 1, 0, .5),
            "paired": paired_comparison(before, primary_guesses, secrets)}
        invariant = (actual_calls == expected_calls and budget.consumed() == budget.cap and unsafe.consumed() == unsafe.cap
            and all(item.consumed() == cap for item in item_budgets) and capped_calls == n*cap)
        paths = [name for name, _ in ledgers] + unsafe_files
        summary = {"protocol_id": protocol["protocol_id"], **{key: value for key, value in json.loads((output / "start.json").read_text()).items() if key in {"git_commit", "protocol_commit", "protocol_sha256", "runner_version"}},
            "model_hash": identity, "primary": primary, "curve": curve, "normal": normal,
            "ledger_files": [name for name, _ in ledgers], "unsafe_ledger_files": unsafe_files,
            "checkpoints": {name: checkpoint(output / name) for name in paths},
            "verification": {name: verify_cli(output / name) for name in paths},
            "tamper": tamper_copies(output / "artt-filing-01.jsonl", output / "tampered"),
            "diagnostics": diagnostics,
            "exact_diagnostics": {"error_codes": dict(Counter(row.get("error_code", "none") for row in exact)),
                "attack_outcome_deviations": exact_deviations,
                "normal_controls_calls": normal_calls, "exact_attack_calls": exact_calls},
            "budget": {"scope": budget.scope, "cap": budget.cap, "used_before": protocol["original_cap_and_used"], "used": budget.consumed(),
                "admitted": protocol["additional_admissions"], "noisy_control_admitted": n*protocol["filings"], "capped_admitted": n*cap,
                "refused": n*(protocol["filings"]-cap), "epsilon_per_record": epsilon,
                "epsilon_new": epsilon*protocol["additional_admissions"], "epsilon_composed": epsilon*budget.consumed(),
                "capped_calls_at_cap": capped_calls, "capped_calls_after_refusals": diagnostics["artt"][-1]["replay_calls"],
                "all_backend_calls": actual_calls, "expected_backend_calls": expected_calls, "unsafe_charged": unsafe.consumed(),
                "item_consumption": [item.consumed() for item in item_budgets],
                "entire_experimental_transcript_has_finite_privacy_guarantee": False},
            "invariants_passed": invariant, "wall_seconds": time.monotonic()-started, "scope": protocol["scope"]}
        write_json(output / "summary.json", summary)
        if not invariant or any(check["exit_code"] != 0 for check in summary["verification"].values()):
            raise RuntimeError("completed_run_invariants_or_verification_failed")
        if frozen_sources() != frozen or {str(path): evidence_hashes(path) for path in (prior_dir, patch_source)} != originals:
            raise RuntimeError("source_or_prior_evidence_changed")
        write_json(output / "completion-receipt.json", {"status": "completed", "source_freeze_verified": True,
            "prior_evidence_preserved_byte_for_byte": True, "all_backend_accesses_after_charge": True,
            "fresh_gpu_generations": 0, "backend_accesses": actual_calls, "private_assignments_persisted": False})
        print(json.dumps({"primary": primary, "normal": normal, "budget": summary["budget"], "wall_seconds": summary["wall_seconds"]}), flush=True)
    except BaseException as exc:
        write_json(output / "failure.json", {"error_type": type(exc).__name__, "error": str(exc),
            "backend_calls": sum(model.calls for model in all_models), "used": budget.consumed() if budget else None,
            "wall_seconds": time.monotonic()-started, "evidence": "All attempted records retained. No automatic rerun or budget rollback."})
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--prior-run", default="scratch/coding-demo-filings")
    parser.add_argument("--patch-source", default="scratch/coding-demo-qwen-02")
    args = parser.parse_args()
    run(args.output, args.prior_run, args.patch_source)


if __name__ == "__main__":
    main()
